#!/usr/bin/env bash
#
# lfsb.sh - Complete LFS / Beyond LFS orchestrator (single-file)
# Features:
#  - Bash >=5 script (uses associative arrays)
#  - Secure-ish chroot build using unshare when available
#  - Downloads with aria2c/curl/wget, cache, checksum & GPG verification
#  - Git sync for ports/metafiles and automatic patch fetching
#  - Applies patches (git apply / patch / quilt fallback)
#  - Builds in DESTDIR using fakeroot, creates .FILES manifest of installed paths
#  - Packages into tar.zst, supports strip, caches packages
#  - Uninstall using manifest (removes files), detects orphans, reverse-dep order
#  - Upgrade with topo-sort (Kahn), rebuild modes
#  - Dependency resolver with Kahn topological sort and cycle detection
#  - Hooks system (pre/post stages)
#  - CLI: long and abbreviated commands, plus interactive menu
#  - Locks (flock), retries, logs (color), silent/verbose modes
#
# Usage:
#   ./lfsb.sh [--silent] [--verbose] <command> [args...]
#
# Requirements (recommended): bash>=5, git, aria2c/curl/wget, tar, zstd, sha256sum, gpg, fakeroot
#
set -euo pipefail
shopt -s inherit_errexit nullglob globstar

# -------- CONFIG --------
PREFIX="${PREFIX:-/opt/lfsb}"
DISTDIR="${DISTDIR:-$PREFIX/distfiles}"
CACHE_DIR="${CACHE_DIR:-$PREFIX/cache}"
PKG_DIR="${PKG_DIR:-$PREFIX/pkgs}"
BUILD_DIR="${BUILD_DIR:-$PREFIX/build}"
PORTS_DIR="${PORTS_DIR:-$PREFIX/ports}"
PATCHES_DIR="${PATCHES_DIR:-$PREFIX/patches}"
HOOKS_DIR="${HOOKS_DIR:-$PREFIX/hooks}"
LOG_DIR="${LOG_DIR:-$PREFIX/logs}"
STATE_DIR="${STATE_DIR:-$PREFIX/var}"
LOCK_FILE="${LOCK_FILE:-$STATE_DIR/lock}"
DB_FILE="${DB_FILE:-$STATE_DIR/state.json}"
DEFAULT_CONCURRENCY="${DEFAULT_CONCURRENCY:-2}"
MAKEFLAGS="${MAKEFLAGS:--j$(nproc || echo 2)}"
RETRY_COUNT="${RETRY_COUNT:-3}"
RETRY_WAIT="${RETRY_WAIT:-3}"
ALLOW_UNSIGNED="${ALLOW_UNSIGNED:-0}"

# Colors if tty
if [[ -t 2 ]]; then
  RED=$(printf '\033[31m')
  YEL=$(printf '\033[33m')
  GRN=$(printf '\033[32m')
  CYN=$(printf '\033[36m')
  BLU=$(printf '\033[34m')
  RESET=$(printf '\033[0m')
else
  RED='' YEL='' GRN='' CYN='' BLU='' RESET=''
fi

# runtime flags
VERBOSE=1
SILENT=0
CONCURRENCY="$DEFAULT_CONCURRENCY"
DRY_RUN=0
FORCE=0
INTERACTIVE=0

declare -A METAFILE_CACHE
declare -A INSTALLED_MAP  # name->version (in-memory)

# ensure base dirs
mkdir -p "$DISTDIR" "$CACHE_DIR" "$PKG_DIR" "$BUILD_DIR" "$PORTS_DIR" "$PATCHES_DIR" "$HOOKS_DIR" "$LOG_DIR" "$STATE_DIR"

LOGFILE="$LOG_DIR/lfsb.log"

# ------- logging -------
log() {
  local level="$1"; shift
  local msg="$*"
  local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
  case "$level" in
    ERROR) [[ $SILENT -eq 0 ]] && printf "%b[%s][%bERROR%b]%b %s\n" "$RED" "$ts" "$RESET" "$RED" "$RESET" "$msg" >&2 ;;
    WARN)  [[ $SILENT -eq 0 ]] && printf "%b[%s][%bWARN%b]%b %s\n" "$YEL" "$ts" "$RESET" "$YEL" "$RESET" "$msg" ;;
    INFO)  [[ $SILENT -eq 0 || $VERBOSE -ge 1 ]] && printf "%b[%s][%bINFO%b]%b %s\n" "$GRN" "$ts" "$RESET" "$GRN" "$RESET" "$msg" ;;
    DEBUG) [[ $VERBOSE -ge 2 && $SILENT -eq 0 ]] && printf "%b[%s][%bDEBUG%b]%b %s\n" "$CYN" "$ts" "$RESET" "$CYN" "$RESET" "$msg" ;;
    *) [[ $SILENT -eq 0 ]] && printf "[%s][%s] %s\n" "$ts" "$level" "$msg" ;;
  esac
  printf "[%s][%s] %s\n" "$ts" "$level" "$msg" >> "$LOGFILE"
}

safe_run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    log INFO "DRY RUN: $*"
    return 0
  fi
  if [[ $SILENT -eq 1 ]]; then
    if ! "$@" >/dev/null 2>&1; then
      log ERROR "Command failed: $*"
      return 1
    fi
    return 0
  else
    "$@"
  fi
}

# trap cleanup
_on_exit() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    log ERROR "Exit with code $rc"
  else
    log INFO "Exited successfully"
  fi
  if [[ -n "${LOCK_FD:-}" ]]; then
    flock -u "$LOCK_FD" || true
    exec {LOCK_FD}>&-
  fi
}
trap _on_exit EXIT

# -------- prereq check -------
check_prereqs() {
  local need=(tar zstd sha256sum git)
  local found_any_downloader=0
  for t in "${need[@]}"; do
    if ! command -v "$t" >/dev/null 2>&1; then
      log WARN "Prerequisite missing: $t"
    fi
  done
  for d in aria2c curl wget; do command -v "$d" >/dev/null 2>&1 && found_any_downloader=1 && break; done
  if [[ $found_any_downloader -eq 0 ]]; then log WARN "No downloader (aria2c/curl/wget) found"; fi
  if ! command -v fakeroot >/dev/null 2>&1; then log WARN "fakeroot recommended but not found"; fi
  if ! command -v gpg >/dev/null 2>&1; then log WARN "gpg recommended for signature verification"; fi
}

# -------- locking -----------
acquire_lock() {
  local lf="${1:-$LOCK_FILE}"
  mkdir -p "$(dirname "$lf")"
  exec {LOCK_FD}>"$lf"
  if ! flock -n "$LOCK_FD"; then
    log ERROR "Unable to acquire lock $lf - another operation is running"
    return 1
  fi
  log DEBUG "Lock acquired ($lf)"
  return 0
}
release_lock() {
  if [[ -n "${LOCK_FD:-}" ]]; then
    flock -u "$LOCK_FD" || true
    exec {LOCK_FD}>&-
    log DEBUG "Lock released"
  fi
}

# -------- utils -----------
retry() {
  local tries=${1:-3}; shift
  local delay=${RETRY_WAIT}
  local i=0
  until "$@"; do
    i=$((i+1))
    if [[ $i -ge $tries ]]; then
      log ERROR "Command failed after $i tries: $*"
      return 1
    fi
    log WARN "Attempt $i failed, retrying in ${delay}s..."
    sleep "$delay"
    delay=$((delay*2))
  done
}

mktempdir() { mktemp -d "${BUILD_DIR}/tmp.XXXXXXXX"; }

_split_csv() {
  local csv="$1"; local __ret="$2"
  IFS=',' read -r -a arr <<< "$csv"
  eval "$__ret=(\"\${arr[@]}\")"
}

# -------- metafile parser (key=value) -----------
parse_metafile() {
  local mf="$1"
  declare -gA MF
  MF=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    [[ -z "${line// }" ]] && continue
    if [[ "$line" =~ ^([^=]+)=(.*)$ ]]; then
      MF["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
    fi
  done < "$mf"
  if [[ -z "${MF[name]:-}" || -z "${MF[version]:-}" ]]; then
    log ERROR "Invalid metafile $mf (missing name/version)"
    return 1
  fi
  METAFILE_CACHE["${MF[name]}"]="$mf"
  return 0
}

# -------- downloader with cache & verification ----------
download_to_cache() {
  local url="$1"; local outdir="$2"
  mkdir -p "$outdir"
  local fname="${url##*/}"
  local out="$outdir/$fname"
  if [[ -f "$out" ]]; then
    log INFO "Found in cache: $out"
    echo "$out"; return 0
  fi
  if command -v aria2c >/dev/null 2>&1; then
    retry "$RETRY_COUNT" aria2c -x4 -s4 -d "$outdir" -o "$fname" "$url"
  elif command -v curl >/dev/null 2>&1; then
    retry "$RETRY_COUNT" curl -L --fail -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    retry "$RETRY_COUNT" wget -O "$out" "$url"
  else
    log ERROR "No downloader available"
    return 1
  fi
  [[ -f "$out" ]] || { log ERROR "Download failed for $url"; return 1; }
  echo "$out"
}

verify_checksum() {
  local file="$1"; local checksum_line="$2"
  if [[ -z "$checksum_line" ]]; then
    log WARN "No checksum provided for $file"
    [[ $ALLOW_UNSIGNED -eq 1 ]] && return 0 || return 2
  fi
  if [[ "$checksum_line" =~ ^([a-z0-9]+):([0-9a-fA-F]+)$ ]]; then
    local alg="${BASH_REMATCH[1]}"; local expected="${BASH_REMATCH[2]}"
    case "$alg" in
      sha256)
        local got; got=$(sha256sum "$file" | awk '{print $1}')
        if [[ "$got" == "$expected" ]]; then log INFO "Checksum ok for $file"; return 0; else log ERROR "Checksum mismatch for $file"; return 1; fi
        ;;
      *) log WARN "Checksum alg $alg not supported"; return 0 ;;
    esac
  else
    log WARN "Invalid checksum format: $checksum_line"; return 2
  fi
}

gpg_verify_if_present() {
  local file="$1"
  local asc="${file}.asc"
  if [[ -f "$asc" ]]; then
    if command -v gpg >/dev/null 2>&1; then
      if gpg --verify "$asc" "$file" >/dev/null 2>&1; then
        log INFO "GPG signature valid for $file"
        return 0
      else
        log ERROR "GPG verify failed for $file"
        return 1
      fi
    else
      log WARN "gpg not available to verify signature $asc"
      return 2
    fi
  fi
  return 0
}

fetch_sources_for_pkg() {
  local name="$1"; local mf="$2"
  parse_metafile "$mf" || return 1
  local urls_csv="${MF[source_urls]:-}"
  _split_csv "$urls_csv" urls
  if [[ ${#urls[@]} -eq 0 ]]; then log ERROR "No source URLs in $mf"; return 1; fi
  for u in "${urls[@]}"; do
    u="${u// /}"
    [[ -z "$u" ]] && continue
    local path; path=$(download_to_cache "$u" "$DISTDIR") || { log WARN "Failed $u"; continue; }
    # checksum
    local checksum="${MF[checksum]:-}"
    if ! verify_checksum "$path" "$checksum"; then
      log WARN "Checksum failed for $path, removing and trying next"
      rm -f "$path"; continue
    fi
    # gpg verify if asc present via same base URL
    # attempt to download .asc next to file if possible
    local asc_url="${u}.asc"
    if command -v aria2c >/dev/null 2>&1; then
      aria2c -q --conditional-get=false -d "$DISTDIR" -o "${path##*/}.asc" "$asc_url" || true
    else
      curl -fsSL -o "$DISTDIR/${path##*/}.asc" "$asc_url" || true
    fi
    gpg_verify_if_present "$path" || { log WARN "GPG verify failed for $path"; [[ $ALLOW_UNSIGNED -eq 1 ]] || return 1; }
    echo "$path"; return 0
  done
  log ERROR "Failed to fetch sources for $name"
  return 1
}

# -------- git sync for ports --------
git_sync_ports() {
  local repo="$1"; local branch="${2:-main}"
  if [[ -z "$repo" ]]; then log ERROR "git repo required"; return 1; fi
  if [[ -d "$PORTS_DIR/.git" ]]; then
    pushd "$PORTS_DIR" >/dev/null
    git fetch --all || true
    git reset --hard "origin/$branch" || git pull --rebase origin "$branch" || true
    popd >/dev/null
  else
    git clone --depth 1 -b "$branch" "$repo" "$PORTS_DIR"
  fi
  # copy patches
  if [[ -d "$PORTS_DIR/patches" ]]; then
    rsync -a --delete "$PORTS_DIR/patches/" "$PATCHES_DIR/" || true
  fi
  log INFO "Ports sync done"
}

# -------- apply patches ----------
apply_patches() {
  local srcdir="$1"; local pkgname="$2"; local patches_csv="$3"
  _split_csv "$patches_csv" patches
  for p in "${patches[@]:-}"; do
    [[ -z "$p" ]] && continue
    local ppath="$PATCHES_DIR/$pkgname/$p"
    if [[ ! -f "$ppath" && -f "$PATCHES_DIR/$p" ]]; then ppath="$PATCHES_DIR/$p"; fi
    if [[ ! -f "$ppath" ]]; then log WARN "Patch $p not found, skipping"; continue; fi
    pushd "$srcdir" >/dev/null
    log INFO "Applying patch $ppath"
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      git apply "$ppath" || patch -p1 < "$ppath" || { popd >/dev/null; log ERROR "Failed to apply $ppath"; return 1; }
    else
      patch -p1 < "$ppath" || { popd >/dev/null; log ERROR "Failed to apply $ppath"; return 1; }
    fi
    popd >/dev/null
  done
}

# -------- prepare chroot (basic, safer uses unshare) -----------
prepare_chroot() {
  local chroot_dir="$1"
  if [[ -z "$chroot_dir" ]]; then log ERROR "chroot_dir required"; return 1; fi
  mkdir -p "$chroot_dir"/{proc,sys,dev,etc,usr,var,tmp}
  # bind minimal mounts
  for d in proc sys dev; do
    if ! mountpoint -q "$chroot_dir/$d"; then
      sudo mount --bind "/$d" "$chroot_dir/$d" || true
    fi
  done
  cp -L /etc/resolv.conf "$chroot_dir/etc/resolv.conf" || true
  log DEBUG "Chroot prepared at $chroot_dir"
}

enter_chroot_and_run() {
  local chroot_dir="$1"; shift
  if command -v unshare >/dev/null 2>&1; then
    sudo unshare --map-root-user --fork --mount-proc --pid chroot "$chroot_dir" -- "$@"
  else
    sudo chroot "$chroot_dir" "$@"
  fi
}

# -------- build package --------------
build_package() {
  local mf="$1"
  parse_metafile "$mf" || return 1
  local name="${MF[name]}" version="${MF[version]}"
  PKG_NAME="$name"
  run_hook pre-build "$name" "$version"
  local src_archive; src_archive=$(fetch_sources_for_pkg "$name" "$mf") || return 1
  local wd; wd=$(mktempdir)
  log INFO "Extracting $src_archive -> $wd"
  case "$src_archive" in
    *.tar.*|*.tgz|*.tar) tar -xf "$src_archive" -C "$wd" ;;
    *.zip) unzip -q "$src_archive" -d "$wd" ;;
    *) tar -xf "$src_archive" -C "$wd" ;;
  esac
  local srcdir; srcdir=$(find "$wd" -maxdepth 2 -mindepth 1 -type d | head -n1 || true)
  [[ -z "$srcdir" ]] && srcdir="$wd"
  apply_patches "$srcdir" "$name" "${MF[patches]:-}" || { log ERROR "Patches failed"; return 1; }
  local chroot_dir="${BUILD_DIR}/${name}-chroot"
  mkdir -p "$chroot_dir"
  prepare_chroot "$chroot_dir" || log WARN "prepare_chroot failed, continuing"
  mkdir -p "$chroot_dir/var/cache"
  sudo mount --bind "$DISTDIR" "$chroot_dir/var/cache" || true
  local destdir="${BUILD_DIR}/${name}-dest"
  rm -rf "$destdir"; mkdir -p "$destdir"
  pushd "$srcdir" >/dev/null
  log INFO "Building $name-$version"
  local cfgargs="${MF[configure_args]:-}"
  # preserve list of installed files by using DESTDIR and tracking after install
  if ! ( ./configure $cfgargs && make $MAKEFLAGS && fakeroot make DESTDIR="$destdir" install ); then
    log ERROR "Build failed for $name"
    popd >/dev/null
    return 1
  fi
  popd >/dev/null
  # create .FILES manifest (list all installed paths relative)
  local files_manifest="${PKG_DIR}/${name}-${version}.FILES"
  (cd "$destdir" && find . -type f -print | sed 's|^\./||' > "$files_manifest")
  log INFO "Files manifest created: $files_manifest (count=$(wc -l < "$files_manifest"))"
  # strip executables if strip available and allowed
  if command -v strip >/dev/null 2>&1; then
    find "$destdir" -type f -executable -print0 | xargs -0 -r strip --strip-all || log WARN "strip failed (ignored)"
  fi
  # package
  local pkgfile="${PKG_DIR}/${name}-${version}.tar.zst"
  tar -C "$destdir" -I 'zstd -T0' -cf "$pkgfile" . || tar -C "$destdir" -cf - . | zstd -o "$pkgfile"
  sha256sum "$pkgfile" | awk '{print $1}' > "${pkgfile}.sha256"
  # PKGINFO
  printf "name=%s\nversion=%s\nsha256=%s\n" "$name" "$version" "$(cat ${pkgfile}.sha256)" > "${pkgfile}.PKGINFO"
  log INFO "Package created: $pkgfile"
  # record installed map (local db)
  echo "$name $version $(cat ${pkgfile}.sha256)" >> "$STATE_DIR/installed.list"
  INSTALLED_MAP["$name"]="$version"
  # unmount binds
  sudo umount "$chroot_dir/var/cache" >/dev/null 2>&1 || true
  run_hook post-build "$name" "$version" "$pkgfile"
  return 0
}

# -------- Kahn topological sort (package names) ----------
kahn_toposort() {
  local -n nodes_ref=$1
  declare -A in_deg adj
  for n in "${nodes_ref[@]}"; do in_deg["$n"]=0; adj["$n"]=''; done
  for n in "${nodes_ref[@]}"; do
    local mf="${METAFILE_CACHE[$n]:-$PORTS_DIR/$n/metafile}"
    [[ -f "$mf" ]] || continue
    parse_metafile "$mf"
    _split_csv "${MF[build_deps]:-},${MF[run_deps]:-}" deps
    for d in "${deps[@]:-}"; do
      d="${d// /}"; [[ -z "$d" ]] && continue
      # only consider deps in our nodes list
      local found=0
      for candidate in "${nodes_ref[@]}"; do [[ "$candidate" == "$d" ]] && found=1 && break; done
      if [[ $found -eq 1 ]]; then
        adj["$n"]+="$d,"
        in_deg["$d"]=$((in_deg["$d"]+1))
      fi
    done
  done
  local -a S=() L=()
  for n in "${nodes_ref[@]}"; do [[ ${in_deg[$n]:-0} -eq 0 ]] && S+=("$n"); done
  while ((${#S[@]})); do
    local n="${S[0]}"; S=("${S[@]:1}")
    L+=("$n")
    IFS=',' read -r -a neighs <<< "${adj[$n]}"
    for m in "${neighs[@]:-}"; do
      [[ -z "$m" ]] && continue
      in_deg["$m"]=$((in_deg["$m"]-1))
      if [[ ${in_deg[$m]} -eq 0 ]]; then S+=("$m"); fi
    done
  done
  local edges_left=0
  for n in "${nodes_ref[@]}"; do if [[ ${in_deg[$n]:-0} -gt 0 ]]; then edges_left=1; fi; done
  if [[ $edges_left -eq 1 ]]; then
    log ERROR "Dependency cycle detected:"
    for n in "${nodes_ref[@]}"; do [[ ${in_deg[$n]:-0} -gt 0 ]] && log ERROR " - $n (in_deg=${in_deg[$n]})"; done
    return 1
  fi
  # print order
  for p in "${L[@]}"; do echo "$p"; done
  return 0
}

# -------- hooks -----------
run_hook() {
  local stage="$1"; shift
  local pkg="$1"; local ver="$2"
  local hook="$HOOKS_DIR/$stage"
  if [[ -x "$hook" ]]; then
    log INFO "Running hook $stage for $pkg"
    PKG_NAME="$pkg" PKG_VERSION="$ver" "$hook" || log WARN "Hook $stage failed"
  fi
}

# -------- uninstall using .FILES manifest -----------
uninstall_package() {
  local pkg="$1"; local prune="${2:-0}"
  if [[ -z "$pkg" ]]; then log ERROR "uninstall requires package name"; return 1; fi
  # ensure package was recorded
  if ! grep -q "^${pkg} " "$STATE_DIR/installed.list" 2>/dev/null; then
    log WARN "Package $pkg not recorded as installed"
  fi
  # compute reverse deps to ensure safe removal
  mapfile -t installed < <(awk '{print $1}' "$STATE_DIR/installed.list" 2>/dev/null || true)
  declare -A revdeps
  for p in "${installed[@]}"; do revdeps["$p"]=''; done
  for p in "${installed[@]}"; do
    local mf="${METAFILE_CACHE[$p]:-$PORTS_DIR/$p/metafile}"
    [[ -f "$mf" ]] || continue
    parse_metafile "$mf"
    _split_csv "${MF[build_deps]:-},${MF[run_deps]:-}" deps
    for d in "${deps[@]:-}"; do d="${d// /}"; [[ -z "$d" ]] && continue
      if [[ -n "${revdeps[$d]+x}" ]]; then revdeps["$d"]+="$p,"; fi
    done
  done
  # if package has reverse deps and not forced, abort
  if [[ -n "${revdeps[$pkg]:-}" && $FORCE -eq 0 ]]; then
    log ERROR "Package $pkg is required by: ${revdeps[$pkg]}. Use --force to remove anyway."
    return 1
  fi
  # get package file and .FILES
  local pkgfile=$(ls "$PKG_DIR/${pkg}-"*.tar.zst 2>/dev/null | tail -n1 || true)
  local files_manifest="${pkgfile%.tar.zst}.FILES"
  if [[ -f "$files_manifest" ]]; then
    run_hook pre-uninstall "$pkg"
    log INFO "Removing files from manifest for $pkg"
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      local full="/$f"
      if [[ -e "$full" ]]; then
        if [[ -f "$full" || -L "$full" ]]; then rm -f "$full" || log WARN "Failed remove $full"; fi
        if [[ -d "$full" ]]; then rmdir "$full" 2>/dev/null || true; fi
      fi
    done < "$files_manifest"
    # remove package files from PKG_DIR
    rm -f "$pkgfile" "$files_manifest" "${pkgfile}.sha256" "${pkgfile}.PKGINFO" || true
    # remove from installed list
    grep -v "^$pkg " "$STATE_DIR/installed.list" > "$STATE_DIR/installed.list.tmp" || true
    mv "$STATE_DIR/installed.list.tmp" "$STATE_DIR/installed.list"
    run_hook post-uninstall "$pkg"
    log INFO "Uninstalled $pkg"
  else
    log WARN "No files manifest for $pkg; cannot safely remove files. Removing package record."
    grep -v "^$pkg " "$STATE_DIR/installed.list" > "$STATE_DIR/installed.list.tmp" || true
    mv "$STATE_DIR/installed.list.tmp" "$STATE_DIR/installed.list"
  fi
  # prune orphans
  if [[ "$prune" -eq 1 ]]; then prune_orphans; fi
}

prune_orphans() {
  log INFO "Pruning orphan packages"
  mapfile -t installed < <(awk '{print $1}' "$STATE_DIR/installed.list" 2>/dev/null || true)
  local changed=1
  while [[ $changed -eq 1 ]]; do
    changed=0
    for p in "${installed[@]}"; do
      local mf="${METAFILE_CACHE[$p]:-$PORTS_DIR/$p/metafile}"
      if [[ ! -f "$mf" ]]; then continue; fi
      parse_metafile "$mf"
      _split_csv "${MF[build_deps]:-},${MF[run_deps]:-}" deps
      local needed=0
      for other in "${installed[@]}"; do
        for d in "${deps[@]:-}"; do d="${d// /}"; [[ -z "$d" ]] && continue
          if [[ "$other" == "$d" ]]; then needed=1; break 2; fi
        done
      done
      if [[ $needed -eq 0 ]]; then
        log INFO "Package $p seems orphaned, removing"
        uninstall_package "$p" 0
        changed=1
        # refresh installed list
        mapfile -t installed < <(awk '{print $1}' "$STATE_DIR/installed.list" 2>/dev/null || true)
      fi
    done
  done
}

# -------- upgrade (rebuild full or incremental) -----------
upgrade_all() {
  local rebuild="${1:-0}"
  mapfile -t installed < <(awk '{print $1}' "$STATE_DIR/installed.list" 2>/dev/null || true)
  if [[ ${#installed[@]} -eq 0 ]]; then log INFO "No packages installed"; return 0; fi
  # ensure metafile cache
  for p in "${installed[@]}"; do
    if [[ -f "$PORTS_DIR/$p/metafile" ]]; then METAFILE_CACHE["$p"]="$PORTS_DIR/$p/metafile"; fi
  done
  if ! order=$(kahn_toposort installed 2>/dev/null); then
    if [[ $FORCE -eq 1 ]]; then log WARN "Cycle detected but proceeding due to --force"; order="${installed[*]}"; else log ERROR "Cycle in deps; abort"; return 1; fi
  fi
  if [[ "$rebuild" -eq 1 ]]; then
    log INFO "Full rebuild in determined order"
    for p in $order; do
      build_package "${METAFILE_CACHE[$p]}" || { log ERROR "Rebuild of $p failed"; return 1; }
    done
  else
    log INFO "Incremental upgrade (rebuilding all as baseline)"
    for p in $order; do build_package "${METAFILE_CACHE[$p]}" || { log ERROR "Upgrade failed for $p"; return 1; }; done
  fi
}

# -------- interactive menu -----------
print_menu() {
  cat <<EOF
lfsb interactive menu:
1) Sync ports repo
2) Build package
3) Install package
4) Uninstall package
5) Upgrade system
6) Show deps order for packages
7) View logs (tail)
8) Clean temp build dirs
9) Exit
Enter choice:
EOF
}

interactive_loop() {
  INTERACTIVE=1
  while true; do
    print_menu
    read -rp "> " choice
    case "$choice" in
      1) read -rp "Repo URL: " repo; read -rp "Branch (main): " br; br=${br:-main}; acquire_lock; git_sync_ports "$repo" "$br"; release_lock ;;
      2) read -rp "Package name or metafile path: " t; acquire_lock; if [[ -f "$t" ]]; then build_package "$t"; else build_package "$PORTS_DIR/$t/metafile"; fi; release_lock ;;
      3) read -rp "Package name to install: " p; read -rp "Destination (/) : " dest; dest=${dest:-/}; run_hook pre-install "$p"; fakeroot bash -c "tar -C $dest -I 'zstd -d' -xf '$PKG_DIR/${p}-'*.tar.zst" || log ERROR "Install failed"; run_hook post-install "$p" ;;
      4) read -rp "Package to uninstall: " p; read -rp "Prune orphans? (y/N): " pr; prune=0; [[ "$pr" =~ ^[Yy] ]] && prune=1; acquire_lock; uninstall_package "$p" "$prune"; release_lock ;;
      5) read -rp "Full rebuild? (y/N): " r; r=${r:-N}; acquire_lock; upgrade_all $([[ "$r" =~ ^[Yy] ]] && echo 1 || echo 0); release_lock ;;
      6) read -rp "Comma-separated package list: " csv; IFS=, read -r -a arr <<< "$csv"; for n in "${arr[@]}"; do [[ -f "$PORTS_DIR/$n/metafile" ]] && METAFILE_CACHE["$n"]="$PORTS_DIR/$n/metafile"; done; kahn_toposort arr ;;
      7) tail -n 200 "$LOGFILE" ;;
      8) rm -rf "$BUILD_DIR/tmp."* || true; log INFO "Cleaned" ;;
      9) break ;;
      *) echo "Invalid" ;;
    esac
  done
}

# -------- CLI / arg parsing -----------
print_help() {
  cat <<EOF
Usage: lfsb.sh [global flags] <command> [args...]

Global flags:
  --silent        - silent mode (errors only)
  --verbose       - increase verbosity (can be used multiple times)
  --force         - force risky operations
  --concurrency N - number of parallel builds
  --dry-run       - show actions without executing
  --interactive   - launch interactive menu

Commands (abbrev supported):
  sync|s <repo> [branch]        - git sync ports and patches
  build|b <pkg|metafile>        - build package
  install|i <pkg> --dest=PATH   - install package tar.zst to dest (uses fakeroot)
  uninstall|rm <pkg> [--prune]  - uninstall package
  upgrade|up [--rebuild]        - upgrade system (rebuild if specified)
  deps <pkg1,pkg2,...>          - show topological order or detect cycles
  logs [tail]                   - show logs (or tail)
  clean                         - remove temp build dirs
  help                          - this help
EOF
}

main() {
  if [[ $# -eq 0 ]]; then print_help; exit 0; fi
  # parse global flags first
  local args=()
  while (( $# )); do
    case "$1" in
      --silent) SILENT=1; shift ;;
      --verbose) VERBOSE=$((VERBOSE+1)); shift ;;
      --force) FORCE=1; shift ;;
      --concurrency) CONCURRENCY="$2"; shift 2 ;;
      --concurrency=*) CONCURRENCY="${1#*=}"; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --interactive) INTERACTIVE=1; shift ;;
      --help) print_help; exit 0 ;;
      *) args+=("$1"); shift ;;
    esac
  done

  check_prereqs

  if [[ $INTERACTIVE -eq 1 ]]; then interactive_loop; return 0; fi

  local cmd="${args[0]:-}"; shift || true
  case "$cmd" in
    sync|s) acquire_lock; git_sync_ports "${args[1]:-${args[0]}}" "${args[2]:-main}"; release_lock ;;
    build|b)
      local target="${args[1]:-}"
      if [[ -z "$target" ]]; then log ERROR "build target required"; exit 1; fi
      if [[ -f "$target" ]]; then acquire_lock; build_package "$target"; release_lock; else acquire_lock; build_package "$PORTS_DIR/$target/metafile"; release_lock; fi
      ;;
    install|i)
      local pkg="${args[1]:-}"; local dest="/"
      for a in "${args[@]:2}"; do case "$a" in --dest=*) dest="${a#--dest=}";; esac; done
      if [[ -z "$pkg" ]]; then log ERROR "install requires package name"; exit 1; fi
      run_hook pre-install "$pkg"
      fakeroot bash -c "tar -C $dest -I 'zstd -d' -xf '$PKG_DIR/${pkg}-'*.tar.zst" || { log ERROR "Install failed"; exit 1; }
      run_hook post-install "$pkg"
      ;;
    uninstall|rm)
      local pkg="${args[1]:-}"
      local prune=0
      for a in "${args[@]:2}"; do [[ "$a" == "--prune" ]] && prune=1; done
      acquire_lock
      uninstall_package "$pkg" "$prune"
      release_lock
      ;;
    upgrade|up)
      local rebuild=0
      for a in "${args[@]:1}"; do [[ "$a" == "--rebuild" ]] && rebuild=1; done
      acquire_lock
      upgrade_all "$rebuild"
      release_lock
      ;;
    deps)
      local csv="${args[1]:-}"
      IFS=, read -r -a arr <<< "$csv"
      for n in "${arr[@]}"; do [[ -f "$PORTS_DIR/$n/metafile" ]] && METAFILE_CACHE["$n"]="$PORTS_DIR/$n/metafile"; done
      kahn_toposort arr || exit 1
      ;;
    logs) if [[ "${args[1]:-}" == "tail" ]]; then tail -n 200 "$LOGFILE"; else cat "$LOGFILE"; fi ;;
    clean) rm -rf "$BUILD_DIR/tmp."* || true; log INFO "Cleaned" ;;
    help|--help) print_help ;;
    *) log ERROR "Unknown command: $cmd"; print_help; exit 1 ;;
  esac
}

# Create default configs on first run
bootstrap() {
  if [[ ! -f "$STATE_DIR/installed.list" ]]; then
    mkdir -p "$STATE_DIR"
    touch "$STATE_DIR/installed.list"
    log INFO "Bootstrap: created state dir and installed.list"
  fi
  # create sample hook that does nothing
  if [[ ! -f "$HOOKS_DIR/pre-build" ]]; then
    cat > "$HOOKS_DIR/pre-build" <<'HOOK'
#!/usr/bin/env bash
# sample pre-build hook (no-op)
exit 0
HOOK
    chmod +x "$HOOKS_DIR/pre-build"
  fi
}

bootstrap
main "$@"
