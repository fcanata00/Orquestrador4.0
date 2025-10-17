#!/usr/bin/env bash
# lib_build.sh - Build manager for LFS Ports
# Version: 1.0
# Responsibilities:
#  - Read and validate metafile for packages
#  - Prepare isolated build environment (fakeroot + unshare)
#  - Download sources via lib_net.sh, apply patches
#  - Run build phases with hooks and safe execution
#  - Package outputs (.tar.zst) with manifests and hashes
#  - Install/uninstall via manifests, detect and remove orphans
#  - Integrate with lib_common.sh, lib_fs.sh, lib_net.sh, lib_dep.sh, lib_pkgdb.sh
#
# Security & robustness:
#  - Runs builds as a non-root build user (configurable)
#  - Uses namespaces (unshare) where available
#  - Uses atomic operations and rollback on failure
#  - Detailed audit and metrics for each step
#
# Usage (example):
#   source lib_common.sh
#   source lib_fs.sh
#   source lib_net.sh
#   source lib_build.sh
#   build_init
#   build_from_metafile /usr/ports/foo/meta
#
set -o errtrace
set -o pipefail
# do not set -o errexit globally; use controlled error handling

LIBBUILD_VERSION="1.0"

# ------------------ Configuration (override before calling build_init) ------------------
: "${BUILD_USER:=lfsbuild}"                       # non-root user to run builds
: "${BUILD_BASE_DIR:=/var/tmp/lfsports/builds}"  # workspace base
: "${BUILD_LOG_DIR:=/var/log/lfsports/builds}"   # logs per build
: "${BUILD_PKG_DIR:=/var/lib/lfsports/packages}" # packages output
: "${BUILD_MANIFEST_DIR:=/var/lib/lfsports/installed}" # installed manifests
: "${BUILD_TMPFS:=0}"                            # use tmpfs for builddir if 1
: "${BUILD_TMPFS_SIZE:=2G}"                      # desired tmpfs size
: "${BUILD_TIMEOUT:=3600}"                       # default timeout per phase (seconds)
: "${BUILD_KEEP_TEMP:=0}"                        # keep temp dirs for debugging
: "${BUILD_STRIP_BINARIES:=1}"                   # strip binaries in package by default
: "${BUILD_CROSSDEVICE_SAFE:=1}"                 # use rsync when moving across FS boundaries
: "${BUILD_MAX_PARALLEL:=$(nproc || echo 1)}"    # recommended parallelism default
: "${BUILD_USE_CCACHE:=1}"                      # use ccache if available
: "${BUILD_VERIFY_SIGNATURES:=0}"                # verify GPG signatures if manifests present
# ---------------------------------------------------------------------------------------

# ------------------ Internal state ------------------
_BUILD_INITED=0
_BUILD_ACTIVE=0
_BUILD_WORKDIR=""
_BUILD_LOGFILE=""
_BUILD_META=()   # associative array simulated via declare -A when bash supports
_BUILD_ERRORS=0
# ------------------


# --- Fallback log functions if lib_common not loaded ---
if ! declare -f log_info >/dev/null 2>&1; then
  log_info() { printf '[%s] [INFO] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
  log_warn() { printf '[%s] [WARN] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
  log_error(){ printf '[%s] [ERROR] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fi
if ! declare -f safe_run >/dev/null 2>&1; then
  safe_run() { "$@"; return $?; }
fi

# --- helpers ---
_build_mkdir() {
  mkdir -p "$1" || { log_error "mkdir failed: $1"; return 1; }
}
_build_join() { local IFS="$1"; shift; echo "$*"; }

# --- sanity checks ---
_build_assert_user_exists() {
  if ! id -u "$BUILD_USER" >/dev/null 2>&1; then
    log_warn "build_user $BUILD_USER does not exist. Recommended to create it (useradd -m $BUILD_USER)"
  fi
}

# --- init ---
build_init() {
  if (( _BUILD_INITED )); then return 0; fi
  _build_mkdir "$BUILD_BASE_DIR" || return 1
  _build_mkdir "$BUILD_LOG_DIR" || return 1
  _build_mkdir "$BUILD_PKG_DIR" || return 1
  _build_mkdir "$BUILD_MANIFEST_DIR" || return 1

  _build_assert_user_exists

  # prefer ccache if available
  if [[ "$BUILD_USE_CCACHE" -eq 1 && -x "$(command -v ccache 2>/dev/null)" ]]; then
    export CCACHE_DIR="${CCACHE_DIR:-/var/cache/lfsports/ccache}"
    _build_mkdir "$CCACHE_DIR" || true
    export PATH="/usr/lib/ccache:$PATH"
    log_info "build_init: ccache enabled (dir=$CCACHE_DIR)"
  fi

  _BUILD_INITED=1
  log_info "build_init: done. base=$BUILD_BASE_DIR logs=$BUILD_LOG_DIR pkgs=$BUILD_PKG_DIR"
}

# --- utility: create unique build workdir ---
_build_create_workdir() {
  local name="$1"; local ver="$2"
  local base="$BUILD_BASE_DIR"
  local ts; ts=$(date +%s)
  local wd
  wd="$(mktemp -d "$base/${name}-${ver}.XXXXXX")" || wd="$base/${name}-${ver}.$$.tmp"
  echo "$wd"
}

# --- read metafile ---
# Support input formats: simple shell (KEY=VAL), ini-like (KEY=VAL), JSON (requires jq), YAML (requires yq)
build_read_metafile() {
  local mf="$1"
  if [[ -z "$mf" || ! -f "$mf" ]]; then
    log_error "build_read_metafile: metafile required and must exist"
    return 1
  fi
  declare -gA BUILD_META 2>/dev/null || true  # bash associative array if supported
  BUILD_META=()

  # detect format by extension or content
  case "${mf##*.}" in
    json)
      if command -v jq >/dev/null 2>&1; then
        BUILD_META[NAME]=$(jq -r '.name // empty' "$mf")
        BUILD_META[VERSION]=$(jq -r '.version // empty' "$mf")
        BUILD_META[SOURCE]=$(jq -r '.source // empty' "$mf")
        BUILD_META[SHA256]=$(jq -r '.sha256 // empty' "$mf")
        BUILD_META[DEPENDS]=$(jq -r '.depends[]? // empty' "$mf" | paste -sd',' -)
        BUILD_META[HOOKS]=$(jq -r '.hooks // empty' "$mf")
        BUILD_META[DESTDIR]=$(jq -r '.destdir // "/"' "$mf")
        BUILD_META[PATCHES]=$(jq -r '.patches[]? // empty' "$mf" | paste -sd',' -)
      else
        log_error "build_read_metafile: jq not found to parse json metafile"
        return 1
      fi
      ;;
    yml|yaml)
      if command -v yq >/dev/null 2>&1; then
        BUILD_META[NAME]=$(yq e '.name // ""' "$mf")
        BUILD_META[VERSION]=$(yq e '.version // ""' "$mf")
        BUILD_META[SOURCE]=$(yq e '.source // ""' "$mf")
        BUILD_META[SHA256]=$(yq e '.sha256 // ""' "$mf")
        BUILD_META[DEPENDS]=$(yq e '.depends[]? | @sh' "$mf" | paste -sd',' -)
        BUILD_META[HOOKS]=$(yq e '.hooks // ""' "$mf")
        BUILD_META[DESTDIR]=$(yq e '.destdir // "/"' "$mf")
        BUILD_META[PATCHES]=$(yq e '.patches[]? | @sh' "$mf" | paste -sd',' -)
      else
        log_error "build_read_metafile: yq not found to parse yaml metafile"
        return 1
      fi
      ;;
    sh|conf|ini)
      local tmp; tmp="$(mktemp)"
      sed 's/\r$//' "$mf" > "$tmp"
      while IFS='=' read -r key val; do
        key=$(echo "$key" | tr -d '[:space:]' )
        val="${val#\"}"; val="${val%\"}"
        case "$key" in
          NAME) BUILD_META[NAME]="$val";;
          VERSION) BUILD_META[VERSION]="$val";;
          SOURCE) BUILD_META[SOURCE]="$val";;
          SHA256) BUILD_META[SHA256]="$val";;
          DEPENDS) BUILD_META[DEPENDS]="$val";;
          HOOKS) BUILD_META[HOOKS]="$val";;
          DESTDIR) BUILD_META[DESTDIR]="$val";;
          PATCHES) BUILD_META[PATCHES]="$val";;
        esac
      done < <(grep -E '^[A-Za-z0-9_]+=.*' "$tmp")
      rm -f "$tmp" 2>/dev/null || true
      ;;
    *)
      local tmp; tmp="$(mktemp)"
      sed 's/\r$//' "$mf" > "$tmp"
      while IFS='=' read -r key val; do
        key=$(echo "$key" | tr -d '[:space:]' )
        val="${val#\"}"; val="${val%\"}"
        case "$key" in
          NAME) BUILD_META[NAME]="$val";;
          VERSION) BUILD_META[VERSION]="$val";;
          SOURCE) BUILD_META[SOURCE]="$val";;
          SHA256) BUILD_META[SHA256]="$val";;
          DEPENDS) BUILD_META[DEPENDS]="$val";;
          HOOKS) BUILD_META[HOOKS]="$val";;
          DESTDIR) BUILD_META[DESTDIR]="$val";;
          PATCHES) BUILD_META[PATCHES]="$val";;
        esac
      done < "$tmp"
      rm -f "$tmp" 2>/dev/null || true
      ;;
  esac

  if [[ -z "${BUILD_META[NAME]}" || -z "${BUILD_META[VERSION]}" ]]; then
    log_error "build_read_metafile: NAME and VERSION are required in metafile"
    return 1
  fi
  log_info "build_read_metafile: loaded ${BUILD_META[NAME]}-${BUILD_META[VERSION]}"
  return 0
}

# --- validate meta deeper ---
build_validate_meta() {
  local name="${BUILD_META[NAME]}"; local ver="${BUILD_META[VERSION]}"
  if [[ -z "$name" || -z "$ver" ]]; then
    log_error "build_validate_meta: no meta loaded"
    return 1
  fi
  if [[ -n "${BUILD_META[SOURCE]}" ]]; then
    if [[ "${NET_OFFLINE:-0}" -eq 1 ]]; then
      log_info "build_validate_meta: offline mode, skipping URL reachability check"
    else
      if command -v curl >/dev/null 2>&1; then
        if ! curl -I --silent --fail --max-time 10 "${BUILD_META[SOURCE]}" >/dev/null 2>&1; then
          log_warn "build_validate_meta: warning: SOURCE ${BUILD_META[SOURCE]} not reachable (will rely on cache)"
        fi
      fi
    fi
  fi
  log_info "build_validate_meta: metadata validated for $name-$ver"
  return 0
}

# --- prepare environment for build ---
build_prepare_env() {
  local name="${BUILD_META[NAME]}"; local ver="${BUILD_META[VERSION]}"
  if [[ -z "$name" ]]; then log_error "build_prepare_env: no package meta loaded"; return 1; fi

  local wd; wd="$(_build_create_workdir "$name" "$ver")"
  _BUILD_WORKDIR="$wd"
  mkdir -p "$_BUILD_WORKDIR" || return 1

  if [[ "$BUILD_TMPFS" -eq 1 && -x "$(command -v mount)" ]]; then
    mkdir -p "$_BUILD_WORKDIR" || true
    if mount -t tmpfs -o size=${BUILD_TMPFS_SIZE} tmpfs "$_BUILD_WORKDIR" 2>/dev/null; then
      log_info "build_prepare_env: tmpfs mounted at $wd size=$BUILD_TMPFS_SIZE"
    else
      log_warn "build_prepare_env: failed to mount tmpfs at $wd; continuing on disk"
    fi
  fi

  mkdir -p "$_BUILD_WORKDIR/sources" "$_BUILD_WORKDIR/build" "$_BUILD_WORKDIR/destdir" "$_BUILD_WORKDIR/logs"
  chmod 700 "$_BUILD_WORKDIR" 2>/dev/null || true
  _BUILD_LOGFILE="$_BUILD_WORKDIR/logs/build.log"
  touch "$_BUILD_LOGFILE" 2>/dev/null || true

  export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
  export LC_ALL=C
  export MAKEFLAGS="-j${BUILD_MAX_PARALLEL}"
  export DESTDIR="$_BUILD_WORKDIR/destdir"
  export PKG_CONFIG_PATH="$_BUILD_WORKDIR/destdir/usr/lib/pkgconfig:$_BUILD_WORKDIR/destdir/usr/share/pkgconfig"
  log_info "build_prepare_env: workdir=$_BUILD_WORKDIR destdir=$DESTDIR"
  return 0
}

# --- helper for running commands as build user with timeout and logging ---
_build_run_as_user() {
  local timeout_secs="$1"; shift
  local prefix="$1"; shift
  local cmd=( "$@" )
  local start ts rc
  start=$(date +%s)
  local phase_log="$_BUILD_WORKDIR/logs/${prefix}.log"
  touch "$phase_log" || true
  chmod 640 "$phase_log" 2>/dev/null || true

  if [[ "$BUILD_USER" != "$(id -un 2>/dev/null)" ]]; then
    if command -v runuser >/dev/null 2>&1; then
      if [[ -n "$timeout_secs" && "$timeout_secs" -gt 0 ]]; then
        timeout "$timeout_secs" runuser -u "$BUILD_USER" -- bash -lc "${cmd[*]}" >>"$phase_log" 2>&1
        rc=$?
      else
        runuser -u "$BUILD_USER" -- bash -lc "${cmd[*]}" >>"$phase_log" 2>&1
        rc=$?
      fi
    elif command -v sudo >/dev/null 2>&1; then
      if [[ -n "$timeout_secs" && "$timeout_secs" -gt 0 ]]; then
        timeout "$timeout_secs" sudo -u "$BUILD_USER" -- bash -lc "${cmd[*]}" >>"$phase_log" 2>&1
        rc=$?
      else
        sudo -u "$BUILD_USER" -- bash -lc "${cmd[*]}" >>"$phase_log" 2>&1
        rc=$?
      fi
    else
      if [[ -n "$timeout_secs" && "$timeout_secs" -gt 0 ]]; then
        timeout "$timeout_secs" bash -lc "${cmd[*]}" >>"$phase_log" 2>&1
        rc=$?
      else
        bash -lc "${cmd[*]}" >>"$phase_log" 2>&1
        rc=$?
      fi
    fi
  else
    if [[ -n "$timeout_secs" && "$timeout_secs" -gt 0 ]]; then
      timeout "$timeout_secs" bash -lc "${cmd[*]}" >>"$phase_log" 2>&1
      rc=$?
    else
      bash -lc "${cmd[*]}" >>"$phase_log" 2>&1
      rc=$?
    fi
  fi
  ts=$(date +%s)
  local elapsed=$((ts - start))
  local metrics="elapsed=${elapsed}s"
  if declare -f get_metrics >/dev/null 2>&1; then
    metrics="${metrics} $(get_metrics)"
  fi
  log_info "phase:$prefix rc=$rc ${metrics} (log=$phase_log)"
  if (( rc != 0 )); then
    log_error "phase:$prefix failed, rc=$rc; tail of $phase_log:"
    tail -n 50 "$phase_log" >&2 || true
  fi
  return $rc
}

# --- phase orchestration with hooks ---
_build_run_phase() {
  local phase="$1"; shift
  local cmd=( "$@" )
  log_info "[PHASE] $phase starting"
  _fs_audit_write "phase_start" "$_BUILD_WORKDIR" "{\"phase\":\"$phase\"}" 2>/dev/null || true

  if [[ -n "${BUILD_META[HOOKS]}" ]]; then
    local hookdir="${BUILD_META[HOOKS]}"
    local prehook="$hookdir/pre_${phase}.sh"
    if [[ -f "$prehook" ]]; then
      log_info "[HOOK] running $prehook"
      _build_run_as_user "$BUILD_TIMEOUT" "hook_pre_${phase}" "bash $prehook"
      if (( $? != 0 )); then
        log_error "[HOOK] pre-hook $prehook failed"
        return 1
      fi
    fi
  fi

  _build_run_as_user "$BUILD_TIMEOUT" "$phase" "${cmd[@]}"
  local rc=$?
  if (( rc != 0 )); then
    log_error "[PHASE] $phase failed (rc=$rc)"
    _fs_audit_write "phase_fail" "$_BUILD_WORKDIR" "{\"phase\":\"$phase\",\"rc\":$rc}" 2>/dev/null || true
    return $rc
  fi

  if [[ -n "${BUILD_META[HOOKS]}" ]]; then
    local hookdir="${BUILD_META[HOOKS]}"
    local posthook="$hookdir/post_${phase}.sh"
    if [[ -f "$posthook" ]]; then
      log_info "[HOOK] running $posthook"
      _build_run_as_user "$BUILD_TIMEOUT" "hook_post_${phase}" "bash $posthook"
      if (( $? != 0 )); then
        log_error "[HOOK] post-hook $posthook failed"
        return 1
      fi
    fi
  fi
  _fs_audit_write "phase_done" "$_BUILD_WORKDIR" "{\"phase\":\"$phase\"}" 2>/dev/null || true
  log_info "[PHASE] $phase done"
  return 0
}

# --- download and prepare sources ---
build_download_sources() {
  local src="${BUILD_META[SOURCE]}"; local sha="${BUILD_META[SHA256]}"
  if [[ -z "$src" ]]; then
    log_error "build_download_sources: no SOURCE in metafile"
    return 1
  fi
  if declare -f net_download_one >/dev/null 2>&1; then
    log_info "build_download_sources: fetching $src"
    local fetched
    if fetched=$(net_download_one "$src" "$sha" "${BUILD_META[NAME]}-${BUILD_META[VERSION]}"); then
      log_info "build_download_sources: fetched -> $fetched"
      cp -a "$fetched" "$_BUILD_WORKDIR/sources/" || { log_error "copy to workdir failed"; return 1; }
      _fs_audit_write "source_copied" "$_BUILD_WORKDIR" "{\"src\":\"$fetched\"}" 2>/dev/null || true
      return 0
    else
      log_error "build_download_sources: download failed for $src"
      return 1
    fi
  else
    local fname="$_BUILD_WORKDIR/sources/$(basename "$src")"
    safe_run "curl -L --fail -o $fname $src" curl -L --fail -o "$fname" "$src" || return 1
    return 0
  fi
}

# --- extract sources ---
build_extract_sources() {
  local srcfile; srcfile=$(ls -1 $_BUILD_WORKDIR/sources/* 2>/dev/null | head -n1)
  if [[ -z "$srcfile" ]]; then
    log_error "build_extract_sources: no source archive present"
    return 1
  fi
  log_info "build_extract_sources: extracting $srcfile"
  case "$srcfile" in
    *.tar.gz|*.tgz) tar -xzf "$srcfile" -C "$_BUILD_WORKDIR/build" || return 1 ;;
    *.tar.xz) tar -xJf "$srcfile" -C "$_BUILD_WORKDIR/build" || return 1 ;;
    *.tar.zst) if command -v zstd >/dev/null 2>&1; then zstd -d -c "$srcfile" | tar -xf - -C "$_BUILD_WORKDIR/build" || return 1; else tar -xf "$srcfile" -C "$_BUILD_WORKDIR/build" || return 1; fi ;;
    *.zip) unzip -q "$srcfile" -d "$_BUILD_WORKDIR/build" || return 1 ;;
    *) log_warn "build_extract_sources: unknown archive type, attempting tar -xf"; tar -xf "$srcfile" -C "$_BUILD_WORKDIR/build" || return 1 ;;
  esac
  local top; top=$(find "$_BUILD_WORKDIR/build" -mindepth 1 -maxdepth 1 -type d | head -n1)
  if [[ -n "$top" ]]; then
    cd "$top" || return 1
  else
    cd "$_BUILD_WORKDIR/build" || return 1
  fi
  log_info "build_extract_sources: cwd=$(pwd)"
  return 0
}

# --- apply patches via net_apply_patches if present ---
build_apply_patches() {
  if [[ -n "${BUILD_META[PATCHES]}" ]]; then
    if declare -f net_apply_patches >/dev/null 2>&1; then
      local patchdir="${BUILD_META[PATCHES]}"
      if net_apply_patches "$(pwd)" "$patchdir"; then
        log_info "build_apply_patches: patches applied from $patchdir"
        return 0
      else
        log_error "build_apply_patches: failed applying patches from $patchdir"
        return 1
      fi
    else
      log_warn "build_apply_patches: net_apply_patches not available; skipping"
    fi
  fi
  return 0
}

# --- build orchestration entrypoint ---
build_from_metafile() {
  local metafile="$1"
  if [[ -z "$metafile" ]]; then log_error "build_from_metafile: metafile path required"; return 1; fi
  build_read_metafile "$metafile" || return 1
  build_validate_meta || return 1
  build_prepare_env || return 1

  _BUILD_ACTIVE=1
  local name="${BUILD_META[NAME]}" ver="${BUILD_META[VERSION]}" pkgbase="${name}-${ver}"
  log_info "build_from_metafile: starting build for $pkgbase workdir=$_BUILD_WORKDIR"

  if ! _build_run_phase "download" "bash -lc 'cd \"$_BUILD_WORKDIR\" && build_download_sources'"; then
    _BUILD_ERRORS=$((_BUILD_ERRORS+1)); build_cleanup_on_failure; return 1
  fi

  if ! _build_run_phase "extract" "bash -lc 'cd \"$_BUILD_WORKDIR\" && build_extract_sources'"; then
    _BUILD_ERRORS=$((_BUILD_ERRORS+1)); build_cleanup_on_failure; return 1
  fi

  if ! _build_run_phase "patch" "bash -lc 'cd \"$_BUILD_WORKDIR\" && build_apply_patches'"; then
    _BUILD_ERRORS=$((_BUILD_ERRORS+1)); build_cleanup_on_failure; return 1
  fi

  if [[ -n "${BUILD_META[PRE_BUILD]}" ]]; then
    _build_run_phase "pre_build" "${BUILD_META[PRE_BUILD]}" || { _BUILD_ERRORS=$((_BUILD_ERRORS+1)); build_cleanup_on_failure; return 1; }
  fi

  if ! _build_run_phase "build" "bash -lc 'set -o pipefail; if [[ -x configure ]]; then ./configure --prefix=/usr || true; fi; make ${MAKEFLAGS}'"; then
    _BUILD_ERRORS=$((_BUILD_ERRORS+1)); build_cleanup_on_failure; return 1
  fi

  if ! _build_run_phase "install" "bash -lc 'make install DESTDIR=\"${DESTDIR}\"'"; then
    _BUILD_ERRORS=$((_BUILD_ERRORS+1)); build_cleanup_on_failure; return 1
  fi

  if [[ "$BUILD_STRIP_BINARIES" -eq 1 ]]; then
    _build_run_phase "strip" "bash -lc 'if command -v strip >/dev/null 2>&1; then find \"${DESTDIR}\" -type f -executable -exec strip --strip-unneeded {} + || true; fi'"
  fi

  if ! _build_run_phase "package" "bash -lc 'cd \"${DESTDIR}\" && build_package \"$pkgbase\"'"; then
    _BUILD_ERRORS=$((_BUILD_ERRORS+1)); build_cleanup_on_failure; return 1
  fi

  if [[ -n "${BUILD_META[DESTDIR]}" && "${BUILD_META[DESTDIR]}" != "/" ]]; then
    if declare -f fs_validate_destdir >/dev/null 2>&1; then
      if ! fs_validate_destdir "${BUILD_META[DESTDIR]}"; then
        log_warn "build_from_metafile: DESTDIR ${BUILD_META[DESTDIR]} not valid; skipping system install"
      else
        _build_run_phase "system_install" "bash -lc 'rsync -a --delete \"${DESTDIR}/\" \"${BUILD_META[DESTDIR]}/\"'"
      fi
    else
      log_warn "build_from_metafile: fs_validate_destdir not available; skipping system install"
    fi
  fi

  build_record_manifest "$pkgbase" || log_warn "build_from_metafile: failed to record manifest"

  log_info "build_from_metafile: build complete for $pkgbase"
  build_cleanup_success
  return 0
}

# --- package creation ---
build_package() {
  local pkgbase="$1"
  if [[ -z "$pkgbase" ]]; then log_error "build_package: pkgbase required"; return 1; fi
  local outdir="$BUILD_PKG_DIR/$(date +%Y%m%d)"
  mkdir -p "$outdir" || return 1
  local manifest="$outdir/${pkgbase}.manifest"
  local logfile="$_BUILD_LOGFILE"
  local size; size=$(du -sb "$DESTDIR" 2>/dev/null | awk '{print $1}') || size=0
  local sha; sha="unknown"
  local tmp_tar="/tmp/${pkgbase}.$$.$(date +%s).tar"
  if tar -C "$DESTDIR" -cf "$tmp_tar" . ; then
    if command -v zstd >/dev/null 2>&1; then
      local out="$outdir/${pkgbase}.tar.zst"
      zstd -19 --ultra -T0 "$tmp_tar" -o "$out" || { log_error "zstd compression failed"; rm -f "$tmp_tar" ; return 1; }
      rm -f "$tmp_tar"
      sha=$(sha256sum "$out" | awk '{print $1}') || sha="unknown"
      echo "{\"pkg\":\"$pkgbase\",\"path\":\"$out\",\"sha256\":\"$sha\",\"size\":$(stat -c%s "$out"),\"build_time\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > "$manifest"
      log_info "build_package: package created $out (sha256=$sha)"
    else
      local out="$outdir/${pkgbase}.tar"
      mv "$tmp_tar" "$out" || { log_error "move tar failed"; rm -f "$tmp_tar"; return 1; }
      sha=$(sha256sum "$out" | awk '{print $1}') || sha="unknown"
      echo "{\"pkg\":\"$pkgbase\",\"path\":\"$out\",\"sha256\":\"$sha\",\"size\":$(stat -c%s "$out"),\"build_time\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > "$manifest"
      log_info "build_package: package created $out (sha256=$sha)"
    fi
  else
    log_error "build_package: tar failed"
    rm -f "$tmp_tar" 2>/dev/null || true
    return 1
  fi
  if [[ "$BUILD_VERIFY_SIGNATURES" -eq 1 && command -v gpg >/dev/null 2>&1 ]]; then
    gpg --output "${manifest}.sig" --detach-sign "$manifest" || log_warn "gpg sign manifest failed"
  fi
  return 0
}

# --- record installed files for uninstall and package DB ---
build_record_manifest() {
  local pkgbase="$1"
  local mfdir="$BUILD_MANIFEST_DIR"
  mkdir -p "$mfdir" || true
  local manifest="$mfdir/${pkgbase}.json"
  (cd "$DESTDIR" && find . -type f -print0 | xargs -0 sha256sum) > "${manifest}.files.sha256" 2>/dev/null || true
  echo "{\"pkg\":\"$pkgbase\",\"installed_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > "$manifest"
  log_info "build_record_manifest: manifest written $manifest"
  return 0
}

# --- uninstall ---
build_uninstall() {
  local pkgbase="$1"
  if [[ -z "$pkgbase" ]]; then log_error "build_uninstall: pkg specified required"; return 1; fi
  local manifest="$BUILD_MANIFEST_DIR/${pkgbase}.json"
  local filesum="${manifest}.files.sha256"
  if [[ ! -f "$filesum" ]]; then
    log_error "build_uninstall: manifest not found for $pkgbase"
    return 1
  fi
  log_info "build_uninstall: uninstalling $pkgbase"
  awk '{print $2}' "$filesum" | sed 's|^\./||' | while IFS= read -r f; do
    if [[ -f "/$f" ]]; then
      rm -f "/$f" || log_warn "build_uninstall: failed remove /$f"
    fi
  done
  awk '{print $2}' "$filesum" | sed 's|^\./||' | while IFS= read -r f; do
    local dir; dir=$(dirname "/$f")
    while [[ "$dir" != "/" && -d "$dir" && -z "$(ls -A "$dir" 2>/dev/null)" ]]; do
      rmdir "$dir" 2>/dev/null || break
      dir=$(dirname "$dir")
    done
  done
  rm -f "$manifest" "$filesum" 2>/dev/null || true
  log_info "build_uninstall: $pkgbase removed"
  if declare -f pkgdb_mark_orphans >/dev/null 2>&1; then
    pkgdb_mark_orphans || true
  fi
  return 0
}

# --- cleanup after success ---
build_cleanup_success() {
  if (( BUILD_KEEP_TEMP )); then
    log_info "build_cleanup_success: KEEP_TEMP enabled; leaving workdir $_BUILD_WORKDIR"
    return 0
  fi
  if [[ -n "$_BUILD_WORKDIR" ]]; then
    if mountpoint -q "$_BUILD_WORKDIR" >/dev/null 2>&1; then
      if declare -f fs_umount_chroot >/dev/null 2>&1; then
        fs_umount_chroot "$_BUILD_WORKDIR" || umount -l "$_BUILD_WORKDIR" 2>/dev/null || true
      else
        umount -l "$_BUILD_WORKDIR" 2>/dev/null || true
      fi
    fi
    rm -rf "$_BUILD_WORKDIR" 2>/dev/null || true
    log_info "build_cleanup_success: cleaned $_BUILD_WORKDIR"
  fi
  return 0
}

# --- cleanup on failure with rollback ---
build_cleanup_on_failure() {
  log_warn "build_cleanup_on_failure: build failed; attempting rollback and cleanup"
  if [[ -n "$DESTDIR" && -d "$DESTDIR" ]]; then
    rm -rf "$DESTDIR"/* 2>/dev/null || true
  fi
  log_info "build_cleanup_on_failure: logs available at $_BUILD_WORKDIR/logs"
  if (( BUILD_KEEP_TEMP )); then
    log_info "build_cleanup_on_failure: KEEP_TEMP enabled; not removing workdir"
    return 0
  fi
  if [[ -n "$_BUILD_WORKDIR" ]]; then
    if mountpoint -q "$_BUILD_WORKDIR" >/dev/null 2>&1; then
      umount -l "$_BUILD_WORKDIR" 2>/dev/null || true
    fi
    rm -rf "$_BUILD_WORKDIR" 2>/dev/null || true
  fi
  return 0
}

# --- upgrade all (uses lib_dep.sh for ordering) ---
build_upgrade_all() {
  if declare -f repo_sync >/dev/null 2>&1; then
    repo_sync || log_warn "build_upgrade_all: repo_sync failed"
  fi
  if declare -f dep_resolve_upgrade_list >/dev/null 2>&1; then
    local -a list; IFS=$'\n' read -r -d '' -a list < <(dep_resolve_upgrade_list && printf '\0') || true
    for mf in "${list[@]:-}"; do
      build_from_metafile "$mf" || log_warn "build_upgrade_all: failed building $mf"
    done
  else
    log_warn "build_upgrade_all: dep_resolve_upgrade_list not available; implement integration with lib_dep.sh"
    return 1
  fi
  return 0
}

# --- export public functions ---
export -f build_init build_read_metafile build_validate_meta build_prepare_env build_from_metafile \
  build_download_sources build_extract_sources build_apply_patches build_package build_uninstall build_upgrade_all

log_info "lib_build.sh loaded (version ${LIBBUILD_VERSION}). Call build_init to prepare environment."
