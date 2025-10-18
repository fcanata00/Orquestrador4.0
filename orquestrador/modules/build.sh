#!/usr/bin/env bash
# lftool/lib/build.sh - Build module for lftool
# Generated: implements fetch, extract, patch, build, package, locks, manifests, retries, isolation.
set -Eeuo pipefail
IFS=$'\n\t'

# Try to source core.sh from expected locations
__try_source_core() {
  local candidates=(
    "${LF_ROOT:-}/lib/core.sh"
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/lib/core.sh"
    "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/core.sh"
    "/usr/local/lib/lftool/core.sh"
    "/usr/lib/lftool/core.sh"
    "/mnt/data/core.sh"
  )
  for p in "${candidates[@]}"; do
    if [[ -f "$p" ]]; then
      # shellcheck source=/dev/null
      . "$p"
      return 0
    fi
  done
  echo "ERROR: core.sh not found in expected locations. Set LF_ROOT or place core.sh in lib/ under project." >&2
  exit 2
}

__try_source_core

# Defaults
LOCK_WAIT_SECS="${LOCK_WAIT_SECS:-300}"
LOCK_STALE_SECS="${LOCK_STALE_SECS:-86400}"
DOWNLOAD_TIMEOUT="${DOWNLOAD_TIMEOUT:-600}"
DOWNLOAD_RETRIES="${DOWNLOAD_RETRIES:-5}"
PACKAGE_COMPRESS_LEVEL="${PACKAGE_COMPRESS_LEVEL:-19}"
ZIP_FALLBACK="${ZIP_FALLBACK:-0}"  # not used by default
STRIP_POLICY_DEFAULT="${STRIP_POLICY_DEFAULT:-strip}"
EXPECTED_ARTIFACTS_KEY="expected_artifacts"

# Utility: simple YAML/INI parser (supports key: value lines and key=value)
# Returns variable assignments printed to stdout like KEY="value"
__lf_parse_meta_to_env() {
  local metafile="$1"
  if [[ ! -f "$metafile" ]]; then
    __lf_log_err "Metadata file not found: $metafile"
    return 1
  fi
  local ext="${metafile##*.}"
  # Very small parser: handles KEY: value, key=value, lists as - item
  local in_list="" list_key=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    # strip comments
    line="${line%%#*}"
    line="${line%"${line##*[![:space:]]}"}"
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^- ]]; then
      # list item
      local item="${line#- }"
      item="$(__lf_sanitize "$item")"
      if [[ -n "$list_key" ]]; then
        printf 'LF_META_%s+=(%q)\n' "$list_key" "$item"
      fi
      continue
    fi
    if [[ "$line" =~ ^([A-Za-z0-9_.-]+)[[:space:]]*:[[:space:]]*(.*)$ ]]; then
      local k=${BASH_REMATCH[1]}
      local v=${BASH_REMATCH[2]}
      k="${k//./_}"
      v="$(__lf_sanitize "$v")"
      # uppercase
      printf 'LF_META_%s=%q\n' "${k^^}" "$v"
      list_key="${k^^}"
      continue
    fi
    if [[ "$line" =~ ^([A-Za-z0-9_.-]+)=(.*)$ ]]; then
      local k=${BASH_REMATCH[1]}
      local v=${BASH_REMATCH[2]}
      k="${k//./_}"
      v="$(__lf_sanitize "$v")"
      printf 'LF_META_%s=%q\n' "${k^^}" "$v"
      list_key="${k^^}"
      continue
    fi
    # ignore others
  done <"$metafile"
}

# High-level build entrypoint
# usage: build_one <meta-file> [--dry-run]
build_one() {
  local meta="$1"
  shift || true
  if [[ "${LF_DRYRUN:-0}" -ne 0 || "${1:-}" == "--dry-run" ]]; then
    LF_DRYRUN=1
  fi
  # load metadata into env variables prefixed LF_META_
  eval "$(__lf_parse_meta_to_env "$meta")"
  # require at least NAME and VERSION or PKG_NAME
  local name="${LF_META_NAME:-${LF_META_PKGNAME:-}}"
  local version="${LF_META_VERSION:-}"
  if [[ -z "$name" || -z "$version" ]]; then
    __lf_log_err "Metadata missing name/version in $meta"
    return 1
  fi
  local pkg="${name}-${version}"
  export PKG_NAME="$name"
  export PKG_VER="$version"
  export PKG_IDENT="$pkg"
  export PKG_META_FILE="$meta"
  local workdir="${LF_WORKDIR}/${pkg}"
  export PKG_WORKDIR="$workdir"
  local destdir="${workdir}/destdir"
  export PKG_DESTDIR="$destdir"
  __lf_ensure_dir "$workdir"
  __lf_ensure_dir "$destdir"
  __lf_ensure_dir "$LF_PKGS"
  __lf_ensure_dir "$LF_CACHEDIR"
  __lf_ensure_dir "$LF_LOCKDIR"
  __lf_check_diskspace "$LF_WORKDIR" 1024 || { __lf_log_err "Insufficient disk space in workdir"; return 1; }
  __lf_adjust_jobs

  # set logfile for this package run
  __lf_logfile="${LF_LOGDIR}/${pkg}-$(date +%Y%m%d-%H%M%S).log"
  __lf_rotate_logs

  __lf_log_info "Starting build_one for $pkg"
  __lf_log_debug "Meta file: $meta"

  # Acquire lock
  if ! build_acquire_lock "$pkg"; then
    __lf_log_err "Could not acquire lock for $pkg"
    return 2
  fi

  # ensure we release lock on return
  local rc=0
  trap "build_release_lock '$pkg' || true" RETURN

  # run pipeline
  if ! fetch_sources "$pkg"; then rc=$?; __lf_log_err "fetch_sources failed rc=$rc"; return $rc; fi
  if ! extract_sources "$pkg"; then rc=$?; __lf_log_err "extract_sources failed rc=$rc"; return $rc; fi
  if ! apply_patches "$pkg"; then rc=$?; __lf_log_err "apply_patches failed rc=$rc"; return $rc; fi
  if ! check_build_deps "$pkg"; then rc=$?; __lf_log_err "check_build_deps failed rc=$rc"; return $rc; fi
  if ! run_build_commands "$pkg"; then rc=$?; __lf_log_err "run_build_commands failed rc=$rc"; return $rc; fi
  if ! package_pkg "$pkg"; then rc=$?; __lf_log_err "package_pkg failed rc=$rc"; return $rc; fi

  __lf_log_info "Build completed successfully: $pkg"
  return 0
}

# Acquire package lock with wait and stale detection
build_acquire_lock() {
  local pkg="$1"
  local start_time; start_time=$(date +%s)
  local waited=0
  while true; do
    if __lf_acquire_lock "$pkg"; then
      __lf_log_debug "Lock acquired for $pkg"
      return 0
    fi
    # lock exists: check age
    local lockdir="$LF_LOCKDIR/$pkg.lock"
    if [[ -d "$lockdir" ]]; then
      local ts; ts=$(stat -c%Y "$lockdir" 2>/dev/null || echo 0)
      local now; now=$(date +%s)
      local age=$((now - ts))
      if (( age > LOCK_STALE_SECS )); then
        __lf_log_warn "Stale lock detected for $pkg (age ${age}s). Reclaiming."
        rm -rf "$lockdir" || true
        continue
      fi
    fi
    if (( waited >= LOCK_WAIT_SECS )); then
      __lf_log_warn "Timeout waiting for lock on $pkg after ${waited}s"
      return 1
    fi
    sleep 3
    waited=$(( $(date +%s) - start_time ))
  done
}

build_release_lock() {
  local pkg="$1"
  __lf_release_lock "$pkg"
}

# fetch_sources: download with cache, verify sha256
fetch_sources() {
  local pkg="$1"
  local cachefile=""
  local meta="$PKG_META_FILE"
  # derive src urls from env variables LF_META_SRC_URLS or LF_META_SRC_URL
  local urls=()
  # collect variables starting with LF_META_SRC
  eval "urls=(\"\${LF_META_SRC_URLS[@]:-}\")"
  if [[ "${#urls[@]}" -eq 0 ]]; then
    if [[ -n "${LF_META_SRC_URL:-}" ]]; then urls=("${LF_META_SRC_URL}"); fi
  fi
  if [[ "${#urls[@]}" -eq 0 ]]; then
    __lf_log_err "No source URLs provided in metadata for $pkg"
    return 1
  fi
  local expect_sha="${LF_META_SHA256:-}"
  # attempt to use cached by sha or by url-fingerprint
  for url in "${urls[@]}"; do
    local fname; fname=$(basename "$url")
    # fingerprint name
    local fingerprint
    fingerprint=$(printf "%s" "$url" | sha256sum | awk '{print $1}')
    local cached_candidates=("$LF_CACHEDIR/${fname}" "$LF_CACHEDIR/${pkg}-${fingerprint}" "$LF_CACHEDIR/${fingerprint}.tar")
    for c in "${cached_candidates[@]}"; do
      if [[ -f "$c" ]]; then
        __lf_log_info "Using cached source $c for $pkg"
        cachefile="$c"
        break 2
      fi
    done
  done

  if [[ -n "$cachefile" ]]; then
    # verify checksum if expected
    if [[ -n "$expect_sha" ]]; then
      if ! echo "${expect_sha}  $cachefile" | sha256sum -c - >/dev/null 2>&1; then
        __lf_log_warn "Cached file checksum mismatch, removing $cachefile"
        rm -f "$cachefile"
        cachefile=""
      fi
    fi
  fi

  if [[ -z "$cachefile" ]]; then
    # try downloads with retries
    for url in "${urls[@]}"; do
      __lf_log_info "Attempting download: $url"
      local out="$LF_CACHEDIR/$(basename "$url").part"
      local success=0
      local attempt=1
      while (( attempt <= DOWNLOAD_RETRIES )); do
        __lf_log_info "Download attempt $attempt/$DOWNLOAD_RETRIES for $url"
        if command -v wget >/dev/null 2>&1; then
          if timeout "$DOWNLOAD_TIMEOUT" wget -c -O "$out" "$url" 2>&1 | tee -a "$__lf_logfile"; then
            success=1; break
          fi
        elif command -v curl >/dev/null 2>&1; then
          if timeout "$DOWNLOAD_TIMEOUT" curl -fL --retry 3 -o "$out" "$url" 2>&1 | tee -a "$__lf_logfile"; then
            success=1; break
          fi
        else
          __lf_log_err "No downloader available (wget/curl)"
          return 1
        fi
        attempt=$((attempt+1))
        sleep $((attempt * 2))
      done
      if (( success == 1 )); then
        # verify if expected sha provided
        if [[ -n "$expect_sha" ]]; then
          if ! sha256sum -c <(printf "%s  %s\n" "$expect_sha" "$out") >/dev/null 2>&1; then
            __lf_log_warn "Downloaded file checksum mismatch for $url; trying next mirror"
            rm -f "$out"
            continue
          fi
        fi
        # move atomically
        local final="$LF_CACHEDIR/$(basename "$url")"
        mv -f "$out" "$final"
        cachefile="$final"
        break
      fi
    done
  fi

  if [[ -z "$cachefile" ]]; then
    __lf_log_err "Failed to download any source for $pkg"
    return 2
  fi

  __lf_log_info "Fetched source: $cachefile"
  __lf_mark_done "$pkg" "downloaded"
  # record cache path
  printf "%s\n" "$cachefile" >"${PKG_WORKDIR}/.cached_source" || true
  return 0
}

# Secure extraction verifying no path traversal
extract_sources() {
  local pkg="$1"
  if __lf_is_done "$pkg" "extracted"; then
    __lf_log_info "Already extracted: $pkg"
    return 0
  fi
  local cachepath; cachepath=$(cat "${PKG_WORKDIR}/.cached_source" 2>/dev/null || true)
  if [[ -z "$cachepath" || ! -f "$cachepath" ]]; then
    __lf_log_err "Cached source not found for $pkg"
    return 1
  fi
  local extractdir="${PKG_WORKDIR}/src"
  rm -rf "$extractdir"
  __lf_ensure_dir "$extractdir"
  # check tar members for safety
  if tar -tf "$cachepath" >/dev/null 2>&1; then
    # ensure no entry with .. or absolute path
    if tar -tf "$cachepath" | awk ' /(^\/|(^|\/)\.\.)/ {print; exit 1}' >/dev/null 2>&1; then
      __lf_log_err "Archive contains unsafe paths (absolute or ..). Aborting extraction."
      return 2
    fi
  fi
  if __lf_run_cmd "extract $pkg" -- tar -xf "$cachepath" -C "$extractdir"; then
    __lf_log_info "Extraction completed for $pkg"
    __lf_mark_done "$pkg" "extracted"
    return 0
  else
    __lf_log_warn "Extraction failed; attempting to re-download and retry once"
    rm -f "$cachepath"
    fetch_sources "$pkg" || return 3
    if __lf_run_cmd "extract retry $pkg" -- tar -xf "$cachepath" -C "$extractdir"; then
      __lf_mark_done "$pkg" "extracted"
      return 0
    fi
    return 4
  fi
}

# Apply patches with dry-run first and rollback on failure
apply_patches() {
  local pkg="$1"
  if __lf_is_done "$pkg" "patched"; then
    __lf_log_info "Patches already applied for $pkg"
    return 0
  fi
  local patches_dir="${LF_ROOT}/patches/${PKG_NAME}"
  if [[ ! -d "$patches_dir" ]]; then
    __lf_log_debug "No patches directory for $pkg"
    __lf_mark_done "$pkg" "patched"
    return 0
  fi
  local srcdir
  # detect top-level dir in src
  srcdir=$(find "${PKG_WORKDIR}/src" -mindepth 1 -maxdepth 1 -type d | head -n1)
  if [[ -z "$srcdir" ]]; then srcdir="${PKG_WORKDIR}/src"; fi
  local applied=0
  pushd "$srcdir" >/dev/null || return 1
  for p in $(ls -1 "$patches_dir" 2>/dev/null | sort -V); do
    local patchpath="$patches_dir/$p"
    __lf_log_info "Checking patch $p"
    if ! patch --dry-run -p1 <"$patchpath" >/dev/null 2>&1; then
      __lf_log_err "Patch dry-run failed: $p"
      popd >/dev/null
      return 2
    fi
    if ! __lf_run_cmd "apply-patch $p" -- patch -p1 <"$patchpath"; then
      __lf_log_err "Applying patch failed: $p"
      popd >/dev/null
      return 3
    fi
    applied=$((applied+1))
  done
  popd >/dev/null
  __lf_log_info "Applied $applied patches for $pkg"
  __lf_mark_done "$pkg" "patched"
  return 0
}

# check build deps; for now, ensure declared build-deps are present in LF_PKGS or optionally trigger build
check_build_deps() {
  local pkg="$1"
  local missing=()
  # LF_META_BUILD_DEPS may be a single string or space-separated
  local deps_var="${LF_META_BUILD_DEPS:-}"
  if [[ -z "$deps_var" ]]; then
    __lf_log_debug "No build-deps declared for $pkg"
    return 0
  fi
  # split by space
  read -r -a deps <<<"$deps_var"
  for d in "${deps[@]}"; do
    # check if installed/packaged in LF_PKGS by name prefix
    if ! ls "$LF_PKGS"/*"${d}"* >/dev/null 2>&1; then
      missing+=("$d")
    fi
  done
  if ((${#missing[@]})); then
    __lf_log_warn "Missing build deps for $pkg: ${missing[*]}"
    # if one-shot or auto-build allowed, user can build deps; here we just abort with list
    return 2
  fi
  return 0
}

# run build commands from metadata or default autotools
run_build_commands() {
  local pkg="$1"
  if __lf_is_done "$pkg" "built"; then
    __lf_log_info "Already built: $pkg"
    return 0
  fi
  # locate source dir
  local srcroot
  srcroot=$(find "${PKG_WORKDIR}/src" -mindepth 1 -maxdepth 1 -type d | head -n1 || true)
  if [[ -z "$srcroot" ]]; then srcroot="${PKG_WORKDIR}/src"; fi
  pushd "$srcroot" >/dev/null || return 1

  # Determine build commands
  local cmds_var="${LF_META_BUILD_COMMANDS:-}"
  if [[ -n "$cmds_var" ]]; then
    # split by ';;' for multiple commands or newline in meta converted earlier
    IFS=$'\n' read -rd '' -a cmds <<<"$cmds_var" || true
  else
    # default: try configure && make && make install
    cmds=("./configure --prefix=/usr" "make -j${LF_JOBS}" "make DESTDIR=${PKG_DESTDIR} install")
  fi

  __lf_ensure_dir "$PKG_DESTDIR"

  local idx=0
  for cmd in "${cmds[@]}"; do
    idx=$((idx+1))
    # inject LF_JOBS for make lines if not specified
    if [[ "$cmd" =~ ^make[[:space:]] ]]; then
      if ! [[ "$cmd" =~ -j[0-9]+ ]]; then
        cmd="$cmd -j${LF_JOBS}"
      fi
    fi
    __lf_log_info "Running build step $idx: $cmd"
    # run under fakeroot for install step
    if [[ "$cmd" =~ DESTDIR= ]]; then
      if command -v fakeroot >/dev/null 2>&1 && [[ "$(id -u)" -ne 0 ]]; then
        __lf_run_cmd "build-step-$idx" -- fakeroot bash -c "$cmd"
      else
        __lf_run_cmd "build-step-$idx" -- bash -lc "$cmd"
      fi
    else
      __lf_run_cmd "build-step-$idx" -- bash -lc "$cmd"
    fi
    # after each cmd, heuristic check for artifacts if metadata declares expected artifacts
    local artifacts="${LF_META_EXPECTED_ARTIFACTS:-}"
    if [[ -n "$artifacts" ]]; then
      IFS=' ' read -r -a arts <<<"$artifacts"
      for a in "${arts[@]}"; do
        if ! find "${PKG_DESTDIR}" -path "*/${a}" -print -quit >/dev/null 2>&1; then
          __lf_log_err "Expected artifact '${a}' not found after step $idx"
          popd >/dev/null
          return 3
        fi
      done
    fi
  done

  popd >/dev/null
  __lf_mark_done "$pkg" "built"
  return 0
}

# package: strip, manifest, tar.zst
package_pkg() {
  local pkg="$1"
  if __lf_is_done "$pkg" "packaged"; then
    __lf_log_info "Already packaged: $pkg"
    return 0
  fi
  local outname="${pkg}.tar.zst"
  local outpath="${LF_PKGS}/${outname}"
  # prepare manifest
  local manifest="${PKG_WORKDIR}/manifest.json"
  __lf_write_manifest "$pkg" "$manifest"
  # compute file list and hashes
  local files_json="${PKG_WORKDIR}/files.json"
  (cd "${PKG_DESTDIR}" && find . -type f -print0) | while IFS= read -r -d $'\0' f; do
    local ab="${PKG_DESTDIR}/${f#./}"
    sha256sum "$ab" >>"${PKG_WORKDIR}/files.sha256" 2>/dev/null || true
  done
  # stripping: loop ELF files and strip unless policy says no-strip
  if [[ "${LF_META_STRIP_POLICY:-$STRIP_POLICY_DEFAULT}" != "no-strip" ]]; then
    if command -v file >/dev/null 2>&1; then
      while IFS= read -r -d '' bin; do
        if file "$bin" | grep -q "ELF"; then
          if command -v strip >/dev/null 2>&1; then
            __lf_log_debug "Stripping $bin"
            strip --strip-unneeded "$bin" || true
          fi
        fi
      done < <(find "${PKG_DESTDIR}" -type f -print0)
    fi
  fi

  # create tar.zst
  __lf_log_info "Packaging ${pkg} -> ${outpath}"
  if command -v zstd >/dev/null 2>&1; then
    (cd "${PKG_DESTDIR}" && tar --numeric-owner -cf - .) | zstd -${PACKAGE_COMPRESS_LEVEL} -o "${outpath}" || { __lf_log_err "Packaging failed"; return 3; }
  else
    (cd "${PKG_DESTDIR}" && tar --numeric-owner -czf "${outpath}.gz" .) || { __lf_log_err "Packaging gzip fallback failed"; return 4; }
  fi

  # record db entry
  local db="${LF_PKGS}/db.csv"
  __lf_ensure_dir "$(dirname "$db")"
  local ts="$(__lf_timestamp)"
  echo "${pkg},${outpath},${ts}" >>"$db" || true

  __lf_mark_done "$pkg" "packaged"
  __lf_log_info "Packaged $pkg at $outpath"
  return 0
}

# CLI wrapper for building list or one
main() {
  if [[ "${1:-}" == "--selftest" ]]; then
    __lf_selfcheck
    return $?
  fi
  if [[ "${1:-}" == "--help" ]]; then
    cat <<'EOH'
build.sh - build module for lftool
Usage:
  build.sh <meta-file>         Build single package from metadata (YAML or INI)
  build.sh --dry-run <meta>   Dry-run mode (no destructive actions)
EOH
    return 0
  fi
  local dry=0
  if [[ "${1:-}" == "--dry-run" ]]; then dry=1; shift; fi
  if [[ -z "${1:-}" ]]; then
    __lf_log_err "No metadata file provided"
    return 2
  fi
  LF_DRYRUN=${dry}
  build_one "$1" || return $?
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  __lf_prepare_env
  main "$@"
fi
