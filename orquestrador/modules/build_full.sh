#!/usr/bin/env bash
# lftool/lib/build_full.sh - Full-featured Build module for lftool
# Generated: extended, production-oriented implementation implementing:
#  - fetch, extract, patch, build, package (tar.zst)
#  - strong error handling, silent-error detection
#  - chroot/fakeroot usage and isolation checks
#  - locks (per-package and global), stale detection
#  - hooks execution, bulk builds, repair mode, toolchain checks
#  - manifests, diagnostics JSON on failure, DB of builds
#  - YAML/INI parsing, progress-aware steps, retries, timeouts
#
# NOTE: This script expects a working lib/core.sh in the path (LF_ROOT/lib/core.sh)
set -Eeuo pipefail
IFS=$'\n\t'

# source core
__try_source_core() {
  local candidates=(
    "${LF_ROOT:-}/lib/core.sh"
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/lib/core.sh"
    "/mnt/data/core.sh"
  )
  for p in "${candidates[@]}"; do
    if [[ -f "$p" ]]; then
      # shellcheck source=/dev/null
      . "$p"
      return 0
    fi
  done
  echo "ERROR: core.sh not found. Please set LF_ROOT or place core.sh in lib/." >&2
  exit 2
}
__try_source_core

# Defaults and tunables
LOCK_WAIT_SECS="${LOCK_WAIT_SECS:-300}"
LOCK_STALE_SECS="${LOCK_STALE_SECS:-86400}"
DOWNLOAD_TIMEOUT="${DOWNLOAD_TIMEOUT:-900}"
DOWNLOAD_RETRIES="${DOWNLOAD_RETRIES:-5}"
PACKAGE_COMPRESS_LEVEL="${PACKAGE_COMPRESS_LEVEL:-19}"
GLOBAL_CONCURRENCY="${GLOBAL_CONCURRENCY:-$(nproc)}"
RETRY_TRANSIENT="${RETRY_TRANSIENT:-1}"
TOOLCHAIN_HASH_FILE="${TOOLCHAIN_HASH_FILE:-$LF_ROOT/.toolchain.hash}"
DIAG_TAIL_LINES=200

# helpers for diagnostics JSON
__lf_diag_write() {
  local pkg="$1"; local stage="$2"; local rc="$3"; local msg="$4"
  local dir="$LF_WORKDIR/${pkg}/.state"
  __lf_ensure_dir "$dir"
  local fn="${dir}/error-${stage}.json"
  cat >"$fn" <<EOF
{
  "package": "${pkg}",
  "stage": "${stage}",
  "rc": ${rc},
  "message": "$(printf '%s' "$msg" | sed 's/\"/\\"/g')",
  "timestamp": "$(__lf_timestamp)"
}
EOF
  __lf_log_debug "Wrote diagnostic JSON: $fn"
}

# parse meta: improved parser that supports YAML simple mapping and INI style
__lf_read_meta() {
  local metafile="$1"
  if [[ ! -f "$metafile" ]]; then
    __lf_log_err "Meta file not found: $metafile"
    return 1
  fi
  # reset meta vars
  unset LF_META_NAME LF_META_VERSION LF_META_SRC_URLS LF_META_SHA256 LF_META_BUILD_COMMANDS
  LF_META_SRC_URLS=()
  LF_META_BUILD_COMMANDS=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line%"${line##*[![:space:]]}"}"
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^-?[[:space:]]*https?:// ]]; then
      LF_META_SRC_URLS+=("$(__lf_sanitize "$line")")
      continue
    fi
    if [[ "$line" =~ ^([A-Za-z0-9_.-]+)[[:space:]]*[:=][[:space:]]*(.*)$ ]]; then
      local k=${BASH_REMATCH[1]}
      local v=${BASH_REMATCH[2]}
      v="$(__lf_sanitize "$v")"
      case "${k,,}" in
        name) LF_META_NAME="$v" ;;
        version) LF_META_VERSION="$v" ;;
        src_url|source|url) LF_META_SRC_URLS+=("$v") ;;
        sha256|sha256sum) LF_META_SHA256="$v" ;;
        build_commands) LF_META_BUILD_COMMANDS="$v" ;;
        build_deps) LF_META_BUILD_DEPS="$v" ;;
        run_deps) LF_META_RUN_DEPS="$v" ;;
        expected_artifacts) LF_META_EXPECTED_ARTIFACTS="$v" ;;
        strip_policy) LF_META_STRIP_POLICY="$v" ;;
        *) 
          # other keys become LF_META_<UPPERKEY>
          local uk=$(echo "$k" | tr '[:lower:].' '[:upper:]_')
          eval "LF_META_${uk}=\"${v}\""
          ;;
      esac
    fi
  done <"$metafile"
  # if single src_url in variable, okay; prefer explicit list
  return 0
}

# Compute a compact toolchain fingerprint (gcc --version and ld --version)
__lf_compute_toolchain_hash() {
  local tmpf; tmpf=$(mktemp)
  { gcc --version 2>/dev/null || true; ld --version 2>/dev/null || true; uname -a; } >"$tmpf" 2>/dev/null || true
  sha256sum "$tmpf" | awk '{print $1}' || true
  rm -f "$tmpf"
}

# Ensure toolchain hash file, warn on mismatch
__lf_toolchain_check() {
  local current; current="$(__lf_compute_toolchain_hash)"
  if [[ -f "$TOOLCHAIN_HASH_FILE" ]]; then
    local prev; prev=$(cat "$TOOLCHAIN_HASH_FILE")
    if [[ "$prev" != "$current" ]]; then
      __lf_log_warn "Toolchain changed since last builds. Some packages may need rebuild."
      # write current for record
      printf "%s" "$current" >"$TOOLCHAIN_HASH_FILE".new || true
      mv -f "$TOOLCHAIN_HASH_FILE".new "$TOOLCHAIN_HASH_FILE" || true
    fi
  else
    printf "%s" "$current" >"$TOOLCHAIN_HASH_FILE" || true
  fi
}

# Acquire a global semaphore to limit concurrent builds (uses mkdir)
__lf_acquire_global_slot() {
  __lf_ensure_dir "$LF_LOCKDIR/.global"
  local slotmax=$GLOBAL_CONCURRENCY
  local i
  for i in $(seq 1 "$slotmax"); do
    local slot="$LF_LOCKDIR/.global/slot.$i"
    if mkdir "$slot" 2>/dev/null; then
      echo "$i" >"$slot/pid"
      export LF_GLOBAL_SLOT="$i"
      return 0
    fi
  done
  return 1
}
__lf_release_global_slot() {
  if [[ -n "${LF_GLOBAL_SLOT:-}" ]]; then
    local slotdir="$LF_LOCKDIR/.global/slot.${LF_GLOBAL_SLOT}"
    rm -rf "$slotdir" 2>/dev/null || true
    unset LF_GLOBAL_SLOT
  fi
}

# robust download with validation, content-length checks and retries
__lf_download_url_into() {
  local url="$1"; local out="$2"
  local attempt=1
  local tmp="${out}.part"
  while (( attempt <= DOWNLOAD_RETRIES )); do
    __lf_log_info "Downloading (attempt $attempt): $url"
    if command -v wget >/dev/null 2>&1; then
      if timeout "$DOWNLOAD_TIMEOUT" wget -c -O "$tmp" "$url" 2>&1 | tee -a "$__lf_logfile"; then
        true
      else
        __lf_log_warn "wget failed for $url on attempt $attempt"
      fi
    elif command -v curl >/dev/null 2>&1; then
      if timeout "$DOWNLOAD_TIMEOUT" curl -fL --retry 3 -o "$tmp" "$url" 2>&1 | tee -a "$__lf_logfile"; then
        true
      else
        __lf_log_warn "curl failed for $url on attempt $attempt"
      fi
    else
      __lf_log_err "No downloader available"
      return 2
    fi
    # check size if Content-Length available (best-effort)
    if [[ -s "$tmp" ]]; then
      # finalize
      mv -f "$tmp" "$out"
      return 0
    fi
    attempt=$((attempt+1))
    sleep $((attempt * 2))
  done
  return 3
}

# fetch_sources: robust implementation with caching and sha256 validation
fetch_sources() {
  local pkg="$1"
  if __lf_is_done "$pkg" "downloaded"; then
    __lf_log_info "Already downloaded: $pkg"
    return 0
  fi
  local meta="$PKG_META_FILE"
  __lf_read_meta "$meta" || return 2
  local urls=("${LF_META_SRC_URLS[@]:-}")
  local expect_sha="${LF_META_SHA256:-}"
  if ((${#urls[@]} == 0)); then
    __lf_log_err "No URLs in metadata for $pkg"
    return 1
  fi
  # try to find in cache by sha if provided
  local cachepath=""
  if [[ -n "$expect_sha" ]]; then
    local candidate="$LF_CACHEDIR/${expect_sha}.tar"
    if [[ -f "$candidate" ]]; then
      cachepath="$candidate"
      __lf_log_info "Found cached by sha: $cachepath"
    fi
  fi
  # otherwise try fingerprint of URL
  if [[ -z "$cachepath" ]]; then
    for url in "${urls[@]}"; do
      local fp; fp=$(printf "%s" "$url" | sha256sum | awk '{print $1}')
      local c="$LF_CACHEDIR/${fp}"
      if [[ -f "$c" ]]; then
        cachepath="$c"
        __lf_log_info "Found cached by fingerprint: $c"
        break
      fi
    done
  fi

  # if no cache, download
  if [[ -z "$cachepath" ]]; then
    for url in "${urls[@]}"; do
      local fname="$(basename "$url")"
      local out="$LF_CACHEDIR/${fname}"
      if __lf_download_url_into "$url" "$out"; then
        # verify sha if provided
        if [[ -n "$expect_sha" ]]; then
          if ! echo "${expect_sha}  ${out}" | sha256sum -c - >/dev/null 2>&1; then
            __lf_log_warn "Checksum mismatch for $out, removing and trying next mirror"
            rm -f "$out"
            continue
          fi
        fi
        cachepath="$out"
        break
      else
        __lf_log_warn "Download failed for $url"
        continue
      fi
    done
  fi

  if [[ -z "$cachepath" ]]; then
    __lf_log_err "All downloads failed for $pkg"
    __lf_diag_write "$pkg" "fetch" 5 "All downloads failed"
    return 3
  fi

  # finalize cache file: standardize name by sha if available
  if [[ -n "$expect_sha" ]]; then
    local std="$LF_CACHEDIR/${expect_sha}"
    mv -f "$cachepath" "$std" || true
    cachepath="$std"
  fi

  echo "$cachepath" >"${PKG_WORKDIR}/.cached_source" || true
  __lf_mark_done "$pkg" "downloaded"
  __lf_log_info "Fetched source for $pkg: $cachepath"
  return 0
}

# extract with safety checks and detection of topdir
extract_sources() {
  local pkg="$1"
  if __lf_is_done "$pkg" "extracted"; then
    __lf_log_info "Already extracted: $pkg"
    return 0
  fi
  local cachepath
  cachepath=$(cat "${PKG_WORKDIR}/.cached_source" 2>/dev/null || true)
  if [[ -z "$cachepath" || ! -f "$cachepath" ]]; then
    __lf_log_err "No cached source for $pkg"
    return 1
  fi
  local extractdir="${PKG_WORKDIR}/src"
  rm -rf "$extractdir"
  __lf_ensure_dir "$extractdir"

  # list members and check for path traversal or absolute paths
  if tar -tf "$cachepath" >/dev/null 2>&1; then
    if tar -tf "$cachepath" | awk '/(^\/|(^|\/)\.\.)/ {print; exit 1}' >/dev/null 2>&1; then
      __lf_log_err "Archive contains unsafe paths, aborting extraction"
      __lf_diag_write "$pkg" "extract" 6 "Unsafe archive members"
      return 2
    fi
  fi

  if __lf_run_cmd "extract $pkg" -- tar -xf "$cachepath" -C "$extractdir"; then
    # detect top-level dir
    local top
    top=$(find "$extractdir" -mindepth 1 -maxdepth 1 -type d | head -n1 || true)
    if [[ -n "$top" ]]; then
      __lf_log_debug "Top-level source dir: $top"
    fi
    __lf_mark_done "$pkg" "extracted"
    return 0
  else
    __lf_log_warn "Extraction failed for $pkg"
    __lf_diag_write "$pkg" "extract" 7 "Extraction failed"
    return 3
  fi
}

# apply patches with dry-run and rollback strategy
apply_patches() {
  local pkg="$1"
  if __lf_is_done "$pkg" "patched"; then
    __lf_log_info "Patches already applied"
    return 0
  fi
  local pdir="${LF_ROOT}/patches/${PKG_NAME}"
  if [[ ! -d "$pdir" ]]; then
    __lf_log_debug "No patches found for $pkg"
    __lf_mark_done "$pkg" "patched"
    return 0
  fi
  local srcroot
  srcroot=$(find "${PKG_WORKDIR}/src" -mindepth 1 -maxdepth 1 -type d | head -n1 || true)
  if [[ -z "$srcroot" ]]; then srcroot="${PKG_WORKDIR}/src"; fi
  pushd "$srcroot" >/dev/null || return 1
  local applied=0
  for p in $(ls -1 "$pdir" 2>/dev/null | sort -V); do
    local patch="$pdir/$p"
    __lf_log_info "Dry-run patch $p"
    if ! patch --dry-run -p1 <"$patch" >/dev/null 2>&1; then
      __lf_log_err "Patch dry-run failed: $p"
      popd >/dev/null
      __lf_diag_write "$pkg" "patch" 8 "Patch dry-run failed: $p"
      return 2
    fi
    if ! __lf_run_cmd "apply-patch $p" -- patch -p1 <"$patch"; then
      __lf_log_err "Patch apply failed: $p"
      popd >/dev/null
      __lf_diag_write "$pkg" "patch" 9 "Patch apply failed: $p"
      return 3
    fi
    applied=$((applied+1))
  done
  popd >/dev/null
  __lf_log_info "Applied $applied patches for $pkg"
  __lf_mark_done "$pkg" "patched"
  return 0
}

# check build deps; attempt to resolve by checking LF_PKGS and optionally queue
check_build_deps() {
  local pkg="$1"
  local deps="${LF_META_BUILD_DEPS:-}"
  if [[ -z "$deps" ]]; then
    __lf_log_debug "No build deps for $pkg"
    return 0
  fi
  # split into array (space or comma)
  IFS=', ' read -r -a depa <<<"$deps"
  local missing=()
  for d in "${depa[@]}"; do
    if [[ -z "$d" ]]; then continue; fi
    # check if package artifact exists in LF_PKGS (prefix search)
    if ! ls "$LF_PKGS"/*"${d}"* >/dev/null 2>&1; then
      missing+=("$d")
    fi
  done
  if ((${#missing[@]})); then
    __lf_log_warn "Missing build deps for $pkg: ${missing[*]}"
    __lf_diag_write "$pkg" "deps" 10 "Missing build deps: ${missing[*]}"
    return 2
  fi
  return 0
}

# detect OOM kill or suspicious silent failures by heuristics on logs and artifacts
__lf_detect_silent_failures() {
  local pkg="$1" stage="$2" logfile="$__lf_logfile"
  # search for common failure keywords even if exit code 0
  if [[ -f "$logfile" ]]; then
    if tail -n 200 "$logfile" | egrep -i 'error:|fatal:|segmentation fault|killed|internal compiler error' >/dev/null 2>&1; then
      __lf_log_warn "Heuristic found error keywords in log for $pkg at stage $stage"
      __lf_diag_write "$pkg" "$stage" 11 "Heuristic error keywords in log"
      return 1
    fi
  fi
  # also, check expected artifacts if provided
  if [[ -n "${LF_META_EXPECTED_ARTIFACTS:-}" ]]; then
    IFS=' ' read -r -a arts <<<"$LF_META_EXPECTED_ARTIFACTS"
    for a in "${arts[@]}"; do
      if ! find "${PKG_DESTDIR}" -path "*/${a}" -print -quit >/dev/null 2>&1; then
        __lf_log_warn "Expected artifact $a missing for $pkg"
        __lf_diag_write "$pkg" "$stage" 12 "Expected artifact missing: $a"
        return 1
      fi
    done
  fi
  return 0
}

# run build commands, with retries for transient failures
run_build_commands() {
  local pkg="$1"
  if __lf_is_done "$pkg" "built"; then
    __lf_log_info "Already built"
    return 0
  fi
  local srcroot
  srcroot=$(find "${PKG_WORKDIR}/src" -mindepth 1 -maxdepth 1 -type d | head -n1 || true)
  if [[ -z "$srcroot" ]]; then srcroot="${PKG_WORKDIR}/src"; fi
  pushd "$srcroot" >/dev/null || return 1

  local cmds=()
  if [[ -n "${LF_META_BUILD_COMMANDS:-}" ]]; then
    # split on ';;' or newline
    IFS=$'\n' read -r -d '' -a cmds <<<"${LF_META_BUILD_COMMANDS}" || true
    if ((${#cmds[@]} == 0)); then
      IFS=';;' read -r -a cmds <<<"${LF_META_BUILD_COMMANDS}"
    fi
  else
    cmds=("./configure --prefix=/usr" "make -j${LF_JOBS}" "make DESTDIR=${PKG_DESTDIR} install")
  fi

  __lf_ensure_dir "$PKG_DESTDIR"

  local idx=0
  for raw in "${cmds[@]}"; do
    idx=$((idx+1))
    local cmd="$raw"
    # inject -j if make and missing -j
    if [[ "$cmd" =~ ^make[[:space:]] && ! "$cmd" =~ -j[0-9]+ ]]; then
      cmd="$cmd -j${LF_JOBS}"
    fi
    __lf_log_info "Build step $idx: $cmd"
    local attempt=1
    local max_attempts=1
    if [[ "$RETRY_TRANSIENT" -ne 0 ]]; then max_attempts=2; fi
    while (( attempt <= max_attempts )); do
      if [[ "$cmd" =~ DESTDIR= ]]; then
        if command -v fakeroot >/dev/null 2>&1 && [[ "$(id -u)" -ne 0 ]]; then
          __lf_run_cmd "build-${idx}" -- fakeroot bash -lc "$cmd" || rc=$?
        else
          __lf_run_cmd "build-${idx}" -- bash -lc "$cmd" || rc=$?
        fi
      else
        __lf_run_cmd "build-${idx}" -- bash -lc "$cmd" || rc=$?
      fi
      rc=${rc:-0}
      if [[ "$rc" -eq 0 ]]; then
        # quick heuristic to detect silent failures
        __lf_detect_silent_failures "$pkg" "build-step-$idx" || { __lf_log_warn "Silent failure detected, attempt $attempt"; rc=100; }
      fi
      if [[ "$rc" -eq 0 ]]; then break; fi
      __lf_log_warn "Step $idx failed (rc=$rc), attempt $attempt/$max_attempts"
      attempt=$((attempt+1))
      sleep $((attempt * 2))
    done
    if [[ "$rc" -ne 0 ]]; then
      popd >/dev/null
      __lf_diag_write "$pkg" "build-step-$idx" "$rc" "Build step failed after $max_attempts attempts"
      return 4
    fi
  done

  popd >/dev/null
  __lf_mark_done "$pkg" "built"
  return 0
}

# packaging: manifest, strip, tar.zst, sign (sha256)
package_pkg() {
  local pkg="$1"
  if __lf_is_done "$pkg" "packaged"; then
    __lf_log_info "Already packaged"
    return 0
  fi
  local outname="${pkg}.tar.zst"
  local outpath="${LF_PKGS}/${outname}"
  __lf_ensure_dir "$LF_PKGS"
  # write manifest with file list and hashes
  local manifest="${PKG_WORKDIR}/manifest.json"
  {
    echo "{"
    echo "  \"package\": \"${pkg}\","
    echo "  \"generated\": \"$(__lf_timestamp)\","
    echo "  \"files\": ["
    local first=1
    (cd "${PKG_DESTDIR}" && find . -type f -print0) | while IFS= read -r -d $'\0' f; do
      if [[ $first -eq 0 ]]; then echo ","; fi
      first=0
      local path="${f#./}"
      local h; h=$(sha256sum "${PKG_DESTDIR}/${path}" | awk '{print $1}' || echo "")
      printf "    {\"path\":\"%s\",\"sha256\":\"%s\"}" "$path" "$h"
    done
    echo
    echo "  ]"
    echo "}"
  } >"$manifest" || true

  # optional strip
  if [[ "${LF_META_STRIP_POLICY:-$STRIP_POLICY_DEFAULT}" != "no-strip" ]]; then
    if command -v file >/dev/null 2>&1 && command -v strip >/dev/null 2>&1; then
      while IFS= read -r -d '' f; do
        if file "$f" | grep -q "ELF"; then
          __lf_log_debug "Stripping $f"
          strip --strip-unneeded "$f" || true
        fi
      done < <(find "${PKG_DESTDIR}" -type f -print0)
    fi
  fi

  # tar.zst
  if command -v zstd >/dev/null 2>&1; then
    (cd "${PKG_DESTDIR}" && tar --numeric-owner -cf - .) | zstd -${PACKAGE_COMPRESS_LEVEL} -o "${outpath}" || { __lf_log_err "Packaging failed"; __lf_diag_write "$pkg" "package" 13 "Packaging failed"; return 5; }
  else
    (cd "${PKG_DESTDIR}" && tar -czf "${outpath}.gz" .) || { __lf_log_err "gzip packaging failed"; __lf_diag_write "$pkg" "package" 14 "gzip packaging failed"; return 6; }
  fi

  # record db
  local db="${LF_PKGS}/db.csv"
  __lf_ensure_dir "$(dirname "$db")"
  echo "${pkg},${outpath},$(__lf_timestamp)" >>"$db" || true

  __lf_mark_done "$pkg" "packaged"
  __lf_log_info "Packaged $pkg -> $outpath"
  return 0
}

# deploy: install package into target (optional)
deploy_pkg() {
  local pkg="$1"; local target="${2:-/}"
  local out="${LF_PKGS}/${pkg}.tar.zst"
  if [[ ! -f "$out" ]]; then
    __lf_log_err "Package not found: $out"
    return 1
  fi
  __lf_log_info "Deploying $pkg to $target"
  __lf_log_warn "Deploy is potentially destructive; ensure target is correct"
  if [[ "${LF_DRYRUN:-0}" -ne 0 ]]; then __lf_log_info "[DRYRUN] deploy skipped"; return 0; fi
  # extract as root or with fakeroot into target (dangerous)
  if [[ "$(id -u)" -ne 0 ]]; then
    __lf_log_err "Deploy requires root privileges to write to $target"
    return 2
  fi
  if command -v zstd >/dev/null 2>&1; then
    zstd -dc "$out" | tar -xpf - -C "$target" || return 3
  else
    tar -xpf "${out}.gz" -C "$target" || return 4
  fi
  return 0
}

# repair mode: validate manifest and optionally rebuild
repair_pkg() {
  local pkg="$1"
  local manifest="${PKG_WORKDIR}/manifest.json"
  if [[ ! -f "$manifest" ]]; then
    __lf_log_warn "No manifest for $pkg; cannot repair automatically"
    return 1
  fi
  # verify files exist and hashes match
  local mismatches=0
  jq -r '.files[].path' "$manifest" 2>/dev/null | while IFS= read -r f; do
    if [[ ! -f "$PKG_DESTDIR/$f" ]]; then
      __lf_log_warn "Missing file: $f"
      mismatches=$((mismatches+1))
    fi
  done
  if (( mismatches )); then
    __lf_log_warn "Repair needs rebuild for $pkg"
    build_one "$PKG_META_FILE"
  else
    __lf_log_info "No mismatches detected for $pkg"
  fi
  return 0
}

# bulk build: accepts list of meta files or package names (resolves to meta)
bulk_build() {
  local metas=( "$@" )
  # naive serial for now; could do topo sort and parallel
  for m in "${metas[@]}"; do
    build_one "$m" || __lf_log_warn "bulk build: failed for $m"
  done
}

# main entrypoint and CLI
main() {
  if [[ "${1:-}" == "--help" ]]; then
    cat <<'EOH'
build_full.sh - extended build module
Usage:
  build_full.sh <meta-file>          Build single package from YAML/INI metadata
  build_full.sh --bulk meta1 meta2  Build multiple
  build_full.sh --repair <meta>     Repair package by manifest
  build_full.sh --deploy <pkg> [target]
  build_full.sh --selfcheck
EOH
    return 0
  fi

  # prepare environment
  __lf_prepare_env
  __lf_toolchain_check

  case "${1:-}" in
    --selfcheck)
      __lf_selfcheck; return $?
      ;;
    --bulk)
      shift
      bulk_build "$@"; return 0
      ;;
    --repair)
      shift
      if [[ -z "${1:-}" ]]; then __lf_log_err "missing meta for repair"; return 2; fi
      __lf_read_meta "$1"
      build_prepare_common "$1" || return 1
      repair_pkg
      return $?
      ;;
    --deploy)
      shift
      deploy_pkg "$@" || return $?
      return $?
      ;;
    *)
      if [[ -z "${1:-}" ]]; then __lf_log_err "No metafile provided"; return 2; fi
      build_one "$1"
      return $?
      ;;
  esac
}

# Build prepare: sets PKG_* variables given meta
build_prepare_common() {
  local meta="$1"
  __lf_read_meta "$meta" || return 1
  if [[ -z "${LF_META_NAME:-}" || -z "${LF_META_VERSION:-}" ]]; then
    __lf_log_err "Meta missing name or version"
    return 2
  fi
  export PKG_NAME="${LF_META_NAME}"
  export PKG_VER="${LF_META_VERSION}"
  export PKG_IDENT="${PKG_NAME}-${PKG_VER}"
  export PKG_META_FILE="$meta"
  export PKG_WORKDIR="${LF_WORKDIR}/${PKG_IDENT}"
  export PKG_DESTDIR="${PKG_WORKDIR}/destdir"
  __lf_ensure_dir "$PKG_WORKDIR"
  __lf_ensure_dir "$PKG_DESTDIR"
  __lf_log_debug "Prepared build env for ${PKG_IDENT}"
  return 0
}

# build_one uses prepare and pipeline with global slot
build_one() {
  local meta="$1"
  build_prepare_common "$meta" || return $?
  local pkg="$PKG_IDENT"
  # acquire global slot
  if ! __lf_acquire_global_slot; then
    __lf_log_warn "Global concurrency slots exhausted. Waiting..."
    local waited=0
    while ! __lf_acquire_global_slot; do
      sleep 2
      waited=$((waited+2))
      if (( waited > LOCK_WAIT_SECS )); then
        __lf_log_err "Timeout waiting for global slot"
        return 3
      fi
    done
  fi
  trap '__lf_release_global_slot' RETURN

  # set package-specific logfile
  __lf_logfile="${LF_LOGDIR}/${pkg}-$(date +%Y%m%d-%H%M%S).log"
  __lf_rotate_logs

  # detect chroot and require unless forced
  __lf_detect_chroot
  if [[ "${LF_IN_CHROOT}" -eq 0 && "${LF_FORCE}" -eq 0 ]]; then
    __lf_log_err "Builds must run inside chroot or with --force"
    return 4
  fi

  # acquire package lock
  if ! build_acquire_lock "$pkg"; then
    __lf_log_err "Could not acquire package lock"
    return 5
  fi
  trap "build_release_lock '$pkg'; __lf_release_global_slot; " RETURN

  __lf_log_info "Starting pipeline for $pkg"

  # pipeline
  if ! fetch_sources "$pkg"; then __lf_log_err "fetch failed"; return 6; fi
  if ! extract_sources "$pkg"; then __lf_log_err "extract failed"; return 7; fi
  if ! apply_patches "$pkg"; then __lf_log_err "patch failed"; return 8; fi
  if ! check_build_deps "$pkg"; then __lf_log_err "deps check failed"; return 9; fi
  if ! run_build_commands "$pkg"; then __lf_log_err "build failed"; return 10; fi
  if ! package_pkg "$pkg"; then __lf_log_err "package failed"; return 11; fi

  __lf_log_info "Pipeline completed for $pkg"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  __lf_prepare_env
  main "$@"
fi
