#!/usr/bin/env bash
# lib_net.sh - Network / downloader module for LFS Ports
# Version: 1.0
# Features:
#  - net_init / net_check_tools
#  - parallel downloads (aria2c or curl fallback) with worker pool
#  - integrity verification (sha256/sha512)
#  - git mirror/cache and clone-from-mirror
#  - progress integration (uses lib_common progress_start/progress_update/progress_end if available)
#  - cache compression (zstd) and cleaning
#  - robust error handling, retries, exponential backoff
#  - audit trail (JSONL) and metrics logging
#  - offline mode, dry-run, silent modes
#
# Dependencies (recommended): bash>=4, curl, git, sha256sum, sha512sum (optional), zstd (optional), aria2c (optional), pv (optional)
#
# Usage:
#   source lib_common.sh   # recommended (for log_info, safe_run, with_lock, progress functions)
#   source lib_net.sh
#   net_init
#   net_download_one "https://example.org/foo.tar.gz" "expectedsha256" "foo.tar.gz"
#
set -o errtrace
set -o pipefail

# -------- Configuration (override before calling net_init) ----------------
: "${NET_CACHE_DIR:=/var/cache/lfsports/sources}"
: "${NET_ARCHIVES_DIR:=$NET_CACHE_DIR/archives}"
: "${NET_GIT_DIR:=$NET_CACHE_DIR/git}"
: "${NET_PATCHES_DIR:=$NET_CACHE_DIR/patches}"
: "${NET_TMP_DIR:=$NET_CACHE_DIR/tmp}"
: "${NET_AUDIT_DIR:=$NET_CACHE_DIR/audit}"
: "${NET_PARALLEL:=4}"
: "${NET_CONNECT_TIMEOUT:=15}"
: "${NET_MAX_RETRIES:=6}"
: "${NET_BACKOFF_BASE:=2}"
: "${NET_BACKOFF_MAX:=60}"
: "${NET_USER:=lfsbuild}"
: "${NET_BANDWIDTH_LIMIT:=0}"   # e.g. "500K" or "1M"; 0 = disabled
: "${NET_OFFLINE:=0}"
: "${NET_STRICT_SSL:=1}"
: "${NET_USE_ARIA2:=1}"
: "${NET_SILENT:=0}"
: "${NET_FAIL_SOFT:=0}"        # continue on failure when many downloads
: "${NET_CLEAN_AGE_DAYS:=120}"
: "${NET_COMPRESS_OLD:=1}"
# -------------------------------------------------------------------------

_NET_INITED=0

# Fallbacks if lib_common functions missing
if ! declare -f log_info >/dev/null 2>&1; then
  log_info(){ printf '[%s] [INFO] %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*"; }
  log_warn(){ printf '[%s] [WARN] %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*"; }
  log_error(){ printf '[%s] [ERROR] %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*"; }
fi
if ! declare -f safe_run >/dev/null 2>&1; then
  safe_run(){ "$@"; return $?; }
fi
if ! declare -f with_lock >/dev/null 2>&1; then
  with_lock(){
    local name="$1"; shift
    local lock="/tmp/net-lock-${name}.lock"
    exec 9>"$lock"
    if ! flock -n 9; then
      log_info "with_lock: waiting for lock $lock"
      flock 9 || true
    fi
    "$@"
    local rc=$?
    flock -u 9
    return $rc
  }
fi

_net_mkdir_p() { mkdir -p "$1" 2>/dev/null || return 1; }

# --- Audit trail for network operations
net_audit_write() {
  # net_audit_write <event> <url_or_target> <json-details>
  local ev="$1"; local target="$2"; local details="$3"
  _net_mkdir_p "$NET_AUDIT_DIR"
  local file="$NET_AUDIT_DIR/net-$(date +%Y-%m-%d).jsonl"
  local ts; ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  # escape quotes in details
  local d; d=$(printf '%s' "$details" | awk 'BEGIN{gsub("\n","\\n")} {gsub(/"/,"\\\""); print}')
  printf '{"ts":"%s","event":"%s","target":"%s","pid":%s,"user":"%s","details":"%s"}\n' \
    "$ts" "$ev" "$target" "$$" "$(id -un 2>/dev/null || echo unknown)" "$d" >> "$file"
  if [[ "$NET_SILENT" -eq 0 ]]; then
    log_info "NET AUDIT: $ev $target"
  fi
}

# --- Tool checks
net_check_tools() {
  local missing=0
  local need=(curl git sha256sum)
  for cmd in "${need[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      log_warn "net_check_tools: missing $cmd"
      missing=1
    fi
  done
  if [[ "$NET_USE_ARIA2" -eq 1 && -z "$(command -v aria2c 2>/dev/null)" ]]; then
    log_info "net_check_tools: aria2c not found, falling back to curl/wget"
    NET_USE_ARIA2=0
  fi
  _NET_INITED=1
  return $missing
}

# --- Init
net_init() {
  if (( _NET_INITED )); then return 0; fi
  _net_mkdir_p "$NET_ARCHIVES_DIR" "$NET_GIT_DIR" "$NET_PATCHES_DIR" "$NET_TMP_DIR" "$NET_AUDIT_DIR"
  chmod 750 "$NET_CACHE_DIR" 2>/dev/null || true
  net_check_tools
  log_info "net_init: cache=$NET_CACHE_DIR parallel=$NET_PARALLEL tmp=$NET_TMP_DIR"
}

# --- helpers for checksums and cache paths
_net_ext_from_url() {
  local url="$1"
  # try to extract extension from URL path
  local path="${url##*/}"
  if [[ "$path" == *.* ]]; then
    echo "${path##*.}"
  else
    echo "bin"
  fi
}

net_get_cached() {
  # net_get_cached <sha256>
  local sha="$1"
  [[ -z "$sha" ]] && return 1
  local f="$NET_ARCHIVES_DIR/$sha"
  # try with known extensions
  for ext in tgz tar.gz tar.xz tar.zst zip txz tbz2 gz bz2 bin; do
    if [[ -f "${f}.${ext}" ]]; then
      echo "${f}.${ext}"
      return 0
    fi
  done
  if [[ -f "$f" ]]; then echo "$f"; return 0; fi
  return 1
}

# verify integrity
net_verify_integrity() {
  # net_verify_integrity <file> <expected_hash> [algo]
  local file="$1"; local expected="$2"; local algo="${3:-sha256}"
  if [[ -z "$file" || -z "$expected" ]]; then
    log_error "net_verify_integrity: file and expected required"
    return 2
  fi
  if [[ ! -f "$file" ]]; then
    log_error "net_verify_integrity: file not found $file"
    return 2
  fi
  local calc
  if [[ "$algo" == "sha512" && command -v sha512sum >/dev/null 2>&1 ]]; then
    calc="$(sha512sum "$file" | awk '{print $1}')"
  else
    calc="$(sha256sum "$file" | awk '{print $1}')"
  fi
  if [[ "$calc" == "$expected" ]]; then
    log_info "net_verify_integrity: OK $file"
    return 0
  else
    log_warn "net_verify_integrity: mismatch for $file expected=$expected got=$calc"
    return 1
  fi
}

# atomic move into cache
_net_atomic_store() {
  local tmp="$1" final="$2"
  mv -f "$tmp" "$final" || { log_error "atomic move failed $tmp -> $final"; return 1; }
  chmod 640 "$final" 2>/dev/null || true
  return 0
}

# download using aria2c if available
_net_download_aria2() {
  local url="$1" tmp="$2" outname="$3"
  local aria_opts=(--file-allocation=none --continue=true --max-connection-per-server=4 --split=4 --min-split-size=1M)
  (( NET_STRICT_SSL )) && aria_opts+=(--check-certificate=true) || aria_opts+=(--check-certificate=false)
  if (( NET_BANDWIDTH_LIMIT )) && [[ -n "$NET_BANDWIDTH_LIMIT" && "$NET_BANDWIDTH_LIMIT" != "0" ]]; then
    aria_opts+=(--max-download-limit="$NET_BANDWIDTH_LIMIT")
  fi
  aria_opts+=(--dir="$(dirname "$tmp")" --out="$(basename "$tmp")" "$url")
  log_info "aria2c ${aria_opts[*]}"
  aria2c "${aria_opts[@]}" >/dev/null 2>&1
  return $?
}

# download using curl (supports resume)
_net_download_curl() {
  local url="$1" tmp="$2" outname="$3"
  local curl_opts=(--fail --location --connect-timeout "$NET_CONNECT_TIMEOUT" --retry 3 --retry-delay 2)
  (( NET_STRICT_SSL )) || curl_opts+=(--insecure)
  if [[ -n "$NET_BANDWIDTH_LIMIT" && "$NET_BANDWIDTH_LIMIT" != "0" ]]; then
    curl_opts+=(--limit-rate "$NET_BANDWIDTH_LIMIT")
  fi
  curl_opts+=(--output "$tmp" --compressed "$url")
  log_info "curl ${curl_opts[*]}"
  curl "${curl_opts[@]}" >/dev/null 2>&1
  return $?
}

# generic download one URL into temp and verify
net_download_one() {
  # net_download_one <url> <expected_sha256_or_empty> [hint_name]
  local url="$1"; local expected="$2"; local hint="$3"
  if [[ -z "$url" ]]; then log_error "net_download_one: url required"; return 2; fi
  net_init
  if [[ "$NET_OFFLINE" -eq 1 ]]; then
    log_warn "net_download_one: offline mode active, checking cache only"
    if [[ -n "$expected" ]]; then
      local cached; cached="$(net_get_cached "$expected")" || true
      if [[ -n "$cached" ]]; then
        log_info "net_download_one: found in cache $cached"
        net_audit_write "download_cache_hit" "$url" "{\"sha\":\"$expected\",\"path\":\"$cached\"}"
        echo "$cached"
        return 0
      fi
    fi
    log_error "net_download_one: offline and not in cache: $url"
    return 1
  fi

  # if expected hash provided and cached, return
  if [[ -n "$expected" ]]; then
    local cached; cached="$(net_get_cached "$expected")" || true
    if [[ -n "$cached" ]]; then
      log_info "net_download_one: cache hit -> $cached"
      net_audit_write "download_cache_hit" "$url" "{\"sha\":\"$expected\",\"path\":\"$cached\"}"
      echo "$cached"
      return 0
    fi
  fi

  # prepare tmp file
  _net_mkdir_p "$NET_TMP_DIR" || return 1
  local ext; ext="$(_net_ext_from_url "$url")"
  local tmp; tmp="$(mktemp -p "$NET_TMP_DIR" "dl.XXXXXX.${ext}.part")" || tmp="$NET_TMP_DIR/dl.$$.${ext}.part"
  local final_sha_basename="${expected:-$(date +%s%N)}"
  local final="${NET_ARCHIVES_DIR}/${final_sha_basename}.${ext}"

  # lock by expected hash if provided, otherwise by URL hash
  local lockname
  if [[ -n "$expected" ]]; then lockname="sha-$expected"; else lockname="url-$(echo -n "$url" | sha256sum | awk '{print $1}')"; fi

  _fs_acquired=0
  with_lock "$lockname" bash -c '
    # inner shell for lock
    exit_code=0
    '"$(typeset -f log_info log_warn log_error net_audit_write safe_run net_verify_integrity net_get_cached _net_atomic_store _net_download_aria2 _net_download_curl _net_ext_from_url)"'
    url="'"$url"'"; expected="'"$expected"'"; hint="'"$hint"'"; tmp="'"$tmp"'"; final="'"$final"'"; ext="'"$ext"'"
    attempts=0
    start_ts=$(date +%s)
    while (( attempts < '"$NET_MAX_RETRIES"' )); do
      attempts=$((attempts+1))
      if [[ '"$NET_USE_ARIA2"' -eq 1 && command -v aria2c >/dev/null 2>&1 ]]; then
        _net_download_aria2 "$url" "$tmp" "$hint"
      else
        _net_download_curl "$url" "$tmp" "$hint"
      fi
      rc=$?
      if [[ $rc -ne 0 || ! -s "$tmp" ]]; then
        log_warn "download attempt $attempts failed for $url (rc=$rc)"
        sleep $(( '"$NET_BACKOFF_BASE"' ** attempts > '"$NET_BACKOFF_MAX"' ? '"$NET_BACKOFF_MAX"': '"$NET_BACKOFF_BASE"'**attempts ))
        continue
      fi
      # compute hash if expected provided
      if [[ -n "$expected" ]]; then
        if net_verify_integrity "$tmp" "$expected" "sha256"; then
          # move to final
          finalpath="'"$NET_ARCHIVES_DIR"'/'"$expected"'.'"$ext"'"
          _net_atomic_store "$tmp" "$finalpath"
          net_audit_write "download_ok" "$url" "{\"path\":\"$finalpath\",\"attempts\":'"$attempts"'}"
          echo "$finalpath"
          exit 0
        else
          log_warn "checksum mismatch for $url on attempt $attempts"
          rm -f "$tmp" || true
          sleep $(( '"$NET_BACKOFF_BASE"' ** attempts > '"$NET_BACKOFF_MAX"' ? '"$NET_BACKOFF_MAX"': '"$NET_BACKOFF_BASE"'**attempts ))
          continue
        fi
      else
        # no expected: move to final with generated name (sha256 of file)
        sha="$(sha256sum "$tmp" | awk "{print \$1}")"
        finalpath="'"$NET_ARCHIVES_DIR"'/${sha}.'"$ext"'"
        _net_atomic_store "$tmp" "$finalpath"
        net_audit_write "download_ok" "$url" "{\"path\":\"$finalpath\",\"sha\":\"$sha\",\"attempts\":'"$attempts"'}"
        echo "$finalpath"
        exit 0
      fi
    done
    net_audit_write "download_fail" "$url" "{\"attempts\":$attempts}"
    exit 2
  ' || return_code=$?
  # with_lock returns code of inner; capture and return
  local inner_rc=${return_code:-0}
  if [[ "$inner_rc" -ne 0 ]]; then
    if [[ "$NET_FAIL_SOFT" -eq 1 ]]; then
      log_warn "net_download_one: failing softly for $url"
      return 1
    fi
    return $inner_rc
  fi
  return 0
}

# Parallel download manager: accepts file with lines: url,sha,name OR an array
net_download_many() {
  # net_download_many <file> OR if called with multiple args, treat as url|sha|name triples
  local src="$1"
  local -a tasks=()
  if [[ -f "$src" ]]; then
    while IFS=, read -r url sha name; do
      tasks+=("$url|$sha|$name")
    done < "$src"
  else
    # interpret args as triples
    if (( $# % 3 == 0 )); then
      while (( $# )); do
        url="$1"; sha="$2"; name="$3"; shift 3
        tasks+=("$url|$sha|$name")
      done
    else
      log_error "net_download_many: bad args"
      return 2
    fi
  fi

  local total=${#tasks[@]}
  if (( total == 0 )); then log_info "net_download_many: no tasks"; return 0; fi
  log_info "net_download_many: starting $total tasks with parallel=$NET_PARALLEL"
  local running=0
  local -a pids=()
  local success_count=0
  local fail_count=0

  # progress aggregator
  if declare -f progress_start >/dev/null 2>&1; then
    progress_start "Downloading sources" "$total"
  fi

  for t in "${tasks[@]}"; do
    while (( running >= NET_PARALLEL )); do
      # wait for any
      if ! wait -n; then true; fi
      running=$((running-1))
      if declare -f progress_update >/dev/null 2>&1; then
        progress_update $((success_count+fail_count)) "$total"
      fi
    done
    IFS='|' read -r url sha name <<< "$t"
    (
      if (( NET_SILENT == 0 )); then log_info "worker: download $url"; fi
      if net_download_one "$url" "$sha" "$name"; then
        exit 0
      else
        exit 1
      fi
    ) &
    pids+=($!)
    running=$((running+1))
  done

  # wait all
  for pid in "${pids[@]}"; do
    if wait "$pid"; then
      success_count=$((success_count+1))
    else
      fail_count=$((fail_count+1))
    fi
    if declare -f progress_update >/dev/null 2>&1; then
      progress_update $((success_count+fail_count)) "$total"
    fi
  done

  if declare -f progress_end >/dev/null 2>&1; then
    progress_end
  fi

  log_info "net_download_many: done success=$success_count fail=$fail_count"
  if (( fail_count > 0 )); then
    if (( NET_FAIL_SOFT )); then
      log_warn "net_download_many: some downloads failed but continuing (fail_soft)"
      return 0
    fi
    return 2
  fi
  return 0
}

# Git mirror and clone-from-mirror
net_fetch_git() {
  # net_fetch_git <repo_url> <ref> <destdir> [--mirror|--shallow]
  local repo="$1"; local ref="$2"; local dest="$3"; shift 3
  local opts=( "$@" )
  net_init
  _net_mkdir_p "$NET_GIT_DIR"
  local hostdir repo_name
  hostdir="$(echo "$repo" | sed -E 's|https?://||; s|/.*||')"
  repo_name="$(basename "$repo" .git)"
  local mirror="$NET_GIT_DIR/${hostdir}_${repo_name}.git"
  # create or update mirror
  if [[ -d "$mirror" ]]; then
    log_info "net_fetch_git: updating mirror $mirror"
    safe_run "git --git-dir=$mirror remote update --prune" git --git-dir="$mirror" remote update --prune || log_warn "mirror update failed"
  else
    log_info "net_fetch_git: creating mirror $mirror"
    safe_run "git clone --mirror $repo $mirror" git clone --mirror "$repo" "$mirror" || {
      log_error "net_fetch_git: mirror clone failed for $repo"
      return 1
    }
  fi
  # clone from mirror to dest
  _net_mkdir_p "$dest"
  if [[ " ${opts[*]} " == *" --shallow "* ]]; then
    safe_run "git clone --depth 1 --branch ${ref} $mirror $dest" git clone --depth 1 --branch "$ref" "$mirror" "$dest" || return 1
  else
    safe_run "git clone $mirror $dest" git clone "$mirror" "$dest" || return 1
    if [[ -n "$ref" ]]; then
      safe_run "git -C $dest checkout $ref" git -C "$dest" checkout "$ref" || true
    fi
  fi
  local commit
  commit="$(git -C "$dest" rev-parse --verify HEAD 2>/dev/null || true)"
  net_audit_write "git_clone" "$repo" "{\"mirror\":\"$mirror\",\"dest\":\"$dest\",\"commit\":\"$commit\"}"
  return 0
}

# Apply patches (simple)
net_apply_patches() {
  # net_apply_patches <srcdir> <patchdir>
  local src="$1" patchdir="$2"
  if [[ -z "$src" || -z "$patchdir" ]]; then
    log_error "net_apply_patches: src and patchdir required"
    return 1
  fi
  if [[ ! -d "$patchdir" ]]; then
    log_warn "net_apply_patches: patchdir not found $patchdir"
    return 0
  fi
  for p in "$patchdir"/*; do
    [[ -f "$p" ]] || continue
    log_info "net_apply_patches: applying $p"
    safe_run "patch -p1 -d $src < $p" bash -c "patch -p1 -d \"$src\" < \"$p\"" || {
      log_error "net_apply_patches: failed $p"
      return 1
    }
    net_audit_write "patch_applied" "$src" "{\"patch\":\"$p\"}"
  done
  return 0
}

# Cache cleaning & compression
net_cache_clean() {
  # net_cache_clean [--age DAYS] [--max-size BYTES]
  local age="${NET_CLEAN_AGE_DAYS}"; local maxsize=""
  while (( "$#" )); do
    case "$1" in
      --age) shift; age="$1"; shift;;
      --max-size) shift; maxsize="$1"; shift;;
      *) shift;;
    esac
  done
  log_info "net_cache_clean: age=$age maxsize=$maxsize compress_old=$NET_COMPRESS_OLD"
  # compress old files
  if (( NET_COMPRESS_OLD )) && command -v zstd >/dev/null 2>&1; then
    find "$NET_ARCHIVES_DIR" -type f -mtime +"$age" ! -name "*.zst" -print0 | xargs -0 -r -n1 -P2 zstd -q -19 && log_info "net_cache_clean: compression pass done"
  fi
  # optional size-based cleanup (LRU)
  if [[ -n "$maxsize" ]]; then
    # compute total size and remove oldest until under maxsize
    local totalsize; totalsize=$(du -sb "$NET_ARCHIVES_DIR" 2>/dev/null | awk '{print $1}')
    while [[ -n "$totalsize" && "$totalsize" -gt "$maxsize" ]]; do
      local oldest; oldest=$(find "$NET_ARCHIVES_DIR" -type f -printf '%T@ %p\n' | sort -n | head -n1 | awk '{print $2}')
      [[ -z "$oldest" ]] && break
      rm -f "$oldest" && log_info "net_cache_clean: removed $oldest"
      totalsize=$(du -sb "$NET_ARCHIVES_DIR" 2>/dev/null | awk '{print $1}')
    done
  fi
  net_audit_write "cache_clean" "$NET_ARCHIVES_DIR" "{\"age\":$age,\"maxsize\":\"$maxsize\"}"
  return 0
}

# Bandwidth limit setter (for aria2c/curl usage)
net_set_bandwidth_limit() {
  NET_BANDWIDTH_LIMIT="$1"
  log_info "net_set_bandwidth_limit: set to $NET_BANDWIDTH_LIMIT"
}

# Offline mode
net_offline_mode_on() { NET_OFFLINE=1; log_info "net_offline_mode: ON"; }
net_offline_mode_off(){ NET_OFFLINE=0; log_info "net_offline_mode: OFF"; }

# Abort handler
net_abort() {
  log_warn "net_abort: cleaning temporary downloads and locks"
  rm -rf "$NET_TMP_DIR"/* 2>/dev/null || true
  net_audit_write "abort" "" "{}"
  exit 1
}
trap net_abort INT TERM

# Export functions
export -f net_init net_check_tools net_download_one net_download_many net_fetch_git net_apply_patches \
  net_cache_clean net_set_bandwidth_limit net_offline_mode_on net_offline_mode_off net_verify_integrity

log_info "lib_net.sh loaded (version 1.0). Call net_init to prepare environment."
