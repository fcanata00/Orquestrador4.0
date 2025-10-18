#!/usr/bin/env bash
# lib/downloader.sh
# Downloader module for ports manager
# - supports http(s)/ftp/git/file/repo://
# - cache with sha256/md5 verification
# - retries, backoff, timeout
# - isolation via tempdir and restricted user
# - integrates with lib/common.sh (expects to be sourced)
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true

# Configurable vars (can be overridden by load_config or env)
PORTS_DOWNLOAD_TIMEOUT="${PORTS_DOWNLOAD_TIMEOUT:-60}"
PORTS_DOWNLOAD_RETRY="${PORTS_DOWNLOAD_RETRY:-3}"
PORTS_PARALLEL_DOWNLOADS="${PORTS_PARALLEL_DOWNLOADS:-2}"
PORTS_OFFLINE="${PORTS_OFFLINE:-0}"
MIRRORS=()      # user can set MIRRORS=( "https://mirror1" "https://mirror2" )

# Ensure common.sh has been sourced (basic checks)
if ! declare -f info >/dev/null 2>&1; then
  echo "lib/common.sh must be sourced before lib/downloader.sh" >&2
  return 1 2>/dev/null || exit 1
fi

# Helpers #####################################################################
_safe_tempdir() {
  mktemp -d "${TMPDIR:-/tmp}/ports-dl-XXXXXX"
}

_sanitize_name() {
  local s="$1"
  # keep safe characters only
  printf "%s" "$s" | sed -E 's|[^A-Za-z0-9._-]|_|g'
}

_escape_url_for_hash() {
  # produce a stable name from URL for cache path
  printf "%s" "$1" | sha256sum | awk '{print $1}'
}

_cache_path_for_url() {
  local url="$1"
  local h="$(_escape_url_for_hash "$url")"
  printf "%s/%s" "${PORTS_CACHEDIR:-/var/cache/ports}" "$h"
}

# verify_integrity <file> [sha256] [md5]
verify_integrity() {
  local file="$1"; shift
  local want_sha256="${1:-}"; local want_md5="${2:-}"
  if [[ ! -f "$file" ]]; then
    warn "verify_integrity: file not found: $file"
    return 2
  fi
  if [[ -n "$want_sha256" ]] && command -v sha256sum >/dev/null 2>&1; then
    local have_sha256
    have_sha256="$(sha256sum "$file" | awk '{print $1}')"
    if [[ "$have_sha256" != "$want_sha256" ]]; then
      warn "sha256 mismatch for $file (have=$have_sha256 want=$want_sha256)"
      return 1
    else
      debug "sha256 OK for $file"
    fi
  fi
  if [[ -n "$want_md5" ]] && command -v md5sum >/dev/null 2>&1; then
    local have_md5
    have_md5="$(md5sum "$file" | awk '{print $1}')"
    if [[ "$have_md5" != "$want_md5" ]]; then
      warn "md5 mismatch for $file (have=$have_md5 want=$want_md5)"
      return 1
    else
      debug "md5 OK for $file"
    fi
  fi
  # If no hashes provided, return 0 but warn
  if [[ -z "$want_sha256" && -z "$want_md5" ]]; then
    warn "No hash provided for $file; skipping strict verification"
  fi
  return 0
}

# cache_lookup <url> [sha256]
cache_lookup() {
  local url="$1"; local want_sha256="${2:-}"
  local cpath; cpath="$(_cache_path_for_url "$url")"
  if [[ -f "$cpath" ]]; then
    # verify if sha256 provided
    if [[ -n "$want_sha256" ]]; then
      if verify_integrity "$cpath" "$want_sha256"; then
        debug "cache_lookup: cache hit $cpath"
        printf "%s" "$cpath"
        return 0
      else
        warn "cache_lookup: cache present but failed integrity, removing $cpath"
        rm -f "$cpath" || true
        return 1
      fi
    else
      debug "cache_lookup: cache hit (no hash to verify) $cpath"
      printf "%s" "$cpath"
      return 0
    fi
  fi
  return 1
}

# run_hook <hook-name> [args...]
run_hook() {
  local hook="$1"; shift
  # Hooks can be global in /etc/ports/hooks or per-port in workdir/hooks
  local global_hook="/etc/ports/hooks/${hook}.sh"
  if [[ -x "$global_hook" ]]; then
    debug "Running global hook $global_hook"
    "$global_hook" "$@" || warn "Global hook $hook failed: $global_hook"
  fi
  # per-package hooks expected to be executed by caller (context dependent)
  return 0
}

# safe_download_cmd: prefer curl then wget
_safe_download_cmd() {
  if command -v curl >/dev/null 2>&1; then
    printf "curl"
  elif command -v wget >/dev/null 2>&1; then
    printf "wget"
  else
    printf ""
  fi
}

# atomic move: write to .part then mv
_atomic_write_move() {
  local src="$1" dst="$2"
  mv -f "$src" "$dst"
}

# ensure non-root execution for downloads (if root, try to drop privs)
_run_as_unprivileged() {
  local cmd=( "$@" )
  if [[ "$EUID" -eq 0 ]]; then
    # prefer a dedicated user 'portsdownloader' if exists
    if id -u portsdownloader >/dev/null 2>&1; then
      debug "Running as portsdownloader user"
      sudo -u portsdownloader "${cmd[@]}"
      return $?
    fi
    # fallback to nobody
    if id -u nobody >/dev/null 2>&1; then
      debug "Running as nobody user"
      sudo -u nobody "${cmd[@]}"
      return $?
    fi
    # last resort: use fakeroot if present to simulate non-root file ownerships
    if command -v fakeroot >/dev/null 2>&1; then
      debug "Running under fakeroot as last-resort"
      fakeroot "${cmd[@]}"
      return $?
    fi
    warn "Running download as root (no safer user found)"
    "${cmd[@]}"
    return $?
  else
    "${cmd[@]}"
    return $?
  fi
}

# try_download <url> <dest_tmp> <timeout> <want_sha256> <want_md5>
try_download() {
  local url="$1"; local dest_tmp="$2"; local timeout="${3:-$PORTS_DOWNLOAD_TIMEOUT}"
  local want_sha256="${4:-}"; local want_md5="${5:-}"
  local retries="${PORTS_DOWNLOAD_RETRY:-3}"
  local attempt=1
  local backoff=1
  local dlcmd
  dlcmd="$(_safe_download_cmd)"
  if [[ -z "$dlcmd" ]]; then
    error "No download tool (curl or wget) available"
    return 2
  fi
  while [[ $attempt -le $retries ]]; do
    info "TRY $attempt/$retries: downloading $url"
    if is_dryrun; then
      info "[DRY-RUN] would download $url -> $dest_tmp"
      return 0
    fi
    # run in isolated tempdir subshell
    (
      set -o pipefail
      umask 027
      cd "$(dirname "$dest_tmp")" || exit 2
      if [[ "$dlcmd" == "curl" ]]; then
        # -f fail on http error, --connect-timeout, --max-time, -L follow redirects
        # write to temporary file
        curl --fail --location --connect-timeout 15 --max-time "$timeout" --retry 2 --retry-delay 2 \
             --output "$(basename "$dest_tmp").part" --silent --show-error "$url"
      else
        # wget fallback
        wget --timeout="$timeout" --tries=2 --output-document="$(basename "$dest_tmp").part" --quiet "$url"
      fi
      local rc=$?
      if [[ $rc -ne 0 ]]; then
        echo "DL_FAILED" >&2
        exit $rc
      fi
      # atomic move to final tmp name
      mv -f "$(basename "$dest_tmp").part" "$(basename "$dest_tmp")"
      # adjust perms
      chmod 0644 "$(basename "$dest_tmp")" || true
      exit 0
    )
    local rc=$?
    if [[ $rc -eq 0 ]]; then
      # verify integrity if hashes provided
      if [[ -n "$want_sha256" || -n "$want_md5" ]]; then
        if verify_integrity "$dest_tmp" "$want_sha256" "$want_md5"; then
          success "Downloaded + verified $url"
          return 0
        else
          warn "Integrity check failed for $url on attempt $attempt"
          rm -f "$dest_tmp" || true
          # continue to retry
        fi
      else
        success "Downloaded $url (no hash provided)"
        return 0
      fi
    else
      warn "Download attempt $attempt failed for $url (rc=$rc)"
    fi
    attempt=$((attempt+1))
    sleep "$backoff"
    backoff=$((backoff * 2))
  done
  error "Failed to download $url after $retries attempts"
  return 1
}

# download_file <url> [destdir] [sha256] [md5]
download_file() {
  local url="$1"; local destdir="${2:-.}"; local want_sha256="${3:-}"; local want_md5="${4:-}"
  run_hook pre_download "$url" || true
  if [[ "$PORTS_OFFLINE" -eq 1 ]]; then
    warn "Offline mode enabled; skipping network download for $url"
    return 2
  fi
  local cpath; cpath="$(_cache_path_for_url "$url")"
  safe_mkdir "$PORTS_CACHEDIR"
  # check cache first
  if cached="$(_cache_path_for_url "$url")" && [[ -f "$cached" ]]; then
    if [[ -n "$want_sha256" ]]; then
      if verify_integrity "$cached" "$want_sha256" "$want_md5"; then
        info "Using cached file for $url -> $cached"
        run_hook post_download "$url" "$cached" || true
        # copy to destdir
        local destname="${destdir%/}/$(basename "$url")"
        cp -a "$cached" "$destname" || die "Failed to copy cached file to $destname"
        return 0
      else
        warn "Cache present but failed integrity; removing $cached"
        rm -f "$cached" || true
      fi
    else
      info "Using cached file for $url -> $cached (no hash provided)"
      run_hook post_download "$url" "$cached" || true
      local destname="${destdir%/}/$(basename "$url")"
      cp -a "$cached" "$destname" || die "Failed to copy cached file to $destname"
      return 0
    fi
  fi

  # Not cached or invalid: download to temp and then move atomically to cache
  local tmpdir; tmpdir="$(_safe_tempdir)"
  local tmpfile="$tmpdir/$(_sanitize_name "$(basename "$url")")"
  trap 'rm -rf "$tmpdir"' RETURN
  # use lock per-url to avoid racing downloads into same cache file
  local lockname="download-$(_sanitize_name "$(_escape_url_for_hash "$url")")"
  acquire_lock "$lockname" || { error "Could not acquire download lock for $url"; rm -rf "$tmpdir"; return 3; }
  # If another process populated cache while we waited, reuse it
  if cached2="$(_cache_path_for_url "$url")" && [[ -f "$cached2" ]]; then
    info "Cache was populated while waiting; using $cached2"
    release_lock "$lockname" || true
    cp -a "$cached2" "${destdir%/}/$(basename "$url")" || die "Failed to copy cached file"
    rm -rf "$tmpdir"
    run_hook post_download "$url" "$cached2" || true
    return 0
  fi

  # attempt download
  if try_download "$url" "$tmpfile" "$PORTS_DOWNLOAD_TIMEOUT" "$want_sha256" "$want_md5"; then
    # move to cache atomically
    safe_mkdir "$PORTS_CACHEDIR"
    _atomic_write_move "$tmpfile" "$cpath"
    info "Cached $url -> $cpath"
    # copy to destdir
    local destname="${destdir%/}/$(basename "$url")"
    cp -a "$cpath" "$destname" || warn "Failed to copy cached file to $destname"
    release_lock "$lockname" || true
    rm -rf "$tmpdir"
    run_hook post_download "$url" "$cpath" || true
    return 0
  else
    warn "Download failed for $url"
    release_lock "$lockname" || true
    rm -rf "$tmpdir"
    run_hook on_download_error "$url" || true
    return 4
  fi
}

# download_git <repo> [destdir] [ref]
download_git() {
  local repo="$1"; local destdir="${2:-.}"; local ref="${3:-HEAD}"
  run_hook pre_download "$repo" || true
  if [[ "$PORTS_OFFLINE" -eq 1 ]]; then
    warn "Offline mode; skipping git network ops for $repo"
    return 2
  fi
  safe_mkdir "$PORTS_CACHEDIR/git"
  local gitcachedir="$PORTS_CACHEDIR/git/$(_sanitize_name "$repo")"
  if [[ -d "$gitcachedir/.git" ]]; then
    info "Updating git cached repo $repo"
    if is_dryrun; then info "[DRY-RUN] git -C $gitcachedir fetch --all --prune"; else git -C "$gitcachedir" fetch --all --prune; fi
  else
    info "Cloning $repo into cache"
    if is_dryrun; then info "[DRY-RUN] git clone --mirror $repo $gitcachedir"; else git clone --mirror --depth=1 "$repo" "$gitcachedir"; fi
  fi
  # export a working copy to destdir
  safe_mkdir "$destdir"
  local tmpwork="$(_safe_tempdir)"
  trap 'rm -rf "$tmpwork"' RETURN
  if is_dryrun; then
    info "[DRY-RUN] git archive from $gitcachedir -> $destdir"
    return 0
  fi
  git --git-dir="$gitcachedir" archive --remote="$gitcachedir" "$ref" | tar -x -C "$tmpwork"
  # move into destdir atomically
  rsync -a "$tmpwork"/ "$destdir"/
  rm -rf "$tmpwork"
  run_hook post_download "$repo" "$destdir" || true
  return 0
}

# download_repo <pkgdir> - works with /usr/ports layout
download_repo() {
  local pkg="$1"; local destdir="${2:-.}"
  local srcdir="/usr/ports/${pkg}"
  if [[ ! -d "$srcdir" ]]; then
    warn "Package repo not found: $srcdir"
    return 2
  fi
  run_hook pre_download "$srcdir" || true
  # if it's a git repo, update it
  if [[ -d "$srcdir/.git" ]]; then
    info "Updating local repo $srcdir"
    if is_dryrun; then info "[DRY-RUN] git -C $srcdir pull"; else git -C "$srcdir" pull --no-edit || warn "git pull had warnings"
    fi
  fi
  # find source archives in the pkg dir
  local found=0
  while IFS= read -r -d '' f; do
    found=1
    local fname; fname="$(basename "$f")"
    info "Found source $fname in $srcdir; copying to $destdir"
    cp -a "$f" "$destdir/" || warn "Could not copy $f to $destdir"
  done < <(find "$srcdir" -maxdepth 2 -type f -iregex '.*\.\(tar\|tar\.gz\|tgz\|tar\.xz\|tar\.zst\|zip\|gz\|bz2\|xz\)' -print0)
  if [[ $found -eq 0 ]]; then
    warn "No source archives found in $srcdir"
  fi
  # apply patches if present
  if [[ -d "$srcdir/patches" ]]; then
    info "Applying patches from $srcdir/patches to $destdir"
    # naive apply: iterate patch files
    while IFS= read -r -d '' p; do
      info "Applying patch $(basename "$p")"
      patch -p1 -d "$destdir" --forward < "$p" || warn "Patch failed: $p"
    done < <(find "$srcdir/patches" -type f -name '*.patch' -print0)
  fi
  run_hook post_download "$srcdir" "$destdir" || true
  return 0
}

# update_cache: remove old files older than DAYS (default 30)
update_cache() {
  local days="${1:-30}"
  if is_dryrun; then
    info "[DRY-RUN] would clean cache older than $days days in $PORTS_CACHEDIR"
    return 0
  fi
  safe_mkdir "$PORTS_CACHEDIR"
  info "Cleaning cache older than $days days in $PORTS_CACHEDIR"
  find "$PORTS_CACHEDIR" -type f -mtime +"$days" -print -exec rm -f {} \; | while read -r f; do info "Removed $f"; done
  return 0
}

# download_sources <manifest-file>
# manifest lines: URL [sha256] [md5]
download_sources() {
  local manifest="$1"
  if [[ ! -f "$manifest" ]]; then
    die "Manifest not found: $manifest"
  fi
  local jobs="${PORTS_PARALLEL_DOWNLOADS:-2}"
  local urls=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(echo -e "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$line" ]] && continue
    urls+=("$line")
  done < "$manifest"

  if [[ ${#urls[@]} -eq 0 ]]; then
    warn "No sources to download in manifest $manifest"
    return 0
  fi

  # export functions/vars for xargs subshells
  export -f download_file verify_integrity try_download run_hook _cache_path_for_url _safe_tempdir _sanitize_name _escape_url_for_hash
  export PORTS_CACHEDIR PORTS_DOWNLOAD_TIMEOUT PORTS_DOWNLOAD_RETRY PORTS_OFFLINE PORTS_PARALLEL_DOWNLOADS

  # use xargs for parallelism: each line -> call a small wrapper parsing URL and hashes
  printf "%s\n" "${urls[@]}" | xargs -n1 -P "$jobs" -I{} bash -c '
    line="{}"
    # split fields: url sha256 md5
    set -- $line
    url="$1"; sha256="${2:-}"; md5="${3:-}"
    destdir="."
    download_file "$url" "$destdir" "$sha256" "$md5"
  '
  return 0
}

# end of downloader module
debug "lib/downloader.sh loaded"
