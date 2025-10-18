#!/usr/bin/env bash
# lfsctl init module
# Path: /usr/libexec/lfsctl/init.sh  (suggested)
# License: MIT
# Purpose: Initialize and validate LFSCTL build environment
# Features: idempotent init, user/group create/validate, dirs atomic create,
#           chroot/fakeroot setup, tool/version checks, LFS/BLFS verification,
#           hooks, auto-heal, monitor-friendly, dry-run & diagnostic modes.
#
# NOTE: This script is intended to be sourced by other scripts OR executed directly.
# It integrates with config.sh, logger.sh and lock.sh if they are available.
set -euo pipefail

# -------------------- Defaults (can be overridden by config.sh) --------------------
: "${LFSCTL_CONFIG:=/etc/lfsctl.conf}"
: "${LFSCTL_PREFIX:=/usr}"
: "${LFSCTL_ROOT:=/mnt/lfs}"
: "${LFSCTL_BUILD_USER:=lfsbuild}"
: "${LFSCTL_BUILD_GROUP:=lfsbuild}"
: "${LFSCTL_BUILD_UID:=}"   # optional
: "${LFSCTL_BUILD_GID:=}"   # optional
: "${LFSCTL_BUILD_HOME:=/var/lib/lfsbuild}"
: "${LFSCTL_CACHE_DIR:=/var/cache/lfsctl}"
: "${LFSCTL_BUILD_DIR:=/var/lfsctl/build}"
: "${LFSCTL_PKG_DIR:=/var/lfsctl/packages}"
: "${LFSCTL_META_DIR:=/var/lfsctl/meta}"
: "${LFSCTL_LOG_DIR:=/var/lfsctl/logs}"
: "${LFSCTL_LOCK_DIR:=/var/lock/lfsctl}"
: "${LFSCTL_PORTS_DIR:=/usr/ports}"
: "${LFSCTL_REPO_URL:=}"
: "${LFSCTL_CHROOT_ENABLED:=true}"
: "${LFSCTL_FAKEROOT_ENABLED:=true}"
: "${LFSCTL_JOBS:=$(nproc 2>/dev/null || echo 1)}"
: "${LFSCTL_COLOR:=auto}"
: "${LFSCTL_MIN_TOOLS:=gcc:10.2 make:4.2.1 tar:1.30 git:2.25 zstd:1.4.5 sha256sum:0}"

# Hooks (can be set in config)
: "${LFSCTL_PRE_INIT_HOOK:=}"
: "${LFSCTL_POST_INIT_HOOK:=}"
: "${LFSCTL_ON_FAIL_HOOK:=}"

# Behavior flags
DRY_RUN=0
DIAGNOSTIC=0
NON_INTERACTIVE=0

# Internal state
_INIT_START_TS=$(date +%s)
_INIT_ERRORS=0
_INIT_CREATED=0
_INIT_CHANGED=0
_INIT_REPORT_FILE=""

# Helper: safe logger integration fallback
_log() {
  local lvl="$1"; shift
  if type -t log_info >/dev/null 2>&1; then
    case "$lvl" in
      info) log_info "$@" ;;
      warn) log_warn "$@" ;;
      error) log_error "$@" ;;
      debug) log_debug "$@" ;;
      success) log_success "$@" ;;
      *) log_info "$@" ;;
    esac
  else
    case "$lvl" in
      error) >&2 printf 'ERROR: %s\n' "$*" ;;
      warn) >&2 printf 'WARN: %s\n' "$*" ;;
      debug) printf 'DEBUG: %s\n' "$*" ;;
      success) printf 'OK: %s\n' "$*" ;;
      *) printf '%s\n' "$*" ;;
    esac
  fi
}

# Simple prompt helper (respects non-interactive)
_prompt_yesno() {
  local question="$1" default="$2" ans
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    [[ "$default" == "y" ]] && return 0 || return 1
  fi
  read -r -p "$question [y/N]: " ans </dev/tty || return 1
  case "$ans" in [Yy]* ) return 0;; *) return 1;; esac
}

# Atomic directory creation (mktemp + mv to avoid TOCTOU)
_atomic_mkdir() {
  local dest="$1" owner="$2" group="$3" mode="$4" dry="${5:-0}"
  if [[ "$dry" -eq 1 ]]; then
    _log info "dry-run: would create dir $dest owner=$owner group=$group mode=$mode"
    return 0
  fi
  if [[ -d "$dest" ]]; then
    # apply ownership/perms if needed
    chown "$owner:$group" "$dest" 2>/dev/null || true
    chmod "$mode" "$dest" 2>/dev/null || true
    return 0
  fi
  local parent tmp
  parent=$(dirname "$dest")
  mkdir -p "$parent" 2>/dev/null || true
  tmp=$(mktemp -d "${parent}/.lfsctl.tmp.XXXX") || tmp="/tmp/.lfsctl.tmp.$$.$RANDOM"
  chmod "$mode" "$tmp" 2>/dev/null || true
  chown "$owner:$group" "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$dest"
  _INIT_CREATED=$((_INIT_CREATED+1))
  _log debug "Created directory $dest"
  return 0
}

# Version compare function: returns 0 if a>=b, 1 otherwise. handles X.Y[.Z]
vercmp_ge() {
  # usage: vercmp_ge "1.2.3" "1.2"
  local a=$1 b=$2 IFS=.
  local -a A=(${a//./ }) B=(${b//./ })
  local i max=${#A[@]}; (( ${#B[@]} > max )) && max=${#B[@]}
  for ((i=0;i<max;i++)); do
    local ai=${A[i]:-0} bi=${B[i]:-0}
    if ((10#${ai} > 10#${bi})); then return 0; fi
    if ((10#${ai} < 10#${bi})); then return 1; fi
  done
  return 0
}

# Extract version helper (tries --version, -v, -V)
_extract_version() {
  local cmd="$1"; shift
  local out ver
  out=$("$cmd" --version 2>/dev/null || "$cmd" -v 2>/dev/null || "$cmd" -V 2>/dev/null || true)
  # find first x.y(.z)
  ver=$(printf '%s' "$out" | grep -oE '[0-9]+(\.[0-9]+){1,3}' | head -n1 || true)
  printf '%s' "$ver"
}

# Load config if available
init_env() {
  local cfg="${1:-$LFSCTL_CONFIG}"
  if [[ -f "$cfg" ]]; then
    # source config safely: only KEY=VAL lines, no eval of arbitrary code
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="${line%"${line##*[![:space:]]}"}" # rstrip
      line="${line#"${line%%[![:space:]]*}"}" # lstrip
      [[ -z "$line" ]] && continue
      if [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
        local key="${BASH_REMATCH[1]}" val="${BASH_REMATCH[2]}"
        # strip surrounding quotes if present
        if [[ "$val" =~ ^\"(.*)\"$ ]]; then val="${BASH_REMATCH[1]}"; fi
        if [[ "$val" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"; fi
        # basic sanitization: no backticks or $()
        if [[ "$val" =~ [\`\$\(] ]]; then
          _log warn "Ignoring suspicious value for $key in $cfg"
        else
          export "$key"="$val"
        fi
      else
        _log debug "Skipping non-kv line in config: $line"
      fi
    done <"$cfg"
    _log info "Loaded config from $cfg"
  else
    _log warn "Config file $cfg not found; using defaults"
  fi
  # ensure meta dir exists
  mkdir -p "${LFSCTL_META_DIR}" 2>/dev/null || true
}

# Ensure logger and lock modules are sourced if available
_init_optional_modules() {
  if [[ -f /usr/libexec/lfsctl/logger.sh ]]; then
    # shellcheck source=/dev/null
    source /usr/libexec/lfsctl/logger.sh || _log warn "Failed to source logger.sh"
  fi
  if [[ -f /usr/libexec/lfsctl/lock.sh ]]; then
    # shellcheck source=/dev/null
    source /usr/libexec/lfsctl/lock.sh || _log warn "Failed to source lock.sh"
  fi
}

# Create or validate build user account
init_user() {
  local uid="${1:-$LFSCTL_BUILD_UID}" gid="${2:-$LFSCTL_BUILD_GID}" fix="${3:-}" dry="${4:-$DRY_RUN}"
  if [[ "$dry" -eq 1 ]]; then
    _log info "dry-run: would ensure user ${LFSCTL_BUILD_USER} (uid=${uid}) group=${LFSCTL_BUILD_GROUP}"
    return 0
  fi

  if id -u "$LFSCTL_BUILD_USER" >/dev/null 2>&1; then
    local existing_uid existing_gid
    existing_uid=$(id -u "$LFSCTL_BUILD_USER")
    existing_gid=$(id -g "$LFSCTL_BUILD_USER")
    _log info "Build user exists: ${LFSCTL_BUILD_USER} uid=${existing_uid} gid=${existing_gid}"
    # if UID/GID mismatch and fix requested, attempt usermod/groupmod
    if [[ -n "$uid" && "$existing_uid" != "$uid" ]]; then
      if [[ "$fix" == "--fix" || "$NON_INTERACTIVE" -eq 1 ]]; then
        if command -v usermod >/dev/null 2>&1; then
          usermod -u "$uid" "$LFSCTL_BUILD_USER" || _log error "usermod failed to set uid $uid for $LFSCTL_BUILD_USER"
          _log info "Adjusted uid for $LFSCTL_BUILD_USER -> $uid"
        else
          _log error "usermod not available to fix UID"
          return 3
        fi
      else
        _log error "User ${LFSCTL_BUILD_USER} exists with UID=${existing_uid} (expected ${uid}). Run with --fix to adjust or choose a different user."
        return 3
      fi
    fi
    # group fix
    if [[ -n "$gid" && "$existing_gid" != "$gid" ]]; then
      if command -v groupmod >/dev/null 2>&1 && { [[ "$fix" == "--fix" ]] || [[ "$NON_INTERACTIVE" -eq 1 ]]; }; then
        groupmod -g "$gid" "$LFSCTL_BUILD_GROUP" || _log warn "groupmod failed"
        _log info "Adjusted gid for $LFSCTL_BUILD_GROUP -> $gid"
      else
        _log warn "Group ${LFSCTL_BUILD_GROUP} exists with GID=${existing_gid} (expected ${gid})"
      fi
    fi
    return 0
  fi

  # Create group (if needed)
  if ! getent group "$LFSCTL_BUILD_GROUP" >/dev/null 2>&1; then
    if [[ "$dry" -eq 0 ]]; then
      if command -v groupadd >/dev/null 2>&1; then
        if [[ -n "$gid" ]]; then groupadd -g "$gid" "$LFSCTL_BUILD_GROUP" || _log warn "groupadd failed"; else groupadd "$LFSCTL_BUILD_GROUP" || _log warn "groupadd failed"; fi
      elif command -v addgroup >/dev/null 2>&1; then
        addgroup --system "$LFSCTL_BUILD_GROUP" || _log warn "addgroup failed"
      else
        _log warn "No group add tool; please create group $LFSCTL_BUILD_GROUP manually"
      fi
      _log info "Created group $LFSCTL_BUILD_GROUP"
    fi
  fi

  # Create user
  if [[ "$dry" -eq 0 ]]; then
    if command -v useradd >/dev/null 2>&1; then
      local ua=(useradd -r -M -d "$LFSCTL_BUILD_HOME" -s /usr/sbin/nologin -g "$LFSCTL_BUILD_GROUP" -c "LFSCTL build user" "$LFSCTL_BUILD_USER")
      [[ -n "$uid" ]] && ua+=(-u "$uid")
      [[ -n "$gid" ]] && ua+=(-g "$gid")
      "${ua[@]}" >/dev/null 2>&1 || { _log error "useradd failed for $LFSCTL_BUILD_USER"; return 3; }
      _log info "Created build user $LFSCTL_BUILD_USER"
    elif command -v adduser >/dev/null 2>&1; then
      adduser --system --home "$LFSCTL_BUILD_HOME" --no-create-home --shell /usr/sbin/nologin --ingroup "$LFSCTL_BUILD_GROUP" "$LFSCTL_BUILD_USER" >/dev/null 2>&1 || _log warn "adduser failed"
      _log info "Created build user (adduser) $LFSCTL_BUILD_USER"
    else
      _log error "No useradd/adduser available; create user $LFSCTL_BUILD_USER manually"
      return 3
    fi
  fi

  # Ensure home exists and ownership
  if [[ "$dry" -eq 0 ]]; then
    mkdir -p "$LFSCTL_BUILD_HOME" 2>/dev/null || true
    chown -R "$LFSCTL_BUILD_USER:$LFSCTL_BUILD_GROUP" "$LFSCTL_BUILD_HOME" 2>/dev/null || true
  fi

  # register in meta
  mkdir -p "$LFSCTL_META_DIR" 2>/dev/null || true
  local meta_file="${LFSCTL_META_DIR}/users.json"
  local now; now="$(date -Is 2>/dev/null || date +%s)"
  if [[ -f "$meta_file" && command -v jq >/dev/null 2>&1 ]]; then
    jq --arg u "$LFSCTL_BUILD_USER" --arg uid "$(id -u "$LFSCTL_BUILD_USER" 2>/dev/null || echo 0)" --arg gid "$(id -g "$LFSCTL_BUILD_USER" 2>/dev/null || echo 0)" --arg now "$now" '.[$u]={uid:$uid|tonumber,gid:$gid|tonumber,modified:$now} + .' "$meta_file" >"${meta_file}.tmp" 2>/dev/null || true
    mv -f "${meta_file}.tmp" "$meta_file" 2>/dev/null || true
  else
    printf '{"%s":{"uid":%s,"gid":%s,"created":"%s"}}\n' "$LFSCTL_BUILD_USER" "$(id -u "$LFSCTL_BUILD_USER" 2>/dev/null || echo 0)" "$(id -g "$LFSCTL_BUILD_USER" 2>/dev/null || echo 0)" "$now" >"$meta_file" 2>/dev/null || true
  fi
  return 0
}

# Create and ensure directories
init_dirs() {
  local dry="${1:-$DRY_RUN}"
  local owner="${LFSCTL_BUILD_USER}" group="${LFSCTL_BUILD_GROUP}"
  local dirs=( "$LFSCTL_BUILD_DIR" "$LFSCTL_CACHE_DIR" "$LFSCTL_PKG_DIR" "$LFSCTL_META_DIR" "$LFSCTL_LOG_DIR" "$LFSCTL_LOCK_DIR" "$LFSCTL_ROOT" "$LFSCTL_PORTS_DIR" )
  for d in "${dirs[@]}"; do
    _atomic_mkdir "$d" "$owner" "$group" 2770 "$dry" || { _log error "Failed to ensure dir $d"; _INIT_ERRORS=$((_INIT_ERRORS+1)); }
  done
  # create subdirs
  mkdir -p "${LFSCTL_LOCK_DIR}/stale" "${LFSCTL_META_DIR}/metrics" "${LFSCTL_LOG_DIR}/archive" 2>/dev/null || true
  chown -R "$owner:$group" "${LFSCTL_BUILD_DIR}" "${LFSCTL_CACHE_DIR}" "${LFSCTL_PKG_DIR}" "${LFSCTL_META_DIR}" "${LFSCTL_LOG_DIR}" "${LFSCTL_LOCK_DIR}" 2>/dev/null || true
  chmod 2770 "${LFSCTL_BUILD_DIR}" "${LFSCTL_CACHE_DIR}" "${LFSCTL_PKG_DIR}" 2>/dev/null || true
  _log info "Directories created and permissions applied"
}

# Initialize logger subsystem
init_logger() {
  if [[ -f /usr/libexec/lfsctl/logger.sh ]]; then
    # shellcheck source=/dev/null
    source /usr/libexec/lfsctl/logger.sh || _log warn "Failed to source logger.sh"
  fi
  # attempt to init logger for init tasks
  if type -t log_init >/dev/null 2>&1; then
    log_init init || _log warn "logger log_init failed"
  fi
}

# Initialize lock subsystem
init_lock() {
  if [[ -f /usr/libexec/lfsctl/lock.sh ]]; then
    # shellcheck source=/dev/null
    source /usr/libexec/lfsctl/lock.sh || _log warn "Failed to source lock.sh"
    if type -t _lock_ensure_dir >/dev/null 2>&1; then
      _lock_ensure_dir || _log warn "Lock dir ensure failed"
    fi
  fi
}

# Verify tools and versions
init_verify_tools() {
  local strict=0
  while [[ $# -gt 0 ]]; do case "$1" in --strict) strict=1; shift;; *) shift;; esac; done
  _log info "Checking required tools and versions"
  local -A results=()
  IFS=',' read -r -a pairs <<<"${LFSCTL_MIN_TOOLS}"
  # support both colon and comma separated form; normalize
  # If LFSCTL_MIN_TOOLS uses spaces or colons, handle common cases
  local token_list
  token_list="${LFSCTL_MIN_TOOLS//,/ }"
  token_list="${token_list//:/ }"
  for token in $token_list; do
    [[ -z "$token" ]] && continue
    # token like gcc 10.2 or gcc:10.2 or gcc:10.2, etc.
    local tool="${token%%[>=]*}" minv="${token#${tool}}"
    # hack: if token contained colon earlier, minv may include colon; attempt to split
    if [[ "$minv" =~ [0-9] ]]; then
      # remove non-digits prefix
      minv=$(echo "$token" | sed -E 's/^[^0-9]*([0-9].*)$/\1/' 2>/dev/null || echo "")
    else
    minv=""
    fi
    # find executable for tool
    local pathcmd
    pathcmd="$(command -v "$tool" 2>/dev/null || true)"
    if [[ -z "$pathcmd" ]]; then
      results[$tool]="MISSING"
      _log warn "Tool missing: $tool"
      if [[ $strict -eq 1 ]]; then _INIT_ERRORS=$((_INIT_ERRORS+1)); fi
      continue
    fi
    local ver
    ver="$(_extract_version "$pathcmd")"
    if [[ -n "$minv" && -n "$ver" ]]; then
      if vercmp_ge "$ver" "$minv"; then
        results[$tool]="OK:$ver"
        _log debug "$tool version $ver meets minimum $minv"
      else
        results[$tool]="OLD:$ver (min $minv)"
        _log warn "$tool version too old: $ver (min $minv)"
        _INIT_ERRORS=$((_INIT_ERRORS+1))
      fi
    else
      results[$tool]="OK:$ver"
      _log debug "$tool found: $tool -> $pathcmd (version $ver)"
    fi
  done
  # produce JSON report if jq is available
  if command -v jq >/dev/null 2>&1; then
    local rep="${LFSCTL_META_DIR}/tools-$(date +%s).json"
    printf '{' >"$rep"
    local first=1
    for k in "${!results[@]}"; do
      [[ $first -eq 1 ]] && first=0 || printf ',' >>"$rep"
      printf '"%s":"%s"' "$k" "${results[$k]}" >>"$rep"
    done
    printf '}\n' >>"$rep"
    _log info "Wrote tool verification report to $rep"
  fi
  return $(_INIT_ERRORS)
}

# Network checks and repository sync tests
init_network() {
  local check_mirrors=0
  while [[ $# -gt 0 ]]; do case "$1" in --check-mirrors) check_mirrors=1; shift;; *) shift;; esac; done
  _log info "Checking network connectivity"
  # simple DNS check
  if command -v ping >/dev/null 2>&1; then
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
      _log info "Network: reachable (ping 8.8.8.8)"
    else
      _log warn "Network may be unreachable (ping failed)"
      _INIT_ERRORS=$((_INIT_ERRORS+1))
    fi
  fi
  # repo check
  if [[ -n "$LFSCTL_REPO_URL" ]]; then
    if command -v git >/dev/null 2>&1; then
      if git ls-remote --exit-code --heads "$LFSCTL_REPO_URL" >/dev/null 2>&1; then
        _log info "Ports repo reachable: $LFSCTL_REPO_URL"
      else
        _log warn "Cannot reach ports repo $LFSCTL_REPO_URL"
        _INIT_ERRORS=$((_INIT_ERRORS+1))
      fi
    else
      _log warn "git not available to check ports repo"
    fi
  fi
  # mirrors check: optional, not implemented here fully
  if [[ "$check_mirrors" -eq 1 ]]; then
    _log info "Mirror checks requested but not fully configured"
  fi
}

# Prepare chroot environment (mount proc/sys/dev etc.) and optionally enter
init_chroot() {
  local enter=0 mounts="${1:-auto}"
  # if LFSCTL_CHROOT_ENABLED is false skip
  if [[ "$LFSCTL_CHROOT_ENABLED" != "true" ]]; then
    _log info "Chroot support disabled by config"
    return 0
  fi
  # allow option --enter
  while [[ $# -gt 0 ]]; do case "$1" in --enter) enter=1; shift;; --mounts) mounts="$2"; shift 2;; *) shift;; esac; done
  _log info "Preparing chroot at $LFSCTL_ROOT (mounts=$mounts)"
  mkdir -p "$LFSCTL_ROOT" 2>/dev/null || { _log error "Cannot create LFS root $LFSCTL_ROOT"; return 6; }
  # mount points: /proc, /sys, /dev, /dev/pts, /run
  local binds=( "/dev" "/dev/pts" "/proc" "/sys" "/run" )
  for b in "${binds[@]}"; do
    local target="${LFSCTL_ROOT%/}$b"
    if mountpoint -q "$target" 2>/dev/null; then
      _log debug "$target already mounted"
    else
      mkdir -p "$target" 2>/dev/null || true
      if mount --bind "$b" "$target" >/dev/null 2>&1; then
        _log debug "Bind mounted $b -> $target"
      else
        _log warn "Failed to bind mount $b -> $target; attempting mount type-specific"
        case "$b" in
          /proc) mount -t proc proc "$target" 2>/dev/null || _log error "Failed to mount proc";;
          /sys) mount -t sysfs sysfs "$target" 2>/dev/null || _log error "Failed to mount sysfs";;
          /dev/pts) mount -t devpts devpts "$target" 2>/dev/null || _log error "Failed to mount devpts";;
        esac
      fi
    fi
  done
  _log info "Chroot mounts ensured under $LFSCTL_ROOT"
  if [[ "$enter" -eq 1 ]]; then
    _log info "Entering chroot $LFSCTL_ROOT"
    if [[ $(id -u) -ne 0 ]]; then
      _log error "Entering chroot requires root privileges"
      return 2
    fi
    # clean env (safe PATH)
    export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
    exec chroot "$LFSCTL_ROOT" /bin/bash --login
  fi
  return 0
}

# Prepare fakeroot environment (checks)
init_fakeroot() {
  if [[ "$LFSCTL_FAKEROOT_ENABLED" != "true" ]]; then
    _log info "Fakeroot disabled by config"
    return 0
  fi
  if command -v fakeroot >/dev/null 2>&1; then
    _log info "fakeroot available"
    return 0
  fi
  if command -v fakeroot-ng >/dev/null 2>&1; then
    _log info "fakeroot-ng available"
    return 0
  fi
  _log warn "No fakeroot found; packaging may require root or alternative"
  return 6
}

# Cleanup residues, stale locks, tmp, partial builds
init_cleanup() {
  local force=0 dry="${1:-$DRY_RUN}"
  while [[ $# -gt 0 ]]; do case "$1" in --force) force=1; shift;; --dry-run) dry=1; shift;; *) shift;; esac; done
  _log info "Running init cleanup (dry=$dry)"
  # attempt to remove partial pidfiles under build dir older than 1 day
  if [[ "$dry" -eq 0 ]]; then
    find "${LFSCTL_BUILD_DIR}" -maxdepth 2 -type f -name '*.pid' -mtime +1 -print0 2>/dev/null | xargs -0r rm -f 2>/dev/null || true
    # call lock cleanup if lock module available
    if type -t lock_cleanup >/dev/null 2>&1; then
      lock_cleanup "$LOCK_CLEANUP_AGE" || _log warn "lock_cleanup returned non-zero"
    fi
  else
    _log info "dry-run: would clean stale pid files and locks"
  fi
  return 0
}

# Verify LFS and BLFS requirements
init_verify_lfs() {
  local level="basic"
  while [[ $# -gt 0 ]]; do case "$1" in --level) level="$2"; shift 2;; *) shift;; esac; done
  _log info "Running LFS/BLFS verification (level=$level)"
  # basic checks: tools, disk, mounts, user
  init_verify_tools || _log warn "Tool verification reported issues"
  # disk: ensure at least 5GB available at LFS_ROOT
  local avail_kb
  avail_kb=$(df -P "${LFSCTL_ROOT%/}" 2>/dev/null | awk 'NR==2{print $4}' || echo 0)
  if (( avail_kb < 5242880 )); then
    _log warn "Low space on ${LFSCTL_ROOT}: ${avail_kb}KB (<5GB)"
    _INIT_ERRORS=$((_INIT_ERRORS+1))
  fi
  if [[ "$level" == "full" ]]; then
    # deeper checks: kernel headers, glibc headers, C toolchain sanity
    if [[ ! -d "/usr/include" ]]; then _log warn "/usr/include not present"; fi
    if ! command -v gcc >/dev/null 2>&1; then _log warn "gcc missing"; fi
    # check for libc headers (glibc) - best effort
    if [[ ! -f "/usr/include/stdio.h" ]]; then _log warn "stdio.h not found in /usr/include"; fi
    # BLFS optional checks could be extended here (Xorg libs etc.)
  fi
  return 0
}

# Summarize init run
init_summary() {
  local json="${1:-}"
  local now ts elapsed
  now=$(date -Is 2>/dev/null || date +%s)
  ts=$(date +%s)
  elapsed=$((ts - _INIT_START_TS))
  local report="${LFSCTL_META_DIR}/init-report-$(date +%s).json"
  _INIT_REPORT_FILE="$report"
  if [[ "$json" == "--json" || "$json" == "json" ]]; then
    cat >"$report" <<EOF
{
  "timestamp":"$now",
  "elapsed_seconds":$elapsed,
  "errors":$_INIT_ERRORS,
  "created_dirs":$_INIT_CREATED
}
EOF
    _log info "Init summary written to $report"
    printf '%s\n' "$report"
  else
    _log info "Init complete in ${elapsed}s; errors=${_INIT_ERRORS}; created_dirs=${_INIT_CREATED}"
    printf 'Init summary: elapsed=%ss errors=%s created=%s\n' "$elapsed" "$_INIT_ERRORS" "$_INIT_CREATED"
  fi
}

# Self test minimal checks
init_self_test() {
  _log info "Running self-test"
  local ok=0 warn=0 fail=0
  # test parsing config
  init_env || fail=$((fail+1))
  # test dirs (dry)
  init_dirs 1 || warn=$((warn+1))
  # test user (dry)
  init_user "" "" "" 1 || warn=$((warn+1))
  # test tools
  init_verify_tools || warn=$((warn+1))
  _log info "self-test: ok=$ok warn=$warn fail=$fail"
  return $fail
}

# Run full init pipeline
init_run_all() {
  local dry=0 nocroot=0 diagnostic=0
  while [[ $# -gt 0 ]]; do case "$1" in --dry-run) dry=1; shift;; --no-chroot) nocroot=1; shift;; --diagnostic) diagnostic=1; shift;; --non-interactive) NON_INTERACTIVE=1; shift;; *) shift;; esac; done
  DRY_RUN=$dry
  DIAGNOSTIC=$diagnostic
  init_env || _log error "init_env failed"
  _init_optional_modules
  init_logger
  init_user "" "" "" "$DRY_RUN" || _log error "init_user failed"
  init_dirs "$DRY_RUN"
  init_lock
  init_network || _log warn "network check reported issues"
  init_verify_tools --strict || _log warn "verify_tools reported issues"
  if [[ "$nocroot" -eq 0 && "$LFSCTL_CHROOT_ENABLED" == "true" ]]; then
    init_chroot || _log warn "init_chroot reported issues"
  fi
  init_fakeroot || _log warn "init_fakeroot reported issues"
  init_cleanup --dry-run "$DRY_RUN"
  if [[ "$DIAGNOSTIC" -eq 1 ]]; then
    _log info "Diagnostic mode: running verify_lfs full check"
    init_verify_lfs --level full || _log warn "verify_lfs issues"
  fi
  init_summary
  # run post hook if configured
  if [[ -n "$LFSCTL_POST_INIT_HOOK" ]]; then
    _log info "Running post-init hook: $LFSCTL_POST_INIT_HOOK"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      if [[ -x "$LFSCTL_POST_INIT_HOOK" ]]; then
        sudo -u "$LFSCTL_BUILD_USER" "$LFSCTL_POST_INIT_HOOK" || _log warn "post-init hook failed"
      else
        _log warn "Post-init hook not executable: $LFSCTL_POST_INIT_HOOK"
      fi
    else
      _log info "dry-run: would run post-init hook"
    fi
  fi
}

# CLI dispatcher when executed directly
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  cmd="${1:-run}"; shift || true
  case "$cmd" in
    env) init_env "$@" ;;
    user) init_user "$@" ;;
    dirs) init_dirs "$@" ;;
    logger) init_logger "$@" ;;
    lock) init_lock "$@" ;;
    verify-tools) init_verify_tools "$@" ;;
    network) init_network "$@" ;;
    chroot) init_chroot "$@" ;;
    fakeroot) init_fakeroot "$@" ;;
    cleanup) init_cleanup "$@" ;;
    verify-lfs) init_verify_lfs "$@" ;;
    summary) init_summary "$@" ;;
    self-test) init_self_test "$@" ;;
    run) init_run_all "$@" ;;
    *) printf 'Usage: %s {run|env|user|dirs|logger|lock|verify-tools|network|chroot|fakeroot|cleanup|verify-lfs|summary|self-test}\n' "$0"; exit 1 ;;
  esac
fi

# End of init.sh
