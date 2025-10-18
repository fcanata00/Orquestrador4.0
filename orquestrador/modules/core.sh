#!/usr/bin/env bash
# lftool/lib/core.sh - Core utilities for lftool
# Generated: production-ready baseline implementing robust checks, logging, traps, locks and state.
set -Eeuo pipefail
IFS=$'\n\t'

# Basic env
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"

# Minimum bash version
_min_bash_major=4
if (( BASH_VERSINFO[0] < _min_bash_major )); then
  echo "ERROR: bash >= ${_min_bash_major} required. Current: $BASH_VERSION" >&2
  exit 2
fi

# Defaults (override via env or conf)
LF_ROOT="${LF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"
LF_CONFDIR="${LF_CONFDIR:-$LF_ROOT/conf}"
LF_LOGDIR="${LF_LOGDIR:-$LF_ROOT/logs}"
LF_CACHEDIR="${LF_CACHEDIR:-$LF_ROOT/cache}"
LF_WORKDIR="${LF_WORKDIR:-$LF_ROOT/work}"
LF_PKGS="${LF_PKGS:-$LF_ROOT/pkgs}"
LF_LOCKDIR="${LF_LOCKDIR:-$LF_CACHEDIR/.locks}"
LF_DEFAULT_MIN_DISK_MB="${LF_DEFAULT_MIN_DISK_MB:-2048}"
LF_JOBS="${LF_JOBS:-$(nproc || echo 1)}"
LF_VERBOSE="${LF_VERBOSE:-0}"
LF_DRYRUN="${LF_DRYRUN:-0}"
LF_FORCE="${LF_FORCE:-0}"
LF_IN_CHROOT="${LF_IN_CHROOT:-0}"
LF_CI_MODE="${LF_CI_MODE:-0}"

# Internal
__lf_logfile=""
__lf_cleanup_ran=0

# ---- utilities -------------------------------------------------------------

__lf_timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# color helpers (only if stdout is a tty and not in CI)
__lf_use_color() {
  if [[ "${LF_CI_MODE}" -ne 0 ]]; then return 1; fi
  [[ -t 1 ]]
}
__lf_color() {
  local code="$1"; shift
  if __lf_use_color; then printf "\033[${code}m%s\033[0m" "$*"; else printf "%s" "$*"; fi
}
__lf_log_common() {
  local level="$1"; shift
  local msg="$*"
  local ts; ts=$(__lf_timestamp)
  if [[ -n "$__lf_logfile" ]]; then
    printf "%s [%s] %s\n" "$ts" "$level" "$msg" >>"$__lf_logfile"
  fi
  case "$level" in
    INFO) printf "%s %s\n" "$ts" "$msg" ;;
    WARN) __lf_color "33" "$ts [WARN] $msg"; printf "\n"; ;;
    ERROR) __lf_color "31" "$ts [ERROR] $msg"; printf "\n" >&2; ;;
    DEBUG)
      if [[ "${LF_VERBOSE}" -ne 0 ]]; then __lf_color "35" "$ts [DEBUG] $msg"; printf "\n"; fi
      ;;
    *) printf "%s %s\n" "$ts" "$msg" ;;
  esac
}

__lf_log_info()  { __lf_log_common "INFO" "$*"; }
__lf_log_warn()  { __lf_log_common "WARN" "$*"; }
__lf_log_err()   { __lf_log_common "ERROR" "$*"; }
__lf_log_debug() { __lf_log_common "DEBUG" "$*"; }

# ensure directory exists with mode
__lf_ensure_dir() {
  local d="$1"; local mode="${2:-755}"
  if [[ ! -d "$d" ]]; then
    mkdir -p "$d"
    chmod "$mode" "$d" || true
  fi
}

# abs path without realpath
__lf_abs_path() {
  local p="$1"
  if [[ -z "$p" ]]; then
    return 1
  fi
  if [[ -d "$p" ]]; then
    (cd "$p" 2>/dev/null && pwd -P) || return 1
  else
    local dir; dir=$(dirname "$p")
    local base; base=$(basename "$p")
    (cd "$dir" 2>/dev/null && printf "%s/%s\n" "$(pwd -P)" "$base") || return 1
  fi
}

# sanitize string (remove dangerous chars/newlines)
__lf_sanitize() {
  local s="$1"
  s="${s//$'\n'/ }"
  # remove dangerous chars `;|&$()<>` and control chars
  s="$(printf '%s' "$s" | sed -E 's/[;&|$`<>]//g')"
  s="$(printf '%s' "$s" | tr -d '\000-\037')"
  printf "%s" "$s"
}

# check prerequisites with fallback hints
__lf_check_prereqs() {
  local miss=()
  local check_cmds=(bash tar git awk sed grep wget xz zstd make gcc fakeroot)
  for c in "${check_cmds[@]}"; do
    if ! command -v "$c" >/dev/null 2>&1; then
      miss+=("$c")
    fi
  done

  if ((${#miss[@]})); then
    __lf_log_warn "Missing prerequisites: ${miss[*]}"
    __lf_log_warn "Install missing tools (example for Debian/Ubuntu): sudo apt update && sudo apt install -y ${miss[*]}"
    # in CI we should fail
    if [[ "${LF_CI_MODE}" -ne 0 ]]; then
      __lf_log_err "CI mode: aborting due to missing prerequisites."
      exit 3
    fi
  else
    __lf_log_debug "All prerequisites present."
  fi
}

# detect chroot by comparing /proc/1/root
__lf_detect_chroot() {
  # If /proc/1/root is not equal to / then we are likely in containerish env.
  if [[ -e /proc/1/root ]]; then
    local root1; root1=$(readlink -f /proc/1/root || true)
    local rootcurr; rootcurr=$(readlink -f / || true)
    if [[ "$root1" != "$rootcurr" ]]; then
      LF_IN_CHROOT=1
    else
      LF_IN_CHROOT=0
    fi
  else
    LF_IN_CHROOT=0
  fi
  export LF_IN_CHROOT
  __lf_log_debug "LF_IN_CHROOT=${LF_IN_CHROOT}"
}

# require non-root unless forced or inside chroot where root is expected
__lf_require_nonroot() {
  if [[ "$(id -u)" -eq 0 && "${LF_IN_CHROOT}" -eq 0 && "${LF_FORCE}" -eq 0 ]]; then
    __lf_log_err "Refusing to run as root outside chroot. Rerun with --force to override."
    exit 4
  fi
}

__lf_require_root_or_fakeroot() {
  if [[ "$(id -u)" -ne 0 ]]; then
    if command -v fakeroot >/dev/null 2>&1; then
      __lf_log_warn "Not root: operations requiring root should run under fakeroot."
    else
      __lf_log_err "Root-required operation and fakeroot not available. Aborting."
      exit 5
    fi
  fi
}

# state dir per package
__lf_state_dir_for() {
  local pkg="$1"
  if [[ -z "$pkg" ]]; then
    echo ""
    return 1
  fi
  printf "%s/%s/.state" "$LF_WORKDIR" "$pkg"
}

# mark done atomically
__lf_mark_done() {
  local pkg="$1"; local step="$2"
  local sd; sd="$(__lf_state_dir_for "$pkg")"
  __lf_ensure_dir "$sd"
  local tmp="${sd}/${step}.tmp"
  local target="${sd}/${step}"
  printf "%s\n" "$(__lf_timestamp)" >"$tmp"
  mv -f "$tmp" "$target"
  __lf_log_debug "Marked done: $pkg/$step"
}

__lf_is_done() {
  local pkg="$1"; local step="$2"
  local sd; sd="$(__lf_state_dir_for "$pkg")"
  [[ -f "${sd}/${step}" ]]
}

# lock acquire/release using mkdir atomic
__lf_acquire_lock() {
  local pkg="$1"
  __lf_ensure_dir "$LF_LOCKDIR"
  local lockdir="$LF_LOCKDIR/$pkg.lock"
  if mkdir "$lockdir" 2>/dev/null; then
    echo $$ >"$lockdir/pid"
    return 0
  else
    # check pid alive
    if [[ -f "$lockdir/pid" ]]; then
      local p; p=$(cat "$lockdir/pid" 2>/dev/null || echo "")
      if [[ -n "$p" && ! -d "/proc/$p" ]]; then
        # stale lock, remove
        __lf_log_warn "Removing stale lock for $pkg (pid $p no longer exists)"
        rm -rf "$lockdir"
        if mkdir "$lockdir" 2>/dev/null; then
          echo $$ >"$lockdir/pid"
          return 0
        fi
      fi
    fi
    __lf_log_warn "Package $pkg is locked by another process. PID file: $lockdir/pid"
    return 1
  fi
}

__lf_release_lock() {
  local pkg="$1"
  local lockdir="$LF_LOCKDIR/$pkg.lock"
  if [[ -d "$lockdir" ]]; then
    rm -rf "$lockdir"
    __lf_log_debug "Released lock for $pkg"
  fi
}

# create tmp dir for package
__lf_tmp_dir() {
  local pkg="$1"
  local prefix="${LF_WORKDIR}/${pkg}/tmp-$$-$(date +%s)"
  __lf_ensure_dir "$prefix"
  echo "$prefix"
}

# sysinfo: cpu%, mem used MB, load averages
__lf_sysinfo() {
  local info=""
  if [[ -r /proc/stat && -r /proc/meminfo ]]; then
    # simple mem
    local mem_total mem_free mem_used
    mem_total=$(awk '/MemTotal/ {print $2}' /proc/meminfo || echo 0)
    mem_free=$(awk '/MemAvailable/ {print $2}' /proc/meminfo || echo 0)
    mem_used=$(( (mem_total - mem_free) / 1024 ))
    local load; load=$(cut -d' ' -f1-3 /proc/loadavg || echo "0 0 0")
    info="mem=${mem_used}MB load=${load}"
  fi
  printf "%s" "$info"
}

# run command with logging, time, pipefail
# usage: __lf_run_cmd "label" -- cmd arg...
__lf_run_cmd() {
  local label="$1"; shift
  if [[ "$1" == "--" ]]; then shift; else __lf_log_err "internal: expected -- in __lf_run_cmd"; exit 6; fi
  local cmd=( "$@" )
  local start; start=$(date +%s)
  __lf_log_info "[RUN] $label: ${cmd[*]}"
  if [[ -n "$__lf_logfile" ]]; then
    if [[ "${LF_DRYRUN}" -ne 0 ]]; then
      __lf_log_info "[DRYRUN] Would run: ${cmd[*]}"
      return 0
    fi
    set -o pipefail
    if "${cmd[@]}" 2>&1 | tee -a "$__lf_logfile"; then
      local ret=0
    else
      local ret=${PIPESTATUS[0]:-${?}}
    fi
  else
    if "${cmd[@]}"; then
      local ret=0
    else
      local ret=$?
    fi
  fi
  local end; end=$(date +%s)
  local dur=$((end - start))
  local si; si=$(__lf_sysinfo)
  if [[ "$ret" -ne 0 ]]; then
    __lf_log_err "[FAIL] $label after ${dur}s (sys: $si) - exit $ret"
    # append tail of log if exists
    if [[ -n "$__lf_logfile" && -f "$__lf_logfile" ]]; then
      __lf_log_err "Last 200 lines of log:"
      tail -n 200 "$__lf_logfile" >&2 || true
    fi
    return "$ret"
  else
    __lf_log_info "[OK] $label completed in ${dur}s (sys: $si)"
    return 0
  fi
}

# disk space check (min MB)
__lf_check_diskspace() {
  local path="${1:-/}"
  local min_mb="${2:-$LF_DEFAULT_MIN_DISK_MB}"
  local avail; avail=$(df --output=avail -m "$path" 2>/dev/null | tail -n1 || echo 0)
  if [[ -z "$avail" ]]; then avail=0; fi
  if (( avail < min_mb )); then
    __lf_log_err "Insufficient disk space on $path: ${avail}MB < ${min_mb}MB required"
    return 1
  fi
  return 0
}

# adjust jobs based on memory heuristics
__lf_adjust_jobs() {
  local mem_mb; mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo || echo 0)
  local procs; procs=$(nproc || echo 1)
  # assume 1GB per job required; adjust conservatively
  local max_jobs=$procs
  if (( mem_mb > 0 )); then
    local mem_jobs=$(( mem_mb / 1024 ))
    if (( mem_jobs < max_jobs )); then max_jobs=$mem_jobs; fi
    if (( max_jobs < 1 )); then max_jobs=1; fi
  fi
  LF_JOBS=${LF_JOBS:-$max_jobs}
  export LF_JOBS
  __lf_log_debug "Adjusted LF_JOBS=${LF_JOBS} (mem ${mem_mb}MB, procs ${procs})"
}

# trap handlers
__lf_trap_err() {
  local lineno="${1:-0}"; local cmd="${2:-}"
  __lf_log_err "Error at line ${lineno}: ${cmd}"
  __lf_cleanup_temp
}

__lf_trap_exit() {
  local code=${1:-0}; local lineno=${2:-0}
  if (( code != 0 )); then
    __lf_log_err "Exiting with code ${code}"
  else
    __lf_log_info "Exiting normally"
  fi
  __lf_flush_logs
  __lf_cleanup_temp
  return "$code"
}

__lf_trap_int() {
  __lf_log_warn "Interrupted (SIGINT). Cleaning up..."
  __lf_cleanup_temp
  exit 130
}

__lf_trap_term() {
  __lf_log_warn "Termination requested (SIGTERM). Cleaning up..."
  __lf_cleanup_temp
  exit 143
}

# cleanup function idempotent
__lf_cleanup_temp() {
  if [[ "$__lf_cleanup_ran" -ne 0 ]]; then return 0; fi
  __lf_cleanup_ran=1
  __lf_log_debug "Running cleanup..."
  # attempt to unmount bind mounts in work dirs (best effort)
  if mountpoint -q "$LF_WORKDIR" 2>/dev/null; then
    # do nothing; user space decide
    :
  fi
  # remove tmp dirs older than a day (best-effort)
  if [[ -d "$LF_WORKDIR" ]]; then
    find "$LF_WORKDIR" -maxdepth 2 -type d -name 'tmp-*' -mtime +1 -exec rm -rf {} + 2>/dev/null || true
  fi
  # release any locks owned by this pid
  if [[ -d "$LF_LOCKDIR" ]]; then
    for d in "$LF_LOCKDIR"/*.lock 2>/dev/null; do
      [[ -d "$d" ]] || continue
      local p; p=$(cat "$d/pid" 2>/dev/null || echo "")
      if [[ "$p" == "$$" ]]; then
        rm -rf "$d"
      fi
    done
  fi
  __lf_log_debug "Cleanup complete."
}

# rotate logs if too big (default 100MB)
__lf_rotate_logs() {
  local max_bytes=$((100 * 1024 * 1024))
  if [[ -f "$__lf_logfile" ]]; then
    local size; size=$(stat -c%s "$__lf_logfile" 2>/dev/null || echo 0)
    if (( size > max_bytes )); then
      mv "$__lf_logfile" "${__lf_logfile}.$(date +%s).old"
      __lf_log_info "Rotated large log file."
    fi
  fi
}

__lf_flush_logs() {
  # no-op in this context; ensure stdout/stderr flushed
  true
}

# load configuration files from conf dir (safe)
__lf_load_config() {
  __lf_ensure_dir "$LF_CONFDIR"
  for f in "$LF_CONFDIR"/*.conf; do
    [[ -f "$f" ]] || continue
    __lf_log_debug "Loading config $f"
    # read line by line; accept KEY=VALUE where KEY matches /^[A-Z0-9_]+$/
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"         # strip comments
      line="${line%"${line##*[![:space:]]}"}" # rstrip
      line="${line#"${line%%[![:space:]]*}"}" # lstrip
      [[ -z "$line" ]] && continue
      if [[ "$line" =~ ^([A-Z0-9_]+)=(.*)$ ]]; then
        local k=${BASH_REMATCH[1]}
        local v=${BASH_REMATCH[2]}
        # sanitize value
        v="$(__lf_sanitize "$v")"
        # export as LF_ prefixed if not already
        if [[ "$k" != LF_* ]]; then
          k="LF_${k}"
        fi
        export "$k"="$v"
        __lf_log_debug "Config: $k set"
      else
        __lf_log_warn "Skipping invalid config line in $f: $line"
      fi
    done <"$f"
  done
}

# initialize environment
__lf_prepare_env() {
  __lf_ensure_dir "$LF_ROOT"
  __lf_ensure_dir "$LF_LOGDIR"
  __lf_ensure_dir "$LF_CACHEDIR"
  __lf_ensure_dir "$LF_WORKDIR"
  __lf_ensure_dir "$LF_PKGS"
  __lf_ensure_dir "$LF_LOCKDIR"
  umask 022
  # default logfile (per run)
  local name="core-$(date +%Y%m%d-%H%M%S).log"
  __lf_logfile="${LF_LOGDIR}/${name}"
  __lf_rotate_logs
  __lf_log_info "Initializing lftool core (root: $LF_ROOT)"
  __lf_detect_chroot
  __lf_load_config
  __lf_check_prereqs
  __lf_adjust_jobs
  __lf_log_info "Environment prepared. LF_JOBS=${LF_JOBS}"
}

# self-check utility for CI/manual
__lf_selfcheck() {
  __lf_log_info "Running selfcheck..."
  __lf_check_prereqs || return 1
  __lf_check_diskspace "/" 512 || __lf_log_warn "Low disk space (<512MB) on /"
  # test lock acquire/release
  __lf_acquire_lock "selfcheck-test" || { __lf_log_warn "Lock acquire failed (selfcheck)"; }
  __lf_release_lock "selfcheck-test"
  __lf_log_info "Selfcheck complete."
}

# basic manifest writer
__lf_write_manifest() {
  local pkg="$1"; local dest="$2"
  __lf_ensure_dir "$(dirname "$dest")"
  jq -n --arg pkg "$pkg" --arg ts "$(__lf_timestamp)" '{package:$pkg, generated:$ts}' >"$dest" 2>/dev/null || printf '{"package":"%s","generated":"%s"}\n' "$pkg" "$(__lf_timestamp)" >"$dest"
}

# help text
__lf_show_help() {
  cat <<'EOF'
lftool core helper - functions (sourced)
Environment variables:
  LF_ROOT LF_CONFDIR LF_LOGDIR LF_CACHEDIR LF_WORKDIR LF_PKGS LF_JOBS
Flags:
  LF_DRYRUN=1  - don't execute destructive actions
  LF_VERBOSE=1 - verbose debug logs
  LF_FORCE=1   - override safety checks
  LF_CI_MODE=1 - CI-friendly, no colors
Utilities exported:
  __lf_prepare_env
  __lf_run_cmd
  __lf_mark_done
  __lf_is_done
  __lf_acquire_lock
  __lf_release_lock
  __lf_tmp_dir
  __lf_check_diskspace
  __lf_adjust_jobs
  __lf_selfcheck
EOF
}

# ---- initialize traps ----
trap '__lf_trap_err $LINENO "$BASH_COMMAND"' ERR
trap '__lf_trap_exit $? $LINENO' EXIT
trap '__lf_trap_int' INT
trap '__lf_trap_term' TERM

# If script executed directly, run prepare and show help
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  __lf_prepare_env
  if [[ "${1:-}" == "--selfcheck" ]]; then
    __lf_selfcheck
    exit $?
  fi
  __lf_show_help
fi
