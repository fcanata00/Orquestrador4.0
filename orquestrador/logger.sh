#!/usr/bin/env bash
# lfsctl logger module
# Path: /usr/libexec/lfsctl/logger.sh (suggested)
# License: MIT
# Purpose: Robust, concurrent-safe logging for lfsctl
# Note: Designed to be sourced by other scripts after config_init from config.sh
set -euo pipefail

# Default values (overridable by config.sh before sourcing)
: "${LFSCTL_LOG_DIR:=/var/lfsctl/logs}"
: "${LFSCTL_LOG_LEVEL:=info}"
: "${LFSCTL_COLOR:=auto}"
: "${LFSCTL_BUILD_USER:=lfsbuild}"
: "${LFSCTL_FALLBACK_LOG_DIR:=/tmp/lfsctl-logs}"

# Internal state
declare -A _LOG_LEVELS=( [silent]=0 [error]=1 [warn]=2 [info]=3 [debug]=4 [trace]=5 )
_LOG_NUM=${_LOG_LEVELS[${LFSCTL_LOG_LEVEL:-info}]:-3}
_LOG_FD=3
_LOG_FILE=""
_LOG_DIR_CURRENT=""
_LOG_CREATED_FALLBACK=0
: "${LFSCTL_PID:=$$}"

# detect whether output is a TTY for color behaviour
_is_tty() {
  [[ -t 1 ]]
}

# color helpers using tput if available
_color_code() {
  case "$1" in
    red)  printf '%b' "$(tput setaf 1 2>/dev/null || echo '')";;
    green) printf '%b' "$(tput setaf 2 2>/dev/null || echo '')";;
    yellow) printf '%b' "$(tput setaf 3 2>/dev/null || echo '')";;
    blue) printf '%b' "$(tput setaf 4 2>/dev/null || echo '')";;
    magenta) printf '%b' "$(tput setaf 5 2>/dev/null || echo '')";;
    cyan) printf '%b' "$(tput setaf 6 2>/dev/null || echo '')";;
    gray) printf '%b' "$(tput setaf 7 2>/dev/null || echo '')";;
    reset) printf '%b' "$(tput sgr0 2>/dev/null || echo '')";;
    *) ;;
  esac
}

# sanitize messages: remove non-printable chars, protect against control sequences
_sanitize_msg() {
  local msg="$1"
  # replace non-printable except tab/newline with ?
  printf '%s' "$msg" | sed -r 's/[^[:print:]\t]//g'
}

# transform level name to numeric
_level_num() {
  local lvl="${1:-info}"
  echo "${_LOG_LEVELS[$lvl]:-${_LOG_LEVELS[info]}}"
}

# choose whether to output colors to terminal
_use_colors() {
  case "${LFSCTL_COLOR:-auto}" in
    always) return 0;;
    never) return 1;;
    auto)
      _is_tty && return 0 || return 1
      ;;
    *) _is_tty && return 0 || return 1 ;;
  esac
}

# ensure directory exists and is writable; fallback to /tmp on failure
_log_ensure_dir() {
  local dir="$1"
  if [[ -d "$dir" && -w "$dir" ]]; then
    return 0
  fi
  if [[ ! -d "$dir" ]]; then
    mkdir -p "$dir" 2>/dev/null || true
  fi
  if [[ -d "$dir" && -w "$dir" ]]; then
    return 0
  fi
  # fallback
  mkdir -p "${LFSCTL_FALLBACK_LOG_DIR}" 2>/dev/null || true
  if [[ -d "${LFSCTL_FALLBACK_LOG_DIR}" && -w "${LFSCTL_FALLBACK_LOG_DIR}" ]]; then
    _LOG_CREATED_FALLBACK=1
    _config_fallback_warn "Log dir $dir not writable; falling back to ${LFSCTL_FALLBACK_LOG_DIR}"
    return 0
  fi
  return 1
}

# helper to write bootstrap warnings (used before logger fully initialized)
_config_fallback_warn() {
  local msg="$1"; shift
  local bf="${LFSCTL_FALLBACK_LOG_DIR}/fallback.log"
  mkdir -p "$(dirname "$bf")" 2>/dev/null || true
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$msg" >>"$bf" 2>/dev/null || true
  >&2 printf 'WARNING: %s\n' "$msg"
}

# acquire exclusive logfile descriptor with flock and retries
_log_open_file() {
  local pkg_name="${1:-session}"
  local date_dir subdir file fd retries=0 max_retries=5 wait=0.1 lockfile
  date_dir="$(date +%F)"
  _LOG_DIR_CURRENT="${LFSCTL_LOG_DIR%/}/${date_dir}"
  if ! _log_ensure_dir "$_LOG_DIR_CURRENT"; then
    # fallback dir should already be ensured
    _LOG_DIR_CURRENT="${LFSCTL_FALLBACK_LOG_DIR%/}/$date_dir"
    mkdir -p "$_LOG_DIR_CURRENT" 2>/dev/null || true
  fi
  mkdir -p "$_LOG_DIR_CURRENT" 2>/dev/null || true
  subdir="${_LOG_DIR_CURRENT}/${pkg_name}-$LFSCTL_PID"
  mkdir -p "$subdir" 2>/dev/null || true
  file="${subdir}/${pkg_name}-${LFSCTL_PID}.log"
  lockfile="${subdir}/.lock"
  # Try to open and lock fd
  while :; do
    # ensure file exists
    touch "$file" 2>/dev/null || true
    # open fd 3 for append
    exec {fd}>>"$file" || { _config_fallback_warn \"Cannot open log file $file\"; return 2; }
    # try flock non-blocking, on fd
    if command -v flock >/dev/null 2>&1; then
      if flock -n "$fd"; then
        _LOG_FD=$fd
        _LOG_FILE="$file"
        return 0
      else
        # couldn't get lock; close fd and retry with backoff
        eval "exec ${fd}>&-"
        retries=$((retries+1))
        if [[ $retries -gt $max_retries ]]; then
          _config_fallback_warn \"Could not lock $file after $retries attempts\"
          # fallback: use per-process fallback file
          local fb="${LFSCTL_FALLBACK_LOG_DIR%/}/fallback-${pkg_name}-${LFSCTL_PID}.log"
          mkdir -p "$(dirname "$fb")" 2>/dev/null || true
          exec {fd}>>"$fb" || return 3
          if flock -n "$fd"; then
            _LOG_FD=$fd
            _LOG_FILE="$fb"
            return 0
          else
            eval "exec ${fd}>&-"
            return 3
          fi
        fi
        sleep "$wait"
        wait=$(awk "BEGIN {print $wait * 2}") || wait=0.5
        continue
      fi
    else\n      # no flock available: keep fd open and use it (best-effort)\n      _LOG_FD=$fd\n      _LOG_FILE=\"$file\"\n      return 0\n    fi\n  done\n}\n\n# Close log fd if open\n_log_close() {\n  if [[ -n \"${_LOG_FD:-}\" ]]; then\n    # close fd\n    eval \"exec ${_LOG_FD}>&-\" 2>/dev/null || true\n    unset _LOG_FD || true\n  fi\n}\n\n# format timestamp\n_log_timestamp() {\n  date -u +\"%Y-%m-%dT%H:%M:%SZ\"\n}\n\n# core log writer: writes to fd and optionally to stdout with color\n_log_write() {\n  local level=\"$1\" msg=\"$2\" ts pid\n  ts=$(_log_timestamp)\n  pid=\"${LFSCTL_PID:-$$}\"\n  msg=$(_sanitize_msg \"$msg\")\n  local line=\"${ts} ${level^^} [pid=${pid}] ${msg}\" # file format\n\n  # write to file via fd if available\n  if [[ -n \"${_LOG_FD:-}\" ]]; then\n    # use printf to fd\n    printf '%s\\n' \"$line\" >&${_LOG_FD} 2>/dev/null || {\n      # Write failed: fallback\n      _config_fallback_warn \"Write to log file failed; writing to stderr\"\n      >&2 printf '%s %s\\n' \"$ts\" \"$msg\"\n    }\n  else\n    # no fd: try to open default session log\n    _log_open_file \"session\" || {\n      >&2 printf '%s %s\\n' \"$ts\" \"$msg\"\n      return 2\n    }\n    printf '%s\\n' \"$line\" >&${_LOG_FD} 2>/dev/null || true\n  fi\n\n  # Console output based on level and configured threshold\n  local lvlnum\n  lvlnum=$(_level_num \"$level\")\n  if [[ $lvlnum -le $_LOG_NUM ]]; then\n    # colorize for console if appropriate\n    local outmsg=\"$msg\" prefix=\"[${level^^}]\"\n    if _use_colors; then\n      case \"$level\" in\n        error) printf '%s%s%s %s\\n' \"$(_color_code red)\" \"$prefix\" \"$(_color_code reset)\" \"$outmsg\" ;;\n        warn) printf '%s%s%s %s\\n' \"$(_color_code yellow)\" \"$prefix\" \"$(_color_code reset)\" \"$outmsg\" ;;\n        info) printf '%s%s%s %s\\n' \"$(_color_code blue)\" \"$prefix\" \"$(_color_code reset)\" \"$outmsg\" ;;\n        debug) printf '%s%s%s %s\\n' \"$(_color_code magenta)\" \"$prefix\" \"$(_color_code reset)\" \"$outmsg\" ;;\n        success) printf '%s%s%s %s\\n' \"$(_color_code green)\" \"$prefix\" \"$(_color_code reset)\" \"$outmsg\" ;;\n        *) printf '%s %s\\n' \"$prefix\" \"$outmsg\" ;;\n      esac\n    else\n      printf '[%s] %s\\n' \"${level^^}\" \"$outmsg\"\n    fi\n  fi\n}\n\n# Public wrapper functions\nlog_init() {\n  local pkgname=\"${1:-session}\"\n  # ensure config variables exist\n  : \"${LFSCTL_LOG_DIR:=/var/lfsctl/logs}\"\n  : \"${LFSCTL_FALLBACK_LOG_DIR:=/tmp/lfsctl-logs}\"\n  # attempt to open file for this pkg\n  if ! _log_open_file \"$pkgname\"; then\n    _config_fallback_warn \"Logger failed to initialize for pkg=$pkgname\"\n    return 2\n  fi\n  # set a trap to close fd on exit\n  trap '_log_close' EXIT\n  log_debug \"Logger initialized (file=${_LOG_FILE})\"\n  return 0\n}\n\nlog_set_level() {\n  local lvl=\"$1\"\n  if [[ -z \"${lvl:-}\" || -z \"${_LOG_LEVELS[$lvl]:-}\" ]]; then\n    log_warn \"Ignored invalid log level: $lvl\"\n    return 1\n  fi\n  _LOG_NUM=${_LOG_LEVELS[$lvl]}\n  return 0\n}\n\nlog_msg() {\n  local level=\"$1\"; shift\n  local msg=\"${*:-}\"\n  if [[ -z \"$level\" || -z \"$msg\" ]]; then\n    return 1\n  fi\n  _log_write \"$level\" \"$msg\"\n}\n\nlog_info() { log_msg info \"$*\"; }\nlog_warn() { log_msg warn \"$*\"; }\nlog_error() {\n  log_msg error \"$*\"\n}\nlog_debug() { log_msg debug \"$*\"; }\nlog_success() { log_msg success \"$*\"; }\n\n# Execute a command and log its stdout/stderr to files and console\nlog_trace() {\n  local cmd=(\"$@\")\n  local base=\"${_LOG_DIR_CURRENT:-/tmp}/trace-${LFSCTL_PID}\"\n  mkdir -p \"$(dirname \"$base\")\" 2>/dev/null || true\n  local stdoutf=\"${base}.stdout.log\" stderrf=\"${base}.stderr.log\"\n  # Run command, capture outputs\n  \"${cmd[@]}\" > >(tee -a \"$stdoutf\" >&2) 2> >(tee -a \"$stderrf\" >&2)\n  local rc=$?\n  if [[ $rc -ne 0 ]]; then\n    log_error \"Command failed (${cmd[*]}) rc=$rc; stdout=${stdoutf} stderr=${stderrf}\"\n  else\n    log_info \"Command succeeded: ${cmd[*]}\"\n  fi\n  return $rc\n}\n\n# Rotate old logs (daily rotation) - compress files older than days\nlog_rotate() {\n  local days=${1:-7}\n  if ! command -v zstd >/dev/null 2>&1 && ! command -v gzip >/dev/null 2>&1; then\n    log_warn \"No compressor (zstd/gzip) found; skipping compression during rotation\"\n    return 1\n  fi\n  find \"${LFSCTL_LOG_DIR:-/var/lfsctl/logs}\" -type f -mtime +$days -print0 | while IFS= read -r -d '' f; do\n    if [[ -f \"$f\" ]]; then\n      if command -v zstd >/dev/null 2>&1; then\n        zstd -q \"$f\" && rm -f \"$f\" || log_warn \"Failed to compress $f\"\n      else\n        gzip -9 \"$f\" && rm -f \"$f\" || log_warn \"Failed to compress $f\"\n      fi\n    fi\n  done\n}\n\n# summary at exit - optional\nlog_summary() {\n  # simple stats: lines in current log\n  if [[ -n \"${_LOG_FILE:-}\" && -f \"${_LOG_FILE}\" ]]; then\n    local lines\n    lines=$(wc -l <\"${_LOG_FILE}\" 2>/dev/null || echo 0)\n    printf 'Log file: %s (lines=%s)\\n' \"${_LOG_FILE}\" \"$lines\"\n  fi\n}\n\n# If the script is executed directly, run a small demo\nif [[ \"${BASH_SOURCE[0]}\" == \"$0\" ]]; then\n  # basic standalone demo\n  log_init demo || exit 1\n  log_info \"Logger demo start\"\n  log_debug \"Debug message\"\n  log_warn \"Warning example\"\n  log_error \"Error example\"\n  log_success \"Success example\"\n  log_summary\nfi\n