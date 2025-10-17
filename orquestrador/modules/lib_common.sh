#!/usr/bin/env bash
# lib_common.sh - v0.2
# Biblioteca comum para LFS build system (logging, locks, safe_run, progress, metrics)
# Requisitos: bash, coreutils; opcional: logger, flock, tput, /proc
#
# Usage:
#   source lib_common.sh
#   libcommon_init "module-name"
#
# Globals exported:
#   MODULE_NAME, LOG_DIR, LOG_FILE, LOG_LEVEL, SYSLOG, DRY_RUN, QUIET, ERROR_SILENT, KEEP_TEMP

set -o errtrace
set -o pipefail

LIBCOMMON_VERSION="0.2"
: "${LOG_LEVEL:=INFO}"
: "${SYSLOG:=0}"
: "${MAX_LOG_SIZE:=10485760}"
: "${MAX_LOG_ROTATE:=5}"
: "${DRY_RUN:=0}"
: "${QUIET:=0}"
: "${ERROR_SILENT:=0}"
: "${KEEP_TEMP:=0}"
: "${SAFE_RUN_STRICT:=1}"
: "${LOCK_TTL:=600}"

_LIBCOMMON_STARTED=0
_MODULE_NAME=""
_LOG_DIR=""
_LOG_FILE=""
_TMPDIR=""
_TMPDIRS=()
_LOCKFILES=()

is_tty() {
  [[ -t 1 && -t 2 ]]
}

timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

bytes_to_human() {
  local bytes=$1
  if (( bytes < 1024 )); then
    printf "%dB" "$bytes"
  elif (( bytes < 1048576 )); then
    awk -v b=$bytes 'BEGIN{printf "%.1fK", b/1024}'
  elif (( bytes < 1073741824 )); then
    awk -v b=$bytes 'BEGIN{printf "%.1fM", b/1048576}'
  else
    awk -v b=$bytes 'BEGIN{printf "%.1fG", b/1073741824}'
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "require_cmd: missing required command: $cmd"
    return 1
  fi
  return 0
}

_init_colors() {
  if is_tty && command -v tput >/dev/null 2>&1; then
    RED="$(tput setaf 1)"
    GREEN="$(tput setaf 2)"
    YELLOW="$(tput setaf 3)"
    BLUE="$(tput setaf 4)"
    BOLD="$(tput bold)"
    NORMAL="$(tput sgr0)"
  else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; NORMAL=""
  fi
}

_rotate_once() {
  local f="$1"
  local i
  for ((i=MAX_LOG_ROTATE-1;i>=1;i--)); do
    if [[ -f "${f}.$i" ]]; then
      mv -f "${f}.$i" "${f}.$((i+1))" 2>/dev/null || true
    fi
  done
  if [[ -f "$f" ]]; then
    mv -f "$f" "${f}.1" 2>/dev/null || true
  fi
}

rotate_logs() {
  local f="${LOG_FILE:-}"
  if [[ -z "$f" || ! -f "$f" ]]; then
    return 0
  fi
  local sz
  sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
  if (( sz >= MAX_LOG_SIZE )); then
    _rotate_once "$f"
  fi
}

_log_line() {
  local level="$1"; shift
  local module="${MODULE_NAME:-libcommon}"
  local msg="$*"
  local ts
  ts="$(timestamp)"
  local line="[$ts] [$level] [$module] $msg"
  if [[ -n "$LOG_FILE" ]]; then
    printf '%s\n' "$line" >>"$LOG_FILE"
  fi
  if (( SYSLOG )); then
    if command -v logger >/dev/null 2>&1; then
      logger -t "$module" -- "$line" >/dev/null 2>&1 || true
    fi
  fi
  if (( QUIET )); then
    return 0
  fi
  case "$level" in
    DEBUG)
      if [[ "$LOG_LEVEL" == "DEBUG" ]]; then
        printf '%s\n' "${BLUE}${line}${NORMAL}"
      fi
      ;;
    INFO)
      printf '%s\n' "${GREEN}${line}${NORMAL}"
      ;;
    WARN)
      printf '%s\n' "${YELLOW}${line}${NORMAL}"
      ;;
    ERROR)
      if (( ERROR_SILENT )); then
        :
      else
        printf '%s\n' "${RED}${line}${NORMAL}" >&2
      fi
      ;;
    *)
      printf '%s\n' "$line"
      ;;
  esac
}

log_debug() { [[ "$LOG_LEVEL" == "DEBUG" ]] && _log_line "DEBUG" "$*"; }
log_info()  { _log_line "INFO"  "$*"; }
log_warn()  { _log_line "WARN"  "$*"; }
log_error() { _log_line "ERROR" "$*"; }

log_metrics() {
  local metrics="$*"
  _log_line "INFO" "METRICS: $metrics"
}

_get_cpu_pct() {
  if [[ ! -r /proc/stat ]]; then
    echo "N/A"
    return
  fi
  read -r cpu a b c d e f g h i j < /proc/stat
  local total1=$((a+b+c+d+e+f+g+h))
  local idle1=$d
  sleep 0.2
  read -r cpu a b c d e f g h i j < /proc/stat
  local total2=$((a+b+c+d+e+f+g+h))
  local idle2=$d
  local totald=$((total2 - total1))
  local idled=$((idle2 - idle1))
  if (( totald == 0 )); then
    echo "0.0"
    return
  fi
  awk -v t="$totald" -v i="$idled" 'BEGIN{printf "%.1f", (t-i)/t*100}'
}

_get_mem() {
  if [[ ! -r /proc/meminfo ]]; then
    echo "N/A"
    return
  fi
  local mem_total mem_free buff_cache
  mem_total=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
  mem_free=$(awk '/^MemFree:/ {print $2}' /proc/meminfo)
  buff_cache=$(awk '/^Buffers:/ {b=$2} /^Cached:/ {c=$2} END{print b+c}' /proc/meminfo)
  local used_kb=$((mem_total - mem_free - buff_cache))
  bytes_to_human $((used_kb*1024))
}

_get_load() {
  awk '{print $1}' /proc/loadavg 2>/dev/null
}

get_metrics() {
  local cpu mem load
  cpu=$(_get_cpu_pct)
  mem=$(_get_mem)
  load=$(_get_load)
  printf "CPU=%s MEM=%s LOAD=%s" "$cpu" "$mem" "$load"
}

mktempdir_safe() {
  local dir
  dir=$(mktemp -d "${TMPDIR:-/tmp}/lfscommon.XXXXXX") || {
    log_error "mktempdir_safe: failed to create tempdir"
    return 1
  }
  chmod 700 "$dir" || true
  _TMPDIRS+=("$dir")
  echo "$dir"
}

_cleanup_tmpdirs() {
  for d in "${_TMPDIRS[@]:-}"; do
    if [[ -n "$d" && -d "$d" && $KEEP_TEMP -eq 0 ]]; then
      rm -rf "$d" >/dev/null 2>&1 || true
    fi
  done
}

with_lock() {
  local lockname="$1"; shift
  local cmd=( "$@" )
  local lockdir="${LOCK_DIR:-/var/lock/lfsports}"
  mkdir -p "$lockdir" >/dev/null 2>&1 || lockdir="/tmp"
  local lockfile="$lockdir/${lockname}.lock"
  if command -v flock >/dev/null 2>&1; then
    exec 200>"$lockfile"
    flock -n 200 || { flock 200; }
    "${cmd[@]}"
    local rc=$?
    exec 200>&-
    return $rc
  else
    mkdir "$lockfile" 2>/dev/null || return 1
    echo "$$" >"$lockfile/pid"
    _LOCKFILES+=("$lockfile")
    "${cmd[@]}"
    local rc=$?
    rm -rf "$lockfile" >/dev/null 2>&1 || true
    return $rc
  fi
}

_cleanup_locks() {
  for lf in "${_LOCKFILES[@]:-}"; do
    rm -rf "$lf" >/dev/null 2>&1 || true
  done
}

progress_start() {
  if ! is_tty; then
    _PROGRESS_ACTIVE=0
    return 0
  fi
  _PROGRESS_ACTIVE=1
  _PROGRESS_DESC="$1"
  _PROGRESS_TOTAL="${2:-100}"
  _PROGRESS_CUR=0
}

progress_update() {
  if (( _PROGRESS_ACTIVE == 0 )); then return 0; fi
  local cur="$1"; local total="${2:-$_PROGRESS_TOTAL}"
  _PROGRESS_CUR="$cur"
  local pct=$((cur*100/total))
  local metrics="$(get_metrics)"
  printf "\r[%3d%%] %s | %s" "$pct" "$_PROGRESS_DESC" "$metrics"
}

progress_end() {
  if (( _PROGRESS_ACTIVE == 0 )); then return 0; fi
  printf "\n"
  _PROGRESS_ACTIVE=0
}

handle_error() {
  local exitcode=$?
  local lastcmd="${BASH_COMMAND:-}"
  log_error "Trap ERR: '${lastcmd}' exited with $exitcode"
  if (( SAFE_RUN_STRICT )); then
    exit $exitcode
  fi
}

safe_run() {
  local desc="$1"; shift
  if (( DRY_RUN )); then
    log_info "DRY_RUN: $desc -> $*"
    return 0
  fi
  local logfile="${LOG_FILE:-/tmp/libcommon.tmp.log}"
  local start_ts=$(date +%s)
  log_info "RUN START: $desc"
  (
    exec "$@"
  ) >>"$logfile" 2>&1 &
  local pid=$!
  while kill -0 "$pid" >/dev/null 2>&1; do
    sleep 0.25
  done
  wait "$pid"
  local rc=$?
  local end_ts=$(date +%s)
  local elapsed=$((end_ts - start_ts))
  if (( rc != 0 )); then
    log_error "safe_run failed for: $desc"
    handle_error
  else
    log_info "RUN END: $desc elapsed=${elapsed}s"
  fi
  return $rc
}

libcommon_init() {
  if (( _LIBCOMMON_STARTED )); then return 0; fi
  _LIBCOMMON_STARTED=1
  _MODULE_NAME="${1:-libcommon}"
  MODULE_NAME="$_MODULE_NAME"
  _init_colors
  if [[ -w /var/log || -d /var/log ]]; then
    LOG_DIR="${LOG_DIR:-/var/log/lfsports}"
  else
    LOG_DIR="${LOG_DIR:-/tmp/lfsports}"
  fi
  mkdir -p "$LOG_DIR" >/dev/null 2>&1 || true
  LOG_FILE="${LOG_FILE:-$LOG_DIR/${MODULE_NAME}.log}"
  touch "$LOG_FILE" 2>/dev/null || true
  chmod 640 "$LOG_FILE" 2>/dev/null || true
  _TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/lfscommon.${MODULE_NAME}.XXXXXX")" || _TMPDIR="/tmp"
  _TMPDIRS+=("$_TMPDIR")
  trap 'handle_error' ERR
  trap 'cleanup_on_exit' EXIT
  log_info "lib_common initialized (version ${LIBCOMMON_VERSION})"
  rotate_logs
}

cleanup_on_exit() {
  local rc=$?
  rotate_logs
  _cleanup_tmpdirs
  _cleanup_locks
  log_info "lib_common exiting with code $rc"
  return $rc
}

export -f log_debug log_info log_warn log_error log_metrics safe_run with_lock mktempdir_safe progress_start progress_update progress_end get_metrics require_cmd rotate_logs

