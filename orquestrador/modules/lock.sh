#!/usr/bin/env bash
# lfsctl lock module
# Path: /usr/libexec/lfsctl/lock.sh (suggested)
# License: MIT
# Purpose: Robust lock manager for lfsctl
# Implements: lock init, acquire, try, release, cleanup, monitor, list, status, acquire_many
set -euo pipefail
# Allow debug via env
: "${LFSCTL_LOCK_DIR:=/var/lock/lfsctl}"
: "${LFSCTL_BUILD_USER:=lfsbuild}"
: "${LFSCTL_FALLBACK_LOCK_DIR:=/tmp/lfsctl-locks}"
: "${LOCK_RETRY_BASE:=0.1}"
: "${LOCK_RETRY_MAX:=2.0}"
: "${LOCK_ALERT_AGE:=1800}"    # 30 minutes default alert threshold in seconds
: "${LOCK_CLEANUP_AGE:=60}"    # 60 seconds before considering orphan for auto-cleanup
: "${LOCK_MONITOR_INTERVAL:=300}" # monitor loop interval (seconds)
: "${LOCK_MONITOR_PIDFILE:=${LFSCTL_LOCK_DIR}/monitor.pid}"

# helper: safe logger calls if logger.sh is sourced; fallback to echo/stderr
_log() {
  local level="$1"; shift
  if command -v log_info >/dev/null 2>&1 && command -v log_warn >/dev/null 2>&1 && command -v log_error >/dev/null 2>&1; then
    case "$level" in
      info) log_info "$@" ;;
      warn) log_warn "$@" ;;
      error) log_error "$@" ;;
      debug) log_debug "$@" ;;
      *) log_info "$@" ;;
    esac
  else
    case "$level" in
      error) >&2 printf 'ERROR: %s\n' "$*" ;;
      warn) >&2 printf 'WARN: %s\n' "$*" ;;
      *) printf '%s\n' "$*" ;;
    esac
  fi
}

# atomic write key=value pairs to file
_atomic_write() {
  local dest="$1"; shift
  local tmp
  tmp="$(mktemp "${dest}.tmp.XXXX")"
  umask 077
  for line in "$@"; do
    printf '%s\n' "$line" >>"$tmp"
  done
  mv -f "$tmp" "$dest"
}

# ensure lock dir exists or fallback
_lock_ensure_dir() {
  local d="${LFSCTL_LOCK_DIR}"
  if [[ -d "$d" && -w "$d" ]]; then
    return 0
  fi
  if ! mkdir -p "$d" 2>/dev/null; then
    mkdir -p "${LFSCTL_FALLBACK_LOCK_DIR}" 2>/dev/null || return 1
    LFSCTL_LOCK_DIR="${LFSCTL_FALLBACK_LOCK_DIR}"
    _log warn "Lock dir not writable; falling back to ${LFSCTL_FALLBACK_LOCK_DIR}"
  fi
  return 0
}

# read key=value from lock file into associative array (bash 4+)
_read_lock_file() {
  local f="$1"
  declare -n _out="$2"
  _out=()
  [[ -f "$f" ]] || return 1
  while IFS='=' read -r k v; do
    # strip quotes
    v="${v#\"}"; v="${v%\"}"
    _out["$k"]="$v"
  done <"$f"
  return 0
}

# check if pid exists
_pid_exists() {
  local pid="$1"
  if [[ -z "$pid" ]]; then return 1; fi
  if kill -0 "$pid" 2>/dev/null; then
    return 0
  fi
  return 1
}

# get current epoch
_now() { date +%s; }

# get process elapsed seconds via ps (best-effort)
_proc_elapsed() {
  local pid="$1"
  if [[ -z "$pid" ]]; then echo 0; return; fi
  if ps -p "$pid" -o etimes= 2>/dev/null | awk '{print $1+0}'; then
    return 0
  fi
  echo 0
}

# internal: create lock metadata array
_lock_meta_create() {
  local name="$1" pid="$2" user="$3" reason="$4" cwd="$5" cmd="$6" count="$7" now
  now="$(_now)"
  printf 'pid=%s\nuid=%s\nuser=%s\ntime=%s\ncmd="%s"\nreason="%s"\ncwd="%s"\nreentrant_count=%s\n' \
    "$pid" "$(id -u "$user" 2>/dev/null || echo 0)" "$user" "$now" "$cmd" "$reason" "$cwd" "${count:-1}"
}

# get lock file path
_lock_file_path() {
  local name="$1"
  printf "%s/%s.lock" "${LFSCTL_LOCK_DIR%/}" "$name"
}

# attempt to acquire lock using flock if available, else mkdir fallback
_lock_acquire_impl() {
  local name="$1"; shift
  local reason="${1:-}" timeout="${2:-}" now pid fd file meta retries=0 wait="$LOCK_RETRY_BASE" max_wait="$LOCK_RETRY_MAX"
  pid="$$"
  file="$(_lock_file_path "$name")"
  _lock_ensure_dir || { _log error "Lock dir unavailable"; return 3; }

  # reentrant: if lock exists and pid == $$, increment count
  if [[ -f "$file" ]]; then
    declare -A tmp; _read_lock_file "$file" tmp || true
    if [[ "${tmp[pid]:-}" == "$$" ]]; then
      # increment reentrant_count safely
      local c="${tmp[reentrant_count]:-1}"; c=$((c+1))
      _atomic_write "$file" "$(_lock_meta_create "$name" "$$" "${tmp[user]:-$LFSCTL_BUILD_USER}" "${tmp[reason]:-}" "${tmp[cwd]:-}" "${tmp[cmd]:-}" "$c")"
      _log debug "Reentrant lock incremented for $name (count=$c)"
      return 0
    fi
  fi

  # use flock if available
  if command -v flock >/dev/null 2>&1; then
    # create file and open fd
    touch "$file" 2>/dev/null || true
    exec {fd}>>"$file" || { _log error "Cannot open lock file $file"; return 3; }
    # try acquire with timeout/backoff
    local start; start="$(_now)"
    while :; do
      if flock -n "$fd"; then
        # write metadata
        _atomic_write "$file" "$(_lock_meta_create "$name" "$pid" "$LFSCTL_BUILD_USER" "$reason" "${PWD:-}" "${BASH_COMMAND:-}" 1)"
        # keep fd open in our process to hold flock (store fd in map)
        eval "export LOCK_FD_${name}=$fd" 2>/dev/null || true
        _log info "Lock acquired: $name (pid=$pid)"
        return 0
      fi
      # flock not acquired, check timeout
      if [[ -n "$timeout" ]]; then
        local elapsed=$((_now - start))
        if (( elapsed >= timeout )); then
          eval "exec ${fd}>&-" 2>/dev/null || true
          return 1
        fi
      fi
      # check existing lock whether it's orphan
      if [[ -f "$file" ]]; then
        declare -A tmp; _read_lock_file "$file" tmp || true
        local otherpid="${tmp[pid]:-}"; local locktime="${tmp[time]:-0}"
        if [[ -n "$otherpid" ]]; then
          if ! _pid_exists "$otherpid"; then
            # additional check: if process elapsed < (now-locktime) then PID reused -> treat as orphan
            local elapsed_proc; elapsed_proc="$(_proc_elapsed "$otherpid")"
            local since_lock=$((_now - locktime))
            if (( elapsed_proc == 0 || elapsed_proc > since_lock )); then
              _log warn "Removing stale lock $name (pid=$otherpid dead or reused)"
              # move file to stale for audit, then continue
              mkdir -p "${LFSCTL_LOCK_DIR%/}/stale" 2>/dev/null || true
              mv -f "$file" "${LFSCTL_LOCK_DIR%/}/stale/$(basename "$file").$otherpid" 2>/dev/null || true
              # close fd if opened
              eval "exec ${fd}>&-" 2>/dev/null || true || true
              # continue to attempt acquire
            fi
          fi
        fi
      fi
      # backoff
      sleep "$wait"
      wait=$(awk "BEGIN {print $wait*1.5}" 2>/dev/null || echo "$LOCK_RETRY_MAX")
      if (( $(awk "BEGIN {print ($wait>$max_wait)}") )); then wait="$max_wait"; fi
    done
  else
    # mkdir fallback: create directory atomically
    local dir="${file}.d"
    local start; start="$(_now)"
    while :; do
      if mkdir "$dir" 2>/dev/null; then
        # we own it; write metadata inside
        _atomic_write "${dir}/meta" "$(_lock_meta_create "$name" "$pid" "$LFSCTL_BUILD_USER" "$reason" "${PWD:-}" "${BASH_COMMAND:-}" 1)"
        _log info "Lock acquired (mkdir backend): $name (pid=$pid)"
        return 0
      fi
      # exists: check for orphan
      if [[ -d "$dir" ]]; then
        if [[ -f "${dir}/meta" ]]; then
          declare -A tmp; _read_lock_file "${dir}/meta" tmp || true
          local otherpid="${tmp[pid]:-}"; local locktime="${tmp[time]:-0}"
          if [[ -n "$otherpid" ]]; then
            if ! _pid_exists "$otherpid"; then
              _log warn "Removing stale lock dir $dir (pid=$otherpid dead)"
              mkdir -p "${LFSCTL_LOCK_DIR%/}/stale" 2>/dev/null || true
              mv -f "$dir" "${LFSCTL_LOCK_DIR%/}/stale/$(basename "$dir").$otherpid" 2>/dev/null || true
              continue
            fi
          fi
        fi
      fi
      if [[ -n "$timeout" ]]; then
        local elapsed=$((_now - start))
        if (( elapsed >= timeout )); then
          return 1
        fi
      fi
      sleep "$wait"
      wait=$(awk "BEGIN {print $wait*1.5}" 2>/dev/null || echo "$LOCK_RETRY_MAX")
      if (( $(awk "BEGIN {print ($wait>$LOCK_RETRY_MAX)}") )); then wait="$LOCK_RETRY_MAX"; fi
    done
  fi
}

# Public: acquire with optional timeout (seconds)
# Usage: lock_acquire name [--timeout N] [--reason TEXT]
lock_acquire() {
  local name timeout reason
  name="$1"; shift || { _log error "lock_acquire requires a name"; return 4; }
  while [[ $# -gt 0 ]]; do case "$1" in --timeout) timeout="$2"; shift 2;; --reason) reason="$2"; shift 2;; *) shift;; esac; done
  _lock_acquire_impl "$name" "$reason" "$timeout"
}

# try acquire non-blocking
lock_try() {
  local name="$1"
  _lock_acquire_impl "$name" "" 0 && return 0 || return 1
}

# release lock - only owner or root may release; handles reentrant count
lock_release() {
  local name="$1"
  [[ -n "$name" ]] || { _log error "lock_release requires name"; return 4; }
  local file="$(_lock_file_path "$name")"
  # flock backend: check for FD env var
  local fdvar="LOCK_FD_${name}"
  if [[ -n "${!fdvar:-}" ]]; then
    local fd="${!fdvar}"
    # read meta to check pid
    declare -A meta; _read_lock_file "$file" meta || true
    if [[ "${meta[pid]:-}" != "$$" && "$(id -u)" -ne 0 ]]; then
      _log error "Cannot release lock $name owned by pid=${meta[pid]:-}"
      return 2
    fi
    # reentrant handling
    local cnt="${meta[reentrant_count]:-1}"; cnt=$((cnt-1))
    if (( cnt > 0 )); then
      _atomic_write "$file" "$(_lock_meta_create "$name" "$$" "${meta[user]:-$LFSCTL_BUILD_USER}" "${meta[reason]:-}" "${meta[cwd]:-}" "${meta[cmd]:-}" "$cnt")"
      _log debug "Decremented reentrant count for $name => $cnt"
      return 0
    fi
    # final release: unlock and remove
    if command -v flock >/dev/null 2>&1; then
      flock -u "$fd" || true
      eval "exec ${fd}>&-" 2>/dev/null || true
    fi
    rm -f "$file" 2>/dev/null || true
    _log info "Lock released: $name"
    unset "LOCK_FD_${name}" 2>/dev/null || true
    return 0
  fi
  # mkdir backend
  local dir="${file}.d"
  if [[ -d "$dir" ]]; then
    if [[ -f "${dir}/meta" ]]; then
      declare -A meta; _read_lock_file "${dir}/meta" meta || true
      if [[ "${meta[pid]:-}" != "$$" && "$(id -u)" -ne 0 ]]; then
        _log error "Cannot release lock $name owned by pid=${meta[pid]:-}"
        return 2
      fi
      local cnt="${meta[reentrant_count]:-1}"; cnt=$((cnt-1))
      if (( cnt > 0 )); then
        _atomic_write "${dir}/meta" "$(_lock_meta_create "$name" "$$" "${meta[user]:-$LFSCTL_BUILD_USER}" "${meta[reason]:-}" "${meta[cwd]:-}" "${meta[cmd]:-}" "$cnt")"
        _log debug "Decremented reentrant count for $name => $cnt (dir backend)"
        return 0
      fi
    fi
    rm -rf "$dir" 2>/dev/null || true
    _log info "Lock released (dir backend): $name"
    return 0
  fi
  _log warn "No lock present for $name"
  return 1
}

# check if lock held
lock_held() {
  local name="$1"
  local file="$(_lock_file_path "$name")"
  if [[ -f "$file" || -d "${file}.d" ]]; then return 0; fi
  return 1
}

# list locks with info
lock_list() {
  _lock_ensure_dir || return 1
  local json="${1:-}"
  local out=()
  for f in "${LFSCTL_LOCK_DIR}"/*.lock "${LFSCTL_LOCK_DIR}"/*.lock.d 2>/dev/null; do
    [[ -e "$f" ]] || continue
    if [[ -f "$f" && "$f" == *.lock ]]; then
      declare -A meta; _read_lock_file "$f" meta || true
      out+=("$(basename "$f") pid=${meta[pid]:-} user=${meta[user]:-} age=$(( $(_now) - ${meta[time]:-0} ))")
    elif [[ -d "$f" ]]; then
      [[ -f "${f}/meta" ]] || continue
      declare -A meta; _read_lock_file "${f}/meta" meta || true
      out+=("$(basename "$f") pid=${meta[pid]:-} user=${meta[user]:-} age=$(( $(_now) - ${meta[time]:-0} ))")
    fi
  done
  if [[ "$json" == "--json" ]]; then
    printf '['
    local first=1
    for e in "${out[@]}"; do
      if (( first )); then first=0; else printf ','; fi
      local name=$(printf '%s' "$e" | awk '{print $1}')
      local pid=$(printf '%s' "$e" | awk '{print $2}' | cut -d'=' -f2)
      local user=$(printf '%s' "$e" | awk '{print $3}' | cut -d'=' -f2)
      local age=$(printf '%s' "$e" | awk '{print $4}' | cut -d'=' -f2)
      printf '{"name":"%s","pid":%s,"user":"%s","age":%s}' "$name" "$pid" "$user" "$age"
    done
    printf ']\n'
  else
    for e in "${out[@]}"; do printf '%s\n' "$e"; done
  fi
}

# cleanup stale locks (age in seconds) - default uses LOCK_CLEANUP_AGE
lock_cleanup() {
  local age="${1:-$LOCK_CLEANUP_AGE}"
  _lock_ensure_dir || return 1
  local now="$(_now)"; local removed=0
  mkdir -p "${LFSCTL_LOCK_DIR%/}/stale" 2>/dev/null || true
  for f in "${LFSCTL_LOCK_DIR}"/*.lock "${LFSCTL_LOCK_DIR}"/*.lock.d 2>/dev/null; do
    [[ -e "$f" ]] || continue
    local mtime=0
    if [[ -f "$f" ]]; then
      declare -A meta; _read_lock_file "$f" meta || true
      mtime="${meta[time]:-0}"
      local pid="${meta[pid]:-}"
      # if pid doesn't exist or appears reused/older than age, remove
      if [[ -n "$pid" ]]; then
        if ! _pid_exists "$pid"; then
          local since=$((now - mtime))
          if (( since >= age )); then
            mv -f "$f" "${LFSCTL_LOCK_DIR%/}/stale/$(basename "$f").${pid}" 2>/dev/null || rm -f "$f" 2>/dev/null || true
            _log info "Removed stale lock file $(basename "$f") pid=${pid} age=${since}s"
            removed=$((removed+1))
          fi
        else
          # check for PID reuse: if process elapsed < (now - mtime) treat as reused -> stale
          local pelapsed="$(_proc_elapsed "$pid")"
          local since_lock=$((now - mtime))
          if (( pelapsed > 0 && pelapsed < since_lock )); then
            mv -f "$f" "${LFSCTL_LOCK_DIR%/}/stale/$(basename "$f").${pid}" 2>/dev/null || rm -f "$f" 2>/dev/null || true
            _log warn "Removed lock for possibly reused pid ${pid} (file $(basename "$f"))"
            removed=$((removed+1))
          fi
        fi
      else
        # no pid metadata: older file - move to stale if older than age
        local fage=$(( now - $(stat -c %Y "$f") ))
        if (( fage >= age )); then
          mv -f "$f" "${LFSCTL_LOCK_DIR%/}/stale/$(basename "$f")" 2>/dev/null || rm -f "$f" 2>/dev/null || true
          _log info "Removed anonymous stale lock $(basename "$f") age=${fage}s"
          removed=$((removed+1))
        fi
      fi
    elif [[ -d "$f" ]]; then
      # dir backend
      if [[ -f "${f}/meta" ]]; then
        declare -A meta; _read_lock_file "${f}/meta" meta || true
        local pid="${meta[pid]:-}"; mtime="${meta[time]:-0}"
        if [[ -n "$pid" ]]; then
          if ! _pid_exists "$pid"; then
            local since=$((now - mtime))
            if (( since >= age )); then
              mv -f "$f" "${LFSCTL_LOCK_DIR%/}/stale/$(basename "$f").${pid}" 2>/dev/null || rm -rf "$f" 2>/dev/null || true
              _log info "Removed stale lock dir $(basename "$f") pid=${pid} age=${since}s"
              removed=$((removed+1))
            fi
          fi
        fi
      fi
    fi
  done
  _log info "lock_cleanup completed, removed=${removed}"
  return 0
}

# lock_wait: wait until lock free or timeout
lock_wait() {
  local name="$1" timeout="${2:-}"
  local start="$(_now)" now
  while :; do
    if ! lock_held "$name"; then return 0; fi
    now="$(_now)"
    if [[ -n "$timeout" && $((now-start)) -ge "$timeout" ]]; then
      return 1
    fi
    sleep 1
  done
}

# acquire many with canonical order to avoid deadlocks
lock_acquire_many() {
  local names=("$@"); [[ ${#names[@]} -gt 0 ]] || return 4
  # sort names to canonical order
  IFS=$'\n' sorted=($(printf '%s\n' "${names[@]}" | sort)); unset IFS
  local acquired=()
  for n in "${sorted[@]}"; do
    if ! lock_acquire "$n" --timeout 10; then
      _log error "Failed to acquire $n; releasing acquired locks"
      for a in "${acquired[@]}"; do lock_release "$a"; done
      return 1
    fi
    acquired+=("$n")
  done
  return 0
}

# status of a lock
lock_status() {
  local name="$1"; [[ -n "$name" ]] || { _log error "lock_status requires name"; return 4; }
  local file="$(_lock_file_path "$name")"
  if [[ -f "$file" ]]; then
    declare -A meta; _read_lock_file "$file" meta || true
    printf 'name=%s\npid=%s\nuser=%s\nage=%s\ncmd=%s\nreason=%s\nreentrant_count=%s\n' "$name" "${meta[pid]:-}" "${meta[user]:-}" "$(( $(_now) - ${meta[time]:-0} ))" "${meta[cmd]:-}" "${meta[reason]:-}" "${meta[reentrant_count]:-1}"
    return 0
  elif [[ -d "${file}.d" ]]; then
    declare -A meta; _read_lock_file "${file}.d/meta" meta || true
    printf 'name=%s\npid=%s\nuser=%s\nage=%s\ndir=true\ncmd=%s\nreason=%s\nreentrant_count=%s\n' "$name" "${meta[pid]:-}" "${meta[user]:-}" "$(( $(_now) - ${meta[time]:-0} ))" "${meta[cmd]:-}" "${meta[reason]:-}" "${meta[reentrant_count]:-1}"
    return 0
  fi
  _log info "No lock for $name"
  return 1
}

# Monitor: runs cleanup and alerts for locks older than LOCK_ALERT_AGE
_lock_monitor_loop() {
  local interval="${1:-$LOCK_MONITOR_INTERVAL}"
  while :; do
    lock_cleanup "$LOCK_CLEANUP_AGE" || _log warn "lock_cleanup failed in monitor"
    # alert for long locks
    for f in "${LFSCTL_LOCK_DIR}"/*.lock "${LFSCTL_LOCK_DIR}"/*.lock.d 2>/dev/null; do
      [[ -e "$f" ]] || continue
      local t=0 name pid
      if [[ -f "$f" ]]; then
        declare -A meta; _read_lock_file "$f" meta || true
        name="$(basename "$f")"; pid="${meta[pid]:-}"; t="${meta[time]:-0}"
      else
        declare -A meta; _read_lock_file "${f}/meta" meta || true
        name="$(basename "$f")"; pid="${meta[pid]:-}"; t="${meta[time]:-0}"
      fi
      local age=$((_now - t))
      if (( age >= LOCK_ALERT_AGE )); then
        _log warn "Lock ${name} held by pid=${pid} for ${age}s (>=${LOCK_ALERT_AGE}); please investigate"
      fi
    done
    sleep "$interval"
  done
}

# start monitor (foreground) or daemonize with --daemonize
lock_monitor_start() {
  local daemonize=0 interval=
  while [[ $# -gt 0 ]]; do case "$1" in --daemonize) daemonize=1; shift;; --interval) interval="$2"; shift 2;; *) shift;; esac; done
  if [[ $daemonize -eq 1 ]]; then
    nohup "$0" monitor --interval "${interval:-$LOCK_MONITOR_INTERVAL}" >/dev/null 2>&1 &
    echo $! > "$LOCK_MONITOR_PIDFILE" 2>/dev/null || true
    _log info "Lock monitor started (daemon) pid=$(cat "$LOCK_MONITOR_PIDFILE" 2>/dev/null || echo 'unknown')"
    return 0
  else
    _log info "Lock monitor running (foreground)"
    _lock_monitor_loop "${interval:-$LOCK_MONITOR_INTERVAL}"
  fi
}

lock_monitor_stop() {
  if [[ -f "$LOCK_MONITOR_PIDFILE" ]]; then
    local pid; pid="$(cat "$LOCK_MONITOR_PIDFILE")"
    if _pid_exists "$pid"; then
      kill "$pid" 2>/dev/null || true
      _log info "Sent TERM to monitor pid=$pid"
    fi
    rm -f "$LOCK_MONITOR_PIDFILE" 2>/dev/null || true
  else
    _log warn "No monitor pidfile found"
  fi
}

# CLI dispatcher if executed directly
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  cmd="${1:-}"; shift || true
  case "$cmd" in
    init) _lock_ensure_dir && mkdir -p "${LFSCTL_LOCK_DIR}/stale" && _log info "lock_init done";;
    acquire) lock_acquire "$@" ;;
    try) lock_try "$@" ;;
    release) lock_release "$@" ;;
    held) lock_held "$@" ;;
    wait) lock_wait "$@" ;;
    list) lock_list "$@" ;;
    cleanup) lock_cleanup "$@" ;;
    status) lock_status "$@" ;;
    acquire-many) lock_acquire_many "$@" ;;
    monitor) lock_monitor_start "$@" ;;
    monitor-stop) lock_monitor_stop "$@" ;;
    *) printf 'Usage: %s {init|acquire|try|release|held|wait|list|cleanup|status|acquire-many|monitor|monitor-stop}\n' "$0"; exit 4 ;;
  esac
fi
