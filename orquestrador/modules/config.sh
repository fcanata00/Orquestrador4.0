#!/usr/bin/env bash
# lfsctl config module
# Path: /usr/libexec/lfsctl/config.sh
# License: MIT
# Purpose: Central configuration manager for lfsctl
# Implements: secure config parsing, defaults, environment export,
#            sanity checks, atomic directory creation, build-user management,
#            traps and robust error handling.

set -euo pipefail
# We purposely avoid global `set -x` here; caller can enable debug via LFSCTL_DEBUG=1

# -----------------------------
# Defaults
# -----------------------------
LFSCTL_DEFAULTS=$(cat <<'EOF'
# default values (do not edit in runtime)
LFSCTL_PREFIX=/usr
LFSCTL_ROOT=/
LFSCTL_BUILD_DIR=/var/lfsctl/build
LFSCTL_CACHE_DIR=/var/lfsctl/cache
LFSCTL_PKG_DIR=/var/lfsctl/packages
LFSCTL_META_DIR=/var/lfsctl/meta
LFSCTL_LOG_DIR=/var/lfsctl/logs
LFSCTL_PORTS_DIR=/usr/ports
LFSCTL_LOCK_DIR=/var/lock/lfsctl
LFSCTL_JOBS=0
LFSCTL_COLOR=auto
LFSCTL_FAKER00T=true
LFSCTL_CHROOT=false
LFSCTL_STRIP=true
LFSCTL_LOG_LEVEL=info
LFSCTL_SYNC_REPO=""
LFSCTL_BUILD_USER=lfsbuild
LFSCTL_BUILD_GROUP=lfsbuild
LFSCTL_BUILD_HOME=/var/lib/lfsbuild
LFSCTL_ALLOW_SUDO=false
EOF
)

# In-memory associative store for config (bash arrays)
declare -A _LFSCTL_CFG

# bootstrap log until full logger loaded
_bootstrap_log() {
  local ts level msg file
  ts=$(date --rfc-3339=seconds 2>/dev/null || date +"%Y-%m-%dT%H:%M:%S%z")
  level="$1"; shift
  msg="$*"
  file="${_LFSCTL_CFG[LFSCTL_LOG_DIR]:-/var/lfsctl/logs}/bootstrap.log"
  mkdir -p "$(dirname "$file")" 2>/dev/null || true
  printf "%s %s: %s\n" "$ts" "${level^^}" "$msg" >>"$file"
}

# safe echo helpers
_config_warn() { _bootstrap_log WARN "$*"; }
_config_info() { _bootstrap_log INFO "$*"; }
_config_error() { _bootstrap_log ERROR "$*"; }

# -----------------------------
# Utility functions
# -----------------------------
_config_atomic_write() {
  local dest content tmp
  dest="$1"; shift
  tmp="$dest.$$.$(date +%s)"
  umask 077
  printf "%s\n" "$*" >"$tmp" || return 1
  mv -f "$tmp" "$dest"
}

# sanitize key: only A-Z0-9_ and start with letter
_config_valid_key() {
  [[ "$1" =~ ^[A-Z][A-Z0-9_]*$ ]]
}

# sanitize value: disallow suspicious chars used for injection
_config_valid_value() {
  # allow most chars but reject backticks, $(), ;, &&, |, >, <
  case "$1" in
    *\`*|*\$(*|*;*|*\&\&*|*\|*|*\>*|*\<* ) return 1;;
  esac
  return 0
}

# expand ~ and env vars safely for paths
_config_expand_path() {
  local p="$1"
  if [[ "$p" == ~* ]]; then
    p="${p/#~/$HOME}"
  fi
  # Only expand $HOME and ${HOME} for safety
  p="${p//\$HOME/$HOME}"
  printf '%s' "$p"
}

# normalize path to absolute if possible
_config_abspath() {
  local p; p="$1"
  case "$p" in
    /*) printf '%s' "$p" ;;
    *) printf '%s' "$(pwd)/$p" ;;
  esac
}

# -----------------------------
# Config parser
# -----------------------------
config_load_file() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    # trim
    line="${line%%#*}"
    line="${line%%$'\r'}"
    line="$(echo -n "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$line" ]] && continue
    # expect KEY=VALUE
    if [[ "$line" =~ ^([A-Z][A-Z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      local key="${BASH_REMATCH[1]}"
      local val="${BASH_REMATCH[2]}"
      # remove optional surrounding quotes
      if [[ "$val" =~ ^"(.*)"$ ]]; then val="${BASH_REMATCH[1]}"; fi
      if [[ "$val" =~ ^'(.*)'$ ]]; then val="${BASH_REMATCH[1]}"; fi

      if ! _config_valid_key "$key"; then
        _config_warn "Ignoring invalid key in $file: $key"
        continue
      fi
      if ! _config_valid_value "$val"; then
        _config_warn "Ignoring suspicious value for $key in $file"
        continue
      fi
      _LFSCTL_CFG["$key"]="$val"
    else
      _config_warn "Ignoring malformed line in $file: $line"
    fi
  done <"$file"
}

# -----------------------------
# Set defaults and load hierarchy
# -----------------------------
_config_load_defaults() {
  while IFS= read -r l; do
    [[ "$l" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || continue
    _LFSCTL_CFG["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
  done <<<"$LFSCTL_DEFAULTS"
}

# -----------------------------
# Tools checks
# -----------------------------
config_assert_tool() {
  local tool="$1" friendly
  friendly="$tool"
  if ! command -v "$tool" >/dev/null 2>&1; then
    _config_error "Required tool not found: $tool"
    return 2
  fi
  return 0
}

config_sanity_check() {
  local tools=(tar zstd git curl patch make cc sha256sum)
  local miss=0
  for t in "${tools[@]}"; do
    if ! command -v "$t" >/dev/null 2>&1; then
      _config_warn "Tool missing: $t"
      miss=$((miss+1))
    fi
  done
  if [[ $miss -gt 0 ]]; then
    _config_warn "Some recommended tools are missing. Use --self-test for details."
  fi

  # check disk space on build dir (>=100MB)
  local builddir="${_LFSCTL_CFG[LFSCTL_BUILD_DIR]:-/var/lfsctl/build}"
  mkdir -p "$builddir" 2>/dev/null || true
  local avail
  avail=$(df -P "$builddir" 2>/dev/null | awk 'NR==2{print $4}') || avail=0
  if [[ -n "$avail" && "$avail" -lt 102400 ]]; then
    _config_warn "Low disk space on $builddir: ${avail}KB available"
  fi
}

# -----------------------------
# Export environment
# -----------------------------
config_env_export() {
  for k in "${!_LFSCTL_CFG[@]}"; do
    case "$k" in
      LFSCTL_*) export "$k"="${_LFSCTL_CFG[$k]}" ;;
      *) : ;;
    esac
  done
}

# -----------------------------
# Create atomic dir with perms and owner
# -----------------------------
_config_ensure_dir_atomic() {
  local dir="$1" owner="$2" group="$3" mode="$4"
  if [[ -d "$dir" ]]; then
    chown "$owner":"$group" "$dir" || true
    chmod "$mode" "$dir" || true
    return 0
  fi
  local parent tmpdir
  parent=$(dirname "$dir")
  mkdir -p "$parent" 2>/dev/null || true
  tmpdir="${dir}.$$.$RANDOM"
  mkdir -p "$tmpdir"
  chown "$owner":"$group" "$tmpdir" 2>/dev/null || true
  chmod "$mode" "$tmpdir" 2>/dev/null || true
  mv "$tmpdir" "$dir"
}

config_ensure_dirs_with_perms() {
  local user="${_LFSCTL_CFG[LFSCTL_BUILD_USER]:-lfsbuild}"
  local group="${_LFSCTL_CFG[LFSCTL_BUILD_GROUP]:-lfsbuild}"
  local dirs=(LFSCTL_BUILD_DIR LFSCTL_CACHE_DIR LFSCTL_PKG_DIR LFSCTL_META_DIR LFSCTL_LOG_DIR LFSCTL_LOCK_DIR)
  for key in "${dirs[@]}"; do
    local d="${_LFSCTL_CFG[$key]}"
    [[ -n "$d" ]] || continue
    d=$(_config_expand_path "$d")
    # create parent directories and set ownership
    _config_ensure_dir_atomic "$d" "$user" "$group" 2770 || _config_warn "Could not ensure dir $d"
  done
}

# -----------------------------
# Build-user management
# -----------------------------
config_create_build_user() {
  local user="${_LFSCTL_CFG[LFSCTL_BUILD_USER]:-lfsbuild}"
  local group="${_LFSCTL_CFG[LFSCTL_BUILD_GROUP]:-lfsbuild}"
  local uid="${_LFSCTL_CFG[LFSCTL_BUILD_UID]:-}" gid="${_LFSCTL_CFG[LFSCTL_BUILD_GID]:-}"
  local home="${_LFSCTL_CFG[LFSCTL_BUILD_HOME]:-/var/lib/$user}"

  if id -u "$user" >/dev/null 2>&1; then
    _config_info "Build user exists: $user"
    return 0
  fi

  # detect available useradd command
  if command -v useradd >/dev/null 2>&1; then
    local cmd=(useradd -r -M -d "$home" -s /usr/sbin/nologin -g "$group" "$user")
    # create group if needed
    if ! getent group "$group" >/dev/null 2>&1; then
      if command -v groupadd >/dev/null 2>&1; then
        groupadd -r "$group" || _config_warn "groupadd failed for $group"
      fi
    fi
    if [[ -n "$uid" ]]; then cmd+=( -u "$uid" ); fi
    if [[ -n "$gid" ]]; then cmd+=( -g "$gid" ); fi
    set +e
    "${cmd[@]}" >/dev/null 2>&1
    local rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      _config_error "Failed to create user $user (useradd returned $rc)"
      return 4
    fi
    _config_info "Created build user $user"
  elif command -v adduser >/dev/null 2>&1; then
    # busybox/adduser style
    set +e
    adduser -D -H -h "$home" -s /usr/sbin/nologin "$user" >/dev/null 2>&1 || true
    set -e
    _config_info "Created build user $user with adduser"
  else
    _config_error "No useradd/adduser available to create build user. Run as root to create manually."
    return 4
  fi

  # ensure dirs owned by this user
  config_ensure_dirs_with_perms

  # register in meta
  mkdir -p "${_LFSCTL_CFG[LFSCTL_META_DIR]:-/var/lfsctl/meta}"
  local meta_file="${_LFSCTL_CFG[LFSCTL_META_DIR]}/users.json"
  local now
  now=$(date -Is 2>/dev/null || date +%s)
  if [[ -f "$meta_file" ]]; then
    jq --arg u "$user" --arg uid "$(id -u $user)" --arg gid "$(id -g $user)" --arg now "$now" '.[$u]={uid:$uid|tonumber,gid:$gid|tonumber,modified:$now} + .' "$meta_file" >"${meta_file}.tmp" 2>/dev/null || true
    mv -f "${meta_file}.tmp" "$meta_file" 2>/dev/null || true
  else
    printf '{"%s":{"uid":%s,"gid":%s,"created":"%s"}}\n' "$user" "$(id -u $user)" "$(id -g $user)" "$now" >"$meta_file" 2>/dev/null || true
  fi
}

# -----------------------------
# Traps and error handling
# -----------------------------
config_on_error() {
  local rc=$? lineno=$1 func="$2"
  local cmd
  cmd=${BASH_COMMAND:-}
  _config_error "Runtime error (rc=$rc) in ${func} at line ${lineno}: ${cmd}"
  # attempt to cleanup partial locks
  if [[ -n "${_LFSCTL_CFG[LFSCTL_LOCK_DIR]:-}" && -d "${_LFSCTL_CFG[LFSCTL_LOCK_DIR]}" ]]; then
    # don't remove locks blindly; just warn
    _config_warn "Locks may be present in ${_LFSCTL_CFG[LFSCTL_LOCK_DIR]} - please verify"
  fi
  exit $rc
}

config_trap_errors() {
  trap 'config_on_error $? ${FUNCNAME:-MAIN} ${LINENO}' ERR
  trap 'config_on_exit' EXIT
}

config_on_exit() {
  # placeholder for future cleanup
  return 0
}

# -----------------------------
# Public API
# -----------------------------
config_init() {
  # populate defaults
  _config_load_defaults

  # load system config
  if [[ -f /etc/lfsctl.conf ]]; then
    config_load_file /etc/lfsctl.conf
  fi
  # load user config
  if [[ -f "$HOME/.config/lfsctl.conf" ]]; then
    config_load_file "$HOME/.config/lfsctl.conf"
  fi
  # load env-provided file
  if [[ -n "${LFSCTL_CONFIG:-}" && -f "$LFSCTL_CONFIG" ]]; then
    config_load_file "$LFSCTL_CONFIG"
  fi

  # resolve LFSCTL_JOBS default to nproc if 0
  if [[ -n "${_LFSCTL_CFG[LFSCTL_JOBS]:-0}" && "${_LFSCTL_CFG[LFSCTL_JOBS]}" -le 0 ]]; then
    if command -v nproc >/dev/null 2>&1; then
      _LFSCTL_CFG[LFSCTL_JOBS]=$(nproc)
    else
      _LFSCTL_CFG[LFSCTL_JOBS]=1
    fi
  fi

  # normalize paths
  for k in LFSCTL_BUILD_DIR LFSCTL_CACHE_DIR LFSCTL_PKG_DIR LFSCTL_META_DIR LFSCTL_LOG_DIR LFSCTL_PORTS_DIR LFSCTL_LOCK_DIR LFSCTL_BUILD_HOME; do
    if [[ -n "${_LFSCTL_CFG[$k]:-}" ]]; then
      _LFSCTL_CFG[$k]=$(_config_abspath "$(_config_expand_path "${_LFSCTL_CFG[$k]}")")
    fi
  done

  # ensure dirs and permissions
  config_trap_errors
  config_sanity_check
  config_create_build_user || true
  config_ensure_dirs_with_perms

  config_env_export
  _config_info "config_init complete"
}

config_show() {
  for k in "${!_LFSCTL_CFG[@]}"; do
    printf "%s=%s\n" "$k" "${_LFSCTL_CFG[$k]}"
  done | sort
}

config_get() {
  local k="$1"
  printf '%s' "${_LFSCTL_CFG[$k]:-}"
}

config_set() {
  local k="$1" v="$2"
  if ! _config_valid_key "$k"; then
    _config_error "Invalid key: $k"
    return 1
  fi
  if ! _config_valid_value "$v"; then
    _config_error "Invalid/suspicious value for $k"
    return 1
  fi
  _LFSCTL_CFG[$k]="$v"
  export "$k"="$v"
}

config_self_test() {
  echo "Running lfsctl config self-test..."
  local ok=0 warn=0 fail=0
  # test parsing sample
  local tmpf; tmpf=$(mktemp)
  cat >"$tmpf" <<'EOF'
# sample
LFSCTL_BUILD_DIR=/tmp/lfsbuild
LFSCTL_JOBS=2
BADLINE=mal formed
EVIL=`echo hi`
EOF
  config_load_file "$tmpf"
  if [[ "${_LFSCTL_CFG[LFSCTL_BUILD_DIR]:-}" == "/tmp/lfsbuild" ]]; then ok=$((ok+1)); else fail=$((fail+1)); fi
  rm -f "$tmpf"
  # test tool check
  if command -v tar >/dev/null 2>&1; then ok=$((ok+1)); else warn=$((warn+1)); fi
  # test dir creation (dry)
  local testdir="$(pwd)/.lfsctl_testdir"
  _config_ensure_dir_atomic "$testdir" root root 0700 || fail=$((fail+1))
  rm -rf "$testdir" || true
  echo "self-test: OK=$ok WARN=$warn FAIL=$fail"
  return $fail
}

# -----------------------------
# Provide a small wrapper when sourced or executed
# -----------------------------
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  # invoked directly: run init and show config
  config_init
  echo "Configuration loaded. Use config_show to list variables."
fi

