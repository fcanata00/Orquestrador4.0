#!/usr/bin/env bash
# ports-locks.sh — biblioteca de locks para o sistema Ports (LFS/BLFS)
# - Exclusão mútua com flock (exclusivo e compartilhado)
# - Reentrante por processo (refcount)
# - Hierarquia e verificação de ordem para evitar deadlocks
# - Timeout, tentativa não-bloqueante, avisos periódicos de espera
# - Limpeza de locks órfãos, traps para liberar tudo ao sair
# - Sidecar .pid para diagnóstico (exclusivo) e .pid.$PID para compartilhado
# - Integra com ports-logs.sh se carregado (fallback para echo)

# Requisitos: bash >= 4.2, coreutils (date, install, mkdir, rm, find), flock, awk, sed

set -uo pipefail

# =========================
# Configuração (defaults)
# =========================
: "${PORTS_ETC_CONF:=/etc/ports.conf}"
: "${PORTS_USER_CONF:=~/.config/ports/config}"
PORTS_USER_CONF="$(eval echo "$PORTS_USER_CONF")"

# Defaults (podem ser sobrescritos via conf)
: "${LOCK_DIR:=/run/ports/locks}"
: "${LOCK_DEFAULT_TIMEOUT:=0}"           # 0 = infinito
: "${LOCK_STRICT_ORDER:=false}"          # true => erro ao violar ordem
: "${LOCK_VERBOSE:=true}"                # mensagens de status
: "${LOCK_WAIT_NOTICE_INTERVAL:=10}"     # segundos entre avisos de espera
: "${LOCK_ORPHAN_MAX_AGE:=86400}"        # 24h
: "${LOCK_FALLBACK_DIR1:=/var/lock/ports}"
: "${LOCK_FALLBACK_DIR2:=~/.cache/ports/locks}"
LOCK_FALLBACK_DIR2="$(eval echo "$LOCK_FALLBACK_DIR2")"

# =========================
# Carregar configurações
# =========================
_ports_locks_source_if() {
  local f="$1"
  # shellcheck disable=SC1090
  [[ -f "$f" ]] && source "$f"
}
_ports_locks_source_if "$PORTS_ETC_CONF"
_ports_locks_source_if "$PORTS_USER_CONF"

# =========================
# Integração com logs (opcional)
# =========================
_log_have=0
if declare -F log::step >/dev/null 2>&1 && declare -F log::ok >/dev/null 2>&1; then
  _log_have=1
fi
_log_step() { if (( _log_have )); then log::step "$@"; elif [[ "${LOCK_VERBOSE}" == "true" ]]; then echo "[STEP] $*"; fi; }
_log_ok()   { if (( _log_have )); then log::ok   "$@"; elif [[ "${LOCK_VERBOSE}" == "true" ]]; then echo "[OK ] $*";  fi; }
_log_info() { if (( _log_have )); then log::info "$@"; elif [[ "${LOCK_VERBOSE}" == "true" ]]; then echo "[INFO] $*"; fi; }
_log_warn() { if (( _log_have )); then log::warn "$@"; elif [[ "${LOCK_VERBOSE}" == "true" ]]; then echo "[WARN] $*"; fi; }
_log_err()  { if (( _log_have )); then log::err  "$@"; else echo "[ERR ] $*" >&2; fi; }

# =========================
# Sanitização e utilitários
# =========================
lock::sanitize_name() {
  sed -E 's/[^a-zA-Z0-9._/-]+/_/g' <<<"$1" | sed -E 's#/+#/#g;s#^/+##;s#/+$##;'
}

__ensure_dir() { install -d -m 0775 "$1" 2>/dev/null || mkdir -p "$1"; }

__path_for_name() {
  local name sanitized
  name="$(lock::sanitize_name "$1")"
  echo "${LOCK_DIR}/${name}.lock"
}

__pid_sidecar() {
  local path="$1" mode="$2"
  if [[ "$mode" == "shared" ]]; then
    echo "${path}.pid.$$"
  else
    echo "${path}.pid"
  fi
}

__name_class_ord() {
  # Retorna uma ordem numérica para verificação hierárquica
  # global(1) -> repo(2) -> cache(3) -> pkg(4) -> pkgver(5) -> custom(6)
  local name="$1"
  case "$name" in
    global) echo 1 ;;
    repo)   echo 2 ;;
    cache)  echo 3 ;;
    pkg/*/*) echo 5 ;;
    pkg/*)   echo 4 ;;
    *)      echo 6 ;;
  esac
}

__seconds_now() { date +%s; }

# =========================
# Estado (por processo)
# =========================
# Arrays associativos de FDs, refcounts, modos, caminhos, tempos
declare -Ag LOCK_FD=() LOCK_REF=() LOCK_MODE=() LOCK_PATH=() LOCK_ACQ_TIME=()
declare -ag LOCK_HELD_ORDER=()    # sequência de nomes na ordem adquirida
declare -Ag LOCK_HELD_INDEX=()    # map nome -> índice em LOCK_HELD_ORDER

# Stacktrace por lock (para diagnóstico)
declare -Ag LOCK_STACK_FILE=() LOCK_STACK_LINE=()

# =========================
# Verificações e init
# =========================
lock::__try_prepare_dir() {
  local dir="$1"
  __ensure_dir "$dir"
  # tenta criar arquivo temporário para validar acesso
  local t="$dir/.ports-locks-touch-$$"
  if ! ( : > "$t" 2>/dev/null ); then
    return 1
  fi
  rm -f -- "$t" 2>/dev/null || true
  return 0
}

lock::__select_lock_dir() {
  local tried=()
  for d in "$LOCK_DIR" "$LOCK_FALLBACK_DIR1" "$LOCK_FALLBACK_DIR2"; do
    [[ -z "$d" ]] && continue
    if lock::__try_prepare_dir "$d"; then
      if [[ "$d" != "$LOCK_DIR" ]]; then
        _log_warn "LOCK_DIR indisponível; usando fallback: $d"
        LOCK_DIR="$d"
      fi
      return 0
    else
      tried+=("$d")
    fi
  done
  _log_err "Não foi possível preparar diretório de locks. Tentativas: ${tried[*]}"
  return 6
}

# Limpeza de órfãos (leve)
lock::__cleanup_orphans() {
  # Evita corrida: usa um lock de limpeza rápido
  local clean_lock="${LOCK_DIR}/.clean.lock"
  __ensure_dir "$LOCK_DIR" || return 0
  exec {clfd}>"$clean_lock" 2>/dev/null || return 0
  if flock -n "$clfd"; then
    local now; now=$(__seconds_now)
    local removed=0 bytes=0
    while IFS= read -r -d '' f; do
      local base pid
      base="$(basename "$f")"
      pid="${base##*.pid.}"
      if [[ "$base" == *.pid ]]; then
        # exclusivo: unica .pid
        if ! [[ -s "$f" ]]; then
          rm -f -- "$f" && ((removed++))
          continue
        fi
        pid="$(cat "$f" 2>/dev/null || true)"
      fi
      if [[ -n "$pid" && ! -d "/proc/$pid" ]]; then
        local sz; sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
        rm -f -- "$f" && ((removed++)) && ((bytes+=sz))
      else
        # verifica idade
        local mt; mt=$(stat -c %Y "$f" 2>/dev/null || echo "$now")
        if (( now - mt > LOCK_ORPHAN_MAX_AGE )); then
          local sz; sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
          rm -f -- "$f" && ((removed++)) && ((bytes+=sz))
        fi
      fi
    done < <(find "$LOCK_DIR" -type f \( -name "*.pid" -o -name "*.pid.*" \) -print0 2>/dev/null || true)
    if (( removed > 0 )); then
      _log_info "CLEANUP: removidos $removed arquivos de PID órfãos (~${bytes} bytes)"
    fi
  fi
  exec {clfd}>&- 2>/dev/null || true
}

# Dump de estado do processo atual
lock::dump_state() {
  if [[ "${1:-}" == "--all" ]]; then
    _log_info "Estado de locks (sistema):"
    while IFS= read -r -d '' p; do
      local owner="?"
      if [[ "$p" == *.pid ]]; then
        owner="$(cat "$p" 2>/dev/null || echo "?")"
      elif [[ "$p" == *.pid.* ]]; then
        owner="${p##*.pid.}"
      fi
      local mt; mt=$(stat -c %y "$p" 2>/dev/null || echo "?")
      local name; name="${p#${LOCK_DIR}/}"; name="${name%.pid*}"
      name="${name%.lock}"
      _log_info "  ${name} → PID ${owner} desde ${mt}"
    done < <(find "$LOCK_DIR" -type f \( -name "*.pid" -o -name "*.pid.*" \) -print0 2>/dev/null || true)
    return 0
  fi

  _log_info "Estado de locks (processo $$):"
  local i
  for i in "${!LOCK_HELD_ORDER[@]}"; do
    local n="${LOCK_HELD_ORDER[$i]}"
    [[ -z "$n" ]] && continue
    local fd="${LOCK_FD[$n]:-?}" ref="${LOCK_REF[$n]:-0}" mode="${LOCK_MODE[$n]:-?}" path="${LOCK_PATH[$n]:-?}"
    _log_info "  $((i+1)). ${n} (fd=${fd}, ref=${ref}, mode=${mode}, path=${path})"
  done
}

# Owner info
lock::owner_info() {
  local name="$1"
  local path; path="$(__path_for_name "$name")"
  if [[ -f "${path}.pid" ]]; then
    echo "excl: PID $(cat "${path}.pid" 2>/dev/null || echo '?') file=${path}.pid"
  fi
  local f
  for f in "${path}.pid."*; do
    [[ -e "$f" ]] || continue
    echo "shared: PID ${f##*.pid.} file=$f"
  done
}

# =========================
# Ordem de aquisição
# =========================
lock::__check_order() {
  local name="$1"
  local want; want="$(__name_class_ord "$name")"
  local max=0
  local i
  for i in "${!LOCK_HELD_ORDER[@]}"; do
    local n="${LOCK_HELD_ORDER[$i]}"
    [[ -z "$n" ]] && continue
    local o; o="$(__name_class_ord "$n")"
    (( o > max )) && max="$o"
  done
  if (( want < max )); then
    _log_warn "Ordem de locks potencialmente perigosa: já detidos até nível ${max}, tentando adquirir nível ${want} (${name})"
    if [[ "$LOCK_STRICT_ORDER" == "true" ]]; then
      return 5
    fi
  fi
  return 0
}

# =========================
# API: init e cleanup
# =========================
lock::__cleanup() {
  # Libera todos os locks mantidos por este processo (ordem inversa)
  local i
  for (( i=${#LOCK_HELD_ORDER[@]}-1; i>=0; i-- )); do
    local n="${LOCK_HELD_ORDER[$i]}"
    [[ -n "$n" ]] || continue
    # shellcheck disable=SC2154
    lock::release "$n" >/dev/null 2>&1 || true
  done
}

lock::init() {
  lock::__select_lock_dir || return $?
  __ensure_dir "$LOCK_DIR/pkg"
  __ensure_dir "$LOCK_DIR/.meta"
  # traps
  trap lock::__cleanup EXIT INT TERM
  # limpeza leve
  lock::__cleanup_orphans
  _log_ok "LOCK_DIR pronto: $LOCK_DIR"
  return 0
}

# =========================
# Aquisição (exclusivo/compartilhado)
# =========================
# lock::acquire <name> [mode] [timeout]
lock::acquire() {
  local name="$1"; shift || true
  local mode="${1:-exclusive}"; shift || true
  local timeout="${1:-$LOCK_DEFAULT_TIMEOUT}"

  [[ -z "$name" ]] && { _log_err "lock::acquire: requer <name>"; return 1; }
  name="$(lock::sanitize_name "$name")"
  [[ "$mode" != "exclusive" && "$mode" != "shared" ]] && { _log_err "lock::acquire: modo inválido '$mode'"; return 1; }

  # Reentrância
  if [[ -n "${LOCK_REF[$name]:-}" ]] && (( LOCK_REF[$name] > 0 )); then
    # Se reentrante em modo diferente, permitir mas manter modo original (não intensifica)
    (( LOCK_REF[$name]++ ))
    _log_info "lock::acquire reentrante: $name (ref=${LOCK_REF[$name]})"
    return 0
  fi

  lock::__check_order "$name" || return $?

  local path; path="$(__path_for_name "$name")"
  local dir; dir="$(dirname "$path")"
  __ensure_dir "$dir" || { _log_err "Falha ao criar diretório $dir"; return 4; }

  # Garante existência do arquivo
  : > "$path" 2>/dev/null || true

  # Open FD conforme modo
  local fd
  if [[ "$mode" == "exclusive" ]]; then
    if ! exec {fd}> "$path"; then
      _log_err "Falha ao abrir FD exclusivo para $name ($path)"
      return 4
    fi
  else
    # shared precisa abrir leitura; garante que exista
    : > "$path" 2>/dev/null || true
    if ! exec {fd}< "$path"; then
      _log_err "Falha ao abrir FD compartilhado para $name ($path)"
      return 4
    fi
  fi

  local start; start=$(__seconds_now)
  local waited=0 last_notice=0 rc=0
  local flargs=()
  if [[ "$mode" == "shared" ]]; then
    flargs=(-s)
  fi

  _log_step "Aguardando lock $name → $path (modo=$mode, timeout=${timeout}s)"
  # Implementa espera com avisos periódicos (loop usando -n)
  while true; do
    if [[ "$timeout" -gt 0 && "$waited" -ge "$timeout" ]]; then
      _log_err "Timeout aguardando lock $name após ${waited}s"
      # fecha FD
      exec {fd}>&- 2>/dev/null || exec {fd}<&- 2>/dev/null || true
      return 2
    fi

    if flock -n "${flargs[@]}" "$fd"; then
      rc=0
      break
    fi

    # Avisos periódicos
    local now; now=$(__seconds_now)
    waited=$(( now - start ))
    if (( waited - last_notice >= LOCK_WAIT_NOTICE_INTERVAL )); then
      last_notice="$waited"
      _log_step "Aguardando lock $name (${waited}s elapsed)"
      # mostra dono atual (melhor esforço)
      lock::owner_info "$name" | while read -r ln; do _log_info "$ln"; done
    fi
    sleep 1
  done

  # Sucesso: registra estado
  LOCK_FD["$name"]="$fd"
  LOCK_REF["$name"]=1
  LOCK_MODE["$name"]="$mode"
  LOCK_PATH["$name"]="$path"
  LOCK_ACQ_TIME["$name"]="$start"
  LOCK_STACK_FILE["$name"]="${BASH_SOURCE[1]:-?}"
  LOCK_STACK_LINE["$name"]="${BASH_LINENO[0]:-0}"

  # Ordem mantida
  LOCK_HELD_INDEX["$name"]="${#LOCK_HELD_ORDER[@]}"
  LOCK_HELD_ORDER+=("$name")

  # PID sidecar
  local pidfile; pidfile="$(__pid_sidecar "$path" "$mode")"
  echo "$$" > "$pidfile" 2>/dev/null || true

  _log_ok "Lock adquirido: $name (fd=${fd}, mode=${mode})"
  return 0
}

# lock::try <name> [mode]
lock::try() {
  local name="$1"; shift || true
  local mode="${1:-exclusive}"

  [[ -z "$name" ]] && { _log_err "lock::try: requer <name>"; return 1; }
  name="$(lock::sanitize_name "$name")"
  [[ "$mode" != "exclusive" && "$mode" != "shared" ]] && { _log_err "lock::try: modo inválido '$mode'"; return 1; }

  if [[ -n "${LOCK_REF[$name]:-}" ]] && (( LOCK_REF[$name] > 0 )); then
    (( LOCK_REF[$name]++ ))
    _log_info "lock::try reentrante: $name (ref=${LOCK_REF[$name]})"
    return 0
  fi

  lock::__check_order "$name" || return $?

  local path; path="$(__path_for_name "$name")"
  local dir; dir="$(dirname "$path")"
  __ensure_dir "$dir" || { _log_err "Falha ao criar diretório $dir"; return 4; }
  : > "$path" 2>/dev/null || true

  local fd
  if [[ "$mode" == "exclusive" ]]; then
    exec {fd}> "$path" || { _log_err "Falha ao abrir FD para $name"; return 4; }
    if ! flock -n "$fd"; then
      exec {fd}>&- 2>/dev/null || true
      return 3
    fi
  else
    exec {fd}< "$path" || { _log_err "Falha ao abrir FD para $name"; return 4; }
    if ! flock -s -n "$fd"; then
      exec {fd}<&- 2>/dev/null || true
      return 3
    fi
  fi

  LOCK_FD["$name"]="$fd"
  LOCK_REF["$name"]=1
  LOCK_MODE["$name"]="$mode"
  LOCK_PATH["$name"]="$path"
  LOCK_ACQ_TIME["$name"]="$(__seconds_now)"
  LOCK_STACK_FILE["$name"]="${BASH_SOURCE[1]:-?}"
  LOCK_STACK_LINE["$name"]="${BASH_LINENO[0]:-0}"
  LOCK_HELD_INDEX["$name"]="${#LOCK_HELD_ORDER[@]}"
  LOCK_HELD_ORDER+=("$name")
  echo "$$" > "$(__pid_sidecar "$path" "$mode")" 2>/dev/null || true
  _log_ok "Lock (try) adquirido: $name"
  return 0
}

# lock::release <name>
lock::release() {
  local name="$1"
  [[ -z "$name" ]] && { _log_err "lock::release: requer <name>"; return 1; }
  name="$(lock::sanitize_name "$name")"

  if [[ -z "${LOCK_REF[$name]:-}" || "${LOCK_REF[$name]}" -le 0 ]]; then
    _log_warn "lock::release($name): não estava detido (possível dupla liberação)"
    return 0
  fi

  local ref="${LOCK_REF[$name]}"
  (( ref-- ))
  LOCK_REF["$name"]="$ref"
  if (( ref > 0 )); then
    _log_info "lock::release reentrante: $name (ref rest=${ref})"
    return 0
  fi

  local fd="${LOCK_FD[$name]:-}"
  local mode="${LOCK_MODE[$name]:-exclusive}"
  local path="${LOCK_PATH[$name]:-}"
  if [[ -z "$fd" || -z "$path" ]]; then
    _log_err "lock::release: estado interno ausente para $name"
    return 4
  fi

  # fecha FD (solta flock)
  exec {fd}>&- 2>/dev/null || exec {fd}<&- 2>/dev/null || true

  # remove sidecar PID
  local pidfile; pidfile="$(__pid_sidecar "$path" "$mode")"
  rm -f -- "$pidfile" 2>/dev/null || true

  # Limpa estruturas
  LOCK_FD["$name"]=""
  LOCK_MODE["$name"]=""
  LOCK_PATH["$name"]=""
  LOCK_ACQ_TIME["$name"]=""

  # Remove da ordem
  local idx="${LOCK_HELD_INDEX[$name]:-}"
  if [[ -n "$idx" ]]; then
    LOCK_HELD_ORDER["$idx"]=""
    LOCK_HELD_INDEX["$name"]=""
  fi

  _log_ok "Lock liberado: $name"
  return 0
}

# Açúcar sintático: lock::with <name> [mode] [timeout] -- <cmd...>
lock::with() {
  local name mode timeout
  if [[ $# -lt 1 ]]; then _log_err "lock::with: requer <name> ... -- <cmd>"; return 1; fi
  name="$1"; shift
  mode="${1:-exclusive}"; shift || true
  timeout="${1:-$LOCK_DEFAULT_TIMEOUT}"; shift || true
  if [[ "${1:-}" == "--" ]]; then shift; else _log_err "lock::with: faltou '--' antes do comando"; return 1; fi
  lock::acquire "$name" "$mode" "$timeout" || return $?
  "$@"
  local rc=$?
  lock::release "$name" || true
  return $rc
}

# =========================
# Helpers de escopo
# =========================
lock::global_acquire() { lock::acquire "global" "exclusive" "${1:-$LOCK_DEFAULT_TIMEOUT}"; }
lock::global_release() { lock::release "global"; }

lock::repo_acquire()   { lock::acquire "repo" "exclusive" "${1:-$LOCK_DEFAULT_TIMEOUT}"; }
lock::repo_release()   { lock::release "repo"; }

lock::cache_acquire()  { lock::acquire "cache" "${1:-shared}" "${2:-$LOCK_DEFAULT_TIMEOUT}"; } # default shared
lock::cache_release()  { lock::release "cache"; }

lock::pkg_acquire() {
  local pkg="$1"; local t="${2:-$LOCK_DEFAULT_TIMEOUT}"
  [[ -z "$pkg" ]] && { _log_err "lock::pkg_acquire: requer <pkg>"; return 1; }
  lock::acquire "pkg/$(lock::sanitize_name "$pkg")" "exclusive" "$t"
}
lock::pkg_release() {
  local pkg="$1"; [[ -z "$pkg" ]] && { _log_err "lock::pkg_release: requer <pkg>"; return 1; }
  lock::release "pkg/$(lock::sanitize_name "$pkg")"
}

lock::pkgver_acquire() {
  local pkg="$1" ver="$2" t="${3:-$LOCK_DEFAULT_TIMEOUT}"
  [[ -z "$pkg" || -z "$ver" ]] && { _log_err "lock::pkgver_acquire: requer <pkg> <ver>"; return 1; }
  # Regra: primeiro pkg (shared), depois pkgver (exclusive)
  lock::acquire "pkg/$(lock::sanitize_name "$pkg")" "shared" "$t" || return $?
  lock::acquire "pkg/$(lock::sanitize_name "$pkg")/$(lock::sanitize_name "$ver")" "exclusive" "$t" || { local rc=$?; lock::release "pkg/$(lock::sanitize_name "$pkg")" || true; return $rc; }
  return 0
}
lock::pkgver_release() {
  local pkg="$1" ver="$2"
  [[ -z "$pkg" || -z "$ver" ]] && { _log_err "lock::pkgver_release: requer <pkg> <ver>"; return 1; }
  lock::release "pkg/$(lock::sanitize_name "$pkg")/$(lock::sanitize_name "$ver")" || true
  lock::release "pkg/$(lock::sanitize_name "$pkg")" || true
}

# =========================
# Estado/consultas
# =========================
lock::is_held() {
  local name="$1"; [[ -z "$name" ]] && return 1
  name="$(lock::sanitize_name "$name")"
  [[ -n "${LOCK_REF[$name]:-}" && "${LOCK_REF[$name]}" -gt 0 ]]
}

# =========================
# Selftest embutido (opcional)
# =========================
if [[ "${1-}" == "selftest" ]]; then
  shift
  echo ">> Selftest: ports-locks.sh"
  LOCK_DIR="${LOCK_DIR:-/tmp/ports-locks-test}"
  lock::init || exit $?
  # Aquisição simples
  lock::acquire global exclusive 5 || exit $?
  lock::acquire global exclusive 5 || exit $?
  lock::release global || exit $?
  lock::release global || exit $?
  # Try/timeout
  ( lock::init; lock::acquire global exclusive 0; sleep 2 ) &
  sleep 0.2
  lock::try global exclusive || echo "try falhou (ok se rc=3): $?"
  lock::acquire global exclusive 3 || echo "timeout esperado rc=$?"
  wait
  echo ">> Done selftest."
  exit 0
fi
