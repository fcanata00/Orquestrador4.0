#!/usr/bin/env bash
# lib_common.sh - Biblioteca comum para o sistema de build LFS Ports
# Versão: 1.0 (produção)
#
# Funções: logging, métricas, locks, progress bar, safe_run, syslog, rotação de logs, erros e namespace
# Compatibilidade: bash >= 4.0
# Autor: Gerado por GPT-5 sob especificação de usuário
#
# ================================================================
set -o errtrace
set -o pipefail

LIBCOMMON_VERSION="1.0"

# =========================== Configurações ===========================
: "${LOG_LEVEL:=INFO}"            # DEBUG|INFO|WARN|ERROR
: "${SYSLOG:=0}"                 # 1 -> envia logs ao syslog
: "${SYSLOG_IDENT:=lfsports}"
: "${MAX_LOG_SIZE:=10485760}"    # 10 MiB
: "${MAX_LOG_ROTATE:=5}"
: "${COMPRESS_ROTATED:=1}"
: "${JSON_LOGS:=1}"
: "${DRY_RUN:=0}"
: "${QUIET:=0}"
: "${ERROR_SILENT:=0}"
: "${KEEP_TEMP:=0}"
: "${SAFE_RUN_STRICT:=1}"
: "${LOCK_TTL:=600}"             # segundos antes de considerar lock obsoleto

# =========================== Variáveis internas ===========================
LIBCOMMON_INIT=0
MODULE_NAME=""
LOG_DIR=""
LOG_FILE_TEXT=""
LOG_FILE_JSON=""
TMP_DIR=""
TMP_DIRS=()
LOCKFILES=()

# =========================== Utilitários ===========================
timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
is_tty() { [[ -t 1 && -t 2 ]]; }

require_cmd() {
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "[FATAL] Missing command: $cmd" >&2
      exit 1
    fi
  done
}

# =========================== Cores ===========================
init_colors() {
  if is_tty && command -v tput >/dev/null 2>&1; then
    RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4); CYAN=$(tput setaf 6); BOLD=$(tput bold); RESET=$(tput sgr0)
  else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; BOLD=""; RESET=""
  fi
}

# =========================== Logging ===========================
rotate_logs() {
  local txt="$1"; local json="$2"
  [[ ! -f "$txt" ]] && return 0
  local sz; sz=$(stat -c%s "$txt" 2>/dev/null || echo 0)
  (( sz < MAX_LOG_SIZE )) && return 0

  for ((i=MAX_LOG_ROTATE-1;i>=1;i--)); do
    [[ -f "${txt}.$i" ]] && mv -f "${txt}.$i" "${txt}.$((i+1))" 2>/dev/null || true
    [[ -f "${json}.$i" ]] && mv -f "${json}.$i" "${json}.$((i+1))" 2>/dev/null || true
  done
  mv -f "$txt" "${txt}.1" 2>/dev/null || true
  mv -f "$json" "${json}.1" 2>/dev/null || true
  if (( COMPRESS_ROTATED )) && command -v zstd >/dev/null 2>&1; then
    zstd -q -19 "${txt}.1" && rm -f "${txt}.1" || true
    zstd -q -19 "${json}.1" && rm -f "${json}.1" || true
  fi
}

_log_emit() {
  local level="$1"; shift
  local msg="$*"
  local ts; ts=$(timestamp)
  local mod="${MODULE_NAME:-libcommon}"
  local text_line="[$ts] [$level] [$mod] $msg"

  rotate_logs "$LOG_FILE_TEXT" "$LOG_FILE_JSON"
  echo "$text_line" >>"$LOG_FILE_TEXT"
  if (( JSON_LOGS )); then
    printf '{"ts":"%s","level":"%s","module":"%s","msg":"%s"}\n' "$ts" "$level" "$mod" "$(echo "$msg" | sed 's/"/\\"/g')" >>"$LOG_FILE_JSON"
  fi
  if (( SYSLOG )) && command -v logger >/dev/null 2>&1; then
    logger -t "${SYSLOG_IDENT}-${mod}" "$msg"
  fi
  if (( QUIET )); then return; fi
  case "$level" in
    DEBUG) [[ "$LOG_LEVEL" == "DEBUG" ]] && echo "${CYAN}$text_line${RESET}" ;;
    INFO)  echo "${GREEN}$text_line${RESET}" ;;
    WARN)  echo "${YELLOW}$text_line${RESET}" ;;
    ERROR) (( ERROR_SILENT )) || echo "${RED}$text_line${RESET}" >&2 ;;
  esac
}

log_debug() { [[ "$LOG_LEVEL" == "DEBUG" ]] && _log_emit "DEBUG" "$*"; }
log_info()  { _log_emit "INFO" "$*"; }
log_warn()  { _log_emit "WARN" "$*"; }
log_error() { _log_emit "ERROR" "$*"; }

# =========================== Locks ===========================
with_lock() {
  local name="$1"; shift
  local lock="/tmp/lfs-lock-$name.lock"
  local fd
  exec {fd}> "$lock"
  if ! flock -n "$fd"; then
    log_warn "Lock ativo para $name, aguardando..."
    flock "$fd"
  fi
  "$@"
  local ret=$?
  flock -u "$fd"
  rm -f "$lock"
  return $ret
}

# =========================== Temporários ===========================
mktempdir_safe() {
  local dir; dir=$(mktemp -d -t "lfsports-XXXXXX") || { log_error "Falha ao criar tmpdir"; exit 1; }
  TMP_DIRS+=("$dir")
  echo "$dir"
}

cleanup_on_exit() {
  for lock in "${LOCKFILES[@]}"; do rm -f "$lock" 2>/dev/null || true; done
  if (( ! KEEP_TEMP )); then
    for t in "${TMP_DIRS[@]}"; do rm -rf "$t" 2>/dev/null || true; done
  fi
}

# =========================== Métricas ===========================
get_metrics() {
  if [[ ! -r /proc/stat || ! -r /proc/meminfo || ! -r /proc/loadavg ]]; then
    echo "CPU:N/A MEM:N/A LOAD:N/A"; return
  fi
  local idle1 total1 idle2 total2
  read -r _ user nice system idle iowait irq softirq steal guest < /proc/stat
  idle1=$((idle + iowait)); total1=$((user + nice + system + idle + iowait + irq + softirq + steal))
  sleep 0.2
  read -r _ user nice system idle iowait irq softirq steal guest < /proc/stat
  idle2=$((idle + iowait)); total2=$((user + nice + system + idle + iowait + irq + softirq + steal))
  local totald=$((total2 - total1)); local idled=$((idle2 - idle1))
  local cpu_usage=$(awk -v t=$totald -v i=$idled 'BEGIN{printf "%.1f", (t-i)/t*100}')
  local mem_total mem_free mem_used
  mem_total=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  mem_free=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
  mem_used=$((mem_total - mem_free))
  local load; read -r load _ < /proc/loadavg
  echo "CPU:${cpu_usage}% MEM:$((mem_used/1024))MB LOAD:${load}"
}

log_metrics() {
  log_info "Métricas: $(get_metrics)"
}

# =========================== Barra de Progresso ===========================
progress_start() {
  local msg="$1"
  echo -ne "${BOLD}${BLUE}$msg...${RESET}\r"
}

progress_update() {
  local current=$1 total=$2
  local percent=$(( 100 * current / total ))
  local filled=$(( percent / 4 ))
  local bar=$(printf "%${filled}s" | tr ' ' '#')
  printf "\r[%-25s] %3d%%" "$bar" "$percent"
}

progress_end() {
  echo -e "\r${GREEN}✔ Concluído${RESET}"
}

# =========================== Execução Segura ===========================
safe_run() {
  local desc="$1"; shift
  log_info "Executando: $desc"
  if (( DRY_RUN )); then log_info "[Dry-run] $*"; return 0; fi
  local tmpout; tmpout=$(mktempdir_safe)/run.log
  if ! "$@" &>"$tmpout"; then
    log_error "Falha ao executar '$*'"
    [[ -f "$tmpout" ]] && tail -n 10 "$tmpout" >&2
    if (( SAFE_RUN_STRICT )); then exit 1; fi
    return 1
  fi
  rm -f "$tmpout"
  return 0
}

# =========================== Inicialização ===========================
libcommon_init() {
  MODULE_NAME="${1:-libcommon}"
  init_colors
  LOG_DIR="/var/log/lfsports"
  mkdir -p "$LOG_DIR"
  LOG_FILE_TEXT="$LOG_DIR/${MODULE_NAME}.log"
  LOG_FILE_JSON="$LOG_DIR/${MODULE_NAME}.jsonl"
  trap cleanup_on_exit EXIT INT TERM
  log_info "Iniciado módulo $MODULE_NAME (versão $LIBCOMMON_VERSION)"
}

# =====================================================================
