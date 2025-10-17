#!/usr/bin/env bash
# - ports-logs.sh — biblioteca de logging/cores para o sistema Ports (LFS/BLFS)
# - Saída colorida, limpa, somente etapas no terminal
# - Log completo por etapa/pacote em arquivo
# - Rotação por quantidade, idade e tamanho
# - Seguro para concorrência (flock)
# - Sem 'set -e' para não matar pipelines do chamador
# - Garantir que o usuário (portsbuild) tenha permissão em /var/log/ports
# - chgrp -R ports /var/log/ports
# - chmod -R 0775 /var/log/ports
# - setfacl -R -m d:g:ports:rwx /var/log/ports
# Requisitos: bash >= 4.2, coreutils (date, mkdir, install, stat, awk, sed), flock
# =========================
# Opções de shell seguras
# =========================
set -uo pipefail
# =========================
# Configuração (defaults)
# =========================
: "${PORTS_ETC_CONF:=/etc/ports.conf}"
: "${PORTS_USER_CONF:=~/.config/ports/config}"
# Expande ~ com eval seguro
PORTS_USER_CONF="$(eval echo "$PORTS_USER_CONF")"
# Defaults (podem ser sobrescritos pelos confs)
: "${LOG_ROOT:=/var/log/ports}"
: "${LOG_COLOR:=auto}"           # auto|on|off
: "${LOG_TERMINAL_LEVEL:=STEP}"  # TRACE|DEBUG|INFO|NOTE|STEP|WARN|ERR|OK
: "${LOG_FILE_LEVEL:=DEBUG}"     # idem acima
: "${LOG_ROTATE_KEEP:=7}"        # manter N arquivos por etapa
: "${LOG_ROTATE_DAYS:=30}"       # apagar logs com mais de D dias (0 = desabilita)
: "${LOG_ROTATE_SIZE:=104857600}"# 100M por arquivo (0 = desabilita)
: "${LOG_PROGRESS_PREFIX:=@progress}"  # prefixo para "vazar" linhas ao terminal no log::tee
# =========================
# Carregar configurações
# =========================
_ports_logs_source_if() {
  local f="$1"
  # shellcheck disable=SC1090
  [[ -f "$f" ]] && source "$f"
}
_ports_logs_source_if "$PORTS_ETC_CONF"
_ports_logs_source_if "$PORTS_USER_CONF"
# =========================
# Níveis
# =========================
declare -A __LOG_LEVEL_NUM=(
  [TRACE]=0
  [DEBUG]=10
  [INFO]=20
  [NOTE]=25
  [STEP]=30
  [WARN]=40
  [ERR]=50
  [OK]=60
)
__level_num() { echo "${__LOG_LEVEL_NUM[$1]:-999}"; }

__TERM_MIN="$(__level_num "$LOG_TERMINAL_LEVEL")"
__FILE_MIN="$(__level_num "$LOG_FILE_LEVEL")"
# =========================
# Cores (ANSI)
# =========================
__COLOR_ON=0
__detect_color() {
  case "${LOG_COLOR:-auto}" in
    on)  __COLOR_ON=1 ;;
    off) __COLOR_ON=0 ;;
    auto)
      if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
        __COLOR_ON=1
      else
        __COLOR_ON=0
      fi
      ;;
    *) __COLOR_ON=0 ;;
  esac
}
__detect_color
# Códigos
if (( __COLOR_ON )); then
  C_RESET=$'\033[0m'
  C_DIM=$'\033[2m'
  C_GRAY=$'\033[90m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_MAGENTA=$'\033[35m'
else
  C_RESET=""; C_DIM=""; C_GRAY=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_MAGENTA="";
fi

log::set_color() {
  case "${1:-auto}" in
    on) LOG_COLOR=on ;;
    off) LOG_COLOR=off ;;
    *) LOG_COLOR=auto ;;
  esac
  __detect_color
}
# =========================
# Variáveis de contexto
# =========================
PORTS_LOG_PKG=""
PORTS_LOG_VER=""
PORTS_LOG_STAGE=""
PORTS_LOG_FILE=""
PORTS_LOG_LOCK=""
PORTS_LOG_BUILD_ID="${PORTS_LOG_BUILD_ID:-}" # opcional, pode vir do chamador

# "Mute" terminal
__LOG_MUTE=0
log::mute_terminal() { __LOG_MUTE=1; }
log::unmute_terminal() { __LOG_MUTE=0; }

# =========================
# Utilitários
# =========================
__sanitize() {
  # Mantém [a-zA-Z0-9._-]; troca outros por "_"
  sed -E 's/[^a-zA-Z0-9._-]+/_/g' <<<"$1"
}

__timestamp() {
  # ISO 8601 com offset
  date +"%Y-%m-%dT%H:%M:%S%z"
}

__ensure_dir() {
  local dir="$1"
  install -d -m 0755 "$dir"
}

__bytes_to_h() {
  local b=${1:-0} d=0 s=(B KB MB GB TB PB)
  while (( b >= 1024 && d < ${#s[@]}-1 )); do b=$((b/1024)); d=$((d+1)); done
  printf "%s%s" "$b" "${s[$d]}"
}

# =========================
# Rotação
# =========================
# Políticas:
# - keep: mantém N arquivos (arquivo base + sufixos .1 .2 ...) por etapa
# - days: remove arquivos mais velhos que D dias
# - size: se arquivo atual > SIZE, rotaciona numericamente (.N), truncando o atual
log::rotate() {
  local keep="${1:-$LOG_ROTATE_KEEP}" days="${2:-$LOG_ROTATE_DAYS}" size="${3:-$LOG_ROTATE_SIZE}"
  [[ -z "$PORTS_LOG_FILE" ]] && return 0

  local base="$PORTS_LOG_FILE"
  local dir; dir="$(dirname "$base")"
  [[ -d "$dir" ]] || return 0

  # 1) Por idade (days)
  if [[ "$days" =~ ^[0-9]+$ ]] && (( days > 0 )); then
    find "$dir" -maxdepth 1 -type f -name "$(basename "$base")*" -mtime +"$days" -print0 | xargs -0r rm -f
  fi

  # 2) Por quantidade (keep)
  if [[ "$keep" =~ ^[0-9]+$ ]] && (( keep > 0 )); then
    # Ordena por mtime (mais novos primeiro), remove excedente
    mapfile -t files < <(ls -1t "$dir"/"$(basename "$base")"* 2>/dev/null || true)
    if (( ${#files[@]} > keep )); then
      for ((i=keep; i<${#files[@]}; i++)); do
        rm -f -- "${files[$i]}" || true
      done
    fi
  fi

  # 3) Por tamanho (size)
  if [[ "$size" =~ ^[0-9]+$ ]] && (( size > 0 )); then
    if [[ -f "$base" ]]; then
      local sz
      sz=$(stat -c %s "$base" 2>/dev/null || echo 0)
      if (( sz > size )); then
        # Rotaciona: .(keep-1) é removido, .(k) <- .(k-1), .1 <- base
        local k
        for ((k=keep-1; k>=1; k--)); do
          [[ -f "$base.$k" ]] && mv -f "$base.$k" "$base.$((k+1))"
        done
        mv -f "$base" "$base.1"
        : > "$base"
      fi
    fi
  fi
}

# =========================
# Setup
# =========================
log::setup() {
  local raw_pkg="${1:-}" raw_ver="${2:-}" raw_stage="${3:-}"
  if [[ -z "$raw_pkg" || -z "$raw_ver" || -z "$raw_stage" ]]; then
    echo "log::setup: requer argumentos: <pkg> <ver> <stage>" >&2
    return 2
  fi
  PORTS_LOG_PKG="$(__sanitize "$raw_pkg")"
  PORTS_LOG_VER="$(__sanitize "$raw_ver")"
  PORTS_LOG_STAGE="$(__sanitize "$raw_stage")"

  __ensure_dir "$LOG_ROOT/$PORTS_LOG_PKG/$PORTS_LOG_VER"
  PORTS_LOG_FILE="$LOG_ROOT/$PORTS_LOG_PKG/$PORTS_LOG_VER/$PORTS_LOG_STAGE.log"
  PORTS_LOG_LOCK="$PORTS_LOG_FILE.lock"
  : > "$PORTS_LOG_FILE" 2>/dev/null || true # garante existência (sem truncar se já existir)
  # Rotaciona conforme política (se necessário)
  log::rotate "$LOG_ROTATE_KEEP" "$LOG_ROTATE_DAYS" "$LOG_ROTATE_SIZE"
  return 0
}

log::path_current() {
  [[ -n "$PORTS_LOG_FILE" ]] && echo "$PORTS_LOG_FILE"
}

# =========================
# Escrita
# =========================
__write_file() {
  # $1 LEVEL, $2 MSG
  local level="$1" msg="$2"
  local ts; ts="$(__timestamp)"
  local ctx="PKG=$PORTS_LOG_PKG VER=$PORTS_LOG_VER STAGE=$PORTS_LOG_STAGE"
  local bid=""
  [[ -n "$PORTS_LOG_BUILD_ID" ]] && bid=" BUILD_ID=$PORTS_LOG_BUILD_ID"
  local line="$ts $ctx LEVEL=$level$bid MSG=$(printf '%q' "$msg")"

  # flock por lock-file (não bloqueante longo; espera curto para reduzir interleaving)
  {
    exec 9>"$PORTS_LOG_LOCK"
    flock -w 5 9 || true
    printf "%s\n" "$line" >>"$PORTS_LOG_FILE"
    flock -u 9 || true
    exec 9>&-
  } 2>/dev/null || true
}

__print_term() {
  # $1 LEVEL, $2 MSG
  local level="$1" msg="$2"
  local nlevel="$(__level_num "$level")"
  (( nlevel < __TERM_MIN )) && return 0
  (( __LOG_MUTE )) && return 0

  local tag color text
  case "$level" in
    TRACE) tag="TRACE"; color="$C_GRAY" ;;
    DEBUG) tag="DEBUG"; color="$C_GRAY" ;;
    INFO)  tag="INFO "; color="" ;;
    NOTE)  tag="NOTE "; color="$C_BLUE" ;;
    STEP)  tag="STEP "; color="$C_MAGENTA" ;;
    WARN)  tag="WARN "; color="$C_YELLOW" ;;
    ERR)   tag="ERR  "; color="$C_RED" ;;
    OK)    tag="OK   "; color="$C_GREEN" ;;
    *)     tag="$level"; color="" ;;
  esac
  # Para STEP/OK/ERR destacamos caminho do log quando houver
  local suffix=""
  if [[ "$level" =~ ^(STEP|ERR|OK)$ ]] && [[ -n "$PORTS_LOG_FILE" ]]; then
    suffix=" → ${PORTS_LOG_FILE}"
  fi
  printf "%s[%s]%s %s%s\n" "$color" "$tag" "$C_RESET" "$msg" "$suffix" >&1
}

# API púbica de mensagens
log::step() { __write_file STEP "$*"; __print_term STEP "$*"; }
log::ok()   { __write_file OK   "$*"; __print_term OK   "$*"; }
log::warn() { __write_file WARN "$*"; __print_term WARN "$*"; }
log::err()  {
  local code="${2:-1}"
  __write_file ERR "$1"
  __print_term ERR "$1"
  PORTS_LAST_ERRCODE="$code"
  return "$code"
}
log::info()  { __write_file INFO  "$*"; __print_term INFO  "$*"; }
log::debug() { __write_file DEBUG "$*"; __print_term DEBUG "$*"; }
log::note()  { __write_file NOTE  "$*"; __print_term NOTE  "$*"; }
log::trace() { __write_file TRACE "$*"; __print_term TRACE "$*"; }

# =========================
# Execução de comandos
# =========================
# log::trace <cmd...>
# - Registra o comando
# - Redireciona stdout/stderr COMPLETOS para o arquivo de log
# - Mostra no terminal apenas o cabeçalho/etapas (não "vaza" a saída)
log::trace_cmd() {
  if [[ $# -eq 0 ]]; then
    log::err "log::trace_cmd: nenhum comando fornecido" 1
    return $?
  fi
  local start s end rc
  start=$(date +%s)
  log::trace "Running: $*"
  # Execução com redirecionamento total para o arquivo
  {
    # Bloqueio curto apenas para cabeçalhos; saída do comando vai direto ao arquivo
    {
      exec 9>"$PORTS_LOG_LOCK"
      flock -w 5 9 || true
      printf -- "----- BEGIN CMD: %s -----\n" "$*" >>"$PORTS_LOG_FILE"
      flock -u 9 || true
      exec 9>&-
    } 2>/dev/null || true
    # saída
    "$@" >>"$PORTS_LOG_FILE" 2>&1
    rc=$?
    {
      exec 9>"$PORTS_LOG_LOCK"
      flock -w 5 9 || true
      printf -- "----- END CMD (rc=%d) -----\n" "$rc" >>"$PORTS_LOG_FILE"
      flock -u 9 || true
      exec 9>&-
    } 2>/dev/null || true
    return $rc
  }
  rc=$?
  end=$(date +%s)
  s=$(( end - start ))
  if (( rc == 0 )); then
    log::ok "Comando concluído (rc=0, ${s}s)"
  else
    log::err "Comando falhou (rc=$rc, ${s}s)" "$rc"
    return "$rc"
  fi
}

# log::tee <cmd...>
# - Grava saída completa no arquivo
# - "Vaza" para o terminal SOMENTE linhas que iniciem com $LOG_PROGRESS_PREFIX
log::tee() {
  if [[ $# -eq 0 ]]; then
    log::err "log::tee: nenhum comando fornecido" 1
    return $?
  fi
  local start end s rc
  start=$(date +%s)
  log::trace "Running (tee): $*"
  # Unifica stdout/stderr e processa linha a linha
  # shellcheck disable=SC2094
  {
    "$@" 2>&1 | while IFS= read -r __tee_line; do
      # escreve no arquivo (com flock curto)
      {
        exec 9>"$PORTS_LOG_LOCK"
        flock -w 5 9 || true
        printf "%s\n" "$__tee_line" >>"$PORTS_LOG_FILE"
        flock -u 9 || true
        exec 9>&-
      } 2>/dev/null || true
      # imprime no terminal se prefixado e não mutado
      if (( __COLOR_ON )); then
        : # cores não aplicadas aqui; apenas linhas brutas controladas pelo produtor
      fi
      if (( __LOG_MUTE == 0 )) && [[ "$__tee_line" == "$LOG_PROGRESS_PREFIX"* ]] && [[ -t 1 ]]; then
        printf "%s\n" "${__tee_line#"$LOG_PROGRESS_PREFIX"}"
      fi
    done
  }
  rc=${PIPESTATUS[0]}
  end=$(date +%s)
  s=$(( end - start ))
  if (( rc == 0 )); then
    log::ok "Comando (tee) concluído (rc=0, ${s}s)"
  else
    log::err "Comando (tee) falhou (rc=$rc, ${s}s)" "$rc"
    return "$rc"
  fi
}

# =========================
# Checagens auxiliares
# =========================
log::check_space() {
  # Verifica espaço disponível no filesystem de LOG_ROOT
  local path="$LOG_ROOT"
  __ensure_dir "$path"
  local avail
  avail=$(df -Pk "$path" | awk 'NR==2{print $4*1024}')
  if [[ "$avail" -lt 10485760 ]]; then # <10MB
    log::warn "Pouco espaço livre em $path ($( __bytes_to_h "$avail" ))"
  fi
}

# =========================
# Self-test embutido (opcional)
# =========================
if [[ "${1-}" == "selftest" ]]; then
  shift
  echo ">> Selftest: ports-logs.sh"
  LOG_ROOT="${LOG_ROOT:-/tmp/ports-logs-test}"
  rm -rf -- "$LOG_ROOT"
  log::setup "pkg-demo" "1.0" "build" || exit 1
  log::step "Iniciando build demo"
  log::info "Isso é info"
  log::debug "Debug oculto no terminal"
  log::note "Uma nota legal"
  log::trace_cmd bash -c 'echo "linha normal"; echo "'"$LOG_PROGRESS_PREFIX"' progresso 1"; sleep 0.2; echo "linha normal stderr" 1>&2; exit 0'
  log::tee bash -c 'for i in 1 2 3; do echo "'"$LOG_PROGRESS_PREFIX"' passo $i"; echo "ruido $i"; sleep 0.1; done'
  log::ok "Build demo finalizado"
  echo ">> Arquivo de log:"
  log::path_current
  exit 0
fi
