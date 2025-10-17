#!/usr/bin/env bash
# ports-db.sh — Banco de Dados Local do sistema Ports (LFS/BLFS)
# Requisitos: bash >= 4.2, coreutils, sha256sum, flock; jq (opcional)
# Integra: /usr/lib/ports/ports-locks.sh (Módulo 2) e ports-logs.sh (Módulo 1)
set -euo pipefail
# =========================
# Configuração (defaults)
# =========================
: "${PORTS_DB_ROOT:=/var/lib/ports}"
: "${PORTS_DB_VERSION:=1}"
: "${PORTS_DB_FSYNC:=false}"              # fsync ao salvar JSON crítico
: "${PORTS_DB_MIN_FREE_MB:=100}"          # mínimo de espaço livre para mutações
: "${PORTS_DB_HISTORY_ZSTD:=false}"       # compactar histórico antigo
: "${PORTS_DB_VERIFY_ON_LOAD:=false}"     # valida integridade completa ao iniciar
: "${PORTS_DB_USER:=portsbuild}"
: "${PORTS_DB_GROUP:=ports}"
# Chroot (alvo final para instalar/remover arquivos)
: "${PORTS_CHROOT_ROOT:=/}"               # pode ser /mnt/lfs
# Caminhos internos
DB_DIR="$PORTS_DB_ROOT"
DB_REPO="$DB_DIR/repo"
DB_INSTALLED="$DB_DIR/installed"
DB_STATES="$DB_DIR/states"
DB_HISTORY="$DB_DIR/history"
DB_CACHE="$DB_DIR/cache"
DB_CACHE_TX="$DB_CACHE/transactions"
DB_META="$DB_DIR/.meta"

# Índices derivados
IDX_FILES="$DB_META/files.idx"
IDX_INSTALLED="$DB_META/installed.idx"
IDX_PROVIDES="$DB_META/provides.idx"
IDX_REQUIRES="$DB_META/requires.idx"

# =========================
# Logs (Módulo 1) — fallback elegante
# =========================
_log_have=0
if declare -F log::step >/dev/null 2>&1 && declare -F log::ok >/dev/null 2>&1; then _log_have=1; fi
log_step() { if (( _log_have )); then log::step "$@"; else echo "[STEP] $*"; fi; }
log_ok()   { if (( _log_have )); then log::ok   "$@"; else echo "[OK ] $*";  fi; }
log_info() { if (( _log_have )); then log::info "$@"; else echo "[INFO] $*"; fi; }
log_warn() { if (( _log_have )); then log::warn "$@"; else echo "[WARN] $*"; fi; }
log_err()  { if (( _log_have )); then log::err  "$@"; else echo "[ERR ] $*" >&2; fi; }

# =========================
# Locks (Módulo 2)
# =========================
if ! declare -F lock::init >/dev/null 2>&1; then
  if [[ -f /usr/lib/ports/ports-locks.sh ]]; then
    # shellcheck disable=SC1091
    source /usr/lib/ports/ports-locks.sh
  else
    echo "[FATAL] ports-locks.sh não encontrado. Instale o Módulo 2." >&2
    exit 99
  fi
fi

# =========================
# Utilitários gerais
# =========================
have_jq=0
command -v jq >/dev/null 2>&1 && have_jq=1

__ensure_dir() { install -d -m "$2" "$1" 2>/dev/null || install -d "$1"; }
__ts() { date -Is; }
__fsync() { [[ "$PORTS_DB_FSYNC" == "true" ]] || return 0; command -v sync >/dev/null 2>&1 && sync -f "$1" 2>/dev/null || true; }
__bytes_free() { df -Pm "$1" 2>/dev/null | awk 'NR==2{print $4}'; }   # MB
__check_space() {
  local mb; mb=$(__bytes_free "$PORTS_DB_ROOT")
  if [[ -z "$mb" ]]; then log_warn "Não foi possível determinar espaço livre em $PORTS_DB_ROOT"; return 0; fi
  if (( mb < PORTS_DB_MIN_FREE_MB )); then
    log_err "Espaço insuficiente em $PORTS_DB_ROOT (${mb} MB livre < ${PORTS_DB_MIN_FREE_MB} MB)"; return 70
  fi
  return 0
}
__sha256_file() { sha256sum "$1" | awk '{print $1}'; }
__sanitize() { sed -E 's/[^a-zA-Z0-9._+-]+/_/g' <<<"$1"; }

# Escrita atômica de arquivo (texto)
# usage: __atomic_write <dest> <content_string_or_file> [--from-file]
__atomic_write() {
  local dest="$1"; shift
  local tmp="${dest}.tmp.$$"
  local from_file=0
  if [[ "${1:-}" == "--from-file" ]]; then from_file=1; shift; fi
  __ensure_dir "$(dirname "$dest")" 775
  if (( from_file )); then
    cat "$1" > "$tmp"
  else
    printf "%s" "$1" > "$tmp"
  fi
  __fsync "$tmp"
  mv -f "$tmp" "$dest"
  __fsync "$dest"
}

# Escrita atômica de JSON (validação com jq se disponível)
__atomic_write_json() {
  local dest="$1"; shift
  local tmp="${dest}.tmp.$$"
  __ensure_dir "$(dirname "$dest")" 775
  if (( have_jq )); then
    printf "%s" "$1" | jq -c . > "$tmp"
  else
    # fallback: grava como veio; chama verificação leve
    printf "%s" "$1" > "$tmp"
  fi
  __fsync "$tmp"
  mv -f "$tmp" "$dest"
  __fsync "$dest"
}

# Lê uma chave JSON simples com jq ou fallback (apenas strings)
__json_get() {
  local file="$1" key="$2"
  if (( have_jq )); then
    jq -r ".$key // empty" "$file"
  else
    # fallback muito simples: "key": "value"
    grep -E "\"$key\"[[:space:]]*:" "$file" | head -n1 | sed -E 's/.*"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/'
  fi
}

# =========================
# Segurança e permissões
# =========================
db::_ensure_permissions() {
  local fix=0
  for d in "$DB_DIR:775" "$DB_REPO:775" "$DB_INSTALLED:770" "$DB_STATES:775" "$DB_HISTORY:775" "$DB_CACHE:775" "$DB_CACHE_TX:770" "$DB_META:775"; do
    IFS=: read -r path mode <<<"$d"
    __ensure_dir "$path" "$mode"
    # proprietários
    if ! chown root:"$PORTS_DB_GROUP" "$path" 2>/dev/null; then
      log_warn "Não consegui chown root:$PORTS_DB_GROUP em $path (permita com sudo)"
    fi
    chmod "$mode" "$path" || true
  done
  # versão do schema
  if [[ ! -f "$DB_DIR/.version" ]]; then echo "$PORTS_DB_VERSION" > "$DB_DIR/.version"; fi
  return 0
}

# =========================
# Journaling (WAL)
# =========================
# Formato JSON:
# { "op":"install|uninstall", "pkg":"...", "ver":"...", "intent":"start|precommit|commit", "paths":[...], "ts":"..." }

db::_new_tx_path() { echo "$DB_CACHE_TX/$(date +%Y%m%d-%H%M%S)-$$-$(__sanitize "$1")-$(__sanitize "$2").txn"; }

db::begin_tx() {
  local op="$1" pkg="$2" ver="$3"
  __check_space || return $?
  __ensure_dir "$DB_CACHE_TX" 770
  local tx; tx="$(db::_new_tx_path "$pkg" "$ver")"
  local json
  json=$(cat <<-JSON
{"op":"$op","pkg":"$pkg","ver":"$ver","intent":"start","paths":[],"ts":"$(__ts)"}
JSON
)
  __atomic_write_json "$tx" "$json"
  echo "$tx"
}

db::_tx_update_intent() {
  local tx="$1" intent="$2"
  if (( have_jq )); then
    tmp="${tx}.tmp.$$"
    jq -c ".intent=\"$intent\" | .ts=\"$(__ts)\"" "$tx" > "$tmp"
    mv -f "$tmp" "$tx"
  else
    # substitui chave intent
    sed -E -i "s/\"intent\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"intent\":\"$intent\"/" "$tx"
  fi
  __fsync "$tx"
}

db::_tx_add_path() {
  local tx="$1" path="$2"
  if (( have_jq )); then
    tmp="${tx}.tmp.$$"
    jq -c ".paths += [\"$path\"]" "$tx" > "$tmp"
    mv -f "$tmp" "$tx"
  else
    # append simples antes do colchete final
    sed -E -i "s/\"paths\"[[:space:]]*:[[:space:]]*\[/\"paths\":[\"$path\", /" "$tx" || true
  fi
  __fsync "$tx"
}

db::_tx_commit_and_remove() {
  local tx="$1"
  db::_tx_update_intent "$tx" "commit"
  rm -f -- "$tx" || true
}

db::_replay_recovery() {
  __ensure_dir "$DB_CACHE_TX" 770
  shopt -s nullglob
  local tx count=0
  for tx in "$DB_CACHE_TX"/*.txn; do
    count=$((count+1))
    local op pkg ver intent
    if (( have_jq )); then
      op=$(jq -r '.op' "$tx"); pkg=$(jq -r '.pkg' "$tx"); ver=$(jq -r '.ver' "$tx"); intent=$(jq -r '.intent' "$tx")
    else
      op=$(grep -oE '"op"[[:space:]]*:[[:space:]]*"[^"]+"' "$tx" | sed -E 's/.*"([^"]+)"/\1/')
      pkg=$(grep -oE '"pkg"[[:space:]]*:[[:space:]]*"[^"]+"' "$tx" | sed -E 's/.*"([^"]+)"/\1/')
      ver=$(grep -oE '"ver"[[:space:]]*:[[:space:]]*"[^"]+"' "$tx" | sed -E 's/.*"([^"]+)"/\1/')
      intent=$(grep -oE '"intent"[[:space:]]*:[[:space:]]*"[^"]+"' "$tx" | sed -E 's/.*"([^"]+)"/\1/')
    fi
    log_warn "Recuperando transação pendente: $op $pkg-$ver (intent=$intent)"
    case "$op" in
      install)
        # Se precommit, tenta completar commit de DB; se start, remove diretórios parciais.
        if [[ -d "$DB_INSTALLED/$pkg/$ver" ]]; then
          db::_regenerate_indices_quick || true
          db::event "{\"event\":\"recover-install\",\"pkg\":\"$pkg\",\"ver\":\"$ver\",\"ts\":\"$(__ts)\"}"
        else
          log_info "Limpando resíduos de install pendente $pkg-$ver"
        fi
        ;;
      uninstall)
        # Se start e pacote ainda existe, mantemos; se precommit, removemos índices.
        if [[ ! -d "$DB_INSTALLED/$pkg/$ver" ]]; then
          db::_regenerate_indices_quick || true
          db::event "{\"event\":\"recover-uninstall\",\"pkg\":\"$pkg\",\"ver\":\"$ver\",\"ts\":\"$(__ts)\"}"
        fi
        ;;
      *)
        log_warn "TX desconhecida: $op"
        ;;
    esac
    rm -f -- "$tx" || true
  done
  shopt -u nullglob
  (( count > 0 )) && log_ok "Recovery: $count transação(ões) tratadas"
}

# =========================
# Inicialização do DB
# =========================
db::init() {
  lock::init
  log_step "Inicializando DB em $PORTS_DB_ROOT"
  __ensure_dir "$DB_DIR" 775
  __ensure_dir "$DB_META" 775
  __ensure_dir "$DB_REPO" 775
  __ensure_dir "$DB_INSTALLED" 770
  __ensure_dir "$DB_STATES" 775
  __ensure_dir "$DB_HISTORY" 775
  __ensure_dir "$DB_CACHE_TX" 770
  db::_ensure_permissions
  # recovery
  db::_replay_recovery
  # índices se faltando
  [[ -f "$IDX_FILES" ]] || __atomic_write "$IDX_FILES" ""       # vazio
  [[ -f "$IDX_INSTALLED" ]] || __atomic_write "$IDX_INSTALLED" ""
  [[ -f "$IDX_PROVIDES" ]] || __atomic_write "$IDX_PROVIDES" ""
  [[ -f "$IDX_REQUIRES" ]] || __atomic_write "$IDX_REQUIRES" ""
  # arquivos de estado básicos
  [[ -f "$DB_STATES/world.json" ]] || __atomic_write_json "$DB_STATES/world.json" '{"roots":[]}'
  [[ -f "$DB_STATES/holds.json" ]] || __atomic_write_json "$DB_STATES/holds.json" '{"holds":[]}'
  [[ -f "$DB_STATES/auto.json" ]] || __atomic_write_json "$DB_STATES/auto.json" '{"auto":[]}'
  (( PORTS_DB_VERIFY_ON_LOAD == 1 )) && db::verify || true
  log_ok "DB pronto"
}

# =========================
# Histórico encadeado (SHA-256)
# =========================
# Cada linha: {"ts":"...","event":"...","prev_hash":"...","hash":"..."}
db::_history_file_for_today() {
  local day; day="$(date +%F)"
  __ensure_dir "$DB_HISTORY/$day" 775
  echo "$DB_HISTORY/$day/events.jsonl"
}
db::_history_prev_hash() {
  local f="$1"
  [[ -f "$f" ]] || { echo ""; return 0; }
  tail -n1 "$f" | sed -E 's/.*"hash":"([^"]+)".*/\1/'
}
db::event() {
  local json="$1"
  local f; f="$(db::_history_file_for_today)"
  local prev; prev="$(db::_history_prev_hash "$f")"
  local payload
  if (( have_jq )); then
    payload=$(jq -c --arg ts "$(__ts)" --arg prev "$prev" '.ts=$ts | .prev_hash=$prev' <<<"$json")
  else
    payload="${json%}}"', "ts":"'"$(__ts)"'","prev_hash":"'"$prev"'"}'
  fi
  local h; h=$(printf "%s" "$payload" | sha256sum | awk '{print $1}')
  if (( have_jq )); then
    payload=$(jq -c --arg h "$h" '.hash=$h' <<<"$payload")
  else
    payload="${payload%}}"', "hash":"'"$h"'"}'
  fi
  __ensure_dir "$(dirname "$f")" 775
  printf "%s\n" "$payload" >> "$f"
}

db::verify_history() {
  local day f prev=""
  for day in "$DB_HISTORY"/*; do
    [[ -d "$day" ]] || continue
    f="$day/events.jsonl"
    [[ -f "$f" ]] || continue
    local ok=1
    while IFS= read -r line; do
      local lh; lh=$(printf "%s" "$line" | sha256sum | awk '{print $1}')
      local hh; hh=$(sed -E 's/.*"hash":"([^"]+)".*/\1/' <<<"$line")
      if [[ "$lh" != "$hh" ]]; then ok=0; break; fi
      local pv; pv=$(sed -E 's/.*"prev_hash":"([^"]*)".*/\1/' <<<"$line")
      [[ -z "$prev" || "$pv" == "$prev" ]] || { ok=0; break; }
      prev="$hh"
    done < "$f"
    if (( ok )); then log_ok "Histórico OK: $f"; else log_err "Histórico adulterado: $f"; fi
  done
}

# =========================
# Consultas rápidas
# =========================
db::is_installed() {
  local pkg="$1" ver="${2:-}"
  if [[ -z "$ver" ]]; then [[ -d "$DB_INSTALLED/$pkg" && -L "$DB_INSTALLED/$pkg/CURRENT" ]]; return $?; fi
  [[ -d "$DB_INSTALLED/$pkg/$ver" ]]
}
db::active_version() {
  local pkg="$1"
  [[ -L "$DB_INSTALLED/$pkg/CURRENT" ]] || { echo ""; return 1; }
  readlink -f "$DB_INSTALLED/$pkg/CURRENT" | xargs basename
}
db::manifest_path() {
  local pkg="$1" ver="${2:-$(db::active_version "$pkg" || true)}"
  [[ -n "$ver" && -f "$DB_INSTALLED/$pkg/$ver/manifest.json" ]] && echo "$DB_INSTALLED/$pkg/$ver/manifest.json" || echo ""
}
db::list_files() {
  local p; p="$(db::manifest_path "$1" "${2:-}")"; [[ -n "$p" ]] || return 1
  if (( have_jq )); then jq -r '.files[].path' "$p"; else grep -oE '"path"[[:space:]]*:[[:space:]]*"[^"]*"' "$p" | sed -E 's/.*"([^"]*)"/\1/'; fi
}
db::who_owns() {
  local path="$1"; [[ -f "$IDX_FILES" ]] || { echo ""; return 1; }
  awk -v p="$path" '$1==p {print $2, $3}' "$IDX_FILES"
}

# =========================
# Índices derivados
# =========================
db::_index_footer_hash() {
  local file="$1"
  local h; h=$(grep -vE '^#' "$file" | sha256sum | awk '{print $1}')
  printf "# SHA256: %s\n" "$h"
}
db::_write_index_atomic() {
  local dest="$1"; shift
  local tmp="${dest}.tmp.$$"
  __ensure_dir "$(dirname "$dest")" 775
  cat /dev/null > "$tmp"
  # conteúdo vem por stdin
  cat >> "$tmp"
  db::_index_footer_hash "$tmp" >> "$tmp"
  mv -f "$tmp" "$dest"
}
db::_regenerate_indices_quick() {
  log_step "Regenerando índices (rápido)"
  # installed.idx
  { find "$DB_INSTALLED" -mindepth 2 -maxdepth 2 -type d -printf "%P\n" 2>/dev/null | awk -F/ 'NF==2 {print $1, $2}' | sort; } | db::_write_index_atomic "$IDX_INSTALLED"
  # files.idx
  {
    find "$DB_INSTALLED" -mindepth 2 -maxdepth 2 -type f -name manifest.json -print0 2>/dev/null | \
    xargs -0 -I{} sh -c '
      f="{}"
      if command -v jq >/dev/null 2>&1; then
        jq -r --arg pkg "$(basename "$(dirname "$f")")" --arg ver "$(basename "$(dirname "$(dirname "$f")")")" \
          ".files[] | [.path, $pkg, $ver] | @tsv" "$f"
      else
        pkg=$(basename "$(dirname "$f")"); ver=$(basename "$(dirname "$(dirname "$f")")")
        grep -oE "\"path\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$f" | sed -E "s/.*\"([^\"]*)\"/\1\t$pkg\t$ver/"
      fi
    ' | sort
  } | db::_write_index_atomic "$IDX_FILES"
  # provides / requires se existirem
  {
    find "$DB_INSTALLED" -mindepth 2 -maxdepth 2 -type f -name provides.json -print0 2>/dev/null | \
    xargs -0 -I{} sh -c '
      f="{}"; pkg=$(basename "$(dirname "$f")"); ver=$(basename "$(dirname "$(dirname "$f")")")
      if command -v jq >/dev/null 2>&1; then
        jq -r --arg pkg "$pkg" --arg ver "$ver" ".provides[]? | [. , $pkg, $ver] | @tsv" "$f"
      else
        sed -n "s/^[[:space:]]*\"\\([^\"]\\+\\)\"[[:space:]]*,*[[:space:]]*$/\\1\t$pkg\t$ver/p" "$f"
      fi
    ' | sort
  } | db::_write_index_atomic "$IDX_PROVIDES"
  {
    find "$DB_INSTALLED" -mindepth 2 -maxdepth 2 -type f -name provides.json -print0 2>/dev/null | \
    xargs -0 -I{} sh -c '
      f="{}"; pkg=$(basename "$(dirname "$f")"); ver=$(basename "$(dirname "$(dirname "$f")")")
      if [ -f "$(dirname "$f")/meta.json" ]; then
        m="$(dirname "$f")/meta.json"
        if command -v jq >/dev/null 2>&1; then
          jq -r --arg pkg "$pkg" --arg ver "$ver" ".requires[]? | [. , $pkg, $ver] | @tsv" "$m"
        else
          sed -n "s/^[[:space:]]*\"\\([^\"]\\+\\)\"[[:space:]]*,*[[:space:]]*$/\\1\t$pkg\t$ver/p" "$m"
        fi
      fi
    ' | sort
  } | db::_write_index_atomic "$IDX_REQUIRES"
  log_ok "Índices atualizados"
}

# =========================
# Commit de instalação
# =========================
# db::install_commit <pkg> <ver> <manifest.json> <meta.json> <provides.json> <build.json> [install_reason]
db::install_commit() {
  local pkg="$1" ver="$2" manifest_src="$3" meta_src="$4" provides_src="$5" build_src="$6" reason="${7:-dep}"
  [[ -f "$manifest_src" && -f "$meta_src" && -f "$build_src" ]] || { log_err "Arquivos obrigatórios ausentes (manifest/meta/build)"; return 64; }

  lock::pkgver_acquire "$pkg" "$ver" 0

  __check_space || { lock::pkgver_release "$pkg" "$ver"; return $?; }

  local base="$DB_INSTALLED/$pkg/$ver"
  __ensure_dir "$base" 770

  # Verifica SHA-256 dos arquivos listados no manifest (se existirem no chroot)
  if (( have_jq )); then
    while IFS=$'\t' read -r path sha; do
      [[ -z "$path" ]] && continue
      local real="$PORTS_CHROOT_ROOT$path"
      if [[ -f "$real" ]]; then
        local calc; calc=$(__sha256_file "$real")
        if [[ "$calc" != "$sha" ]]; then
          log_err "Hash divergente em $path (calc=$calc, esperado=$sha)"; lock::pkgver_release "$pkg" "$ver"; return 65
        fi
      fi
    done < <(jq -r '.files[] | select(.type=="f" or .type==null) | [.path, .sha256] | @tsv' "$manifest_src")
  fi

  # Journal (start)
  local tx; tx=$(db::begin_tx install "$pkg" "$ver") || { lock::pkgver_release "$pkg" "$ver"; return 70; }

  # Copia arquivos de DB (manifest, meta, provides, build) — atômico
  __atomic_write_json "$base/manifest.json" "$(cat "$manifest_src")"; db::_tx_add_path "$tx" "$base/manifest.json"
  __atomic_write_json "$base/meta.json" "$(cat "$meta_src")"; db::_tx_add_path "$tx" "$base/meta.json"
  [[ -f "$provides_src" ]] && { __atomic_write_json "$base/provides.json" "$(cat "$provides_src")"; db::_tx_add_path "$tx" "$base/provides.json"; } || true
  __atomic_write_json "$base/build.json" "$(cat "$build_src")"; db::_tx_add_path "$tx" "$base/build.json"

  # state.json (pacote)
  local state_json; state_json=$(cat <<-JSON
{"active":"$ver","install_reason":"$reason","auto":$([ "$reason" = "dep" ] && echo true || echo false),"hold":false}
JSON
)
  __atomic_write_json "$DB_INSTALLED/$pkg/state.json" "$state_json"; db::_tx_add_path "$tx" "$DB_INSTALLED/$pkg/state.json"

  # symlink CURRENT
  ln -sfn "$ver" "$DB_INSTALLED/$pkg/CURRENT"

  # Índices
  db::_regenerate_indices_quick

  # Atualiza states/auto/world conforme motivo
  if [[ "$reason" == "manual" ]]; then
    db::world_add "$pkg"
  else
    db::auto_add "$pkg"
  fi

  # Atualiza journal → commit e evento
  db::_tx_update_intent "$tx" "precommit"
  db::event "{\"event\":\"install\",\"pkg\":\"$pkg\",\"ver\":\"$ver\"}"
  db::_tx_commit_and_remove "$tx"

  lock::pkgver_release "$pkg" "$ver"
  log_ok "Install commit aplicado: $pkg-$ver"
}

# =========================
# Commit de desinstalação
# =========================
# db::uninstall_commit <pkg> <ver>
db::uninstall_commit() {
  local pkg="$1" ver="$2"
  lock::pkgver_acquire "$pkg" "$ver" 0
  __check_space || { lock::pkgver_release "$pkg" "$ver"; return $?; }

  [[ -d "$DB_INSTALLED/$pkg/$ver" ]] || { log_warn "Pacote $pkg-$ver não está no DB"; lock::pkgver_release "$pkg" "$ver"; return 0; }

  local tx; tx=$(db::begin_tx uninstall "$pkg" "$ver") || { lock::pkgver_release "$pkg" "$ver"; return 70; }

  # Remove diretório da versão
  rm -rf -- "$DB_INSTALLED/$pkg/$ver"
  # Ajusta CURRENT e state.json
  if [[ -L "$DB_INSTALLED/$pkg/CURRENT" ]]; then
    local cur; cur=$(readlink -f "$DB_INSTALLED/$pkg/CURRENT" | xargs basename)
    if [[ "$cur" == "$ver" ]]; then
      rm -f "$DB_INSTALLED/$pkg/CURRENT"
      # Se houver outras versões, aponta uma (a maior, se possível)
      local latest=""; latest=$(find "$DB_INSTALLED/$pkg" -mindepth 1 -maxdepth 1 -type d -printf "%f\n" 2>/dev/null | grep -v '^CURRENT$' | sort -V | tail -n1 || true)
      if [[ -n "$latest" ]]; then ln -sfn "$latest" "$DB_INSTALLED/$pkg/CURRENT"; fi
      # Atualiza state.json
      if [[ -f "$DB_INSTALLED/$pkg/state.json" ]]; then
        if (( have_jq )); then
          jq -c --arg v "$latest" '.active=$v' "$DB_INSTALLED/$pkg/state.json" > "$DB_INSTALLED/$pkg/state.json.tmp" && mv -f "$DB_INSTALLED/$pkg/state.json.tmp" "$DB_INSTALLED/$pkg/state.json"
        else
          sed -E -i "s/\"active\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"active\":\"$latest\"/" "$DB_INSTALLED/$pkg/state.json"
        fi
      fi
    fi
  fi

  # Regenera índices
  db::_regenerate_indices_quick

  db::_tx_update_intent "$tx" "precommit"
  db::event "{\"event\":\"uninstall\",\"pkg\":\"$pkg\",\"ver\":\"$ver\"}"
  db::_tx_commit_and_remove "$tx"

  # Se pacote não tiver mais versões, remover de auto/world
  if [[ ! -d "$DB_INSTALLED/$pkg" ]]; then
    db::world_del "$pkg"
    db::auto_del "$pkg"
    rm -rf -- "$DB_INSTALLED/$pkg"
  fi

  lock::pkgver_release "$pkg" "$ver"
  log_ok "Uninstall commit aplicado: $pkg-$ver"
}

# =========================
# Estados (world/auto/holds)
# =========================
db::world_add() {
  local pkg="$1" f="$DB_STATES/world.json"
  if (( have_jq )); then
    tmp="${f}.tmp.$$"; jq -c --arg p "$pkg" '.roots |= (. + [$p] | unique)' "$f" > "$tmp"; mv -f "$tmp" "$f"
  else
    if ! grep -q "\"$pkg\"" "$f" 2>/dev/null; then sed -E -i "s/\[ *\]/[\"$pkg\"]/" "$f" || echo "{\"roots\":[\"$pkg\"]}" > "$f"; fi
  fi
}
db::world_del() {
  local pkg="$1" f="$DB_STATES/world.json"
  (( have_jq )) && { tmp="${f}.tmp.$$"; jq -c --arg p "$pkg" '.roots |= map(select(. != $p))' "$f" > "$tmp"; mv -f "$tmp" "$f"; } || true
}
db::auto_add() {
  local pkg="$1" f="$DB_STATES/auto.json"
  (( have_jq )) && { tmp="${f}.tmp.$$"; jq -c --arg p "$pkg" '.auto |= (. + [$p] | unique)' "$f" > "$tmp"; mv -f "$tmp" "$f"; } || true
}
db::auto_del() {
  local pkg="$1" f="$DB_STATES/auto.json"
  (( have_jq )) && { tmp="${f}.tmp.$$"; jq -c --arg p "$pkg" '.auto |= map(select(. != $p))' "$f" > "$tmp"; mv -f "$tmp" "$f"; } || true
}

# =========================
# Dependências & Órfãos
# =========================
# rdepends: quem depende de <pkg>
db::rdepends_of() {
  local target="$1"
  [[ -f "$IDX_REQUIRES" ]] || { echo ""; return 0; }
  awk -v t="$target" 'NF>=3 {req=$1; pkg=$2} req==t {print pkg}' "$IDX_REQUIRES" | sort -u
}

# compute_orphans: pacotes instalados (como dep) sem reverse-deps a partir de world
db::compute_orphans() {
  local roots=()
  if (( have_jq )); then
    mapfile -t roots < <(jq -r '.roots[]?' "$DB_STATES/world.json")
  else
    roots=($(grep -oE '"[^"]+"' "$DB_STATES/world.json" | tr -d '"'))
  fi
  # Coleta todos instalados
  local installed=()
  mapfile -t installed < <(awk 'NF>=2 {print $1}' "$IDX_INSTALLED" | sort -u)

  # Marca alcançáveis via requires (grafo reverso usando rdepends)
  declare -A reachable=()
  for r in "${roots[@]}"; do reachable["$r"]=1; done

  # BFS pelos rdepends
  local queue=("${roots[@]}")
  while ((${#queue[@]})); do
    local cur="${queue[0]}"; queue=("${queue[@]:1}")
    mapfile -t deps < <(db::rdepends_of "$cur" || true)
    for d in "${deps[@]}"; do
      [[ -n "$d" ]] || continue
      if [[ -z "${reachable[$d]:-}" ]]; then
        reachable["$d"]=1; queue+=("$d")
      fi
    done
  done

  # Órfãos = instalados - alcançáveis - world
  local orphans=()
  for p in "${installed[@]}"; do
    if [[ -z "${reachable[$p]:-}" && ! " ${roots[*]} " =~ " $p " ]]; then
      orphans+=("$p")
    fi
  done

  # Salva cache
  if (( have_jq )); then
    printf '%s\n' "$(jq -c --arg ts "$(__ts)" --argjson arr "$(printf '%s\n' "${orphans[@]}" | jq -R . | jq -s .)" '{generated_at:$ts,orphans:$arr}')" > "$DB_STATES/orphans.json"
  else
    printf '{"generated_at":"%s","orphans":[%s]}\n' "$(__ts)" "$(printf '"%s",' "${orphans[@]}" | sed 's/,$//')" > "$DB_STATES/orphans.json"
  fi

  printf "%s\n" "${orphans[@]}"
}

# =========================
# Verificação de integridade
# =========================
db::verify() {
  log_step "Verificando integridade do DB"
  local ok=1
  # Verifica manifests: hashes de arquivos reais (se existirem)
  while IFS= read -r -d '' mf; do
    if (( have_jq )); then
      while IFS=$'\t' read -r path sha; do
        local real="$PORTS_CHROOT_ROOT$path"
        if [[ -f "$real" ]]; then
          local calc; calc=$(__sha256_file "$real")
          if [[ "$calc" != "$sha" ]]; then
            log_err "Hash divergente: $real"; ok=0
          fi
        fi
      done < <(jq -r '.files[] | select(.type=="f" or .type==null) | [.path, .sha256] | @tsv' "$mf")
    fi
  done < <(find "$DB_INSTALLED" -type f -name manifest.json -print0 2>/dev/null)

  # Verifica índices por checksum
  for idx in "$IDX_FILES" "$IDX_INSTALLED" "$IDX_PROVIDES" "$IDX_REQUIRES"; do
    [[ -f "$idx" ]] || { ok=0; log_err "Índice ausente: $idx"; continue; }
    local recalc; recalc=$(grep -vE '^#' "$idx" | sha256sum | awk '{print $1}')
    local footer; footer=$(tail -n1 "$idx" | awk '{print $3}')
    if [[ "$recalc" != "$footer" ]]; then
      log_warn "Checksum inválido em $idx — regenerando"
      db::_regenerate_indices_quick
      break
    fi
  done

  (( ok )) && log_ok "DB verificado com sucesso" || log_warn "DB com inconsistências (veja os erros acima)"
  return $(( ok ? 0 : 1 ))
}

# =========================
# Export snapshot
# =========================
db::export_snapshot() {
  local out="$1"
  [[ -n "$out" ]] || { log_err "Uso: db::export_snapshot <arquivo.tar.zst>"; return 64; }
  local tmpdir; tmpdir="$(mktemp -d)"
  lock::global_acquire 0
  rsync -a --exclude '/cache/transactions' "$PORTS_DB_ROOT/" "$tmpdir/ports/"
  tar -C "$tmpdir" -c ports | zstd -q -19 -o "$out"
  rm -rf -- "$tmpdir"
  lock::global_release
  log_ok "Snapshot exportado: $out"
}

# =========================
# CLI mínima (opcional)
# =========================
if [[ "${1:-}" == "cli" ]]; then
  cmd="${2:-}"; shift 2 || true
  case "$cmd" in
    init) db::init ;;
    is-installed) db::init; db::is_installed "$1" "${2:-}" && echo yes || echo no ;;
    active) db::init; db::active_version "$1" ;;
    who-owns) db::init; db::who_owns "$1" ;;
    list-files) db::init; db::list_files "$1" "${2:-}" ;;
    compute-orphans) db::init; db::compute_orphans ;;
    verify) db::init; db::verify ;;
    history-verify) db::init; db::verify_history ;;
    export) db::init; db::export_snapshot "${1:-/tmp/ports-snapshot.tar.zst}" ;;
    *) echo "Comandos: init | is-installed <pkg> [ver] | active <pkg> | who-owns <path> | list-files <pkg> [ver] | compute-orphans | verify | history-verify | export <file.tar.zst>"; exit 2 ;;
  esac
  exit $?
fi
