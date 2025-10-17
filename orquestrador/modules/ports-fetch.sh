#!/usr/bin/env bash
# ports-fetch.sh — Módulo 4: Fetch & Cache (LFS/BLFS)
# Requisitos: bash >= 4.2, coreutils, sha256sum, curl, git
# Opcionais: jq, gpg, aria2c
# Integra: ports-logs.sh (M1), ports-locks.sh (M2), ports-db.sh (M3) [opcional para eventos]
set -euo pipefail
TMP_TRACK=()
trap '__tmp_cleanup' EXIT

# =========================
# Configuração (defaults)
# =========================
: "${PORTS_CACHE_ROOT:=/var/cache/ports}"       # raiz do cache
: "${PORTS_REPO_DIR:=/usr/ports}"               # repositório de metafiles (git)
: "${PORTS_TMPDIR:=/var/cache/ports/tmp}"       # tmp local (atômico)
: "${PORTS_CACHE_CONCURRENCY:=4}"               # paralelismo de downloads
: "${PORTS_FETCH_RETRIES:=3}"                   # reintentos por URL
: "${PORTS_FETCH_TIMEOUT:=60}"                  # timeout de conexão (s)
: "${PORTS_FETCH_TOTAL_TIMEOUT:=0}"             # 0 = sem
: "${PORTS_USE_ARIA2C:=auto}"                   # auto|true|false
: "${PORTS_VERIFY_GPG:=false}"
: "${PORTS_CONFIG_FILE:=/etc/ports/fetch.conf}"      # arquivo de configuração opcional
: "${PORTS_MIN_FREE_MB:=256}"                     # espaço mínimo livre em MB no CACHE_DIR
: "${PORTS_REQUIRE_GPG:=false}"                   # exigir GPG para certos pacotes
# Carrega configuração se existir (shell-style)
if [[ -r "$PORTS_CONFIG_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$PORTS_CONFIG_FILE"
fi
                  # verificar .asc se disponível
: "${PORTS_DB_ROOT:=/var/lib/ports}"            # para eventos (M3)
: "${PORTS_DB_HISTORY_EVENTS:=true}"            # gerar eventos em M3, se presente
# Estrutura do cache
CACHE_DIR="$PORTS_CACHE_ROOT"
SRC_DIR="$CACHE_DIR/sources"       # arquivos baixados (.tar.*, patches, etc.)
GIT_DIR="$CACHE_DIR/git"           # clones bare de repositórios
META_DIR="$CACHE_DIR/meta"         # metadados por artefato
TMP_DIR="$PORTS_TMPDIR"
# Catálogos (JSON/índices)
CATALOG_DIR="$CACHE_DIR/catalog"
CAT_URL_IDX="$CATALOG_DIR/url.idx"           # URL -> caminho no cache
CAT_SHA_IDX="$CATALOG_DIR/sha256.idx"        # sha256 -> caminho no cache
CAT_DB_JSON="$CATALOG_DIR/catalog.json"      # JSON de artefatos
CAT_DB_LOCK="$CATALOG_DIR/catalog.lock"      # lock de catálogo
# =========================
# Logs (Módulo 1) — fallback
# =========================
_have_logs=0
if declare -F log::step >/dev/null 2>&1 && declare -F log::ok >/dev/null 2>&1; then _have_logs=1; fi
log_step(){ if ((_have_logs)); then log::step "$@"; else echo "[STEP] $*"; fi; }
log_ok()  { if ((_have_logs)); then log::ok   "$@"; else echo "[OK ] $*";  fi; }
log_info(){ if ((_have_logs)); then log::info "$@"; else echo "[INFO] $*"; fi; }
log_warn(){ if ((_have_logs)); then log::warn "$@"; else echo "[WARN] $*"; fi; }
log_err() { if ((_have_logs)); then log::err  "$@"; else echo "[ERR] $*" >&2; fi; }

# =========================
# Locks (Módulo 2) — obrigatório
# =========================
if ! declare -F lock::init >/dev/null 2>&1; then
  if [[ -f /usr/lib/ports/ports-locks.sh ]]; then
    # shellcheck disable=SC1091
    source /usr/lib/ports/ports-locks.sh
  else
    echo "[FATAL] ports-locks.sh não encontrado (Módulo 2). Instale antes." >&2
    exit 99
  fi
fi

# =========================
# DB (Módulo 3) — opcional (para eventos)
# =========================
_have_db=0
if declare -F db::event >/dev/null 2>&1; then _have_db=1; fi
event_emit(){ ((_have_db)) && db::event "$1" || true; }

# =========================
# Utilitários
# =========================
have_jq=0; command -v jq >/dev/null 2>&1 && have_jq=1
have_gpg=0; command -v gpg >/dev/null 2>&1 && have_gpg=1
have_b3=0; command -v b3sum >/dev/null 2>&1 && have_b3=1
have_aria2=0; command -v aria2c >/dev/null 2>&1 && have_aria2=1

__ensure_dir(){ install -d -m "${2:-775}" "$1" 2>/dev/null || install -d "$1"; }
__sanitize(){ sed -E 's/[^a-zA-Z0-9._+:-]+/_/g' <<<"$1"; }
__sha256_file(){ sha256sum "$1" | awk '{print $1}'; }
__ts(){ date -Is; }

__atomic_write(){
  local dest="$1" tmp="${dest}.tmp.$$"
  __ensure_dir "$(dirname "$dest")" 775
  cat > "$tmp"
  mv -f "$tmp" "$dest"
}

__append_atomic(){
  local dest="$1" tmp="${dest}.tmp.$$"
  __ensure_dir "$(dirname "$dest")" 775
  [[ -f "$dest" ]] && cat "$dest" > "$tmp" || :
  cat >> "$tmp"
  mv -f "$tmp" "$dest"
}

# Espaço livre mínimo
__check_space(){
  local path="${1:-$CACHE_DIR}" min_mb="${2:-$PORTS_MIN_FREE_MB}"
  local free_mb
  free_mb=$(df -Pm "$path" | awk 'NR==2 {print $4}')
  if [[ -n "$free_mb" && "$free_mb" -lt "$min_mb" ]]; then
    log_err "Espaço insuficiente em $path: ${free_mb}MB < ${min_mb}MB"
    return 75
  fi
  return 0
}

# Garante que o destino está dentro da raiz permitida (anti-symlink traversal)
__safe_in_dir(){
  local base="$1" target="$2"
  local rbase rtarget
  rbase="$(realpath -m "$base")"
  rtarget="$(realpath -m "$target")"
  [[ "${rtarget}" == "${rbase}"* ]]
}

# Registro de arquivos temporários para limpeza
__tmp_register(){ TMP_TRACK+=("$1"); }
__tmp_cleanup(){
  local f
  for f in "${TMP_TRACK[@]:-}"; do
    [[ -n "$f" && -e "$f" ]] && rm -f -- "$f" || true
  done
}
# =========================
# Permissões & Inicialização
# =========================
fetch::init(){
  lock::init
  log_step "Inicializando Fetch & Cache em $CACHE_DIR"
  for d in "$CACHE_DIR:775" "$SRC_DIR:775" "$GIT_DIR:775" "$META_DIR:775" "$TMP_DIR:770" "$CATALOG_DIR:775"; do
    IFS=: read -r p m <<<"$d"; __ensure_dir "$p" "$m"
  done
  for f in "$CAT_URL_IDX" "$CAT_SHA_IDX" "$CAT_DB_JSON"; do
    [[ -f "$f" ]] || : > "$f"
  done
  log_ok "Fetch & Cache operacional"
}

# =========================
# Catálogo (Índices)
# =========================
catalog::_record_file(){
  # args: <url> <path> <sha256> <size> <mtime> <etag>
  # calcula blake3 automaticamente se b3sum disponível
  local url="$1" path="$2" sha="$3" size="$4" mtime="$5" etag="$6"
  local rec b3=""
  if (( have_b3 )); then b3="$(b3sum "$path" | awk '{print $1}')"; fi
  if (( have_jq )); then
    rec=$(jq -nc --arg url "$url" --arg path "$path" --arg sha "$sha"                --arg size "$size" --arg mtime "$mtime" --arg etag "$etag" --arg b3 "$b3"                '{url:$url, path:$path, sha256:$sha, blake3: ($b3|select(length>0)), size:($size|tonumber?), mtime:$mtime, etag:$etag}')
  else
    rec="{\"url\":\"$url\",\"path\":\"$path\",\"sha256\":\"$sha\",\"blake3\":\"$b3\",\"size\":$size,\"mtime\":\"$mtime\",\"etag\":\"$etag\"}"
  fi

  # lock do catálogo
  lock::path_acquire "$CAT_DB_LOCK" 0
  # índices simples (tsv)
  printf "%s\t%s\n" "$url" "$path" | __append_atomic "$CAT_URL_IDX"
  printf "%s\t%s\n" "$sha" "$path" | __append_atomic "$CAT_SHA_IDX"
  # jsonl catálogo
  printf "%s\n" "$rec" | __append_atomic "$CAT_DB_JSON"
  lock::path_release "$CAT_DB_LOCK"
}
}

catalog::find_by_sha(){
  local sha="$1"
  [[ -f "$CAT_SHA_IDX" ]] || return 1
  awk -v s="$sha" '$1==s {print $2; exit}' "$CAT_SHA_IDX"
}
catalog::find_by_url(){
  local url="$1"
  [[ -f "$CAT_URL_IDX" ]] || return 1
  awk -v u="$url" '$1==u {print $2; exit}' "$CAT_URL_IDX"
}

# =========================
# Download por CURL (único)
# =========================
fetch::_curl_one(){
  # args: <url> <out_tmp> <timeout> <total_timeout>
  local url="$1" out="$2" to="$3" toto="$4"
  local args=(--fail --location --proto-redir =https --retry "$PORTS_FETCH_RETRIES" --retry-delay 2 --connect-timeout "$to" --continue-at - --output "$out" "$url")
  [[ "$toto" != "0" ]] && args+=(--max-time "$toto")
  # condicional por ETag/Last-Modified se .meta existir
  local meta="${out}.http"
  if [[ -f "$meta" ]]; then
    local lm etag
    lm=$(awk -F': ' 'tolower($1)=="last-modified"{print $2}' "$meta" | tail -n1 || true)
    etag=$(awk -F': ' 'tolower($1)=="etag"{print $2}' "$meta" | tail -n1 || true)
    [[ -n "$lm" ]] && args+=(-z "$(date -d "$lm" -R 2>/dev/null || echo "$lm")")
    # curl não aceita If-None-Match fácil via cli; mantemos -z para LM
  fi
  curl "${args[@]}"
  # salva cabeçalhos para meta
  curl --head --location --connect-timeout "$to" "$url" > "$meta" || true
}

# =========================
# Verificação de SHA-256 e GPG opcional
# =========================
fetch::verify_sha256(){
  local file="$1" expected="$2"
  local got="$(__sha256_file "$file")"
  if [[ "$got" != "$expected" ]]; then
    log_err "SHA-256 divergente: esperado=$expected obtido=$got para $(basename "$file")"
    return 65
  fi
  log_ok "SHA-256 OK: $got"
}

fetch::verify_gpg_if_enabled(){
  local file="$1" url="$2"
  [[ "$PORTS_VERIFY_GPG" == "true" ]] || return 0
  (( have_gpg )) || { log_warn "GPG não disponível; ignorando verificação de assinatura"; return 0; }
  # tenta obter .asc no mesmo local de cache (ou baixar)
  local asc="${file}.asc"
  if [[ ! -f "$asc" ]]; then
    local asc_url="${url}.asc"
    local tmp="${asc}.tmp.$$"
    if curl -fsSL --connect-timeout "$PORTS_FETCH_TIMEOUT" -o "$tmp" "$asc_url"; then
      mv -f "$tmp" "$asc"
    else
      log_warn "Assinatura .asc não encontrada para $url; seguindo sem GPG"
      return 0
    fi
  fi
  if gpg --verify "$asc" "$file" >/dev/null 2>&1; then
    log_ok "Assinatura GPG válida para $(basename "$file")"
  else
    log_err "Falha na verificação GPG para $(basename "$file")"
    return 66
  fi
}

# =========================
# Baixar um artefato (com múltiplos espelhos)
# =========================
# fetch::get_file "<sha256>" "<outfile_name>" "<url1>" "[url2]" ...
#   - se sha256 existir no catálogo, reutiliza o cache
#   - senão, tenta cada URL até sucesso
#   - registra no catálogo (URL original, SHA, tamanho, mtime, ETag)
fetch::get_file(){
  local sha="$1"; shift
  local name="$1"; shift
  local urls=( "$@" )
  [[ -n "$sha" && -n "$name" && ${#urls[@]} -gt 0 ]] || { log_err "Uso: fetch::get_file <sha256> <name> <url...>"; return 64; }

  fetch::init

  # lock por SHA para evitar duplicidade
  lock::named_acquire "sha:$sha" 0

  # Reutiliza por SHA
  local existing; existing="$(catalog::find_by_sha "$sha" || true)"
  if [[ -n "$existing" && -f "$existing" ]]; then
    log_info "Cache hit por SHA: $sha → $existing"
    echo "$existing"
    lock::named_release "sha:$sha"
    return 0
  fi

  # Reutiliza por URL
  for u in "${urls[@]}"; do
    local p; p="$(catalog::find_by_url "$u" || true)"
    if [[ -n "$p" && -f "$p" ]]; then
      local got; got="$(__sha256_file "$p")"
      if [[ "$got" == "$sha" ]]; then
        log_info "Cache hit por URL: $u → $p"
        echo "$p"; return 0
      fi
    fi
  done

  # Baixa (primeira URL que funcionar)
  local out="$SRC_DIR/$name"
  __ensure_dir "$SRC_DIR" 775; __ensure_dir "$TMP_DIR" 770
  # segurança de caminho
  if ! __safe_in_dir "$SRC_DIR" "$out"; then log_err "Destino fora da raiz do cache: $out"; lock::named_release "sha:$sha"; return 65; fi
  local tmp="$TMP_DIR/$name.tmp.$$"
  __tmp_register "$tmp"
  __check_space "$CACHE_DIR" "$PORTS_MIN_FREE_MB" || { lock::named_release "sha:$sha"; return 75; }

  # lock por nome de saída
  lock::path_acquire "$out" 0

  local ok=0 last_err=0 used_url=""
  for u in "${urls[@]}"; do
    used_url="$u"
    log_step "Baixando: $u"
    if fetch::_curl_one "$u" "$tmp" "$PORTS_FETCH_TIMEOUT" "$PORTS_FETCH_TOTAL_TIMEOUT"; then
      if fetch::verify_sha256 "$tmp" "$sha"; then
        ok=1
        break
      else
        last_err=$?
        log_warn "Descartando arquivo baixado por hash inválido; tentando próximo mirror"
        rm -f -- "$tmp"
      fi
    else
      last_err=$?
      log_warn "Falha ao baixar $u (rc=$last_err); tentando próximo mirror"
      rm -f -- "$tmp" || true
    fi
  done

  if (( ! ok )); then
    lock::path_release "$out"
    log_err "Nenhum mirror atendeu com hash válido para $name"
    return "${last_err:-1}"
  fi

  # Verificação GPG (opcional)
  fetch::verify_gpg_if_enabled "$tmp" "$used_url" || { lock::path_release "$out"; rm -f -- "$tmp"; return 66; }

  # Move atômico para destino final
  mv -f "$tmp" "$out"

  # Meta HTTP (cabeçalhos gravados por _curl_one em $tmp.http; renomeia)
  [[ -f "${tmp}.http" ]] && mv -f "${tmp}.http" "${out}.http" || true

  # Coleta metadados
  local size mtime etag
  size=$(stat -c '%s' "$out" 2>/dev/null || wc -c < "$out")
  mtime="$(date -Is -r "$out" 2>/dev/null || date -Is)"
  etag=$(awk -F': ' 'tolower($1)=="etag"{print $2}' "${out}.http" 2>/dev/null | tail -n1 || true)

  # Registra catálogo
  catalog::_record_file "$used_url" "$out" "$sha" "$size" "$mtime" "$etag"
  event_emit "{\"event\":\"fetch\",\"name\":\"$name\",\"sha256\":\"$sha\",\"url\":\"$used_url\",\"size\":$size}"

  lock::path_release "$out"
  log_ok "Arquivo disponível: $out"
  echo "$out"
}

# =========================
# Paralelismo — lote de downloads
# =========================
# fetch::batch <manifest.tsv>
# TSV por linha: sha256<TAB>name<TAB>url1[|url2|...]
fetch::batch(){
  local tsv="$1"; [[ -f "$tsv" ]] || { log_err "Arquivo não encontrado: $tsv"; return 2; }
  fetch::init
  lock::named_acquire "batch" 0
  log_step "Iniciando batch (concorrência=$PORTS_CACHE_CONCURRENCY)"

  # Worker para xargs -P
  fetch::_worker() {
    local line="$1"
    IFS=$'\t' read -r sha name urls <<<"$line"
    IFS='|' read -r -a arr <<<"$urls"
    fetch::get_file "$sha" "$name" "${arr[@]}" >/dev/null
  }

  export -f fetch::get_file fetch::_curl_one fetch::verify_sha256 fetch::verify_gpg_if_enabled \
            catalog::_record_file catalog::find_by_sha catalog::find_by_url \
            __ensure_dir __sha256_file __ts __sanitize __atomic_write __append_atomic __check_space __safe_in_dir __tmp_register __tmp_cleanup \
            
            log_step log_ok log_info log_warn log_err \
            event_emit lock::init lock::named_acquire lock::named_release lock::path_acquire lock::path_release \
            SRC_DIR TMP_DIR PORTS_FETCH_TIMEOUT PORTS_FETCH_TOTAL_TIMEOUT PORTS_FETCH_RETRIES \
            PORTS_VERIFY_GPG have_gpg have_jq have_b3 CACHE_DIR META_DIR CATALOG_DIR CAT_URL_IDX CAT_SHA_IDX CAT_DB_JSON PORTS_MIN_FREE_MB PORTS_CONFIG_FILE PORTS_REQUIRE_GPG

  # xargs paralelo
  < "$tsv" grep -vE '^\s*$|^\s*#' | xargs -I{} -P "${PORTS_CACHE_CONCURRENCY}" bash -c 'fetch::_worker "$@"' _ {}

  lock::named_release "batch"
  log_ok "Batch finalizado"
}

# =========================
# Git: clone bare cache + export por commit/branch/tag
# =========================
# fetch::git_ensure "<url>" -> cria/atualiza bare em $GIT_DIR
fetch::git_ensure(){
  local url="$1"
  fetch::init
  __ensure_dir "$GIT_DIR" 775
  local name; name="$(__sanitize "$url")"
  local path="$GIT_DIR/$name.git"

  # lock por repo
  lock::path_acquire "$path" 0
  if [[ -d "$path" ]]; then
    log_info "Atualizando bare: $url"
    git -C "$path" remote set-url origin "$url" || true
    git -C "$path" fetch --prune --tags origin +refs/heads/*:refs/heads/* +refs/tags/*:refs/tags/* >/dev/null
  else
    log_step "Clonando bare: $url"
    git clone --mirror --quiet "$url" "$path"
  fi
  lock::path_release "$path"
  echo "$path"
}

# fetch::git_export "<url>" "<ref>" "<dest_dir>"
fetch::git_export(){
  local url="$1" ref="$2" dest="$3"
  [[ -n "$url" && -n "$ref" && -n "$dest" ]] || { log_err "Uso: fetch::git_export <url> <ref> <dest>"; return 64; }
  local bare; bare="$(fetch::git_ensure "$url")"
  __ensure_dir "$dest" 775
  log_step "Exportando $url@$ref → $dest"
  # Usa archive se commit/branch; fallback para worktree
  if git -C "$bare" rev-parse --verify --quiet "$ref^{commit}" >/dev/null; then
    git -C "$bare" archive --format=tar "$ref" | tar -C "$dest" -xf -
  else
    # worktree (refs exóticos)
    local tmp="$TMP_DIR/git-export-$$"
    rm -rf -- "$tmp"; mkdir -p "$tmp"
    git clone --quiet "$bare" "$tmp"
    git -C "$tmp" checkout --quiet "$ref"
    rsync -a --delete "$tmp/" "$dest/"
    rm -rf -- "$tmp"
  fi
  log_ok "Export git OK"
}

# =========================
# Repo de Metafiles: sync (git)
# =========================
# fetch::sync_repo [branch] [remote]
fetch::sync_repo(){
  local branch="${1:-}" remote="${2:-origin}"
  lock::named_acquire "fetch:repo" 0
  [[ -d "$PORTS_REPO_DIR/.git" ]] || { log_err "Diretório não é repositório git: $PORTS_REPO_DIR"; return 2; }
  log_step "Sincronizando repositório de metafiles em $PORTS_REPO_DIR"
  git -C "$PORTS_REPO_DIR" fetch --prune --tags "$remote" >/dev/null
  [[ -n "$branch" ]] && git -C "$PORTS_REPO_DIR" checkout -q "$branch" || true
  git -C "$PORTS_REPO_DIR" pull --rebase "$remote" "$(git -C "$PORTS_REPO_DIR" rev-parse --abbrev-ref HEAD)" >/dev/null || true
  log_ok "Repo sincronizado"
  lock::named_release "fetch:repo"
}

# =========================
# Evicção e limpeza de cache
# =========================
# fetch::prune_files [days]
fetch::prune_files(){
  local days="${1:-90}"
  log_step "Limpando arquivos não acessados há $days dias"
  find "$SRC_DIR" -type f -atime +"$days" -print -delete 2>/dev/null || true
  log_ok "Prune concluído"
}
# fetch::prune_git [days]
fetch::prune_git(){
  local days="${1:-180}"
  log_step "Limpando refs remotas antigas (> $days dias)"
  find "$GIT_DIR" -type d -name '*.git' -print0 2>/dev/null | while IFS= read -r -d '' d; do
    git -C "$d" gc --prune="${days}.days.ago" --quiet || true
  done
  log_ok "GC git concluído"
}
# fetch::purge_cache — apaga tudo (cautela)
fetch::purge_cache(){
  log_warn "Purging de TODO o cache em $CACHE_DIR"
  rm -rf -- "$CACHE_DIR"
  fetch::init
}

# =========================
# CLI (deve ser o último)
# =========================
if [[ "${1:-}" == "cli" ]]; then
  sub="${2:-}"; shift 2 || true
  case "$sub" in
    init) fetch::init ;;
    get-file)
      sha="$1"; name="$2"; shift 2
      fetch::get_file "$sha" "$name" "$@"
      ;;
    batch)
      fetch::batch "$1"
      ;;
    git-ensure)
      fetch::git_ensure "$1"
      ;;
    git-export)
      fetch::git_export "$1" "$2" "$3"
      ;;
    sync-repo)
      fetch::sync_repo "${1:-}" "${2:-origin}"
      ;;
    prune-files)
      fetch::prune_files "${1:-90}"
      ;;
    prune-git)
      fetch::prune_git "${1:-180}"
      ;;
    purge)
      fetch::purge_cache
      ;;
    *) cat <<EOF
Uso: ports-fetch.sh cli <comando> [args]

Comandos:
  init
  get-file <sha256> <name> <url1> [url2|...]
  batch <manifest.tsv>        # sha256<TAB>name<TAB>url1|url2|...
  git-ensure <git_url>
  git-export <git_url> <ref> <dest>
  sync-repo [branch] [remote]
  prune-files [days]
  prune-git [days]
  purge
EOF
      exit 2
      ;;
  esac
  exit $?
fi
