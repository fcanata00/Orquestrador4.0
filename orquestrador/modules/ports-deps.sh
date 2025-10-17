#!/usr/bin/env bash
# Módulo 4 — Gerenciador de Dependências (LFS/BLFS)
# Requisitos: bash>=4.2, coreutils, jq
# Integra: M1 (logs), M2 (locks), M3 (db) — com fallback seguro.
# Sempre verifique hashes antes de rebuild: evita trabalho desnecessário.
# Ative logs detalhados (PORTS_DEBUG=1) para traçar resolução recursiva.
# Integre o selftest no CI local: o script selftest-deps.sh pode ser usado como validação contínua para novos pacotes.
# Use o arquivo cycles.json para bootstrap: ele lista os pacotes que precisam ser construídos manualmente primeiro.
# Tenha política clara para opcionais: opcional ≠ dependência. Só ative quando realmente precisar.
# Mantenha o diretório /usr/ports/repo versionado no git: ajuda a detectar mudanças de dependência via diff.
# Desative rebuild automático durante migração grande: use flag --no-auto-rebuild.
# Sempre rode deps::verify_integrity após atualização de index.json para garantir consistência.
#
set -euo pipefail
########################################
# Configurações
########################################
: "${PORTS_REPO_DIR:=/usr/ports}"                  # raiz do repo de metafiles
: "${PORTS_DB_ROOT:=/var/lib/ports}"               # raiz do DB (M3)
: "${DEPS_CACHE_DIR:=/var/lib/ports/cache/deps}"   # cache do módulo
: "${DEPS_TMP_DIR:=/var/lib/ports/cache/deps/tmp}" # tmp do módulo
: "${DEPS_FEATURES_FILE:=/etc/ports/features.conf}"# features/USE flags (opcional)
: "${DEPS_VIRTUALS_MAP:=/etc/ports/virtuals.map}"  # preferências de providers (opcional)
: "${DEPS_POLICY:=/etc/ports/deps.policy}"         # política do resolvedor (opcional)
# Arquivos de saída/artefatos
DEPS_GRAPH_JSON="$DEPS_CACHE_DIR/graph.json"
DEPS_GRAPH_SHA="$DEPS_GRAPH_JSON.sha256"
DEPS_ORDER_LIST="$DEPS_CACHE_DIR/order.list"
DEPS_ORDER_SHA="$DEPS_ORDER_LIST.sha256"
DEPS_CYCLES_JSON="$DEPS_CACHE_DIR/cycles.json"
DEPS_CYCLES_SHA="$DEPS_CYCLES_JSON.sha256"
DEPS_MISSING_JSON="$DEPS_CACHE_DIR/missing.json"
DEPS_MISSING_SHA="$DEPS_MISSING_JSON.sha256"
DEPS_STATS_JSON="$DEPS_CACHE_DIR/stats.json"
DEPS_META_CACHE="$DEPS_CACHE_DIR/meta"          # cache de parsing por pacote
DEPS_RESOLVED_DIR="$DEPS_CACHE_DIR/resolved"    # resolved/<pkg>.list
DEPS_REBUILD_DIR="$DEPS_CACHE_DIR/rebuild"      # rebuild/<pkg>.list
DEPS_DOT_FILE="$DEPS_CACHE_DIR/graph.dot"       # opcional
DEPS_SVG_FILE="$DEPS_CACHE_DIR/graph.svg"       # opcional
########################################
# Logs (M1) — fallback
########################################
_have_logs=0
if declare -F log::step >/dev/null 2>&1 && declare -F log::ok >/dev/null 2>&1; then _have_logs=1; fi
log_step(){ if ((_have_logs)); then log::step "$@"; else echo "[STAGE] $*"; fi; }
log_ok()  { if ((_have_logs)); then log::ok   "$@"; else echo "[OK] $*"; fi; }
log_info(){ if ((_have_logs)); then log::info "$@"; else echo "[INFO] $*"; fi; }
log_warn(){ if ((_have_logs)); then log::warn "$@"; else echo "[WARN] $*"; fi; }
log_err() { if ((_have_logs)); then log::err  "$@"; else echo "[ERR] $*" >&2; fi; }
########################################
# Locks (M2) — obrigatório
########################################
if ! declare -F lock::init >/dev/null 2>&1; then
  if [[ -f /usr/lib/ports/ports-locks.sh ]]; then
    # shellcheck disable=SC1091
    source /usr/lib/ports/ports-locks.sh
  else
    echo "[FATAL] ports-locks.sh (M2) não encontrado" >&2
    exit 99
  fi
fi
########################################
# DB (M3) — opcional (eventos/consultas)
########################################
_have_db=0
if declare -F db::event >/dev/null 2>&1; then _have_db=1; fi
if declare -F db::is_installed >/dev/null 2>&1; then _have_db=1; fi
event_emit(){ ((_have_db)) && db::event "$1" || true; }
########################################
# Utils
########################################
__ensure_dir(){ install -d -m "${2:-0770}" "$1" 2>/dev/null || install -d "$1"; }
__sha256_file(){ sha256sum "$1" | awk '{print $1}'; }
__ts(){ date -Is; }
__ms(){ perl -MPOSIX -e 'print int(1000*Time::HiRes::time())' 2>/dev/null || date +%s%3N; }
__atomic_write(){
  local dest="$1" tmp="${dest}.tmp.$$"
  __ensure_dir "$(dirname "$dest")" 0770
  cat > "$tmp"
  install -m 0660 "$tmp" "$dest"
  rm -f -- "$tmp"
}
__write_and_hash(){
  local dest="$1" sha="$1.sha256"
  __atomic_write "$dest"
  __sha256_file "$dest" | __atomic_write "$sha"
}
########################################
# Políticas/Features/Virtuals (opcionais)
########################################
declare -A FEATURES VIRTUALS POLICY
deps::load_features(){
  FEATURES=()
  [[ -f "$DEPS_FEATURES_FILE" ]] || return 0
  while IFS='=' read -r k v; do
    [[ -z "${k// }" || "$k" =~ ^# ]] && continue
    v="${v,,}"; FEATURES["$k"]="$v"
  done < <(grep -vE '^\s*(#|$)' "$DEPS_FEATURES_FILE" || true)
}
deps::load_virtuals(){
  VIRTUALS=()
  [[ -f "$DEPS_VIRTUALS_MAP" ]] || return 0
  while IFS='=' read -r k v; do
    [[ -z "${k// }" || "$k" =~ ^# ]] && continue
    VIRTUALS["$k"]="$v"
  done < <(grep -vE '^\s*(#|$)' "$DEPS_VIRTUALS_MAP" || true)
}
deps::load_policy(){
  POLICY=()
  [[ -f "$DEPS_POLICY" ]] || return 0
  while IFS='=' read -r k v; do
    [[ -z "${k// }" || "$k" =~ ^# ]] && continue
    v="${v,,}"; POLICY["$k"]="$v"
  done < <(grep -vE '^\s*(#|$)' "$DEPS_POLICY" || true)
}

########################################
# Inicialização
########################################
deps::init(){
  lock::init
  log_step "Inicializando Gerenciador de Dependências"
  for d in "$DEPS_CACHE_DIR" "$DEPS_TMP_DIR" "$DEPS_META_CACHE" "$DEPS_RESOLVED_DIR" "$DEPS_REBUILD_DIR"; do
    __ensure_dir "$d" 0770
  done
  deps::load_features
  deps::load_virtuals
  deps::load_policy
  log_ok "Módulo de dependências pronto"
}

########################################
# Index de Metafiles
########################################
# Preferência: /usr/ports/repo/index.json
# Fallback: varrer *.metafile e gerar índice simples
deps::scan_index(){
  local index_file="$PORTS_REPO_DIR/repo/index.json"
  local started_ms ended_ms
  started_ms=$(__ms)

  if [[ -f "$index_file" ]]; then
    jq -e . "$index_file" >/dev/null
    log_info "Usando índice existente: $index_file"
  else
    log_warn "repo/index.json não encontrado — varrendo repositório para gerar índice"
    local tmp="${DEPS_TMP_DIR}/index.json.tmp.$$"
    # Varrer metafiles
    mapfile -t files < <(find "$PORTS_REPO_DIR" -type f -name '*.metafile' -print | sort -u)
    {
      echo '['
      local first=1
      for f in "${files[@]}"; do
        local name ver
        name=$(jq -r '.name // empty' "$f" 2>/dev/null || true)
        ver=$(jq -r '.version // empty' "$f" 2>/dev/null || true)
        [[ -z "$name" ]] && { log_warn "Ignorando metafile sem .name: $f"; continue; }
        local sha; sha=$(__sha256_file "$f")
        [[ $first -eq 1 ]] || echo ','
        printf '{"name":%q,"version":%q,"metafile":%q,"sha256":%q}' "$name" "$ver" "$f" "$sha"
        first=0
      done
      echo ']'
    } > "$tmp"
    __atomic_write "$index_file" < "$tmp"
    rm -f -- "$tmp"
    log_ok "Índice gerado: $index_file"
  fi

  # Salvar hash do index para invalidar cache do grafo quando mudar
  local idx_sha="${DEPS_CACHE_DIR}/index.json.sha256"
  __sha256_file "$index_file" | __atomic_write "$idx_sha"

  ended_ms=$(__ms)
  log_info "Index verificado em $((ended_ms-started_ms)) ms"
  echo "$index_file"
}

########################################
# Parse de um metafile (cacheado)
########################################
# Saída JSON normalizada:
# { name, version, requires[], optional[], provides[], conflicts[], virtual[] }
deps::parse_metafile(){
  local metafile="$1" pkg name version out tmp
  [[ -f "$metafile" ]] || { log_err "metafile ausente: $metafile"; return 2; }
  name=$(jq -r '.name // empty' "$metafile")
  version=$(jq -r '.version // empty' "$metafile")
  [[ -n "$name" ]] || { log_err "metafile sem .name: $metafile"; return 2; }
  pkg="$name"

  local cache_json="$DEPS_META_CACHE/${pkg}.json"
  local cache_sha="$cache_json.sha256"
  local cur_sha; cur_sha=$(__sha256_file "$metafile")
  if [[ -f "$cache_json" && -f "$cache_sha" ]] && grep -q "$cur_sha" "$cache_sha" 2>/dev/null; then
    cat "$cache_json"
    return 0
  fi

  # Extrair listas com padrão seguro (vazios → [])
  out=$(jq -c '{
      name: .name,
      version: (.version // ""),
      requires: (.requires // []) | map(tostring),
      optional: (.optional // []) | map(tostring),
      provides: (.provides // []) | map(tostring),
      conflicts: (.conflicts // []) | map(tostring),
      virtual: (.virtual // []) | map(tostring)
    }' "$metafile")

  # Política de opcionais: inclui só se FEATURE=on
  if [[ -f "$DEPS_FEATURES_FILE" ]]; then
    # Filtrar optional[] mantendo apenas os habilitados
    out=$(jq --argfile feats <(
           awk -F= '
             !/^\s*(#|$)/ {
               gsub(/\r/,"",$2);
               printf("{\"k\":\"%s\",\"v\":\"%s\"}\n",$1,$2)
             }' "$DEPS_FEATURES_FILE" | jq -sc '.'
         ) '
      (.optional) as $opt
      | .optional = ($opt | map(select((. as $o | $feats[]? | select(.k==$o and (.v|ascii_downcase)=="on")) != null)))
    ' <<<"$out")
  fi

  # Cacheia resultado + sha do metafile fonte
  __atomic_write "$cache_json" <<<"$out"
  __atomic_write "$cache_sha" <<<"$cur_sha"
  echo "$out"
}

########################################
# Construção do Grafo
########################################
# Produz JSON: { "pkgA": {"requires":["x","y"],"conflicts":["z"],"provides":["a"],"virtual":["mpi"]}, ... }
deps::build_graph(){
  deps::init
  local index; index="$(deps::scan_index)"
  local start_ms; start_ms=$(__ms)

  lock::named_acquire "deps" 0

  local tmp_graph="${DEPS_TMP_DIR}/graph.json.$$"
  echo '{}' > "$tmp_graph"

  # Iterar entradas do índice
  local count=0
  jq -c '.[]' "$index" | while read -r entry; do
    local metafile name meta_json reqs opt prov conf virt
    metafile=$(jq -r '.metafile' <<<"$entry")
    name=$(jq -r '.name' <<<"$entry")
    meta_json=$(deps::parse_metafile "$metafile") || { log_warn "metafile inválido: $metafile"; continue; }

    reqs=$(jq -c '.requires // []' <<<"$meta_json")
    opt=$( jq -c '.optional // []' <<<"$meta_json")
    prov=$(jq -c '.provides // []' <<<"$meta_json")
    conf=$(jq -c '.conflicts // []' <<<"$meta_json")
    virt=$(jq -c '.virtual // []' <<<"$meta_json")

    # Expandir requisitos: requires + opcionais habilitados
    local final_reqs; final_reqs=$(jq -sc '.[0] + .[1]' <(echo "$reqs") <(echo "$opt"))

    # Resolver virtual:xxx → provider preferido, se existir
    local resolved_reqs="$final_reqs"
    if [[ -f "$DEPS_VIRTUALS_MAP" ]]; then
      # Substitui "virtual:mpi" por provider definido
      while IFS='=' read -r vkey vprov; do
        [[ -z "${vkey// }" || "$vkey" =~ ^# ]] && continue
        resolved_reqs=$(jq --arg v "virtual:${vkey}" --arg p "$vprov" '
           map(if . == $v then $p else . end)
        ' <<<"$resolved_reqs")
      done < <(grep -vE '^\s*(#|$)' "$DEPS_VIRTUALS_MAP" || true)
    fi

    # Acumula no grafo
    tmp=$(mktemp -p "$DEPS_TMP_DIR" deps-node-XXXX.json)
    __atomic_write "$tmp" <<<"{
      \"requires\": $resolved_reqs,
      \"conflicts\": $conf,
      \"provides\": $prov,
      \"virtual\": $virt
    }"
    # merge: .[name]=node
    jq --arg k "$name" --slurpfile node "$tmp" '. + {($k): $node[0]}' "$tmp_graph" > "${tmp_graph}.new"
    mv -f "${tmp_graph}.new" "$tmp_graph"
    rm -f -- "$tmp"
    count=$((count+1))
  done

  __write_and_hash "$tmp_graph"
  mv -f "$tmp_graph" "$DEPS_GRAPH_JSON"
  __sha256_file "$DEPS_GRAPH_JSON" | __atomic_write "$DEPS_GRAPH_SHA"

  lock::named_release "deps"

  local elapsed=$(( $(__ms) - start_ms ))
  log_ok "Grafo criado (${count} pacotes) em ${elapsed} ms"
  event_emit "{\"event\":\"deps.build\",\"pkgs\":$count,\"elapsed_ms\":$elapsed,\"ts\":\"$(__ts)\"}"
}

########################################
# Missing & Conflicts
########################################
deps::missing(){
  [[ -f "$DEPS_GRAPH_JSON" ]] || { log_err "Grafo ausente — rode deps::build_graph"; return 2; }
  local missing_json="${DEPS_TMP_DIR}/missing.json.$$"

  # Nome de todos os nós
  local names; names=$(jq -r 'keys[]' "$DEPS_GRAPH_JSON" | sort -u)
  # Conjunto para lookup rápido
  local names_re='^('"$(printf "%s|" $names | sed 's/|$//')"')$'

  # Descobrir requeridos inexistentes (ignorando virtual:xxx sem provider)
  jq -r '
    to_entries[]
    | {pkg: .key, reqs: .value.requires}
    | .reqs[]
    | select(startswith("virtual:") | not)
  ' "$DEPS_GRAPH_JSON" \
  | sort -u \
  | awk -v re="$names_re" '{
      if ($0 ~ re) next;
      print $0;
    }' \
  | jq -R -s 'split("\n") | map(select(length>0)) | {missing: .}' \
  > "$missing_json"

  __write_and_hash "$missing_json"
  mv -f "$missing_json" "$DEPS_MISSING_JSON"
  __sha256_file "$DEPS_MISSING_JSON" | __atomic_write "$DEPS_MISSING_SHA"

  local count; count=$(jq '.missing|length' "$DEPS_MISSING_JSON")
  if (( count > 0 )); then
    log_warn "Dependências ausentes: $count (ver $DEPS_MISSING_JSON)"
  else
    log_ok "Nenhuma dependência ausente"
  fi
}

deps::conflicts_check(){
  [[ -f "$DEPS_GRAPH_JSON" ]] || { log_err "Grafo ausente — rode deps::build_graph"; return 2; }
  # Se dois pacotes que se conflitam aparecem como requeridos simultaneamente,
  # a detecção completa depende do alvo. Aqui fazemos uma verificação global simples:
  local conflicts
  conflicts=$(jq -c '
    to_entries[]
    | select(.value.conflicts|length>0)
    | {pkg:.key, conflicts:.value.conflicts}
  ' "$DEPS_GRAPH_JSON" || true)
  if [[ -n "$conflicts" ]]; then
    while read -r row; do
      local pkg; pkg=$(jq -r '.pkg' <<<"$row")
      local arr; arr=$(jq -c '.conflicts' <<<"$row")
      log_info "Conflitos declarados por $pkg: $(jq -r '.[]' <<<"$arr" | xargs echo)"
    done <<<"$conflicts"
  fi
}

########################################
# Ciclos (Tarjan simplificado via DFS com pilha)
########################################
deps::detect_cycles(){
  [[ -f "$DEPS_GRAPH_JSON" ]] || { log_err "Grafo ausente — rode deps::build_graph"; return 2; }
  local tmp="${DEPS_TMP_DIR}/cycles.json.$$"
  # Vamos fazer DFS em Bash usando jq para obter adjacências.
  # Estados: 0=unvisited, 1=visiting, 2=done
  local -A state parent
  local -a stack cycles
  cycles=()

  mapfile -t nodes < <(jq -r 'keys[]' "$DEPS_GRAPH_JSON" | sort)

  _neighbors(){ jq -r --arg n "$1" '.[$n].requires[]? // empty' "$DEPS_GRAPH_JSON" 2>/dev/null || true; }

  _dfs(){
    local v="$1"; state["$v"]=1; stack+=("$v")
    local u
    while IFS= read -r u; do
      [[ -z "$u" ]] && continue
      # ignorar virtuais sem provider
      [[ "$u" == virtual:* ]] && continue
      if [[ -z "${state[$u]:-}" || "${state[$u]}" -eq 0 ]]; then
        parent["$u"]="$v"
        _dfs "$u"
      elif [[ "${state[$u]}" -eq 1 ]]; then
        # ciclo encontrado: reconstruir caminho u..v
        local cyc=("$u")
        local x="$v"
        while [[ -n "$x" && "$x" != "$u" ]]; do
          cyc+=("$x"); x="${parent[$x]:-}"
        done
        cyc+=("$u")
        cycles+=("$(printf '%s ' "${cyc[@]}")")
      fi
    done < <(_neighbors "$v")
    state["$v"]=2
    # pop stack
    unset 'stack[${#stack[@]}-1]'
  }

  for n in "${nodes[@]}"; do state["$n"]=0; done
  for n in "${nodes[@]}"; do
    [[ "${state[$n]}" -eq 0 ]] && _dfs "$n"
  done

  {
    echo '{ "cycles": ['
    local first=1
    for c in "${cycles[@]}"; do
      [[ $first -eq 1 ]] || echo ','
      # normaliza espaço -> array JSON
      awk '{printf("["); for(i=1;i<=NF;i++){printf("%s%q", (i>1?",":""), $i)}; printf("]")}' <<<"$c"
      first=0
    done
    echo ']}'
  } > "$tmp"

  __write_and_hash "$tmp"
  mv -f "$tmp" "$DEPS_CYCLES_JSON"
  __sha256_file "$DEPS_CYCLES_JSON" | __atomic_write "$DEPS_CYCLES_SHA"

  local ncyc; ncyc=$(jq '.cycles|length' "$DEPS_CYCLES_JSON")
  if (( ncyc > 0 )); then
    log_err "Ciclos detectados ($ncyc) — ver $DEPS_CYCLES_JSON"
  else
    log_ok "Nenhum ciclo detectado"
  fi
}

########################################
# Toposort (Kahn determinístico)
########################################
deps::toposort(){
  [[ -f "$DEPS_GRAPH_JSON" ]] || { log_err "Grafo ausente — rode deps::build_graph"; return 2; }
  local tmp="${DEPS_TMP_DIR}/order.list.$$"
  # in-degree
  # Produz: pkg \t indegree
  local indeg; indeg=$(jq -r '
    . as $G
    | [ keys[] as $k | {k:$k, v: ([$G[$k].requires[]? | select(startswith("virtual:") | not)] // [])} ]
    | (map(.k) | unique) as $N
    | $N as $all
    | $N
    | map({key: ., value: 0}) | from_entries
    | . as $D
    | reduce (to_entries[]) as $e (
        $D;
        reduce ($e.value.v[]) as $r (.;
          if has($r) then .[$r] += 1 else . end
        )
      )
    | to_entries[]
    | "\(.key)\t\(.value)"
  ' "$DEPS_GRAPH_JSON")

  # Ler indegree para arrays/assocs
  declare -A indegree
  declare -A adj
  declare -a queue order

  while IFS=$'\t' read -r k v; do
    indegree["$k"]="$v"
  done <<< "$indeg"

  # Adjacências: u -> [v...]
  while read -r k; do
    local neigh
    neigh=$(jq -r --arg k "$k" '.[$k].requires[]? // empty' "$DEPS_GRAPH_JSON" | grep -v '^virtual:' || true)
    adj["$k"]="$neigh"
  done < <(jq -r 'keys[]' "$DEPS_GRAPH_JSON" | sort)

  # Queue inicial: nós com indegree=0 (ordenado)
  mapfile -t queue < <(for k in "${!indegree[@]}"; do
    if [[ "${indegree[$k]}" -eq 0 ]]; then echo "$k"; fi
  done | sort)

  while ((${#queue[@]})); do
    local n="${queue[0]}"
    queue=("${queue[@]:1}")
    order+=("$n")
    # reduzir indegree dos vizinhos
    while read -r v; do
      [[ -z "$v" ]] && continue
      local d=$(( indegree["$v"] - 1 ))
      indegree["$v"]="$d"
      if (( d == 0 )); then
        queue+=("$v")
        # manter determinismo
        IFS=$'\n' queue=($(printf "%s\n" "${queue[@]}" | sort))
      fi
    done <<< "${adj[$n]}"
  done

  # Verificar se todos foram ordenados (se não, há ciclo)
  local total_nodes; total_nodes=$(jq 'keys|length' "$DEPS_GRAPH_JSON")
  if ((${#order[@]} != total_nodes)); then
    log_err "Toposort incompleto (${\#order[@]}/$total_nodes) — verifique ciclos"
  fi

  printf "%s\n" "${order[@]}" > "$tmp"
  __write_and_hash "$tmp"
  mv -f "$tmp" "$DEPS_ORDER_LIST"
  __sha256_file "$DEPS_ORDER_LIST" | __atomic_write "$DEPS_ORDER_SHA"

  log_ok "Ordem topológica salva em $DEPS_ORDER_LIST"
}

########################################
# Resolve (recursivo) e Reverse Deps
########################################
deps::resolve(){
  local target="$1"
  [[ -f "$DEPS_GRAPH_JSON" ]] || { log_err "Grafo ausente"; return 2; }
  [[ -n "$target" ]] || { log_err "Uso: deps::resolve <pkg>"; return 64; }

  declare -A seen
  declare -a out
  _res(){
    local x="$1"
    [[ -n "${seen[$x]:-}" ]] && return 0
    seen["$x"]=1
    local r
    r=$(jq -r --arg x "$x" '.[$x].requires[]? // empty' "$DEPS_GRAPH_JSON" 2>/dev/null || true)
    while read -r d; do
      [[ -z "$d" || "$d" == virtual:* ]] && continue
      _res "$d"
    done <<<"$r"
    out+=("$x")
  }
  _res "$target"

  local file="$DEPS_RESOLVED_DIR/${target}.list"
  printf "%s\n" "${out[@]}" | awk 'NF' | sort -u > "${file}.tmp"
  __write_and_hash "${file}.tmp"
  mv -f "${file}.tmp" "$file"
  log_ok "Dependências resolvidas para $target → $file"
  printf "%s\n" "${out[@]}"
}

deps::reverse_deps(){
  local pkg="$1"
  [[ -f "$DEPS_GRAPH_JSON" ]] || { log_err "Grafo ausente"; return 2; }
  [[ -n "$pkg" ]] || { log_err "Uso: deps::reverse_deps <pkg>"; return 64; }

  jq -r --arg p "$pkg" '
    to_entries[]
    | select(.value.requires[]? == $p)
    | .key
  ' "$DEPS_GRAPH_JSON" | sort -u
}

deps::needed_for_rebuild(){
  local pkg="$1"
  [[ -n "$pkg" ]] || { log_err "Uso: deps::needed_for_rebuild <pkg>"; return 64; }
  [[ -f "$DEPS_GRAPH_JSON" ]] || { log_err "Grafo ausente"; return 2; }

  declare -A seen
  declare -a queue out
  queue=("$pkg")
  while ((${#queue[@]})); do
    local x="${queue[0]}"; queue=("${queue[@]:1}")
    while read -r d; do
      [[ -z "$d" ]] && continue
      if [[ -z "${seen[$d]:-}" ]]; then
        seen["$d"]=1
        out+=("$d")
        queue+=("$d")
      fi
    done < <(deps::reverse_deps "$x")
  done

  local file="$DEPS_REBUILD_DIR/${pkg}.list"
  printf "%s\n" "${out[@]}" | awk 'NF' | sort -u > "${file}.tmp"
  __write_and_hash "${file}.tmp"
  mv -f "${file}.tmp" "$file"
  log_ok "Rebuild impact para $pkg: ${#out[@]} pacotes (lista em $file)"
  printf "%s\n" "${out[@]}"
}

########################################
# Export, Verify, Stats
########################################
deps::verify_integrity(){
  local ok=1
  for f in "$DEPS_GRAPH_JSON" "$DEPS_ORDER_LIST" "$DEPS_CYCLES_JSON" "$DEPS_MISSING_JSON"; do
    [[ -f "$f" && -f "$f.sha256" ]] || { log_warn "Ausente: $f (ou .sha256)"; ok=0; continue; }
    local a b; a=$(__sha256_file "$f"); b=$(cat "$f.sha256")
    if [[ "$a" != "$b" ]]; then
      log_warn "Hash divergente: $f"
      ok=0
    fi
  done
  (( ok )) && log_ok "Integridade OK" || log_warn "Integridade falhou (cache será reconstruído conforme necessário)"
  return $(( ok ? 0 : 1 ))
}

deps::stats(){
  local pkgs edges cycles missing elapsed_ms mem_kb
  pkgs=$(jq 'keys|length' "$DEPS_GRAPH_JSON" 2>/dev/null || echo 0)
  edges=$(jq '[to_entries[]|.value.requires|length]|add' "$DEPS_GRAPH_JSON" 2>/dev/null || echo 0)
  cycles=$(jq '.cycles|length' "$DEPS_CYCLES_JSON" 2>/dev/null || echo 0)
  missing=$(jq '.missing|length' "$DEPS_MISSING_JSON" 2>/dev/null || echo 0)
  elapsed_ms="${1:-0}"
  mem_kb=$(grep -E '^MemTotal:' /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
  jq -nc --argjson pk "$pkgs" --argjson ed "$edges" --argjson cy "$cycles" \
        --argjson mi "$missing" --argjson ms "$elapsed_ms" --arg ts "$(__ts)" \
        --argjson mem "$mem_kb" \
        '{packages:$pk,edges:$ed,cycles:$cy,missing:$mi,elapsed_ms:$ms,mem_kb:$mem,timestamp:$ts}' \
    | __atomic_write "$DEPS_STATS_JSON"
  log_info "Stats: pkgs=$pkgs edges=$edges cycles=$cycles missing=$missing elapsed=${elapsed_ms}ms"
}

########################################
# Pipeline completo: build → missing → cycles → toposort → stats
########################################
deps::recompute_all(){
  local t0 t1
  t0=$(__ms)
  deps::build_graph
  deps::missing
  deps::detect_cycles
  deps::toposort
  t1=$(__ms)
  deps::stats $((t1 - t0))
  event_emit "{\"event\":\"deps.verify\",\"elapsed_ms\":$((t1-t0)),\"ts\":\"$(__ts)\"}"
}

########################################
# (Opcional) Export DOT/SVG
########################################
deps::export_graphviz(){
  [[ -f "$DEPS_GRAPH_JSON" ]] || { log_err "Grafo ausente"; return 2; }
  local tmp="$DEPS_TMP_DIR/graph.dot.$$"
  {
    echo 'digraph deps {'
    echo '  rankdir=LR;'
    jq -r '
      to_entries[]
      | .key as $k
      | .value.requires[]? as $r
      | select(($r|startswith("virtual:"))|not)
      | "  \"" + $k + "\" -> \"" + $r + "\";"
    ' "$DEPS_GRAPH_JSON" || true
    echo '}'
  } > "$tmp"
  mv -f "$tmp" "$DEPS_DOT_FILE"
  if command -v dot >/dev/null 2>&1; then
    dot -Tsvg "$DEPS_DOT_FILE" -o "$DEPS_SVG_FILE" || true
  fi
  log_ok "Graphviz exportado em $DEPS_DOT_FILE${DEPS_SVG_FILE:+, $DEPS_SVG_FILE}"
}
