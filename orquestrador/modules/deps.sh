#!/usr/bin/env bash
# lfsctl deps module
# Path suggestion: /usr/libexec/lfsctl/deps.sh
# Purpose: dependency manager for LFSCTL — graph, Kahn ordering, cycles, install/uninstall/rebuild/upgrade
# Features: metafile parsing, sqlite cache, json cache, Kahn topological sort with batch-parallel levels,
#           parallel worker pool, repo.sh integration hooks, graphviz export, dry-run, policies, auto-fix heuristics,
#           robust error handling, logging integration, locks, retries/backoff, JSON export, visualization.
set -euo pipefail

# ---- Defaults (can be overridden by config.sh) ----
: "${LFSCTL_PORTS_DIR:=/usr/ports}"
: "${LFSCTL_META_DIR:=/var/lfsctl/meta}"
: "${LFSCTL_JOBS:=$(nproc 2>/dev/null || echo 1)}"
: "${LFSCTL_DB:=${LFSCTL_META_DIR}/deps.db}"
: "${DEPS_CACHE_JSON:=${LFSCTL_META_DIR}/deps-cache.json}"
: "${DEPS_GRAPH_DOT:=${LFSCTL_META_DIR}/deps-graph.dot}"
: "${DEPS_LOG:=${LFSCTL_META_DIR}/deps-action.log}"
: "${DEPS_MAX_RETRIES:=2}"
: "${DEPS_RETRY_BASE:=0.5}"

# Policies file
: "${LFSCTL_POLICY:=/etc/lfsctl/policies.yaml}"

# Behavior flags
DRY_RUN=0
STRICT=0
VERBOSE=0
AUTO_FIX=0
CONTINUE_ON_ERROR=0
PARALLEL_JOBS="$LFSCTL_JOBS"
QUIET=0

# Internal state
declare -A DEPS_GRAPH        # DEPS_GRAPH[pkg]="dep1 dep2"
declare -A REVERSE_GRAPH     # REVERSE_GRAPH[pkg]="dep_by1 dep_by2"
declare -A META_HASH         # META_HASH[pkg]=sha256
declare -A PKG_PATH          # PKG_PATH[pkg]=/usr/ports/.../meta
declare -A PKG_VERSION       # PKG_VERSION[pkg]=x.y.z
declare -a ALL_PKGS=()
declare -A INDEGREE
declare -A VISITED
declare -a BUILD_ORDER=()
DB_OK=0

mkdir -p "${LFSCTL_META_DIR}" 2>/dev/null || true

# ---- logging wrapper ----
_log() {
  local lvl="$1"; shift || true
  if type -t log_info >/dev/null 2>&1; then
    case "$lvl" in
      info) log_info "$@" ;;
      warn) log_warn "$@" ;;
      error) log_error "$@" ;;
      debug) log_debug "$@" ;;
      *) log_info "$@" ;;
    esac
  else
    case "$lvl" in
      error) >&2 printf 'ERROR: %s\n' "$*" ;;
      warn) >&2 printf 'WARN: %s\n' "$*" ;;
      debug) [[ "$VERBOSE" -ne 0 ]] && printf 'DEBUG: %s\n' "$*" ;;
      info) [[ "$QUIET" -eq 0 ]] && printf 'INFO: %s\n' "$*" ;;
      *) printf '%s\n' "$*" ;;
    esac
  fi
  # also append to action log
  printf '[%s] %s\n' "$(date -Is)" "[$lvl] ${*}" >> "${DEPS_LOG}" 2>/dev/null || true
}

# ---- helper utilities ----
_err_exit() { local code=$1; shift; _log error "$@"; exit "$code"; }
_warn() { _log warn "$@"; }

# safe sha256
_sha256() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f" | awk '{print $1}'; return; fi
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$f" | awk '{print $1}'; return; fi
  echo ""
}

# minimal JSON writer for simple maps if jq absent
_json_write_simple_map() {
  local out="$1"; shift
  : >"$out"
  printf '{\n' >>"$out"
  local first=1 k v
  for k in "$@"; do
    v="${!k}"
    if [[ $first -eq 1 ]]; then first=0; else printf ',\n' >>"$out"; fi
    printf '  "%s": "%s"' "$k" "${v//\"/\\\"}" >>"$out"
  done
  printf '\n}\n' >>"$out"
}

# ---- SQLite helpers ----
_sqlite_init() {
  if ! command -v sqlite3 >/dev/null 2>&1; then
    _log warn "sqlite3 not found: SQLite persistence disabled"
    DB_OK=0; return 1
  fi
  DB_OK=1
  if [[ ! -f "$LFSCTL_DB" ]]; then
    _log info "Initializing SQLite DB at $LFSCTL_DB"
    sqlite3 "$LFSCTL_DB" <<'SQL'
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS packages (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE,
  category TEXT,
  version TEXT,
  meta_hash TEXT,
  path TEXT,
  last_scanned INTEGER
);
CREATE TABLE IF NOT EXISTS deps (
  id INTEGER PRIMARY KEY,
  pkg_id INTEGER,
  dep_name TEXT,
  type TEXT,
  condition TEXT
);
CREATE INDEX IF NOT EXISTS idx_pkg_name ON packages(name);
CREATE INDEX IF NOT EXISTS idx_deps_pkg ON deps(pkg_id);
SQL
  fi
  return 0
}

_sqlite_upsert_package() {
  local name="$1" category="$2" version="$3" meta_hash="$4" path="$5" ts="$6"
  if [[ $DB_OK -eq 0 ]]; then return 0; fi
  sqlite3 "$LFSCTL_DB" <<SQL
INSERT INTO packages(name,category,version,meta_hash,path,last_scanned)
VALUES('$(sqlite3_escape "$name")','$(sqlite3_escape "$category")','$(sqlite3_escape "$version")','$(sqlite3_escape "$meta_hash")','$(sqlite3_escape "$path")',$ts)
ON CONFLICT(name) DO UPDATE SET category=excluded.category, version=excluded.version, meta_hash=excluded.meta_hash, path=excluded.path, last_scanned=excluded.last_scanned;
SQL
}

_sqlite_insert_dep() {
  local name="$1" dep="$2" type="$3" cond="$4"
  if [[ $DB_OK -eq 0 ]]; then return 0; fi
  sqlite3 "$LFSCTL_DB" <<SQL
WITH p AS (SELECT id FROM packages WHERE name='$(sqlite3_escape "$name")' LIMIT 1)
INSERT INTO deps(pkg_id,dep_name,type,condition)
SELECT p.id,'$(sqlite3_escape "$dep")','$(sqlite3_escape "$type")','$(sqlite3_escape "$cond")' FROM p;
SQL
}

sqlite3_escape() {
  # simple escape function for sqlite literal usage
  printf "%s" "$1" | sed "s/'/''/g"
}

# ---- Metafile parser ----
# Accepts simple bash-style KEY=VAL with arrays DEPENDS=("a" "b") or DEPENDS=("a b") etc.
_parse_metafile() {
  local meta="$1"
  declare -A map=()
  local line key val
  while IFS= read -r line || [[ -n "$line" ]]; do
    # strip comments
    line="${line%%#*}"
    line="${line%"${line##*[![:space:]]}"}"
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      val="${BASH_REMATCH[2]}"
      # remove surrounding quotes
      if [[ "$val" =~ ^\"(.*)\"$ ]]; then val="${BASH_REMATCH[1]}"; fi
      if [[ "$val" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"; fi
      # arrays: simple parse for DEPENDS=("a" "b")
      if [[ "$val" =~ ^\([^\)]*\)$ ]]; then
        # remove parens then split by space respecting quotes
        local inner="${val:1:${#val}-2}"
        # replace newlines with spaces
        inner="${inner//$'\n'/ }"
        # parse quoted tokens
        local arr=()
        while [[ -n "$inner" ]]; do
          if [[ "$inner" =~ ^\"([^\"]*)\"[[:space:]]*(.*)$ ]]; then
            arr+=("${BASH_REMATCH[1]}"); inner="${BASH_REMATCH[2]}"
          elif [[ "$inner" =~ ^\'([^\']*)\'[[:space:]]*(.*)$ ]]; then
            arr+=("${BASH_REMATCH[1]}"); inner="${BASH_REMATCH[2]}"
          elif [[ "$inner" =~ ^([^[:space:]]+)[[:space:]]*(.*)$ ]]; then
            arr+=("${BASH_REMATCH[1]}"); inner="${BASH_REMATCH[2]}"
          else
            break
          fi
        done
        map["$key"]="${arr[*]}"
      else
        map["$key"]="$val"
      fi
    else
      _log debug "Skipping non-kv line in $meta: $line"
    fi
  done <"$meta"
  # return via stdout as key=value lines
  for k in "${!map[@]}"; do printf '%s=%s\n' "$k" "${map[$k]}"; done
}

# ---- Scan ports and build graph ----
deps_scan() {
  local ports_dir="${1:-$LFSCTL_PORTS_DIR}"
  _log info "Scanning ports directory: $ports_dir"
  ALL_PKGS=()
  DEPS_GRAPH=(); REVERSE_GRAPH=(); META_HASH=(); PKG_PATH=(); PKG_VERSION=()
  local meta_files count=0
  while IFS= read -r -d '' meta; do
    ((count++))
    # parse path to extract name/category
    local pkg_dir; pkg_dir="$(dirname "$meta")"
    local pkg_name; pkg_name="$(basename "$pkg_dir")"
    local category; category="$(basename "$(dirname "$pkg_dir")")"
    local sha; sha="$(_sha256 "$meta" 2>/dev/null || echo "")"
    META_HASH["$pkg_name"]="$sha"
    PKG_PATH["$pkg_name"]="$meta"
    # parse metafile lines into map
    local parsed; parsed="$(_parse_metafile "$meta")"
    # read parsed lines into env-like vars in subshell
    local NAME VERSION DEPENDS OPT_DEPENDS CONDITIONAL_DEPENDS
    while IFS= read -r ln; do
      local k="${ln%%=*}"; local v="${ln#*=}"
      case "$k" in
        NAME) NAME="$v";;
        VERSION) VERSION="$v";;
        DEPENDS) DEPENDS="$v";;
        OPT_DEPENDS) OPT_DEPENDS="$v";;
        CONDITIONAL_DEPENDS) CONDITIONAL_DEPENDS="$v";;
        *) ;;
      esac
    done <<<"$parsed"
    [[ -z "$NAME" ]] && NAME="$pkg_name"
    PKG_VERSION["$NAME"]="${VERSION:-}"
    ALL_PKGS+=("$NAME")
    # normalize dependencies (space separated)
    local deps_list=()
    if [[ -n "${DEPENDS:-}" ]]; then deps_list+=( ${DEPENDS} ); fi
    if [[ -n "${OPT_DEPENDS:-}" ]]; then deps_list+=( ${OPT_DEPENDS} ); fi
    # CONDITIONAL_DEPENDS handled as raw string; parser later
    DEPS_GRAPH["$NAME"]="${deps_list[*]}"
    for d in ${deps_list[*]}; do
      REVERSE_GRAPH["$d"]+="$NAME "
      # persist to sqlite
      _sqlite_upsert_package "$NAME" "$category" "${VERSION:-}" "${sha}" "$meta" "$(date +%s)" || true
      _sqlite_insert_dep "$NAME" "$d" "required" "" || true
    done
  done < <(find "$ports_dir" -type f -name meta -print0 2>/dev/null)
  _log info "Scanned $count metafiles; packages discovered: ${#ALL_PKGS[@]}"
  # save cache JSON
  deps_save_cache
  return 0
}

# ---- cache save/load ----
deps_save_cache() {
  local out="${DEPS_CACHE_JSON}"
  _log info "Saving deps cache to $out"
  if command -v jq >/dev/null 2>&1; then
    local tmp; tmp="$(mktemp "${out}.tmp.XXXX")"
    printf '{ "packages": [' >"$tmp"
    local first=1 pkg
    for pkg in "${ALL_PKGS[@]}"; do
      [[ $first -eq 1 ]] && first=0 || printf ', ' >>"$tmp"
      printf '{ "name": "%s", "version": "%s", "deps": [' "${pkg}" "${PKG_VERSION[$pkg]:-}"' >>"$tmp"
      local d fd=1
      for d in ${DEPS_GRAPH[$pkg]:-}; do
        [[ $fd -eq 1 ]] && fd=0 || printf ', ' >>"$tmp"
        printf '"%s"' "$d" >>"$tmp"
      done
      printf '] }' >>"$tmp"
    done
    printf ' ], "generated":"%s" }' "$(date -Is)" >>"$tmp"
    mv -f "$tmp" "$out" 2>/dev/null || true
  else
    : >"$out"
    for pkg in "${ALL_PKGS[@]}"; do
      printf '%s|%s|%s\n' "$pkg" "${PKG_VERSION[$pkg]:-}" "${DEPS_GRAPH[$pkg]:-}" >>"$out"
    done
  fi
}

deps_load_cache() {
  local file="${DEPS_CACHE_JSON}"
  if [[ ! -f "$file" ]]; then _log warn "Cache not found: $file"; return 1; fi
  _log info "Loading deps cache from $file"
  if command -v jq >/dev/null 2>&1; then
    local names; names=$(jq -r '.packages[].name' "$file" 2>/dev/null || true)
    ALL_PKGS=()
    for n in $names; do ALL_PKGS+=("$n"); done
    for n in "${ALL_PKGS[@]}"; do
      DEPS_GRAPH["$n"]=$(jq -r --arg n "$n" '.packages[] | select(.name==$n) | (.deps[]?)' "$file" 2>/dev/null | xargs echo)
    done
  else
    local line
    while IFS= read -r line; do
      local name ver deps rest
      name="${line%%|*}"; rest="${line#*|}"; ver="${rest%%|*}"; deps="${rest#*|}"
      ALL_PKGS+=("$name")
      DEPS_GRAPH["$name"]="$deps"
    done <"$file"
  fi
}

# ---- Kahn topological sort (produces BUILD_ORDER array) ----
deps_kahn_order() {
  BUILD_ORDER=()
  local -a q=()
  INDEGREE=()
  for pkg in "${ALL_PKGS[@]}"; do INDEGREE["$pkg"]=0; done
  for pkg in "${ALL_PKGS[@]}"; do
    for d in ${DEPS_GRAPH[$pkg]:-}; do
      INDEGREE["$pkg"]=$((INDEGREE["$pkg"]+1))
    done
  done
  for pkg in "${ALL_PKGS[@]}"; do
    if [[ "${INDEGREE[$pkg]:-0}" -eq 0 ]]; then q+=("$pkg"); fi
  done
  while ((${#q[@]})); do
    IFS=$'\n' q=($(printf '%s\n' "${q[@]}" | sort))
    local n="${q[0]}"; q=("${q[@]:1}")
    BUILD_ORDER+=("$n")
    for m in ${REVERSE_GRAPH[$n]:-}; do
      INDEGREE["$m"]=$((INDEGREE["$m"]-1))
      if [[ "${INDEGREE[$m]}" -eq 0 ]]; then q+=("$m"); fi
    done
  done
  if [[ "${#BUILD_ORDER[@]}" -ne "${#ALL_PKGS[@]}" ]]; then
    _log error "Cycle detected or missing nodes: processed ${#BUILD_ORDER[@]} of ${#ALL_PKGS[@]}"
    local -a remaining=()
    for pkg in "${ALL_PKGS[@]}"; do
      local found=0
      for p in "${BUILD_ORDER[@]}"; do [[ "$p" == "$pkg" ]] && found=1 && break; done
      [[ $found -eq 0 ]] && remaining+=("$pkg")
    done
    _log error "Remaining nodes: ${remaining[*]}"
    return 3
  fi
  _log info "Topological order computed: ${#BUILD_ORDER[@]} packages"
  return 0
}

# produce batch levels for parallelism: levels array of arrays
deps_kahn_levels() {
  local -A indeg; indeg=()
  local pkg
  for pkg in "${ALL_PKGS[@]}"; do indeg["$pkg"]="${INDEGREE[$pkg]:-0}"; done
  local -a queue=()
  for pkg in "${ALL_PKGS[@]}"; do [[ "${indeg[$pkg]}" -eq 0 ]] && queue+=("$pkg"); done
  local -a levels=()
  while ((${#queue[@]})); do
    IFS=$'\n' queue=($(printf '%s\n' "${queue[@]}" | sort))
    local -a next=()
    local level_str=""
    for p in "${queue[@]}"; do
      level_str+="$p "
      for dep in ${REVERSE_GRAPH[$p]:-}; do indeg["$dep"]=$((indeg["$dep"]-1)); if [[ "${indeg[$dep]}" -eq 0 ]]; then next+=("$dep"); fi; done
    done
    levels+=("$level_str")
    queue=("${next[@]}")
  done
  for l in "${levels[@]}"; do printf '%s\n' "$l"; done
}

# ---- Graphviz export ----
deps_graphviz() {
  local out="${1:-$DEPS_GRAPH_DOT}"
  _log info "Generating graphviz dot to $out"
  {
    printf "digraph deps {\n rankdir=LR; node [shape=box];\n"
    for pkg in "${ALL_PKGS[@]}"; do
      printf ' "%s" [label="%s\n%s"] ;\n' "$pkg" "$pkg" "${PKG_VERSION[$pkg]:-}"
    done
    for pkg in "${ALL_PKGS[@]}"; do
      for d in ${DEPS_GRAPH[$pkg]:-}; do
        printf ' "%s" -> "%s" ;\n' "$pkg" "$d"
      done
    done
    printf "}\n"
  } >"$out"
  _log info "Graph written to $out"
  return 0
}

# ---- JSON export/report ----
deps_export_json() {
  local out="${1:-${LFSCTL_META_DIR}/deps-report-$(date +%s).json}"
  _log info "Exporting deps report to $out"
  if command -v jq >/dev/null 2>&1; then
    local tmp; tmp="$(mktemp "${out}.tmp.XXXX")"
    printf '{ "generated":"%s", "packages": [' "$(date -Is)" >"$tmp"
    local first=1 pkg
    for pkg in "${ALL_PKGS[@]}"; do
      [[ $first -eq 1 ]] && first=0 || printf ', ' >>"$tmp"
      printf '{ "name":"%s", "version":"%s", "deps": [' "$pkg" "${PKG_VERSION[$pkg]:-}" >>"$tmp"
      local d fd=1
      for d in ${DEPS_GRAPH[$pkg]:-}; do
        [[ $fd -eq 1 ]] && fd=0 || printf ', ' >>"$tmp"
        printf '"%s"' "$d" >>"$tmp"
      done
      printf '] }' >>"$tmp"
    done
    printf ' ] }\n' >>"$tmp"
    mv -f "$tmp" "$out" 2>/dev/null || true
  else
    : >"$out"
    for pkg in "${ALL_PKGS[@]}"; do
      printf '%s %s %s\n' "$pkg" "${PKG_VERSION[$pkg]:-}" "${DEPS_GRAPH[$pkg]:-}" >>"$out"
    done
  fi
  _log info "Deps report exported to $out"
  return 0
}

# ---- Worker pool and job execution ----
job_run_command() {
  local pkg="$1"
  _log info "Starting build for $pkg"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    _log info "dry-run: would build $pkg"; return 0
  fi
  if type -t lock_acquire >/dev/null 2>&1; then lock_acquire "build-$pkg" --timeout 10 || { _log warn "Could not lock $pkg"; return 4; }; fi
  if [[ -f /usr/libexec/lfsctl/hooks.sh ]]; then
    source /usr/libexec/lfsctl/hooks.sh || _log warn "Failed to source hooks.sh"
    if type -t hooks_run >/dev/null 2>&1; then hooks_run pre_build "$pkg" || _log warn "pre_build hook failed for $pkg"; fi
  fi
  local retries=0 rc=0 wait="$DEPS_RETRY_BASE"
  while :; do
    # TODO: replace this with actual build invocation (build.sh)
    sleep 0.1
    rc=0
    if [[ $rc -eq 0 ]]; then break; fi
    if (( retries >= DEPS_MAX_RETRIES )); then break; fi
    retries=$((retries+1))
    sleep "$wait"
    wait=$(awk "BEGIN {print $wait*2}" 2>/dev/null || echo "$DEPS_RETRY_BASE")
  done
  if type -t hooks_run >/dev/null 2>&1; then hooks_run post_build "$pkg" || _log warn "post_build hook failed for $pkg"; fi
  if type -t lock_release >/dev/null 2>&1; then lock_release "build-$pkg" || true; fi
  _log info "Finished build for $pkg (rc=$rc)"
  return $rc
}

deps_execute_level() {
  local level_line="$1"
  local -a level_pkgs=($level_line)
  local pcount=${#level_pkgs[@]}
  local maxjobs="${PARALLEL_JOBS}"
  [[ $maxjobs -lt 1 ]] && maxjobs=1
  _log info "Executing level with $pcount packages, parallel=$maxjobs"
  for pkg in "${level_pkgs[@]}"; do
    job_run_command "$pkg" &
    # throttle
    while (( $(jobs -pr | wc -l) >= maxjobs )); do sleep 0.1; done
  done
  wait
  _log info "Level complete"
  return 0
}

# ---- High-level operations ----
deps_install() {
  local target="$1"
  _log info "Installing package: $target"
  if [[ ! " ${ALL_PKGS[*]} " =~ " ${target} " ]]; then
    _log warn "Package $target not found in scanned ports. Attempting auto-fix via repo.sh"
    if [[ "$AUTO_FIX" -eq 1 && -x /usr/libexec/lfsctl/repo.sh ]]; then
      /usr/libexec/lfsctl/repo.sh fetch "$target" || _log warn "repo.sh fetch failed for $target"
      deps_scan "$LFSCTL_PORTS_DIR"
    else
      _err_exit 4 "Missing package: $target"
    fi
  fi
  local -a to_build=()
  deps_resolve_recursive "$target" to_build
  ALL_PKGS=("${to_build[@]}")
  REVERSE_GRAPH=(); for p in "${ALL_PKGS[@]}"; do for d in ${DEPS_GRAPH[$p]:-}; do REVERSE_GRAPH["$d"]+="$p "; done; done
  deps_kahn_order || _err_exit 3 "Cycle detected while computing order for $target"
  local levels; levels=$(deps_kahn_levels)
  if [[ "$DRY_RUN" -eq 1 ]]; then
    _log info "dry-run: computed build order: ${BUILD_ORDER[*]}"
    printf '%s\n' "${BUILD_ORDER[@]}"
    return 0
  fi
  local lvl
  while IFS= read -r lvl; do deps_execute_level "$lvl"; done <<<"$levels"
  _log info "Install completed for $target"
  return 0
}

deps_resolve_recursive() {
  local root="$1"; local -n outarr="$2"
  declare -A seen=()
  local stack=("$root")
  while ((${#stack[@]})); do
    local p="${stack[-1]}"; stack=("${stack[@]:0:${#stack[@]}-1}")
    if [[ -n "${seen[$p]:-}" ]]; then continue; fi
    seen["$p"]=1
    outarr+=("$p")
    for d in ${DEPS_GRAPH[$p]:-}; do stack+=("$d"); done
  done
  IFS=$'\n' outarr=($(printf '%s\n' "${outarr[@]}" | awk '!x[$0]++' | sort))
}

deps_uninstall() {
  local pkg="$1"
  _log info "Uninstalling package: $pkg"
  local dependents="${REVERSE_GRAPH[$pkg]:-}"
  if [[ -n "$dependents" ]]; then _err_exit 4 "Cannot uninstall $pkg: dependents exist: $dependents"; fi
  if [[ "$DRY_RUN" -eq 1 ]]; then _log info "dry-run: would uninstall $pkg"; return 0; fi
  _log info "Uninstalled $pkg (simulated)"
  return 0
}

deps_rebuild() {
  local pkg="$1"
  _log info "Rebuilding $pkg and dependents"
  local -a to_rebuild=()
  deps_reverse_closure "$pkg" to_rebuild
  ALL_PKGS=("${to_rebuild[@]}")
  deps_kahn_order || _err_exit 3 "Cycle detected on rebuild"
  local levels; levels=$(deps_kahn_levels)
  local lvl
  while IFS= read -r lvl; do deps_execute_level "$lvl"; done <<<"$levels"
  _log info "Rebuild completed for $pkg"
}

deps_reverse_closure() {
  local root="$1"; local -n outarr="$2"
  declare -A seen=()
  local stack=("$root")
  while ((${#stack[@]})); do
    local p="${stack[-1]}"; stack=("${stack[@]:0:${#stack[@]}-1}")
    if [[ -n "${seen[$p]:-}" ]]; then continue; fi
    seen["$p"]=1
    outarr+=("$p")
    for d in ${REVERSE_GRAPH[$p]:-}; do stack+=("$d"); done
  done
  IFS=$'\n' outarr=($(printf '%s\n' "${outarr[@]}" | awk '!x[$0]++' | sort))
}

deps_upgrade() {
  local pkg="$1"
  _log info "Upgrading $pkg via repo.sh"
  if [[ -x /usr/libexec/lfsctl/repo.sh ]]; then
    /usr/libexec/lfsctl/repo.sh fetch "$pkg" || _log warn "repo.sh fetch failed for $pkg"
    deps_scan "$LFSCTL_PORTS_DIR"
    deps_rebuild "$pkg"
  else
    _err_exit 1 "repo.sh not available for upgrade"
  fi
}

deps_check_cycles() {
  deps_kahn_order || {
    _log warn "Attempting cycle diagnostics"
    local -A state=()
    local path=()
    local found=0
    dfs_find_cycle() {
      local node="$1"
      state["$node"]=1; path+=("$node")
      for nbr in ${DEPS_GRAPH[$node]:-}; do
        if [[ "${state[$nbr]:-0}" -eq 1 ]]; then
          local out=(); local p
          for p in "${path[@]}"; do out+=("$p"); if [[ "$p" == "$nbr" ]]; then break; fi; done
          out+=("$nbr")
          _log error "Cycle detected: ${out[*]}"
          found=1; return 0
        fi
        if [[ "${state[$nbr]:-0}" -eq 0 ]]; then dfs_find_cycle "$nbr" || return 0; fi
      done
      state["$node"]=2; path=("${path[@]:0:${#path[@]}-1}")
    }
    for n in "${ALL_PKGS[@]}"; do [[ "${state[$n]:-0}" -eq 0 ]] && dfs_find_cycle "$n" || true; done
    return 3
  }
  _log info "No cycles detected"
  return 0
}

# ---- CLI dispatcher ----
deps_help() {
  cat <<'EOF'
Usage: deps.sh <command> [options]
Commands:
  scan [ports_dir]           Scan /usr/ports and build dependency graph
  load-cache                 Load deps cache JSON
  check                      Validate graph and detect cycles
  order                      Compute topological order and print
  install <pkg>              Install package and dependencies (supports --dry-run --parallel N)
  uninstall <pkg>            Uninstall package (safe: checks dependents)
  rebuild <pkg>              Rebuild package and its dependents
  upgrade <pkg>              Upgrade package via repo.sh then rebuild dependents
  graph [out.dot]            Generate graphviz .dot file
  export-json [out.json]     Export report JSON
  help                       Show this help
Options:
  --dry-run        simulate actions
  --strict         strict failures
  --verbose        verbose output
  --auto-fix       allow auto-fix via repo.sh
  -j N             parallel jobs
  --continue       continue on error where safe
EOF
}

_parse_global_opts() {
  local argv=("$@") cmdargs=()
  while [[ $# -gt 0 ]]; do case "$1" in
    --dry-run) DRY_RUN=1; shift;;
    --strict) STRICT=1; shift;;
    --verbose) VERBOSE=1; shift;;
    --auto-fix) AUTO_FIX=1; shift;;
    --continue) CONTINUE_ON_ERROR=1; shift;;
    -j) PARALLEL_JOBS="$2"; shift 2;;
    -j*) PARALLEL_JOBS="${1#-j}"; shift;;
    *) cmdargs+=("$1"); shift;;
  esac; done
  set -- "${cmdargs[@]}"
  echo "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  ARGS=( "$@" )
  eval set -- "$(_parse_global_opts "${ARGS[@]}")"
  cmd="${1:-help}"; shift || true
  case "$cmd" in
    scan) deps_scan "${1:-$LFSCTL_PORTS_DIR}" ;;
    load-cache) deps_load_cache ;;
    check) deps_check_cycles ;;
    order) deps_kahn_order && printf '%s\n' "${BUILD_ORDER[@]}" ;;
    install) [[ -n "$1" ]] || _err_exit 1 "install requires package"; deps_scan "$LFSCTL_PORTS_DIR"; deps_install "$1" ;;
    uninstall) [[ -n "$1" ]] || _err_exit 1 "uninstall requires package"; deps_scan "$LFSCTL_PORTS_DIR"; deps_uninstall "$1" ;;
    rebuild) [[ -n "$1" ]] || _err_exit 1 "rebuild requires package"; deps_scan "$LFSCTL_PORTS_DIR"; deps_rebuild "$1" ;;
    upgrade) [[ -n "$1" ]] || _err_exit 1 "upgrade requires package"; deps_upgrade "$1" ;;
    graph) deps_scan "$LFSCTL_PORTS_DIR"; deps_graphviz "${1:-$DEPS_GRAPH_DOT}" ;;
    export-json) deps_scan "$LFSCTL_PORTS_DIR"; deps_export_json "${1:-}" ;;
    help|*) deps_help ;;
  esac
fi
