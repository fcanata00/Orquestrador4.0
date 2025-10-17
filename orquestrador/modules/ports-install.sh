#!/usr/bin/env bash
#===============================================================================
# ports-install.sh — M7 Install Manager & System Integration
# Author: ChatGPT (GPT-5 Thinking) — Production-grade module
# License: MIT
#===============================================================================
# HARD REQUIREMENTS:
# - Bash 5+, coreutils, util-linux, procps, tar, zstd, gzip, xz, bzip2
# - fakeroot, jq, file, readelf, ldd, sha256sum, timeout
# - Optional: gpg, rsync (não obrigatório), blake3
# - Existing modules: M1 logs, M2 lock, M3 db, M4 deps
#===============================================================================

set -o errexit -o pipefail -o nounset -o errtrace

#------------------------------------------------------------------------------
# Module bootstrap
#------------------------------------------------------------------------------
PORTS_LIB_DIR="${PORTS_LIB_DIR:-/usr/lib/ports}"
: "${PORTS_ETC_DIR:=/etc/ports}"
: "${PORTS_VAR_DIR:=/var/lib/ports}"
: "${PORTS_LOG_DIR:=/var/log/ports}"
: "${PORTS_CACHE_DIR:=/var/cache/ports}"
: "${PORTS_REPO_DIR:=/usr/ports}"

# Source core modules (required)
for m in ports-logs.sh ports-lock.sh ports-db.sh ports-deps.sh; do
  if [[ -r "$PORTS_LIB_DIR/$m" ]]; then
    # shellcheck disable=SC1090
    . "$PORTS_LIB_DIR/$m"
  else
    echo "FATAL: missing module $PORTS_LIB_DIR/$m" >&2
    exit 127
  fi
done

#------------------------------------------------------------------------------
# Config (defaults + /etc overrides)
#------------------------------------------------------------------------------
: "${CHROOT_ROOT:=/}"                # or /mnt/lfs
: "${ENFORCE_FHS:=1}"
: "${ENFORCE_SETUID:=1}"
: "${ENFORCE_RPATH:=1}"
: "${ALLOW_GPG_REQUIRED:=0}"         # 1 exige assinatura .sig
: "${PROTECT_ETC:=1}"
: "${KEEP_DAYS:=14}"
: "${AUTO_CLEAN_OLD:=1}"
: "${PARALLEL_VERIFY:=1}"            # 1 paraleliza verificação de hashes
: "${HOOK_TIMEOUT:=600}"

INSTALL_CONF="${PORTS_ETC_DIR}/install.conf"
if [[ -r "$INSTALL_CONF" ]]; then
  # shellcheck disable=SC1090
  . "$INSTALL_CONF"
fi

#------------------------------------------------------------------------------
# Paths
#------------------------------------------------------------------------------
PKG_STORE_DIR="${PORTS_VAR_DIR}/pkg"
INSTALL_LOG_DIR="${PORTS_LOG_DIR}/install"
BACKUP_DIR="${PORTS_VAR_DIR}/backups"
GLOBAL_HOOKS_DIR="${PORTS_REPO_DIR}/hooks/_global"

# Runtime vars
PKG=""
TARBALL=""
PKG_VERSION=""
OP_ID=""
OP_TS=""
INSTALL_JSON_LOG=""

umask 022

#------------------------------------------------------------------------------
# Helpers
#------------------------------------------------------------------------------
_require_bin() {
  local b
  for b in "$@"; do
    command -v "$b" >/dev/null 2>&1 || {
      echo "Ferramenta obrigatória ausente: $b" >&2
      exit 127
    }
  done
}

_json_escape() { jq -Rsa . <<<"${1:-}"; }

_write_json_event() {
  local event="$1"; shift
  local now; now=$(date -u +"%FT%TZ")
  printf '{"ts":"%s","event":"%s","pkg":%s,"op_id":%s,%s}\n' \
    "$now" "$event" \
    "$(_json_escape "$PKG")" "$(_json_escape "$OP_ID")" \
    "$*" >> "$INSTALL_JSON_LOG"
}

is_root() { [[ ${EUID:-$(id -u)} -eq 0 ]]; }

real_root() { echo "${CHROOT_ROOT%/}"; }

# Normalize and ensure path stays under CHROOT_ROOT
safe_target_path() {
  local p="$1"
  local dest root
  root="$(real_root)"
  dest="$(realpath -m --no-symlinks "$root/$p" 2>/dev/null || true)"
  [[ -n "$dest" ]] || return 1
  [[ "$dest" == "$root"* ]] || return 1
  echo "$dest"
}

#------------------------------------------------------------------------------
# Error handling
#------------------------------------------------------------------------------
install::error_handler() {
  local code="${1:-1}"
  local func="${2:-?}"
  local line="${3:-0}"
  local cmd="${4:-?}"
  log::error "[${func}:${line}] Falha: ${cmd} (exit ${code})"
  _write_json_event "error" \
    "$(printf '"func":%s,"line":%s,"cmd":%s,"exit":%s' \
      "$(_json_escape "$func")" "$line" "$(_json_escape "$cmd")" "$code")"
  lock::release || true
  exit "$code"
}
trap 'install::error_handler $? ${FUNCNAME:-main} ${BASH_LINENO[0]} "${BASH_COMMAND}"' ERR

#------------------------------------------------------------------------------
# Init / permissions
#------------------------------------------------------------------------------
install::init() {
  _require_bin bash jq tar zstd file readelf ldd sha256sum timeout
  mkdir -p -m 0775 "$INSTALL_LOG_DIR" "$PKG_STORE_DIR" "$BACKUP_DIR"
  chown root:portsbuild "$INSTALL_LOG_DIR" "$PKG_STORE_DIR" "$BACKUP_DIR" || true
  chmod 0775 "$INSTALL_LOG_DIR" "$PKG_STORE_DIR" "$BACKUP_DIR" || true

  # log rotation simple
  if [[ "${AUTO_CLEAN_OLD}" -eq 1 ]]; then
    find "$INSTALL_LOG_DIR" -type f -name '*.log' -mtime +"$KEEP_DAYS" -exec sh -c '
      for f in "$@"; do zstd -q --rm "$f"; done
    ' sh {} + || true
    find "$BACKUP_DIR" -type f -mtime +"$KEEP_DAYS" -delete || true
  fi
}

#------------------------------------------------------------------------------
# Hooks
#------------------------------------------------------------------------------
_hooks_run() {
  local stage="$1" pkg="$2"
  local local_hook_dir="${PORTS_REPO_DIR}/hooks/${pkg}"
  local hooks=()
  [[ -x "$GLOBAL_HOOKS_DIR/pre-${stage}" ]] && hooks+=("$GLOBAL_HOOKS_DIR/pre-${stage}")
  [[ -x "$local_hook_dir/${stage}" ]] && hooks+=("$local_hook_dir/${stage}")
  [[ -x "$GLOBAL_HOOKS_DIR/post-${stage}" ]] && hooks+=("$GLOBAL_HOOKS_DIR/post-${stage}")

  local h
  for h in "${hooks[@]}"; do
    log::info "Executando hook ${stage}: $h"
    timeout "$HOOK_TIMEOUT" bash -Eeuo pipefail "$h" "$PKG" || {
      log::error "Hook $h falhou"
      return 1
    }
  done
}

#------------------------------------------------------------------------------
# Integrity / signature
#------------------------------------------------------------------------------
tarball::detect() {
  local spec="$1"
  if [[ -f "$spec" ]]; then
    echo "$spec"
    return 0
  fi
  # try store dir
  local found
  found=$(ls -1 "$PKG_STORE_DIR"/"${spec}"-*.tar.zst 2>/dev/null | sort -V | tail -n1 || true)
  [[ -n "$found" ]] || { log::error "Tarball não encontrado para $spec em $PKG_STORE_DIR"; return 1; }
  echo "$found"
}

tarball::sha256_verify() {
  local tb="$1"
  local sumfile="${tb}.sha256"
  if [[ -r "$sumfile" ]]; then
    ( cd "$(dirname "$tb")" && sha256sum -c "$(basename "$sumfile")" ) || {
      log::error "SHA-256 mismatch em $(basename "$tb")"
      return 1
    }
    _write_json_event "sha256.ok" "\"tarball\":$(_json_escape "$tb")"
  else
    log::warn "Arquivo .sha256 ausente — prosseguindo (recomendado manter)"
  fi
}

tarball::gpg_verify() {
  local tb="$1"
  local sig="${tb}.sig"
  if [[ -r "$sig" ]]; then
    if command -v gpg >/dev/null 2>&1; then
      if gpg --verify "$sig" "$tb" >/dev/null 2>&1; then
        _write_json_event "gpg.ok" "\"tarball\":$(_json_escape "$tb")"
      else
        if [[ "$ALLOW_GPG_REQUIRED" -eq 1 ]]; then
          log::error "Assinatura GPG inválida e GPG é obrigatório"
          return 1
        else
          log::warn "Assinatura GPG inválida — prosseguindo sem bloquear"
        fi
      fi
    else
      log::warn "gpg não encontrado; pulei verificação de assinatura"
    fi
  else
    if [[ "$ALLOW_GPG_REQUIRED" -eq 1 ]]; then
      log::error "Assinatura GPG ausente e GPG é obrigatório"
      return 1
    fi
  fi
}

#------------------------------------------------------------------------------
# Read metadata / manifest from tarball (if present)
#------------------------------------------------------------------------------
tarball::read_manifest_json() {
  local tb="$1"
  # try to read manifest path meta/manifest.json
  if tar -tf "$tb" | grep -q '^meta/manifest\.json$'; then
    tar -xOf "$tb" meta/manifest.json
    return 0
  fi
  echo "{}"
}

tarball::get_version() {
  local tb="$1"
  local ver
  ver=$(tar -tf "$tb" | sed -n 's,^.*/,,;s,.*-,,;s,\.tar\.zst$,,p' | head -n1 | tr -d '\n' || true)
  if [[ -z "$ver" ]]; then
    # fallback to manifest
    ver=$(tarball::read_manifest_json "$tb" | jq -r '.version // empty')
  fi
  echo "$ver"
}

#------------------------------------------------------------------------------
# Staging extraction with path validation
#------------------------------------------------------------------------------
staging::extract_safe() {
  local tb="$1"
  local staging="$2"
  mkdir -p "$staging"
  # Pre-validate entries
  local bad=0
  while IFS= read -r e; do
    # disallow absolute, parent traversal, control chars
    if [[ "$e" == /* || "$e" == *".."* || "$e" == *$'\n'* || "$e" == *$'\r'* ]]; then
      bad=1; log::error "Entrada insegura no tar: $e"
    fi
  done < <(tar -tf "$tb")
  [[ "$bad" -eq 0 ]] || return 1

  tar --zstd -xf "$tb" -C "$staging" --no-same-owner --no-same-permissions
  # Validate all extracted paths resolve under staging
  local rp
  while IFS= read -r f; do
    rp=$(realpath -m -- "$f" 2>/dev/null || true)
    [[ -n "$rp" && "$rp" == "$staging"* ]] || {
      log::error "Extração fora do staging detectada: $f"
      return 1
    }
  done < <(find "$staging" -mindepth 1 -print)
}

#------------------------------------------------------------------------------
# FHS and policy checks
#------------------------------------------------------------------------------
policy::check_paths() {
  local root staging="$1"
  root="$(real_root)"
  local ok_prefixes=("usr" "etc" "var" "lib" "lib64" "bin" "sbin" "opt")
  local rel
  while IFS= read -r abs; do
    rel="${abs#$root/}"
    # allow meta/ inside staging (not installed)
    [[ "$rel" == meta/* ]] && continue
    local head="${rel%%/*}"
    local allowed=1
    local p
    for p in "${ok_prefixes[@]}"; do
      if [[ "$head" == "$p" ]]; then allowed=0; break; fi
    done
    if [[ "$ENFORCE_FHS" -eq 1 && "$allowed" -ne 0 ]]; then
      log::error "Caminho fora do FHS permitido: /$rel"
      return 1
    fi
  done < <(find "$staging" -type f -o -type l | sed "s#^#$root/#")
}

policy::sanitize_perms() {
  local dest="$1"
  # Normalize: dirs 755, files 644, exec 755; keep executable bit if present
  find "$dest" -type d -exec chmod 755 {} + || true
  find "$dest" -type f -exec chmod 644 {} + || true
  find "$dest" -type f -perm -111 -exec chmod 755 {} + || true
}

policy::check_setuid_rpath() {
  local dest="$1"
  local setuid_found=0 rpath_found=0
  while IFS= read -r f; do
    file "$f" | grep -q 'ELF' || continue
    if [[ -u "$f" || -g "$f" ]]; then
      if [[ "$ENFORCE_SETUID" -eq 1 ]]; then
        log::error "Arquivo setuid/setgid não permitido: $f"
        setuid_found=1
      else
        log::warn "setuid/setgid detectado: $f"
      fi
    fi
    if readelf -d "$f" 2>/dev/null | grep -Eq '(RPATH|RUNPATH)'; then
      if [[ "$ENFORCE_RPATH" -eq 1 ]]; then
        log::error "RPATH/RUNPATH não permitido: $f"
        rpath_found=1
      else
        log::warn "RPATH/RUNPATH presente: $f"
      fi
    fi
  done < <(find "$dest" -type f -perm -111)
  [[ "$setuid_found" -eq 0 && "$rpath_found" -eq 0 ]]
}

#------------------------------------------------------------------------------
# DB helpers (interfaces esperadas do M3)
#------------------------------------------------------------------------------
db::pkg_installed_version() { portsdb::get_pkg_version "$1"; }             # echo version or empty
db::pkg_manifest_json() { portsdb::get_pkg_manifest_json "$1"; }           # echo JSON {"files":[{"path":...,"sha256":...}]}
db::register_pkg_manifest() { portsdb::register_pkg_manifest "$@"; }       # pkg ver json
db::remove_pkg() { portsdb::remove_pkg "$1"; }
db::reverse_deps() { portsdb::reverse_deps "$1"; }                         # echo space-separated list
db::is_base_pkg() { portsdb::is_base_pkg "$1"; }                           # returns 0 if base, 1 otherwise
db::register_event() { db::event "$1" "$2"; }                              # from ports-db.sh

#------------------------------------------------------------------------------
# Diff / delta calculation for upgrade
#------------------------------------------------------------------------------
manifest::from_staging() {
  local staging="$1"; shift
  # produce {"files":[{"path": "...", "sha256":"..."}]}
  jq -n '{files: []}' > "$staging/.manifest.json"
  local root; root="$(real_root)"
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    local rel="${f#$staging/}"
    local sha; sha=$(sha256sum "$f" | awk '{print $1}')
    jq --arg p "$rel" --arg s "$sha" '.files += [{"path":$p,"sha256":$s}]' \
      "$staging/.manifest.json" > "$staging/.m2.json" && mv -f "$staging/.m2.json" "$staging/.manifest.json"
  done < <(find "$staging" -type f ! -path "$staging/meta/*" -print | sort)
  cat "$staging/.manifest.json"
}

manifest::diff() {
  local old_json="$1" new_json="$2"
  jq -n --argjson old "$old_json" --argjson neu "$new_json" '
    def toMap: ( .files // [] ) | map({(.path): .sha256}) | add;
    def keysOf($m): ($m|keys) // [];
    def inAonly($a;$b): [ ($a|keys - ($b|keys))[] | {path:., op:"remove"} ];
    def inBonly($a;$b): [ ($b|keys - ($a|keys))[] | {path:., op:"add", sha256:$b[.]} ];
    def inBothDiff($a;$b): [ ($a|keys * ($b|keys))[] | select($a[.] != $b[.]) | {path:., op:"change", sha256:$b[.]} ];
    (toMap as $A | ($neu|toMap) as $B | (inAonly($A;$B) + inBonly($A;$B) + inBothDiff($A;$B)))'
}

#------------------------------------------------------------------------------
# Apply: copy from staging to CHROOT_ROOT atomically (per-file)
#------------------------------------------------------------------------------
apply::file() {
  local staging="$1" rel="$2"
  local src="$staging/$rel"
  local dst; dst="$(safe_target_path "$rel")" || { log::error "Caminho inseguro: $rel"; return 1; }
  mkdir -p "$(dirname "$dst")"
  # atomic replace: copy to temp then move
  local tmp="${dst}.ports.$$"
  cp -a --reflink=auto --remove-destination "$src" "$tmp" 2>/dev/null || cp -a "$src" "$tmp"
  mv -f "$tmp" "$dst"
}

apply::remove() {
  local rel="$1"
  local dst; dst="$(safe_target_path "$rel")" || return 0
  if [[ -e "$dst" || -L "$dst" ]]; then
    rm -rf --one-file-system "$dst"
    # cleanup empty parent dirs up to root
    local d; d="$(dirname "$dst")"
    while [[ "$d" != "$(real_root)" && "$d" != "/" ]]; do
      rmdir "$d" 2>/dev/null || break
      d="$(dirname "$d")"
    done
  fi
}

#------------------------------------------------------------------------------
# Backup / Rollback
#------------------------------------------------------------------------------
backup::create() {
  local label="$1" # e.g. upgrade or uninstall
  local list_json="$2" # manifest json describing affected files
  local ts; ts="$(date -u +%Y%m%d-%H%M%S)"
  local out="${BACKUP_DIR}/${PKG}-${label}-${ts}.tar.zst"
  jq -r '.files[].path' <<<"$list_json" | while IFS= read -r rel; do
    local dst; dst="$(safe_target_path "$rel")" || continue
    [[ -e "$dst" || -L "$dst" ]] && echo "${dst#$(real_root)/}"
  done | tar -C "$(real_root)" --zstd -cf "$out" -T -
  echo "$out"
}

backup::restore() {
  local tarball="$1"
  log::warn "Restaurando backup: $tarball"
  tar --zstd -xf "$tarball" -C "$(real_root)"
}

#------------------------------------------------------------------------------
# Post-install checks
#------------------------------------------------------------------------------
post::verify_hashes() {
  local manifest_json="$1"
  local mismatches=0
  jq -r '.files[].path' <<<"$manifest_json" | while IFS= read -r rel; do
    local dst; dst="$(safe_target_path "$rel")" || { echo "MISS $rel"; continue; }
    if [[ -f "$dst" ]]; then
      local sha_cur; sha_cur=$(sha256sum "$dst" | awk '{print $1}')
      local sha_exp; sha_exp=$(jq -r --arg p "$rel" '.files[] | select(.path==$p) | .sha256' <<<"$manifest_json")
      [[ "$sha_cur" == "$sha_exp" ]] || { echo "MISMATCH $rel"; mismatches=$((mismatches+1)); }
    else
      echo "MISSING $rel"
      mismatches=$((mismatches+1))
    fi
  done | tee -a /dev/null
  [[ "$mismatches" -eq 0 ]]
}

post::verify_elf() {
  local manifest_json="$1"
  local errs=0
  jq -r '.files[].path' <<<"$manifest_json" | while IFS= read -r rel; do
    local dst; dst="$(safe_target_path "$rel")" || continue
    [[ -f "$dst" ]] || continue
    file "$dst" | grep -q 'ELF' || continue
    if ! ldd "$dst" >/dev/null 2>&1; then
      log::error "ldd falhou em $rel"; errs=$((errs+1))
    else
      if ldd "$dst" | grep -q 'not found'; then
        log::error "Biblioteca faltante em $rel"; errs=$((errs+1))
      fi
    fi
    if [[ "$ENFORCE_RPATH" -eq 1 ]] && readelf -d "$dst" 2>/dev/null | grep -Eq '(RPATH|RUNPATH)'; then
      log::error "RPATH/RUNPATH não permitido: $rel"
      errs=$((errs+1))
    fi
  done
  [[ "$errs" -eq 0 ]]
}

post::verify_symlinks() {
  local root; root="$(real_root)"
  local broken
  broken=$(find "$root" -xtype l 2>/dev/null | wc -l || echo 0)
  if [[ "$broken" -gt 0 ]]; then
    log::warn "Symlinks quebrados detectados: $broken"
  fi
}

#------------------------------------------------------------------------------
# Orphans detection
#------------------------------------------------------------------------------
orphans::list() {
  local all installed
  installed=$(portsdb::list_installed_pkgs) # expected to echo packages
  local o=()
  local p
  for p in $installed; do
    if db::is_base_pkg "$p"; then
      continue
    fi
    local rdeps; rdeps="$(db::reverse_deps "$p" | tr -s ' ' '\n' | sed '/^$/d')" || rdeps=""
    if [[ -z "$rdeps" ]]; then
      o+=("$p")
    fi
  done
  printf '%s\n' "${o[@]}" || true
}

orphans::remove() {
  local list; list="$(orphans::list)"
  [[ -n "$list" ]] || { log::info "Sem órfãos."; return 0; }
  log::warn "Removendo órfãos: $list"
  local p
  for p in $list; do
    uninstall::run "$p" "--no-orphan-scan"
  done
}

#------------------------------------------------------------------------------
# Install / Upgrade core
#------------------------------------------------------------------------------
install::apply_manifest() {
  local staging="$1" manifest_new="$2" manifest_old="$3" is_upgrade="$4"
  local diff_json
  if [[ -n "$manifest_old" ]]; then
    diff_json="$(manifest::diff "$manifest_old" "$manifest_new")"
  else
    diff_json="$(jq -n --argjson neu "$manifest_new" '$neu.files | map({path:.path, op:"add", sha256:.sha256})')"
  fi

  # backup affected files before touching
  local affected; affected="$(jq -n --argjson d "$diff_json" '{files: ($d|map(select(.op!="remove")|{path:.path}))}')" # add/change
  local bkp=""
  if [[ "$is_upgrade" == "1" ]]; then
    bkp="$(backup::create upgrade "$affected")"
    _write_json_event "backup.created" "\"file\":$(_json_escape "$bkp")"
  fi

  # apply adds/changes
  jq -r '.[] | select(.op=="add" or .op=="change") | .path' <<<"$diff_json" | while IFS= read -r rel; do
    apply::file "$staging" "$rel"
  done

  # apply removes (only if upgrade or install-with-prune)
  jq -r '.[] | select(.op=="remove") | .path' <<<"$diff_json" | while IFS= read -r rel; do
    apply::remove "$rel"
  done

  echo "$diff_json"
}

install::from_tarball() {
  TARBALL="$1"
  tarball::sha256_verify "$TARBALL"
  tarball::gpg_verify "$TARBALL"

  # read manifest from tar (if any); otherwise compute from staging
  local staging; staging="$(mktemp -d "${PORTS_CACHE_DIR}/install.XXXXXX")"
  _write_json_event "staging.create" "\"dir\":$(_json_escape "$staging")"
  trap 'rm -rf "$staging" || true' RETURN

  staging::extract_safe "$TARBALL" "$staging"

  # optional 'meta/manifest.json' may declare install prefix; we install relative to CHROOT_ROOT
  local manifest_new; manifest_new="$(tarball::read_manifest_json "$TARBALL")"
  if [[ "$(jq -r 'has("files")' <<<"$manifest_new")" != "true" ]]; then
    manifest_new="$(manifest::from_staging "$staging")"
  fi

  # policy checks and sanitize perms (staging)
  policy::check_paths "$staging"
  policy::sanitize_perms "$staging"
  policy::check_setuid_rpath "$staging"

  # If protect /etc, backup config files before overwrite
  if [[ "$PROTECT_ETC" -eq 1 ]]; then
    local etc_aff; etc_aff=$(jq -r '.files[].path | select(startswith("etc/"))' <<<"$manifest_new" | wc -l)
    if [[ "$etc_aff" -gt 0 ]]; then
      log::warn "Pacote modifica /etc ($etc_aff arquivos) — será feito backup automático."
      local etc_json; etc_json="$(jq -n --argjson m "$manifest_new" '{files: ($m.files | map(select(.path|startswith("etc/")))) }')"
      local bkp_etc; bkp_etc="$(backup::create install-etc "$etc_json")"
      _write_json_event "backup.etc" "\"file\":$(_json_escape "$bkp_etc")"
    fi
  fi

  local is_upgrade=0
  local old_ver=""; old_ver="$(db::pkg_installed_version "$PKG" || true)"
  local manifest_old=""
  if [[ -n "$old_ver" ]]; then
    is_upgrade=1
    manifest_old="$(db::pkg_manifest_json "$PKG" || echo "{}")"
  fi

  # pre-hooks
  _hooks_run "pre-install" "$PKG"
  [[ "$is_upgrade" -eq 0 ]] || _hooks_run "pre-upgrade" "$PKG"

  # apply changes
  local diff_json
  diff_json="$(install::apply_manifest "$staging" "$manifest_new" "$manifest_old" "$is_upgrade")"

  # post-checks
  post::verify_hashes "$manifest_new"
  post::verify_elf "$manifest_new"
  post::verify_symlinks

  # register DB (transactional: only after success)
  local new_ver; new_ver="$(tarball::get_version "$TARBALL" | tr -d '\n')"
  [[ -n "$new_ver" ]] || new_ver="unknown"
  db::register_pkg_manifest "$PKG" "$new_ver" "$manifest_new"

  # post-hooks
  _hooks_run "post-install" "$PKG"
  [[ "$is_upgrade" -eq 0 ]] || _hooks_run "post-upgrade" "$PKG"

  _write_json_event "install.ok" "$(printf '"tarball":%s,"version":%s,"delta":%s' \
    "$(_json_escape "$TARBALL")" "$(_json_escape "$new_ver")" "$(jq -c <<<"$diff_json")")"
  db::register_event "install.ok" "$(printf '{"pkg":%s,"version":%s}' "$(_json_escape "$PKG")" "$(_json_escape "$new_ver")")"
  log::ok "Instalação concluída: $PKG ($new_ver)"
}

#------------------------------------------------------------------------------
# Uninstall
#------------------------------------------------------------------------------
uninstall::run() {
  local pkg="$1"; local no_orphan="${2:-}"
  PKG="$pkg"
  lock::named_acquire "install:$PKG"
  install::init
  OP_TS="$(date -u +%Y%m%d-%H%M%S)"
  OP_ID="${PKG}-uninstall-${OP_TS}"
  INSTALL_JSON_LOG="${INSTALL_LOG_DIR}/${PKG}-${OP_TS}.json"; : > "$INSTALL_JSON_LOG"

  _write_json_event "uninstall.start" "\"root\":$(_json_escape "$(real_root)")"
  local manifest_old; manifest_old="$(db::pkg_manifest_json "$PKG" || echo "{}")"
  [[ "$(jq -r 'has(\"files\")' <<<"$manifest_old")" == "true" ]] || {
    log::error "Pacote não encontrado no DB: $PKG"
    lock::release; return 1
  }

  _hooks_run "pre-uninstall" "$PKG"

  # backup files to be removed
  local bkp; bkp="$(backup::create uninstall "$manifest_old")"
  _write_json_event "backup.created" "\"file\":$(_json_escape "$bkp")"

  # remove files
  jq -r '.files[].path' <<<"$manifest_old" | tac | while IFS= read -r rel; do
    apply::remove "$rel"
  done

  db::remove_pkg "$PKG"
  _hooks_run "post-uninstall" "$PKG"
  _write_json_event "uninstall.ok" "\"backup\":$(_json_escape "$bkp")"
  db::register_event "uninstall.ok" "$(printf '{"pkg":%s}' "$(_json_escape "$PKG")")"
  log::ok "Uninstall concluído: $PKG"

  lock::release

  # handle orphans unless suppressed
  if [[ "$no_orphan" != "--no-orphan-scan" ]]; then
    local list; list="$(orphans::list || true)"
    if [[ -n "$list" ]]; then
      log::warn "Foram detectados pacotes órfãos: $list"
      # Remoção automática de órfãos, pode ser ajustado para confirmar
      orphans::remove
    fi
  fi
}

#------------------------------------------------------------------------------
# CLI
#------------------------------------------------------------------------------
usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [args]

Commands:
  install <pkg|tarball>   - Instala um pacote .tar.zst (de arquivo ou por nome)
  upgrade <pkg>           - Atualiza pacote para a versão mais recente do store
  uninstall <pkg>         - Remove pacote e atualiza DB
  verify <pkg>            - Verifica integridade (hash/ELF/symlinks) do pacote instalado
  orphans [list|remove]   - Lista ou remove pacotes órfãos
  clean [logs|backups]    - Rotaciona/apaga logs e backups antigos
  version                 - Mostra versão do módulo
EOF
}

main() {
  local cmd="${1:-}"; shift || true
  case "$cmd" in
    install)
      local spec="${1:-}"
      [[ -n "$spec" ]] || { usage; exit 2; }
      if [[ -f "$spec" ]]; then
        PKG="$(basename "$spec" | sed 's/\.tar\.zst$//' | sed 's/-[0-9].*$//' )"
      else
        PKG="$spec"
      fi
      lock::named_acquire "install:$PKG"
      install::init
      OP_TS="$(date -u +%Y%m%d-%H%M%S)"
      OP_ID="${PKG}-install-${OP_TS}"
      INSTALL_JSON_LOG="${INSTALL_LOG_DIR}/${PKG}-${OP_TS}.json"; : > "$INSTALL_JSON_LOG"
      _write_json_event "install.start" "\"root\":$(_json_escape "$(real_root)")"
      TARBALL="$(tarball::detect "${1}")"
      install::from_tarball "$TARBALL"
      lock::release
      ;;
    upgrade)
      PKG="${1:-}"
      [[ -n "$PKG" ]] || { usage; exit 2; }
      local tb; tb="$(tarball::detect "$PKG")"
      lock::named_acquire "install:$PKG"
      install::init
      OP_TS="$(date -u +%Y%m%d-%H%M%S)"
      OP_ID="${PKG}-upgrade-${OP_TS}"
      INSTALL_JSON_LOG="${INSTALL_LOG_DIR}/${PKG}-${OP_TS}.json"; : > "$INSTALL_JSON_LOG"
      _write_json_event "upgrade.start" "\"root\":$(_json_escape "$(real_root)")"
      install::from_tarball "$tb"
      lock::release
      ;;
    uninstall)
      local p="${1:-}"
      [[ -n "$p" ]] || { usage; exit 2; }
      uninstall::run "$p"
      ;;
    verify)
      PKG="${1:-}"
      [[ -n "$PKG" ]] || { usage; exit 2; }
      install::init
      OP_TS="$(date -u +%Y%m%d-%H%M%S)"
      OP_ID="${PKG}-verify-${OP_TS}"
      INSTALL_JSON_LOG="${INSTALL_LOG_DIR}/${PKG}-${OP_TS}.json"; : > "$INSTALL_JSON_LOG"
      local manifest_old; manifest_old="$(db::pkg_manifest_json "$PKG" || echo "{}")"
      [[ "$(jq -r 'has(\"files\")' <<<"$manifest_old")" == "true" ]] || {
        log::error "Pacote não encontrado no DB: $PKG"; exit 1; }
      _write_json_event "verify.start" "\"root\":$(_json_escape "$(real_root)")"
      post::verify_hashes "$manifest_old"
      post::verify_elf "$manifest_old"
      post::verify_symlinks
      _write_json_event "verify.ok" "\"pkg\":$(_json_escape "$PKG")"
      log::ok "Verificação concluída: $PKG"
      ;;
    orphans)
      install::init
      case "${1:-list}" in
        list) orphans::list ;;
        remove) orphans::remove ;;
        *) usage ;;
      esac
      ;;
    clean)
      install::init
      case "${1:-}" in
        logs) find "$INSTALL_LOG_DIR" -type f -mtime +"$KEEP_DAYS" -delete ;;
        backups) find "$BACKUP_DIR" -type f -mtime +"$KEEP_DAYS" -delete ;;
        *) usage ;;
      esac
      ;;
    version|-v|--version)
      echo "ports-install.sh (M7) — $(date -u +"%Y-%m-%d")"
      ;;
    *)
      usage ;;
  esac
}

# Ensure logs module is loaded (M1)
if ! command -v log::step >/dev/null 2>&1; then
  echo "FATAL: ports-logs.sh (M1) não carregado" >&2
  exit 127
fi

main "$@"
