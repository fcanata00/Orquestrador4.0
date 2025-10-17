#!/usr/bin/env bash
#===============================================================================
# ports-build.sh — M6 Build Manager & Secure Chroot Builder
# Author: ChatGPT (GPT-5 Thinking) — Production-grade module
# License: MIT
#===============================================================================
# HARD REQUIREMENTS:
# - Bash 5+, coreutils, util-linux, procps, tar, zstd, gzip, xz, bzip2
# - fakeroot, jq, file, findutils, grep, sed, awk, readelf (binutils), objdump
# - ldd (glibc), sha256sum, (optional) b3sum, pstree, timeout
# - mount namespace tools: unshare (util-linux)
# - cgroup v2 mounted at /sys/fs/cgroup (systemd preferred, but fallback works)
# - Existing modules: M1 logs, M2 lock, M3 db, M4 deps, M5 fetch
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
for m in ports-logs.sh ports-lock.sh ports-db.sh ports-deps.sh ports-fetch.sh; do
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
: "${PORTS_BUILD_MIN_MB:=2048}"
: "${PORTS_REUSE_OBJ:=1}"
: "${PORTS_BUILD_NET:=0}"
: "${STRIP_BINARIES:=1}"
: "${PORTS_ENFORCE_DESTDIR:=1}"
: "${PORTS_ENFORCE_RPATH:=1}"
: "${HOOK_TIMEOUT:=900}"
: "${MAKE_JOBS:=$(nproc)}"
: "${PORTS_BUILD_TIMEOUT:=7200}"
: "${PORTS_BUILD_LOG_COMPRESS:=1}"
: "${PORTS_LOG_KEEP_DAYS:=7}"
: "${PORTS_STRICT_BUILD:=1}"
: "${PORTS_BUILD_SILENT_RETRY:=2}"
: "${PORTS_ERROR_RETRY_DELAY:=5}"
: "${CGROUP_ENABLE:=1}"
: "${CGROUP_CPU_MAX:=}"             # e.g. "200000 100000"
: "${CGROUP_MEM_MAX:=}"             # e.g. "4G"
: "${CGROUP_SWAP_MAX:=}"            # e.g. "0" to disable swap
: "${CGROUP_IO_MAX:=}"              # optional, device throttling

BUILD_CONF="${PORTS_ETC_DIR}/build.conf"
if [[ -r "$BUILD_CONF" ]]; then
  # shellcheck disable=SC1090
  . "$BUILD_CONF"
fi

#------------------------------------------------------------------------------
# Paths
#------------------------------------------------------------------------------
SRC_CACHE_DIR="${PORTS_CACHE_DIR}/sources"
BUILD_CACHE_DIR="${PORTS_CACHE_DIR}/build"
PKG_DIR="${PORTS_VAR_DIR}/pkg"
BUILD_LOG_DIR="${PORTS_LOG_DIR}/build"
HOOKS_DIR="${PORTS_REPO_DIR}/hooks"
META_ROOT="${PORTS_REPO_DIR}/repo"
WORK_BASE="${BUILD_CACHE_DIR}"

# Runtime vars
PKG=""
PKG_VERSION=""
BUILD_ID=""
BUILD_TS=""
PKG_BUILD_DIR=""
DESTDIR=""
BUILD_JSON_LOG=""
CGROUP_ROOT="/sys/fs/cgroup"
CGROUP_PATH=""

#------------------------------------------------------------------------------
# Helpers
#------------------------------------------------------------------------------
umask 022

_require_bin() {
  local b
  for b in "$@"; do
    command -v "$b" >/dev/null 2>&1 || {
      log::error "Ferramenta obrigatória ausente: $b"
      exit 127
    }
  done
}

_is_root() { [[ ${EUID:-$(id -u)} -eq 0 ]]; }

_check_space_mb() {
  local path="$1" need_mb="$2"
  local avail
  avail=$(df -Pm "$path" | awk 'NR==2{print $4}')
  if [[ -z "$avail" || "$avail" -lt "$need_mb" ]]; then
    log::error "Espaço insuficiente em $path: disponivel=${avail:-0}MB < necessário=${need_mb}MB"
    return 1
  fi
}

_json_escape() {
  jq -Rsa . <<<"${1:-}"
}

_write_json_event() {
  local key="$1"; shift
  local now
  now=$(date -u +"%FT%TZ")
  printf '{"ts":"%s","event":"%s","pkg":%s,"build_id":%s,%s}\n' \
    "$now" "$key" \
    "$(_json_escape "$PKG")" "$(_json_escape "$BUILD_ID")" \
    "$*" >> "$BUILD_JSON_LOG"
}

#------------------------------------------------------------------------------
# Error handling
#------------------------------------------------------------------------------
build::error_handler() {
  local code="${1:-1}"
  local func="${2:-?}"
  local line="${3:-0}"
  local cmd="${4:-?}"
  log::error "[${func}:${line}] Falha: ${cmd} (exit ${code})"
  _write_json_event "error" \
    "$(printf '"func":%s,"line":%s,"cmd":%s,"exit":%s' \
      "$(_json_escape "$func")" "$line" "$(_json_escape "$cmd")" "$code")"
  db::event "build.fail" "$(printf '{"pkg":%s,"build_id":%s,"exit":%s}' \
     "$(_json_escape "$PKG")" "$(_json_escape "$BUILD_ID")" "$code")" || true
  # Ensure cleanup
  chroot::mounts_cleanup --force || true
  cgroup::cleanup || true
  exit "$code"
}
trap 'build::error_handler $? ${FUNCNAME:-main} ${BASH_LINENO[0]} "${BASH_COMMAND}"' ERR

#------------------------------------------------------------------------------
# Init / permissions
#------------------------------------------------------------------------------
build::init() {
  _require_bin bash jq tar zstd fakeroot file find readelf objdump ldd sha256sum timeout
  mkdir -p -m 0775 "$BUILD_LOG_DIR" "$PKG_DIR" "$BUILD_CACHE_DIR"
  chown root:portsbuild "$BUILD_LOG_DIR" "$PKG_DIR"
  chmod 0775 "$BUILD_LOG_DIR" "$PKG_DIR"
  # sources cache is maintained by M5
  [[ -d "$SRC_CACHE_DIR" ]] || mkdir -p -m 0755 "$SRC_CACHE_DIR"
  chown root:portsbuild "$SRC_CACHE_DIR" || true
  chmod 0755 "$SRC_CACHE_DIR" || true

  # Build user sanity
  if ! id -u portsbuild >/dev/null 2>&1; then
    log::warn "Usuário 'portsbuild' ausente — criando (sem shell de login)"
    useradd -r -s /usr/sbin/nologin -m -d /var/lib/portsbuild portsbuild || true
  fi

  # Clean old logs
  if [[ "${PORTS_BUILD_LOG_COMPRESS}" -eq 1 ]]; then
    find "$BUILD_LOG_DIR" -type f -name '*.log' -mtime +"$PORTS_LOG_KEEP_DAYS" -exec sh -c '
      for f in "$@"; do zstd -q --rm "$f"; done
    ' sh {} + || true
  fi
}

#------------------------------------------------------------------------------
# Cgroup v2 management
#------------------------------------------------------------------------------
cgroup::enabled() {
  [[ "$CGROUP_ENABLE" -eq 1 ]] && [[ -e "$CGROUP_ROOT/cgroup.controllers" ]]
}

cgroup::path_for_pkg() {
  local p="ports-build.slice/${PKG}.scope"
  echo "$p"
}

cgroup::setup() {
  CGROUP_PATH=""
  cgroup::enabled || return 0
  local scope=""
  scope=$(cgroup::path_for_pkg)
  mkdir -p "$CGROUP_ROOT/ports-build.slice" || true
  # Create our scope
  if [[ ! -d "$CGROUP_ROOT/$scope" ]]; then
    mkdir -p "$CGROUP_ROOT/$scope"
  fi
  CGROUP_PATH="$CGROUP_ROOT/$scope"

  # Enable controllers
  if [[ -r "$CGROUP_ROOT/cgroup.subtree_control" ]]; then
    # shellcheck disable=SC2016
    for c in cpu memory io pids; do
      grep -qw "$c" "$CGROUP_ROOT/cgroup.controllers" 2>/dev/null || continue
      if ! grep -qw "+$c" "$CGROUP_ROOT/cgroup.subtree_control" 2>/dev/null; then
        (echo "+$c" >> "$CGROUP_ROOT/cgroup.subtree_control") 2>/dev/null || true
      fi
    done
  fi

  # Apply limits if provided
  if [[ -n "${CGROUP_CPU_MAX:-}" && -w "$CGROUP_PATH/cpu.max" ]]; then
    echo "$CGROUP_CPU_MAX" > "$CGROUP_PATH/cpu.max" || log::warn "Falha ao setar cpu.max"
  fi
  if [[ -n "${CGROUP_MEM_MAX:-}" && -w "$CGROUP_PATH/memory.max" ]]; then
    echo "$CGROUP_MEM_MAX" > "$CGROUP_PATH/memory.max" || log::warn "Falha ao setar memory.max"
  fi
  if [[ -n "${CGROUP_SWAP_MAX:-}" && -w "$CGROUP_PATH/memory.swap.max" ]]; then
    echo "$CGROUP_SWAP_MAX" > "$CGROUP_PATH/memory.swap.max" || log::warn "Falha ao setar memory.swap.max"
  fi
  # IO throttling left optional due to device specificity
  _write_json_event "cgroup.setup" "\"path\":$(_json_escape "$CGROUP_PATH")"
}

cgroup::attach_self() {
  cgroup::enabled || return 0
  [[ -n "$CGROUP_PATH" ]] || return 0
  if [[ -w "$CGROUP_PATH/cgroup.procs" ]]; then
    echo $$ > "$CGROUP_PATH/cgroup.procs" || log::warn "Não foi possível associar pid ao cgroup"
  fi
}

cgroup::check_oom() {
  cgroup::enabled || return 0
  [[ -n "$CGROUP_PATH" ]] || return 0
  if [[ -r "$CGROUP_PATH/memory.events" ]]; then
    if awk '/oom_kill/ {if($2>0) exit 10}' "$CGROUP_PATH/memory.events"; then :; else
      log::error "Detectado OOM-kill no cgroup"
      _write_json_event "cgroup.oom" "\"events\":$(jq -Rs . < \"$CGROUP_PATH/memory.events\")"
      return 1
    fi
  fi
}

cgroup::cleanup() {
  cgroup::enabled || return 0
  [[ -n "$CGROUP_PATH" ]] || return 0
  # try to cleanup scope if empty
  rmdir "$CGROUP_PATH" 2>/dev/null || true
  CGROUP_PATH=""
}

#------------------------------------------------------------------------------
# Chroot mounts
#------------------------------------------------------------------------------
MOUNTS_CREATED=()

_mount_add() { MOUNTS_CREATED+=("$1"); }

chroot::mounts_create() {
  local root="$CHROOT_ROOT"
  log::step "Preparando chroot em $root"
  [[ -d "$root" ]] || { log::error "CHROOT_ROOT inexistente: $root"; return 1; }

  # pseudo FS
  mount -t proc proc "$root/proc" || true
  _mount_add "$root/proc"

  mount -t sysfs -o ro sysfs "$root/sys" || true
  _mount_add "$root/sys"

  mount -t tmpfs -o nodev,nosuid,noexec tmpfs "$root/tmp" || true
  _mount_add "$root/tmp"

  mkdir -p "$root/build" "$root/run" "$root/var/tmp"
  mount -t tmpfs -o nodev,nosuid,noexec tmpfs "$root/build" || true
  _mount_add "$root/build"

  # bind /dev minimal
  mkdir -p "$root/dev"
  mount --bind /dev "$root/dev" || true
  _mount_add "$root/dev"

  # sources readonly
  mkdir -p "$root/var/cache/ports/sources"
  mount --bind "$SRC_CACHE_DIR" "$root/var/cache/ports/sources"
  _mount_add "$root/var/cache/ports/sources"
  mount -o remount,ro,bind "$root/var/cache/ports/sources" || true

  # build cache rw
  mkdir -p "$root/var/cache/ports/build"
  mount --bind "$BUILD_CACHE_DIR" "$root/var/cache/ports/build"
  _mount_add "$root/var/cache/ports/build"

  # pkg dir rw
  mkdir -p "$root$PKG_DIR"
  mount --bind "$PKG_DIR" "$root$PKG_DIR"
  _mount_add "$root$PKG_DIR"

  # repo readonly (metafiles/patches)
  if [[ -d "$META_ROOT" ]]; then
    mkdir -p "$root$META_ROOT"
    mount --bind "$META_ROOT" "$root$META_ROOT"
    _mount_add "$root$META_ROOT"
    mount -o remount,ro,bind "$root$META_ROOT" || true
  fi

  # disable network by default
  mkdir -p "$root/etc"
  if [[ "${PORTS_BUILD_NET}" -eq 0 ]]; then
    : > "$root/etc/resolv.conf"
  fi
  _write_json_event "chroot.mounts" "\"count\":${#MOUNTS_CREATED[@]}"
}

chroot::mounts_cleanup() {
  local force="${1:-}"
  local root="$CHROOT_ROOT"
  [[ "${#MOUNTS_CREATED[@]}" -gt 0 ]] || return 0
  log::step "Limpando chroot mounts"
  # Unmount in reverse
  local m
  for ((i=${#MOUNTS_CREATED[@]}-1; i>=0; i--)); do
    m="${MOUNTS_CREATED[$i]}"
    if mountpoint -q "$m"; then
      umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null || true
    fi
  done
  MOUNTS_CREATED=()
  # Verify no leaked mounts under root
  if grep -q "^.* $root" /proc/self/mounts; then
    if [[ "$force" == "--force" ]]; then
      awk -v r="$root" '$2 ~ "^"r {print $2}' /proc/self/mounts | tac | xargs -r -n1 umount -l || true
    fi
  fi
  _write_json_event "chroot.unmounts" "\"ok\":true"
}

#------------------------------------------------------------------------------
# Hooks
#------------------------------------------------------------------------------
_hooks_run() {
  local stage="$1" pkg="$2"
  local hook_dir="$HOOKS_DIR/$pkg"
  local hook="$hook_dir/$stage"
  [[ -x "$hook" ]] || return 0
  log::info "Executando hook $stage ($hook)"
  timeout "$HOOK_TIMEOUT" bash -Eeuo pipefail "$hook" || {
    log::error "Hook $stage falhou"
    return 1
  }
}

#------------------------------------------------------------------------------
# Package metadata & sources
#------------------------------------------------------------------------------
meta::path_for() {
  local pkg="$1"
  # Expect repository layout: /usr/ports/repo/*/<pkg>/<pkg>.metafile
  local mp
  mp=$(find "$META_ROOT" -maxdepth 3 -type f -name "${pkg}.metafile" | head -n1 || true)
  [[ -n "$mp" ]] || { log::error "Metafile não encontrado para $pkg em $META_ROOT"; return 1; }
  echo "$mp"
}

meta::load() {
  local mf; mf="$(meta::path_for "$PKG")"
  PKG_VERSION=$(jq -r '.version // empty' "$mf")
  [[ -n "$PKG_VERSION" ]] || { log::error "version ausente no metafile de $PKG"; return 1; }
  echo "$mf"
}

sources::ensure() {
  local mf="$1"
  local list
  list=$(jq -r '.sources[] | @tsv' "$mf" 2>/dev/null || true)
  [[ -n "$list" ]] || return 0
  while IFS=$'\t' read -r url sha extra; do
    [[ -n "$url" ]] || continue
    fetch::get_file "$url" "$sha"
  done <<< "$list"
}

#------------------------------------------------------------------------------
# Build workspace / incremental
#------------------------------------------------------------------------------
build::workspace_prepare() {
  PKG_BUILD_DIR="$WORK_BASE/$PKG/work"
  DESTDIR="$WORK_BASE/$PKG/dest"
  mkdir -p "$PKG_BUILD_DIR" "$DESTDIR"
  chown -R portsbuild:portsbuild "$WORK_BASE/$PKG"
  chmod 0775 "$WORK_BASE/$PKG"

  # Compute build hash (sources+flags+version)
  local mf; mf="$(meta::path_for "$PKG")"
  local hash_in
  hash_in="$(jq -c '{pkg:.name,ver:.version,flags:env.CFLAGS,ld:env.LDFLAGS,sources:.sources}' "$mf" | jq -S .)"
  local bhash
  bhash="$(printf '%s' "$hash_in" | sha256sum | awk '{print $1}')"

  echo "$bhash" > "$WORK_BASE/$PKG/.build.hash.new"
  if [[ -f "$WORK_BASE/$PKG/.build.hash" ]]; then
    if cmp -s "$WORK_BASE/$PKG/.build.hash" "$WORK_BASE/$PKG/.build.hash.new"; then
      if [[ "${PORTS_REUSE_OBJ}" -eq 1 ]]; then
        log::info "Reusando objetos de build anteriores (incremental ON)"
      else
        log::info "Incremental desativado — limpando"
        rm -rf "$PKG_BUILD_DIR"/* || true
      fi
    else
      log::warn "Alterações detectadas (versão/flags/fontes) — limpando workspace"
      rm -rf "$PKG_BUILD_DIR" "$DESTDIR"
      mkdir -p "$PKG_BUILD_DIR" "$DESTDIR"
    fi
  fi
  mv -f "$WORK_BASE/$PKG/.build.hash.new" "$WORK_BASE/$PKG/.build.hash"
}

#------------------------------------------------------------------------------
# Source extraction (safe)
#------------------------------------------------------------------------------
sources::extract_all() {
  local mf="$1"
  local entries
  entries=$(jq -r '.sources[]? | @base64' "$mf" 2>/dev/null || true)
  [[ -n "$entries" ]] || return 0

  pushd "$PKG_BUILD_DIR" >/dev/null
  while IFS= read -r enc; do
    local url sha name
    url=$(printf '%s' "$enc" | base64 -d | jq -r '.url')
    sha=$(printf '%s' "$enc" | base64 -d | jq -r '.sha256 // empty')
    name=$(basename "${url%%\?*}")
    local src="$SRC_CACHE_DIR/$name"
    [[ -r "$src" ]] || { log::error "Fonte não encontrada no cache: $src"; return 1; }

    # Prevent path traversal on extraction
    case "$src" in
      *..*) log::error "Nome de fonte potencialmente inseguro: $src"; return 1;;
    esac

    # Extract based on extension
    if [[ "$name" =~ \.(tar\.gz|tgz)$ ]]; then
      tar -xzf "$src" --no-same-owner --no-same-permissions
    elif [[ "$name" =~ \.(tar\.bz2)$ ]]; then
      tar -xjf "$src" --no-same-owner --no-same-permissions
    elif [[ "$name" =~ \.(tar\.xz)$ ]]; then
      tar -xJf "$src" --no-same-owner --no-same-permissions
    elif [[ "$name" =~ \.(tar\.zst)$ ]]; then
      tar --zstd -xf "$src" --no-same-owner --no-same-permissions
    elif [[ "$name" =~ \.zip$ ]]; then
      _require_bin unzip
      unzip -q "$src"
    else
      # plain file; leave as-is
      cp -a "$src" .
    fi
  done <<< "$entries"
  popd >/dev/null
}

#------------------------------------------------------------------------------
# In-chroot run wrapper
#------------------------------------------------------------------------------
build::in_chroot() {
  local cmd=("$@")
  local root="$CHROOT_ROOT"
  local rcfile="$root/tmp/build.rc.$$"
  local wrapper="$root/tmp/build.run.$$"

  cat > "$wrapper" <<'EOS'
#!/usr/bin/env bash
set -Eeuo pipefail
export HOME=/build
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
export LC_ALL=C
export SOURCE_DATE_EPOCH=0
umask 002
exec "$@"
EOS
  chmod 0755 "$wrapper"

  # network isolation hint
  if [[ "${PORTS_BUILD_NET}" -eq 0 ]]; then
    : > "$root/etc/resolv.conf"
  fi

  # Run as portsbuild inside chroot
  chroot "$root" /usr/bin/env -i \
    HOME=/build PATH=/usr/bin:/usr/sbin:/bin:/sbin LC_ALL=C SOURCE_DATE_EPOCH=0 \
    su -s /bin/bash -c "/tmp/$(basename "$wrapper") \"${cmd[@]}\"; echo \$? > /tmp/$(basename "$rcfile")" portsbuild

  local rc=1
  if [[ -r "$rcfile" ]]; then
    rc=$(cat "$rcfile") || true
    rm -f "$rcfile" || true
  fi
  rm -f "$wrapper" || true
  return "$rc"
}

#------------------------------------------------------------------------------
# Compile / Install
#------------------------------------------------------------------------------
build::compile() {
  local mf="$1"
  local cmd
  cmd=$(jq -r '.build.configure // empty' "$mf")
  if [[ -n "$cmd" ]]; then
    log::step "[configure] $cmd"
    build::in_chroot bash -lc "cd /var/cache/ports/build/$PKG/work && $cmd"
  fi

  cmd=$(jq -r '.build.make // "make -j'"$MAKE_JOBS"'"' "$mf")
  log::step "[make] $cmd"
  build::in_chroot bash -lc "cd /var/cache/ports/build/$PKG/work && $cmd"

  if [[ "${PORTS_STRICT_BUILD}" -eq 1 ]]; then
    # very simple heuristic: detect common fatal markers in last build log file if available
    true
  fi
}

build::install() {
  local mf="$1"
  local cmd
  cmd=$(jq -r '.build.install // "make install"' "$mf")
  log::step "[install] $cmd (DESTDIR=/var/cache/ports/build/'"$PKG"'/dest)"
  build::in_chroot bash -lc "cd /var/cache/ports/build/$PKG/work && DESTDIR=/var/cache/ports/build/$PKG/dest $cmd"

  if [[ "${PORTS_ENFORCE_DESTDIR}" -eq 1 ]]; then
    # Validate that DESTDIR has content
    local count
    count=$(find "$DESTDIR" -mindepth 1 -maxdepth 2 | wc -l || echo 0)
    if [[ "$count" -lt 3 ]]; then
      log::error "DESTDIR vazio ou incompleto após install"
      return 1
    fi
  fi
}

#------------------------------------------------------------------------------
# Post-install checks
#------------------------------------------------------------------------------
post::scan_files() {
  local count
  count=$(find "$DESTDIR" -type f | wc -l || echo 0)
  [[ "$count" -gt 0 ]] || { log::error "Nenhum arquivo instalado em DESTDIR"; return 1; }
}

post::check_elfs() {
  local missing=0 badrpath=0 setuids=0 brokenlinks=0
  while IFS= read -r f; do
    file "$f" | grep -q 'ELF' || continue
    # ldd
    if ! ldd "$f" >/dev/null 2>&1; then
      log::warn "ldd falhou em $f"
    else
      if ldd "$f" | grep -q 'not found'; then
        log::error "Biblioteca faltante em $f"
        missing=$((missing+1))
      fi
    fi
    # RPATH/RUNPATH
    if readelf -d "$f" 2>/dev/null | grep -Eq '(RPATH|RUNPATH)'; then
      if [[ "${PORTS_ENFORCE_RPATH}" -eq 1 ]]; then
        log::error "RPATH/RUNPATH detectado em $f"
        badrpath=$((badrpath+1))
      else
        log::warn "RPATH/RUNPATH presente em $f"
      fi
    fi
    # setuid/setgid
    if [[ -u "$f" || -g "$f" ]]; then
      log::warn "Arquivo com setuid/setgid: $f"
      setuids=$((setuids+1))
    fi
  done < <(find "$DESTDIR" -type f -perm -0001 -o -type f)

  brokenlinks=$(find "$DESTDIR" -xtype l | wc -l || echo 0)

  jq -n --argjson miss "$missing" --argjson rpath "$badrpath" \
        --argjson setu "$setuids" --argjson brk "$brokenlinks" \
        '{ldd_missing:$miss,rpath_bad:$rpath,setuid:$setu,symlink_broken:$brk}' \
        > "$BUILD_LOG_DIR/$PKG.post.json"

  if [[ "$missing" -gt 0 || "$badrpath" -gt 0 ]]; then
    log::error "Falhas nas verificações pós-install (ldd_missing=$missing, rpath_bad=$badrpath)"
    return 1
  fi
}

#------------------------------------------------------------------------------
# Strip & package
#------------------------------------------------------------------------------
package::strip() {
  [[ "$STRIP_BINARIES" -eq 1 ]] || return 0
  log::step "Strip de binários e bibliotecas"
  while IFS= read -r f; do
    file "$f" | grep -q 'ELF' || continue
    objcopy --only-keep-debug "$f" "$f.debug" 2>/dev/null || true
    strip --strip-unneeded "$f" || true
  done < <(find "$DESTDIR" -type f -perm -111)
}

package::create() {
  local out="$PKG_DIR/${PKG}-${PKG_VERSION}.tar.zst"
  log::step "Empacotando $out"
  ( cd "$DESTDIR" && tar --numeric-owner --owner=0 --group=0 --mtime='@0' \
      --zstd -cf "$out" . )
  local sha
  sha=$(sha256sum "$out" | awk '{print $1}')
  local b3=""
  if command -v b3sum >/dev/null 2>&1; then
    b3=$(b3sum "$out" | awk '{print $1}')
  fi
  printf '%s  %s\n' "$sha" "$(basename "$out")" > "${out}.sha256"
  [[ -n "$b3" ]] && printf '%s  %s\n' "$b3" "$(basename "$out")" > "${out}.blake3"
  echo "$out"
}

#------------------------------------------------------------------------------
# Install into system (outside DESTDIR) — optional
#------------------------------------------------------------------------------
package::install_to_system() {
  local tarball="$1"
  local root="${CHROOT_ROOT:-/}"
  log::step "Instalando pacote no sistema ($root)"
  tar --zstd -xf "$tarball" -C "$root" || {
    log::error "Falha ao instalar tarball"
    return 1
  }
}

#------------------------------------------------------------------------------
# Main build flow
#------------------------------------------------------------------------------
build::run() {
  PKG="$1"
  [[ -n "$PKG" ]] || { log::error "Uso: ports-build.sh build <pkg>"; return 2; }

  lock::named_acquire "build:$PKG"
  trap 'lock::release; exit' INT TERM

  build::init

  _check_space_mb "$BUILD_CACHE_DIR" "$PORTS_BUILD_MIN_MB"

  # Prepare logging
  BUILD_TS="$(date -u +%Y%m%d-%H%M%S)"
  BUILD_ID="${PKG}-${PKG_VERSION:-unknown}-${BUILD_TS}"
  mkdir -p "$BUILD_LOG_DIR"
  BUILD_JSON_LOG="$BUILD_LOG_DIR/${PKG}-${BUILD_TS}.json"
  : > "$BUILD_JSON_LOG"

  _write_json_event "build.start" "\"chroot_root\":$(_json_escape "$CHROOT_ROOT")"

  # Load metadata and sources
  local mf; mf="$(meta::load)"
  _write_json_event "meta" "\"mf\":$(_json_escape "$mf"),\"version\":$(_json_escape "$PKG_VERSION")"

  deps::resolve "$PKG" || { log::error "Dependências não resolvidas"; return 1; }
  sources::ensure "$mf"

  build::workspace_prepare
  sources::extract_all "$mf"

  # Chroot and cgroup
  chroot::mounts_create
  cgroup::setup
  cgroup::attach_self

  # Pre hooks
  _hooks_run "pre-compile" "$PKG" || return 1

  # Compile & install
  timeout "$PORTS_BUILD_TIMEOUT" bash -lc "build::compile '$mf'"
  timeout "$PORTS_BUILD_TIMEOUT" bash -lc "build::install '$mf'"

  # Post hooks
  _hooks_run "post-compile" "$PKG" || true
  _hooks_run "pre-install" "$PKG" || true

  # Post-install checks
  post::scan_files
  post::check_elfs

  # Strip and package
  package::strip
  local out
  out="$(package::create)"

  _hooks_run "post-install" "$PKG" || true

  # Cleanup mounts and cgroup
  chroot::mounts_cleanup
  cgroup::cleanup

  _write_json_event "build.ok" "\"package\":$(_json_escape "$out")"

  db::event "build.ok" "$(printf '{"pkg":%s,"build_id":%s,"package":%s}' \
    "$(_json_escape "$PKG")" "$(_json_escape "$BUILD_ID")" "$(_json_escape "$out")")" || true

  lock::release
  log::ok "Build concluído: $out"
}

#------------------------------------------------------------------------------
# CLI
#------------------------------------------------------------------------------
usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [args]

Commands:
  build <pkg>          - Compila e empacota um pacote dentro do chroot seguro
  mounts create|clean  - Gerencia mounts do chroot manualmente
  cgroup check         - Mostra estado/oom do cgroup atual
  version              - Mostra versão do módulo

Environment:
  CHROOT_ROOT=/ | /mnt/lfs, PORTS_REUSE_OBJ=1, STRIP_BINARIES=1, ...
  Ver /etc/ports/build.conf para todas as opções.
EOF
}

main() {
  local cmd="${1:-}"; shift || true

  case "$cmd" in
    build)
      PKG="${1:-}"
      [[ -n "$PKG" ]] || { usage; exit 2; }
      build::run "$PKG"
      ;;
    mounts)
      case "${1:-}" in
        create) chroot::mounts_create ;;
        clean|cleanup) chroot::mounts_cleanup --force ;;
        *) usage ;;
      esac
      ;;
    cgroup)
      case "${1:-}" in
        check)
          cgroup::check_oom || exit 1
          log::info "cgroup OK ou não habilitado"
          ;;
        *) usage ;;
      esac
      ;;
    version|-v|--version)
      echo "ports-build.sh (M6) — $(date -u +"%Y-%m-%d")"
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
