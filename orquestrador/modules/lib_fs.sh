#!/usr/bin/env bash
# lib_fs.sh - Módulo de filesystem e chroot para LFS build system
# Versão: 1.0
# Funções: montagem/desmontagem seguras de chroot, bind mounts, verificação, recuperação,
#          snapshot (btrfs), audit trail, filesystem metrics, locks robustos, limpeza, utilitários.
#
# Dependências (mínimas): bash >= 4, coreutils (mount/umount/mkdir/rm/stat), awk, grep, sed, df, du
# Dependências opcionais: logger, zstd, btrfs-progs, iostat (sysstat), realpath
#
# Uso:
#   source /path/to/lib_common.sh    # obrigatório
#   source /path/to/lib_fs.sh
#   fs_init                             # configura diretórios e options
#   fs_mount_chroot /srv/lfs-chroots/build-001 /mnt/lfs
#
set -o errtrace
set -o pipefail

# -------- Defaults / configuration (podem ser alteradas antes do fs_init) ----------
: "${FS_BASE_DIR:=/srv/lfs-chroots}"        # base para chroots
: "${FS_LOCK_DIR:=/var/lock/lfsports}"      # locks
: "${FS_AUDIT_DIR:=/var/log/lfsports/fs-audit}" # audit trail logs
: "${FS_TMP_PREFIX:=lfsfs-}"                # prefix para mktemp
: "${FS_MOUNT_RETRY:=5}"                    # tentativas de ummount/umount busy
: "${FS_MOUNT_RETRY_SLEEP:=1}"              # sleep entre retries
: "${FS_USE_BTRFS_SNAPSHOT:=1}"             # usar snapshot se btrfs disponível
: "${FS_ALLOWED_PREFIXES:=/mnt/lfs:/srv/lfs-chroots}" # locais que podemos desmontar; colon-separated
: "${FS_MAKE_RPRIVATE:=1}"                  # executar mount --make-rprivate on chroot parent
: "${FS_NOEXEC_NOSUID_NODEV:=1}"            # aplicar flags a bind mounts quando aplica
: "${FS_UMOUNT_LAZY_FALLBACK:=1}"           # fallback para ummount -l se busy
: "${FS_MAX_LOCK_AGE:=900}"                 # 15 minutes for stale lock TTL
: "${FS_CHROOT_USER:=lfsbuild}"             # recommended build user created outside
# ------------------------------------------------------------------------------------

# ---- internal state ----
_FS_INITED=0
_FS_BASE_DIR=""
_FS_LOCK_DIR=""
_FS_AUDIT_DIR=""
_FS_TMPDIRS=()
_FS_ACTIVE_CHROOTS=()   # list of chroot roots currently mounted (tracking)
LOCKFILES=()

# --- Ensure lib_common functions exist; provide minimal fallbacks if absent ----
if ! declare -f log_info >/dev/null 2>&1; then
  log_info()  { printf '[%s] [INFO] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
  log_warn()  { printf '[%s] [WARN] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
  log_error() { printf '[%s] [ERROR] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fi
if ! declare -f safe_run >/dev/null 2>&1; then
  safe_run() { "$@"; return $?; }
fi
if ! declare -f with_lock >/dev/null 2>&1; then
  # simple fallback lock: mkdir-based
  with_lock() {
    local name="$1"; shift
    local lockdir="${FS_LOCK_DIR:-/tmp}/$name"
    local tries=0
    until mkdir -p "$lockdir" 2>/dev/null; do
      sleep 0.1
      ((tries++)) || true
      if (( tries > 600 )); then
        log_error "with_lock fallback: timeout acquiring lock $lockdir"
        return 1
      fi
    done
    printf "%s\n" "$$" > "$lockdir/pid"
    "$@"
    local rc=$?
    rm -rf "$lockdir" 2>/dev/null || true
    return $rc
  }
fi

# --- Utility helpers ------------------------------------------------------------

_fs_join_prefixes() {
  # check if path under any allowed prefix
  local path="$1"
  IFS=':' read -r -a prefixes <<< "$FS_ALLOWED_PREFIXES"
  for p in "${prefixes[@]}"; do
    if command -v realpath >/dev/null 2>&1; then
      local rp rp_p
      rp="$(realpath -e "$path" 2>/dev/null || true)"
      rp_p="$(realpath -e "$p" 2>/dev/null || true)"
      [[ -n "$rp" && -n "$rp_p" ]] && [[ "$rp" == "$rp_p"* ]] && return 0
    else
      [[ "$path" == "$p"* ]] && return 0
    fi
  done
  return 1
}

_fs_mkdirp() {
  local d="$1"
  if [[ ! -d "$d" ]]; then
    safe_run "mkdir -p $d" mkdir -p "$d" || return 1
  fi
  return 0
}

_fs_assert_root() {
  if (( EUID != 0 )); then
    log_error "fs: operação requer root. Execute como root ou use sudo."
    return 1
  fi
  return 0
}

_fs_lockfile_path() {
  local name="$1"
  mkdir -p "${FS_LOCK_DIR:-/var/lock/lfsports}" 2>/dev/null || true
  echo "${FS_LOCK_DIR:-/var/lock/lfsports}/${name}.lock"
}

_fs_acquire_lock() {
  # robust pid lock with stale check
  local name="$1"
  local lockfile; lockfile="$(_fs_lockfile_path "$name")"
  local now pid ts
  now=$(date +%s)
  if [[ -f "$lockfile" ]]; then
    read -r pid ts < <(awk '{print $1, $2}' "$lockfile" 2>/dev/null || echo "")
    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
      log_warn "fs: lock $name held by pid $pid (started $ts). Waiting..."
      local waited=0
      while [[ -f "$lockfile" && -d "/proc/$pid" ]]; do
        sleep 0.2; waited=$((waited+1))
        if (( waited > 600 )); then
          log_warn "fs: waited too long for lock $name (pid $pid); checking stale..."
          break
        fi
      done
    fi
    if [[ -f "$lockfile" ]]; then
      read -r pid ts < <(awk '{print $1, $2}' "$lockfile" 2>/dev/null || echo "")
      if [[ -n "$ts" ]]; then
        local age=$((now - ts))
        if (( age > FS_MAX_LOCK_AGE )); then
          log_warn "fs: removing stale lock $name (pid $pid age ${age}s)"
          rm -f "$lockfile" 2>/dev/null || true
        else
          sleep 0.5
        fi
      else
        rm -f "$lockfile" 2>/dev/null || true
      fi
    fi
  fi
  printf "%s %s\n" "$$" "$(date +%s)" > "$lockfile"
  LOCKFILES+=("$lockfile")
  return 0
}

_fs_release_lock() {
  local name="$1"
  local lockfile; lockfile="$(_fs_lockfile_path "$name")"
  [[ -f "$lockfile" ]] && rm -f "$lockfile" 2>/dev/null || true
  local nf=(); for f in "${LOCKFILES[@]:-}"; do [[ "$f" != "$lockfile" ]] && nf+=("$f"); done
  LOCKFILES=("${nf[@]}")
}

_fs_audit_write() {
  # Audit trail write: structured line with timestamp, op, chroot, details
  local op="$1"; local chroot="$2"; local details="$3"
  mkdir -p "${FS_AUDIT_DIR:-/var/log/lfsports/fs-audit}" 2>/dev/null || true
  local file="${FS_AUDIT_DIR:-/var/log/lfsports/fs-audit}/$(date +%Y-%m-%d).log"
  local ts; ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local jmsg
  jmsg=$(printf '%s' "$details" | awk 'BEGIN{gsub("\n","\\n")}{gsub(/"/,"\\\""); print}')
  printf '{"ts":"%s","op":"%s","chroot":"%s","pid":%s,"user":"%s","details":"%s"}\n' \
    "$ts" "$op" "$chroot" "$$" "$(id -un 2>/dev/null || echo unknown)" "$jmsg" >> "$file"
  if declare -f log_info >/dev/null 2>&1; then
    log_info "AUDIT $op chroot=$chroot details=$(echo "$details" | tr '\n' ' ' | cut -c1-200)"
  else
    printf '[%s] [AUDIT] %s %s\n' "$ts" "$op" "$details"
  fi
}

# --- Filesystem metrics -------------------------------------------------------
fs_collect_fs_metrics() {
  # Collect df, du, inodes, optionally iostat stats
  local target="$1"
  local out
  out="$(mktemp -t lfs-fsmetrics-XXXXXX)" || out="/tmp/lfs-fsmetrics.$$"
  {
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "target: $target"
    echo "--- df -h ---"
    df -h "$target" 2>/dev/null || df -h 2>/dev/null || true
    echo "--- du (top 10) ---"
    du -x "$target" 2>/dev/null | sort -nr | head -n 10 || true
    echo "--- inodes (df -i) ---"
    df -i "$target" 2>/dev/null || true
    if command -v iostat >/dev/null 2>&1; then
      echo "--- iostat (1 1) ---"
      iostat 1 1 2>/dev/null || true
    fi
    if [[ -r /proc/diskstats ]]; then
      echo "--- /proc/diskstats (top devices) ---"
      awk '{print $3, $4, $5, $6, $7, $8, $9}' /proc/diskstats | head -n 10 || true
    fi
  } >> "$out"
  local details; details=$(sed ':a;N;$!ba;s/\n/\\n/g' "$out")
  _fs_audit_write "fs_metrics" "$target" "$details"
  cat "$out"
  rm -f "$out" 2>/dev/null || true
}

# --- chroot mount helpers -----------------------------------------------------

fs_init() {
  # initialize directories, validate permissions
  if (( _FS_INITED )); then return 0; fi
  _FS_INITED=1
  FS_BASE_DIR="${FS_BASE_DIR:-$FS_BASE_DIR}"
  FS_LOCK_DIR="${FS_LOCK_DIR:-$FS_LOCK_DIR}"
  FS_AUDIT_DIR="${FS_AUDIT_DIR:-$FS_AUDIT_DIR}"
  mkdir -p "$FS_BASE_DIR" 2>/dev/null || true
  mkdir -p "$FS_LOCK_DIR" 2>/dev/null || true
  mkdir -p "$FS_AUDIT_DIR" 2>/dev/null || true
  chmod 0755 "$FS_LOCK_DIR" 2>/dev/null || true
  log_info "fs_init: base=$FS_BASE_DIR lockdir=$FS_LOCK_DIR audit=$FS_AUDIT_DIR"
  return 0
}

fs_bind_mount() {
  # usage: fs_bind_mount <src> <dest> [ro]
  local src="$1" dest="$2" ro="${3:-}"
  if [[ -z "$src" || -z "$dest" ]]; then
    log_error "fs_bind_mount: src and dest required"
    return 1
  fi
  _fs_mkdirp "$dest" || return 1
  log_info "fs_bind_mount: bind $src -> $dest"
  safe_run "mount --rbind $src $dest" mount --rbind "$src" "$dest" || {
    log_warn "fs_bind_mount: mount --rbind failed for $src -> $dest, attempting fallback"
    safe_run "mount --bind $src $dest" mount --bind "$src" "$dest" || return 1
  }
  if [[ "$FS_MAKE_RPRIVATE" == "1" ]]; then
    safe_run "mount --make-rslave $dest" mount --make-rslave "$dest" || true
  fi
  if [[ -n "$ro" && "$ro" == "ro" ]]; then
    safe_run "mount -o remount,ro,bind $dest" mount -o remount,ro,bind "$dest" || true
  fi
  if [[ "$FS_NOEXEC_NOSUID_NODEV" == "1" ]]; then
    safe_run "mount -o remount,nosuid,nodev,noexec $dest" mount -o remount,nosuid,nodev,noexec "$dest" 2>/dev/null || true
  fi
  return 0
}

fs_safe_umount() {
  # usage: fs_safe_umount <mountpoint>
  local mnt="$1"
  if [[ -z "$mnt" ]]; then
    log_error "fs_safe_umount: mountpoint required"
    return 1
  fi
  if ! _fs_join_prefixes "$mnt"; then
    log_warn "fs_safe_umount: refusing to unmount outside allowed prefixes: $mnt"
    return 1
  fi
  local attempt=1
  while (( attempt <= FS_MOUNT_RETRY )); do
    if umount "$mnt" 2>/dev/null; then
      log_info "fs_safe_umount: umounted $mnt (attempt $attempt)"
      return 0
    fi
    if (( FS_UMOUNT_LAZY_FALLBACK )); then
      log_warn "fs_safe_umount: umount busy for $mnt; trying lazy umount -l"
      if umount -l "$mnt" 2>/dev/null; then
        log_info "fs_safe_umount: lazy umount succeeded for $mnt"
        return 0
      fi
    fi
    sleep "$FS_MOUNT_RETRY_SLEEP"
    attempt=$((attempt+1))
  done
  log_error "fs_safe_umount: failed to unmount $mnt after $FS_MOUNT_RETRY attempts"
  return 1
}

fs_mount_chroot() {
  # usage: fs_mount_chroot <chroot_dir> <destdir_in_chroot (optional)>
  local chroot_dir="$1"
  local destdir="${2:-/}"
  if [[ -z "$chroot_dir" ]]; then
    log_error "fs_mount_chroot: chroot_dir required"
    return 1
  fi
  _fs_assert_root || return 1
  if ! _fs_join_prefixes "$chroot_dir"; then
    log_error "fs_mount_chroot: chroot_dir $chroot_dir not under allowed prefixes ($FS_ALLOWED_PREFIXES)"
    return 1
  fi
  _fs_acquire_lock "chroot-$(echo "$chroot_dir" | sed 's/\//_/g')"
  _fs_audit_write "mount_start" "$chroot_dir" "dest=$destdir"
  _fs_mkdirp "$chroot_dir" || { _fs_release_lock "chroot-$(echo "$chroot_dir" | sed 's/\//_/g')"; return 1; }

  for p in dev dev/pts proc sys run tmp mnt; do _fs_mkdirp "$chroot_dir/$p" || true; done

  # core binds
  fs_bind_mount /dev "$chroot_dir/dev" || true
  fs_bind_mount /dev/pts "$chroot_dir/dev/pts" || true
  if [[ -d /proc ]]; then
    safe_run "mount --bind /proc $chroot_dir/proc" mount --bind /proc "$chroot_dir/proc" || true
  fi
  if [[ -d /sys ]]; then
    safe_run "mount --bind /sys $chroot_dir/sys" mount --bind /sys "$chroot_dir/sys" || true
  fi
  if [[ -d /run ]]; then
    safe_run "mount --bind /run $chroot_dir/run" mount --bind /run "$chroot_dir/run" || true
  fi

  # optional sources cache
  if [[ -d "${FS_BASE_DIR}/sources" ]]; then
    fs_bind_mount "${FS_BASE_DIR}/sources" "$chroot_dir/sources" || true
  fi

  # resolv/hosts
  if [[ -f /etc/resolv.conf && ! -L "$chroot_dir/etc/resolv.conf" ]]; then
    _fs_mkdirp "$chroot_dir/etc"
    cp -L /etc/resolv.conf "$chroot_dir/etc/resolv.conf" 2>/dev/null || true
  fi
  if [[ -f /etc/hosts && ! -L "$chroot_dir/etc/hosts" ]]; then
    cp -L /etc/hosts "$chroot_dir/etc/hosts" 2>/dev/null || true
  fi

  if (( FS_MAKE_RPRIVATE )); then
    local parent
    parent="$(dirname "$chroot_dir")"
    safe_run "mount --make-rprivate $parent" mount --make-rprivate "$parent" || true
  fi

  _FS_ACTIVE_CHROOTS+=("$chroot_dir")
  _fs_audit_write "mount_done" "$chroot_dir" "dest=$destdir"
  _fs_release_lock "chroot-$(echo "$chroot_dir" | sed 's/\//_/g')"
  log_info "fs_mount_chroot: mounted chroot $chroot_dir"
  return 0
}

fs_umount_chroot() {
  # usage: fs_umount_chroot <chroot_dir>
  local chroot_dir="$1"
  if [[ -z "$chroot_dir" ]]; then
    log_error "fs_umount_chroot: chroot_dir required"
    return 1
  fi
  _fs_acquire_lock "chroot-$(echo "$chroot_dir" | sed 's/\//_/g')"
  _fs_audit_write "umount_start" "$chroot_dir" ""
  local mnts=( "$chroot_dir/run" "$chroot_dir/proc" "$chroot_dir/sys" "$chroot_dir/dev/pts" "$chroot_dir/dev" "$chroot_dir/sources" )
  for m in "${mnts[@]}"; do
    if mountpoint -q "$m"; then
      log_info "fs_umount_chroot: unmounting $m"
      fs_safe_umount "$m" || log_warn "fs_umount_chroot: failed to unmount $m (continuing)"
    fi
  done
  for p in proc sys run dev dev/pts sources; do
    local d="$chroot_dir/$p"
    if [[ -d "$d" && -z "$(ls -A "$d" 2>/dev/null)" ]]; then
      rmdir "$d" 2>/dev/null || true
    fi
  done

  local newlist=()
  for c in "${_FS_ACTIVE_CHROOTS[@]:-}"; do [[ "$c" != "$chroot_dir" ]] && newlist+=("$c"); done
  _FS_ACTIVE_CHROOTS=("${newlist[@]}")

  _fs_audit_write "umount_done" "$chroot_dir" ""
  _fs_release_lock "chroot-$(echo "$chroot_dir" | sed 's/\//_/g')"
  log_info "fs_umount_chroot: umount process for $chroot_dir finished"
  return 0
}

# --- Orphan / recovery --------------------------------------------------------
fs_check_mounts() {
  mount | awk -v base="$FS_BASE_DIR" '$3 ~ base {print $0}'
}

fs_recover_orphans() {
  log_info "fs_recover_orphans: scanning for orphan mounts under $FS_BASE_DIR"
  local line mpoint
  while IFS= read -r line; do
    mpoint=$(awk '{print $3}' <<<"$line")
    if [[ -n "$mpoint" ]]; then
      log_warn "fs_recover_orphans: attempting to unmount orphan $mpoint"
      fs_safe_umount "$mpoint" || {
        log_warn "fs_recover_orphans: lazy unmount fallback for $mpoint"
        if (( FS_UMOUNT_LAZY_FALLBACK )); then
          umount -l "$mpoint" 2>/dev/null || true
        fi
      }
    fi
  done < <(fs_check_mounts)
  log_info "fs_recover_orphans: done"
}

# --- Validation & integrity ---------------------------------------------------
fs_verify_integrity() {
  local chroot="$1"
  local missing=0
  for p in bin etc lib usr; do
    if [[ ! -e "$chroot/$p" ]]; then
      log_warn "fs_verify_integrity: $chroot missing $p"
      missing=$((missing+1))
    fi
  done
  if (( missing > 0 )); then
    log_warn "fs_verify_integrity: $chroot appears incomplete"
    return 1
  fi
  log_info "fs_verify_integrity: $chroot looks ok"
  return 0
}

fs_validate_destdir() {
  local dest="$1"
  if [[ -z "$dest" ]]; then
    log_error "fs_validate_destdir: dest required"
    return 1
  fi
  if [[ "$dest" != /* ]]; then
    log_error "fs_validate_destdir: must be absolute path"
    return 1
  fi
  if ! _fs_join_prefixes "$dest"; then
    log_error "fs_validate_destdir: $dest not under allowed prefixes"
    return 1
  fi
  return 0
}

# --- Snapshot (btrfs optional) ------------------------------------------------
fs_snapshot_create() {
  local src="$1" snap="$2"
  if (( FS_USE_BTRFS_SNAPSHOT )) && command -v btrfs >/dev/null 2>&1; then
    if ! mountpoint -q "$src"; then
      log_warn "fs_snapshot_create: $src is not a btrfs mountpoint; snapshot skipped"
      return 1
    fi
    _fs_mkdirp "$(dirname "$snap")" || true
    log_info "fs_snapshot_create: creating btrfs snapshot $snap -> $src"
    safe_run "btrfs subvolume snapshot -r $src $snap" btrfs subvolume snapshot -r "$src" "$snap" || {
      log_warn "fs_snapshot_create: snapshot command failed"
      return 1
    }
    _fs_audit_write "snapshot_create" "$src" "snap=$snap"
    return 0
  else
    log_info "fs_snapshot_create: btrfs not available or disabled; skipping snapshot"
    return 0
  fi
}

fs_snapshot_destroy() {
  local snap="$1"
  if (( FS_USE_BTRFS_SNAPSHOT )) && command -v btrfs >/dev/null 2>&1; then
    log_info "fs_snapshot_destroy: destroying snapshot $snap"
    safe_run "btrfs subvolume delete $snap" btrfs subvolume delete "$snap" || true
    _fs_audit_write "snapshot_destroy" "$snap" ""
    return 0
  fi
  return 0
}

# --- Utilities & reporting ---------------------------------------------------
fs_report_usage() {
  local target="${1:-/}"
  log_info "fs_report_usage: collecting disk usage for $target"
  fs_collect_fs_metrics "$target" | while IFS= read -r line; do log_info "$line"; done
}

fs_cleanup_all() {
  log_info "fs_cleanup_all: unmounting all active chroots"
  for ch in "${_FS_ACTIVE_CHROOTS[@]:-}"; do
    fs_umount_chroot "$ch" || log_warn "fs_cleanup_all: failed to unmount $ch (continuing)"
  done
  fs_recover_orphans
  for t in "${_FS_TMPDIRS[@]:-}"; do rm -rf "$t" 2>/dev/null || true; done
  log_info "fs_cleanup_all: done"
}

trap 'fs_cleanup_all' EXIT INT TERM

# export functions
export -f fs_init fs_bind_mount fs_mount_chroot fs_umount_chroot fs_safe_umount fs_check_mounts \
  fs_recover_orphans fs_verify_integrity fs_validate_destdir fs_snapshot_create \
  fs_snapshot_destroy fs_report_usage fs_collect_fs_metrics fs_cleanup_all

log_info "lib_fs.sh loaded. Call fs_init to setup. (Version 1.0)"
