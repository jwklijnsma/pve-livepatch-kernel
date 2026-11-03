#!/usr/bin/env bash
# =============================================================================
# pve-livepatch.sh — live patch the running kernel WITHOUT a reboot on
#                    Proxmox VE and Ubuntu, using kpatch (dynup/kpatch).
#                    On Ubuntu it can also drive Canonical Livepatch.
#
# Workflow (kpatch, custom patches):
#   1. check    – verify the running kernel can be live patched
#   2. setup    – install build deps + kpatch / kpatch-build
#   3. source   – fetch the EXACT kernel source for `uname -r`
#                   Proxmox VE: pve-kernel git @ matching "bump version" commit
#                               + Proxmox kernel patches
#                   Ubuntu:     `apt-get source` of the running kernel package
#   4. build    – turn a source .patch (file or URL) into livepatch-<name>.ko
#   5. apply    – load the module into the running kernel (optionally persist)
#
# Ubuntu only (official fixes, no build needed):
#   canonical enable|status|disable – Canonical Livepatch via Ubuntu Pro
#
# Notes:
#   * Run as root (or on a test host running the IDENTICAL kernel and gcc —
#     strongly recommended; build there, apply in production later).
#   * First build compiles the full original kernel: ~30 GB disk, 30–90 min.
#   * kpatch builds "atomic replace" patches by default: loading a new patch
#     REPLACES all previously loaded live patches (including Canonical's!),
#     so make each patch cumulative — or pass --non-replace.
#   * Not every change is live-patchable (struct/layout changes, __init code,
#     some asm). kpatch-build refuses those; fall back to migrate + reboot.
# =============================================================================
set -Eeuo pipefail

readonly SCRIPT_VERSION="1.1.0"
readonly WORKDIR="${PVE_LIVEPATCH_DIR:-/var/lib/pve-livepatch}"
readonly PVE_KERNEL_REPO="${PVE_KERNEL_REPO:-https://git.proxmox.com/git/pve-kernel.git}"
readonly KPATCH_REPO="${KPATCH_REPO:-https://github.com/dynup/kpatch.git}"
readonly KPATCH_REF="${KPATCH_REF:-master}"
KREL="$(uname -r)"; readonly KREL
readonly KCONFIG="/boot/config-${KREL}"
JOBS="${JOBS:-$(nproc)}"
ASSUME_YES=0

# ----------------------------------------------------------------------------- helpers
if [[ -t 1 ]]; then C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[34m'; C_0=$'\e[0m'
else C_R=; C_G=; C_Y=; C_B=; C_0=; fi
log()  { printf '%s==>%s %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '  %s✔%s %s\n'  "$C_G" "$C_0" "$*"; }
warn() { printf '  %s!%s %s\n'  "$C_Y" "$C_0" "$*" >&2; }
bad()  { printf '  %s✘%s %s\n'  "$C_R" "$C_0" "$*" >&2; }
die()  { printf '%sERROR:%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO: $BASH_COMMAND"' ERR

need_root() { [[ $EUID -eq 0 ]] || die "run as root"; }
need_cmd()  { command -v "$1" >/dev/null 2>&1 || die "'$1' not found — run: $0 setup"; }

confirm() {
  (( ASSUME_YES )) && return 0
  local a; read -r -p "$1 [y/N] " a
  [[ $a =~ ^[Yy]$ ]]
}

cfg_val() { grep -E "^$1=" "$KCONFIG" 2>/dev/null | cut -d= -f2- || true; }
src_dir() { echo "${WORKDIR}/src/${KREL}"; }

secure_boot_on() {
  command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null | grep -qi 'enabled'
}

# ----------------------------------------------------------------------------- platform
# PLATFORM = pve | ubuntu
detect_platform() {
  if [[ -n ${PLATFORM:-} ]]; then :
  elif command -v pveversion >/dev/null 2>&1 || [[ $KREL == *-pve ]]; then PLATFORM=pve
  elif [[ -r /etc/os-release ]] && grep -qE '^ID=ubuntu$' /etc/os-release; then PLATFORM=ubuntu
  else die "unsupported platform (need Proxmox VE or Ubuntu); override with PLATFORM=pve|ubuntu"
  fi
  case $PLATFORM in
    pve)    MOK_KEY="${MOK_KEY:-/var/lib/dkms/mok.key}"
            MOK_CERT="${MOK_CERT:-/var/lib/dkms/mok.pub}" ;;
    ubuntu) MOK_KEY="${MOK_KEY:-/var/lib/shim-signed/mok/MOK.priv}"
            MOK_CERT="${MOK_CERT:-/var/lib/shim-signed/mok/MOK.der}" ;;
    *)      die "PLATFORM must be pve or ubuntu" ;;
  esac
  readonly PLATFORM MOK_KEY MOK_CERT
}

platform_name() {
  case $PLATFORM in
    pve)    command -v pveversion >/dev/null 2>&1 && pveversion || echo "Proxmox VE" ;;
    ubuntu) . /etc/os-release && echo "${PRETTY_NAME}" ;;
  esac
}

# live patches loaded that were NOT built by kpatch (e.g. Canonical's lkp_*)
foreign_patches() {
  local d n
  for d in /sys/kernel/livepatch/*/; do
    [[ -d $d ]] || continue
    n=$(basename "$d")
    [[ $n == livepatch_* ]] || echo "$n"
  done
}

# ----------------------------------------------------------------------------- check
cmd_check() {
  local fail=0
  log "Checking live-patch readiness for kernel ${KREL} (${PLATFORM})"
  ok "$(platform_name)"

  case $PLATFORM in
    pve)    [[ $KREL == *-pve ]] && ok "running a Proxmox kernel" || warn "kernel release does not end in -pve" ;;
    ubuntu) [[ $KREL =~ -(generic|lowlatency|virtual|kvm|aws|azure|gcp|oracle) ]] \
              && ok "running an Ubuntu kernel flavour" || warn "unusual Ubuntu kernel flavour: ${KREL}" ;;
  esac

  [[ -r $KCONFIG ]] || die "kernel config $KCONFIG not found"

  [[ $(cfg_val CONFIG_LIVEPATCH) == y ]] && ok "CONFIG_LIVEPATCH=y" \
    || { bad "CONFIG_LIVEPATCH not enabled — this kernel cannot be live patched"; fail=1; }
  if [[ $(cfg_val CONFIG_DYNAMIC_FTRACE_WITH_REGS) == y || $(cfg_val CONFIG_DYNAMIC_FTRACE_WITH_ARGS) == y ]]; then
    ok "dynamic ftrace (WITH_REGS/ARGS) available"
  else bad "dynamic ftrace with regs/args missing"; fail=1; fi
  [[ $(cfg_val CONFIG_HAVE_RELIABLE_STACKTRACE) == y ]] && ok "reliable stacktrace (consistency model)" \
    || warn "no reliable stacktrace — patch transitions may stall"
  [[ $(cfg_val CONFIG_KALLSYMS_ALL) == y ]] && ok "CONFIG_KALLSYMS_ALL=y" || warn "CONFIG_KALLSYMS_ALL not set"
  [[ -d /sys/kernel/livepatch ]] && ok "/sys/kernel/livepatch present" \
    || { bad "/sys/kernel/livepatch missing"; fail=1; }

  # compiler must match the one that built the running kernel
  local kgcc lgcc
  kgcc=$(sed -n 's/.*(gcc[^)]*) \([0-9][0-9.]*\).*/\1/p' /proc/version)
  lgcc=$(gcc -dumpfullversion 2>/dev/null || echo "none")
  if [[ -n $kgcc && $kgcc == "$lgcc" ]]; then ok "gcc ${lgcc} matches kernel build compiler"
  else bad "gcc mismatch: kernel built with '${kgcc:-?}', local gcc is '${lgcc}'"; fail=1; fi

  # secure boot / module signing
  if secure_boot_on; then
    warn "Secure Boot enabled — patch modules must be signed with an enrolled MOK key"
    [[ -r $MOK_KEY && -r $MOK_CERT ]] && ok "MOK key found (${MOK_KEY}) — build will sign modules" \
      || { bad "no MOK key at ${MOK_KEY}; set MOK_KEY/MOK_CERT"; fail=1; }
  else ok "Secure Boot off — unsigned modules can load"
  fi
  [[ -r /sys/kernel/security/lockdown ]] && ok "lockdown: $(< /sys/kernel/security/lockdown)"

  if [[ $PLATFORM == ubuntu ]] && command -v canonical-livepatch >/dev/null 2>&1; then
    warn "Canonical Livepatch is installed — kpatch atomic-replace patches would replace its fixes"
  fi

  local disk; disk=$(df -BG --output=avail "$(dirname "$WORKDIR")" | tail -1 | tr -dc 0-9)
  (( disk >= 30 )) && ok "${disk}G free for ${WORKDIR}" || warn "only ${disk}G free — build needs ~30G"

  command -v kpatch-build >/dev/null 2>&1 && ok "kpatch-build installed" || warn "kpatch not installed (run: $0 setup)"

  cmd_status || true
  (( fail == 0 )) && log "${C_G}Ready.${C_0}" || die "host is not ready for live patching (see above)"
}

# ----------------------------------------------------------------------------- setup
cmd_setup() {
  need_root
  log "Installing build dependencies"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends \
    git build-essential bc bison flex cpio rsync kmod curl ca-certificates \
    libelf-dev libdw-dev elfutils libssl-dev dwarves python3 zstd pkg-config \
    mokutil dpkg-dev

  log "Building kpatch (${KPATCH_REF}) from ${KPATCH_REPO}"
  mkdir -p "$WORKDIR"
  if [[ -d $WORKDIR/kpatch/.git ]]; then
    git -C "$WORKDIR/kpatch" fetch --quiet origin
  else
    git clone --quiet "$KPATCH_REPO" "$WORKDIR/kpatch"
  fi
  git -C "$WORKDIR/kpatch" checkout --quiet "$KPATCH_REF"
  git -C "$WORKDIR/kpatch" pull --quiet --ff-only 2>/dev/null || true
  make -C "$WORKDIR/kpatch" -j"$JOBS"
  make -C "$WORKDIR/kpatch" install
  systemctl daemon-reload || true
  ok "kpatch $(kpatch version 2>/dev/null || echo installed)"
}

# ----------------------------------------------------------------------------- source
running_kernel_pkg() {
  local pkg
  pkg=$(dpkg -S "/boot/vmlinuz-${KREL}" 2>/dev/null | cut -d: -f1 | head -1)
  [[ -n $pkg ]] || die "cannot find the package owning /boot/vmlinuz-${KREL}"
  echo "$pkg"
}

# finalise a prepared tree: make `make kernelrelease` == uname -r (vermagic)
finalise_tree() {
  local src=$1 extra="-${KREL#*-}" rel
  sed -i "s/^EXTRAVERSION =.*/EXTRAVERSION = ${extra}/" "$src/Makefile"
  : > "$src/.scmversion"
  cp "$KCONFIG" "$src/.config"
  make -C "$src" -s olddefconfig >/dev/null
  rel=$(make -C "$src" -s kernelrelease)
  [[ $rel == "$KREL" ]] || die "source kernelrelease '${rel}' != running '${KREL}'"
  ok "source tree matches ${KREL}"
}

source_pve() {
  local pkg pkgver repo commit src p n=0
  pkg=$(running_kernel_pkg)
  pkgver=$(dpkg-query -W -f='${Version}' "$pkg")
  log "Running kernel package: ${pkg} ${pkgver}"

  repo="${WORKDIR}/pve-kernel"
  if [[ -d $repo/.git ]]; then
    log "Updating pve-kernel repository"
    git -C "$repo" fetch --quiet --all --tags
  else
    log "Cloning ${PVE_KERNEL_REPO}"
    git clone --quiet "$PVE_KERNEL_REPO" "$repo"
  fi

  if [[ -n ${PVE_COMMIT:-} ]]; then
    commit=$PVE_COMMIT
  else
    commit=$(git -C "$repo" log --all --format='%H%x09%s' -F --grep="bump version to ${pkgver}" \
             | awk -F'\t' -v s="bump version to ${pkgver}" '$2==s {print $1; exit}')
  fi
  [[ -n $commit ]] || die "no 'bump version to ${pkgver}' commit found; set PVE_COMMIT=<sha> manually"
  ok "pve-kernel commit ${commit:0:12}"

  git -C "$repo" checkout --quiet -f --detach "$commit"
  log "Fetching ubuntu-kernel submodule (large, first time takes a while)"
  git -C "$repo" submodule update --init --quiet submodules/ubuntu-kernel

  src=$(src_dir)
  log "Preparing source tree in ${src}"
  rm -rf "$src"; mkdir -p "$src"
  rsync -a --exclude=.git "$repo/submodules/ubuntu-kernel/" "$src/"

  shopt -s nullglob
  for p in "$repo"/patches/kernel/*.patch; do
    patch --batch --quiet -p1 -d "$src" < "$p" || die "PVE patch failed: $(basename "$p")"
    n=$((n+1))
  done
  shopt -u nullglob
  ok "applied ${n} Proxmox kernel patches"
  finalise_tree "$src"
}

# make sure deb-src entries exist so `apt-get source` works
ubuntu_enable_deb_src() {
  if apt-get indextargets 2>/dev/null | grep -q 'Identifier: Sources'; then return 0; fi
  warn "no deb-src repositories enabled — needed for 'apt-get source'"
  confirm "Enable deb-src in the Ubuntu APT sources?" || die "aborted: enable deb-src manually"
  if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
    cp -n /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources.bak
    sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
  else
    cp -n /etc/apt/sources.list /etc/apt/sources.list.bak
    sed -i 's/^# *deb-src /deb-src /' /etc/apt/sources.list
  fi
  apt-get update -qq
  ok "deb-src enabled (backup kept as *.bak)"
}

source_ubuntu() {
  local pkg srcpkg srcver dl dir src
  pkg=$(running_kernel_pkg)
  ubuntu_enable_deb_src

  # the image package is usually built from "linux-signed*"; ask apt for the
  # unsigned image's source, which resolves to the real "linux*" source package
  local q="linux-image-unsigned-${KREL}"
  apt-cache show "$q" >/dev/null 2>&1 || q=$pkg
  srcpkg=$(apt-cache showsrc "$q" 2>/dev/null | awk '/^Package:/{print $2; exit}')
  srcver=$(dpkg-query -W -f='${source:Version}' "$pkg" 2>/dev/null || true)
  log "Running kernel package: ${pkg} → source ${srcpkg:-?} ${srcver:-?}"

  dl="${WORKDIR}/ubuntu-src/${KREL}"
  rm -rf "$dl"; mkdir -p "$dl"
  log "Downloading kernel source with apt-get source (no build-deps)"
  ( cd "$dl" && apt-get source -qq "${q}" ) \
    || die "apt-get source ${q} failed"
  dir=$(find "$dl" -mindepth 1 -maxdepth 1 -type d -name 'linux*' | head -1)
  [[ -n $dir && -f $dir/Makefile ]] || die "unpacked kernel source not found in ${dl}"

  src=$(src_dir)
  log "Preparing source tree in ${src}"
  rm -rf "$src"; mkdir -p "$src"
  rsync -a --exclude=.git "$dir/" "$src/"
  ok "Ubuntu source ready (Ubuntu patches are already part of the tree)"
  finalise_tree "$src"
}

cmd_source() {
  need_root; need_cmd rsync
  case $PLATFORM in
    pve)    need_cmd git; source_pve ;;
    ubuntu) source_ubuntu ;;
  esac
}

# ----------------------------------------------------------------------------- build
cmd_build() {
  need_root; need_cmd kpatch-build
  local patch="" name="" extra=()
  while [[ $# -gt 0 ]]; do
    case $1 in
      -n|--name)     name=$2; shift 2 ;;
      --non-replace) extra+=(--non-replace); shift ;;
      -*)            die "unknown build option: $1" ;;
      *)             patch=$1; shift ;;
    esac
  done
  [[ -n $patch ]] || die "usage: $0 build <file.patch|URL> [--name NAME] [--non-replace]"

  local src; src=$(src_dir)
  [[ -f $src/Makefile ]] || die "no prepared source for ${KREL} — run: $0 source"

  mkdir -p "$WORKDIR/patches" "$WORKDIR/out/$KREL"
  if [[ $patch =~ ^https?:// ]]; then
    local dl; dl="$WORKDIR/patches/$(date +%Y%m%d%H%M%S)-$(basename "${patch%%\?*}").patch"
    log "Downloading ${patch}"
    curl -fsSL "$patch" -o "$dl"
    patch=$dl
  fi
  [[ -r $patch ]] || die "patch file not readable: $patch"
  patch=$(readlink -f "$patch")

  log "Dry-run applying patch to the ${PLATFORM} source"
  ( cd "$src" && patch --dry-run --batch -p1 < "$patch" >/dev/null ) \
    || die "patch does not apply cleanly to the ${KREL} source — backport it first"

  [[ -n $name ]] || name=$(basename "$patch" .patch)
  name=$(echo "$name" | tr -c 'A-Za-z0-9_\n' '_' | cut -c1-40)
  log "Building livepatch-${name}.ko with kpatch-build (-j${JOBS}); first run builds the whole kernel"

  ( cd "$WORKDIR/out/$KREL" && \
    kpatch-build -s "$src" -c "$KCONFIG" -j "$JOBS" -n "$name" "${extra[@]}" "$patch" )

  local ko="$WORKDIR/out/$KREL/livepatch-${name}.ko"
  [[ -f $ko ]] || ko=$(ls -t "$WORKDIR/out/$KREL"/*.ko 2>/dev/null | head -1)
  [[ -f $ko ]] || die "kpatch-build finished but no .ko found"

  if [[ -r $MOK_KEY && -r $MOK_CERT && -x $src/scripts/sign-file ]]; then
    "$src/scripts/sign-file" sha512 "$MOK_KEY" "$MOK_CERT" "$ko" && ok "signed with ${MOK_KEY}"
  elif secure_boot_on; then
    warn "Secure Boot is on but module was NOT signed — it will not load"
  fi
  ok "built: ${ko}"
  echo "$ko"
}

# ----------------------------------------------------------------------------- apply
cmd_apply() {
  need_root; need_cmd kpatch
  local ko="" persist=0
  while [[ $# -gt 0 ]]; do
    case $1 in
      --persist) persist=1; shift ;;
      -*)        die "unknown apply option: $1" ;;
      *)         ko=$1; shift ;;
    esac
  done
  [[ -f $ko ]] || die "usage: $0 apply <livepatch-*.ko> [--persist]"

  local vm; vm=$(modinfo -F vermagic "$ko" | awk '{print $1}')
  [[ $vm == "$KREL" ]] || die "module vermagic '${vm}' does not match running kernel '${KREL}'"
  modinfo -F livepatch "$ko" | grep -qx Y || die "$(basename "$ko") is not a livepatch module"

  local foreign; foreign=$(foreign_patches | tr '\n' ' ')
  if [[ -n $foreign ]] && [[ $(modinfo -F livepatch_replace "$ko" 2>/dev/null || echo Y) != N ]]; then
    warn "other live patches are loaded: ${foreign}"
    warn "this is an atomic-replace patch and will DISABLE them (rebuild with --non-replace to keep them)"
  fi

  confirm "Load $(basename "$ko") into the RUNNING kernel ${KREL}?" || die "aborted"
  log "Loading live patch"
  kpatch load "$ko"
  if (( persist )); then
    kpatch install "$ko"
    systemctl enable --now kpatch.service >/dev/null 2>&1 || warn "could not enable kpatch.service"
    ok "installed — will be re-applied on boot of ${KREL}"
  fi
  cmd_status
}

# ----------------------------------------------------------------------------- status / remove
cmd_status() {
  log "Live patches on ${KREL}"
  local d any=0
  for d in /sys/kernel/livepatch/*/; do
    [[ -d $d ]] || continue
    any=1
    printf '  %-40s enabled=%s transition=%s\n' "$(basename "$d")" \
      "$(cat "$d/enabled")" "$(cat "$d/transition" 2>/dev/null || echo -)"
  done
  (( any )) || echo "  (none loaded)"
  command -v kpatch >/dev/null 2>&1 && { echo; kpatch list 2>/dev/null | sed 's/^/  /'; }
  echo "  taint: $(< /proc/sys/kernel/tainted)"
}

cmd_remove() {
  need_root; need_cmd kpatch
  local name=${1:-}; [[ -n $name ]] || die "usage: $0 remove <livepatch_name>"
  confirm "Disable and unload live patch '${name}'?" || die "aborted"
  kpatch unload "$name"
  kpatch uninstall "$name" 2>/dev/null || true
  cmd_status
}

# ----------------------------------------------------------------------------- canonical (Ubuntu)
cmd_canonical() {
  [[ $PLATFORM == ubuntu ]] || die "Canonical Livepatch only works on Ubuntu kernels, not on ${PLATFORM}"
  local action=${1:-status}
  case $action in
    enable)
      need_root
      command -v pro >/dev/null 2>&1 || { apt-get update -qq; apt-get install -y ubuntu-pro-client; }
      if ! pro status --format json 2>/dev/null | grep -q '"attached": true'; then
        [[ -n ${UBUNTU_PRO_TOKEN:-} ]] \
          || die "set UBUNTU_PRO_TOKEN (from https://ubuntu.com/pro/dashboard) to attach this machine"
        log "Attaching machine to Ubuntu Pro"
        pro attach "$UBUNTU_PRO_TOKEN" --no-auto-enable
      fi
      if compgen -G '/sys/kernel/livepatch/livepatch_*' >/dev/null; then
        warn "kpatch live patches are loaded; Canonical Livepatch may replace them"
      fi
      log "Enabling Canonical Livepatch"
      pro enable livepatch --assume-yes
      cmd_canonical status ;;
    status)
      if command -v canonical-livepatch >/dev/null 2>&1; then
        canonical-livepatch status --verbose
      else
        warn "Canonical Livepatch not installed (run: $0 canonical enable)"
      fi ;;
    disable)
      need_root
      confirm "Disable Canonical Livepatch on this machine?" || die "aborted"
      pro disable livepatch --assume-yes ;;
    *) die "usage: $0 canonical enable|status|disable" ;;
  esac
}

# ----------------------------------------------------------------------------- all
cmd_all() {
  local ko
  cmd_check
  command -v kpatch-build >/dev/null 2>&1 || cmd_setup
  [[ -f $(src_dir)/Makefile ]] || cmd_source
  ko=$(cmd_build "$@" | tail -1)
  cmd_apply "$ko" --persist
}

usage() {
  cat <<EOF
pve-livepatch ${SCRIPT_VERSION} — live patch the running kernel (${KREL}) on Proxmox VE / Ubuntu

Usage: $0 [-y] [-j N] <command> [args]

  check                               verify the kernel/host can be live patched
  setup                               install deps and kpatch/kpatch-build
  source                              fetch + prepare the exact kernel source for ${KREL}
  build <file.patch|URL> [--name N] [--non-replace]
                                      build livepatch-N.ko from a kernel source patch
  apply <livepatch-*.ko> [--persist]  load into running kernel (persist = reapply on boot)
  status                              show loaded live patches
  remove <name>                       unload a live patch
  all <file.patch|URL> [--name N]     check → setup → source → build → apply --persist
  canonical enable|status|disable     (Ubuntu) Canonical Livepatch via Ubuntu Pro

Options:
  -y        don't ask for confirmation
  -j N      parallel build jobs (default: nproc = ${JOBS})

Env: PLATFORM (pve|ubuntu, auto-detected), PVE_LIVEPATCH_DIR (${WORKDIR}),
     PVE_COMMIT, KPATCH_REF, MOK_KEY, MOK_CERT, UBUNTU_PRO_TOKEN

Example:
  $0 check
  $0 setup && $0 source
  $0 build https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id=<sha> --name cve_2026_xxxx
  $0 apply ${WORKDIR}/out/${KREL}/livepatch-cve_2026_xxxx.ko --persist
EOF
}

# ----------------------------------------------------------------------------- main
while [[ $# -gt 0 ]]; do
  case $1 in
    -y|--yes) ASSUME_YES=1; shift ;;
    -j)       JOBS=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -V|--version) echo "$SCRIPT_VERSION"; exit 0 ;;
    *) break ;;
  esac
done

cmd=${1:-}; shift || true
case $cmd in
  ""|help) usage; exit 0 ;;
esac
detect_platform
case $cmd in
  check)     cmd_check ;;
  setup)     cmd_setup ;;
  source)    cmd_source ;;
  build)     cmd_build "$@" ;;
  apply)     cmd_apply "$@" ;;
  status)    cmd_status ;;
  remove)    cmd_remove "$@" ;;
  canonical) cmd_canonical "$@" ;;
  all)       cmd_all "$@" ;;
  *) die "unknown command: $cmd (see --help)" ;;
esac
