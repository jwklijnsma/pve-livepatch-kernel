#!/usr/bin/env bash
# =============================================================================
# pve-livepatch.sh — live patch the running kernel WITHOUT a reboot on
#                    Proxmox VE and Ubuntu, using the kernel's own
#                    scripts/livepatch/klp-build (kernels >= 6.19).
#                    On Ubuntu it can also drive Canonical Livepatch.
#
# Workflow (custom patches):
#   1. check    – verify the running kernel can be live patched
#   2. setup    – install the kernel build toolchain
#   3. source   – fetch the EXACT kernel source for `uname -r`
#                   Proxmox VE: pve-kernel git @ matching "bump version" commit
#                               + Proxmox kernel patches
#                   Ubuntu:     `apt-get source` of the running kernel package
#   4. build    – klp-build turns a source .patch (file or URL) into livepatch-<name>.ko
#   5. apply    – insmod it into the running kernel (optionally re-load on boot)
#
# Small nodes (like Ubuntu Pro): build in GitHub Actions, then on the node
#   setup --minimal  – only what loading needs (kmod, curl, openssl, mokutil)
#   fetch <tag>      – download a CI-built module, verify sha256 + kernel, sign
#   auto enable      – keep the node patched: every 6 h and at boot, fetch and
#                      load the automatic live patch built for its kernel
#
# Ubuntu only (official fixes, no build needed):
#   canonical enable|status|disable – Canonical Livepatch via Ubuntu Pro
#
# Notes:
#   * Run as root (or on a test host running the IDENTICAL kernel and gcc —
#     strongly recommended; build there, apply in production later).
#   * klp-build compiles the original and the patched kernel (vmlinux + all
#     modules): ~30 GB disk and a few hours the first time.
#   * klp-build makes "atomic replace" patches by default: loading a new patch
#     REPLACES all previously loaded live patches (including Canonical's!),
#     so make each patch cumulative — or pass --non-replace.
#   * Not every change is live-patchable (struct/layout changes, __init code,
#     some asm). klp-build refuses those; fall back to migrate + reboot.
# =============================================================================
readonly SCRIPT_VERSION="2.0.0"
readonly WORKDIR="${PVE_LIVEPATCH_DIR:-/var/lib/pve-livepatch}"
readonly PVE_KERNEL_REPO="${PVE_KERNEL_REPO:-https://git.proxmox.com/git/pve-kernel.git}"
readonly UPSTREAM_KERNEL_GIT="${UPSTREAM_KERNEL_GIT:-https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git https://github.com/gregkh/linux.git}"
readonly RELEASE_REPO="${PVE_LIVEPATCH_REPO:-jwklijnsma/pve-livepatch-kernel}"   # where `fetch` downloads from
# paths are overridable so the test suite can point them at fixtures
KREL="${KREL:-$(uname -r)}"; readonly KREL
readonly KCONFIG="${KCONFIG:-/boot/config-${KREL}}"
readonly SYSFS_LP="${SYSFS_LP:-/sys/kernel/livepatch}"
readonly SYS_MODULE="${SYS_MODULE:-/sys/module}"
readonly SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
readonly PROC_VERSION="${PROC_VERSION:-/proc/version}"
readonly OS_RELEASE="${OS_RELEASE:-/etc/os-release}"
readonly LP_WAIT="${LP_WAIT:-60}"                     # seconds to wait for a patch transition
SELF="${PVE_LIVEPATCH_SELF:-$(readlink -f "${BASH_SOURCE[0]}")}"; readonly SELF
JOBS="${JOBS:-$(nproc)}"
ASSUME_YES=0
FULL=0            # 1 = full-history kernel source (default: only the needed commit)
readonly BUILD_DISK_GB=30

# ----------------------------------------------------------------------------- helpers
if [[ -t 1 ]]; then C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[34m'; C_0=$'\e[0m'
else C_R=; C_G=; C_Y=; C_B=; C_0=; fi
log()  { printf '%s==>%s %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '  %s✔%s %s\n'  "$C_G" "$C_0" "$*"; }
warn() { printf '  %s!%s %s\n'  "$C_Y" "$C_0" "$*" >&2; }
bad()  { printf '  %s✘%s %s\n'  "$C_R" "$C_0" "$*" >&2; }
die()  { printf '%sERROR:%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "run as root"; }
need_cmd()  { command -v "$1" >/dev/null 2>&1 || die "'$1' not found — run: $0 setup"; }

confirm() {
  (( ASSUME_YES )) && return 0
  local a; read -r -p "$1 [y/N] " a
  [[ $a =~ ^[Yy]$ ]]
}

cfg_val() { grep -E "^$1=" "$KCONFIG" 2>/dev/null | cut -d= -f2- || true; }
src_dir() { echo "${WORKDIR}/src/${KREL}"; }
installed_dir() { echo "${WORKDIR}/installed/${KREL}"; }

secure_boot_on() {
  command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null | grep -qi 'enabled'
}

# enrolled | pending | not-enrolled | missing
mok_state() {
  [[ -r $MOK_KEY && -r $MOK_CERT ]] || { echo missing; return; }
  local out; out=$(mokutil --test-key "$MOK_CERT" 2>&1 || true)
  case $out in
    *"already enrolled"*)                 echo enrolled ;;
    *"already in the enrollment request"*) echo pending ;;
    *)                                    echo not-enrolled ;;
  esac
}

# ----------------------------------------------------------------------------- platform
# PLATFORM = pve | ubuntu
detect_platform() {
  if [[ -n ${PLATFORM:-} ]]; then :
  elif command -v pveversion >/dev/null 2>&1 || [[ $KREL == *-pve ]]; then PLATFORM=pve
  elif [[ -r $OS_RELEASE ]] && grep -qE '^ID="?ubuntu"?$' "$OS_RELEASE"; then PLATFORM=ubuntu
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
    ubuntu) sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$OS_RELEASE" | grep . || echo Ubuntu ;;
  esac
}

# live patches loaded that were NOT made by this tool (e.g. Canonical's lkp_*)
foreign_patches() {
  local d n
  for d in "$SYSFS_LP"/*/; do
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
  [[ $(cfg_val CONFIG_KLP_BUILD) == y ]] && ok "CONFIG_KLP_BUILD=y (klp-build can make patches for this kernel)" \
    || { bad "CONFIG_KLP_BUILD not enabled — klp-build needs a kernel >= 6.19 built with it"; fail=1; }
  if [[ $(cfg_val CONFIG_DYNAMIC_FTRACE_WITH_REGS) == y || $(cfg_val CONFIG_DYNAMIC_FTRACE_WITH_ARGS) == y ]]; then
    ok "dynamic ftrace (WITH_REGS/ARGS) available"
  else bad "dynamic ftrace with regs/args missing"; fail=1; fi
  [[ $(cfg_val CONFIG_HAVE_RELIABLE_STACKTRACE) == y ]] && ok "reliable stacktrace (consistency model)" \
    || warn "no reliable stacktrace — patch transitions may stall"
  [[ $(cfg_val CONFIG_KALLSYMS_ALL) == y ]] && ok "CONFIG_KALLSYMS_ALL=y" || warn "CONFIG_KALLSYMS_ALL not set"
  [[ -d $SYSFS_LP ]] && ok "${SYSFS_LP} present" \
    || { bad "${SYSFS_LP} missing"; fail=1; }

  # local builds need the same compiler that built the running kernel;
  # nodes without a compiler just load CI-built modules (fetch / auto)
  local kgcc lgcc build_host=0
  kgcc=$(sed -n 's/.*(gcc[^)]*) \([0-9][0-9.]*\).*/\1/p' "$PROC_VERSION")
  lgcc=$(gcc -dumpfullversion 2>/dev/null || echo "none")
  if [[ $lgcc == none ]]; then
    ok "fetch mode: no local build toolchain needed (kernel was built with gcc ${kgcc:-?})"
  elif [[ -n $kgcc && $kgcc == "$lgcc" ]]; then
    ok "gcc ${lgcc} matches kernel build compiler (local builds possible)"; build_host=1
  else
    warn "gcc mismatch: kernel built with '${kgcc:-?}', local gcc is '${lgcc}' — no local builds; use fetch / auto"
  fi

  # secure boot / module signing
  if secure_boot_on; then
    warn "Secure Boot enabled — patch modules must be signed with an enrolled MOK key"
    case $(mok_state) in
      enrolled)     ok "MOK key ${MOK_CERT} is enrolled — modules get signed with it" ;;
      pending)      bad "MOK key enrollment is pending — reboot once and confirm it in MOK Manager"; fail=1 ;;
      not-enrolled) bad "MOK key ${MOK_CERT} exists but is not enrolled — run: $0 mok setup"; fail=1 ;;
      missing)      bad "no MOK key at ${MOK_KEY} — run: $0 mok setup"; fail=1 ;;
    esac
  else ok "Secure Boot off — unsigned modules can load"
  fi
  [[ -r /sys/kernel/security/lockdown ]] && ok "lockdown: $(< /sys/kernel/security/lockdown)"

  if [[ $PLATFORM == ubuntu ]] && command -v canonical-livepatch >/dev/null 2>&1; then
    warn "Canonical Livepatch is installed — atomic-replace patches from this tool would replace its fixes"
  fi

  if (( build_host )); then
    local dpath=$WORKDIR disk
    while [[ ! -d $dpath ]]; do dpath=$(dirname "$dpath"); done
    disk=$(df -BG --output=avail "$dpath" | tail -1 | tr -dc 0-9)
    if (( disk >= BUILD_DISK_GB )); then ok "${disk}G free for ${WORKDIR} (a build needs ~${BUILD_DISK_GB}G)"
    else warn "only ${disk}G free on ${dpath} — a build needs ~${BUILD_DISK_GB}G; use 'fetch' / 'auto' (CI-built modules), set PVE_LIVEPATCH_DIR to a larger disk, or run '$0 clean'"
    fi
  fi
  if command -v insmod >/dev/null 2>&1; then ok "insmod available (can load patches)"
  else bad "insmod not found — run: $0 setup --minimal"; fail=1; fi

  cmd_status || true
  (( fail == 0 )) && log "${C_G}Ready.${C_0}" || die "host is not ready for live patching (see above)"
}

# ----------------------------------------------------------------------------- setup
cmd_setup() {
  need_root
  local minimal=0
  while [[ $# -gt 0 ]]; do
    case $1 in
      --minimal) minimal=1; shift ;;
      *)         die "unknown setup option: $1" ;;
    esac
  done
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  if (( minimal )); then
    log "Installing minimal dependencies (load + sign only, no build toolchain)"
    apt-get install -y --no-install-recommends curl ca-certificates kmod openssl mokutil
    ok "ready to load CI-built modules: $0 fetch <release-tag>  or  $0 auto enable"
    return 0
  fi
  log "Installing the kernel build toolchain for klp-build"
  apt-get install -y --no-install-recommends \
    git build-essential bc bison flex cpio rsync kmod curl ca-certificates gawk patch \
    patchutils libxxhash-dev \
    libelf-dev libdw-dev elfutils libssl-dev dwarves python3 zstd pkg-config \
    mokutil dpkg-dev
  ok "build toolchain installed — next: $0 source"
}

# ----------------------------------------------------------------------------- source
disk_preflight() {
  local dpath=$WORKDIR disk need
  while [[ ! -d $dpath ]]; do dpath=$(dirname "$dpath"); done
  disk=$(df -BG --output=avail "$dpath" | tail -1 | tr -dc 0-9)
  need=$BUILD_DISK_GB
  (( disk >= need )) || warn "only ${disk}G free on ${dpath}; a klp-build needs ~${need}G"
}

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
  # Ubuntu/PVE configs may point at certificate files that aren't part of the
  # source tree; a plain `make vmlinux` would then fail. They only matter for
  # module-signature checks in the reference image, not for the patched code.
  local k v
  for k in SYSTEM_TRUSTED_KEYS SYSTEM_REVOCATION_KEYS; do
    v=$(sed -n "s/^CONFIG_${k}=\"\(.*\)\"$/\1/p" "$src/.config")
    if [[ -n $v && ! -e $src/$v ]]; then
      sed -i "s|^CONFIG_${k}=.*|CONFIG_${k}=\"\"|" "$src/.config"
      warn "CONFIG_${k} pointed at missing '${v}' — cleared for the build"
    fi
  done
  make -C "$src" -s olddefconfig >/dev/null
  rel=$(make -C "$src" -s kernelrelease)
  [[ $rel == "$KREL" ]] || die "source kernelrelease '${rel}' != running '${KREL}'"
  ok "source tree matches ${KREL}"
}

# commit in pve-kernel whose subject is exactly "bump version to <pkgver>"
# (awk reads all input: an early `exit` would SIGPIPE git log under pipefail)
find_pve_commit() {
  local repo=$1 pkgver=$2
  git -C "$repo" log --all --format='%H%x09%s' -F --grep="bump version to ${pkgver}" \
    | awk -F'\t' -v s="bump version to ${pkgver}" '!found && $2==s {print $1; found=1}'
}

source_pve() {
  local pkg pkgver repo commit src p n=0
  if [[ -n ${PVE_KERNEL_PKGVER:-} ]]; then      # CI: building for a kernel that isn't running here
    pkg="proxmox-kernel-${KREL}"; pkgver=$PVE_KERNEL_PKGVER
  else
    pkg=$(running_kernel_pkg)
    pkgver=$(dpkg-query -W -f='${Version}' "$pkg")
  fi
  log "Kernel package: ${pkg} ${pkgver}"

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
    commit=$(find_pve_commit "$repo" "$pkgver")
  fi
  [[ -n $commit ]] || die "no 'bump version to ${pkgver}' commit found; set PVE_COMMIT=<sha> manually"
  ok "pve-kernel commit ${commit:0:12}"

  git -C "$repo" checkout --quiet -f --detach "$commit"
  local sub=submodules/ubuntu-kernel
  if (( FULL )); then
    log "Fetching ubuntu-kernel submodule with full history (large, first time takes a while)"
    git -C "$repo" submodule update --init --quiet "$sub"
  else
    log "Fetching ubuntu-kernel submodule (only the needed commit)"
    git -C "$repo" submodule update --init --depth 1 --quiet "$sub" || {
      warn "server refused a shallow fetch — falling back to full history"
      git -C "$repo" submodule update --init --quiet "$sub"
    }
  fi

  src=$(src_dir)
  log "Preparing source tree in ${src}"
  rm -rf "$src"; mkdir -p "$src"
  rsync -a --exclude=.git "$repo/$sub/" "$src/"
  if (( ! FULL )); then
    # the copy in $src is all we need: drop the checkout and its objects
    git -C "$repo" submodule deinit -f --quiet "$sub"
    rm -rf "$repo/.git/modules/$sub"
    ok "removed submodule checkout to save space"
  fi

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
  rm -rf "$dl"
  ok "Ubuntu source ready (Ubuntu patches are already part of the tree)"
  finalise_tree "$src"
}

cmd_source() {
  need_root; need_cmd rsync
  while [[ $# -gt 0 ]]; do
    case $1 in
      --full) FULL=1; shift ;;
      *)      die "unknown source option: $1" ;;
    esac
  done
  disk_preflight
  case $PLATFORM in
    pve)    need_cmd git; source_pve ;;
    ubuntu) source_ubuntu ;;
  esac
}

# ----------------------------------------------------------------------------- build
# upstream base version of a prepared tree, e.g. 7.0.14
tree_base_version() {
  awk -F' *= *' '$1=="VERSION"{v=$2} $1=="PATCHLEVEL"{p=$2} $1=="SUBLEVEL"{s=$2} END{print v"."p"."s}' "$1/Makefile"
}

objtool_has_klp() {
  local o="$1/tools/objtool/objtool"
  [[ -x $o ]] && ! "$o" klp 2>&1 | grep -q 'not implemented'
}

# Replace tools/objtool + scripts/livepatch with the matching upstream stable
# versions. Used when a distro tree carries a partial klp-build backport whose
# objtool does not compile with live-patch support (seen in Proxmox 7.0).
use_upstream_klp_tools() {
  local src=$1 base t url tag ok_fetch=""
  base=$(tree_base_version "$src")
  t=$(mktemp -d)
  git -C "$t" init -q
  git -C "$t" config core.sparseCheckout true
  printf 'tools/objtool/\nscripts/livepatch/\n' > "$t/.git/info/sparse-checkout"
  for tag in "v${base}" "v${base%.*}"; do
    for url in $UPSTREAM_KERNEL_GIT; do
      if git -C "$t" fetch -q --depth 1 --filter=blob:none "$url" tag "$tag" 2>/dev/null; then
        ok_fetch="$tag from $url"; break 2
      fi
    done
  done
  [[ -n $ok_fetch ]] || { rm -rf "$t"; die "could not fetch upstream ${base} objtool/klp-build (tried: ${UPSTREAM_KERNEL_GIT})"; }
  git -C "$t" checkout -q FETCH_HEAD
  [[ -f $t/tools/objtool/Makefile && -x $t/scripts/livepatch/klp-build ]] \
    || { rm -rf "$t"; die "upstream ${ok_fetch} has no klp-build"; }
  rm -rf "$src/tools/objtool" "$src/scripts/livepatch"
  cp -a "$t/tools/objtool" "$src/tools/objtool"
  cp -a "$t/scripts/livepatch" "$src/scripts/livepatch"
  rm -rf "$t"
  warn "using upstream objtool + klp-build (${ok_fetch}) — this tree's copies don't build with live-patch support"
}

# klp-build needs objtool built with live-patch support (libxxhash).
ensure_klp_objtool() {
  local src=$1 olog="$WORKDIR/out/$KREL/objtool-build.log"
  log "Building objtool with live-patch support"
  if make -C "$src" -j"$JOBS" tools/objtool > "$olog" 2>&1 && objtool_has_klp "$src"; then
    ok "objtool ready"; return 0
  fi
  grep -E 'error' "$olog" | head -n 5 >&2 || true
  warn "this kernel tree's objtool does not build with live-patch support (log: ${olog})"
  use_upstream_klp_tools "$src"
  if ! make -C "$src" -j"$JOBS" tools/objtool > "$olog" 2>&1 || ! objtool_has_klp "$src"; then
    tail -n 25 "$olog" >&2
    die "objtool still has no live-patch support — is libxxhash-dev installed? (log: ${olog})"
  fi
  ok "objtool ready (upstream)"
}

cmd_build() {
  need_root
  local patch="" name="" klpargs=()
  while [[ $# -gt 0 ]]; do
    case $1 in
      -n|--name)     name=$2; shift 2 ;;
      --non-replace) klpargs+=(--no-replace); shift ;;
      --full)        FULL=1; shift ;;            # accepted for compatibility: klp-build always builds everything
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
  # --forward: a fix that is already in this kernel is reported, not silently reversed
  ( cd "$src" && patch --dry-run --forward --batch -p1 < "$patch" >/dev/null ) \
    || die "patch does not apply cleanly to the ${KREL} source (already included, or needs a backport)"

  [[ -n $name ]] || name=$(basename "$patch" .patch)
  name=$(echo "$name" | tr -c 'A-Za-z0-9_\n' '_' | cut -c1-40)

  # Kernels >= 6.19 ship their own builder (scripts/livepatch/klp-build).
  [[ -x $src/scripts/livepatch/klp-build ]] && grep -qx 'CONFIG_KLP_BUILD=y' "$src/.config" 2>/dev/null \
    || die "${KREL} has no klp-build support: it needs a kernel >= 6.19 built with CONFIG_KLP_BUILD=y"

  disk_preflight
  ensure_klp_objtool "$src"
  log "Building livepatch-${name}.ko with the kernel's own klp-build (-j${JOBS}, vmlinux + modules)"
  log "it compiles the original and the patched kernel — the first run takes a long time"
  local ko="$WORKDIR/out/$KREL/livepatch-${name}.ko"
  local blog="$WORKDIR/out/$KREL/klp-build-${name}.log"
  # OBJTOOL: some distro copies of klp-build (e.g. Proxmox/Ubuntu 7.0) use it
  # without defining it; upstream sets the same path itself.
  if ! ( cd "$src" && OBJTOOL="$src/tools/objtool/objtool" \
         ./scripts/livepatch/klp-build -j "$JOBS" -o "$ko" "${klpargs[@]}" "$patch" ) 2>&1 | tee "$blog"; then
    grep -q 'no changes detected' "$blog" \
      && die "klp-build found no changed functions — does the patch touch code built into this kernel?"
    die "klp-build failed — see ${blog} (work files in ${src}/klp-tmp)"
  fi
  [[ -f $ko ]] || die "klp-build finished but ${ko} is missing"

  if [[ -r $MOK_KEY && -r $MOK_CERT ]]; then
    sign_module "$ko"
  elif secure_boot_on; then
    warn "Secure Boot is on but module was NOT signed — it will not load"
  fi
  ok "built: ${ko}"
  echo "$ko"
}

# ----------------------------------------------------------------------------- signing
readonly SIG_MARKER='~Module signature appended~'

is_signed() { [[ $(tail -c 28 "$1" | head -c 27) == "$SIG_MARKER" ]]; }

# Append a kernel module signature using only openssl. Produces exactly what
# the kernel's scripts/sign-file does (sha512, PKCS#7/CMS, no attributes,
# issuer+serial signer id), so nodes need neither kernel headers nor sign-file.
sign_module() {
  local ko=$1 t len b
  [[ -r $MOK_KEY && -r $MOK_CERT ]] || die "no MOK key at ${MOK_KEY} — run: $0 mok setup"
  if is_signed "$ko"; then ok "$(basename "$ko") is already signed"; return 0; fi
  t=$(mktemp -d)
  # certificate may be DER (mok.pub, MOK.der) or PEM
  openssl x509 -inform DER -in "$MOK_CERT" -out "$t/cert.pem" 2>/dev/null \
    || openssl x509 -in "$MOK_CERT" -out "$t/cert.pem" 2>/dev/null \
    || { rm -rf "$t"; die "cannot read certificate ${MOK_CERT}"; }
  openssl cms -sign -binary -nocerts -noattr -nosmimecap -md sha512 \
    -in "$ko" -inkey "$MOK_KEY" -signer "$t/cert.pem" -outform DER -out "$t/sig" \
    || { rm -rf "$t"; die "openssl failed to sign $(basename "$ko")"; }
  len=$(stat -c %s "$t/sig")
  {
    cat "$t/sig"
    # struct module_signature: algo, hash, id_type=PKCS7(2), signer_len, key_id_len, pad[3]
    printf '\000\000\002\000\000\000\000\000'
    for b in 24 16 8 0; do                        # sig_len, big-endian u32
      # shellcheck disable=SC2059
      printf "\\$(printf %03o $(( (len >> b) & 255 )))"
    done
    printf '%s\n' "$SIG_MARKER"
  } >> "$ko"
  rm -rf "$t"
  ok "signed $(basename "$ko") with ${MOK_CERT}"
}


# ----------------------------------------------------------------------------- fetch
# Download a module that GitHub Actions built (see .github/workflows/build-livepatch.yml),
# check it and sign it. Sets FETCHED_KO.
#   fetch_verified <url> <SHA256SUMS-url|""> <asset-file-name> <name>
fetch_verified() {
  local url=$1 sums=$2 asset=$3 name=$4 out ko want have
  out="$WORKDIR/out/$KREL"; mkdir -p "$out"
  name=$(echo "$name" | tr -c 'A-Za-z0-9_\n' '_' | cut -c1-40)
  ko="$out/livepatch-${name}.ko"

  log "Downloading ${url}"
  curl -fsSL "$url" -o "$ko.part" || { rm -f "$ko.part"; die "download failed: ${url}"; }
  if [[ -n $sums ]]; then
    curl -fsSL "$sums" -o "$out/SHA256SUMS.part" || { rm -f "$ko.part" "$out/SHA256SUMS.part"; die "could not download SHA256SUMS"; }
    want=$(awk -v f="$asset" '{n=$2; sub(/^[*]/,"",n); sub(/^[.][/]/,"",n)} n==f {print $1}' "$out/SHA256SUMS.part")
    rm -f "$out/SHA256SUMS.part"
    [[ -n $want ]] || { rm -f "$ko.part"; die "SHA256SUMS has no entry for ${asset}"; }
    have=$(sha256sum "$ko.part" | cut -d' ' -f1)
    [[ $want == "$have" ]] || { rm -f "$ko.part"; die "checksum mismatch for ${asset} — not using it"; }
    ok "sha256 verified"
  else
    warn "direct URL: no SHA256SUMS to verify against"
  fi

  local vm; vm=$(modinfo -F vermagic "$ko.part" 2>/dev/null | awk '{print $1}')
  [[ $vm == "$KREL" ]] || { rm -f "$ko.part"; die "module is for kernel '${vm:-?}', running ${KREL}"; }
  modinfo -F livepatch "$ko.part" 2>/dev/null | grep -qx Y || { rm -f "$ko.part"; die "${asset} is not a livepatch module"; }
  mv -f "$ko.part" "$ko"
  ok "module matches running kernel ${KREL}"

  if [[ -r $MOK_KEY && -r $MOK_CERT ]]; then
    sign_module "$ko"
  elif secure_boot_on; then
    die "Secure Boot is on but there is no signing key — run: $0 mok setup (module kept at ${ko})"
  else
    warn "no MOK key — module left unsigned (fine while Secure Boot is off)"
  fi
  FETCHED_KO=$ko
}

# Release tags look like lp-<name>-<kernel>, assets livepatch-<name>-<kernel>.ko + SHA256SUMS.
cmd_fetch() {
  need_root; need_cmd curl
  local ref=${1:-} name url sums="" asset
  [[ -n $ref ]] || die "usage: $0 fetch <release-tag|URL-to-.ko>"

  if [[ $ref =~ ^https?:// ]]; then
    url=$ref
    asset=$(basename "${url%%\?*}")
    name=${asset%.ko}; name=${name#livepatch-}; name=${name%-"$KREL"}
  else
    [[ $ref == lp-* ]] || die "'${ref}' is not a live-patch release tag (expected lp-<name>-${KREL})"
    [[ $ref == *-"$KREL" ]] || die "release '${ref}' was not built for this kernel (${KREL})"
    [[ $ref != "lp-auto-${KREL}" ]] || die "automatic patches are handled by: $0 auto"
    name=${ref#lp-}; name=${name%-"$KREL"}
    asset="livepatch-${name}-${KREL}.ko"
    url="https://github.com/${RELEASE_REPO}/releases/download/${ref}/${asset}"
    sums="https://github.com/${RELEASE_REPO}/releases/download/${ref}/SHA256SUMS"
  fi
  fetch_verified "$url" "$sums" "$asset" "$name"
  ok "ready: ${FETCHED_KO}"
  echo "  load it with: $0 apply ${FETCHED_KO} --persist" >&2
  echo "$FETCHED_KO"
}

# ----------------------------------------------------------------------------- auto
# GitHub Actions (.github/workflows/auto-livepatch.yml) builds one cumulative
# live patch from patches/auto/ for every new Proxmox kernel and publishes it
# as release lp-auto-<kernel>, asset livepatch-auto_<patchset-id>-<kernel>.ko.
# The id changes whenever the patch set changes, so a new module never clashes
# with the loaded one and atomically replaces it.
readonly AUTO_UNIT=pve-livepatch-auto

auto_run() {
  need_cmd curl
  local tag="lp-auto-${KREL}" base sums asset name mod f
  base="https://github.com/${RELEASE_REPO}/releases/download/${tag}"
  sums=$(mktemp)
  log "Looking for ${tag} in ${RELEASE_REPO}"
  if ! curl -fsSL "$base/SHA256SUMS" -o "$sums"; then
    rm -f "$sums"
    ok "no automatic live patch for ${KREL} (not published yet, or no network) — nothing to do"
    return 0
  fi
  asset=$(awk '{n=$2; sub(/^[*]/,"",n); sub(/^[.][/]/,"",n)} n ~ /^livepatch-auto_[0-9a-f]+-.*[.]ko$/ {print n}' "$sums" | head -1)
  rm -f "$sums"
  if [[ -z $asset ]]; then
    ok "nothing to patch: every fix in the patch set is already part of ${KREL}"
    return 0
  fi
  name=${asset#livepatch-}; name=${name%-"$KREL".ko}
  [[ $name =~ ^auto_[0-9a-f]+$ && $asset == "livepatch-${name}-${KREL}.ko" ]] \
    || die "unexpected file ${asset} in release ${tag}"
  mod="livepatch_${name}"
  if [[ -d $SYSFS_LP/$mod ]]; then
    ok "up to date: ${mod} is loaded"
    return 0
  fi

  fetch_verified "$base/$asset" "$base/SHA256SUMS" "$asset" "$name"
  ASSUME_YES=1 cmd_apply "$FETCHED_KO" --persist
  # the new module replaced the older automatic ones: stop loading those at boot
  for f in "$(installed_dir)"/livepatch-auto_*.ko "$WORKDIR/out/$KREL"/livepatch-auto_*.ko; do
    if [[ -e $f && $(basename "$f") != "livepatch-${name}.ko" ]]; then rm -f "$f"; fi
  done
  ok "automatic live patch ${mod} is active"
}

auto_enable() {
  write_boot_unit
  cat > "$SYSTEMD_DIR/${AUTO_UNIT}.service" <<EOF
[Unit]
Description=Fetch and load the automatic live patch for the running kernel
Wants=network-online.target
After=network-online.target pve-livepatch.service

[Service]
Type=oneshot
ExecStart=${SELF} -y auto run
EOF
  cat > "$SYSTEMD_DIR/${AUTO_UNIT}.timer" <<EOF
[Unit]
Description=Check for new automatic live patches (pve-livepatch)

[Timer]
OnBootSec=2min
OnUnitActiveSec=6h
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload || true
  systemctl enable pve-livepatch.service >/dev/null 2>&1 || warn "could not enable pve-livepatch.service"
  systemctl enable --now "${AUTO_UNIT}.timer" || die "could not enable ${AUTO_UNIT}.timer"
  ok "automatic live patching on: checks ${RELEASE_REPO} at boot and every 6 hours"
  echo "  run it now:   $0 auto run"
  echo "  see the log:  journalctl -u ${AUTO_UNIT}.service"
}

auto_disable() {
  systemctl disable --now "${AUTO_UNIT}.timer" >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_DIR/${AUTO_UNIT}.service" "$SYSTEMD_DIR/${AUTO_UNIT}.timer"
  systemctl daemon-reload || true
  ok "automatic live patching off (patches that are loaded stay loaded; '$0 remove <name>' unloads one)"
}

cmd_auto() {
  need_root
  local action=${1:-run}
  case $action in
    run)     auto_run ;;
    enable)  auto_enable ;;
    disable) auto_disable ;;
    *)       die "usage: $0 auto [run|enable|disable]" ;;
  esac
}

# ----------------------------------------------------------------------------- clean
cmd_clean() {
  need_root
  local d targets=() size
  for d in "$WORKDIR/src" "$WORKDIR/ubuntu-src" "$WORKDIR/pve-kernel"; do
    [[ -e $d ]] && targets+=("$d")
  done
  if (( ${#targets[@]} == 0 )); then ok "nothing to clean"; return 0; fi
  size=$(du -sch "${targets[@]}" 2>/dev/null | tail -1 | cut -f1)
  log "Will delete kernel sources and build trees (${size}):"
  printf '    %s\n' "${targets[@]}"
  echo "  Kept: built and installed modules, downloaded patches."
  echo "  The next build needs '$0 source' again and recompiles the kernel."
  confirm "Delete them?" || die "aborted"
  rm -rf "${targets[@]}"
  ok "freed ${size}"
}

# ----------------------------------------------------------------------------- loading
# Plain kernel interfaces, no extra tools: insmod loads and enables a live-patch
# module; /sys/kernel/livepatch/<mod>/{enabled,transition} show its state.
module_name() {
  local n; n=$(modinfo -F name "$1" 2>/dev/null || true)
  [[ -n $n ]] || n=$(basename "$1" .ko | tr - _)
  echo "$n"
}

# wait until <mod> finished its transition (enabled) — 0 ok, 1 timeout
wait_enabled() {
  local d="$SYSFS_LP/$1" i
  for (( i = 0; i <= LP_WAIT; i++ )); do
    [[ -f $d/transition && $(< "$d/transition") == 0 ]] && return 0
    sleep 1
  done
  return 1
}

# wait until <mod> is disabled and gone from sysfs — 0 ok, 1 timeout
wait_disabled() {
  local d="$SYSFS_LP/$1" i
  for (( i = 0; i <= LP_WAIT; i++ )); do
    [[ ! -d $d ]] && return 0
    [[ $(cat "$d/enabled" 2>/dev/null) == 0 && $(cat "$d/transition" 2>/dev/null) == 0 ]] && return 0
    sleep 1
  done
  return 1
}

load_module() {
  local ko=$1 mod; mod=$(module_name "$ko")
  if [[ -d $SYSFS_LP/$mod ]]; then ok "${mod} is already loaded"; return 0; fi
  insmod "$ko" || die "insmod $(basename "$ko") failed — see: dmesg | tail"
  if wait_enabled "$mod"; then ok "${mod} enabled"
  else warn "${mod} is still in transition (a task is busy in a patched function); check: $0 status"; fi
}

# modules of patches that an atomic-replace patch disabled: unload them
unload_replaced() {
  local m n
  for m in "$SYS_MODULE"/livepatch_*; do
    [[ -d $m ]] || continue
    n=$(basename "$m")
    [[ -d $SYSFS_LP/$n ]] && continue
    if rmmod "$n" 2>/dev/null; then ok "unloaded replaced patch module ${n}"; fi
  done
}

write_boot_unit() {
  mkdir -p "$SYSTEMD_DIR"
  cat > "$SYSTEMD_DIR/pve-livepatch.service" <<EOF
[Unit]
Description=Load installed live patches for the running kernel (pve-livepatch)
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${SELF} -y boot

[Install]
WantedBy=multi-user.target
EOF
}

# `boot`: load what `apply --persist` installed for this kernel, oldest first
cmd_boot() {
  local dir ko n=0; dir=$(installed_dir)
  [[ -d $dir ]] || { ok "no live patches installed for ${KREL}"; return 0; }
  while IFS= read -r ko; do
    [[ -n $ko ]] || continue
    ( load_module "$ko" ) || warn "could not load $(basename "$ko")"
    n=$((n+1))
  done < <(compgen -G "$dir/*.ko" >/dev/null && ls -tr -- "$dir"/*.ko)
  unload_replaced
  ok "${n} installed live patch(es) processed for ${KREL}"
}

# ----------------------------------------------------------------------------- apply
cmd_apply() {
  need_root; need_cmd insmod
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
  if secure_boot_on; then
    [[ -n $(modinfo -F signer "$ko" 2>/dev/null) ]] \
      || die "Secure Boot is on and $(basename "$ko") is not signed — run '$0 mok setup', then rebuild or fetch again"
    [[ $(mok_state) == enrolled ]] \
      || warn "MOK key is not enrolled (yet) — the kernel will probably reject this module"
  fi

  local foreign; foreign=$(foreign_patches | tr '\n' ' ')
  if [[ -n $foreign ]] && [[ $(modinfo -F livepatch_replace "$ko" 2>/dev/null || echo Y) != N ]]; then
    warn "other live patches are loaded: ${foreign}"
    warn "an atomic-replace patch (klp-build's default) DISABLES them (build with --non-replace to keep them)"
  fi

  confirm "Load $(basename "$ko") into the RUNNING kernel ${KREL}?" || die "aborted"
  log "Loading live patch"
  load_module "$ko"
  unload_replaced
  if (( persist )); then
    install -D -m 0644 "$ko" "$(installed_dir)/$(basename "$ko")"
    write_boot_unit
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable pve-livepatch.service >/dev/null 2>&1 || warn "could not enable pve-livepatch.service"
    ok "installed — loaded again on every boot of ${KREL} (pve-livepatch.service)"
  fi
  cmd_status
}

# ----------------------------------------------------------------------------- status / remove
cmd_status() {
  log "Live patches on ${KREL}"
  local d any=0 f
  for d in "$SYSFS_LP"/*/; do
    [[ -d $d ]] || continue
    any=1
    printf '  %-40s enabled=%s transition=%s\n' "$(basename "$d")" \
      "$(cat "$d/enabled")" "$(cat "$d/transition" 2>/dev/null || echo -)"
  done
  (( any )) || echo "  (none loaded)"
  for f in "$(installed_dir)"/*.ko; do
    [[ -e $f ]] && echo "  loaded at boot: $(basename "$f")"
  done
  [[ -e $SYSTEMD_DIR/${AUTO_UNIT}.timer ]] && echo "  automatic updates: on (${AUTO_UNIT}.timer)"
  echo "  taint: $(< /proc/sys/kernel/tainted)"
}

cmd_remove() {
  need_root
  local name=${1:-}; [[ -n $name ]] || die "usage: $0 remove <livepatch_name>"
  [[ -d $SYSFS_LP/$name || ! -d $SYSFS_LP/livepatch_$name ]] || name="livepatch_$name"
  confirm "Disable and unload live patch '${name}'?" || die "aborted"
  if [[ -d $SYSFS_LP/$name ]]; then
    log "Disabling ${name}"
    echo 0 > "$SYSFS_LP/$name/enabled"
    wait_disabled "$name" || die "${name} is still in transition — try again in a minute"
    ok "${name} disabled"
  else
    warn "${name} is not loaded"
  fi
  if [[ -d $SYS_MODULE/$name ]]; then
    rmmod "$name" && ok "module ${name} unloaded" || warn "could not unload module ${name}"
  fi
  local f; f="$(installed_dir)/livepatch-${name#livepatch_}.ko"
  if [[ -e $f ]]; then rm -f "$f"; ok "no longer loaded at boot"; fi
  cmd_status
}

# ----------------------------------------------------------------------------- mok (Secure Boot)
cmd_mok() {
  local action=${1:-status}
  case $action in
    status)
      echo "  key:  ${MOK_KEY}"
      echo "  cert: ${MOK_CERT}"
      if secure_boot_on; then ok "Secure Boot enabled — modules must be signed"
      else ok "Secure Boot disabled — signing optional"; fi
      case $(mok_state) in
        enrolled)     ok "key is enrolled" ;;
        pending)      warn "enrollment pending — reboot once and confirm it in MOK Manager" ;;
        not-enrolled) warn "key exists but is not enrolled — run: $0 mok setup" ;;
        missing)      warn "no key yet — run: $0 mok setup" ;;
      esac ;;
    setup)
      need_root; need_cmd mokutil
      if [[ -r $MOK_KEY && -r $MOK_CERT ]]; then
        ok "using existing key ${MOK_KEY}"
      else
        [[ -e $MOK_KEY || -e $MOK_CERT ]] \
          && die "only one of ${MOK_KEY} / ${MOK_CERT} exists — refusing to overwrite; fix or remove it"
        need_cmd openssl
        log "Creating MOK signing key"
        install -d -m 700 "$(dirname "$MOK_KEY")"
        mkdir -p "$(dirname "$MOK_CERT")"
        ( umask 077
          openssl req -new -x509 -nodes -days 36500 -newkey rsa:2048 \
            -subj "/CN=$(hostname -s) pve-livepatch module signing key/" \
            -keyout "$MOK_KEY" -outform DER -out "$MOK_CERT" >/dev/null 2>&1 )
        ok "created ${MOK_KEY} (private, keep it safe) and ${MOK_CERT}"
      fi
      case $(mok_state) in
        enrolled) ok "key is already enrolled — nothing to do"; return 0 ;;
        pending)  warn "enrollment already pending — reboot once and confirm it in MOK Manager"; return 0 ;;
      esac
      log "Requesting enrollment — choose a one-time password, you need it at the next boot"
      mokutil --import "$MOK_CERT"
      cat <<EOF

  Next steps (one-time, needs ONE reboot because Secure Boot keys live in firmware):
    1. Reboot this node (live-migrate guests off first).
    2. At the blue "MOK management" screen: Enroll MOK → Continue → Yes,
       enter the password you just chose → Reboot.
    3. Check: $0 mok status   (should say: key is enrolled)
  After that, live patches signed with this key load without any reboot.
  Tip: copy ${MOK_KEY} and ${MOK_CERT} to your other nodes and run
       '$0 mok setup' there, so one signed module loads on every node.
EOF
      ;;
    *) die "usage: $0 mok setup|status" ;;
  esac
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
      if compgen -G "$SYSFS_LP/livepatch_*" >/dev/null; then
        warn "live patches from this tool are loaded; Canonical Livepatch may replace them"
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
  { command -v gcc && command -v make && command -v rsync; } >/dev/null 2>&1 || cmd_setup
  [[ -f $(src_dir)/Makefile ]] || cmd_source
  ko=$(cmd_build "$@" | tail -1)
  cmd_apply "$ko" --persist
}

usage() {
  cat <<EOF
pve-livepatch ${SCRIPT_VERSION} — live patch the running kernel (${KREL}) on Proxmox VE / Ubuntu
with the kernel's own klp-build (kernels >= 6.19 with CONFIG_KLP_BUILD=y)

Usage: $0 [-y] [-j N] <command> [args]

  check                               verify the kernel/host can be live patched
  setup [--minimal]                   install the kernel build toolchain
                                      (--minimal: only what loading needs, for fetch/auto)
  fetch <release-tag|URL>             download a CI-built module, verify, sign (no build)
  auto [run|enable|disable]           automatic live patches built by GitHub Actions for
                                      every new Proxmox kernel (enable = at boot + every 6 h)
  source [--full]                     fetch + prepare the exact kernel source for ${KREL}
  build <file.patch|URL> [--name N] [--non-replace]
                                      build livepatch-N.ko from a kernel source patch
  apply <livepatch-*.ko> [--persist]  load into running kernel (persist = load again on boot)
  status                              show loaded live patches
  remove <name>                       disable and unload a live patch
  clean                               delete kernel sources/build trees to free disk
  all <file.patch|URL> [--name N]     check → setup → source → build → apply --persist
  mok setup|status                    Secure Boot: create + enroll the module signing key
  canonical enable|status|disable     (Ubuntu) Canonical Livepatch via Ubuntu Pro

Options:
  -y        don't ask for confirmation
  -j N      parallel build jobs (default: nproc = ${JOBS})
  --full    download the full kernel source history (default: only the needed commit)

Env: PLATFORM (pve|ubuntu, auto-detected), PVE_LIVEPATCH_DIR (${WORKDIR}),
     PVE_LIVEPATCH_REPO (${RELEASE_REPO}, used by fetch/auto),
     PVE_COMMIT, MOK_KEY, MOK_CERT, UBUNTU_PRO_TOKEN

Example:
  $0 check
  $0 setup && $0 source
  $0 build https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id=<sha> --name cve_2026_xxxx
  $0 apply ${WORKDIR}/out/${KREL}/livepatch-cve_2026_xxxx.ko --persist
EOF
}

# ----------------------------------------------------------------------------- main
main() {
  set -Eeuo pipefail
  trap 'die "failed at line $LINENO: $BASH_COMMAND"' ERR
  while [[ $# -gt 0 ]]; do
    case $1 in
      -y|--yes) ASSUME_YES=1; shift ;;
      -j)       JOBS=$2; shift 2 ;;
      --full)   FULL=1; shift ;;
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
    setup)     cmd_setup "$@" ;;
    fetch)     cmd_fetch "$@" ;;
    auto)      cmd_auto "$@" ;;
    boot)      cmd_boot ;;
    source)    cmd_source "$@" ;;
    build)     cmd_build "$@" ;;
    apply)     cmd_apply "$@" ;;
    status)    cmd_status ;;
    remove)    cmd_remove "$@" ;;
    clean)     cmd_clean ;;
    mok)       cmd_mok "$@" ;;
    canonical) cmd_canonical "$@" ;;
    all)       cmd_all "$@" ;;
    *) die "unknown command: $cmd (see --help)" ;;
  esac
}

# run main unless the file is being sourced (the test suite sources it)
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
