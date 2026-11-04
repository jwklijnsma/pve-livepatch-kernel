#!/usr/bin/env bash
# =============================================================================
# pve-livepatch-build.sh — BUILD side of pve-livepatch. Runs in GitHub Actions
# (ci/build-livepatch.sh), not on your nodes.
#
#   setup    – install the kernel build toolchain (Debian/Ubuntu)
#   source   – fetch the EXACT kernel source for $KREL
#                Proxmox VE: pve-kernel git @ matching "bump version" commit
#                            + Proxmox kernel patches
#                Ubuntu:     `apt-get source` of the kernel package
#   build    – the kernel's own scripts/livepatch/klp-build (kernels >= 6.19)
#              turns a source .patch into livepatch-<name>.ko; signed with
#              MOK_KEY / MOK_CERT when they are set
#   clean    – delete sources and build trees
#
# klp-build compiles the original and the patched kernel (vmlinux + all
# modules): ~30 GB disk and a few hours. Its patches are "atomic replace" by
# default (--non-replace to change that).
# =============================================================================
readonly SCRIPT_VERSION="3.0.0"
readonly WORKDIR="${PVE_LIVEPATCH_DIR:-/var/lib/pve-livepatch}"
readonly PVE_KERNEL_REPO="${PVE_KERNEL_REPO:-https://git.proxmox.com/git/pve-kernel.git}"
readonly UPSTREAM_KERNEL_GIT="${UPSTREAM_KERNEL_GIT:-https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git https://github.com/gregkh/linux.git}"
# the kernel to build for (CI sets these; defaults: the running kernel)
KREL="${KREL:-$(uname -r)}"; readonly KREL
readonly KCONFIG="${KCONFIG:-/boot/config-${KREL}}"
readonly OS_RELEASE="${OS_RELEASE:-/etc/os-release}"
MOK_KEY="${MOK_KEY:-}"; MOK_CERT="${MOK_CERT:-}"     # signing key + certificate (optional)
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

# ----------------------------------------------------------------------------- platform
# PLATFORM = pve | ubuntu
detect_platform() {
  if [[ -n ${PLATFORM:-} ]]; then :
  elif command -v pveversion >/dev/null 2>&1 || [[ $KREL == *-pve ]]; then PLATFORM=pve
  elif [[ -r $OS_RELEASE ]] && grep -qE '^ID="?ubuntu"?$' "$OS_RELEASE"; then PLATFORM=ubuntu
  else die "unsupported platform (need a Proxmox VE or Ubuntu kernel); override with PLATFORM=pve|ubuntu"
  fi
  [[ $PLATFORM == pve || $PLATFORM == ubuntu ]] || die "PLATFORM must be pve or ubuntu"
  readonly PLATFORM
}

# ----------------------------------------------------------------------------- setup
cmd_setup() {
  need_root
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  log "Installing the kernel build toolchain for klp-build"
  apt-get install -y --no-install-recommends \
    git build-essential bc bison flex cpio rsync kmod curl ca-certificates gawk patch \
    patchutils libxxhash-dev openssl \
    libelf-dev libdw-dev elfutils libssl-dev dwarves python3 zstd pkg-config \
    dpkg-dev
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

  if [[ -n $MOK_KEY ]]; then
    sign_module "$ko"
  else
    warn "MOK_KEY/MOK_CERT not set — module NOT signed (it will not load with Secure Boot on)"
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
  [[ -r $MOK_KEY && -r $MOK_CERT ]] || die "signing key '${MOK_KEY}' or certificate '${MOK_CERT}' not readable"
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


usage() {
  cat <<EOF
pve-livepatch-build ${SCRIPT_VERSION} — build live patches for kernel ${KREL} with klp-build
(used by GitHub Actions; nodes only need pve-livepatch to load the result)

Usage: $0 [-y] [-j N] [--full] <command> [args]

  setup                               install the kernel build toolchain
  source                              fetch + prepare the exact kernel source for ${KREL}
  build <file.patch|URL> [--name N] [--non-replace]
                                      build livepatch-N.ko (signed when MOK_KEY/MOK_CERT are set)
  clean                               delete kernel sources/build trees

Env: KREL, KCONFIG (kernel to build for), PLATFORM (pve|ubuntu), PVE_KERNEL_PKGVER,
     PVE_LIVEPATCH_DIR (${WORKDIR}), PVE_COMMIT, MOK_KEY, MOK_CERT
EOF
}

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
  case $cmd in ""|help) usage; exit 0 ;; esac
  detect_platform
  case $cmd in
    setup)  cmd_setup "$@" ;;
    source) cmd_source "$@" ;;
    build)  cmd_build "$@" ;;
    clean)  cmd_clean ;;
    *) die "unknown command: $cmd (see --help)" ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
