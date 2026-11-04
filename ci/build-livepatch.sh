#!/usr/bin/env bash
# Build a live-patch module for a Proxmox VE kernel that is NOT running here.
# Used by .github/workflows/build-livepatch.yml inside a Debian container
# (Debian 13 "trixie" for PVE 9), but works on any Debian box as root.
#
# Usage: ci/build-livepatch.sh <kernel> <patch-file|URL|directory> <name> [dist=trixie]
#   kernel  Proxmox kernel release as shown by `uname -r`, e.g. 7.0.14-26-pve
#   patch   kernel source patch: URL or path (relative to the repo root is fine).
#           A directory (patches/auto) makes one cumulative patch from every
#           *.patch in it that still applies to this kernel; fixes the kernel
#           already contains are skipped. If none is left, no module is built.
#   name    module name: letters, digits, _ (max 40)
#
# Output in dist/: livepatch-<name>-<kernel>.ko, <name>.patch, build.log, SHA256SUMS
#                  (+ PATCHSET for a directory: which patches went in)
set -Eeuo pipefail

KERNEL=${1:?kernel release required, e.g. 7.0.14-26-pve}
PATCH=${2:?patch file or URL required}
NAME=${3:?name required}
DIST=${4:-trixie}
PVE_REPO_BASE=${PVE_REPO_BASE:-http://download.proxmox.com/debian/pve}

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
LP="$REPO_DIR/pve-livepatch.sh"
export PVE_LIVEPATCH_DIR=${PVE_LIVEPATCH_DIR:-$REPO_DIR/_build}
DIST_DIR="$REPO_DIR/dist"
mkdir -p "$PVE_LIVEPATCH_DIR" "$DIST_DIR"

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
# on failure, show the important part of the build logs in the job log
on_exit() {
  local rc=$? f
  if (( rc != 0 )); then
    for f in "$PVE_LIVEPATCH_DIR"/out/*/*-build*.log; do
      [[ -s $f ]] || continue
      echo "::group::errors in $f"
      grep -nE 'error|Error|ERROR|\*\*\*|undefined reference|No such file' "$f" | tail -n 40 || true
      echo "::endgroup::"
      echo "::group::last 80 lines of $f"
      tail -n 80 "$f"
      echo "::endgroup::"
    done
  fi
}
trap on_exit EXIT

[[ $KERNEL =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-pve$ ]] || die "kernel must look like 7.0.14-26-pve (got '$KERNEL')"
[[ $NAME =~ ^[A-Za-z0-9_]{1,40}$ ]] || die "name must be letters, digits or _ (max 40), got '$NAME'"
[[ $DIST =~ ^[a-z]+$ ]] || die "invalid dist '$DIST'"
if [[ ! $PATCH =~ ^https?:// && $PATCH != /* ]]; then PATCH="$REPO_DIR/$PATCH"; fi
[[ $PATCH =~ ^https?:// || -r $PATCH ]] || die "patch not found: $PATCH"
rm -f "$DIST_DIR"/*.ko "$DIST_DIR"/*.patch "$DIST_DIR"/build.log "$DIST_DIR"/PATCHSET "$DIST_DIR"/SHA256SUMS

export DEBIAN_FRONTEND=noninteractive
log "Base packages"
apt-get update -qq
apt-get install -y -qq --no-install-recommends curl ca-certificates gzip >/dev/null

# --- 1. kernel package version + exact config from the Proxmox repository ----------
log "Looking up ${KERNEL} in ${PVE_REPO_BASE} (${DIST})"
meta=$(mktemp -d)
pkgver="" config=""
for comp in pve-no-subscription pve-test; do
  curl -fsSL "${PVE_REPO_BASE}/dists/${DIST}/${comp}/binary-amd64/Packages.gz" -o "$meta/Packages.gz" 2>/dev/null || continue
  for pkg in "proxmox-kernel-${KERNEL}-signed" "proxmox-kernel-${KERNEL}"; do
    ver="" file=""
    # print "Version Filename" of the stanza whose Package line matches exactly
    read -r ver file < <(gunzip -c "$meta/Packages.gz" | awk -v p="Package: $pkg" '
      $0 == p {hit=1} hit && /^Version: /{v=$2} hit && /^Filename: /{f=$2} /^$/{ if (hit) {print v, f; exit} hit=0 }
      END { if (hit) print v, f }') || true
    [[ -n ${file:-} ]] || continue
    echo "found ${pkg} ${ver} in ${comp}"
    curl -fsSL "${PVE_REPO_BASE}/${file}" -o "$meta/kernel.deb" || continue
    mkdir -p "$meta/x"
    dpkg-deb --fsys-tarfile "$meta/kernel.deb" | tar -x -C "$meta/x" --wildcards "*boot/config-${KERNEL}" 2>/dev/null || true
    if [[ -f $meta/x/boot/config-${KERNEL} ]]; then
      pkgver=$ver; config="$PVE_LIVEPATCH_DIR/config-${KERNEL}"
      cp "$meta/x/boot/config-${KERNEL}" "$config"
      break 2
    fi
    echo "  (no /boot/config in ${pkg}, trying next)"
  done
done
rm -rf "$meta"
[[ -n $config ]] || die "kernel ${KERNEL} not found in the Proxmox ${DIST} repository (pve-no-subscription, pve-test)"
echo "kernel package version: ${pkgver}"

grep -qx 'CONFIG_KLP_BUILD=y' "$config" || die "${KERNEL} is not built with CONFIG_KLP_BUILD=y — klp-build cannot make live patches for it"

# --- 2. toolchain and compiler match -------------------------------------------------
# this container is plain Debian: tell pve-livepatch which kernel/platform it builds for
export KREL=$KERNEL KCONFIG=$config PLATFORM=pve PVE_KERNEL_PKGVER=$pkgver

log "Installing build toolchain"
"$LP" -y setup

want=$(sed -n 's/^CONFIG_CC_VERSION_TEXT="\(.*\)"$/\1/p' "$config")
have=$(gcc --version | head -1)
echo "kernel built with: ${want}"
echo "this container:    ${have}"
if [[ $want != "$have" ]]; then
  [[ ${ALLOW_GCC_MISMATCH:-0} == 1 ]] || die "compiler differs from the one Proxmox used — use a container image with '${want}' (or set ALLOW_GCC_MISMATCH=1 at your own risk)"
  echo "WARNING: compiler mismatch allowed by ALLOW_GCC_MISMATCH=1"
fi

# --- 3. source + build ---------------------------------------------------------------
log "Preparing Proxmox kernel source"
"$LP" -y source

if [[ -d $PATCH ]]; then
  # cumulative patch from a directory: keep what still applies to this kernel
  src="$PVE_LIVEPATCH_DIR/src/$KERNEL"
  combined="$DIST_DIR/${NAME}.patch"
  applied=() skipped=()
  : > "$combined"
  shopt -s nullglob
  for p in "$PATCH"/*.patch; do
    # check on top of the patches taken so far (they may touch the same file)
    if cat "$combined" "$p" | patch --dry-run --forward --batch -p1 -d "$src" >/dev/null 2>&1; then
      cat "$p" >> "$combined"; applied+=("$(basename "$p")")
    else
      skipped+=("$(basename "$p")")
    fi
  done
  shopt -u nullglob
  { echo "patchset ${NAME}"
    echo "kernel ${KERNEL}"
    echo "applied: ${applied[*]:-none}"
    echo "skipped (already in this kernel, or no longer applies): ${skipped[*]:-none}"
  } > "$DIST_DIR/PATCHSET"
  cat "$DIST_DIR/PATCHSET"
  if (( ${#applied[@]} == 0 )); then
    rm -f "$combined"
    (cd "$DIST_DIR" && sha256sum PATCHSET > SHA256SUMS)
    log "Nothing to build: no patch in the set applies to ${KERNEL}"
    exit 0
  fi
  PATCH=$combined
fi

log "Building live patch ${NAME}"
"$LP" -y build "$PATCH" --name "$NAME"

# --- 4. release assets -----------------------------------------------------------------
out="$PVE_LIVEPATCH_DIR/out/$KERNEL"
cp "$out/livepatch-${NAME}.ko" "$DIST_DIR/livepatch-${NAME}-${KERNEL}.ko"
cp "$(ls -t "$out"/*-build-"${NAME}".log | head -1)" "$DIST_DIR/build.log"
if [[ $PATCH =~ ^https?:// ]]; then
  cp "$(ls -t "$PVE_LIVEPATCH_DIR"/patches/*.patch | head -1)" "$DIST_DIR/${NAME}.patch"
elif [[ $PATCH != "$DIST_DIR/${NAME}.patch" ]]; then
  cp "$PATCH" "$DIST_DIR/${NAME}.patch"
fi
sums=("livepatch-${NAME}-${KERNEL}.ko" "${NAME}.patch"); [[ -f $DIST_DIR/PATCHSET ]] && sums+=(PATCHSET)
(cd "$DIST_DIR" && sha256sum "${sums[@]}" > SHA256SUMS)
log "Done"
ls -l "$DIST_DIR"
modinfo "$DIST_DIR/livepatch-${NAME}-${KERNEL}.ko" | grep -E '^(name|vermagic|livepatch):' || true
