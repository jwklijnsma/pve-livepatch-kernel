#!/usr/bin/env bash
# Check out the Proxmox kernel source for exactly one release, with Proxmox's
# patches applied.
#
# 7.3 lives in proxmox-kernel.git (branch proxmox/7.3, tags proxmox/<pkgver>),
# an upstream-stable tree with Debian packaging and debian/patches. It is NOT
# in pve-kernel.git, which carries the Ubuntu-based 7.0 series.
#
# usage: fetch-source.sh <kver> <outdir>
source "$(dirname "$0")/lib.sh"
KVER=${1:?kver}; OUT=${2:?outdir}
require git quilt
REPO=${PROXMOX_KERNEL_GIT:-https://git.proxmox.com/git/proxmox-kernel.git}
TAG="proxmox/$(pkgver "$KVER")"

# Same release already prepared: keep the tree and klp-tmp, so klp-build can
# reuse the original build (--short-circuit).
if [ "$(cat "$OUT/.pve-klp-tag" 2>/dev/null)" = "$TAG" ]; then
  # Leftover of v0.1.0's build.sh; it doubles the release suffix.
  rm -f "$OUT/localversion-pve"
  log "source for $KVER already prepared at $OUT"
  exit 0
fi

if [ ! -d "$OUT/.git" ]; then
  git clone --filter=blob:none --no-checkout "$REPO" "$OUT"
fi
git -C "$OUT" fetch --tags origin
git -C "$OUT" -c advice.detachedHead=false checkout --force "$TAG"
git -C "$OUT" clean -fdxq

# Apply Proxmox's patch queue.
( cd "$OUT" && QUILT_PATCHES=debian/patches quilt push -aq ) || die "applying debian/patches failed"
# Commit the patched state so klp-build and `git apply --check` see a clean tree.
git -C "$OUT" -c user.name=pve-klp -c user.email=pve-klp@localhost add -A
git -C "$OUT" -c user.name=pve-klp -c user.email=pve-klp@localhost commit -qm "pve-klp: $TAG with debian/patches"
printf '%s' "$TAG" > "$OUT/.pve-klp-tag"
log "source for $KVER at $OUT ($(git -C "$OUT" rev-parse --short HEAD))"
