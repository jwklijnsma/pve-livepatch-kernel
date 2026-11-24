#!/usr/bin/env bash
# Check out the Proxmox kernel source for exactly one release, with Proxmox's
# patches applied.
#
# 7.3 lives in proxmox-kernel.git (branch proxmox/7.3, tags proxmox/<pkgver>),
# an upstream-stable tree with Debian packaging and debian/patches. It is NOT
# in pve-kernel.git, which carries the Ubuntu-based 7.0 series.
#
# usage: fetch-source.sh <kver> <outdir>
#
# The tag must resolve to the commit recorded in kernels.lock (next to this
# script): a moved tag or a tampered mirror stops the build.
source "$(dirname "$0")/lib.sh"
KVER=${1:?kver}; OUT=${2:?outdir}
LOCK=${KERNELS_LOCK:-$(dirname "$0")/kernels.lock}
WANT=$(awk -v k="$KVER" '$1 == k { print $2 }' "$LOCK" 2>/dev/null || true)

# A reused tree must be exactly the reviewed commit plus Proxmox's patch
# queue, and clean: an interrupted klp-build can leave patches applied.
check_tree() {
  [ "$(git -C "$OUT" rev-parse 'HEAD~1^{commit}')" = "$WANT" ] || die "$OUT is not based on the locked commit $WANT"
  [ -z "$(git -C "$OUT" status --porcelain --untracked-files=no)" ] || die "$OUT has uncommitted changes; remove the tree and build again"
}
require git quilt
REPO=${PROXMOX_KERNEL_GIT:-https://git.proxmox.com/git/proxmox-kernel.git}
TAG="proxmox/$(pkgver "$KVER")"

# Same release already prepared: keep the tree and klp-tmp, so klp-build can
# reuse the original build (--short-circuit).
if [ "$(cat "$OUT/.hvpatch-tag" 2>/dev/null)" = "$TAG" ] && [ -n "$WANT" ]; then
  # Leftover of v0.1.0's build.sh; it doubles the release suffix.
  rm -f "$OUT/localversion-pve"
  check_tree
  log "source for $KVER already prepared at $OUT"
  exit 0
fi

if [ ! -d "$OUT/.git" ]; then
  git clone --filter=blob:none --no-checkout "$REPO" "$OUT"
fi
git -C "$OUT" fetch --tags origin
GOT=$(git -C "$OUT" rev-parse "$TAG^{commit}")
if [ -z "$WANT" ]; then
  die "$KVER is not in $LOCK. Review tag $TAG (commit $GOT) and add this line: $KVER $GOT"
fi
[ "$GOT" = "$WANT" ] || die "tag $TAG is commit $GOT, but kernels.lock says $WANT; refusing to build"
git -C "$OUT" -c advice.detachedHead=false checkout --force "$GOT"
git -C "$OUT" clean -fdxq

# Apply Proxmox's patch queue.
( cd "$OUT" && QUILT_PATCHES=debian/patches quilt push -aq ) || die "applying debian/patches failed"
# Commit the patched state so klp-build and `git apply --check` see a clean tree.
git -C "$OUT" -c user.name=hvpatch -c user.email=hvpatch@localhost add -A
git -C "$OUT" -c user.name=hvpatch -c user.email=hvpatch@localhost commit -qm "hvpatch: $TAG with debian/patches"
printf '%s' "$TAG" > "$OUT/.hvpatch-tag"
check_tree
log "source for $KVER at $OUT ($(git -C "$OUT" rev-parse --short HEAD))"
