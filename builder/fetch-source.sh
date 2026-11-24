#!/usr/bin/env bash
# Check out the Proxmox kernel source for exactly one release, with Proxmox's
# patches applied.
#
# 7.3 and later (opt-in) live in proxmox-kernel.git (branch proxmox/7.3,
# tags proxmox/<pkgver>), an upstream-stable tree with Debian packaging and
# debian/patches. kernels.lock pins the tag's commit.
#
# 7.0 (experimental) lives in pve-kernel.git: the Ubuntu kernel as a
# submodule plus patches/kernel/*.patch, prepared like pve-kernel's Makefile
# does (EXTRAVERSION, debian/ removed, `patch --batch -p1`). kernels.lock
# pins the pve-kernel commit; its Makefile must name exactly this release.
# objtool needs the backports in builder/kernel-7.0/objtool (see the README
# there), applied as a separate commit.
#
# usage: fetch-source.sh <kver> <outdir>
#
# A moved tag, a tampered mirror or an unlisted release stops the build.
source "$(dirname "$0")/lib.sh"
KVER=${1:?kver}; OUT=${2:?outdir}
HERE=$(cd "$(dirname "$0")" && pwd)
LOCK=${KERNELS_LOCK:-$HERE/kernels.lock}
WANT=$(awk -v k="$KVER" '$1 == k { print $2 }' "$LOCK" 2>/dev/null || true)
SERIES=$(series "$KVER")

# A reused tree must be exactly the reviewed commit plus Proxmox's patch
# queue, and clean: an interrupted klp-build can leave patches applied.
# For 7.0 the tree is the Ubuntu kernel commit named by the locked
# pve-kernel commit; .hvpatch-base records it and how many commits of ours
# (Proxmox patches, objtool backports) sit on top.
check_tree() {
  local base=$WANT depth=1
  if [ -f "$OUT/.hvpatch-base" ]; then read -r base depth < "$OUT/.hvpatch-base"; fi
  [ "$(git -C "$OUT" rev-parse "HEAD~$depth^{commit}")" = "$base" ] || die "$OUT is not based on the locked commit $base"
  [ -z "$(git -C "$OUT" status --porcelain --untracked-files=no)" ] || die "$OUT has uncommitted changes; remove the tree and build again"
}
require git quilt patch
PKGVER=$(pkgver "$KVER")

if [ "$SERIES" = 7.0 ]; then
  REPO=${PVE_KERNEL_GIT:-https://git.proxmox.com/git/pve-kernel.git}
  UBUNTU=${PVE_UBUNTU_KERNEL_GIT:-https://git.proxmox.com/git/mirror_ubuntu-kernels.git}
  PVE=${PVE_KERNEL_DIR:-$(dirname "$OUT")/cache/pve-kernel}
  TAG="pve-kernel@$WANT"
  if [ "$(cat "$OUT/.hvpatch-tag" 2>/dev/null)" = "$TAG" ] && [ -n "$WANT" ]; then
    check_tree
    log "source for $KVER already prepared at $OUT"
    exit 0
  fi
  [ -d "$PVE/.git" ] || git clone -q --filter=blob:none --no-checkout "$REPO" "$PVE"
  git -C "$PVE" fetch -q origin '+refs/heads/*:refs/remotes/origin/*' --tags
  if [ -z "$WANT" ]; then
    CAND=$(git -C "$PVE" rev-parse -q --verify "refs/tags/proxmox-kernel-$KVER^{commit}" 2>/dev/null \
      || git -C "$PVE" log --all -1 --format=%H -G"[(]${PKGVER}[)]" -- debian/changelog || true)
    die "$KVER is not in $LOCK. Find the pve-kernel commit that released $PKGVER (candidate: ${CAND:-none found}),
        review it, and add this line: $KVER <commit>"
  fi
  git -C "$PVE" cat-file -e "$WANT^{commit}" 2>/dev/null || die "locked commit $WANT is not in $REPO"
  git -C "$PVE" -c advice.detachedHead=false checkout -q --force "$WANT"
  # The locked commit must build exactly this release.
  mk() { awk -F= -v k="$1" '$1 == k { print $2 }' "$PVE/Makefile"; }
  GOT_KVER="$(mk KERNEL_MAJ).$(mk KERNEL_MIN).$(mk KERNEL_PATCHLEVEL)-$(mk KREL)$(mk KREL_EXTRA)-pve"
  [ "$GOT_KVER" = "$KVER" ] || die "pve-kernel $WANT builds $GOT_KVER, not $KVER"
  UB=$(git -C "$PVE" ls-tree "$WANT" submodules/ubuntu-kernel | awk '$2 == "commit" { print $3 }')
  [ -n "$UB" ] || die "no submodules/ubuntu-kernel in pve-kernel $WANT"

  [ -d "$OUT/.git" ] || git clone -q --filter=blob:none --no-checkout "$UBUNTU" "$OUT"
  git -C "$OUT" cat-file -e "$UB^{commit}" 2>/dev/null || git -C "$OUT" fetch -q origin '+refs/heads/*:refs/remotes/origin/*' --tags
  git -C "$OUT" cat-file -e "$UB^{commit}" 2>/dev/null || die "Ubuntu kernel commit $UB not found in $UBUNTU"
  git -C "$OUT" -c advice.detachedHead=false checkout -q --force "$UB"
  git -C "$OUT" clean -fdxq
  # As pve-kernel's Makefile prepares its build directory.
  sed -i "s/^EXTRAVERSION.*$/EXTRAVERSION=-$(mk KREL)$(mk KREL_EXTRA)-pve/" "$OUT/Makefile"
  rm -rf "$OUT/debian" "$OUT/debian.master"
  for p in "$PVE"/patches/kernel/*.patch; do
    ( cd "$OUT" && patch --batch -p1 --no-backup-if-mismatch -s < "$p" ) || die "applying $(basename "$p") failed"
  done
  G=(-c user.name=hvpatch -c user.email=hvpatch@localhost)
  git -C "$OUT" "${G[@]}" add -A
  git -C "$OUT" "${G[@]}" commit -qm "hvpatch: pve-kernel $WANT ($PKGVER) on Ubuntu kernel $UB"
  DEPTH=1
  if grep -q 'is_alias_sym' "$OUT/tools/objtool/include/objtool/elf.h" 2>/dev/null; then
    log "objtool already has the klp helpers; no backports needed"
  else
    for p in "$HERE"/kernel-7.0/objtool/*.patch; do
      ( cd "$OUT" && patch --batch -p1 --no-backup-if-mismatch -s < "$p" ) \
        || die "objtool backport $(basename "$p") does not apply to this 7.0 tree"
    done
    if find "$OUT/tools/objtool" -name '*.rej' | grep -q .; then die "objtool backports left rejects"; fi
    git -C "$OUT" "${G[@]}" add -A
    git -C "$OUT" "${G[@]}" commit -qm "hvpatch: objtool klp backports for 7.0 (builder/kernel-7.0/objtool)"
    DEPTH=2
  fi
  printf '%s %s\n' "$UB" "$DEPTH" > "$OUT/.hvpatch-base"
  printf 'pve-kernel %s %s\nubuntu-kernel %s %s\n' "$(public_url "$REPO")" "$WANT" "$(public_url "$UBUNTU")" "$UB" > "$OUT/.hvpatch-source"
  printf '%s' "$TAG" > "$OUT/.hvpatch-tag"
  check_tree
  log "source for $KVER at $OUT ($(git -C "$OUT" rev-parse --short HEAD), experimental 7.0 path)"
  exit 0
fi

REPO=${PROXMOX_KERNEL_GIT:-https://git.proxmox.com/git/proxmox-kernel.git}
TAG="proxmox/$PKGVER"

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
rm -f "$OUT/.hvpatch-base"
printf 'proxmox-kernel %s %s (tag %s)\n' "$(public_url "$REPO")" "$WANT" "$TAG" > "$OUT/.hvpatch-source"
check_tree
log "source for $KVER at $OUT ($(git -C "$OUT" rev-parse --short HEAD))"
