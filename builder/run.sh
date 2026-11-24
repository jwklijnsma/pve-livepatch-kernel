#!/usr/bin/env bash
# Build, sign and test one livepatch module in the builder image.
#
# usage: builder/run.sh <kver> <level> [previous-level.ko]
#
# Four containers, each with only what it needs:
#   fetch   fetch-shipped.sh  the packages Proxmox shipped -> shipped/;
#                             nothing else mounted, no code from the tree
#   build   build.sh          repository read-only, shipped/ read-only,
#                             build/<kver> writable, no keys (it runs
#                             kernel Makefiles and catalog patches)
#   sign    sign-module.sh    out/ writable, shipped/ read-only, the module
#                             key read-only; no kernel tree, no catalog, no
#                             network
#   test    qemu-test.sh      out/ writable, shipped/ and the catalog
#                             read-only; no tree, no keys, no network
# Signing the manifest (publish.sh) is a separate step on the signing host.
#
# Environment:
#   ENGINE        podman (default) or docker
#   KEYS          directory with module.priv and module-cert.der
#                 (default: ./keys; keep it outside the repository if you can)
#   CATALOG       catalog directory inside the repository (default: catalog)
#   MIN_FREE_GB   free space required in build/ (default 60, 15 with a cached tree)
#   CYCLES        patch/unpatch cycles in the QEMU stage (default 5)
set -euo pipefail
KVER=${1:?usage: builder/run.sh <kver> <level> [previous-level.ko]}
LEVEL=${2:?level}
PREV=${3:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ENGINE=${ENGINE:-podman}
KEYS=${KEYS:-$ROOT/keys}
CATALOG=${CATALOG:-catalog}
IMAGE=hvpatch-builder

die() { echo "run.sh: $*" >&2; exit 1; }
command -v "$ENGINE" >/dev/null || die "$ENGINE not found (set ENGINE=docker?)"
[ -x "$ROOT/builder/hvpatch-tool" ] || die "builder/hvpatch-tool missing: run 'make builder-image', or download
        hvpatch-tool-x86_64-linux-musl from the release page to builder/hvpatch-tool"
KEYS=$(cd "$KEYS" 2>/dev/null && pwd) || die "key directory $KEYS not found (see docs/self-hosting.md)"
for f in module.priv module-cert.der; do
  [ -f "$KEYS/$f" ] || die "$KEYS/$f missing (see docs/self-hosting.md)"
done

# One build tree (original + patched kernel) needs about 52 GB; a rebuild
# with a cached original far less. Fail now rather than after an hour.
BUILD="$ROOT/build/$KVER"
mkdir -p "$BUILD"
if [ -d "$BUILD/src/.git" ]; then NEED_GB=${MIN_FREE_GB:-15}; else NEED_GB=${MIN_FREE_GB:-60}; fi
FREE_GB=$(df -Pk "$BUILD" | awk 'NR == 2 { print int($4 / 1024 / 1024) }')
if [ "$FREE_GB" -lt "$NEED_GB" ]; then
  die "only ${FREE_GB} GB free in $ROOT/build, need about ${NEED_GB} GB
        (remove old trees in build/, or set MIN_FREE_GB to override)"
fi

"$ENGINE" build -q -t "$IMAGE" -f "$ROOT/builder/Containerfile" "$ROOT/builder" >/dev/null
IMAGE_ID=$("$ENGINE" image inspect "$IMAGE" --format '{{.Id}}')
case "$IMAGE_ID" in sha256:*) ;; *) IMAGE_ID="sha256:$IMAGE_ID" ;; esac

PREV_ARG=()
if [ -n "$PREV" ]; then
  [ -f "$PREV" ] || die "previous module $PREV not found"
  PREV=$(cd "$(dirname "$PREV")" && pwd)/$(basename "$PREV")
fi
DEV=()
[ -e /dev/kvm ] && DEV=(--device /dev/kvm)

W=/work/build/$KVER
# Each stage gets single directories, never all of build/<kver>: a stage
# cannot replace a mount point, so it cannot turn out/ or shipped/ into a
# symlink that the host would follow when mounting them for the next stage.
for d in shipped src out cache; do
  [ -L "$BUILD/$d" ] && die "$BUILD/$d is a symlink; remove it"
  mkdir -p "$BUILD/$d"
done
check_dirs() {
  for d in shipped out; do
    { [ -d "$BUILD/$d" ] && [ ! -L "$BUILD/$d" ]; } || die "$BUILD/$d is not a plain directory any more"
  done
}
SHIPPED_RO=(-v "$BUILD/shipped:$W/shipped:ro")

# Shipped artifacts: fetched once per kernel release; delete
# build/<kver>/shipped to fetch them again.
if [ ! -s "$BUILD/shipped/build-id" ]; then
  echo "run.sh: [0/3] fetch the shipped kernel packages"
  find "$BUILD/shipped" -mindepth 1 -delete
  "$ENGINE" run --rm -v "$BUILD/shipped:$W/shipped" \
    "$IMAGE" /opt/hvpatch/builder/fetch-shipped.sh "$KVER" "$W/shipped"
fi

echo "run.sh: [1/3] build (no keys)"
"$ENGINE" run --rm -v "$ROOT:/work:ro" "${SHIPPED_RO[@]}" \
  -v "$BUILD/src:$W/src" -v "$BUILD/out:$W/out" -v "$BUILD/cache:$W/cache" -w /work \
  -e BUILDER_IMAGE="$IMAGE_ID" -e CATALOG="/work/$CATALOG" \
  "$IMAGE" /opt/hvpatch/builder/build.sh "$KVER" "$LEVEL" "$W"
if ! compgen -G "$BUILD/out/klp_*.ko" >/dev/null; then
  echo "run.sh: no module was built (nothing to livepatch for $KVER)"
  exit 0
fi

check_dirs
echo "run.sh: [2/3] sign (key only here, no tree, no network)"
"$ENGINE" run --rm --network=none \
  -v "$BUILD/out:$W/out" "${SHIPPED_RO[@]}" -v "$KEYS:/keys:ro" \
  -e BUILDER_IMAGE="$IMAGE_ID" -e MODULE_KEY=/keys/module.priv -e MODULE_CERT=/keys/module-cert.der \
  "$IMAGE" /opt/hvpatch/builder/sign-module.sh "$KVER" "$LEVEL" "$W"

check_dirs
echo "run.sh: [3/3] QEMU stage (no tree, no keys, no network)"
PREV_MOUNT=()
if [ -n "$PREV" ]; then
  PREV_MOUNT=(-v "$PREV:/prev/$(basename "$PREV"):ro")
  PREV_ARG=("/prev/$(basename "$PREV")")
fi
"$ENGINE" run --rm --network=none ${DEV[@]+"${DEV[@]}"} \
  -v "$BUILD/out:$W/out" "${SHIPPED_RO[@]}" -v "$ROOT/$CATALOG:/work/catalog:ro" \
  ${PREV_MOUNT[@]+"${PREV_MOUNT[@]}"} -w /work \
  -e CYCLES="${CYCLES:-5}" -e CATALOG=/work/catalog \
  "$IMAGE" /opt/hvpatch/builder/qemu-test.sh "$KVER" "$W" ${PREV_ARG[@]+"${PREV_ARG[@]}"}

echo "run.sh: done. Signed module and unsigned manifest in build/$KVER/out;"
echo "        publish on the signing host with builder/publish.sh"
