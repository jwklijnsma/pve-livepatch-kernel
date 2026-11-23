#!/usr/bin/env bash
# Build and test one livepatch module in the builder container.
#
# usage: builder/run.sh <kver> <level> [previous-level.ko]
#
# Runs build.sh and qemu-test.sh in the pve-klp-builder image and records
# the image id in the manifest. Signing the manifest is a separate step
# (sign-manifest.sh), ideally on another machine.
#
# Environment:
#   ENGINE     podman (default) or docker
#   KEYS       directory with module.priv and module-cert.der (default: ./keys)
#   CATALOG    catalog directory inside the repository (default: catalog)
set -euo pipefail
KVER=${1:?usage: builder/run.sh <kver> <level> [previous-level.ko]}
LEVEL=${2:?level}
PREV=${3:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ENGINE=${ENGINE:-podman}
KEYS=${KEYS:-$ROOT/keys}
CATALOG=${CATALOG:-catalog}
IMAGE=pve-klp-builder

command -v "$ENGINE" >/dev/null || { echo "run.sh: $ENGINE not found (set ENGINE=docker?)" >&2; exit 1; }
[ -x "$ROOT/builder/pve-klp-tool" ] || {
  echo "run.sh: builder/pve-klp-tool missing: run 'make builder-image', or download" >&2
  echo "        pve-klp-tool-x86_64-linux-musl from the release page to builder/pve-klp-tool" >&2
  exit 1
}
for f in module.priv module-cert.der; do
  [ -f "$KEYS/$f" ] || { echo "run.sh: $KEYS/$f missing (see docs/self-hosting.md)" >&2; exit 1; }
done
case "$KEYS" in "$ROOT"/*) ;; *) echo "run.sh: KEYS must be inside $ROOT (it is mounted into the container)" >&2; exit 1 ;; esac

"$ENGINE" build -q -t "$IMAGE" "$ROOT/builder" >/dev/null
IMAGE_ID=$("$ENGINE" image inspect "$IMAGE" --format '{{.Id}}')
case "$IMAGE_ID" in sha256:*) ;; *) IMAGE_ID="sha256:$IMAGE_ID" ;; esac

DEV=()
[ -e /dev/kvm ] && DEV=(--device /dev/kvm)
PREV_ARG=()
if [ -n "$PREV" ]; then
  PREV=$(cd "$(dirname "$PREV")" && pwd)/$(basename "$PREV")
  case "$PREV" in "$ROOT"/*) PREV_ARG=("/work/${PREV#"$ROOT"/}") ;; *) echo "run.sh: previous module must be inside $ROOT" >&2; exit 1 ;; esac
fi

WORK=/work/build/$KVER
"$ENGINE" run --rm ${DEV[@]+"${DEV[@]}"} -v "$ROOT:/work" -w /work \
  -e BUILDER_IMAGE="$IMAGE_ID" \
  -e CATALOG="/work/$CATALOG" \
  -e MODULE_KEY="/work/${KEYS#"$ROOT"/}/module.priv" \
  -e MODULE_CERT="/work/${KEYS#"$ROOT"/}/module-cert.der" \
  "$IMAGE" bash -c '
    set -euo pipefail
    /opt/pve-klp/builder/build.sh "$0" "$1" "$2"
    [ -f "$2/out/manifest.json" ] || exit 0
    /opt/pve-klp/builder/qemu-test.sh "$0" "$2" "${3:-}"
  ' "$KVER" "$LEVEL" "$WORK" ${PREV_ARG[@]+"${PREV_ARG[@]}"}
echo "run.sh: done. Module and unsigned manifest in build/$KVER/out; sign with builder/sign-manifest.sh"
