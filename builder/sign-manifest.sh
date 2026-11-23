#!/usr/bin/env bash
# Sign a manifest and stage it in the static repository tree.
# Run this only after the QEMU stage passed, on the signing runner.
#
# usage: sign-manifest.sh <outdir-of-build.sh> <repo-root> [ring]
#
# MANIFEST_KEY  pve-klp-tool secret key, or use `minisign -S` instead.
source "$(dirname "$0")/lib.sh"
OUT=${1:?outdir}; REPO=${2:?repo root}; RING=${3:-canary}
require pve-klp-tool python3
M="$OUT/manifest.json"
KVER=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["kernel"])' "$M")
MOD=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["module"])' "$M")
DST="$REPO/v1/$KVER"
mkdir -p "$DST/$RING"

if [ "$RING" != canary ]; then
  pve-klp-tool promote --manifest "$M" --ring "$RING" --out "$OUT/manifest.$RING.json"
  M="$OUT/manifest.$RING.json"
fi
cp "$OUT/$MOD" "$DST/$MOD"
cp "$OUT/build.log" "$OUT/functions.txt" "$OUT/gate-a.txt" "$OUT/resolved.json" "$DST/" 2>/dev/null || true
cp "$M" "$DST/$RING/manifest.json.new"
pve-klp-tool sign --key "${MANIFEST_KEY:?MANIFEST_KEY not set}" \
  --trusted-comment "kernel:$KVER ring:$RING file:manifest.json" "$DST/$RING/manifest.json.new"
# Publish signature first, manifest last, so readers never see a manifest
# without its signature.
mv "$DST/$RING/manifest.json.new.minisig" "$DST/$RING/manifest.json.minisig"
mv "$DST/$RING/manifest.json.new" "$DST/$RING/manifest.json"
log "published $KVER ring $RING"
