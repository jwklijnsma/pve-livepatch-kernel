#!/usr/bin/env bash
# Sign a manifest and stage it in the static repository tree.
#
# usage: sign-manifest.sh [--skip-qemu-stage] <outdir-of-build.sh> <repo-root> [ring]
#
# Refuses unless qemu-test.sh passed for exactly this module (out/qemu.ok
# with the module's SHA-256). --skip-qemu-stage overrides that; it is meant
# for emergencies and is recorded in the trusted comment of the signature.
#
# MANIFEST_KEY  pve-klp-tool secret key (or sign with `minisign -S` instead).
source "$(dirname "$0")/lib.sh"
SKIP_QEMU=0
if [ "${1:-}" = "--skip-qemu-stage" ]; then SKIP_QEMU=1; shift; fi
OUT=${1:?outdir}; REPO=${2:?repo root}; RING=${3:-canary}
require pve-klp-tool python3 sha256sum
M="$OUT/manifest.json"
KVER=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["kernel"])' "$M")
MOD=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["module"])' "$M")
SUM=$(sha256sum "$OUT/$MOD" | cut -d' ' -f1)
[ "$SUM" = "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$M")" ] \
  || die "$OUT/$MOD does not match the manifest hash"

QEMU_NOTE="qemu:passed"
if [ "$SKIP_QEMU" = 1 ]; then
  log "WARNING: signing without a QEMU pass (--skip-qemu-stage)"
  QEMU_NOTE="qemu:SKIPPED"
else
  [ -f "$OUT/qemu.ok" ] || die "no QEMU pass for this build: run qemu-test.sh first"
  grep -qx "module_sha256=$SUM" "$OUT/qemu.ok" || die "qemu.ok belongs to a different module build: run qemu-test.sh again"
fi

DST="$REPO/v1/$KVER"
mkdir -p "$DST/$RING"
if [ "$RING" != canary ]; then
  pve-klp-tool promote --manifest "$M" --ring "$RING" --out "$OUT/manifest.$RING.json"
  M="$OUT/manifest.$RING.json"
fi
cp "$OUT/$MOD" "$DST/$MOD"
for f in build.log functions.txt gate-a.txt resolved.json config-check.txt qemu.ok qemu.log; do
  [ -f "$OUT/$f" ] && cp "$OUT/$f" "$DST/"
done
cp "$M" "$DST/$RING/manifest.json.new"
pve-klp-tool sign --key "${MANIFEST_KEY:?MANIFEST_KEY not set}" \
  --trusted-comment "kernel:$KVER ring:$RING file:manifest.json $QEMU_NOTE" "$DST/$RING/manifest.json.new"
# Publish signature first, manifest last, so readers never see a manifest
# without its signature.
mv "$DST/$RING/manifest.json.new.minisig" "$DST/$RING/manifest.json.minisig"
mv "$DST/$RING/manifest.json.new" "$DST/$RING/manifest.json"
log "published $KVER ring $RING"
