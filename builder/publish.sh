#!/usr/bin/env bash
# Publish a built, signed and tested module to ring canary.
#
# usage: publish.sh [--skip-qemu-stage] <workdir-out> <repo-root>
#
# Refuses unless:
#   - qemu-test.sh passed for exactly this module (qemu.ok, module hash);
#     --skip-qemu-stage overrides that and is recorded in the signature
#   - the manifest matches the build output (check-manifest)
#   - the level is higher than the one canary has now
#   - no different file was published under the same name before
# Rings above canary only get what canary has: see promote.sh.
#
# MANIFEST_KEY (hvpatch-tool key) or MINISIGN_KEY (minisign) signs.
source "$(dirname "$0")/lib.sh"
SKIP_QEMU=0
if [ "${1:-}" = "--skip-qemu-stage" ]; then SKIP_QEMU=1; shift; fi
OUT=${1:?usage: publish.sh [--skip-qemu-stage] <workdir-out> <repo-root>}; REPO=${2:?repo root}
require hvpatch-tool python3 sha256sum cmp
M="$OUT/manifest.json"
field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$M" "$1"; }
KVER=$(field kernel); MOD=$(field module); LEVEL=$(field level); RING=$(field ring)
[ "$RING" = canary ] || die "a fresh build goes to canary first (manifest says $RING); use promote.sh for higher rings"

QEMU_NOTE="qemu:passed"
QEMU_ARGS=(--qemu-ok "$OUT/qemu.ok")
if [ "$SKIP_QEMU" = 1 ]; then
  log "WARNING: publishing without a QEMU pass (--skip-qemu-stage)"
  QEMU_NOTE="qemu:SKIPPED"
  QEMU_ARGS=()
else
  [ -f "$OUT/qemu.ok" ] || die "no QEMU pass for this build: run qemu-test.sh first"
fi
hvpatch-tool check-manifest --manifest "$M" --resolved "$OUT/resolved.json" --module "$OUT/$MOD" \
  ${QEMU_ARGS[@]+"${QEMU_ARGS[@]}"} || die "manifest does not match the build output; not publishing"

CURRENT=$(ring_level "$REPO" "$KVER" canary)
[ "$LEVEL" -gt "$CURRENT" ] || die "canary already has level $CURRENT; this build is level $LEVEL"

BASE="$REPO/v1/$KVER"
publish_file "$OUT/$MOD" "$BASE/$MOD"
publish_file "$OUT/${MOD%.ko}.source.tar.gz" "$BASE/${MOD%.ko}.source.tar.gz"
for k in "$OUT"/linux-"$KVER"-*.tar.xz; do
  [ -f "$k" ] && publish_file "$k" "$BASE/source/$(basename "$k")"
done
for f in build.log functions.txt gate-a.txt resolved.json config-check.txt qemu.ok qemu.log; do
  [ -f "$OUT/$f" ] && publish_file "$OUT/$f" "$BASE/$LEVEL/$f"
done
publish_ring "$REPO" "$KVER" canary "$M" "$LEVEL" "kernel:$KVER level:$LEVEL ring:canary $QEMU_NOTE"
