#!/usr/bin/env bash
# Promote the level published in the ring below to the next ring:
# canary -> early -> stable.
#
# usage: promote.sh <repo-root> <kver> <early|stable> <manifest-pubkey>
#
# Takes exactly what the lower ring serves: its signed manifest is verified
# with the given public key, the module in the repository must match its
# hash, and the target ring must not already have this level or a higher
# one. Nothing from a local build directory is involved.
#
# MANIFEST_KEY (hvpatch-tool key) or MINISIGN_KEY (minisign) signs.
source "$(dirname "$0")/lib.sh"
REPO=${1:?usage: promote.sh <repo-root> <kver> <early|stable> <pubkey>}; KVER=${2:?kver}; TO=${3:?ring}; PUB=${4:?pubkey}
require hvpatch-tool python3 sha256sum
case "$TO" in
  early) FROM=canary ;;
  stable) FROM=early ;;
  *) die "promote to early or stable (canary gets fresh builds via publish.sh)" ;;
esac
BASE="$REPO/v1/$KVER"
SRC="$BASE/$FROM/manifest.json"
[ -f "$SRC" ] || die "ring $FROM has nothing for $KVER"
hvpatch-tool verify --pubkey "$PUB" "$SRC" >/dev/null || die "the $FROM manifest does not verify with $PUB"
field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$SRC" "$1"; }
LEVEL=$(field level); MOD=$(field module); SHA=$(field sha256)
[ "$(sha256sum "$BASE/$MOD" | cut -d' ' -f1)" = "$SHA" ] || die "$BASE/$MOD does not match the $FROM manifest"
CURRENT=$(ring_level "$REPO" "$KVER" "$TO")
[ "$LEVEL" -gt "$CURRENT" ] || die "$TO already has level $CURRENT; $FROM offers $LEVEL"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
hvpatch-tool promote --manifest "$SRC" --ring "$TO" --out "$TMP/manifest.json"
publish_ring "$REPO" "$KVER" "$TO" "$TMP/manifest.json" "$LEVEL" "kernel:$KVER level:$LEVEL ring:$TO promoted-from:$FROM"
