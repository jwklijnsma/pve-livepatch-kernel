#!/usr/bin/env bash
# Sign the module built by build.sh and write its manifest (unsigned; the
# manifest is signed by publish.sh on the signing host).
#
# usage: sign-module.sh <kver> <level> <workdir>
#
# run.sh runs this in its own container: only <workdir>/out writable, the
# shipped artifacts read-only, the key read-only, no kernel tree, no
# catalog, no network. The signing tool is Debian's sign-file
# (kernel-sign-file in the image), not the one built from the kernel tree.
#
# Environment:
#   MODULE_KEY, MODULE_CERT   module signing key and certificate
#   BUILDER_IMAGE             builder image id, recorded in the manifest
source "$(dirname "$0")/lib.sh"
KVER=${1:?kver}; LEVEL=${2:?level}; WORK=${3:?workdir}
require hvpatch-tool kernel-sign-file openssl
: "${MODULE_KEY:?MODULE_KEY not set}" "${MODULE_CERT:?MODULE_CERT not set}" "${BUILDER_IMAGE:?BUILDER_IMAGE not set}"
OUT="$WORK/out"; SHIPPED="$WORK/shipped"
NAME=$(hvpatch-tool module-name --kernel "$KVER" --level "$LEVEL")
KO="$OUT/$NAME.ko"
[ -f "$KO" ] || die "no module $KO (run build.sh first)"
if tail -c 28 "$KO" | grep -q 'Module signature appended'; then
  die "$KO is already signed; run build.sh again for a fresh module"
fi

log "signing $NAME.ko"
kernel-sign-file sha512 "$MODULE_KEY" "$MODULE_CERT" "$KO"

# Verify the appended signature against the certificate with openssl, so a
# wrong key is caught here and not only on Secure Boot nodes.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
hvpatch-tool split-module-sig --module "$KO" --content "$TMP/content" --pkcs7 "$TMP/sig.p7"
openssl x509 -inform DER -in "$MODULE_CERT" -out "$TMP/cert.pem" 2>/dev/null || cp "$MODULE_CERT" "$TMP/cert.pem"
openssl cms -verify -binary -inform DER -in "$TMP/sig.p7" -content "$TMP/content" \
  -certfile "$TMP/cert.pem" -nointern -noverify -out /dev/null 2>"$TMP/err" \
  || die "the module signature does not verify against $MODULE_CERT: $(cat "$TMP/err")"
log "signature verified against $(openssl x509 -in "$TMP/cert.pem" -noout -subject)"
rm -f "$OUT/qemu.ok"

log "manifest (unsigned, ring canary)"
hvpatch-tool manifest --resolved "$OUT/resolved.json" --module "$KO" \
  --level "$LEVEL" --ring canary \
  --build-id "$(cat "$SHIPPED/build-id")" --functions "$OUT/functions.txt" \
  --builder-image "$BUILDER_IMAGE" \
  --catalog-commit "$(cat "$OUT/catalog-commit")" \
  --out "$OUT/manifest.json"
log "done: $KO and $OUT/manifest.json (next: qemu-test.sh $KVER $WORK)"
