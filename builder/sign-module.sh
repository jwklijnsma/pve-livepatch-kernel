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
# Everything in out/ was written by the build container and is treated as
# untrusted: only regular files are read (no symlinks to the key), the
# provenance values are checked for their format, and Gate A runs again
# here against the shipped artifacts, which the build container could only
# read.
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
[ -e "$KO" ] || die "no module $KO (run build.sh first)"
regular "$KO" "$OUT/resolved.json" "$OUT/functions.txt" "$OUT/catalog-commit" "$SHIPPED/build-id" \
  "$SHIPPED/System.map" "$SHIPPED/Module.symvers"
CAT_COMMIT=$(head -c 100 "$OUT/catalog-commit")
[[ "$CAT_COMMIT" =~ ^([0-9a-f]{40}(-dirty)?|unknown)$ ]] || die "unexpected catalog commit in $OUT/catalog-commit"
BUILD_ID=$(head -c 100 "$SHIPPED/build-id")
[[ "$BUILD_ID" =~ ^[0-9a-f]{40}$ ]] || die "unexpected build-id in $SHIPPED/build-id"
[[ "$BUILDER_IMAGE" =~ ^[A-Za-z0-9:@/._+-]{1,256}$ ]] || die "unexpected BUILDER_IMAGE"
rm -f "$OUT/manifest.json" "$OUT/qemu.ok"

log "gate A (again, outside the build container)"
hvpatch-tool gate-a --module "$KO" --kernel "$KVER" --expected-name "$NAME" \
  --system-map "$SHIPPED/System.map" --symvers "$SHIPPED/Module.symvers" \
  --modules-dir "$SHIPPED/modules" \
  --functions "$OUT/functions.txt" --resolved "$OUT/resolved.json" >/dev/null
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

log "manifest (unsigned, ring canary)"
hvpatch-tool manifest --resolved "$OUT/resolved.json" --module "$KO" \
  --level "$LEVEL" --ring canary \
  --build-id "$BUILD_ID" --functions "$OUT/functions.txt" \
  --builder-image "$BUILDER_IMAGE" \
  --catalog-commit "$CAT_COMMIT" \
  --out "$OUT/manifest.json"
log "done: $KO and $OUT/manifest.json (next: qemu-test.sh $KVER $WORK)"
