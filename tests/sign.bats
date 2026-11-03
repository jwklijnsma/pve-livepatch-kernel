#!/usr/bin/env bats
# Built-in module signer (openssl only, same format as the kernel's sign-file).

load test_helper

setup() {
  setup_fake_host pve
  make_test_key
  KO="$BATS_TEST_TMPDIR/livepatch-fix1.ko"
  head -c 40000 /dev/urandom > "$KO"
  cp "$KO" "$BATS_TEST_TMPDIR/orig.ko"
}

# split a signed module into: body, signature, trailer fields
parse_signed() {
  local ko=$1 size siglen
  size=$(stat -c %s "$ko")
  siglen=$(tail -c 32 "$ko" | head -c 4 | od -An -tu1 | awk '{print $1*16777216+$2*65536+$3*256+$4}')
  head -c $(( size - 40 - siglen )) "$ko" > "$BATS_TEST_TMPDIR/body"
  tail -c $(( 40 + siglen )) "$ko" | head -c "$siglen" > "$BATS_TEST_TMPDIR/sig"
  tail -c 40 "$ko" | head -c 8 | od -An -tu1 | tr -s ' ' > "$BATS_TEST_TMPDIR/hdr"
}

@test "appends a valid PKCS#7 signature in kernel module format" {
  run in_script 'detect_platform; sign_module "'"$KO"'"'
  assert_success
  parse_signed "$KO"
  cmp -s "$BATS_TEST_TMPDIR/body" "$BATS_TEST_TMPDIR/orig.ko"          # module unchanged
  [[ $(cat "$BATS_TEST_TMPDIR/hdr") == " 0 0 2 0 0 0 0 0" ]]           # id_type = PKCS7
  [[ $(tail -c 28 "$KO") == "~Module signature appended~"* ]]
  openssl x509 -inform DER -in "$MOK_CERT" -out "$BATS_TEST_TMPDIR/cert.pem"
  openssl cms -verify -binary -inform DER -in "$BATS_TEST_TMPDIR/sig" \
    -content "$BATS_TEST_TMPDIR/body" -certfile "$BATS_TEST_TMPDIR/cert.pem" -noverify -out /dev/null
}

@test "signature uses sha512 and no signed attributes (like sign-file)" {
  run in_script 'detect_platform; sign_module "'"$KO"'"'
  parse_signed "$KO"
  run openssl cms -cmsout -print -inform DER -in "$BATS_TEST_TMPDIR/sig"
  assert_output_contains "sha512"
  assert_output_contains "signedAttrs:"
  [[ $output == *"signedAttrs:"*"<ABSENT>"* ]]
  assert_output_contains "issuerAndSerialNumber"
}

@test "a PEM certificate works too" {
  openssl x509 -inform DER -in "$MOK_CERT" -out "$BATS_TEST_TMPDIR/cert.pem"
  MOK_CERT="$BATS_TEST_TMPDIR/cert.pem" run in_script 'detect_platform; sign_module "'"$KO"'"'
  assert_success
  [[ $(tail -c 28 "$KO") == "~Module signature appended~"* ]]
}

@test "signing an already signed module is a no-op" {
  in_script 'detect_platform; sign_module "'"$KO"'"' >/dev/null
  cp "$KO" "$BATS_TEST_TMPDIR/once.ko"
  run in_script 'detect_platform; sign_module "'"$KO"'"'
  assert_success
  assert_output_contains "already signed"
  cmp -s "$KO" "$BATS_TEST_TMPDIR/once.ko"
}

@test "unreadable certificate fails without touching the module" {
  echo garbage > "$MOK_CERT"
  run in_script 'detect_platform; sign_module "'"$KO"'"'
  assert_failure
  assert_output_contains "cannot read certificate"
  cmp -s "$KO" "$BATS_TEST_TMPDIR/orig.ko"
}

@test "missing key points at 'mok setup'" {
  MOK_KEY=/nonexistent run in_script 'detect_platform; sign_module "'"$KO"'"'
  assert_failure
  assert_output_contains "mok setup"
}
