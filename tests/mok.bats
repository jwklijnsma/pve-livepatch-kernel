#!/usr/bin/env bats
# `mok setup|status`: enroll the certificate GitHub signs modules with.

load test_helper

setup() {
  setup_fake_host pve
  export FAKE_WEB="$BATS_TEST_TMPDIR/web"
  CERTDIR="$FAKE_WEB/github.com/jwklijnsma/pve-livepatch-kernel/releases/download/signing-cert"
  mkdir -p "$CERTDIR"; echo "DER CERT" > "$CERTDIR/module-signing.der"
  stub curl '
out=""; url=""
while [[ $# -gt 0 ]]; do case $1 in -o) out=$2; shift ;; -*) ;; *) url=$1 ;; esac; shift; done
log_call curl "$url"
f="$FAKE_WEB/${url#*://}"
[[ -f $f ]] || { echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; }
cp "$f" "$out"'
  CERT="$PVE_LIVEPATCH_DIR/module-signing.der"
}

@test "setup downloads GitHub's certificate and requests enrollment" {
  FAKE_SB=enabled FAKE_MOK=no run lp mok setup
  assert_success
  assert_called "curl https://github.com/jwklijnsma/pve-livepatch-kernel/releases/download/signing-cert/module-signing.der"
  [[ $(cat "$CERT") == "DER CERT" ]]
  assert_called "mokutil --import $CERT"
  assert_output_contains "MOK management"
}

@test "setup never creates a private key on the node" {
  stub openssl 'log_call openssl "$@"'
  FAKE_MOK=no run lp mok setup
  assert_success
  refute_called_match openssl
  [[ -z $(find "$PVE_LIVEPATCH_DIR" -name '*.key' -o -name '*.priv') ]]
}

@test "setup without a published certificate explains the GitHub secret" {
  rm "$CERTDIR/module-signing.der"
  run lp mok setup
  assert_failure
  assert_output_contains "MODULE_SIGNING_PEM"
  [[ ! -e $CERT && ! -e $CERT.part ]]
}

@test "setup does nothing when the certificate is already enrolled" {
  FAKE_MOK=enrolled run lp mok setup
  assert_success
  assert_output_contains "already enrolled"
  refute_called_match "mokutil --import"
}

@test "setup does not re-import while enrollment is pending" {
  FAKE_MOK=pending run lp mok setup
  assert_success
  assert_output_contains "already pending"
  refute_called_match "mokutil --import"
}

@test "status reports each enrollment state" {
  run lp mok status
  assert_output_contains "not downloaded yet"
  echo c > "$CERT"
  FAKE_MOK=no      run lp mok status; assert_output_contains "not enrolled"
  FAKE_MOK=pending run lp mok status; assert_output_contains "enrollment pending"
  FAKE_MOK=enrolled FAKE_SB=enabled run lp mok status
  assert_output_contains "certificate is enrolled"
  assert_output_contains "Secure Boot enabled"
}

@test "unknown mok action fails" {
  run lp mok frob
  assert_failure
  assert_output_contains "usage:"
}
