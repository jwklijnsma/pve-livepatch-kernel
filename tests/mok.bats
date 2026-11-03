#!/usr/bin/env bats
# `mok setup|status`: Secure Boot module signing key.

load test_helper

setup() {
  setup_fake_host pve
  export MOK_KEY="$BATS_TEST_TMPDIR/keys/mok.key"
  export MOK_CERT="$BATS_TEST_TMPDIR/keys/mok.pub"
  stub openssl '
log_call openssl "$@"
while [[ $# -gt 0 ]]; do
  case $1 in -keyout|-out) echo fake > "$2"; shift ;; esac; shift
done'
}

@test "setup creates a key, then requests enrollment" {
  FAKE_SB=enabled FAKE_MOK=no run lp mok setup
  assert_success
  [[ -f $MOK_KEY && -f $MOK_CERT ]]
  grep -q -- "-keyout $MOK_KEY -outform DER -out $MOK_CERT" "$STUB_LOG"
  assert_called "mokutil --import $MOK_CERT"
  assert_output_contains "MOK management"
}

@test "setup creates the private key with mode 600 in a 700 directory" {
  FAKE_MOK=no run lp mok setup
  assert_success
  [[ $(stat -c %a "$MOK_KEY") == 600 ]]
  [[ $(stat -c %a "$(dirname "$MOK_KEY")") == 700 ]]
}

@test "setup reuses an existing key and only enrolls" {
  mkdir -p "$(dirname "$MOK_KEY")"; echo k > "$MOK_KEY"; echo c > "$MOK_CERT"
  FAKE_MOK=no run lp mok setup
  assert_success
  assert_output_contains "using existing key"
  refute_called_match openssl
  assert_called "mokutil --import $MOK_CERT"
  [[ $(cat "$MOK_KEY") == k ]]
}

@test "setup does nothing when the key is already enrolled" {
  mkdir -p "$(dirname "$MOK_KEY")"; echo k > "$MOK_KEY"; echo c > "$MOK_CERT"
  FAKE_MOK=enrolled run lp mok setup
  assert_success
  assert_output_contains "already enrolled"
  refute_called_match "mokutil --import"
}

@test "setup does not re-import while enrollment is pending" {
  mkdir -p "$(dirname "$MOK_KEY")"; echo k > "$MOK_KEY"; echo c > "$MOK_CERT"
  FAKE_MOK=pending run lp mok setup
  assert_success
  assert_output_contains "already pending"
  refute_called_match "mokutil --import"
}

@test "setup refuses to overwrite when only half a key pair exists" {
  mkdir -p "$(dirname "$MOK_KEY")"; echo k > "$MOK_KEY"
  run lp mok setup
  assert_failure
  assert_output_contains "refusing to overwrite"
  [[ $(cat "$MOK_KEY") == k ]]
}

@test "status reports each enrollment state" {
  run lp mok status
  assert_output_contains "no key yet"
  mkdir -p "$(dirname "$MOK_KEY")"; echo k > "$MOK_KEY"; echo c > "$MOK_CERT"
  FAKE_MOK=no      run lp mok status; assert_output_contains "not enrolled"
  FAKE_MOK=pending run lp mok status; assert_output_contains "enrollment pending"
  FAKE_MOK=enrolled FAKE_SB=enabled run lp mok status
  assert_output_contains "key is enrolled"
  assert_output_contains "Secure Boot enabled"
}

@test "unknown mok action fails" {
  run lp mok frob
  assert_failure
  assert_output_contains "usage:"
}
