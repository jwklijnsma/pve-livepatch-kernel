#!/usr/bin/env bats
# `apply`, `status`, `remove`: loading and managing live patches.

load test_helper

setup() {
  setup_fake_host pve
  KO="$BATS_TEST_TMPDIR/livepatch-fix1.ko"
  touch "$KO"
}

@test "loads the module with -y" {
  run lp -y apply "$KO"
  assert_success
  assert_called "kpatch load $KO"
  refute_called_match "kpatch install"
}

@test "--persist installs the module and enables kpatch.service" {
  run lp -y apply "$KO" --persist
  assert_success
  assert_called "kpatch load $KO"
  assert_called "kpatch install $KO"
  assert_called "systemctl enable --now kpatch.service"
}

@test "asks for confirmation and aborts on 'n'" {
  run bash -c 'source "$1"; need_root() { :; }; main apply "$2" <<< n' _ "$SCRIPT" "$KO"
  assert_failure
  assert_output_contains "aborted"
  refute_called_match "kpatch load"
}

@test "proceeds on 'y' at the confirmation prompt" {
  run bash -c 'source "$1"; need_root() { :; }; main apply "$2" <<< y' _ "$SCRIPT" "$KO"
  assert_success
  assert_called "kpatch load $KO"
}

@test "refuses a module built for another kernel" {
  FAKE_VERMAGIC="6.8.12-2-pve" run lp -y apply "$KO"
  assert_failure
  assert_output_contains "does not match running kernel"
  refute_called_match "kpatch load"
}

@test "refuses a module that is not a livepatch" {
  FAKE_LIVEPATCH="" run lp -y apply "$KO"
  assert_failure
  assert_output_contains "is not a livepatch module"
}

@test "refuses an unsigned module when Secure Boot is on" {
  FAKE_SB=enabled FAKE_SIGNER="" run lp -y apply "$KO"
  assert_failure
  assert_output_contains "is not signed"
  assert_output_contains "mok setup"
  refute_called_match "kpatch load"
}

@test "loads a signed module when Secure Boot is on and the key is enrolled" {
  touch "$BATS_TEST_TMPDIR/k" "$BATS_TEST_TMPDIR/c"
  FAKE_SB=enabled MOK_KEY="$BATS_TEST_TMPDIR/k" MOK_CERT="$BATS_TEST_TMPDIR/c" run lp -y apply "$KO"
  assert_success
  refute_output_contains "not enrolled"
  assert_called "kpatch load $KO"
}

@test "warns when the signing key is not enrolled yet" {
  touch "$BATS_TEST_TMPDIR/k" "$BATS_TEST_TMPDIR/c"
  FAKE_SB=enabled FAKE_MOK=no MOK_KEY="$BATS_TEST_TMPDIR/k" MOK_CERT="$BATS_TEST_TMPDIR/c" run lp -y apply "$KO"
  assert_output_contains "MOK key is not enrolled"
}

@test "fails for a missing module file" {
  run lp -y apply "$BATS_TEST_TMPDIR/nope.ko"
  assert_failure
  assert_output_contains "usage:"
}

@test "warns that atomic replace will disable foreign live patches" {
  add_livepatch lkp_Ubuntu_6_8_0_45_generic_1
  run lp -y apply "$KO"
  assert_success
  assert_output_contains "lkp_Ubuntu_6_8_0_45_generic_1"
  assert_output_contains "will DISABLE them"
}

@test "no warning for a --non-replace module" {
  add_livepatch lkp_Ubuntu_6_8_0_45_generic_1
  FAKE_REPLACE=N run lp -y apply "$KO"
  assert_success
  refute_output_contains "will DISABLE"
}

@test "kpatch's own patches are not treated as foreign" {
  add_livepatch livepatch_old_fix
  run in_script 'foreign_patches'
  assert_success
  [[ -z $output ]]
}

@test "foreign_patches lists only non-kpatch patches" {
  add_livepatch livepatch_mine
  add_livepatch lkp_Ubuntu_x
  add_livepatch kgraft_other
  run in_script 'foreign_patches | sort'
  [[ $output == $'kgraft_other\nlkp_Ubuntu_x' ]]
}

@test "status lists loaded patches with state" {
  add_livepatch livepatch_fix1 1
  add_livepatch livepatch_fix2 0
  run lp status
  assert_success
  [[ $output =~ livepatch_fix1[[:space:]]+enabled=1[[:space:]]transition=0 ]]
  [[ $output =~ livepatch_fix2[[:space:]]+enabled=0 ]]
}

@test "status says when nothing is loaded" {
  run lp status
  assert_success
  assert_output_contains "(none loaded)"
}

@test "remove unloads and uninstalls" {
  run lp -y remove livepatch_fix1
  assert_success
  assert_called "kpatch unload livepatch_fix1"
  assert_called "kpatch uninstall livepatch_fix1"
}

@test "remove without a name fails" {
  run lp -y remove
  assert_failure
  assert_output_contains "usage:"
}
