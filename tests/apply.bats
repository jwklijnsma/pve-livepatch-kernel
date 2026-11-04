#!/usr/bin/env bats
# `apply`, `status`, `remove`: loading and managing live patches.

load test_helper

setup() {
  setup_fake_host pve
  KO="$BATS_TEST_TMPDIR/livepatch-fix1.ko"
  touch "$KO"
}

@test "loads the module with insmod and waits until it is enabled" {
  run lp -y apply "$KO"
  assert_success
  assert_called "insmod $KO"
  assert_output_contains "livepatch_fix1 enabled"
  [[ ! -e $PVE_LIVEPATCH_DIR/installed/$KREL/livepatch-fix1.ko ]]
  [[ ! -e $SYSTEMD_DIR/pve-livepatch.service ]]
}

@test "--persist installs the module and a boot service" {
  run lp -y apply "$KO" --persist
  assert_success
  assert_called "insmod $KO"
  [[ -f $PVE_LIVEPATCH_DIR/installed/$KREL/livepatch-fix1.ko ]]
  grep -qx 'ExecStart=/usr/sbin/pve-livepatch -y boot' "$SYSTEMD_DIR/pve-livepatch.service"
  assert_called "systemctl enable pve-livepatch.service"
  assert_output_contains "loaded again on every boot"
}

@test "a patch already loaded is not inserted twice" {
  add_livepatch livepatch_fix1
  run lp -y apply "$KO"
  assert_success
  assert_output_contains "already loaded"
  refute_called_match insmod
}

@test "insmod failure (e.g. key rejected) stops with a dmesg hint" {
  FAKE_INSMOD_FAIL=1 run lp -y apply "$KO"
  assert_failure
  assert_output_contains "Key was rejected"
  assert_output_contains "dmesg"
}

@test "warns when the transition does not finish in time" {
  FAKE_TRANSITION=1 LP_WAIT=0 run lp -y apply "$KO"
  assert_success
  assert_output_contains "still in transition"
}

@test "modules of replaced patches are unloaded" {
  mkdir -p "$SYS_MODULE/livepatch_old"            # loaded module, no longer in livepatch sysfs
  run lp -y apply "$KO"
  assert_success
  assert_called "rmmod livepatch_old"
  refute_called_match "rmmod livepatch_fix1"
}

@test "boot loads installed patches oldest first" {
  local d="$PVE_LIVEPATCH_DIR/installed/$KREL"; mkdir -p "$d"
  touch -d '2 hours ago' "$d/livepatch-a.ko"; touch "$d/livepatch-b.ko"
  run lp -y boot
  assert_success
  [[ $(grep '^insmod' "$STUB_LOG") == "insmod $d/livepatch-a.ko"$'\n'"insmod $d/livepatch-b.ko" ]]
  assert_output_contains "2 installed live patch(es)"
}

@test "boot keeps going when one module fails to load" {
  local d="$PVE_LIVEPATCH_DIR/installed/$KREL"; mkdir -p "$d"; touch "$d/livepatch-a.ko"
  FAKE_INSMOD_FAIL=1 run lp -y boot
  assert_success
  assert_output_contains "could not load livepatch-a.ko"
}

@test "boot with nothing installed" {
  run lp -y boot
  assert_success
  assert_output_contains "no live patches installed"
}

@test "asks for confirmation and aborts on 'n'" {
  run bash -c 'source "$1"; need_root() { :; }; main apply "$2" <<< n' _ "$SCRIPT" "$KO"
  assert_failure
  assert_output_contains "aborted"
  refute_called_match "insmod"
}

@test "proceeds on 'y' at the confirmation prompt" {
  run bash -c 'source "$1"; need_root() { :; }; main apply "$2" <<< y' _ "$SCRIPT" "$KO"
  assert_success
  assert_called "insmod $KO"
}

@test "refuses a module built for another kernel" {
  FAKE_VERMAGIC="6.8.12-2-pve" run lp -y apply "$KO"
  assert_failure
  assert_output_contains "does not match running kernel"
  refute_called_match "insmod"
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
  refute_called_match "insmod"
}

@test "loads a signed module when Secure Boot is on and the key is enrolled" {
  touch "$BATS_TEST_TMPDIR/k" "$BATS_TEST_TMPDIR/c"
  FAKE_SB=enabled MOK_KEY="$BATS_TEST_TMPDIR/k" MOK_CERT="$BATS_TEST_TMPDIR/c" run lp -y apply "$KO"
  assert_success
  refute_output_contains "not enrolled"
  assert_called "insmod $KO"
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
  assert_output_contains "DISABLES them"
}

@test "no warning for a --non-replace module" {
  add_livepatch lkp_Ubuntu_6_8_0_45_generic_1
  FAKE_REPLACE=N run lp -y apply "$KO"
  assert_success
  refute_output_contains "DISABLES"
}

@test "this tool's own patches are not treated as foreign" {
  add_livepatch livepatch_old_fix
  run in_script 'foreign_patches'
  assert_success
  [[ -z $output ]]
}

@test "foreign_patches lists only patches from elsewhere" {
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

@test "remove disables via sysfs, unloads and uninstalls" {
  add_livepatch livepatch_fix1; mkdir -p "$SYS_MODULE/livepatch_fix1"
  mkdir -p "$PVE_LIVEPATCH_DIR/installed/$KREL"; touch "$PVE_LIVEPATCH_DIR/installed/$KREL/livepatch-fix1.ko"
  run lp -y remove livepatch_fix1
  assert_success
  [[ $(cat "$SYSFS_LP/livepatch_fix1/enabled") == 0 ]]
  assert_called "rmmod livepatch_fix1"
  [[ ! -e $PVE_LIVEPATCH_DIR/installed/$KREL/livepatch-fix1.ko ]]
  assert_output_contains "no longer loaded at boot"
}

@test "remove accepts the name without the livepatch_ prefix" {
  add_livepatch livepatch_fix1
  run lp -y remove fix1
  assert_success
  assert_output_contains "livepatch_fix1 disabled"
}

@test "remove gives up when the patch stays in transition" {
  add_livepatch livepatch_fix1; echo 1 > "$SYSFS_LP/livepatch_fix1/transition"
  LP_WAIT=0 run lp -y remove livepatch_fix1
  assert_failure
  assert_output_contains "still in transition"
}

@test "remove without a name fails" {
  run lp -y remove
  assert_failure
  assert_output_contains "usage:"
}
