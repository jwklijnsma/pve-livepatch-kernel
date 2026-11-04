#!/usr/bin/env bats
# `check`: readiness checks for live patching.

load test_helper

setup() { setup_fake_host pve; }

@test "healthy PVE host is ready" {
  run lp check
  assert_success
  assert_output_contains "CONFIG_LIVEPATCH=y"
  assert_output_contains "gcc 12.2.0 matches"
  assert_output_contains "Secure Boot off"
  assert_output_contains "running a Proxmox kernel"
  assert_output_contains "Ready."
}

@test "healthy Ubuntu host is ready" {
  setup_fake_host ubuntu
  run lp check
  assert_success
  assert_output_contains "Ubuntu 24.04.1 LTS"
  assert_output_contains "running an Ubuntu kernel flavour"
  assert_output_contains "Ready."
}

@test "fails when CONFIG_LIVEPATCH is not set" {
  sed -i '/CONFIG_LIVEPATCH/d' "$KCONFIG"
  run lp check
  assert_failure
  assert_output_contains "CONFIG_LIVEPATCH not enabled"
  assert_output_contains "not ready"
}

@test "accepts DYNAMIC_FTRACE_WITH_ARGS instead of WITH_REGS" {
  sed -i 's/CONFIG_DYNAMIC_FTRACE_WITH_REGS=y/CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y/' "$KCONFIG"
  run lp check
  assert_success
  assert_output_contains "dynamic ftrace (WITH_REGS/ARGS) available"
}

@test "fails without any dynamic ftrace with regs/args" {
  sed -i '/CONFIG_DYNAMIC_FTRACE_WITH_REGS/d' "$KCONFIG"
  run lp check
  assert_failure
  assert_output_contains "dynamic ftrace with regs/args missing"
}

@test "missing reliable stacktrace only warns" {
  sed -i '/CONFIG_HAVE_RELIABLE_STACKTRACE/d' "$KCONFIG"
  run lp check
  assert_success
  assert_output_contains "no reliable stacktrace"
}

@test "fails when livepatch sysfs is missing" {
  rmdir "$SYSFS_LP"
  run lp check
  assert_failure
  assert_output_contains "missing"
}

@test "gcc mismatch only rules out local builds (fetch/auto still work)" {
  FAKE_GCC=14.2.0 run lp check
  assert_success
  assert_output_contains "gcc mismatch: kernel built with '12.2.0', local gcc is '14.2.0'"
  assert_output_contains "use fetch / auto"
}

@test "fails when the kernel has no CONFIG_KLP_BUILD" {
  sed -i '/CONFIG_KLP_BUILD/d' "$KCONFIG"
  run lp check
  assert_failure
  assert_output_contains "CONFIG_KLP_BUILD not enabled"
  assert_output_contains ">= 6.19"
}

@test "fails when Secure Boot is on and no MOK key exists" {
  FAKE_SB=enabled MOK_KEY="$BATS_TEST_TMPDIR/nokey" MOK_CERT="$BATS_TEST_TMPDIR/nocert" run lp check
  assert_failure
  assert_output_contains "Secure Boot enabled"
  assert_output_contains "no MOK key"
}

@test "passes with Secure Boot on when the MOK key is enrolled" {
  touch "$BATS_TEST_TMPDIR/mok.key" "$BATS_TEST_TMPDIR/mok.pub"
  FAKE_SB=enabled MOK_KEY="$BATS_TEST_TMPDIR/mok.key" MOK_CERT="$BATS_TEST_TMPDIR/mok.pub" run lp check
  assert_success
  assert_output_contains "is enrolled"
}

@test "fails when the MOK key exists but is not enrolled" {
  touch "$BATS_TEST_TMPDIR/mok.key" "$BATS_TEST_TMPDIR/mok.pub"
  FAKE_SB=enabled FAKE_MOK=no MOK_KEY="$BATS_TEST_TMPDIR/mok.key" MOK_CERT="$BATS_TEST_TMPDIR/mok.pub" run lp check
  assert_failure
  assert_output_contains "exists but is not enrolled"
  assert_output_contains "mok setup"
}

@test "fails with a reboot hint while enrollment is pending" {
  touch "$BATS_TEST_TMPDIR/mok.key" "$BATS_TEST_TMPDIR/mok.pub"
  FAKE_SB=enabled FAKE_MOK=pending MOK_KEY="$BATS_TEST_TMPDIR/mok.key" MOK_CERT="$BATS_TEST_TMPDIR/mok.pub" run lp check
  assert_failure
  assert_output_contains "reboot once and confirm it in MOK Manager"
}

@test "missing MOK key points at 'mok setup'" {
  FAKE_SB=enabled MOK_KEY="$BATS_TEST_TMPDIR/nokey" MOK_CERT="$BATS_TEST_TMPDIR/nocert" run lp check
  assert_failure
  assert_output_contains "run: "
  assert_output_contains "mok setup"
}

@test "40G is enough for a klp-build" {
  stub df 'echo "Avail"; echo " 40G"'
  run lp check
  assert_success
  assert_output_contains "40G free"
  assert_output_contains "a build needs ~30G"
  refute_output_contains "only 40G"
}

@test "low disk space suggests PVE_LIVEPATCH_DIR and clean" {
  stub df 'echo "Avail"; echo " 5G"'
  run lp check
  assert_success
  assert_output_contains "only 5G free"
  assert_output_contains "set PVE_LIVEPATCH_DIR"
  assert_output_contains "clean"
}

@test "12G is too little for a build: suggests fetch / auto" {
  stub df 'echo "Avail"; echo " 12G"'
  run lp check
  assert_success
  assert_output_contains "only 12G free"
  assert_output_contains "use 'fetch' / 'auto'"
}

@test "disk check works when PVE_LIVEPATCH_DIR does not exist yet" {
  export PVE_LIVEPATCH_DIR="$BATS_TEST_TMPDIR/not/yet/there"
  run lp check
  assert_success
  refute_output_contains "df:"
}

@test "dies when the kernel config file is missing" {
  rm "$KCONFIG"
  run lp check
  assert_failure
  assert_output_contains "kernel config"
}

@test "warns about Canonical Livepatch on Ubuntu" {
  setup_fake_host ubuntu
  stub canonical-livepatch 'exit 0'
  run lp check
  assert_success
  assert_output_contains "Canonical Livepatch is installed"
}
