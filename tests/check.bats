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

@test "fails on gcc mismatch with the kernel build compiler" {
  FAKE_GCC=14.2.0 run lp check
  assert_failure
  assert_output_contains "gcc mismatch: kernel built with '12.2.0', local gcc is '14.2.0'"
}

@test "fails when Secure Boot is on and no MOK key exists" {
  FAKE_SB=enabled MOK_KEY="$BATS_TEST_TMPDIR/nokey" MOK_CERT="$BATS_TEST_TMPDIR/nocert" run lp check
  assert_failure
  assert_output_contains "Secure Boot enabled"
  assert_output_contains "no MOK key"
}

@test "passes with Secure Boot on when the MOK key is present" {
  touch "$BATS_TEST_TMPDIR/mok.key" "$BATS_TEST_TMPDIR/mok.pub"
  FAKE_SB=enabled MOK_KEY="$BATS_TEST_TMPDIR/mok.key" MOK_CERT="$BATS_TEST_TMPDIR/mok.pub" run lp check
  assert_success
  assert_output_contains "MOK key found"
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
