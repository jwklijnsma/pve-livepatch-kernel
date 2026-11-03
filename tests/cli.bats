#!/usr/bin/env bats
# Command-line interface: help, version, argument errors, platform detection.

load test_helper

setup() { setup_fake_host pve; }

@test "--help prints usage and exits 0" {
  run lp --help
  assert_success
  assert_output_contains "Usage:"
  assert_output_contains "canonical enable|status|disable"
}

@test "no command prints usage" {
  run lp
  assert_success
  assert_output_contains "Usage:"
}

@test "--version prints SCRIPT_VERSION" {
  local want; want=$(sed -n 's/^readonly SCRIPT_VERSION="\(.*\)"/\1/p' "$SCRIPT")
  run lp --version
  assert_success
  [[ $output == "$want" ]]
}

@test "unknown command fails" {
  run lp frobnicate
  assert_failure
  assert_output_contains "unknown command: frobnicate"
}

@test "script runs directly (not only when sourced)" {
  run "$SCRIPT" --version
  assert_success
}

@test "apply refuses to run as non-root" {
  [[ $EUID -ne 0 ]] || skip "running as root"
  run "$SCRIPT" apply /nonexistent.ko
  assert_failure
  assert_output_contains "run as root"
}

# --- platform detection --------------------------------------------------------

@test "detects Proxmox VE from a -pve kernel" {
  rm -f "$STUB_BIN/pveversion"
  run in_script 'detect_platform; echo "$PLATFORM $MOK_KEY"'
  assert_success
  [[ $output == "pve /var/lib/dkms/mok.key" ]]
}

@test "detects Ubuntu from os-release and uses shim MOK key" {
  setup_fake_host ubuntu
  run in_script 'detect_platform; echo "$PLATFORM $MOK_KEY"'
  assert_success
  [[ $output == "ubuntu /var/lib/shim-signed/mok/MOK.priv" ]]
}

@test "detects Ubuntu when ID is quoted" {
  setup_fake_host ubuntu
  printf 'ID="ubuntu"\n' > "$OS_RELEASE"
  run in_script 'detect_platform; echo "$PLATFORM"'
  [[ $output == "ubuntu" ]]
}

@test "unsupported distro fails with a hint" {
  setup_fake_host ubuntu
  export KREL="6.1.0-25-amd64"
  printf 'ID=debian\n' > "$OS_RELEASE"
  run in_script 'detect_platform'
  assert_failure
  assert_output_contains "unsupported platform"
}

@test "PLATFORM override wins over detection" {
  run in_script 'PLATFORM=ubuntu; detect_platform; echo "$PLATFORM"'
  [[ $output == "ubuntu" ]]
}

@test "invalid PLATFORM override fails" {
  run lp -y status
  assert_success
  PLATFORM=windows run lp status
  assert_failure
  assert_output_contains "PLATFORM must be pve or ubuntu"
}

@test "MOK_KEY env overrides the platform default" {
  MOK_KEY=/custom/key run in_script 'detect_platform; echo "$MOK_KEY"'
  [[ $output == "/custom/key" ]]
}

@test "platform_name shows os-release PRETTY_NAME on Ubuntu" {
  setup_fake_host ubuntu
  run in_script 'detect_platform; platform_name'
  [[ $output == "Ubuntu 24.04.1 LTS" ]]
}
