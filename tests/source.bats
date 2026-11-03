#!/usr/bin/env bats
# Kernel source helpers: pve-kernel commit lookup and tree finalisation.

load test_helper

setup() { setup_fake_host pve; }

make_pve_repo() {
  REPO="$BATS_TEST_TMPDIR/pve-kernel"
  git init -q "$REPO"
  local msg
  for msg in "init" "bump version to 6.8.12-40" "update ABI file" "bump version to 6.8.12-4" "bump version to 6.8.12-4~bpo12+1"; do
    git -C "$REPO" -c user.name=t -c user.email=t@t commit -q --allow-empty -m "$msg"
  done
}

@test "find_pve_commit picks the exact 'bump version' commit" {
  make_pve_repo
  local want; want=$(git -C "$REPO" log --format='%H %s' | awk '$0 ~ / bump version to 6\.8\.12-4$/ {print $1}')
  run in_script "find_pve_commit '$REPO' 6.8.12-4"
  assert_success
  [[ $output == "$want" ]]
}

@test "find_pve_commit does not match a longer version (6.8.12-40)" {
  make_pve_repo
  local want; want=$(git -C "$REPO" log --format='%H %s' | awk '/bump version to 6\.8\.12-40$/ {print $1}')
  run in_script "find_pve_commit '$REPO' 6.8.12-40"
  [[ $output == "$want" ]]
  run in_script "find_pve_commit '$REPO' 6.8.12-4"
  [[ $output != "$want" ]]
}

@test "find_pve_commit handles backport versions with ~ and +" {
  make_pve_repo
  run in_script "find_pve_commit '$REPO' '6.8.12-4~bpo12+1'"
  assert_success
  [[ -n $output ]]
}

@test "find_pve_commit returns nothing for an unknown version" {
  make_pve_repo
  run in_script "find_pve_commit '$REPO' 6.99.0-1"
  assert_success
  [[ -z $output ]]
}

@test "finalise_tree sets EXTRAVERSION and copies the running config" {
  local src="$BATS_TEST_TMPDIR/src"
  mkdir -p "$src"
  printf 'VERSION = 6\nPATCHLEVEL = 8\nSUBLEVEL = 12\nEXTRAVERSION =\n' > "$src/Makefile"
  stub make '[[ " $* " == *" kernelrelease "* ]] && echo "${FAKE_RELEASE:-$KREL}"; exit 0'
  run in_script "finalise_tree '$src'"
  assert_success
  grep -qx 'EXTRAVERSION = -4-pve' "$src/Makefile"
  cmp -s "$KCONFIG" "$src/.config"
  [[ -f $src/.scmversion ]]
}

@test "finalise_tree fails when kernelrelease does not match uname -r" {
  local src="$BATS_TEST_TMPDIR/src"
  mkdir -p "$src"
  printf 'EXTRAVERSION =\n' > "$src/Makefile"
  stub make '[[ " $* " == *" kernelrelease "* ]] && echo "6.8.12-4-pve+"; exit 0'
  run in_script "finalise_tree '$src'"
  assert_failure
  assert_output_contains "!= running '6.8.12-4-pve'"
}

@test "canonical commands are refused on Proxmox" {
  run lp canonical status
  assert_failure
  assert_output_contains "only works on Ubuntu kernels"
}

@test "canonical status calls canonical-livepatch on Ubuntu" {
  setup_fake_host ubuntu
  stub canonical-livepatch 'log_call canonical-livepatch "$@"; echo "fully-patched: true"'
  run lp canonical status
  assert_success
  assert_called "canonical-livepatch status --verbose"
  assert_output_contains "fully-patched: true"
}

@test "canonical enable needs a Pro token on an unattached machine" {
  setup_fake_host ubuntu
  stub pro 'log_call pro "$@"; [[ $1 == status ]] && echo "{\"attached\": false}"; exit 0'
  run lp -y canonical enable
  assert_failure
  assert_output_contains "set UBUNTU_PRO_TOKEN"
  refute_called_match "pro enable"
}

@test "canonical enable attaches and enables livepatch" {
  setup_fake_host ubuntu
  stub pro 'log_call pro "$@"; [[ $1 == status ]] && echo "{\"attached\": false}"; exit 0'
  UBUNTU_PRO_TOKEN=C1234 run lp -y canonical enable
  assert_success
  assert_called "pro attach C1234 --no-auto-enable"
  assert_called "pro enable livepatch --assume-yes"
}

@test "canonical rejects unknown actions" {
  setup_fake_host ubuntu
  run lp canonical frob
  assert_failure
  assert_output_contains "usage:"
}
