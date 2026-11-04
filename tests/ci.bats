#!/usr/bin/env bats
# ci/discover-kernels.sh: which Proxmox kernels need an automatic live patch.

load test_helper

setup() {
  T="$BATS_TEST_TMPDIR"
  export STUB_LOG="$T/stub.log"; : > "$STUB_LOG"
  export STUB_BIN="$T/bin"; mkdir -p "$STUB_BIN"; export PATH="$STUB_BIN:$PATH"
  # fake Proxmox repository (curl reads file://)
  local d="$T/repo/dists/trixie/pve-no-subscription/binary-amd64"; mkdir -p "$d"
  cat <<'P' | gzip > "$d/Packages.gz"
Package: proxmox-kernel-6.17.2-1-pve-signed
Version: 6.17.2-1

Package: proxmox-kernel-7.0.14-26-pve-signed
Version: 7.0.14-26

Package: proxmox-kernel-7.0.14-26-pve-signed-template
Version: 7.0.14-26

Package: proxmox-kernel-7.0.9-3-pve-signed
Version: 7.0.9-3

Package: proxmox-kernel-7.0
Version: 7.0.14-26

Package: proxmox-headers-7.0.15-1-pve
Version: 7.0.15-1
P
  export PVE_REPO_BASE="file://$T/repo"
  # patch set
  export PATCH_DIR=pdir; export DISCOVER_ROOT="$T/root"
  mkdir -p "$T/root/ci" "$T/root/pdir"
  cp "$REPO_ROOT/ci/discover-kernels.sh" "$T/root/ci/"
  echo "fix one" > "$T/root/pdir/0001-a.patch"
  echo "fix two" > "$T/root/pdir/0002-b.patch"
  # gh: releases in $T/releases/<tag>/PATCHSET
  stub gh '
log_call gh "$@"
[[ $1 == release && $2 == download ]] || exit 1
f="$FAKE_RELEASES/$3/PATCHSET"; [[ -f $f ]] || exit 1; cat "$f"'
  export FAKE_RELEASES="$T/releases"; mkdir -p "$FAKE_RELEASES"
}

signing_pem() {   # signing_pem <cn> : key + certificate, like the GitHub secret
  openssl req -new -x509 -nodes -days 30 -newkey rsa:2048 -subj "/CN=$1/" \
    -keyout "$T/k.pem" -out "$T/c.pem" >/dev/null 2>&1
  cat "$T/k.pem" "$T/c.pem"
}

discover() { "$DISCOVER_ROOT/ci/discover-kernels.sh"; }
patchset_id() { run discover; echo "$output" | grep -o 'auto_[0-9a-f]*' | head -1; }

@test "picks the newest KEEP kernels and builds them" {
  KEEP=2 run discover
  assert_success
  [[ ${lines[-1]} =~ ^\[\{\"kernel\":\"7.0.9-3-pve\",\"name\":\"auto_[0-9a-f]{12}\"\},\{\"kernel\":\"7.0.14-26-pve\",\"name\":\"auto_[0-9a-f]{12}\"\}\]$ ]]
  refute_output_contains "6.17.2-1-pve\",\"name"
}

@test "kernels whose release has the same patch set are skipped" {
  local id; id=$(KEEP=1 patchset_id)
  mkdir -p "$FAKE_RELEASES/lp-auto-7.0.14-26-pve"
  echo "patchset $id" > "$FAKE_RELEASES/lp-auto-7.0.14-26-pve/PATCHSET"
  KEEP=1 run discover
  assert_success
  [[ ${lines[-1]} == "[]" ]]
  assert_output_contains "7.0.14-26-pve: up to date"
}

@test "FORCE rebuilds an up-to-date kernel" {
  local id; id=$(KEEP=1 patchset_id)
  mkdir -p "$FAKE_RELEASES/lp-auto-7.0.14-26-pve"
  echo "patchset $id" > "$FAKE_RELEASES/lp-auto-7.0.14-26-pve/PATCHSET"
  KEEP=1 FORCE=true run discover
  [[ ${lines[-1]} == *'"kernel":"7.0.14-26-pve"'* ]]
}

@test "changing a patch gives a new patch set id (rebuild)" {
  local a b
  a=$(KEEP=1 patchset_id)
  echo "fix two, v2" > "$DISCOVER_ROOT/pdir/0002-b.patch"
  b=$(KEEP=1 patchset_id)
  [[ -n $a && -n $b && $a != "$b" ]]
}

@test "KERNELS skips the repository and ignores invalid names" {
  PVE_REPO_BASE=file:///nonexistent KERNELS="7.0.1-1-pve bogus" run discover
  assert_success
  [[ ${lines[-1]} == '[{"kernel":"7.0.1-1-pve","name":"auto_'*'"}]' ]]
  assert_output_contains "skipping invalid kernel 'bogus'"
}

@test "no patches: empty matrix" {
  rm "$DISCOVER_ROOT"/pdir/*.patch
  run discover
  assert_success
  [[ ${lines[-1]} == "[]" ]]
}

@test "the shipped patches/auto set is valid (demo included)" {
  ls "$REPO_ROOT"/patches/auto/*.patch
  grep -q '^+++ b/fs/proc/cmdline.c' "$REPO_ROOT"/patches/auto/0001-demo-proc-cmdline.patch
}

@test "without MODULE_SIGNING_PEM it builds unsigned" {
  KEEP=1 run discover
  assert_success
  assert_output_contains "modules will be unsigned"
  [[ ${lines[-1]} == *'"kernel":"7.0.14-26-pve"'* ]]
}

@test "adding a signing key later rebuilds (new patch set id)" {
  local a b
  a=$(KEEP=1 patchset_id)
  b=$(MODULE_SIGNING_PEM=$(signing_pem one) KEEP=1 patchset_id)
  [[ -n $a && -n $b && $a != "$b" ]]
}

@test "a key without its certificate is rejected" {
  signing_pem a >/dev/null
  MODULE_SIGNING_PEM=$(cat "$T/k.pem") run discover
  assert_failure
  assert_output_contains "has no certificate"
}

@test "a new signing key gives a new patch set id (everything is re-signed)" {
  local a b
  a=$(MODULE_SIGNING_PEM=$(signing_pem one) KEEP=1 patchset_id)
  b=$(MODULE_SIGNING_PEM=$(signing_pem two) KEEP=1 patchset_id)
  [[ -n $a && -n $b && $a != "$b" ]]
}

@test "signing/new-signing-key.sh makes a key + certificate the CI accepts" {
  run "$REPO_ROOT/signing/new-signing-key.sh"
  assert_success
  local pem=$output
  printf '%s\n' "$pem" | openssl pkey -noout
  printf '%s\n' "$pem" | openssl x509 -noout
  [[ $(printf '%s\n' "$pem" | openssl pkey -pubout) == "$(printf '%s\n' "$pem" | openssl x509 -noout -pubkey)" ]]
  MODULE_SIGNING_PEM=$pem run discover
  assert_success
}
