#!/usr/bin/env bats
# `clean`: free disk space, keep built modules.

load test_helper

setup() {
  setup_fake_host pve
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$PVE_LIVEPATCH_DIR"/{src/$KREL,pve-kernel,ubuntu-src,out/$KREL,patches,kpatch} "$HOME/.kpatch"
  head -c 100000 /dev/zero > "$PVE_LIVEPATCH_DIR/src/$KREL/vmlinux"
  touch "$PVE_LIVEPATCH_DIR/out/$KREL/livepatch-fix1.ko" "$PVE_LIVEPATCH_DIR/patches/fix1.patch"
}

@test "clean removes sources and build trees, keeps modules, patches and kpatch" {
  run lp -y clean
  assert_success
  assert_output_contains "freed"
  [[ ! -e $PVE_LIVEPATCH_DIR/src && ! -e $PVE_LIVEPATCH_DIR/pve-kernel && ! -e $PVE_LIVEPATCH_DIR/ubuntu-src && ! -e $HOME/.kpatch ]]
  [[ -f $PVE_LIVEPATCH_DIR/out/$KREL/livepatch-fix1.ko ]]
  [[ -f $PVE_LIVEPATCH_DIR/patches/fix1.patch ]]
  [[ -d $PVE_LIVEPATCH_DIR/kpatch ]]
}

@test "clean asks first and keeps everything on 'n'" {
  run bash -c 'source "$1"; need_root() { :; }; main clean <<< n' _ "$SCRIPT"
  assert_failure
  assert_output_contains "aborted"
  [[ -f $PVE_LIVEPATCH_DIR/src/$KREL/vmlinux ]]
}

@test "clean with nothing to delete" {
  rm -rf "$PVE_LIVEPATCH_DIR"/{src,pve-kernel,ubuntu-src} "$HOME/.kpatch"
  run lp -y clean
  assert_success
  assert_output_contains "nothing to clean"
}
