#!/usr/bin/env bats
# `auto`: fetch + load the automatic live patch GitHub Actions built for this kernel.

load test_helper

setup() {
  setup_fake_host pve
  export FAKE_WEB="$BATS_TEST_TMPDIR/web"
  REL="$FAKE_WEB/github.com/jwklijnsma/pve-livepatch-kernel/releases/download/lp-auto-$KREL"
  ID=0123456789ab
  # curl stub: serve files from $FAKE_WEB/<host>/<path>
  stub curl '
out=""; url=""
while [[ $# -gt 0 ]]; do case $1 in -o) out=$2; shift ;; -*) ;; *) url=$1 ;; esac; shift; done
log_call curl "$url"
f="$FAKE_WEB/${url#*://}"
[[ -f $f ]] || { echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; }
cp "$f" "$out"'
}

publish() {   # publish <id> : release with livepatch-auto_<id>-<kernel>.ko
  mkdir -p "$REL"
  rm -f "$REL"/*.ko
  head -c 20000 /dev/urandom > "$REL/livepatch-auto_$1-$KREL.ko"
  printf 'patchset auto_%s\n' "$1" > "$REL/PATCHSET"
  (cd "$REL" && sha256sum "livepatch-auto_$1-$KREL.ko" PATCHSET > SHA256SUMS)
}

@test "no release for this kernel yet: nothing to do, exit 0" {
  run lp -y auto run
  assert_success
  assert_output_contains "no automatic live patch for $KREL"
  refute_called_match insmod
}

@test "release without a module: every fix is already in this kernel" {
  mkdir -p "$REL"; echo "patchset auto_$ID" > "$REL/PATCHSET"
  (cd "$REL" && sha256sum PATCHSET > SHA256SUMS)
  run lp -y auto run
  assert_success
  assert_output_contains "nothing to patch"
  refute_called_match insmod
}

@test "downloads, verifies, loads and installs the automatic patch" {
  publish "$ID"
  run lp -y auto
  assert_success
  local ko="$PVE_LIVEPATCH_DIR/out/$KREL/livepatch-auto_$ID.ko"
  assert_output_contains "sha256 verified"
  assert_output_contains "signed by:"
  assert_called "insmod $ko"
  [[ -f $PVE_LIVEPATCH_DIR/installed/$KREL/livepatch-auto_$ID.ko ]]
  assert_output_contains "automatic live patch livepatch_auto_$ID is active"
}

@test "already loaded: up to date, downloads only SHA256SUMS" {
  publish "$ID"
  add_livepatch "livepatch_auto_$ID"
  run lp -y auto run
  assert_success
  assert_output_contains "up to date"
  refute_called_match "\.ko$"
  refute_called_match insmod
}

@test "a new patch set replaces the old one, also for the next boot" {
  publish aaaaaaaaaaaa
  run lp -y auto run
  assert_success
  publish "$ID"
  run lp -y auto run
  assert_success
  assert_called "insmod $PVE_LIVEPATCH_DIR/out/$KREL/livepatch-auto_$ID.ko"
  [[ -f $PVE_LIVEPATCH_DIR/installed/$KREL/livepatch-auto_$ID.ko ]]
  [[ ! -e $PVE_LIVEPATCH_DIR/installed/$KREL/livepatch-auto_aaaaaaaaaaaa.ko ]]
  [[ ! -e $PVE_LIVEPATCH_DIR/out/$KREL/livepatch-auto_aaaaaaaaaaaa.ko ]]
}

@test "a tampered module is not loaded" {
  publish "$ID"
  echo tampered >> "$REL/livepatch-auto_$ID-$KREL.ko"
  run lp -y auto run
  assert_failure
  assert_output_contains "checksum mismatch"
  refute_called_match insmod
}

@test "a file that is not an automatic module is ignored" {
  mkdir -p "$REL"; touch "$REL/livepatch-auto_XYZ-$KREL.ko"
  (cd "$REL" && sha256sum "livepatch-auto_XYZ-$KREL.ko" > SHA256SUMS)
  run lp -y auto run
  assert_success
  assert_output_contains "nothing to patch"
}

@test "Secure Boot and an unsigned module: stops before loading" {
  publish "$ID"
  FAKE_SB=enabled FAKE_SIGNER="" run lp -y auto run
  assert_failure
  assert_output_contains "is not signed"
  refute_called_match insmod
}

@test "auto enable writes the boot service and a 6-hourly timer" {
  run lp -y auto enable
  assert_success
  grep -qx 'ExecStart=/usr/sbin/pve-livepatch -y auto run' "$SYSTEMD_DIR/pve-livepatch-auto.service"
  grep -qx 'OnUnitActiveSec=6h' "$SYSTEMD_DIR/pve-livepatch-auto.timer"
  grep -qx 'ExecStart=/usr/sbin/pve-livepatch -y boot' "$SYSTEMD_DIR/pve-livepatch.service"
  assert_called "systemctl enable --now pve-livepatch-auto.timer"
  assert_called "systemctl enable pve-livepatch.service"
  run lp status
  assert_output_contains "automatic updates: on"
}

@test "auto disable removes the timer, keeps loaded patches" {
  lp -y auto enable
  add_livepatch livepatch_auto_x
  run lp -y auto disable
  assert_success
  assert_called "systemctl disable --now pve-livepatch-auto.timer"
  [[ ! -e $SYSTEMD_DIR/pve-livepatch-auto.timer && ! -e $SYSTEMD_DIR/pve-livepatch-auto.service ]]
  [[ -d $SYSFS_LP/livepatch_auto_x ]]
}

@test "unknown auto action fails" {
  run lp auto sometimes
  assert_failure
  assert_output_contains "usage:"
}

@test "fetch points lp-auto releases at 'auto'" {
  run lp fetch "lp-auto-$KREL"
  assert_failure
  assert_output_contains "handled by:"
}
