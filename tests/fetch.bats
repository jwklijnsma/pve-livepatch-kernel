#!/usr/bin/env bats
# `fetch`: CI-built modules from GitHub releases; `setup --minimal`; fetch-mode check.

load test_helper

setup() {
  setup_fake_host pve
  export FAKE_WEB="$BATS_TEST_TMPDIR/web"
  TAG="lp-fix1-$KREL"
  REL="$FAKE_WEB/github.com/jwklijnsma/pve-livepatch-kernel/releases/download/$TAG"
  mkdir -p "$REL"
  head -c 30000 /dev/urandom > "$REL/livepatch-fix1-$KREL.ko"
  (cd "$REL" && sha256sum "livepatch-fix1-$KREL.ko" > SHA256SUMS)
  # curl stub: serve files from $FAKE_WEB/<host>/<path>
  stub curl '
out=""; url=""
while [[ $# -gt 0 ]]; do case $1 in -o) out=$2; shift ;; -*) ;; *) url=$1 ;; esac; shift; done
log_call curl "$url"
f="$FAKE_WEB/${url#*://}"
[[ -f $f ]] || { echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; }
cp "$f" "$out"'
  OUT="$PVE_LIVEPATCH_DIR/out/$KREL/livepatch-fix1.ko"
}

@test "fetch by tag: downloads, verifies sha256, signs, prints path" {
  make_test_key
  run lp fetch "$TAG"
  assert_success
  assert_called "curl https://github.com/jwklijnsma/pve-livepatch-kernel/releases/download/$TAG/livepatch-fix1-$KREL.ko"
  assert_output_contains "sha256 verified"
  assert_output_contains "signed livepatch-fix1.ko"
  [[ ${lines[-1]} == "$OUT" ]]
  [[ $(tail -c 28 "$OUT") == "~Module signature appended~"* ]]
}

@test "PVE_LIVEPATCH_REPO selects another repository" {
  mkdir -p "$FAKE_WEB/github.com/me/fork/releases/download"
  cp -r "$REL" "$FAKE_WEB/github.com/me/fork/releases/download/"
  PVE_LIVEPATCH_REPO=me/fork run lp fetch "$TAG"
  assert_success
  grep -q "github.com/me/fork/" "$STUB_LOG"
}

@test "refuses a release built for another kernel, before downloading" {
  run lp fetch "lp-fix1-6.8.12-2-pve"
  assert_failure
  assert_output_contains "not built for this kernel ($KREL)"
  refute_called_match curl
}

@test "refuses a tag that is not a live-patch release" {
  run lp fetch "v1.3.0"
  assert_failure
  assert_output_contains "not a live-patch release tag"
}

@test "checksum mismatch: fails and leaves nothing behind" {
  echo tampered >> "$REL/livepatch-fix1-$KREL.ko"
  run lp fetch "$TAG"
  assert_failure
  assert_output_contains "checksum mismatch"
  [[ ! -e $OUT && ! -e $OUT.part ]]
}

@test "SHA256SUMS without an entry for the module fails" {
  echo "0000  other.ko" > "$REL/SHA256SUMS"
  run lp fetch "$TAG"
  assert_failure
  assert_output_contains "SHA256SUMS has no entry"
}

@test "SHA256SUMS in binary-mode / ./ form is accepted" {
  sum=$(cut -d' ' -f1 "$REL/SHA256SUMS")
  printf '%s *./livepatch-fix1-%s.ko\n' "$sum" "$KREL" > "$REL/SHA256SUMS"
  run lp fetch "$TAG"
  assert_success
  assert_output_contains "sha256 verified"
}

@test "missing release asset fails clearly" {
  run lp fetch "lp-nope-$KREL"
  assert_failure
  assert_output_contains "download failed"
}

@test "module for another kernel (vermagic) is rejected and removed" {
  FAKE_VERMAGIC=6.8.12-2-pve run lp fetch "$TAG"
  assert_failure
  assert_output_contains "module is for kernel '6.8.12-2-pve'"
  [[ ! -e $OUT && ! -e $OUT.part ]]
}

@test "non-livepatch module is rejected" {
  FAKE_LIVEPATCH="" run lp fetch "$TAG"
  assert_failure
  assert_output_contains "is not a livepatch module"
}

@test "Secure Boot on without a key: stops and says to run mok setup" {
  FAKE_SB=enabled MOK_KEY=/nonexistent run lp fetch "$TAG"
  assert_failure
  assert_output_contains "mok setup"
  [[ -f $OUT ]]
}

@test "Secure Boot off without a key: module kept unsigned" {
  MOK_KEY=/nonexistent run lp fetch "$TAG"
  assert_success
  assert_output_contains "left unsigned"
  [[ $(tail -c 28 "$OUT") != "~Module signature appended~"* ]]
}

@test "direct URL works but warns there is no checksum" {
  run lp fetch "https://github.com/jwklijnsma/pve-livepatch-kernel/releases/download/$TAG/livepatch-fix1-$KREL.ko"
  assert_success
  assert_output_contains "no SHA256SUMS to verify"
  [[ -f $OUT ]]
}

@test "fetch without argument shows usage" {
  run lp fetch
  assert_failure
  assert_output_contains "usage:"
}

# --- setup --minimal -----------------------------------------------------------

@test "setup --minimal installs only loader deps and the kpatch script" {
  stub apt-get 'log_call apt-get "$@"'
  stub git 'log_call git "$@"; [[ $1 == clone ]] && mkdir -p "$4/.git"; exit 0'
  stub make 'log_call make "$@"'
  run lp setup --minimal
  assert_success
  grep -q '^apt-get install -y --no-install-recommends git make curl ca-certificates kmod openssl mokutil$' "$STUB_LOG"
  refute_called_match build-essential
  assert_called "make -C $PVE_LIVEPATCH_DIR/kpatch/kpatch install"
  assert_called "make -C $PVE_LIVEPATCH_DIR/kpatch/contrib install"
  [[ ! -e $PVE_LIVEPATCH_DIR/kpatch ]]
  assert_output_contains "fetch <release-tag>"
}

@test "setup rejects unknown options" {
  run lp setup --tiny
  assert_failure
  assert_output_contains "unknown setup option: --tiny"
}

# --- check on a small node ------------------------------------------------------

@test "check passes on a fetch-only node (no gcc, no kpatch-build)" {
  rm -f "$STUB_BIN/kpatch-build"
  stub gcc 'exit 127'
  stub df 'echo "Avail"; echo " 3G"'
  run lp check
  assert_success
  assert_output_contains "fetch mode: no local build toolchain needed"
  assert_output_contains "kpatch installed"
  refute_output_contains "gcc mismatch"
  refute_output_contains "only 3G"
  assert_output_contains "Ready."
}

@test "check fails when even the kpatch loader is missing" {
  rm -f "$STUB_BIN/kpatch-build" "$STUB_BIN/kpatch"
  run lp check
  assert_failure
  assert_output_contains "setup --minimal"
}
