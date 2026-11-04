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

@test "fetch by tag: downloads, verifies sha256 + signature, never signs itself" {
  run lp fetch "$TAG"
  assert_success
  assert_called "curl https://github.com/jwklijnsma/pve-livepatch-kernel/releases/download/$TAG/livepatch-fix1-$KREL.ko"
  assert_output_contains "sha256 verified"
  assert_output_contains "signed by: pve-livepatch module signing key"
  [[ ${lines[-1]} == "$OUT" ]]
  cmp -s "$OUT" "$REL/livepatch-fix1-$KREL.ko"          # byte-identical to what GitHub signed
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

@test "Secure Boot on and the module is unsigned: stops before loading" {
  FAKE_SB=enabled FAKE_SIGNER="" run lp fetch "$TAG"
  assert_failure
  assert_output_contains "is not signed and Secure Boot is on"
  assert_output_contains "MODULE_SIGNING_PEM"
  [[ -f $OUT ]]
}

@test "Secure Boot off: an unsigned module is accepted with a note" {
  FAKE_SIGNER="" run lp fetch "$TAG"
  assert_success
  assert_output_contains "module is not signed (fine while Secure Boot is off)"
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

@test "setup installs only what loading needs (no compiler, no openssl, no git)" {
  stub apt-get 'log_call apt-get "$@"'
  run lp setup
  assert_success
  assert_called "apt-get install -y --no-install-recommends curl ca-certificates kmod mokutil"
  refute_called_match "build-essential\|openssl\|git"
  assert_output_contains "auto enable"
  run lp setup --minimal                     # old spelling still works
  assert_success
}

@test "builder setup installs everything klp-build needs" {
  stub apt-get 'log_call apt-get "$@"'
  run lpb setup
  assert_success
  local inst; inst=$(grep '^apt-get install' "$STUB_LOG")
  for pkg in build-essential gawk patch patchutils libxxhash-dev bison flex libelf-dev libssl-dev dwarves rsync git openssl; do
    [[ " $inst " == *" $pkg "* ]] || { echo "missing $pkg in: $inst"; return 1; }
  done
}

@test "setup rejects unknown options" {
  run lp setup --tiny
  assert_failure
  assert_output_contains "unknown setup option: --tiny"
}

# --- check on a small node ------------------------------------------------------

@test "check needs no compiler and no free disk space" {
  stub gcc 'exit 127'
  stub df 'echo "Avail"; echo " 1G"'
  run lp check
  assert_success
  assert_output_contains "insmod available"
  refute_output_contains "gcc"
  refute_output_contains "G free"
  assert_output_contains "Ready."
}
