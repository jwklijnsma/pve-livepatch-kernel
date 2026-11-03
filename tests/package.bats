#!/usr/bin/env bats
# packaging/build-deb.sh: the .deb that the release workflow publishes.

load test_helper

setup() {
  command -v dpkg-deb >/dev/null || skip "dpkg-deb not available"
  export OUT_DIR="$BATS_TEST_TMPDIR/dist"
}

build() { "$REPO_ROOT/packaging/build-deb.sh" "$@"; }

@test "builds pve-livepatch_<version>_all.deb" {
  run build 2.3.4
  assert_success
  [[ $output == "$OUT_DIR/pve-livepatch_2.3.4_all.deb" ]]
  [[ -f $output ]]
}

@test "strips a leading v from the version (tag names)" {
  run build v2.3.4
  assert_success
  [[ $output == */pve-livepatch_2.3.4_all.deb ]]
}

@test "defaults to SCRIPT_VERSION from the script" {
  local want; want=$(sed -n 's/^readonly SCRIPT_VERSION="\(.*\)"/\1/p' "$SCRIPT")
  run build
  assert_success
  [[ $output == */pve-livepatch_${want}_all.deb ]]
}

@test "rejects an invalid version" {
  run build "not a version"
  assert_failure
  assert_output_contains "invalid version"
}

@test "control file has the expected metadata" {
  deb=$(build 2.3.4)
  [[ $(dpkg-deb -f "$deb" Package) == pve-livepatch ]]
  [[ $(dpkg-deb -f "$deb" Version) == 2.3.4 ]]
  [[ $(dpkg-deb -f "$deb" Architecture) == all ]]
  [[ $(dpkg-deb -f "$deb" Depends) == *kmod* ]]
  [[ $(dpkg-deb -f "$deb" Depends) == *openssl* ]]
  # build toolchain must not be pulled in on small nodes (apt installs Recommends)
  [[ $(dpkg-deb -f "$deb" Recommends) != *build-essential* ]]
  [[ $(dpkg-deb -f "$deb" Suggests) == *libelf-dev* ]]
}

@test "installs an executable /usr/sbin/pve-livepatch with the release version" {
  deb=$(build 2.3.4)
  x="$BATS_TEST_TMPDIR/x"
  dpkg-deb -x "$deb" "$x"
  [[ -x $x/usr/sbin/pve-livepatch ]]
  run "$x/usr/sbin/pve-livepatch" --version
  assert_success
  [[ $output == 2.3.4 ]]
}

@test "ships docs and a root-owned, world-readable tree" {
  deb=$(build 2.3.4)
  run dpkg-deb -c "$deb"
  assert_output_contains "./usr/share/doc/pve-livepatch/README.md"
  assert_output_contains "./usr/share/doc/pve-livepatch/copyright"
  [[ ${lines[0]} == "drwxr-xr-x root/root"* ]]
  # every entry owned by root/root, whoever built it
  ! grep -v " root/root " <<< "$output"
}

@test "postrm only cleans up on purge" {
  deb=$(build 2.3.4)
  c="$BATS_TEST_TMPDIR/ctl"
  dpkg-deb -e "$deb" "$c"
  [[ -x $c/postrm ]]
  grep -q '"$1" = "purge"' "$c/postrm"
}
