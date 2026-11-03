#!/usr/bin/env bats
# `source` end to end against local git repos / a fake apt, incl. small-disk mode.

load test_helper

pve_fixture() {
  setup_fake_host pve
  # allow file:// submodules (git >= 2.38) and give commits an identity
  export GIT_CONFIG_COUNT=3
  export GIT_CONFIG_KEY_0=protocol.file.allow GIT_CONFIG_VALUE_0=always
  export GIT_CONFIG_KEY_1=user.name           GIT_CONFIG_VALUE_1=t
  export GIT_CONFIG_KEY_2=user.email          GIT_CONFIG_VALUE_2=t@t

  local up="$BATS_TEST_TMPDIR/upstream"
  # Ubuntu kernel tree with two commits (so a shallow fetch is observable)
  git init -q "$up/ubuntu-kernel"
  printf 'VERSION = 6\nPATCHLEVEL = 8\nSUBLEVEL = 12\nEXTRAVERSION =\n' > "$up/ubuntu-kernel/Makefile"
  mkdir -p "$up/ubuntu-kernel/kernel"
  printf 'int answer(void)\n{\n\treturn 40;\n}\n' > "$up/ubuntu-kernel/kernel/answer.c"
  git -C "$up/ubuntu-kernel" add -A; git -C "$up/ubuntu-kernel" commit -q -m one
  sed -i 's/40/41/' "$up/ubuntu-kernel/kernel/answer.c"
  git -C "$up/ubuntu-kernel" commit -qam two

  # pve-kernel repo: submodule + one Proxmox patch + the version-bump commit
  git init -q "$up/pve-kernel"
  git -C "$up/pve-kernel" submodule add -q "file://$up/ubuntu-kernel" submodules/ubuntu-kernel
  mkdir -p "$up/pve-kernel/patches/kernel"
  cat > "$up/pve-kernel/patches/kernel/0001-proxmox-tweak.patch" <<'P'
--- a/kernel/answer.c
+++ b/kernel/answer.c
@@ -1,4 +1,4 @@
 int answer(void)
 {
-	return 41;
+	return 42;
 }
P
  git -C "$up/pve-kernel" add -A; git -C "$up/pve-kernel" commit -q -m "bump version to 6.8.12-4"
  export PVE_KERNEL_REPO="$up/pve-kernel"

  stub dpkg       '[[ $1 == -S ]] && echo "proxmox-kernel-6.8.12-4-pve-signed: $2"'
  stub dpkg-query 'echo 6.8.12-4'
  stub make       '[[ " $* " == *" kernelrelease "* ]] && echo "$KREL"; exit 0'
}

@test "PVE source (small): patched tree ready, submodule checkout removed" {
  pve_fixture
  run lp source
  assert_success
  assert_output_contains "only the needed commit"
  refute_output_contains "falling back"
  assert_output_contains "applied 1 Proxmox kernel patches"
  assert_output_contains "removed submodule checkout"
  local src="$PVE_LIVEPATCH_DIR/src/$KREL" repo="$PVE_LIVEPATCH_DIR/pve-kernel"
  grep -q 'return 42' "$src/kernel/answer.c"
  grep -qx 'EXTRAVERSION = -4-pve' "$src/Makefile"
  [[ ! -e $src/.git ]]
  [[ -z $(ls -A "$repo/submodules/ubuntu-kernel" 2>/dev/null) ]]
  [[ ! -d $repo/.git/modules/submodules/ubuntu-kernel ]]
}

@test "PVE source --full keeps the full-history submodule" {
  pve_fixture
  run lp source --full
  assert_success
  assert_output_contains "full history"
  local sub="$PVE_LIVEPATCH_DIR/pve-kernel/submodules/ubuntu-kernel"
  [[ $(git -C "$sub" rev-list --count HEAD) == 2 ]]
  grep -q 'return 42' "$PVE_LIVEPATCH_DIR/src/$KREL/kernel/answer.c"
}

@test "PVE source can run again (re-fetches after the small-mode cleanup)" {
  pve_fixture
  run lp source;  assert_success
  run lp source;  assert_success
  grep -q 'return 42' "$PVE_LIVEPATCH_DIR/src/$KREL/kernel/answer.c"
}

@test "PVE source fails clearly when no bump-version commit matches" {
  pve_fixture
  stub dpkg-query 'echo 6.8.12-9'
  run lp source
  assert_failure
  assert_output_contains "no 'bump version to 6.8.12-9' commit found"
}

@test "PVE source fails when a Proxmox patch does not apply" {
  pve_fixture
  sed -i 's/return 41;/return 41;  /' "$BATS_TEST_TMPDIR/upstream/pve-kernel/patches/kernel/0001-proxmox-tweak.patch"
  sed -i 's/-\treturn 41;  /-\treturn 99;/' "$BATS_TEST_TMPDIR/upstream/pve-kernel/patches/kernel/0001-proxmox-tweak.patch"
  git -C "$BATS_TEST_TMPDIR/upstream/pve-kernel" commit -qam "bump version to 6.8.12-4"
  run lp source
  assert_failure
  assert_output_contains "PVE patch failed: 0001-proxmox-tweak.patch"
}

@test "PVE_KERNEL_PKGVER builds for a kernel that is not installed (CI)" {
  pve_fixture
  stub dpkg 'echo "dpkg should not be called" >&2; exit 1'
  stub dpkg-query 'echo "dpkg-query should not be called" >&2; exit 1'
  PVE_KERNEL_PKGVER=6.8.12-4 run lp source
  assert_success
  assert_output_contains "Kernel package: proxmox-kernel-$KREL 6.8.12-4"
  grep -q 'return 42' "$PVE_LIVEPATCH_DIR/src/$KREL/kernel/answer.c"
}

@test "unknown source option fails" {
  setup_fake_host pve
  run lp source --bogus
  assert_failure
  assert_output_contains "unknown source option: --bogus"
}

@test "Ubuntu source: apt-get source tree copied, download dir removed" {
  setup_fake_host ubuntu
  stub dpkg       '[[ $1 == -S ]] && echo "linux-image-6.8.0-45-generic: $2"'
  stub dpkg-query 'echo 6.8.0-45.45'
  stub apt-cache  '[[ $1 == showsrc ]] && echo "Package: linux"; exit 0'
  stub apt-get '
log_call apt-get "$@"
case $1 in
  indextargets) echo "Identifier: Sources" ;;
  source) mkdir -p linux-6.8.0; printf "EXTRAVERSION =\n" > linux-6.8.0/Makefile ;;
esac'
  stub make '[[ " $* " == *" kernelrelease "* ]] && echo "$KREL"; exit 0'
  run lp source
  assert_success
  assert_called "apt-get source -qq linux-image-unsigned-$KREL"
  grep -qx 'EXTRAVERSION = -45-generic' "$PVE_LIVEPATCH_DIR/src/$KREL/Makefile"
  [[ ! -e "$PVE_LIVEPATCH_DIR/ubuntu-src/$KREL" ]]
}
