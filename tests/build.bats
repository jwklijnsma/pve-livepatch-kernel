#!/usr/bin/env bats
# `build`: patch → livepatch module with the kernel's own scripts/livepatch/klp-build.

load test_helper

setup() {
  setup_fake_host pve
  SRC="$PVE_LIVEPATCH_DIR/src/$KREL"
  mkdir -p "$SRC/kernel"
  printf 'int answer(void)\n{\n\treturn 41;\n}\n' > "$SRC/kernel/answer.c"
  klp_src

  PATCH="$BATS_TEST_TMPDIR/CVE-2026.1234.patch"
  cat > "$PATCH" <<'P'
--- a/kernel/answer.c
+++ b/kernel/answer.c
@@ -1,4 +1,4 @@
 int answer(void)
 {
-	return 41;
+	return 42;
 }
P
}

klp_src() {
  mkdir -p "$SRC/scripts/livepatch"
  cat > "$SRC/scripts/livepatch/klp-build" <<'K'
#!/usr/bin/env bash
echo "klp-build $* (cwd=$PWD)" >> "$STUB_LOG"
echo "OBJTOOL=${OBJTOOL:-unset}" >> "$STUB_LOG"
[[ -n ${FAKE_KLP_FAIL:-} ]] && { echo "$FAKE_KLP_FAIL" >&2; exit 1; }
out=""; while [[ $# -gt 0 ]]; do [[ $1 == -o ]] && { out=$2; shift; }; shift; done
touch "$out"; echo "SUCCESS"
K
  chmod +x "$SRC/scripts/livepatch/klp-build"
  echo "CONFIG_KLP_BUILD=y" > "$SRC/.config"
  printf 'VERSION = 6\nPATCHLEVEL = 8\nSUBLEVEL = 12\nEXTRAVERSION = -4-pve\n' > "$SRC/Makefile"
  mkdir -p "$SRC/tools/objtool"
  echo "distro objtool" > "$SRC/tools/objtool/Makefile"
  # `make -C <src> tools/objtool`: builds a fake objtool; with FAKE_OBJTOOL_BROKEN
  # the distro copy fails to compile (like Proxmox 7.0), the upstream copy works
  stub make '
log_call make "$@"
src=$2
if [[ " $* " == *" tools/objtool "* ]]; then
  if [[ -n ${FAKE_OBJTOOL_BROKEN:-} ]] && ! grep -q upstream "$src/tools/objtool/Makefile"; then
    echo "klp-checksum.c:73:31: error: implicit declaration of function insn_reloc" >&2; exit 2
  fi
  printf "#!/bin/sh\necho \"usage: objtool klp diff|post-link\"\n" > "$src/tools/objtool/objtool"
  chmod +x "$src/tools/objtool/objtool"
fi
exit 0'
}

# local stand-in for kernel.org: tag v6.8.12 with upstream objtool + klp-build
upstream_repo() {
  local r="$BATS_TEST_TMPDIR/upstream-linux"
  git init -q "$r"
  mkdir -p "$r/tools/objtool" "$r/scripts/livepatch"
  echo "upstream objtool" > "$r/tools/objtool/Makefile"
  cp "$SRC/scripts/livepatch/klp-build" "$r/scripts/livepatch/klp-build"
  echo "# upstream" >> "$r/scripts/livepatch/klp-build"
  git -C "$r" add -A
  git -C "$r" -c user.name=t -c user.email=t@t commit -q -m upstream
  git -C "$r" tag "${1:-v6.8.12}"
  git -C "$r" config uploadpack.allowFilter true
  export UPSTREAM_KERNEL_GIT="file://$r"
}

@test "builds a module with klp-build and prints its path" {
  run lpb -j 3 build "$PATCH" --name cve_2026_1234
  assert_success
  local ko="$PVE_LIVEPATCH_DIR/out/$KREL/livepatch-cve_2026_1234.ko"
  assert_called "klp-build -j 3 -o $ko $PATCH (cwd=$SRC)"
  assert_called "OBJTOOL=$SRC/tools/objtool/objtool"
  assert_output_contains "the kernel's own klp-build"
  [[ -f $ko ]]
  [[ ${lines[-1]} == "$ko" ]]
  [[ -f "$PVE_LIVEPATCH_DIR/out/$KREL/klp-build-cve_2026_1234.log" ]]
}

@test "--non-replace becomes klp-build --no-replace" {
  run lpb build "$PATCH" --name fix1 --non-replace
  assert_success
  grep -q -- "-o $PVE_LIVEPATCH_DIR/out/$KREL/livepatch-fix1.ko --no-replace $PATCH" "$STUB_LOG"
}

@test "--full is still accepted (klp-build always builds everything)" {
  run lpb build "$PATCH" --name fix1 --full
  assert_success
  run lpb --full build "$PATCH" --name fix1
  assert_success
}

@test "a kernel without klp-build is refused clearly" {
  rm -rf "$SRC/scripts/livepatch"
  run lpb build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "has no klp-build support"
  assert_output_contains ">= 6.19"
}

@test "a kernel without CONFIG_KLP_BUILD is refused clearly" {
  echo "# CONFIG_KLP_BUILD is not set" > "$SRC/.config"
  run lpb build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "CONFIG_KLP_BUILD=y"
  refute_called_match "^klp-build"
}

@test "warns before building when disk is short" {
  stub df 'echo "Avail"; echo " 5G"'
  run lpb build "$PATCH" --name fix1
  assert_success
  assert_output_contains "only 5G free"
}

@test "module name defaults to the patch file name, sanitised" {
  run lpb build "$PATCH"
  assert_success
  [[ -f "$PVE_LIVEPATCH_DIR/out/$KREL/livepatch-CVE_2026_1234.ko" ]]
}

@test "does not modify the source tree (dry-run only)" {
  run lpb build "$PATCH" --name fix1
  assert_success
  grep -q 'return 41' "$SRC/kernel/answer.c"
}

@test "a fix that is already in the kernel is reported, not reversed" {
  sed -i 's/return 41/return 42/' "$SRC/kernel/answer.c"
  run lpb build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "already included"
  refute_called_match "^klp-build"
}

@test "downloads a patch given as URL" {
  stub curl '
out=""; while [[ $# -gt 0 ]]; do [[ $1 == -o ]] && { out=$2; shift; }; shift; done
cp "$FAKE_PATCH" "$out"'
  FAKE_PATCH="$PATCH" run lpb build "https://git.kernel.org/stable/patch/?id=abc123" --name fromurl
  assert_success
  assert_output_contains "Downloading https://git.kernel.org/stable/patch/?id=abc123"
  ls "$PVE_LIVEPATCH_DIR/patches/"*.patch
}

@test "fails when the patch does not apply to the kernel source" {
  sed -i 's/return 41/return 40/' "$SRC/kernel/answer.c"
  run lpb build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "does not apply cleanly"
  refute_called_match "^klp-build"
}

@test "fails when source has not been prepared" {
  rm -rf "$SRC"
  run lpb build "$PATCH"
  assert_failure
  assert_output_contains "no prepared source"
}

@test "fails without a patch argument" {
  run lpb build
  assert_failure
  assert_output_contains "usage:"
}

@test "fails for an unreadable patch file" {
  run lpb build "$BATS_TEST_TMPDIR/missing.patch"
  assert_failure
  assert_output_contains "patch file not readable"
}

@test "rejects unknown build options" {
  run lpb build "$PATCH" --bogus
  assert_failure
  assert_output_contains "unknown build option: --bogus"
}

@test "signs the built module with the MOK key (built-in signer)" {
  make_test_key
  run lpb build "$PATCH" --name fix1
  assert_success
  assert_output_contains "signed livepatch-fix1.ko"
  [[ $(tail -c 28 "$PVE_LIVEPATCH_DIR/out/$KREL/livepatch-fix1.ko") == "~Module signature appended~"* ]]
}

@test "without MOK_KEY the module is built unsigned, with a warning" {
  run lpb build "$PATCH" --name fix1
  assert_success
  assert_output_contains "NOT signed"
}

@test "an unreadable signing key fails the build" {
  MOK_KEY=/nonexistent MOK_CERT=/nonexistent run lpb build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "not readable"
}

# --- objtool with live-patch support ---------------------------------------------

@test "klp-build: healthy distro objtool is used as is (no upstream fetch)" {
  klp_src
  upstream_repo
  run lpb build "$PATCH" --name fix1
  assert_success
  assert_output_contains "objtool ready"
  refute_output_contains "upstream"
  grep -q "distro objtool" "$SRC/tools/objtool/Makefile"
}

@test "klp-build: broken distro objtool is replaced by the upstream stable copy" {
  klp_src
  upstream_repo v6.8.12
  FAKE_OBJTOOL_BROKEN=1 run lpb build "$PATCH" --name fix1
  assert_success
  assert_output_contains "insn_reloc"
  assert_output_contains "using upstream objtool + klp-build (v6.8.12 from file://"
  assert_output_contains "objtool ready (upstream)"
  grep -q "upstream objtool" "$SRC/tools/objtool/Makefile"
  grep -q "# upstream" "$SRC/scripts/livepatch/klp-build"
  [[ -f "$PVE_LIVEPATCH_DIR/out/$KREL/livepatch-fix1.ko" ]]
}

@test "klp-build: falls back to the major.minor tag when the stable tag is missing" {
  klp_src
  upstream_repo v6.8
  FAKE_OBJTOOL_BROKEN=1 run lpb build "$PATCH" --name fix1
  assert_success
  assert_output_contains "(v6.8 from file://"
}

@test "klp-build: clear error when no upstream copy can be fetched" {
  klp_src
  export UPSTREAM_KERNEL_GIT="file://$BATS_TEST_TMPDIR/does-not-exist"
  FAKE_OBJTOOL_BROKEN=1 run lpb build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "could not fetch upstream 6.8.12 objtool/klp-build"
  refute_called_match "^klp-build"
}

@test "klp-build 'no changes detected' gets a clear message" {
  klp_src
  FAKE_KLP_FAIL="error: klp-build: no changes detected" run lpb build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "found no changed functions"
}

@test "other klp-build failures point at its log" {
  klp_src
  FAKE_KLP_FAIL="error: klp-build: original kernel build failed" run lpb build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "klp-build failed — see $PVE_LIVEPATCH_DIR/out/$KREL/klp-build-fix1.log"
}
