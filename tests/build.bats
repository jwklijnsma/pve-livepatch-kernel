#!/usr/bin/env bats
# `build`: patch → livepatch module via kpatch-build.

load test_helper

setup() {
  setup_fake_host pve
  SRC="$PVE_LIVEPATCH_DIR/src/$KREL"
  mkdir -p "$SRC/kernel"
  echo "VERSION = 6" > "$SRC/Makefile"
  printf 'int answer(void)\n{\n\treturn 41;\n}\n' > "$SRC/kernel/answer.c"

  PATCH="$BATS_TEST_TMPDIR/CVE-2026.1234.patch"
  cat > "$PATCH" <<'EOF'
--- a/kernel/answer.c
+++ b/kernel/answer.c
@@ -1,4 +1,4 @@
 int answer(void)
 {
-	return 41;
+	return 42;
 }
EOF
}

@test "builds a module and prints its path" {
  run lp build "$PATCH" --name cve_2026_1234
  assert_success
  local ko="$PVE_LIVEPATCH_DIR/out/$KREL/livepatch-cve_2026_1234.ko"
  [[ -f $ko ]]
  [[ ${lines[-1]} == "$ko" ]]
}

@test "passes source dir, config, jobs and name to kpatch-build" {
  run lp -j 3 build "$PATCH" --name fix1
  assert_success
  assert_called "kpatch-build -s $SRC -c $KCONFIG -j 3 -n fix1 $PATCH"
}

@test "--non-replace is passed through" {
  run lp build "$PATCH" --name fix1 --non-replace
  assert_success
  grep -q -- '-n fix1 --non-replace' "$STUB_LOG"
}

@test "module name defaults to the patch file name, sanitised" {
  run lp build "$PATCH"
  assert_success
  [[ -f "$PVE_LIVEPATCH_DIR/out/$KREL/livepatch-CVE_2026_1234.ko" ]]
}

@test "does not modify the source tree (dry-run only)" {
  run lp build "$PATCH" --name fix1
  assert_success
  grep -q 'return 41' "$SRC/kernel/answer.c"
}

@test "downloads a patch given as URL" {
  stub curl '
out=""; while [[ $# -gt 0 ]]; do [[ $1 == -o ]] && { out=$2; shift; }; shift; done
cp "$FAKE_PATCH" "$out"'
  FAKE_PATCH="$PATCH" run lp build "https://git.kernel.org/stable/patch/?id=abc123" --name fromurl
  assert_success
  assert_output_contains "Downloading https://git.kernel.org/stable/patch/?id=abc123"
  ls "$PVE_LIVEPATCH_DIR/patches/"*.patch
}

@test "fails when the patch does not apply to the kernel source" {
  sed -i 's/return 41/return 40/' "$SRC/kernel/answer.c"
  run lp build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "does not apply cleanly"
  refute_called_match kpatch-build
}

@test "fails when source has not been prepared" {
  rm -rf "$SRC"
  run lp build "$PATCH"
  assert_failure
  assert_output_contains "no prepared source"
}

@test "fails without a patch argument" {
  run lp build
  assert_failure
  assert_output_contains "usage:"
}

@test "fails for an unreadable patch file" {
  run lp build "$BATS_TEST_TMPDIR/missing.patch"
  assert_failure
  assert_output_contains "patch file not readable"
}

@test "rejects unknown build options" {
  run lp build "$PATCH" --bogus
  assert_failure
  assert_output_contains "unknown build option: --bogus"
}

@test "propagates kpatch-build failure" {
  FAKE_KPATCH_BUILD_FAIL=1 run lp build "$PATCH" --name fix1
  assert_failure
}

@test "signs the module when a MOK key and sign-file exist" {
  mkdir -p "$SRC/scripts"
  printf '#!/bin/sh\necho "sign-file $*" >> "$STUB_LOG"\n' > "$SRC/scripts/sign-file"
  chmod +x "$SRC/scripts/sign-file"
  touch "$BATS_TEST_TMPDIR/k" "$BATS_TEST_TMPDIR/c"
  MOK_KEY="$BATS_TEST_TMPDIR/k" MOK_CERT="$BATS_TEST_TMPDIR/c" run lp build "$PATCH" --name fix1
  assert_success
  assert_called "sign-file sha512 $BATS_TEST_TMPDIR/k $BATS_TEST_TMPDIR/c $PVE_LIVEPATCH_DIR/out/$KREL/livepatch-fix1.ko"
}

@test "warns when Secure Boot is on but nothing can sign" {
  FAKE_SB=enabled MOK_KEY=/nonexistent run lp build "$PATCH" --name fix1
  assert_success
  assert_output_contains "NOT signed"
}
