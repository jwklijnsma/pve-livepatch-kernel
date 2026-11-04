#!/usr/bin/env bats
# `build`: patch → livepatch module via kpatch-build.

load test_helper

setup() {
  setup_fake_host pve
  SRC="$PVE_LIVEPATCH_DIR/src/$KREL"
  mkdir -p "$SRC/kernel"
  echo "VERSION = 6" > "$SRC/Makefile"
  printf 'int answer(void)\n{\n\treturn 41;\n}\n' > "$SRC/kernel/answer.c"
  echo "fake vmlinux" > "$SRC/vmlinux"            # original kernel already compiled

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

@test "compiles the original vmlinux first when it is missing" {
  rm "$SRC/vmlinux"
  stub make 'log_call make "$@"; [[ " $* " == *" vmlinux "* ]] && echo built > "$2/vmlinux"; exit 0'
  run lp -j 3 build "$PATCH" --name fix1
  assert_success
  assert_called "make -C $SRC -j3 vmlinux"
  assert_output_contains "original vmlinux built"
  # kpatch-build runs after vmlinux exists
  [[ $(grep -n '^make ' "$STUB_LOG" | cut -d: -f1) -lt $(grep -n '^kpatch-build ' "$STUB_LOG" | cut -d: -f1) ]]
}

@test "small mode seeds Module.symvers from vmlinux.symvers" {
  echo "0x1 printk vmlinux EXPORT_SYMBOL" > "$SRC/vmlinux.symvers"
  run lp build "$PATCH" --name fix1
  assert_success
  cmp -s "$SRC/vmlinux.symvers" "$SRC/Module.symvers"
}

@test "an existing Module.symvers is left alone" {
  echo "vmlinux only" > "$SRC/vmlinux.symvers"
  echo "full table"   > "$SRC/Module.symvers"
  run lp build "$PATCH" --name fix1
  assert_success
  [[ $(cat "$SRC/Module.symvers") == "full table" ]]
}

@test "--full does not seed Module.symvers (make modules writes it)" {
  echo "vmlinux only" > "$SRC/vmlinux.symvers"
  run lp build "$PATCH" --name fix1 --full
  assert_success
  [[ ! -e $SRC/Module.symvers ]]
}

@test "does not recompile vmlinux when it is already there" {
  stub make 'log_call make "$@"'
  run lp build "$PATCH" --name fix1
  assert_success
  refute_called_match "vmlinux$"
  grep -q '^kpatch-build ' "$STUB_LOG"
}

@test "a failing vmlinux compile stops with the log tail" {
  rm "$SRC/vmlinux"
  stub make 'echo "drivers/foo.c:1: error: boom"; exit 2'
  run lp build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "error: boom"
  assert_output_contains "compiling the original vmlinux failed — see $PVE_LIVEPATCH_DIR/out/$KREL/vmlinux-build.log"
  refute_called_match kpatch-build
}

@test "small mode (default): builds vmlinux only" {
  run lp -j 3 build "$PATCH" --name fix1
  assert_success
  assert_called "kpatch-build -s $SRC -c $KCONFIG -j 3 -n fix1 -t vmlinux $PATCH"
  assert_output_contains "vmlinux only"
}

@test "build --full builds vmlinux and modules (no -t)" {
  run lp -j 3 build "$PATCH" --name fix1 --full
  assert_success
  assert_called "kpatch-build -s $SRC -c $KCONFIG -j 3 -n fix1 $PATCH"
  assert_output_contains "vmlinux + modules"
}

@test "global --full works too" {
  run lp --full build "$PATCH" --name fix1
  assert_success
  refute_called_match -- "-t vmlinux"
}

@test "module-only patch in small mode explains how to rebuild with --full" {
  stub kpatch-build 'log_call kpatch-build "$@"; echo "ERROR: no changed objects found. Check /root/.kpatch/build.log for more details." >&2; exit 1'
  run lp build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "only changes code in kernel modules"
  assert_output_contains "--name fix1 --full"
}

@test "other kpatch-build failures point at the build log" {
  FAKE_KPATCH_BUILD_FAIL=1 run lp build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "kpatch-build failed — see $PVE_LIVEPATCH_DIR/out/$KREL/kpatch-build-fix1.log"
  refute_output_contains "only changes code in kernel modules"
}

@test "kpatch-build output is kept in a log file" {
  run lp build "$PATCH" --name fix1
  assert_success
  [[ -f "$PVE_LIVEPATCH_DIR/out/$KREL/kpatch-build-fix1.log" ]]
}

@test "warns before building when disk is short" {
  stub df 'echo "Avail"; echo " 5G"'
  run lp build "$PATCH" --name fix1
  assert_success
  assert_output_contains "only 5G free"
}

@test "--non-replace is passed through" {
  run lp build "$PATCH" --name fix1 --non-replace
  assert_success
  grep -q -- '-n fix1 --non-replace -t vmlinux' "$STUB_LOG"
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

@test "signs the built module with the MOK key (built-in signer)" {
  make_test_key
  run lp build "$PATCH" --name fix1
  assert_success
  assert_output_contains "signed livepatch-fix1.ko"
  [[ $(tail -c 28 "$PVE_LIVEPATCH_DIR/out/$KREL/livepatch-fix1.ko") == "~Module signature appended~"* ]]
}

@test "warns when Secure Boot is on but nothing can sign" {
  FAKE_SB=enabled MOK_KEY=/nonexistent run lp build "$PATCH" --name fix1
  assert_success
  assert_output_contains "NOT signed"
}

# --- in-kernel klp-build engine (kernels >= 6.19, required with IBT) -----------

klp_src() {
  mkdir -p "$SRC/scripts/livepatch"
  cat > "$SRC/scripts/livepatch/klp-build" <<'K'
#!/usr/bin/env bash
echo "klp-build $* (cwd=$PWD)" >> "$STUB_LOG"
[[ -n ${FAKE_KLP_FAIL:-} ]] && { echo "$FAKE_KLP_FAIL" >&2; exit 1; }
out=""; while [[ $# -gt 0 ]]; do [[ $1 == -o ]] && { out=$2; shift; }; shift; done
touch "$out"; echo "SUCCESS"
K
  chmod +x "$SRC/scripts/livepatch/klp-build"
  echo "CONFIG_KLP_BUILD=y" > "$SRC/.config"
}

@test "uses the kernel's klp-build when the source has it and KLP_BUILD=y" {
  klp_src
  rm -f "$STUB_BIN/kpatch-build"          # not needed for this engine
  rm "$SRC/vmlinux"                        # klp-build compiles everything itself
  run lp -j 3 build "$PATCH" --name fix1
  assert_success
  assert_called "klp-build -j 3 -o $PVE_LIVEPATCH_DIR/out/$KREL/livepatch-fix1.ko $PATCH (cwd=$SRC)"
  assert_output_contains "the kernel's own klp-build"
  refute_output_contains "original vmlinux"
  [[ -f "$PVE_LIVEPATCH_DIR/out/$KREL/livepatch-fix1.ko" ]]
  [[ -f "$PVE_LIVEPATCH_DIR/out/$KREL/klp-build-fix1.log" ]]
}

@test "klp-build gets --no-replace for --non-replace" {
  klp_src
  run lp build "$PATCH" --name fix1 --non-replace
  assert_success
  grep -q -- "-o $PVE_LIVEPATCH_DIR/out/$KREL/livepatch-fix1.ko --no-replace $PATCH" "$STUB_LOG"
}

@test "falls back to kpatch-build when CONFIG_KLP_BUILD is not set" {
  klp_src
  echo "# CONFIG_KLP_BUILD is not set" > "$SRC/.config"
  run lp build "$PATCH" --name fix1
  assert_success
  grep -q '^kpatch-build ' "$STUB_LOG"
  refute_called_match "^klp-build"
}

@test "LP_ENGINE=kpatch forces kpatch-build" {
  klp_src
  LP_ENGINE=kpatch run lp build "$PATCH" --name fix1
  assert_success
  grep -q '^kpatch-build ' "$STUB_LOG"
  refute_called_match "^klp-build"
}

@test "LP_ENGINE=klp-build without klp-build in the source fails clearly" {
  LP_ENGINE=klp-build run lp build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "has no scripts/livepatch/klp-build"
}

@test "invalid LP_ENGINE is rejected" {
  LP_ENGINE=magic run lp build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "LP_ENGINE must be auto, kpatch or klp-build"
}

@test "klp-build 'no changes detected' gets a clear message" {
  klp_src
  FAKE_KLP_FAIL="error: klp-build: no changes detected" run lp build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "found no changed functions"
}

@test "other klp-build failures point at its log" {
  klp_src
  FAKE_KLP_FAIL="error: klp-build: original kernel build failed" run lp build "$PATCH" --name fix1
  assert_failure
  assert_output_contains "klp-build failed — see $PVE_LIVEPATCH_DIR/out/$KREL/klp-build-fix1.log"
}
