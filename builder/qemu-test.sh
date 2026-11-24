#!/usr/bin/env bash
# QEMU stage: boot the unmodified shipped kernel and put the signed module
# through what it will meet in production. On success writes
# <workdir>/out/qemu.ok, which publish.sh requires.
#
# usage: qemu-test.sh <kver> <workdir> [previous-level.ko]
#
# In the guest:
#   1. load the modules the patch targets (e.g. overlay), run the catalog
#      reproducers: they should show the bug; unload the modules again
#   2. (previous level) load the livepatch, wait for the transition, check
#      replace=1 and the patched functions
#   3. load the target modules after the livepatch (relocations into
#      modules loaded later), check every object is patched, run the
#      reproducers: they must pass
#   4. CYCLES x disable/unload/load under background load
#   5. disable and unload: the reproducers should fail again; load again:
#      they must pass again
#   6. no BUG/Oops/WARNING in the kernel log
#
# Uses KVM when /dev/kvm is writable, otherwise TCG (slower, still fine).
#
# Runs no code from the kernel tree (run.sh does not even mount it): the
# initramfs is written by mkinitramfs.py, the kernel and modules come from
# the shipped packages, reproducers only from the catalog (CATALOG).
source "$(dirname "$0")/lib.sh"
KVER=${1:?kver}; WORK=${2:?workdir}; PREV_KO=${3:-}
CYCLES=${CYCLES:-5}
CATALOG=${CATALOG:-/work/catalog}
HERE=$(cd "$(dirname "$0")" && pwd)
require qemu-system-x86_64 busybox python3 modinfo sha256sum timeout gzip realpath
OUT="$WORK/out"; SHIPPED="$WORK/shipped"
regular "$OUT/manifest.json" "$OUT/functions.txt" "$OUT/resolved.json" "$SHIPPED/vmlinuz" "$SHIPPED/build-id"
MOD=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["module"])' "$OUT/manifest.json")
[[ "$MOD" =~ ^[A-Za-z0-9_-]+\.ko$ ]] || die "unexpected module name in the manifest: $MOD"
KO="$OUT/$MOD"
regular "$KO"
NAME=$(modinfo -F name "$KO")
PREV=""
if [ -n "$PREV_KO" ]; then regular "$PREV_KO"; PREV=$(modinfo -F name "$PREV_KO"); fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Modules the patch targets, plus their dependencies, in load order.
python3 -I - "$OUT/functions.txt" "$SHIPPED/modules" "$TMP" > "$TMP/mods.list" <<'PY'
import os, sys
funcs, moddir, tmp = sys.argv[1:4]
objs = sorted({l.split(":", 1)[0] for l in open(funcs) if ":" in l} - {"vmlinux"})
deps, paths = {}, {}
for line in open(os.path.join(moddir, "modules.dep")):
    if ":" not in line:
        continue
    mod, rest = line.split(":", 1)
    def norm(p):
        p = p.strip()
        for ext in (".zst", ".xz", ".gz"):
            if p.endswith(ext):
                p = p[: -len(ext)]
        return p
    m = norm(mod)
    name = os.path.basename(m)[:-3].replace("-", "_")
    paths[name] = os.path.join(moddir, m)
    deps[name] = [os.path.basename(norm(d))[:-3].replace("-", "_") for d in rest.split()]
order = []
def visit(n):
    if n in order:
        return
    for d in deps.get(n, []):
        visit(d)
    order.append(n)
for o in objs:
    if o not in paths:
        sys.exit(f"target module {o} not found among the shipped modules")
    visit(o)
for n in order:
    print(n, paths[n])
PY
MODS=$(cut -d' ' -f1 "$TMP/mods.list" | paste -sd' ' -)
TARGETS=$(cut -d: -f1 "$OUT/functions.txt" | sort -u | paste -sd' ' -)

# Reproducers of the included fixes (resolved.json: [id, path] pairs), only
# regular files inside the catalog.
CATALOG_REAL=$(realpath "$CATALOG")
python3 -I -c '
import json, re, sys
for cve, path in json.load(open(sys.argv[1])).get("reproducers", []):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", cve):
        sys.exit(f"unexpected reproducer id {cve!r}")
    print(cve, path)
' "$OUT/resolved.json" > "$TMP/repro.raw"
: > "$TMP/repro.list"
while read -r id path; do
  real=$(realpath -e "$path" 2>/dev/null) || die "reproducer $path for $id not found"
  case "$real" in "$CATALOG_REAL"/*) ;; *) die "reproducer $path for $id is outside the catalog" ;; esac
  regular "$real"
  echo "$id $real" >> "$TMP/repro.list"
done < "$TMP/repro.raw"
REPROS=$(cut -d' ' -f1 "$TMP/repro.list" | paste -sd' ' -)

cat > "$TMP/init" <<EOF
#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
NAME=$NAME
PREV=$PREV
MODS="$MODS"
TARGETS="$TARGETS"
REPROS="$REPROS"
CYCLES=$CYCLES
EOF
cat >> "$TMP/init" <<'EOF'
say() { echo "HVPATCH:$*"; }
fail() { say "FAIL:$*"; dmesg | tail -n 60; poweroff -f; sleep 10; }
wait_transition() {
  i=0
  while [ "$(cat /sys/kernel/livepatch/$1/transition 2>/dev/null)" = 1 ]; do
    i=$((i + 1)); [ $i -ge 600 ] && fail "transition of $1 did not finish within 120 s"
    sleep 0.2
  done
}
wait_gone() {
  i=0
  while [ -d /sys/kernel/livepatch/$1 ]; do
    i=$((i + 1)); [ $i -ge 600 ] && fail "$1 did not leave /sys/kernel/livepatch"
    sleep 0.2
  done
}
load_mods() { for m in $MODS; do insmod "/mods/$m.ko" || fail "insmod $m"; done; }
unload_mods() {
  r=""; for m in $MODS; do r="$m $r"; done
  for m in $r; do rmmod "$m" 2>/dev/null || say "NOTE:could not unload $m"; done
}
repros() {
  for id in $REPROS; do
    sh "/repro/$id.sh" > /tmp/repro.out 2>&1; rc=$?
    say "REPRO:$id:$1:$rc"
  done
}
load_patch() {
  insmod /mod.ko || fail "insmod $NAME"
  [ -d "/sys/kernel/livepatch/$NAME" ] || fail "no /sys/kernel/livepatch/$NAME"
  wait_transition "$NAME"
  [ "$(cat /sys/kernel/livepatch/$NAME/enabled)" = 1 ] || fail "$NAME not enabled"
}
unload_patch() {
  echo 0 > "/sys/kernel/livepatch/$NAME/enabled" || fail "disabling $NAME"
  wait_gone "$NAME"
  rmmod "$NAME" || fail "rmmod $NAME"
}

say "NOTES:$(od -An -tx1 -v /sys/kernel/notes | tr -d ' \n')"
dmesg -c >/dev/null

# 1. unpatched
load_mods
repros unpatched
unload_mods

# 2. load (replacing the previous level, if given)
if [ -n "$PREV" ]; then
  insmod /prev.ko || fail "loading the previous level $PREV"
  wait_transition "$PREV"
  say "STEP:previous level active"
fi
start=$(cut -d' ' -f1 /proc/uptime)
load_patch
say "STEP:loaded, transition finished (started at ${start}s, now $(cut -d' ' -f1 /proc/uptime)s)"
say "REPLACE:$(cat /sys/kernel/livepatch/$NAME/replace 2>/dev/null)"
if [ -n "$PREV" ]; then
  wait_gone "$PREV"
  rmmod "$PREV" || fail "the replaced module $PREV cannot be unloaded"
  say "STEP:previous level replaced and unloaded"
fi

# 3. modules loaded after the livepatch get patched on load
load_mods
for o in $TARGETS; do
  say "PATCHED:$o:$(cat /sys/kernel/livepatch/$NAME/$o/patched 2>/dev/null)"
done
for d in /sys/kernel/livepatch/"$NAME"/*/*/; do
  f=${d%/}; obj=${f%/*}; obj=${obj##*/}
  say "FUNC:$obj:${f##*/}"
done
repros patched

# 4. patch/unpatch cycles under load
( while :; do ls -R /proc >/dev/null 2>&1; done ) &
L1=$!
( while :; do dd if=/dev/zero of=/dev/null bs=1M count=64 2>/dev/null; done ) &
L2=$!
c=0
while [ $c -lt "$CYCLES" ]; do
  unload_patch
  load_patch
  c=$((c + 1))
done
kill $L1 $L2 2>/dev/null
say "STEP:$CYCLES disable/unload/load cycles under load"

# 5. without the patch, then with it again
unload_patch
repros reverted
load_patch
repros patched_again
say "STEP:disabled, unloaded and loaded again"

if dmesg | grep -E 'Oops|BUG:|WARNING:|Call Trace|general protection fault|soft lockup|rcu_.*stall'; then
  fail "kernel log shows problems"
fi
say "TAINT:$(cat /proc/sys/kernel/tainted)"
say OK
poweroff -f
EOF

cp "$(command -v busybox)" "$TMP/busybox"
{
  echo "dir /dev 0755 0 0"
  echo "nod /dev/console 0600 0 0 c 5 1"
  echo "nod /dev/null 0666 0 0 c 1 3"
  echo "nod /dev/zero 0666 0 0 c 1 5"
  echo "dir /proc 0755 0 0"
  echo "dir /sys 0755 0 0"
  echo "dir /tmp 1777 0 0"
  echo "dir /bin 0755 0 0"
  echo "dir /mods 0755 0 0"
  echo "dir /repro 0755 0 0"
  echo "file /bin/busybox $TMP/busybox 0755 0 0"
  echo "file /init $TMP/init 0755 0 0"
  echo "file /mod.ko $KO 0644 0 0"
  [ -n "$PREV_KO" ] && echo "file /prev.ko $PREV_KO 0644 0 0"
  while read -r m path; do echo "file /mods/$m.ko $path 0644 0 0"; done < "$TMP/mods.list"
  while read -r id path; do echo "file /repro/$id.sh $path 0755 0 0"; done < "$TMP/repro.list"
} > "$TMP/initramfs.list"
python3 -I "$HERE/mkinitramfs.py" "$TMP/initramfs.list" | gzip -9 > "$TMP/initrd.gz"

ACCEL=tcg; CPU=max
if [ -w /dev/kvm ]; then ACCEL=kvm; CPU=host; fi
log "booting $KVER in QEMU ($ACCEL)"
LOG="$OUT/qemu.log"
timeout 1800 qemu-system-x86_64 -machine q35,accel="$ACCEL" -cpu "$CPU" -m 2048 -smp 4 \
  -nographic -no-reboot -kernel "$SHIPPED/vmlinuz" -initrd "$TMP/initrd.gz" \
  -append "console=ttyS0 rdinit=/init panic=-1 loglevel=4" > "$LOG" 2>&1 || true
tr -d '\r' < "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
grep '^HVPATCH:STEP:' "$LOG" | sed 's/^HVPATCH:STEP:/  /' >&2 || true
if ! grep -q '^HVPATCH:OK$' "$LOG"; then
  grep '^HVPATCH:FAIL:' "$LOG" >&2 || true
  die "QEMU stage failed, see $LOG"
fi

# The booted kernel is the one the manifest is bound to.
BOOT_ID=$(grep '^HVPATCH:NOTES:' "$LOG" | cut -d: -f3 | python3 -I -c '
import sys, struct
b = bytes.fromhex(sys.stdin.read().strip()); o = 0
while o + 12 <= len(b):
    n, d, t = struct.unpack_from("<III", b, o); name = b[o+12:o+12+n]
    desc = o + 12 + ((n + 3) & ~3)
    if t == 3 and name == b"GNU\0": print(b[desc:desc+d].hex()); break
    o = desc + ((d + 3) & ~3)
')
[ "$BOOT_ID" = "$(cat "$SHIPPED/build-id")" ] || die "booted kernel build-id $BOOT_ID != shipped $(cat "$SHIPPED/build-id")"

grep -qx 'HVPATCH:REPLACE:1' "$LOG" || die "the module is not an atomic-replace livepatch (replace != 1)"
for o in $TARGETS; do
  grep -qx "HVPATCH:PATCHED:$o:1" "$LOG" || die "object $o was not patched (module loaded after the livepatch)"
done

# The functions in sysfs are exactly those objtool reported.
grep '^HVPATCH:FUNC:' "$LOG" | cut -d: -f3- | sed 's/,[0-9]*$//' | sort -u > "$OUT/qemu-functions.txt"
sed 's/,[0-9]*$//' "$OUT/functions.txt" | sort -u | diff -u - "$OUT/qemu-functions.txt" >&2 \
  || die "patched functions in sysfs differ from functions.txt"

# Reproducers: exit 1 = vulnerable, 0 = fixed, 2 = cannot run here.
REPRO_RESULT=""
for id in $REPROS; do
  rc() { grep "^HVPATCH:REPRO:$id:$1:" "$LOG" | cut -d: -f5; }
  before=$(rc unpatched); after=$(rc patched); reverted=$(rc reverted); again=$(rc patched_again)
  if [ "$before" != 1 ]; then
    log "WARNING: reproducer $id did not show the bug before patching (exit $before): inconclusive here"
    REPRO_RESULT="$REPRO_RESULT $id:inconclusive"
    continue
  fi
  [ "$after" = 0 ] || die "reproducer $id still shows the bug with the livepatch (exit $after)"
  [ "$reverted" = 1 ] || die "reproducer $id does not show the bug after the livepatch was removed (exit $reverted)"
  [ "$again" = 0 ] || die "reproducer $id shows the bug after loading the livepatch again (exit $again)"
  log "reproducer $id: vulnerable -> fixed -> vulnerable -> fixed"
  REPRO_RESULT="$REPRO_RESULT $id:passed"
done

{
  echo "module=$MOD"
  echo "module_sha256=$(sha256sum "$KO" | cut -d' ' -f1)"
  echo "kernel=$KVER"
  echo "build_id=$BOOT_ID"
  echo "previous_level=${PREV:-none}"
  echo "accel=$ACCEL"
  echo "cycles=$CYCLES"
  echo "objects=${TARGETS}"
  echo "reproducers=${REPRO_RESULT# }"
  grep '^HVPATCH:TAINT:' "$LOG" | cut -d: -f3- | sed 's/^/taint=/'
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$OUT/qemu.ok"
log "QEMU stage passed: $OUT/qemu.ok"
