#!/usr/bin/env bash
# QEMU stage: boot the unmodified shipped kernel, then load the livepatch,
# wait for the transition, compare the patched functions, (replace the
# previous level,) disable, unload and load again. On success writes
# <workdir>/out/qemu.ok, which sign-manifest.sh requires.
#
# usage: qemu-test.sh <kver> <workdir> [previous-level.ko]
#
# Uses KVM when /dev/kvm is writable (podman run --device /dev/kvm),
# otherwise TCG (slower, still fine).
source "$(dirname "$0")/lib.sh"
KVER=${1:?kver}; WORK=${2:?workdir}; PREV_KO=${3:-}
require qemu-system-x86_64 busybox gcc python3 modinfo sha256sum timeout
OUT="$WORK/out"; SHIPPED="$WORK/shipped"; TREE="$WORK/src"
MOD=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["module"])' "$OUT/manifest.json")
KO="$OUT/$MOD"
NAME=$(modinfo -F name "$KO")
PREV=""
[ -n "$PREV_KO" ] && PREV=$(modinfo -F name "$PREV_KO")
for f in "$KO" "$SHIPPED/vmlinuz" "$SHIPPED/build-id" "$OUT/functions.txt" "$TREE/usr/gen_init_cpio.c"; do
  [ -e "$f" ] || die "missing $f (run build.sh first)"
done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/init" <<EOF
#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
NAME=$NAME
PREV=$PREV
EOF
cat >> "$TMP/init" <<'EOF'
say() { echo "PVEKLP:$*"; }
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

say "NOTES:$(od -An -tx1 -v /sys/kernel/notes | tr -d ' \n')"
dmesg -c >/dev/null

if [ -n "$PREV" ]; then
  insmod /prev.ko || fail "loading the previous level $PREV"
  wait_transition "$PREV"
  say "STEP:previous level active"
fi

start=$(cut -d' ' -f1 /proc/uptime)
insmod /mod.ko || fail "insmod $NAME"
[ -d "/sys/kernel/livepatch/$NAME" ] || fail "no /sys/kernel/livepatch/$NAME"
wait_transition "$NAME"
[ "$(cat /sys/kernel/livepatch/$NAME/enabled)" = 1 ] || fail "$NAME not enabled"
say "STEP:loaded, transition finished (started at ${start}s, now $(cut -d' ' -f1 /proc/uptime)s)"
for d in /sys/kernel/livepatch/"$NAME"/*/*/; do
  f=${d%/}; obj=${f%/*}; obj=${obj##*/}
  say "FUNC:$obj:${f##*/}"
done

if [ -n "$PREV" ]; then
  wait_gone "$PREV"
  rmmod "$PREV" || fail "the replaced module $PREV cannot be unloaded"
  say "STEP:previous level replaced and unloaded"
fi

echo 0 > "/sys/kernel/livepatch/$NAME/enabled" || fail "disabling $NAME"
wait_gone "$NAME"
rmmod "$NAME" || fail "rmmod $NAME"
say "STEP:disabled and unloaded"

insmod /mod.ko || fail "loading $NAME again"
wait_transition "$NAME"
[ "$(cat /sys/kernel/livepatch/$NAME/enabled)" = 1 ] || fail "$NAME not enabled after reload"
say "STEP:loaded again"

if dmesg | grep -E 'Oops|BUG:|WARNING:|Call Trace|general protection fault'; then
  fail "kernel log shows problems"
fi
say "TAINT:$(cat /proc/sys/kernel/tainted)"
say OK
poweroff -f
EOF

cp "$(command -v busybox)" "$TMP/busybox"
cat > "$TMP/initramfs.list" <<EOF
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
dir /proc 0755 0 0
dir /sys 0755 0 0
dir /tmp 1777 0 0
dir /bin 0755 0 0
file /bin/busybox $TMP/busybox 0755 0 0
file /init $TMP/init 0755 0 0
file /mod.ko $KO 0644 0 0
EOF
[ -n "$PREV_KO" ] && echo "file /prev.ko $PREV_KO 0644 0 0" >> "$TMP/initramfs.list"
gcc -O2 -o "$TMP/gen_init_cpio" "$TREE/usr/gen_init_cpio.c"
"$TMP/gen_init_cpio" "$TMP/initramfs.list" | gzip -9 > "$TMP/initrd.gz"

ACCEL=tcg; CPU=max
if [ -w /dev/kvm ]; then ACCEL=kvm; CPU=host; fi
log "booting $KVER in QEMU ($ACCEL)"
LOG="$OUT/qemu.log"
timeout 900 qemu-system-x86_64 -machine q35,accel="$ACCEL" -cpu "$CPU" -m 2048 -smp 4 \
  -nographic -no-reboot -kernel "$SHIPPED/vmlinuz" -initrd "$TMP/initrd.gz" \
  -append "console=ttyS0 rdinit=/init panic=-1 loglevel=4" > "$LOG" 2>&1 || true
tr -d '\r' < "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
grep '^PVEKLP:STEP:' "$LOG" | sed 's/^PVEKLP:STEP:/  /' >&2 || true
if ! grep -q '^PVEKLP:OK$' "$LOG"; then
  grep '^PVEKLP:FAIL:' "$LOG" >&2 || true
  die "QEMU stage failed, see $LOG"
fi

# The booted kernel is the one the manifest is bound to.
BOOT_ID=$(grep '^PVEKLP:NOTES:' "$LOG" | cut -d: -f3 | python3 -c '
import sys, struct
b = bytes.fromhex(sys.stdin.read().strip()); o = 0
while o + 12 <= len(b):
    n, d, t = struct.unpack_from("<III", b, o); name = b[o+12:o+12+n]
    desc = o + 12 + ((n + 3) & ~3)
    if t == 3 and name == b"GNU\0": print(b[desc:desc+d].hex()); break
    o = desc + ((d + 3) & ~3)
')
[ "$BOOT_ID" = "$(cat "$SHIPPED/build-id")" ] || die "booted kernel build-id $BOOT_ID != shipped $(cat "$SHIPPED/build-id")"

# The functions in sysfs are exactly those objtool reported.
grep '^PVEKLP:FUNC:' "$LOG" | cut -d: -f3- | sed 's/,[0-9]*$//' | sort -u > "$OUT/qemu-functions.txt"
sed 's/,[0-9]*$//' "$OUT/functions.txt" | sort -u | diff -u - "$OUT/qemu-functions.txt" >&2 \
  || die "patched functions in sysfs differ from functions.txt"

{
  echo "module=$MOD"
  echo "module_sha256=$(sha256sum "$KO" | cut -d' ' -f1)"
  echo "kernel=$KVER"
  echo "build_id=$BOOT_ID"
  echo "previous_level=${PREV:-none}"
  echo "accel=$ACCEL"
  echo "$(grep '^PVEKLP:TAINT:' "$LOG" | cut -d: -f2- | sed 's/^/taint=/')"
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$OUT/qemu.ok"
log "QEMU stage passed: $OUT/qemu.ok"
