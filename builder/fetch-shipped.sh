#!/usr/bin/env bash
# Download and unpack the kernel and headers packages Proxmox shipped, so the
# build can be checked against them (config, System.map, Module.symvers,
# in-tree modules, vmlinux build-id).
#
# usage: fetch-shipped.sh <kver> <outdir>
source "$(dirname "$0")/lib.sh"
KVER=${1:?kver}; OUT=${2:?outdir}
require apt-get dpkg-deb readelf
mkdir -p "$OUT/debs" "$OUT/root"

# The Proxmox repository must be configured in the container (pve-test or
# pve-no-subscription for opt-in kernels), with its signing key.
# M0: confirm the exact package names for the 7.3 series.
( cd "$OUT/debs" && apt-get download "proxmox-kernel-${KVER}-signed" "proxmox-headers-${KVER}" ) \
  || ( cd "$OUT/debs" && apt-get download "proxmox-kernel-${KVER}" "proxmox-headers-${KVER}" )
for d in "$OUT"/debs/*.deb; do dpkg-deb -x "$d" "$OUT/root"; done

R="$OUT/root"
cp "$R/boot/config-$KVER"       "$OUT/config"
cp "$R/boot/System.map-$KVER"   "$OUT/System.map"
cp "$R/usr/src/linux-headers-$KVER/Module.symvers" "$OUT/Module.symvers"
ln -sfn "$R/lib/modules/$KVER" "$OUT/modules"

# vmlinux build-id: the x86 bzImage payload is a stripped ELF that keeps
# .notes. Cross-checked against /sys/kernel/notes in the QEMU stage.
if [ -x "${TREE:-}/scripts/extract-vmlinux" ]; then
  "$TREE/scripts/extract-vmlinux" "$R/boot/vmlinuz-$KVER" > "$OUT/vmlinux.shipped"
  readelf -n "$OUT/vmlinux.shipped" | awk '/Build ID/ {print $3}' > "$OUT/build-id"
fi
log "shipped artifacts for $KVER in $OUT"
