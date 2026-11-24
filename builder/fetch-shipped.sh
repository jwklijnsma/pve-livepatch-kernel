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

# The builder image configures the Proxmox repository (pve-no-subscription;
# opt-in kernels are also in pve-test) with a low pin priority.
apt-get update -qq
( cd "$OUT/debs" && apt-get download "proxmox-kernel-${KVER}-signed" "proxmox-headers-${KVER}" ) \
  || ( cd "$OUT/debs" && apt-get download "proxmox-kernel-${KVER}" "proxmox-headers-${KVER}" )
for d in "$OUT"/debs/*.deb; do dpkg-deb -x "$d" "$OUT/root"; done

R="$OUT/root"
cp "$R/boot/config-$KVER"       "$OUT/config"
cp "$R/boot/System.map-$KVER"   "$OUT/System.map"
cp "$R/usr/src/linux-headers-$KVER/Module.symvers" "$OUT/Module.symvers"
if [ -d "$R/usr/lib/modules/$KVER" ]; then
  ln -sfn "$R/usr/lib/modules/$KVER" "$OUT/modules"
else
  ln -sfn "$R/lib/modules/$KVER" "$OUT/modules"
fi
cp "$R/boot/vmlinuz-$KVER" "$OUT/vmlinuz"
# Gate A and the QEMU stage read the modules as ELF: unpack compressed ones.
find -L "$OUT/modules/" -name '*.ko.zst' -exec zstd -qd --rm {} \;
find -L "$OUT/modules/" -name '*.ko.xz' -exec xz -d {} \;
find -L "$OUT/modules/" -name '*.ko.gz' -exec gzip -d {} \;

# vmlinux build-id: the x86 bzImage payload is a stripped ELF that keeps
# .notes. Cross-checked against /sys/kernel/notes in the QEMU stage.
[ -x "${TREE:-}/scripts/extract-vmlinux" ] || die "TREE must point to the kernel source (scripts/extract-vmlinux)"
"$TREE/scripts/extract-vmlinux" "$R/boot/vmlinuz-$KVER" > "$OUT/vmlinux.shipped"
readelf -n "$OUT/vmlinux.shipped" | awk '/Build ID/ {print $3}' > "$OUT/build-id"
[ -s "$OUT/build-id" ] || die "could not read the vmlinux build-id from the shipped vmlinuz"
log "shipped artifacts for $KVER in $OUT"
