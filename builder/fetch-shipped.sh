#!/usr/bin/env bash
# Download and unpack the kernel and headers packages Proxmox shipped, so the
# build can be checked against them (config, System.map, Module.symvers,
# in-tree modules, vmlinux build-id).
#
# usage: fetch-shipped.sh <kver> <outdir>
#
# run.sh runs this in its own container before the build: the build
# container (kernel Makefiles, catalog patches) only gets the result
# read-only, so it cannot alter what the module is checked against. Runs no
# code from the kernel tree.
source "$(dirname "$0")/lib.sh"
KVER=${1:?kver}; OUT=${2:?outdir}
HERE=$(cd "$(dirname "$0")" && pwd)
require apt-get dpkg-deb python3 zstd xz
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
# 7.3 ships the modules in /usr/lib/modules, 7.0 in /lib/modules (where
# /usr/lib/modules/<kver> exists too, holding only the headers' build link).
# Take the directory that has the modules.
MODDIR=
for d in "$R/usr/lib/modules/$KVER" "$R/lib/modules/$KVER"; do
  [ -f "$d/modules.dep" ] && [ -d "$d/kernel" ] && { MODDIR=$d; break; }
done
[ -n "$MODDIR" ] || die "no module tree (modules.dep, kernel/) for $KVER in the packages"
ln -sfn "$MODDIR" "$OUT/modules"
cp "$R/boot/vmlinuz-$KVER" "$OUT/vmlinuz"
# Gate A and the QEMU stage read the modules as ELF: unpack compressed ones.
find -L "$OUT/modules/" -name '*.ko.zst' -exec zstd -qd --rm {} \;
find -L "$OUT/modules/" -name '*.ko.xz' -exec xz -d {} \;
find -L "$OUT/modules/" -name '*.ko.gz' -exec gzip -d {} \;

# vmlinux build-id: the x86 bzImage payload is a stripped ELF that keeps
# .notes. Cross-checked against /sys/kernel/notes in the QEMU stage.
python3 -I "$HERE/vmlinux-build-id.py" "$R/boot/vmlinuz-$KVER" "$OUT/vmlinux.shipped" > "$OUT/build-id" \
  || die "could not read the vmlinux build-id from the shipped vmlinuz"
grep -qxE '[0-9a-f]{40}' "$OUT/build-id" || die "unexpected build-id: $(cat "$OUT/build-id")"
log "shipped artifacts for $KVER in $OUT"
