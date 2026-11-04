#!/usr/bin/env bash
# Build pve-livepatch_<version>_all.deb into ./dist
# Usage: packaging/build-deb.sh [VERSION]   (default: SCRIPT_VERSION from the script)
set -Eeuo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PKG=pve-livepatch
VERSION=${1:-$(sed -n 's/^readonly SCRIPT_VERSION="\(.*\)"/\1/p' "$ROOT/pve-livepatch.sh")}
VERSION=${VERSION#v}
[[ $VERSION =~ ^[0-9][A-Za-z0-9.+~-]*$ ]] || { echo "invalid version: $VERSION" >&2; exit 1; }

STAGE=$(mktemp -d); chmod 755 "$STAGE"
trap 'rm -rf "$STAGE"' EXIT
OUT="${OUT_DIR:-$ROOT/dist}"
mkdir -p "$OUT"

# --- files
install -Dm755 "$ROOT/pve-livepatch.sh"  "$STAGE/usr/sbin/pve-livepatch"
sed -i "s/^readonly SCRIPT_VERSION=.*/readonly SCRIPT_VERSION=\"${VERSION}\"/" "$STAGE/usr/sbin/pve-livepatch"
install -Dm644 "$ROOT/README.md"         "$STAGE/usr/share/doc/$PKG/README.md"
install -Dm644 "$ROOT/LICENSE"           "$STAGE/usr/share/doc/$PKG/copyright"

# --- control
mkdir -p "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: admin
Priority: optional
Architecture: all
Maintainer: Jan Wiebe Klijnsma <janwiebek@gmail.com>
Depends: bash (>= 4.4), coreutils, kmod, sed, gawk | mawk, curl, ca-certificates
Recommends: mokutil
Suggests: ubuntu-pro-client
Installed-Size: $(du -sk "$STAGE/usr" | cut -f1)
Homepage: https://github.com/jwklijnsma/pve-livepatch-kernel
Description: live patch the running kernel without reboot (Proxmox VE / Ubuntu)
 GitHub Actions builds every live patch with the kernel's own klp-build and
 signs it; pve-livepatch only downloads it, checks the checksum, kernel
 version and signature, and loads it with insmod, without a reboot.
 Nothing is compiled or signed on the node.
 .
 "pve-livepatch auto enable" loads the live patch built for every new
 Proxmox kernel automatically; "pve-livepatch mok setup" enrolls the signing
 certificate once on Secure Boot hosts. On Ubuntu it can also enable
 Canonical Livepatch through Ubuntu Pro.
EOF

# --- on removal: stop the services pve-livepatch wrote (loaded patches stay loaded)
cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ]; then
    systemctl disable --now pve-livepatch-auto.timer >/dev/null 2>&1 || true
    systemctl disable pve-livepatch.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/pve-livepatch-auto.timer /etc/systemd/system/pve-livepatch-auto.service \
          /etc/systemd/system/pve-livepatch.service
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "$STAGE/DEBIAN/prerm"

# --- remove generated state on purge only (never touch it on upgrade)
cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/pve-livepatch/src /var/lib/pve-livepatch/ubuntu-src /var/lib/pve-livepatch/pve-kernel
fi
exit 0
EOF
chmod 755 "$STAGE/DEBIAN/postrm"

DEB="$OUT/${PKG}_${VERSION}_all.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB" >/dev/null
echo "$DEB"
