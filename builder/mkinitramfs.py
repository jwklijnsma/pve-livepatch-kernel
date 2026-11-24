#!/usr/bin/python3 -I
"""Write a newc cpio archive (initramfs) from a gen_init_cpio style list.

usage: mkinitramfs.py <list> > initramfs.cpio

Replaces the kernel tree's usr/gen_init_cpio, so that the QEMU stage runs
no code from the tree. Supported lines:

    dir  <path> <mode> <uid> <gid>
    nod  <path> <mode> <uid> <gid> c|b <major> <minor>
    file <path> <source> <mode> <uid> <gid>

Device nodes are written into the archive directly, so no privileges are
needed.
"""
import os
import stat
import sys

out = sys.stdout.buffer
ino = 721


def pad(n):
    return b"\0" * ((4 - n % 4) % 4)


def entry(name, mode, uid=0, gid=0, nlink=1, data=b"", rmaj=0, rmin=0):
    global ino
    ino += 1
    name_b = name.lstrip("/").encode() + b"\0"
    fields = [ino, mode, uid, gid, nlink, 0, len(data), 0, 0, rmaj, rmin, len(name_b), 0]
    hdr = b"070701" + b"".join(b"%08X" % f for f in fields)
    out.write(hdr + name_b + pad(len(hdr) + len(name_b)))
    out.write(data + pad(len(data)))


for lineno, line in enumerate(open(sys.argv[1]), 1):
    f = line.split()
    if not f or f[0].startswith("#"):
        continue
    kind = f[0]
    if kind == "dir" and len(f) == 5:
        entry(f[1], stat.S_IFDIR | int(f[2], 8), int(f[3]), int(f[4]), nlink=2)
    elif kind == "nod" and len(f) == 8 and f[5] in ("c", "b"):
        t = stat.S_IFCHR if f[5] == "c" else stat.S_IFBLK
        entry(f[1], t | int(f[2], 8), int(f[3]), int(f[4]), rmaj=int(f[6]), rmin=int(f[7]))
    elif kind == "file" and len(f) == 6:
        src = f[2]
        st = os.lstat(src)
        if not stat.S_ISREG(st.st_mode):
            sys.exit(f"line {lineno}: {src} is not a regular file")
        entry(f[1], stat.S_IFREG | int(f[3], 8), int(f[4]), int(f[5]), data=open(src, "rb").read())
    else:
        sys.exit(f"line {lineno}: cannot parse {line.strip()!r}")
entry("TRAILER!!!", 0)
