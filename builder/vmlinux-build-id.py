#!/usr/bin/python3 -I
"""Print the GNU build-id of the vmlinux inside a bzImage (vmlinuz).

usage: vmlinux-build-id.py <vmlinuz> [<vmlinux-out>]

Replaces the kernel tree's scripts/extract-vmlinux, so that fetching the
shipped artifacts runs no code from the tree. Like extract-vmlinux it looks
for the magic of each supported compressor, decompresses from there and
keeps the first result that is an ELF file; the build-id is read from its
.notes section.
"""
import shutil
import struct
import subprocess
import sys

COMPRESSORS = [
    (b"\x28\xb5\x2f\xfd", ["zstd", "-dc"]),
    (b"\x1f\x8b\x08", ["gzip", "-dc"]),
    (b"\xfd7zXZ\x00", ["xz", "-dc"]),
    (b"\x02\x21\x4c\x18", ["lz4", "-dc"]),
    (b"BZh", ["bzip2", "-dc"]),
    (b"\x5d\x00\x00\x00", ["xz", "--format=lzma", "-dc"]),
]


def build_id(elf: bytes):
    if elf[:4] != b"\x7fELF" or elf[4] != 2 or elf[5] != 1:
        return None  # only little-endian ELF64 (x86_64)
    shoff, = struct.unpack_from("<Q", elf, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", elf, 0x3A)
    for i in range(shnum):
        sh = shoff + i * shentsize
        sh_type, = struct.unpack_from("<I", elf, sh + 4)
        if sh_type != 7:  # SHT_NOTE
            continue
        off, size = struct.unpack_from("<QQ", elf, sh + 0x18)
        o, end = off, off + size
        while o + 12 <= end:
            namesz, descsz, ntype = struct.unpack_from("<III", elf, o)
            name = elf[o + 12:o + 12 + namesz]
            desc = o + 12 + ((namesz + 3) & ~3)
            if ntype == 3 and name == b"GNU\x00":
                return elf[desc:desc + descsz].hex()
            o = desc + ((descsz + 3) & ~3)
    return None


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__.strip().splitlines()[2])
    image = open(sys.argv[1], "rb").read()
    for magic, cmd in COMPRESSORS:
        if shutil.which(cmd[0]) is None:
            continue
        start = 0
        while (pos := image.find(magic, start)) >= 0:
            start = pos + 1
            p = subprocess.run(cmd, input=image[pos:], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            out = p.stdout
            if out[:4] != b"\x7fELF":
                continue
            bid = build_id(out)
            if bid is None:
                continue
            if len(sys.argv) == 3:
                with open(sys.argv[2], "wb") as f:
                    f.write(out)
            print(bid)
            return
    sys.exit(f"{sys.argv[1]}: no compressed vmlinux with a build-id found")


main()
