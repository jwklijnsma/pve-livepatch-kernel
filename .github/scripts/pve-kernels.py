#!/usr/bin/env python3
"""List the newest Proxmox VE kernel releases from Proxmox's package repository.

usage: pve-kernels.py [--dist trixie] [--components "pve-no-subscription pve-test"]
                      [--series "7.0 7.3"] [--keep 2] [--packages FILE ...]

Prints one kernel release per line (e.g. 7.3.5-1-pve), newest first within
each series, at most --keep per series. Only used to find out which kernels
to build: what is built is pinned by builder/kernels.lock and verified by
the builder (apt signatures, locked source commit, config gate).
"""
import argparse
import gzip
import re
import sys
import urllib.request

PKG = re.compile(r"^Package: proxmox-kernel-(\d+\.\d+\.\d+-\d+-pve)(?:-signed)?$", re.M)


def key(kver):
    nums = re.findall(r"\d+", kver)
    return tuple(int(n) for n in nums)


def series(kver):
    major, minor = kver.split(".")[:2]
    return f"{major}.{minor}"


def fetch(dist, component):
    url = f"https://download.proxmox.com/debian/pve/dists/{dist}/{component}/binary-amd64/Packages.gz"
    req = urllib.request.Request(url, headers={"User-Agent": "pve-livepatch-kernel-ci"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return gzip.decompress(r.read()).decode("utf-8", "replace")


def select(texts, wanted_series, keep):
    found = set()
    for t in texts:
        found.update(PKG.findall(t))
    out = []
    for s in wanted_series:
        ks = sorted((k for k in found if series(k) == s), key=key, reverse=True)
        out.extend(ks[:keep])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="trixie")
    ap.add_argument("--components", default="pve-no-subscription pve-test")
    ap.add_argument("--series", default="7.3 7.0")
    ap.add_argument("--keep", type=int, default=2)
    ap.add_argument("--packages", nargs="*", help="read local Packages files instead (tests)")
    a = ap.parse_args()
    if a.packages:
        texts = [open(p, encoding="utf-8").read() for p in a.packages]
    else:
        texts = []
        for c in a.components.split():
            try:
                texts.append(fetch(a.dist, c))
            except Exception as e:  # one missing component must not stop the rest
                print(f"warning: {c}: {e}", file=sys.stderr)
        if not texts:
            sys.exit("no package lists could be read")
    for k in select(texts, a.series.split(), a.keep):
        print(k)


if __name__ == "__main__":
    main()
