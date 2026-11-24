# The 7.0 kernel series (experimental)

Proxmox VE 9's default kernel series, 7.0.x, is built from `pve-kernel.git`:
the Ubuntu kernel as a submodule plus Proxmox's `patches/kernel/`. The
opt-in 7.3 series comes from `proxmox-kernel.git` and is supported fully.
7.0 support is **experimental**: one release (7.0.14-30-pve) has been
built, tested and run on a test cluster (below). Please report results
from other hardware.

## What is different

The shipped 7.0 kernels are livepatch-capable (`CONFIG_LIVEPATCH=y`,
`CONFIG_KLP_BUILD=y`) and use the same toolchain as 7.3 (gcc 14.2.0-19,
binutils 2.44, pahole 1.30, rustc 1.94.1 / LLVM 21, bindgen 0.71.1; read from
`proxmox-headers-7.0.14-30-pve`), so the same builder image works.

Building livepatches needs `objtool klp` (diff, checksum, post-link), which
requires objtool built with libxxhash. In the 7.0 tree that does not
compile: the Ubuntu base (since Proxmox 7.0.14-25) carries objtool's
livepatch code backported from 7.2/7.3, but not some helpers it uses.
Proxmox therefore builds objtool with `HAVE_XXHASH=n`
([pve-kernel commit a3e1a30d](https://git.proxmox.com/?p=pve-kernel.git;a=commit;h=a3e1a30d4681bc18ca6b8b6bea686b4b77717edd));
the kernel itself is unaffected, only `klp-build` needs those subcommands.

hvpatch adds the six missing upstream commits (`builder/kernel-7.0/objtool`,
see the README there) on top of the Proxmox tree, as a separate commit in
the build tree and in the GPL source bundle. On Proxmox 7.0.14-30 (Ubuntu
kernel commit `d28b7c09`) they apply without fuzz, and objtool then builds
against libxxhash on Debian trixie and offers `objtool klp checksum`, `diff`
and `post-link`. The Ubuntu `klp-build` also uses `$OBJTOOL` without
setting it; `build.sh` exports it.

klp-build compiles the original and the patched kernel itself with that
objtool. The livepatch does not depend on the shipped kernel having been
built with the same objtool binary: Gate A (symbols, positions, CRCs) and
the QEMU stage (booting the shipped kernel) check the result against what
Proxmox shipped, as for 7.3.

## Tested

7.0.14-30-pve, level 1 with the three catalog entries (patched functions
`vmlinux:gup_fast_fallback`, `overlay:ovl_fileattr_set`):

- **Build:** klp-build, Gate A against the shipped `System.map`,
  `Module.symvers` and modules, signing, QEMU stage (shipped kernel,
  5 patch/unpatch cycles under load, kernel log clean). The first build of
  the release took about 3 hours on 4 cores; later levels reuse the
  original build (about 35 minutes).
- **Three-node PVE 9.2 cluster**, two guests per node with CPU, memory,
  disk and network load:
  - `hvpatch apply` under load: about 13 s per node (fetch, signature
    checks, post-check); the transition itself 2–3 s. Guests pinged every
    100 ms: no loss, longest gap 0.11 s. No warnings in the kernel log.
  - `revert` (3.5 s), the timer skips a node on hold, `apply` lifts it.
  - Reboot with the repository unreachable: the boot unit reloaded the
    cached level 7 s after boot.
  - `apply` on two nodes at once: the second waited for the cluster lock.
  - Revocation: the active level was taken out of service on the next run;
    with the list withheld from the repository, nothing new was loaded.

## Source preparation

`fetch-source.sh` does what pve-kernel's Makefile does for its build
directory:

1. `pve-kernel.git` at the commit pinned in `builder/kernels.lock`; its
   Makefile must name exactly the release (`KERNEL_MAJ.MIN.PATCHLEVEL-KREL-pve`).
2. The Ubuntu kernel at the submodule commit of that pve-kernel commit,
   from `mirror_ubuntu-kernels.git`.
3. `EXTRAVERSION=-<KREL>-pve`, `debian/` and `debian.master/` removed,
   `patches/kernel/*.patch` applied with `patch --batch -p1`.
4. Commit; then the objtool backports, commit.

For an unlisted 7.0 release the build stops and suggests the pve-kernel
commit (tag `proxmox-kernel-<release>` or the changelog bump). Review it and
add `<release> <pve-kernel commit>` to `builder/kernels.lock`.

## Catalog entries

Fixes for 7.0 often need a backport: the Ubuntu tree differs from upstream
stable. Add it to the entry as a patch for the package version, e.g.
`patches: { default: 0001-fix.patch, 7.0.14-30: 0001-fix-7.0.patch }`; the
`default` patch is used where no specific one exists, and `resolve` tests
every patch against the tree before the build.

## Upstream

The proper fix is in the 7.0 tree: backport the helpers (or build objtool
with xxhash once they are there). If you are in touch with Proxmox or the
Ubuntu kernel team, that would let everyone build livepatches for 7.0
without carrying these patches.
