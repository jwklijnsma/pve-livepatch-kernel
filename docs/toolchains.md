# Toolchains per kernel release

A livepatch module must be built with exactly the compiler and tools the
shipped kernel was built with. The kernel config records them, and
`build.sh` refuses to build when `make olddefconfig` changes any of these
values:

| Config symbol | Tool |
| --- | --- |
| `CONFIG_CC_VERSION_TEXT`, `CONFIG_GCC_VERSION` | gcc |
| `CONFIG_AS_VERSION`, `CONFIG_LD_VERSION` | binutils |
| `CONFIG_PAHOLE_VERSION` | dwarves (pahole) |
| `CONFIG_RUSTC_VERSION`, `CONFIG_RUSTC_LLVM_VERSION` | rustc and its LLVM |
| `CONFIG_BINDGEN_VERSION_TEXT` | bindgen |

Read them from the shipped config:

```bash
grep -E 'CC_VERSION_TEXT|_VERSION=|BINDGEN_VERSION_TEXT' /boot/config-$(uname -r)
```

## Known releases

| Kernel | gcc | binutils | pahole | rustc / LLVM | `SNAPSHOT` | `BACKPORTS_SNAPSHOT` |
| --- | --- | --- | --- | --- | --- | --- |
| 7.3.5-1-pve | 14.2.0-19 | 2.44 | 1.30 | 1.94.1 / 21 | `20261120T000000Z` | `20260915T000000Z` |

trixie-backports carried rustc 1.94.1 between the snapshots `20260515` and
`20260915`. Debian main and security stay on the newer `SNAPSHOT`; an older
snapshot for everything conflicts with the security updates already in the
base image.

## Adding a release

1. Read the values above from the new kernel's shipped config.
2. Find snapshot dates where trixie (gcc, binutils, dwarves) and
   trixie-backports (rustc, bindgen) carry those versions
   (`https://snapshot.debian.org/package/<name>/`).
3. Build the image with `--build-arg SNAPSHOT=… --build-arg BACKPORTS_SNAPSHOT=…`
   and tag it per toolchain, e.g. `pve-klp-builder:rust-1.94`.
4. Add a row to the table.
