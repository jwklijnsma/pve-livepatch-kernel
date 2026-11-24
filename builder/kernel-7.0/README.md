# Build fixes for the Proxmox VE 7.0 kernel series (experimental)

The 7.0 series (`pve-kernel.git`, Ubuntu-based) carries objtool's livepatch
support backported from 7.2/7.3, but without some helpers it depends on.
objtool therefore does not build with libxxhash, and Proxmox builds it with
`HAVE_XXHASH=n` (pve-kernel commit `a3e1a30d`, "d/rules: fix objtool build
failure with libxxhash-dev installed"). The shipped kernel is unaffected;
only `klp-build` needs the `objtool klp` subcommands.

`objtool/` holds the missing upstream commits, applied in this order on top
of the Proxmox tree by `fetch-source.sh` (as a separate commit, so the
change is visible in the build tree and the source bundle):

| # | Upstream commit | Subject |
| --- | --- | --- |
| 1 | `8eebd5731133` | objtool: Add is_alias_sym() helper |
| 2 | `6282e9f46b4f` | objtool: Add is_cold_func() helper |
| 3 | `a5b661233262` | objtool: Consolidate file decoding into decode_file() |
| 4 | `3ee67629b2b7` | objtool: Add insn_sym() helper |
| 5 | `479ac5260e7e` | objtool/klp: Fix XXH3 state memory leak |
| 6 | `873a2208ea31` | objtool/klp: Calculate object checksums |

They only touch `tools/objtool`. klp-build compiles the original and the
patched kernel itself with the same objtool, so the livepatch does not
depend on the shipped kernel having been built with it; Gate A and the QEMU
stage check the result against the shipped kernel as for every other
series.

The Ubuntu `klp-build` also uses `$OBJTOOL` without defining it; `build.sh`
exports it.

Once a 7.0 tree already has these helpers (`is_alias_sym()` in
`tools/objtool/include/objtool/elf.h`), `fetch-source.sh` skips the
patches. If they are needed and do not apply, the build stops.

See [docs/kernel-7.0.md](../../docs/kernel-7.0.md).
