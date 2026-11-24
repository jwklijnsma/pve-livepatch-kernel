# Architecture

## Components

| Component | Runs on | Does |
| --- | --- | --- |
| `catalog/` | Git | Reviewed CVE entries: upstream commit, class, patch, functions |
| `builder/` + `hvpatch-tool` | Build host (container) | Source, config/toolchain gate, `klp-build`, Gate A, signing, manifest |
| Static repository | Any HTTPS server or object store | Serves modules and signed manifests |
| `hvpatch` | Every PVE node | Verifies and loads, watches the transition, reports |

Building, checking and signing happen only on the build side. Nothing is
ever compiled on a hypervisor.

## Build pipeline

For each supported kernel release (`builder/run.sh <kver> <level>`):

1. **Shipped artifacts** (`fetch-shipped.sh`): `proxmox-kernel-<kver>` and
   `proxmox-headers-<kver>`; config, System.map, Module.symvers, the
   in-tree modules (unpacked if compressed), vmlinuz and the vmlinux
   build-id.
2. **Source** (`fetch-source.sh`): `proxmox-kernel.git`, tag
   `proxmox/<pkgver>`, which must resolve to the commit reviewed in
   `builder/kernels.lock`; Proxmox's patch queue applied. A reused tree must
   still be based on that commit and clean.
3. **Config and toolchain gate:** the shipped config is copied into the
   tree, `make olddefconfig` must not change it (this pins gcc, binutils,
   pahole, rustc/LLVM), and `make kernelrelease` must equal `<kver>`.
4. **Catalog** (`hvpatch-tool resolve`): each patch is test-applied
   (applies, already contained, or a hard error), then all of them one
   after another in catalog order on a throwaway index. "Already
   contained" must agree with the entry's `fixed_in_pve`.
5. **Build:** `klp-build`, reusing the original build when its stamp
   (config, toolchain, tree, build identity) matches.
6. **Gate A** (`hvpatch-tool gate-a`) against the shipped artifacts:
   modinfo, modversion CRCs, every livepatch relocation symbol and patched
   function in the shipped System.map or module (a missing shipped module is
   an error), and the changed functions equal the reviewed catalog lists.
7. **Source bundle** for the GPL: patches, kernel tarball, config,
   toolchain, scripts.
8. **Sign** (`sign-module.sh`, separate container without tree, catalog or
   network): Debian's `sign-file`, signature verified against the
   certificate with openssl, manifest written.
9. **QEMU stage** (`qemu-test.sh`, separate container without keys or
   network): reproducers before/with/after/again, target modules loaded
   after the patch, `replace=1`, patch/unpatch cycles under load, kernel
   log, build-id. Writes `qemu.ok` with the module hash.
10. **Publish** (`publish.sh`) to `canary`; **promote** (`promote.sh`) what
    the ring below serves. Both sign the manifest and switch the ring
    symlink atomically; published files are never overwritten.

## Repository layout

```
v1/<kver>/<module>.ko                          signed module, never overwritten
v1/<kver>/<module>.source.tar.gz               corresponding source (GPL)
v1/<kver>/source/linux-<kver>-<sha>.tar.xz     kernel source, once per commit
v1/<kver>/<level>/                             build.log, functions, Gate A, QEMU log
v1/<kver>/<ring> -> <ring>.versions/<level>-<time>/
                    manifest.json, manifest.json.minisig
```

Agents read `v1/<kver>/<ring>/manifest.json`; the symlink makes manifest and
signature change together.

## Manifest

```json
{
  "format": 1,
  "kernel": "7.3.5-1-pve",
  "kernel_build_id": "<vmlinux GNU build-id>",
  "level": 3,
  "ring": "canary",
  "module": "klp_hvp_7_3_5_1_p3.ko",
  "module_name": "klp_hvp_7_3_5_1_p3",
  "sha256": "<signed .ko>",
  "built": "2026-11-23T09:00:00Z",
  "expires": "2026-12-23T09:00:00Z",
  "fixes": [{"id": "CVE-2026-XXXXX", "title": "…", "functions": ["vmlinux:tcp_…"]}],
  "not_covered": [{"id": "CVE-2026-YYYYY", "reason": "struct change", "fixed_in": "7.3.6-1-pve"}],
  "superseded_by_kernel": "7.3.6-1-pve",
  "builder_image": "sha256:…",
  "catalog_commit": "…"
}
```

Unknown fields are rejected. The signature covers the exact bytes.

**Why the build-id:** a kernel release string like `7.3.5-1-pve` can in
principle be rebuilt with different contents. The vmlinux GNU build-id,
exposed by the running kernel in `/sys/kernel/notes`, identifies the binary
itself.

## Agent rules

- **Anti-rollback:** the highest level ever accepted per kernel is persisted
  and survives `revert`. A lower level is never applied, not even if it is
  validly signed.
- **Rollback means a new level.** If level N is bad, maintainers publish N+1
  with the content of N−1. Locally, `revert` disables the patch and holds.
- **Taint:** after loading, new taint flags fail the post-checks, except
  those the livepatch module itself carries (`/sys/module/<m>/taint`:
  `O`, `E`, `K`). On a host without ZFS, the module's own `O` is the first
  out-of-tree taint and is expected.
- **Hold:** `revert` puts the kernel on hold. The timer and the boot unit
  then do nothing, without contacting the repository. An explicit `apply`
  always evaluates the repository; the hold ends when it loads a level.
- **Expiry:** an expired manifest is never applied fresh. After a reboot into
  the same kernel, the previously active module is reloaded even if its
  manifest expired meanwhile (`allow_expired_on_boot`), because running
  without it is not safer. `status` reports the expiry either way.
- **Never `force`.** A stalled transition is reversed (`enabled=0`). If the
  reversal also stalls, the agent stops, lists the blocking tasks and leaves
  the node to the operator.
- **Never worse than before.** If post-checks fail after a completed
  transition (missing function in sysfs, new taint bits other than those
  the module carries itself, kernel BUG/Oops/WARNING/lockup/RCU stall,
  failing hook), the previous level is loaded again from the local cache.
  That is an atomic replace of the failed one, so the node has a livepatch
  throughout. Without a previous level the failed one is disabled.
- **Kernel log.** Only records the kernel itself logged (facility 0) at
  warning or worse count, and only if the message starts with a known
  marker. A crashing user process ("traps: … general protection fault",
  info level) or a tenant naming its process "BUG:" does not back a patch
  out.
- **Quarantine.** A load is recorded before it starts. A level that fails,
  or whose load was interrupted by a crash, reboot or killed agent, is
  quarantined by module hash: the timer and the boot reload skip it (the
  boot reload falls back to the highest cached level below it). An
  explicit `apply` retries it. A run interrupted after a completed
  transition is recognised and recorded as active.
- **Cluster.** In a Proxmox VE cluster, a lock directory in pmxcfs
  (`/etc/pve/priv/lock/hvpatch-load`) lets one node load at a time, even if
  timers fire together. Without quorum nothing is loaded.
- **Timer policy.** `delay_hours` (delayed channel) and `pin_level` only
  hold back the timer; an operator's `apply` is not affected.
- **Tracing.** kprobes and BPF programs on a function the patch replaces
  are reported (or refused with `refuse_on_trace_conflict`).
- **Hooks** run like run-parts, with a timeout, only if owned by root and
  not writable by others, with `HVPATCH_MODE` = apply, boot or restore.
- **One owner.** Atomic replace disables all other livepatches. A foreign
  livepatch blocks `apply` unless `--replace-foreign` is given.
- **Forced leftovers.** A livepatch module that is loaded, referenced and
  missing from `/sys/kernel/livepatch` is what a forced transition leaves
  behind. The agent refuses to load anything more.
- **Blocking tasks** are found per thread (`/proc/<pid>/task/<tid>/patch_state`).
  `/proc/<pid>/patch_state` only shows the thread group leader and misses
  QEMU's vCPU and vhost threads.

## State and files

| Path | Content |
| --- | --- |
| `/etc/hvpatch/hvpatch.toml` | configuration; created on first install, never touched by upgrades |
| `/etc/hvpatch/trusted.d/*.pub` | trusted manifest keys |
| `/etc/hvpatch/hooks.d/*` | post-transition hooks |
| `/var/lib/hvpatch/state.json` | per kernel: highest accepted, desired level, hold, phase, last error |
| `/var/lib/hvpatch/cache/<kver>/<level>/` | module, manifest and signature for boot and restore (three levels kept) |
| `/run/hvpatch/effective_version`, `fixed_cves` | effective kernel version and CVEs fixed live, for scanners |
| `/var/lib/prometheus/node-exporter/hvpatch.prom` | metrics |

## Units

- `hvpatch-boot.service`: `hvpatch boot` before `pve-guests.service`.
  It reloads the cached level for the running kernel, without network.
- `hvpatch-auto.timer`: `hvpatch apply --timer` hourly. It is off by default;
  turn it on with `hvpatch auto enable`.
