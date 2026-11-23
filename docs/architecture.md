# Architecture

## Components

| Component | Runs on | Does |
| --- | --- | --- |
| `catalog/` | Git | Reviewed CVE entries: upstream commit, class, patch, functions |
| `builder/` + `pve-klp-tool` | Build host (container) | Source, config/toolchain gate, `klp-build`, Gate A, signing, manifest |
| Static repository | Any HTTPS server or object store | Serves modules and signed manifests |
| `pve-klp` | Every PVE node | Verifies and loads, watches the transition, reports |

Building, checking and signing happen only on the build side. Nothing is
ever compiled on a hypervisor.

## Build pipeline

For each supported kernel release (default: the newest three of the 7.3
series):

1. **Shipped artifacts.** Download `proxmox-kernel-<kver>` and
   `proxmox-headers-<kver>` and extract `config`, `System.map`,
   `Module.symvers`, the in-tree modules and the vmlinux build-id
   (`fetch-shipped.sh`).
2. **Source.** `proxmox-kernel.git`, tag `proxmox/<pkgver>`, with
   `debian/patches` applied (`fetch-source.sh`). The 7.3 series is not in
   `pve-kernel.git`.
3. **Config and toolchain gate.** Copy the shipped config into the tree, run
   `make olddefconfig`, and compare byte for byte with the shipped config
   (`pve-klp-tool config-check`). The config records the compiler, assembler,
   linker, pahole and rustc versions, so this also pins the toolchain. Any
   difference aborts the build. `make kernelrelease` must equal `<kver>`.
4. **Catalog.** `pve-klp-tool resolve` picks the entries the kernel still
   needs. Each patch is test-applied: applies → included; applies in reverse →
   already contained; neither → hard error (backport needed). Nothing is
   dropped silently.
5. **Build.** `scripts/livepatch/klp-build -T -o klp_pve_<tag>_p<N>.ko
   <patches…>`. The original build is reused with `--short-circuit=2`.
6. **Gate A** (`pve-klp-tool gate-a`) against the shipped artifacts:
   - `.modinfo`: `livepatch=Y`, vermagic release, module name;
   - modversion CRCs of all imported symbols against `Module.symvers`;
   - every livepatch relocation symbol `.klp.sym.<obj>.<sym>,<pos>` exists in
     the shipped `System.map` or the shipped module, and its position
     resolves (unique when 0);
   - every patched function from `objtool klp diff` exists under exactly
     that name;
   - the changed functions equal the union of the reviewed `functions` of
     the resolved catalog entries, in both directions.
7. **Sign module** with `scripts/sign-file`.
8. **Manifest** (`pve-klp-tool manifest`), unsigned until the QEMU stage
   passed.
9. **QEMU stage** (`qemu-test.sh`): boot the unmodified shipped kernel,
   load, wait for the transition, compare the functions in sysfs with the
   diff, replace the previous level, disable, unload, load again, check the
   kernel log. Read `/sys/kernel/notes` there and compare it with the
   build-id in the manifest. On success it writes `out/qemu.ok` with the
   module's SHA-256.
10. **Sign manifest and publish** to ring `canary` (`sign-manifest.sh`). It
    refuses without a `qemu.ok` for exactly this module.
    Promotion to `early` and `stable` re-issues a signed manifest with the
    new ring (`pve-klp-tool promote`).

## Repository layout

```
v1/<kver>/<module>.ko
v1/<kver>/<ring>/manifest.json
v1/<kver>/<ring>/manifest.json.minisig
v1/<kver>/build.log  functions.txt  gate-a.txt  resolved.json
```

## Manifest

```json
{
  "format": 1,
  "kernel": "7.3.5-1-pve",
  "kernel_build_id": "<vmlinux GNU build-id>",
  "level": 3,
  "ring": "canary",
  "module": "klp_pve_7_3_5_1_p3.ko",
  "module_name": "klp_pve_7_3_5_1_p3",
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
  transition (missing function in sysfs, new `Oops`/`BUG`/`WARNING` in the
  kernel log, new taint bits other than those the module carries itself (`O`, `E`, `K`), failing hook), the new
  module is disabled and unloaded and the previous level is restored from
  the local cache.
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
| `/etc/pve-klp/pve-klp.toml` | configuration; created on first install, never touched by upgrades |
| `/etc/pve-klp/trusted.d/*.pub` | trusted manifest keys |
| `/etc/pve-klp/hooks.d/*` | post-transition hooks |
| `/var/lib/pve-klp/state.json` | per kernel: highest accepted, desired level, hold, phase, last error |
| `/var/lib/pve-klp/cache/<kver>/<level>/` | module, manifest and signature for boot and restore |
| `/var/lib/prometheus/node-exporter/pve_klp.prom` | metrics |

## Units

- `pve-klp-boot.service`: `pve-klp boot` before `pve-guests.service`.
  It reloads the cached level for the running kernel, without network.
- `pve-klp-auto.timer`: `pve-klp apply --timer` hourly. It is off by default;
  turn it on with `pve-klp auto enable`.
