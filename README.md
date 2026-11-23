# pve-klp: kernel live patching for Proxmox VE 9

[![CI](https://github.com/prepaid-host/pve-klp/actions/workflows/ci.yml/badge.svg)](https://github.com/prepaid-host/pve-klp/actions/workflows/ci.yml)
[![License: GPL-2.0-only](https://img.shields.io/badge/license-GPL--2.0--only-blue.svg)](LICENSE)
![Status: pre-release](https://img.shields.io/badge/status-pre--release-orange.svg)

Build, verify and load kernel livepatches for Proxmox VE hosts, so a
security fix does not have to wait for the next reboot window.

- **Reproducible builds** with the kernel's own `klp-build` (Linux 6.19+),
  against the exact Proxmox kernel source, config and toolchain. The build
  aborts if the configuration or compiler differs from the shipped kernel.
- **A reviewed, per-CVE catalog** that states for every kernel what is fixed
  live and what still needs a reboot.
- **A small agent** that checks signature, kernel release, kernel build-id
  and module hash before loading. It backs out if the transition stalls, and
  restores the previous level if a new one misbehaves. It never uses `force`.
- **Run it yourself**: the pipeline works with your own keys. Project builds
  are an offer, not a requirement.

> This is a bridge, not a replacement. Install the real kernel update and
> reboot at your next maintenance window.

**Status:** pre-release. The agent and the build tooling are implemented and
tested against an emulated kernel. Milestone 0 (a module built from the
Proxmox 7.3 tree, loaded on an unmodified Proxmox kernel) is in progress. Do
not use on production hosts yet.

Not affiliated with Proxmox Server Solutions GmbH.

## How it works

```
 catalog/ (reviewed)   proxmox-kernel.git + shipped .debs
        \                 /
         builder/  ── config/toolchain gate ── klp-build ── Gate A ── sign
                                                                      │
                                                   static repository (HTTPS)
                                                   v1/<kver>/<ring>/manifest.json(.minisig)
                                                   v1/<kver>/klp_pve_<…>_p<N>.ko
                                                                      │
 node:  pve-klp apply ── verify ── finit_module ── watch transition ── post-checks
```

- One cumulative module per kernel release. Atomic replace swaps levels. At
  most one livepatch of this project is active on a node.
- Release rings (`canary`, `early`, `stable`) are separate signed manifests.
  Promotion is an explicit, signed step, not a timer.
- There is no control server. Every node pulls; your configuration
  management decides the order in the fleet.

Details: [docs/architecture.md](docs/architecture.md).

## Agent

```
pve-klp check            # kernel config, Secure Boot/MOK, keys, repository
pve-klp status [--json]  # active level, fixed CVEs, CVEs that need a reboot
pve-klp apply [--level N]
pve-klp revert           # disable, unload, hold until the next explicit apply
pve-klp auto enable|disable
pve-klp mok enroll
```

`apply` in short:

1. Fetch the manifest for the running kernel and ring, then verify its
   minisign signature against `/etc/pve-klp/trusted.d/*.pub`.
2. Policy checks: kernel release and vmlinux build-id, ring, expiry, no
   rollback below the highest level ever accepted, no downgrade.
3. Download the module and check its SHA-256, `livepatch=Y`, name and
   vermagic.
4. Preconditions: no transition in progress, no forced leftovers, no foreign
   livepatch (atomic replace would disable it).
5. `finit_module`. The kernel checks the module signature.
6. Wait for the transition, logging blocking tasks per thread. On timeout,
   reverse the transition. If the reversal is also stuck, stop and report.
7. Post-checks: every promised function is patched, no new kernel warnings,
   no new taint, hooks pass. On failure, back out and restore the previous
   level from cache.

The state is shown in `status --json`, in a node_exporter textfile and in
exit codes:

| `status` exit code | Meaning |
| --- | --- |
| 0 | livepatch active, no known CVE needs a reboot |
| 10 | livepatch active, but a reboot is required (`not_covered`, newer kernel) |
| 11 | no livepatch active |
| 12 | manifest expired: no further patches are coming |
| 20 | last operation failed, or transition in progress |

| `apply` / `boot` / `revert` exit code | Meaning |
| --- | --- |
| 0 | applied, already active, nothing published, or on hold |
| 2 | failed and backed out |
| 3 | rejected by verification or policy; nothing loaded |
| 4 | precondition failed (transition running, forced leftover, foreign patch) |

## Limits

A livepatch replaces functions, not data structures. These always need a
reboot and are reported as such:

- changes to data structures, `__init` code, `lib/`, assembler, vDSO and
  realmode code;
- out-of-tree modules such as ZFS;
- user space (QEMU, libc). A VM restart or migration picks those up.

Supported: Proxmox VE 9 with the opt-in 7.3 kernel series, x86-64.

## Trust

This project loads code into the kernel of your hypervisor. Read
[SECURITY.md](SECURITY.md) and [docs/self-hosting.md](docs/self-hosting.md).
With project builds you trust the maintainers with ring 0. With your own
pipeline and keys you only trust the catalog, which you can review.

## Repository layout

| Path | Content |
| --- | --- |
| `crates/pve-klp` | node agent (Rust) |
| `crates/pve-klp-tool` | build-side tool: catalog, Gate A, manifests, signing |
| `crates/klp-core` | shared manifest, signature, policy and ELF code |
| `catalog/` | reviewed CVE entries and patches |
| `builder/` | build container and pipeline scripts |
| `packaging/`, `debian/` | systemd units, Debian packaging |
| `docs/` | architecture, threat model, self-hosting, APT repository |

## Building

```
make test         # unit and integration tests (any platform)
make static       # static x86_64-linux-musl agent binary
make deb          # Debian package (on Debian trixie / PVE 9)
```

Rust 1.88 or newer.

## Contributing

Catalog entries and code contributions are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md); report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).

## License

GPL-2.0-only, see [LICENSE](LICENSE). Livepatch modules and catalog patches
are derived from the Linux kernel and are GPL-2.0 as well.
