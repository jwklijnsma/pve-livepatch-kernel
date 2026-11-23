# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.2] - 2026-11-23

Second round from the real-host test (PVE 9.2, 7.3.5-1-pve). That test
confirmed the 0.1.1 fixes, the QEMU stage (7 s with KVM, including the
replacement of the previous level), atomic replace of level 1 by level 2,
restore of level 1 after a failing hook, anti-rollback after `revert`,
hooks, and 10 revert/apply cycles under full CPU load without kernel
warnings.

### Fixed

- `build.sh`: a level-2 build reusing the cached original build failed with
  "changed data: linux_banner", because the banner contains the random
  container host name. Build user and host are now fixed
  (`pve-klp@pve-klp-builder`), and the cache carries a stamp of config,
  toolchain and build identity; a cache without a matching stamp is rebuilt
  once.
- `build.sh`: fetches the shipped packages again when any artifact the later
  stages need is missing, not only the config (workdirs from 0.1.0 lacked
  `vmlinuz`).
- `status`: right after a reboot, before the boot unit has reloaded the
  livepatch, the phase is `pending` instead of the stored `active`.

### Changed

- On hold after `revert`, the timer returns immediately without contacting
  the repository. An explicit `apply` still evaluates it.
- Docs: hooks run after `apply` and the boot reload, not after `revert`;
  systemd's LSB names for the exit codes; the module's own `O` taint.

## [0.1.1] - 2026-11-23

Fixes from the first run on a real Proxmox VE 9.2 host with kernel
7.3.5-1-pve. There, build, Gate A, signing, `setup`, `apply`, `revert` and
the reload after a reboot worked after manual workarounds; this release
removes the need for them. The new QEMU stage has not run on real hardware
yet.

### Fixed

- Agent: the first `apply` after boot failed with "kernel gained taint flags
  O" on hosts without ZFS loaded. klp-build modules are out-of-tree, so the
  module's own `O` (with `K` and `E`) is now expected; other new flags still
  fail.
- Agent: `status` returns 20 while the boot reload is in progress (it
  returned 0). Text and `--json` output share one exit code, covered by
  tests for every state.
- Builder image: real base image digest, `http` snapshot sources (no CA
  certificates yet at that point), the Debian security snapshot,
  trixie-backports on its own snapshot for the kernel's rustc/LLVM pair,
  the Proxmox repository for the shipped kernel packages, and `gawk` for
  klp-build.
- `build.sh`: no more doubled release suffix (`7.3.5-1-pve-1-pve+`); a stale
  `localversion-pve` from 0.1.0 is removed.
- `build.sh`: the patched functions are read from klp-build's `diff.log`
  (they were always empty before, so Gate A skipped the check silently). An
  empty list stops the build.
- `lint`: an empty `psa`, `mitigation` or `fixed_in_pve` means "none".

### Added

- Gate A and `manifest` require the module's patched functions to equal the
  reviewed `functions` of the catalog entries, in both directions.
  `functions` is now required for livepatchable entries.
- `builder/qemu-test.sh`: boots the shipped kernel in QEMU, loads, replaces,
  unloads and reloads the module, compares functions and build-id, and
  writes `qemu.ok`. `sign-manifest.sh` refuses to sign without it.
- `builder/run.sh` and `make builder-image`: build and test a module with one
  command; the builder image id is recorded in the manifest.
- `docs/toolchains.md`: compiler and snapshot values per kernel release.
- Release workflow dry run (`workflow_dispatch`).

## [0.1.0] - 2026-11-23

First public preview. The agent and the build tooling are complete and
tested against an emulated kernel; loading a module on a real Proxmox 7.3
kernel is the next milestone, and no livepatch modules are published yet.
Use on test hosts only.

### Added

- Node agent `pve-klp` with `setup`, `check`, `status`, `apply`, `boot`,
  `revert`, `auto` and `mok`.
  - Verifies manifest signature (minisign), kernel release, vmlinux
    build-id, ring, expiry and module hash before loading.
  - Anti-rollback across `revert`; hold after `revert` until the next
    explicit `apply`.
  - Loads via `finit_module`, watches the transition per thread, reverses a
    stalled transition and never uses `force`.
  - Post-checks for kernel log, taint, patched functions and hook scripts;
    on failure the previous level is restored from cache.
  - Refuses to run next to foreign or force-transitioned livepatches.
  - `status --json`, Prometheus textfile metrics and stable exit codes.
- Build tool `pve-klp-tool`: config and toolchain gate, catalog lint (with
  `git patch-id` comparison) and resolution, Gate A against the shipped
  kernel, manifest creation, ring promotion, minisign-compatible signing.
- Builder container and pipeline scripts for the proxmox-kernel 7.3 series.
- Debian package with systemd units, man page and bash completion.
- Release workflow with static binaries, SHA256SUMS and build provenance
  attestations.

[Unreleased]: https://github.com/prepaid-host/pve-klp/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/prepaid-host/pve-klp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/prepaid-host/pve-klp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/prepaid-host/pve-klp/releases/tag/v0.1.0
