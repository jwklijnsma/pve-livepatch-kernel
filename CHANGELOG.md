# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/prepaid-host/pve-klp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/prepaid-host/pve-klp/releases/tag/v0.1.0
