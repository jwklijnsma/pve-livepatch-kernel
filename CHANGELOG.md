# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Node agent `pve-klp`: `check`, `status`, `apply`, `boot`, `revert`, `auto`,
  `mok`. Signature, kernel release, vmlinux build-id and module hash are
  verified before loading. Stalled transitions are reversed, never forced.
  Failed post-checks restore the previous level from cache. Anti-rollback,
  hold after revert, Prometheus textfile output and stable exit codes.
- Build tool `pve-klp-tool`: config/toolchain gate, catalog lint and
  resolution, Gate A, manifest creation, ring promotion, minisign-compatible
  signing.
- Builder container and pipeline scripts for the Proxmox 7.3 kernel series.
- systemd units and Debian packaging for the agent.
