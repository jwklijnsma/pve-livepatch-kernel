# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0+jw1] - 2026-11-24

First release of the fork
[jwklijnsma/pve-livepatch-kernel](https://github.com/jwklijnsma/pve-livepatch-kernel)
of [prepaid-host/hvpatch](https://github.com/prepaid-host/hvpatch), based on
hvpatch's `main` after 0.3.0. The agent, the package and all commands keep
the name `hvpatch`.

### Fork

- `livepatch` workflow: every 6 hours it reads Proxmox's package lists,
  locks new kernel releases in `builder/kernels.lock` (commit of Proxmox's
  release tag, directly or as a pull request), builds, signs and
  QEMU-tests one cumulative module per kernel with `builder/run.sh`, and
  publishes it to ring `canary` of a repository on GitHub Pages. A kernel
  is rebuilt only when its locked commit, the catalog, the builder or the
  build tool changed. Kernel source tarballs go to the `klp-source`
  release.
- `livepatch-admin` workflow: promote (canary -> early -> stable) and
  revoke from the Actions tab; optional automatic promotion with
  `LIVEPATCH_AUTO_PROMOTE`.
- `builder/ci-setup.sh`: creates the signing keys, stores them as Actions
  secrets and turns on GitHub Pages.
- Package metadata, systemd units, man page and the Ansible role point to
  the fork.

### Added

- Releases ship a CycloneDX SBOM (`hvpatch.cdx.json`) with an SBOM
  attestation for the binaries and the package.
- CI checks the minimum Rust version (1.88) and runs `cargo deny`
  (licenses, RustSec advisories, sources); OpenSSF Scorecard runs weekly.
- Issue form for test reports.
- CodeQL analysis of the Rust code and the workflows. Releases also ship
  the signed build provenance as `hvpatch.intoto.jsonl` for offline
  verification. SECURITY.md states response times, the disclosure
  timeline and the supported versions.
- `contrib/prometheus/hvpatch.rules.yml`: example alerting rules (failed
  apply, stuck transition, interrupted operation, quarantine, stale
  metrics, expiry), and a table of the signals in `contrib/README.md`.
- README: terminal recording of `apply`, `revert` and `status` on a node
  with running VMs (`docs/assets/demo.gif`); `contrib/demo/demo.sh` now
  times `apply` (it called `time` as a command, which does not exist).

### Changed

- README: 7.0 in the quick start, current roadmap, dated statement on
  KernelCare. SECURITY.md describes the current signing setup.
- chrono is unmaintained (RUSTSEC-2026-0543); accepted for now, the move
  to jiff is tracked in #5.

## [0.3.0] - 2026-11-24

Livepatches for Proxmox VE 9's default kernel series 7.0 (experimental):
7.0.14-30-pve has been built, tested in QEMU and run on a three-node test
cluster under guest load ([docs/kernel-7.0.md](docs/kernel-7.0.md)).
Also: a signed revocation list, states for fixes with callbacks, CVE
scanning against the kernel CNA's data, a stricter split of the build into
four containers, and integrations (Checkmk, Ansible, notification hook).

Upgrading: install the new package on the nodes; the configuration is
unchanged. Build hosts: rebuild the builder image (`run.sh` does), and keep
using your keys. Nodes that have accepted a revocation list once do not
load anything new while the repository withholds it.

### Changed (build side)

- **Separate containers in `run.sh`:** fetch (the shipped packages,
  read-only for every later stage), build (repository read-only, no keys),
  sign (only the key and the output, no kernel tree, no catalog, no
  network) and QEMU test (no tree, no keys, no network). A malicious catalog
  patch or kernel Makefile can no longer reach the signing key, change the
  build scripts or the artifacts the module is checked against. Later
  stages read the build output as untrusted data (regular files only, no
  symlinks; values checked), the signing stage runs Gate A again, and no
  stage after the build runs code from the kernel tree (own build-id
  extractor and initramfs writer). The agent rejects manifests whose
  provenance fields have an unexpected format.
- **Module signing** with Debian's `sign-file` instead of the one built
  from the kernel tree, and the signature is verified against the
  certificate with openssl before anything is published.
- **Kernel source pinned** in `builder/kernels.lock`; a moved tag or a
  reused tree that is not clean stops the build.
- **Publishing:** `publish.sh` (fresh builds, ring canary) and `promote.sh`
  (promote exactly what the ring below serves, after verifying its
  signature and the module hash) replace `sign-manifest.sh`. Published
  files are never overwritten, levels only go up per ring, and each ring is
  a symlink switched atomically, so readers never see a manifest without
  its signature.
- **QEMU stage:** runs the catalog reproducers before, with, after and
  again with the patch; loads the target modules after the livepatch and
  checks they are patched; checks `replace=1`; patch/unpatch cycles under
  load.
- **GPL:** every build has a corresponding-source bundle (patches, kernel
  tarball, config, toolchain, scripts), published next to the module.
- HTTP repositories time out after 15 s when they cannot be reached at
  all, instead of waiting for the 300 s download timeout (`hvpatch check`
  hung on a dropped connection).
- The boot reload of a level below the highest one accepted (after a
  revocation) is a restore, not a rollback.
- `resolve` refuses "already contained" when it contradicts the entry's
  `fixed_in_pve`; Gate A treats a missing shipped module as an error;
  compressed shipped modules are unpacked; `build.sh` starts from an empty
  output directory and marks a dirty catalog.
- `cve-scan --contained` only counts real backport markers ("cherry picked
  from", "commit … upstream", "Upstream commit") and leaves out reverted
  backports; `Fixes:` lines do not hide a CVE.
- CI compares the catalog patches with the upstream commits (`git
  patch-id`), as documented. The commits come from git.kernel.org (mainline
  or stable) only, which serves nothing outside its own history.
- `run.sh` mounts single directories per stage, never the whole build
  directory, and checks on the host that `out/` and `shipped/` are still
  plain directories before the next stage.

### Added

- **`FROM_STAGE=3 builder/run.sh`** repeats only the QEMU stage for the
  signed module already in `out/`.
- `hvpatch-tool status-page`: static HTML overview of a repository (rings
  per kernel, CVEs fixed live, reboot-only CVEs, revoked levels).

- `docs/threat-model.md` and `docs/key-management.md` (two keys, offline
  manifest key, rotation without a flag day, what to do after a leak).

- **Integrations** (`contrib/`): Checkmk local check, notification hook
  example, Ansible role and a rollout playbook (canary first, one node at a
  time, stop at the first unhealthy node). Shipped as examples in the
  Debian package.

- **States for fixes with callbacks or shadow variables** (catalog
  `states`, manifest `states`): a level must carry every state of the
  active level at the same or a higher version, or the agent refuses it
  before loading (klp-build modules do not declare states to the kernel
  yet). Manifests without states are unchanged, so older agents keep
  reading them. Guide: `docs/writing-fixes.md`.

- **`hvpatch-tool cve-scan` and `builder/cve-scan.sh`:** kernel CVEs that
  affect a Proxmox kernel and are not in the catalog yet, from the kernel
  CNA's vulns.git, with CVSS, CISA KEV and EPSS, prioritised P0–P2 for
  hypervisors, with catalog drafts. For 7.0, backports in the kernel tree
  are recognised by the mainline commit they name.

- **7.0 kernel series (experimental):** `fetch-source.sh` prepares the
  Ubuntu-based tree from `pve-kernel.git` as Proxmox does (pinned
  pve-kernel commit, release checked against its Makefile) and adds the
  six upstream objtool commits the tree lacks for `objtool klp`
  (`builder/kernel-7.0/`, see `docs/kernel-7.0.md`). Checked: the patches
  apply to Proxmox 7.0.14-30 and objtool builds with libxxhash; a 7.0
  livepatch has not been through the QEMU stage and a host yet.
- Catalog: `fixed_in_pve` takes one version per kernel series and is only
  compared within a series; patches can be given per series (`"7.0"`) as
  well as per package version.

- **Signed revocation list** (`v1/revoked.json`, `builder/revoke.sh`,
  `hvpatch-tool revoke`): a revoked module is never loaded again, not even
  explicitly; nodes that run it go back to the highest cached level below
  it on their next timer run, or unload it. Sequence numbers only go up
  (no replay); the list is cached for the boot reload. Once a list was
  accepted, nothing new is loaded while the repository withholds it.

- **Reboot recommendation:** `hvpatch status` names a newer installed
  kernel that waits for the next reboot (reboot reason, exit code 10,
  metric `hvpatch_newer_kernel_installed`). Livepatches bridge the time to
  the maintenance window; they do not replace booting the new kernel.

## [0.2.1] - 2026-11-24

From a review of the whole code base. It found no way to get
unverified code loaded, but three faults in failure handling that made each
other worse; they are fixed here.

### Fixed

- **7.0 builds:** `fetch-shipped.sh` took `/usr/lib/modules/<kver>`
  whenever it existed; the 7.0 packages ship the modules in
  `/lib/modules/<kver>` and only the headers' build link in the former,
  so Gate A found none of the shipped modules (and failed).
- **QEMU stage:** terminal control sequences from the console (the 7.0
  kernel clears the screen) are removed from the log before it is
  evaluated; they hid the first `HVPATCH:` line, and the stage ended
  without a message. A missing build-id line is now reported.
- **QEMU stage reproducers:** the initramfs's busybox has no `chattr`, so
  the CVE-2026-99640 reproducer failed to run and reported "fixed" (and the
  stage "inconclusive"). The initramfs now carries `chattr`/`lsattr` from
  e2fsprogs, and the reproducer exits 2 (cannot run here) unless `chattr`
  is there and fails with "not supported".
- **Kernel log check could be triggered by tenants.** Any line containing
  "general protection fault" or "BUG:" backed a patch out, including a
  crashing user process ("traps: …", info level) or a process named "BUG:".
  Only records the kernel itself logged at warning level or worse count
  now, and only if the message starts with a known marker; taint flags stay
  the primary signal.
- **Failed levels were retried every hour**, and a level that crashed the
  host would have been loaded again after every reboot. Loads are recorded
  before they start; a level that fails or whose load is interrupted is
  quarantined by module hash. The timer and the boot reload skip it (the
  boot reload falls back to the highest cached level below it); an
  explicit `apply` retries it.
- **Restoring the previous level left the node without a livepatch** for
  up to the transition timeout. The previous level is now loaded again
  while the failed one is still active, which replaces it atomically.
- A run interrupted after a completed transition is recognised and
  recorded as active instead of reporting "in progress" forever.
- Every error after a manifest was accepted (download, disk full, …) is
  recorded as `failed` with its reason.
- Hooks: run like run-parts (no `*.dpkg-old`, no dotfiles), with a timeout
  (`hook_timeout`, killed with their process group), only if owned by root
  and not writable by others, with `HVPATCH_MODE` = apply, boot or restore.
- The boot unit is no longer restarted by package upgrades, has the same
  sandbox as the timer unit, and waits for a running timer instead of
  failing (`boot_lock_wait`).
- A livepatch being freed by the kernel (sysfs gone, reference not yet
  dropped) is no longer mistaken for a forced one.
- Read errors in sysfs other than "not found" are errors, not a finished
  transition. Transition timeouts count wall-clock time.
- A node clock behind the build time no longer blocks the boot reload
  (warning instead).
- One damaged file in `trusted.d` is skipped with a warning instead of
  stopping every command. A damaged `state.json` names the way out.
- State writes fsync the directory; the module size limit is 32 MiB; the
  cache keeps three levels per kernel and forgets old kernels;
  `setup --key https://` refuses redirects to http; repositories answering
  403 for missing files (S3) count as "not published"; a manifest whose
  signature does not match is fetched once more before failing (publish
  race).
- Manifests must be bound to a kernel build-id; `hvpatch-tool manifest`
  requires `--build-id`.

### Added

- Cluster-wide lock in pmxcfs: in a Proxmox VE cluster only one node loads
  a livepatch at a time; without quorum nothing is loaded
  (`cluster_lock`).
- Timer policy: `delay_hours` (delayed channel) and `pin_level`.
- `/run/hvpatch/effective_version` and `fixed_cves` for vulnerability
  scanners.
- Warning (or refusal with `refuse_on_trace_conflict`) when kprobes or BPF
  programs are attached to a function the livepatch replaces.
- `status` lists quarantined levels; metric `hvpatch_quarantined`.

### Changed

- Catalog review: one approval is required while the project has a single
  maintainer (was two). Documented in CONTRIBUTING.md and
  `catalog/README.md`; it goes back to two with a second maintainer.

## [0.2.0] - 2026-11-24

### Changed

- **Renamed from pve-klp to hvpatch.** "pve" is the prefix of Proxmox's own
  packages, and a third-party tool should not look like one. Everything
  follows the new name:

  | Before | Now |
  | --- | --- |
  | `pve-klp`, `pve-klp-tool` | `hvpatch`, `hvpatch-tool` |
  | `/etc/pve-klp/pve-klp.toml` | `/etc/hvpatch/hvpatch.toml` |
  | `/var/lib/pve-klp` | `/var/lib/hvpatch` |
  | `pve-klp-boot.service`, `pve-klp-auto.timer` | `hvpatch-boot.service`, `hvpatch-auto.timer` |
  | `PVE_KLP_*` (hooks, `PVE_KLP_CONFIG`) | `HVPATCH_*` |
  | metrics `pve_klp_*`, `pve_klp.prom` | `hvpatch_*`, `hvpatch.prom` |
  | modules `klp_pve_<kernel>_p<N>` | `klp_hvp_<kernel>_p<N>` |
  | builder image `pve-klp-builder` | `hvpatch-builder` |
  | github.com/prepaid-host/pve-klp | github.com/prepaid-host/hvpatch (old URLs redirect) |

### Upgrading from pve-klp

- The `hvpatch` package conflicts with and replaces `pve-klp`. Installing it
  removes `pve-klp` and copies, once, the configuration (paths rewritten),
  trusted keys, hooks, module certificate, state (including the
  anti-rollback history) and module cache. An enabled auto timer stays
  enabled. CI runs this takeover on every change.
- A livepatch loaded by pve-klp (`klp_pve_*`) stays active and counts as
  hvpatch's own: `status` shows it, and the next level replaces it without
  `--replace-foreign`.
- Manifest keys generated by `pve-klp-tool keygen` keep working.
- Update monitoring (metric names, textfile name) and Ansible (package,
  command and unit names).
- The builder's build identity changes to `hvpatch@hvpatch-builder`, so the
  first build per kernel rebuilds the cached original once.

## [0.1.6] - 2026-11-24

Build-side fixes from the sixth real-host round, which confirmed 0.1.5 and
ran `resolve --tree` with the first real catalog entries (PR #4) against the
Proxmox 7.3.4-1 and 7.3.5-1 trees. The agent is unchanged.

### Fixed

- `resolve --tree` with a relative `--catalog` (including the default
  `catalog`) reported every patch as "does not apply": git resolved the
  patch path against the tree. Catalog paths are now absolute.
- The in-order check wrote into the tree's `.git` and failed on read-only
  trees (`:ro` mounts, shared caches), reported as an ordering conflict.
  Index and new objects now go to a temporary directory and the tree's
  objects are only read; I/O problems are reported as such, not as
  conflicts.

### Docs

- `--allow-conflicts` only covers patches that do not fit the kernel.
  Patches that conflict with each other are a catalog defect and always
  fail (help text and `catalog/README.md`).

## [0.1.5] - 2026-11-24

The fifth real-host round confirmed 0.1.4: a non-interactive upgrade from
0.1.3 on a node that ran `setup`, the pending MOK state, and a full kernel
build with the 0.1.4 image whose module is bit-identical to the 0.1.2-era
build of the same catalog.

### Fixed

- A failed module load quoted every kernel log line since the load, e.g.
  an unrelated softdog message after a Secure Boot rejection. Only lines
  about the module, livepatch, signatures and lockdown are kept.

### Added

- `resolve` also checks that the catalog patches apply together, one after
  another in catalog order (on a throwaway git index), not only each on its
  own. Two fixes in the same function could otherwise first fail inside
  klp-build.
- `builder/run.sh` checks free space before it starts (60 GB, 15 GB with a
  cached tree; `MIN_FREE_GB` overrides) instead of failing after an hour.

### Docs

- Obsolete conffile on nodes installed with 0.1.3 or earlier, and the
  leftover `pve-klp.toml.dpkg-dist` from nodes that hung at the prompt.

## [0.1.4] - 2026-11-23

Fourth round from the real-host test, which also ran a guest VM under load
during 10 revert/apply cycles, a patched module object that is loaded only
after the boot reload, and anti-rollback across kernel releases and wrong
build-ids.

### Upgrade note

Nodes that ran `pve-klp setup` on 0.1.3 or earlier may be stuck in a
half-configured state ("iU") after a non-interactive upgrade to 0.1.3. Run
once:

    dpkg --force-confold --configure pve-klp

and then upgrade to 0.1.4. From 0.1.4 on, upgrades never prompt.

### Fixed

- Upgrades prompted (and failed without a TTY) on every node that ran
  `setup`, because `/etc/pve-klp/pve-klp.toml` was a dpkg conffile that
  `setup` edits. The package now ships the template as
  `/usr/share/pve-klp/pve-klp.toml` and creates the config only when it is
  missing; existing configs are kept. CI installs 0.1.3, runs `setup` and
  upgrades without a TTY on every change.
- Running `setup` again without `--ring` reset the ring to `stable`. Options
  that are not given now keep the configured value; `setup` prints each
  value and whether it changed. `--repository` is only required the first
  time.

### Changed

- `check` and `mok enroll` recognize a pending MOK enrollment ("confirm in
  MokManager on the next boot") instead of saying "not enrolled".
- `status` only asks for a reboot when a transition could neither complete
  nor be reversed. After a cleanly backed-out apply it suggests running
  `pve-klp apply` again; the exit code stays 20.
- `sign-manifest.sh` runs the new `pve-klp-tool check-manifest`, which
  compares the manifest with the module, the resolved catalog and
  `qemu.ok` (kernel, module hash, build-id) and refuses to sign an edited
  manifest.

## [0.1.3] - 2026-11-23

Third round from the real-host test, which added a stalled transition
(apply and revert), Secure Boot with MOK enrollment under OVMF, legacy BIOS,
and three backported CVE fixes on 7.3.4-1-pve (in `vmlinux` and in the
`overlay` module) verified with a reproducer before, during and after the
livepatch.

### Fixed

- `check` never detected Secure Boot: the EFI global variable GUID was
  wrong (`…-e098032b8c4c` instead of `…-00e098032b8c`). It now reports
  Secure Boot and fails when the module certificate is not enrolled, so
  `setup` no longer says "all checks passed" on such hosts.
- An `apply` whose stalled transition was reversed automatically was stored
  as `reverted` and `status` returned 0. It is now `failed` (exit 20), like
  other failed applies; `reverted` stays reserved for the operator's
  `revert`.
- Builder image: `rustfmt` from trixie-backports (matching rustc 1.94.1),
  so the kernel build no longer warns about it.

### Added

- `status` notes a livepatch module of ours that is still loaded but unused
  (e.g. after a stalled revert that the kernel finished later) and how to
  remove it.

### Changed

- `make builder-image` adds the musl target with rustup; documented in
  `docs/self-hosting.md`.
- Docs: `mok enroll` needs a terminal; hooks timing in the config template;
  `7.3.4-1-pve` in `docs/toolchains.md`.

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

[Unreleased]: https://github.com/jwklijnsma/pve-livepatch-kernel/compare/v0.3.0+jw1...HEAD
[0.3.0+jw1]: https://github.com/jwklijnsma/pve-livepatch-kernel/releases/tag/v0.3.0+jw1
[0.3.0]: https://github.com/prepaid-host/hvpatch/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/prepaid-host/hvpatch/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/prepaid-host/hvpatch/compare/v0.1.6...v0.2.0
[0.1.6]: https://github.com/prepaid-host/hvpatch/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/prepaid-host/hvpatch/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/prepaid-host/hvpatch/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/prepaid-host/hvpatch/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/prepaid-host/hvpatch/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/prepaid-host/hvpatch/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/prepaid-host/hvpatch/releases/tag/v0.1.0
