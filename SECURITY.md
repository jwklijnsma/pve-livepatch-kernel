# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems in hvpatch itself
(agent, build tooling, published modules or signing). Use GitHub's private
vulnerability reporting for this repository:
[report a vulnerability](https://github.com/jwklijnsma/pve-livepatch-kernel/security/advisories/new)
("Security" tab → "Report a vulnerability").

What happens next:

- We confirm the report within 3 working days and give a first assessment
  within 10 days.
- We aim to release a fix within 30 days, depending on severity and
  complexity, and keep you informed.
- Coordinated disclosure: we publish a GitHub Security Advisory (with a CVE
  where applicable) once a fixed release is available, at the latest 90
  days after the report unless we agree on another date with you. We credit
  reporters who want to be named.

Kernel vulnerabilities themselves belong to the kernel security team and to
Proxmox. This project only packages public fixes.

## Supported versions

| Version | Security fixes |
| --- | --- |
| latest release (0.3.x) | yes |
| older releases | no, please upgrade |

## What you trust

| Mode | You trust |
| --- | --- |
| Own pipeline, own keys (recommended for fleets) | The catalog you review, the upstream fix, your build host |
| Project builds | Additionally the maintainers and their signing infrastructure, with ring 0 access to your hosts |

## Keys

- **Manifest key** (Ed25519, minisign format): signs `manifest.json`, which
  binds kernel release, vmlinux build-id, level, ring, module hash and
  expiry. The agent trusts every `*.pub` in `/etc/hvpatch/trusted.d/`.
  Rotation: ship the new key, sign with it, remove the old one later.
- **Module key** (X.509): signs the `.ko` with `sign-file` from Debian's
  `linux-kbuild` package, in a container without the kernel tree. The kernel
  checks it when the module loads. Under Secure Boot the certificate must be
  enrolled as MOK (`hvpatch mok enroll`, then confirm on the console). A MOK
  can only be removed with a reboot.

The signing keys never live as plain CI secrets. In `builder/run.sh` the
module key is only mounted into the signing container (no kernel tree, no
network), and manifests are signed in a separate step on the signing host,
which can be offline. Project builds, once published, follow the same
split: signing on a dedicated host or hardware token, and only after the
build passed Gate A and the QEMU stage. See
[docs/key-management.md](docs/key-management.md).

## Guarantees and non-guarantees

- The agent loads nothing whose manifest is not signed by a trusted key, not
  bound to the running kernel, expired, or lower than a level already
  accepted on this node.
- The agent never writes `/sys/kernel/livepatch/*/force`. A stalled
  transition is reversed; if that stalls too, the agent stops and reports.
- A loaded livepatch taints the kernel (`K`).
- Livepatches only exist for public fixes. Without embargo access a
  livepatch always appears after the public patch.
- An expired manifest means nobody published updates for this kernel in
  time. `status` reports it; install the kernel update.
