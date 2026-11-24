# Threat model

hvpatch loads code into the kernel of hypervisors. Whoever controls what
gets loaded controls every VM on the host. This document lists what the
design defends against, how, and what it does not cover.

## Assets

- **Hypervisor kernels** of every node that runs the agent.
- **Manifest signing key**: decides what nodes accept.
- **Module signing key**: decides what Secure Boot nodes let into the
  kernel (with lockdown, the only gate besides the agent).
- **The catalog**: decides which source changes become modules.
- **The repository**: serves manifests, modules, the revocation list.

## Trust boundaries

```
catalog (reviewed PRs) ─► build container ─► sign container ─► QEMU container
                         (untrusted code:    (module key,     (no keys)
                          Makefiles, patches) no network)
                                   │
                         signing host (manifest key) ─► repository (untrusted) ─► agent (root on node)
```

The repository and the network are untrusted: everything a node loads is
verified on the node.

## Threats and defences

| Threat | Defence |
| --- | --- |
| Compromised mirror or MITM serves a malicious module | Manifest signature (Ed25519, minisign format) with keys pinned on the node; module SHA-256 in the manifest, re-hashed through the same file descriptor passed to `finit_module`; on Secure Boot also the kernel's module signature check |
| Old, validly signed manifest replayed (rollback to a vulnerable level) | Highest accepted level per kernel persisted; lower levels refused (except the agent's own restore after a failure or revocation) |
| Freeze: repository stops serving updates | Manifests expire (30 days by default); `status` reports age and expiry |
| Revocation suppressed by the mirror | Once a revocation list was accepted, a missing or older one stops all new loads; lists have monotonic sequence numbers |
| Module built for another kernel, or a rebuilt package with the same release string | Manifest bound to the release **and** the vmlinux build-id; `.modinfo` vermagic and name checked |
| Malicious catalog patch | Two-person review rule (currently one maintainer, documented), `lint --upstream` compares patch-ids with the upstream fix commits from git.kernel.org, Gate A compares the patched functions with the reviewed list |
| Malicious code in the build (patch or Makefile) reaches the keys | Separate containers: the build has no keys; the signing container has no tree, catalog or network and reads build output as untrusted data (regular files only, values validated), runs Gate A again against artifacts the build could only read |
| Build manipulates what it is checked against | Shipped artifacts are fetched in their own container, read-only for every later stage |
| QEMU stage faked by build output | The test stage runs no code from the kernel tree (own initramfs writer), boots the shipped kernel, reproducers only from the catalog |
| Kernel source swapped (moved tag, tampered mirror) | `kernels.lock` pins the reviewed commit per release |
| Published file replaced later | `publish_file` never overwrites with different content; rings are symlinks to versioned directories |
| A level that misbehaves on a node | Post-checks (kernel log, taint, sysfs functions, hooks); the previous level is restored by atomic replace; quarantine by module hash |
| A level that misbehaves in the field | Signed revocation list; nodes go back to the level below |
| Stalled transition | Reversed, never `force`d; blocking tasks reported |
| Cluster-wide outage from a bad level | pmxcfs lock (one node at a time), rings, `delay_hours`, the Ansible rollout stops at the first unhealthy node |
| Local attacker edits state or hooks | State and config are root-only; hooks run only if owned by root and not writable by others |

## Out of scope

- **A compromised node.** Root on the node can load any module anyway.
- **A compromised maintainer with both keys.** Mitigations: keep the
  manifest key offline (minisign on a separate machine or token), separate
  module and manifest keys, the review rule, and the public catalog
  history. See [key-management.md](key-management.md).
- **Bugs in the upstream fix itself.** hvpatch ships the upstream change; a
  wrong fix is wrong live as well (the revocation list limits the damage).
- **Semantic equivalence of non-trivial livepatches.** Callbacks and shadow
  variables need human review; tooling checks shape, not meaning.
- **Data-structure changes, `__init` code, user space.** Not livepatchable;
  `status` says "reboot required".

## Reporting

See [SECURITY.md](../SECURITY.md).
