# Patch catalog

One directory per CVE. The catalog says *what* gets fixed; the pipeline
computes per kernel which entries are still missing.

```
catalog/CVE-2026-XXXXX/meta.yaml
catalog/CVE-2026-XXXXX/0001-fix.patch
catalog/CVE-2026-XXXXX/0001-fix-7.3.5-1.patch   # optional backport
```

## meta.yaml

```yaml
id: CVE-2026-XXXXX                 # must equal the directory name
title: Use-after-free in ...
psa: PSA-2026-000NN-1              # Proxmox security advisory, if any
upstream_commits: ["<sha>"]        # authoritative form of the fix
fixed_in_pve: "7.3.6-1"            # first Proxmox package that contains it
severity: high                     # low | medium | high | critical
class: livepatchable               # see below
reason: ""                         # required unless livepatchable
patches:
  default: 0001-fix.patch
  "7.3.5-1": 0001-fix-7.3.5-1.patch
functions: ["vmlinux:tcp_foo"]     # reviewed list of patched functions
mitigation: ""                     # for mitigation-only
tests:
  qemu_load: required
  reproducer: none                 # or a path below tests/
reviewed_by: ["alice", "bob"]
```

## Classes

| Class | Criterion | Shown to the operator |
| --- | --- | --- |
| `livepatchable` | Function-only change, klp-build builds it, tests pass | Included in the module |
| `needs-manual` | Needs shadow variables or callbacks | Not in v1: "reboot required" |
| `not-livepatchable` | Data structure change, `__init`, `lib/`, assembler, vDSO, out-of-tree module (ZFS), notrace | "reboot required" |
| `mitigation-only` | No patch, documented mitigation | Shown in status, never applied automatically |

## Review rules

- Every entry arrives by pull request and names the upstream commit.
- CI compares the patch with upstream via `git patch-id`
  (`pve-klp-tool lint --upstream <linux.git>`); deviations need a `reason`.
- Two approvals, signed commits, protected main branch.
- A backport for a specific kernel is a separate patch with its own review.
- v1 entries use no callbacks and no shadow variables. That keeps replacing a
  cumulative module by an older one safe.
