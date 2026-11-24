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
psa: PSA-2026-000NN-1              # Proxmox security advisory; omit or "" if none
upstream_commits: ["<sha>"]        # authoritative form of the fix
fixed_in_pve: ["7.3.6-1", "7.0.15-3"]  # first Proxmox package per series that contains it
                                   # (a single string is fine; compared within a series only)
severity: high                     # low | medium | high | critical
class: livepatchable               # see below
reason: ""                         # required unless livepatchable
patches:                           # most specific wins: package version, series, default
  default: 0001-fix.patch
  "7.0": 0001-fix-7.0.patch          # backport for the Ubuntu-based 7.0 series
  "7.3.5-1": 0001-fix-7.3.5-1.patch
functions: ["vmlinux:tcp_foo"]     # required for livepatchable: see below
states: []                         # callbacks/shadow variables: docs/writing-fixes.md
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

## Patched functions

`functions` lists every function the fix changes, as `object:function`
(`vmlinux:cmdline_proc_show`, `kvm_amd:svm_vcpu_run`). Reviewers sign off
this list. Gate A compares it with what `objtool klp diff` reports for the
built module: the union over all resolved entries must equal the module's
changed functions exactly. A function the module patches without review, or
a reviewed function the module does not patch, stops the build.

## Patch order

The patches of all entries a kernel needs go into one cumulative module,
applied in catalog order (sorted by CVE id). `hvpatch-tool resolve --tree`
checks each patch on its own and then all of them one after another; it only
reads the tree, so read-only trees work. A patch that does not apply to a
kernel is a kernel mismatch (add a backport, or `--allow-conflicts` to report
it as "not covered"). Two catalog patches that conflict with each other are
a catalog defect and always fail, with or without `--allow-conflicts`:
rebase the later patch onto the earlier one.

## Review rules

- Every entry arrives by pull request and names the upstream commit.
- CI compares the patch with upstream via `git patch-id`
  (`hvpatch-tool lint --upstream <linux.git>`); deviations need a `reason`.
- Two approvals are the goal. While the project has a single maintainer,
  one review is required (and `lint` enforces one); entries name their
  reviewer in `reviewed_by`. This goes back to two as soon as a second
  maintainer joins.
- Signed commits, protected main branch.
- A backport for a specific kernel is a separate patch with its own review.
- v1 entries use no callbacks and no shadow variables. That keeps replacing a
  cumulative module by an older one safe.

## Finding candidates

```bash
builder/cve-scan.sh 7.3.5-1-pve                       # by upstream version
builder/cve-scan.sh 7.0.14-30-pve build/7.0.14-30-pve/src   # with the tree's backports
```

lists the kernel CVEs (from the kernel CNA's
[vulns.git](https://git.kernel.org/pub/scm/linux/security/vulns.git)) that
affect the kernel and are not in the catalog, with the CNA's CVSS score,
CISA KEV (known exploited) and FIRST EPSS, and writes drafts to
`catalog-drafts/` (ignored by git). Priorities:

| | Meaning |
| --- | --- |
| P0 | known exploited, or CVSS ≥ 9 in code a guest reaches on a KVM host (KVM, vhost, vfio, virtio, tun/tap, host network path) |
| P1 | CVSS ≥ 7, EPSS ≥ 10 %, or guest-reachable |
| P2 | the rest |

"Affected" comes from the CNA's version data (`.dyad`). For 7.0 pass the
kernel tree: its Ubuntu base backports fixes without changing the upstream
version, and the scan drops every fix whose mainline commit a backport names
in its commit message. A draft is a starting point, not an entry: decide the
class, write or pick the patch, list the functions, then move it to
`catalog/` in a pull request.

