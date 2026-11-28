# Why

## Why

Kernel security fixes for Proxmox VE arrive regularly. Every one means
draining a node, rebooting it and filling it again. Passthrough guests and
single nodes without a migration target have real downtime. Between the fix
and the reboot the host stays vulnerable, and for a guest-to-host escape that
is the risk that matters.

As of November 2026, KernelCare does not list Proxmox VE 9 among its
supported platforms, and Proxmox itself offers no livepatching. hvpatch
closes the gap with the kernel's own tooling, in the open, and without
making you trust a third party.

## What you get

- **One command to load, one to undo.** `hvpatch apply`, `hvpatch revert`.
- **Honest status.** For every CVE: fixed live, or "reboot required" and in
  which kernel it is fixed.
- **Safe by default.** Signature, kernel build-id and module hash are checked
  before anything is loaded. A stalled transition is reversed, never forced.
  If a new level misbehaves, the previous one comes back automatically.
- **Learns from failures.** A level that failed or crashed a host is
  quarantined and never loaded again automatically; in a cluster only one
  node loads at a time. A level that misbehaves in the field can be revoked
  centrally: nodes go back to the level before it.
- **Fits your tooling.** Exit codes, `--json`, Prometheus metrics, hook
  scripts. Ansible decides the order in your fleet; there is no control
  server.
- **Self-hostable.** Run the build pipeline with your own keys and you only
  trust the catalog you review.
