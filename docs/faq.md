# FAQ

**Does this replace kernel updates?**
No. It moves the reboot into your maintenance window. Install the kernel
update as usual.

**Is it safe?**
The agent never forces a transition and backs out on any sign of trouble.
Still: this is pre-release software that loads code into your hypervisor
kernel. Test on non-production hosts first.

**Why not just KernelCare?**
As of November 2026, KernelCare does not list Proxmox VE 9 as supported.
Check [TuxCare's FAQ](https://support.tuxcare.com/hc/en-us/sections/4408313341724-FAQ)
for the current state. hvpatch is free, open source, and you sign the
patches with your own keys.

**Whom do I trust?**
With your own pipeline and keys, only the catalog you review. With project
builds, also the maintainers. See [SECURITY.md](https://github.com/jwklijnsma/pve-livepatch-kernel/blob/main/SECURITY.md).

**Does it work with ZFS hosts?**
Yes. Fixes inside the ZFS module itself are not livepatchable and are shown
as "reboot required".

**Why does the kernel show taint `E` after loading?**
Without Secure Boot, the kernel cannot verify the module signature against a
trusted key and marks the kernel with `E`; it loads the module anyway. The
agent verified the signed manifest and the module hash before loading. With
Secure Boot, enroll the module certificate as MOK and the `E` goes away.
Every livepatch also sets `K`, and klp-build modules set `O`.

**Does it affect tracing tools?**
kretprobes on a patched function conflict with livepatches, and kprobes in a
replaced function stop firing. `hvpatch check` warns about active kprobes.

**Is this an official Proxmox project?**
No. It is an independent project and not affiliated with Proxmox Server
Solutions GmbH.
