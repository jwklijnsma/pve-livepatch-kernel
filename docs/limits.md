# Limits

A livepatch replaces functions, not data structures. These always need a
reboot, and `status` says so:

- changes to data structures, `__init` code, `lib/`, assembler, vDSO;
- out-of-tree modules such as **ZFS**;
- user space such as QEMU or libc (restart or migrate the VM).

Supported: Proxmox VE 9 with the opt-in 7.3 kernel series, x86-64. The
default 7.0 series is **experimental**: objtool needs backports there, and
7.0.14-30-pve has been built and tested on a three-node test cluster under
guest load ([docs/kernel-7.0.md](kernel-7.0.md)). PVE 8 and older are
out of scope.
