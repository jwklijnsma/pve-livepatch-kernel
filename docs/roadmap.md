# Status and roadmap

| | Milestone | State |
| --- | --- | --- |
| 0 | Module from the Proxmox 7.3 tree loads on an unmodified Proxmox kernel | done (nested PVE 9.2, 7.3.5-1-pve) |
| 1 | A real CVE fix as livepatch; review of all 2026 kernel PSAs for livepatchability | fixes done on 7.3.4-1-pve with reproducer; PSA review open |
| 2 | Automatic pipeline: newest kernels, Gate A, QEMU test, signing, repository | `builder/run.sh` per kernel done; scheduled GitHub Actions pipeline in this fork |
| 3 | Agent: check, status, apply, revert, boot unit, .deb, Ansible role | done (Ansible role and Checkmk check in `contrib/`) |
| 4 | Tests under load, canary on AMD and Intel hardware, 24 h soak | nested tests, stalled transitions, Secure Boot, and a three-node 7.0 cluster with guests under load done; bare-metal canary and 24 h soak open |
| 5 | Public project builds, status page, APT repository | status page generator done (`hvpatch-tool status-page`); public builds and APT repository planned |
| 6 | Default 7.0 kernel series | experimental since 0.3.0 (7.0.14-30-pve); leaves experimental after several releases built and a soak on bare metal |
