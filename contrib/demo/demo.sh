#!/usr/bin/env bash
# Terminal demo of hvpatch on a test node with running guests, for a
# recording (asciinema rec -c contrib/demo/demo.sh, or vhs).
#
# Needs: a node where `hvpatch apply` has something to load, and VMs
# running (the demo shows they keep running). Never run it on production.
set -euo pipefail
PAUSE=${PAUSE:-2}
say() { printf '\n\033[1;34m# %s\033[0m\n' "$*"; sleep "$PAUSE"; }
run() { printf '\033[1;32m$\033[0m %s\n' "$*"; sleep 1; "$@" || true; sleep "$PAUSE"; }

say "A Proxmox VE node with running VMs"
run qm list
run uname -r
say "Which known CVEs affect this kernel, and is a livepatch active?"
run hvpatch status
say "Load the signed livepatch: no reboot, VMs keep running"
run time hvpatch apply
run hvpatch status
say "The VMs did not notice"
run qm list
say "Patched functions, live in the kernel"
run sh -c 'ls /sys/kernel/livepatch/*/*/'
say "Undo is one command, also live"
run hvpatch revert
run hvpatch status
say "And back"
run hvpatch apply
