#!/usr/bin/env bash
# Replaced in 0.2.2 by publish.sh (fresh builds, ring canary) and
# promote.sh (canary -> early -> stable from what is published).
source "$(dirname "$0")/lib.sh"
log "sign-manifest.sh is replaced by publish.sh and promote.sh"
SKIP=()
if [ "${1:-}" = "--skip-qemu-stage" ]; then SKIP=(--skip-qemu-stage); shift; fi
RING=${3:-canary}
[ "$RING" = canary ] || die "promote with: builder/promote.sh <repo> <kver> $RING <manifest-pubkey>"
exec "$(dirname "$0")/publish.sh" ${SKIP[@]+"${SKIP[@]}"} "${1:?outdir}" "${2:?repo root}"
