#!/usr/bin/env bash
# Which Proxmox kernels need a (new) automatic live patch?
# Used by .github/workflows/auto-livepatch.yml; prints a JSON array for a job matrix:
#   [{"kernel":"7.0.14-26-pve","name":"auto_0123456789ab"}, ...]
#
# The patch set is every patches/auto/*.patch; its id (a hash of the file names and
# contents) becomes the module name, so a changed set gives a new module that
# atomically replaces the old one on the nodes. A kernel is rebuilt when its
# release lp-auto-<kernel> is missing or was built from another patch set.
#
# Env: DIST (trixie), KEEP (2 newest kernels), KERNELS (explicit list, skips the
#      repository lookup), FORCE (true = rebuild even if up to date),
#      PATCH_DIR (patches/auto), PVE_REPO_BASE, GH_REPO (for `gh release`)
set -Eeuo pipefail

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
DIST=${DIST:-trixie}
KEEP=${KEEP:-2}
FORCE=${FORCE:-false}
KERNELS=${KERNELS:-}
PATCH_DIR=${PATCH_DIR:-patches/auto}
PVE_REPO_BASE=${PVE_REPO_BASE:-http://download.proxmox.com/debian/pve}

note() { printf '%s\n' "$*" >&2; }

[[ $DIST =~ ^[a-z]+$ ]] || { note "invalid DIST '$DIST'"; exit 1; }
[[ $KEEP =~ ^[1-9][0-9]*$ ]] || { note "invalid KEEP '$KEEP'"; exit 1; }

export LC_ALL=C
shopt -s nullglob
patches=("$REPO_DIR/$PATCH_DIR"/*.patch)
if (( ${#patches[@]} == 0 )); then
  note "no patches in ${PATCH_DIR}/ — nothing to build"
  echo '[]'; exit 0
fi
id=$(for p in "${patches[@]}"; do printf '%s\n' "$(basename "$p")"; cat "$p"; done | sha256sum | cut -c1-12)
name="auto_${id}"
note "patch set ${name}: $(for p in "${patches[@]}"; do printf '%s ' "$(basename "$p")"; done)"

if [[ -z $KERNELS ]]; then
  # newest KEEP kernels in pve-no-subscription (enterprise gets the same ones later)
  KERNELS=$(curl -fsSL "${PVE_REPO_BASE}/dists/${DIST}/pve-no-subscription/binary-amd64/Packages.gz" | gunzip -c \
    | sed -n 's/^Package: proxmox-kernel-\([0-9]\{1,\}\.[0-9]\{1,\}\.[0-9]\{1,\}-[0-9]\{1,\}-pve\)\(-signed\)\{0,1\}$/\1/p' \
    | sort -uV | tail -n "$KEEP")
  [[ -n $KERNELS ]] || { note "no kernels found in the Proxmox ${DIST} repository"; exit 1; }
fi

out=()
for k in $KERNELS; do
  [[ $k =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-pve$ ]] || { note "skipping invalid kernel '$k'"; continue; }
  have=$(gh release download "lp-auto-$k" -p PATCHSET -O - 2>/dev/null | sed -n 's/^patchset //p' || true)
  if [[ $FORCE != true && $have == "$name" ]]; then
    note "$k: up to date (${name})"
    continue
  fi
  note "$k: build ${name} (release has: ${have:-nothing})"
  out+=("{\"kernel\":\"$k\",\"name\":\"$name\"}")
done
( IFS=,; printf '[%s]\n' "${out[*]}" )
