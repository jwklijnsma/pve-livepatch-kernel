#!/usr/bin/env bash
# Decide which kernels the livepatch workflow builds, and at which level.
#
# usage: plan.sh <published-repo-dir> <force:true|false> <kver>...
#
# Prints a JSON list for the build matrix:
#   [{"kver": "...", "level": N, "prev": "<module>.ko or empty", "fingerprint": "..."}]
#
# A kernel is built when it is in builder/kernels.lock and its fingerprint
# (locked commit, catalog, builder scripts, build tool sources) differs from
# the one recorded at the last publish in <repo>/ci/<kver>.fingerprint, or
# when force is true. The level is one above what ring canary serves.
set -euo pipefail
REPO=${1:?repo dir}; FORCE=${2:?force}; shift 2
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

fingerprint() {
  {
    awk -v k="$1" '$1 == k' builder/kernels.lock
    git ls-tree -r HEAD builder catalog crates/hvpatch-tool crates/klp-core Cargo.lock \
      | grep -v $'\tbuilder/kernels.lock$'
  } | sha256sum | cut -d' ' -f1
}

ring_field() {
  local m="$REPO/v1/$1/canary/manifest.json"
  [ -f "$m" ] || { echo "${3:-}"; return; }
  python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$m" "$2"
}

entries=()
for k in "$@"; do
  [[ "$k" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-pve$ ]] || { echo "plan: skipping odd kernel name $k" >&2; continue; }
  if ! awk -v k="$k" '$1 == k { f = 1 } END { exit !f }' builder/kernels.lock; then
    echo "plan: $k is not in builder/kernels.lock, skipped" >&2
    continue
  fi
  fp=$(fingerprint "$k")
  old=$(cat "$REPO/ci/$k.fingerprint" 2>/dev/null || true)
  if [ "$FORCE" != true ] && [ "$fp" = "$old" ]; then
    echo "plan: $k unchanged since the last publish" >&2
    continue
  fi
  level=$(ring_field "$k" level 0)
  prev=$(ring_field "$k" module "")
  [ "$level" -gt 0 ] || prev=
  entries+=("$(printf '{"kver":"%s","level":%d,"prev":"%s","fingerprint":"%s"}' "$k" "$((level + 1))" "$prev" "$fp")")
  echo "plan: $k -> level $((level + 1))" >&2
done
( IFS=,; printf '[%s]\n' "${entries[*]-}" )
