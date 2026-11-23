# shellcheck shell=bash
set -euo pipefail

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# 7.3.5-1-pve -> 7.3.5-1
pkgver() { printf '%s' "${1%-pve}"; }
# 7.3.5-1-pve -> 7.3
series() { local v="${1%%-*}"; printf '%s' "${v%.*}"; }

require() { for c in "$@"; do command -v "$c" >/dev/null || die "missing tool: $c"; done; }
