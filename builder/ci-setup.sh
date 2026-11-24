#!/usr/bin/env bash
# One-time setup for the livepatch workflow (.github/workflows/livepatch.yml):
# creates the signing keys, stores them as GitHub Actions secrets, sets the
# public manifest key as a variable and turns on GitHub Pages.
#
# usage: builder/ci-setup.sh [owner/repo] [key-dir]
#
# Needs openssl, the GitHub CLI (gh, logged in with admin rights on the
# repository) and hvpatch-tool (in PATH, builder/hvpatch-tool, or cargo).
# The keys stay in <key-dir> (default ~/pve-livepatch-keys): back them up
# offline. Losing module.priv means re-enrolling a new certificate as MOK on
# Secure Boot nodes; losing manifest.secret means distributing a new
# manifest.pub. Running the script again with the same key-dir reuses the
# keys and only sets the secrets again.
#
# Anyone who can change this repository's workflows can sign modules your
# nodes load: keep write access tight.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
REPO=${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}
DIR=${2:-$HOME/pve-livepatch-keys}
die() { echo "ci-setup.sh: $*" >&2; exit 1; }
for c in openssl gh base64; do command -v "$c" >/dev/null || die "missing $c"; done

if command -v hvpatch-tool >/dev/null; then TOOL=(hvpatch-tool)
elif [ -x "$ROOT/builder/hvpatch-tool" ]; then TOOL=("$ROOT/builder/hvpatch-tool")
elif command -v cargo >/dev/null; then TOOL=(cargo run --quiet --locked --manifest-path "$ROOT/Cargo.toml" -p hvpatch-tool --)
else die "hvpatch-tool not found: install Rust (cargo) or download hvpatch-tool-x86_64-linux-musl from a release"
fi

mkdir -p "$DIR" && chmod 0700 "$DIR"
cd "$DIR"
if [ ! -f module.priv ]; then
  openssl req -new -x509 -newkey rsa:4096 -sha512 -days 3650 -nodes \
    -subj "/CN=pve-livepatch-kernel module signing ($REPO)/" \
    -keyout module.priv -outform DER -out module-cert.der 2>/dev/null
  chmod 0600 module.priv
  echo "created module signing key and certificate in $DIR"
fi
if [ ! -f manifest.secret ]; then
  "${TOOL[@]}" keygen --secret manifest.secret --public manifest.pub
fi

gh secret set KLP_MODULE_KEY -R "$REPO" < module.priv
base64 -w0 module-cert.der | gh secret set KLP_MODULE_CERT -R "$REPO"
gh secret set KLP_MANIFEST_KEY -R "$REPO" < manifest.secret
gh variable set KLP_MANIFEST_PUB -R "$REPO" < manifest.pub
echo "secrets KLP_MODULE_KEY, KLP_MODULE_CERT, KLP_MANIFEST_KEY and variable KLP_MANIFEST_PUB set on $REPO"

# GitHub Pages, deployed by the workflow.
if gh api "repos/$REPO/pages" >/dev/null 2>&1; then
  gh api -X PUT "repos/$REPO/pages" -f build_type=workflow >/dev/null
else
  gh api -X POST "repos/$REPO/pages" -f build_type=workflow >/dev/null
fi
OWNER=${REPO%%/*}; NAME=${REPO#*/}
URL="https://$(echo "$OWNER" | tr '[:upper:]' '[:lower:]').github.io/$NAME"
echo "GitHub Pages on: $URL"
cat <<EOF

Next:
  gh workflow run livepatch -R $REPO -f force=true     # first build (2-4 h per kernel)

On every node:
  hvpatch setup --repository $URL --key $URL/manifest.pub --ring canary
  install -m 0644 module-cert.der /etc/hvpatch/module-cert.der   # from $DIR, or $URL/module-cert.der
  hvpatch mok enroll        # Secure Boot only, confirm at the console on the next boot
  hvpatch apply && hvpatch auto enable
EOF
