#!/usr/bin/env bash
# Create the module signing key + certificate for the MODULE_SIGNING_PEM secret.
# Run once, on any computer with openssl (same kind of key dkms makes for MOK). The result goes straight into GitHub:
#
#   ./signing/new-signing-key.sh | gh secret set MODULE_SIGNING_PEM -R <owner>/<repo>
#
# or print it and paste it into GitHub → Settings → Secrets and variables →
# Actions → New repository secret, name MODULE_SIGNING_PEM. Nothing is kept on disk.
set -Eeuo pipefail
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT; chmod 700 "$t"
cn=${1:-pve-livepatch module signing key}
openssl req -new -x509 -nodes -days 36500 -newkey rsa:2048 -sha256 \
  -subj "/CN=${cn}/" \
  -keyout "$t/key.pem" -out "$t/cert.pem" >/dev/null 2>&1
cat "$t/key.pem" "$t/cert.pem"
