# Quick start

On a Proxmox VE 9 host with the default 7.0 kernel (experimental) or the
opt-in 7.3 kernel:

```bash
# 1. Install the agent (Debian package from the releases page)
wget https://github.com/jwklijnsma/pve-livepatch-kernel/releases/latest/download/hvpatch_amd64.deb
apt install ./hvpatch_amd64.deb

# 2. Point it at a repository and its signing key, and check the host
hvpatch setup --repository https://jwklijnsma.github.io/pve-livepatch-kernel \
  --key https://jwklijnsma.github.io/pve-livepatch-kernel/manifest.pub --ring canary

# 3. Load the livepatch for the running kernel
hvpatch apply

# 4. Optional: pick up new levels automatically
hvpatch auto enable
```

Every release ships SHA256SUMS, a CycloneDX SBOM (`hvpatch.cdx.json`) and
signed build provenance, so you can check that a download was built by this
repository's CI:

```bash
gh attestation verify hvpatch_amd64.deb --repo jwklijnsma/pve-livepatch-kernel
```

A static binary (`hvpatch-x86_64-linux-musl`) is attached to each release as
well, for hosts where you do not want the Debian package.

With Secure Boot, enroll the module certificate once: run `hvpatch mok enroll`
and confirm in MokManager on the next reboot (BMC or local console).

With Secure Boot, the certificate is at `https://jwklijnsma.github.io/pve-livepatch-kernel/module-cert.der`:
install it as `/etc/hvpatch/module-cert.der` before `mok enroll`.

The repository can be this fork's (GitHub Pages, below) or your own, built
with the pipeline in this repository: see [docs/self-hosting.md](self-hosting.md).
