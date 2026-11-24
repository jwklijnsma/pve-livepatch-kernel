# Publishing the agent as an APT repository

Goal: on a Proxmox VE node,

```
curl -fsSL https://apt.example.org/hvpatch.asc -o /usr/share/keyrings/hvpatch.asc
echo "deb [signed-by=/usr/share/keyrings/hvpatch.asc] https://apt.example.org trixie main" \
  > /etc/apt/sources.list.d/hvpatch.list
apt update && apt install hvpatch
```

APT repositories are signed with OpenPGP, separately from the livepatch
manifests (minisign). Use a dedicated key for the archive.

## 1. Build the package

CI builds `hvpatch_<version>_amd64.deb` on Debian trixie (`make deb`, see
`.github/workflows/ci.yml`). Releases are tagged `v<version>`; the version
in `debian/changelog` must match.

## 2. Create the archive key (once, offline)

```
gpg --quick-gen-key "hvpatch APT archive <archive@example.org>" ed25519 sign 3y
gpg --armor --export <KEYID> > hvpatch.asc
```

Keep the secret key on a hardware token or an offline machine. Only the
release job may use it.

## 3. Maintain the repository with reprepro

```
apt/conf/distributions:
  Origin: hvpatch
  Label: hvpatch
  Codename: trixie
  Architectures: amd64
  Components: main
  Description: hvpatch agent for Proxmox VE 9
  SignWith: <KEYID>
```

```
reprepro -b apt includedeb trixie dist/hvpatch_0.2.0-1_amd64.deb
```

`reprepro` writes `dists/` and `pool/` and signs `InRelease` and
`Release.gpg`. Alternatives are `aptly` (snapshots, publishing to S3) and
plain `dpkg-scanpackages` with `apt-ftparchive` (no tooling, more manual).

## 4. Host it

The `apt/` directory is static. Options:

- **Own web server or object storage** behind HTTPS, ideally the same
  infrastructure as the livepatch repository, on a separate host name
  (`apt.…` and `klp.…`).
- **GitHub Pages** from a `gh-pages` branch. This is free and sufficient for
  the agent package. Mind the size limits if you ever want to host modules
  there too.

## 5. Automate

A release workflow on tag `v*`: build the `.deb` → `reprepro includedeb` →
sign on the release runner → upload. The archive key stays out of normal CI
secrets, just like the manifest and module keys.

## Package contents

`/usr/sbin/hvpatch`, systemd units, the configuration template
`/usr/share/hvpatch/hvpatch.toml` (copied to `/etc/hvpatch/hvpatch.toml` on
first installation; not a conffile, so upgrades never prompt), empty
`/etc/hvpatch/trusted.d/` and `hooks.d/`. The boot unit is enabled; the auto
timer is installed but disabled. Trusted keys are not part
of the package: project builds would ship a separate
`hvpatch-archive-keyring`-style package with the project's manifest key,
self-hosters put their own key into `trusted.d/`.

## Nodes that ran pve-klp

hvpatch was called pve-klp up to 0.1.6. The `hvpatch` package conflicts
with and replaces `pve-klp`: installing it removes `pve-klp` and, once,
copies `/etc/pve-klp/` (configuration with paths rewritten, trusted keys,
hooks, module certificate) and `/var/lib/pve-klp/` (state with the
anti-rollback history, module cache) to the new locations. An enabled auto
timer stays enabled. A livepatch loaded by pve-klp (`klp_pve_*`) stays
active and is recognised as hvpatch's own, so the next level replaces it.

Afterwards `/etc/pve-klp` and `/var/lib/pve-klp` are no longer used;
`dpkg --purge pve-klp` removes them (including the obsolete conffile of
0.1.3 and earlier, and a `pve-klp.toml.dpkg-dist` left by the 0.1.3
upgrade prompt).
