# Publishing the agent as an APT repository

Goal: on a Proxmox VE node,

```
curl -fsSL https://apt.example.org/pve-klp.asc -o /usr/share/keyrings/pve-klp.asc
echo "deb [signed-by=/usr/share/keyrings/pve-klp.asc] https://apt.example.org trixie main" \
  > /etc/apt/sources.list.d/pve-klp.list
apt update && apt install pve-klp
```

APT repositories are signed with OpenPGP, separately from the livepatch
manifests (minisign). Use a dedicated key for the archive.

## 1. Build the package

CI builds `pve-klp_<version>_amd64.deb` on Debian trixie (`make deb`, see
`.github/workflows/ci.yml`). Releases are tagged `v<version>`; the version
in `debian/changelog` must match.

## 2. Create the archive key (once, offline)

```
gpg --quick-gen-key "pve-klp APT archive <archive@example.org>" ed25519 sign 3y
gpg --armor --export <KEYID> > pve-klp.asc
```

Keep the secret key on a hardware token or an offline machine. Only the
release job may use it.

## 3. Maintain the repository with reprepro

```
apt/conf/distributions:
  Origin: pve-klp
  Label: pve-klp
  Codename: trixie
  Architectures: amd64
  Components: main
  Description: pve-klp agent for Proxmox VE 9
  SignWith: <KEYID>
```

```
reprepro -b apt includedeb trixie dist/pve-klp_0.1.0-1_amd64.deb
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

`/usr/sbin/pve-klp`, systemd units, `/etc/pve-klp/pve-klp.toml`
(conffile), empty `/etc/pve-klp/trusted.d/` and `hooks.d/`. The boot unit is
enabled; the auto timer is installed but disabled. Trusted keys are not part
of the package: project builds would ship a separate
`pve-klp-archive-keyring`-style package with the project's manifest key,
self-hosters put their own key into `trusted.d/`.
