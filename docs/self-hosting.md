# Running your own pipeline

Recommended for fleets: you only trust the catalog you review and your own
build host. Everything below runs on any x86-64 Linux host with podman (or
docker); a Proxmox VE host or VM works well. `/dev/kvm` makes the QEMU stage
fast but is optional.

## 1. Builder image (once per toolchain)

```bash
make builder-image          # builds hvpatch-tool and the container image
```

This needs the musl target in your Rust toolchain; the Makefile adds it with
`rustup target add x86_64-unknown-linux-musl` when rustup is available. The
tool is pure Rust, so no musl C toolchain is needed. A locally built tool
differs bit by bit from the release binary (different rustc); use the
attested release binary if you want to match the project's builds.

Without a Rust toolchain, download `hvpatch-tool-x86_64-linux-musl` from the
release page to `builder/hvpatch-tool`, make it executable and run
`podman build -t hvpatch-builder builder/`.

The image pins the base image by digest, Debian main and security by
snapshot, and trixie-backports by a separate snapshot. The toolchain must
match the shipped kernel exactly; [toolchains.md](toolchains.md) lists the
values per kernel release. A mismatch is not silent: the config gate stops
the build with `MISMATCH: do not build`.

## 2. Keys (once)

Keep the keys outside the repository; `run.sh` mounts the key directory
read-only into the signing container only.

```bash
mkdir -p ~/hvpatch-keys && cd ~/hvpatch-keys

# Module signing certificate (X.509), like for DKMS modules.
openssl req -new -x509 -newkey rsa:4096 -sha512 -days 3650 -nodes \
  -subj "/CN=hvpatch module signing/" \
  -keyout module.priv -outform DER -out module-cert.der

# Manifest signing key (minisign-compatible): create it on the signing
# host, not on the build host (`minisign -G` works too; the agent accepts
# both). Only manifest.pub goes to the nodes.
hvpatch-tool keygen --secret manifest.secret --public manifest.pub
```

## 3. Review the kernel source commit (once per kernel release)

`builder/kernels.lock` lists the Proxmox source commit for every kernel
release you build. The first `run.sh` for a new release stops and prints
the line to add:

```
7.3.5-1-pve is not in builder/kernels.lock. Review tag proxmox/7.3.5-1 (commit 1a2b…) and add this line: 7.3.5-1-pve 1a2b…
```

Check the commit on git.proxmox.com and against the package changelog,
then commit the line. A moved tag or a tampered mirror stops every later
build.

## 4. Build, sign and test a module

```bash
KEYS=~/hvpatch-keys builder/run.sh 7.3.5-1-pve 1
```

`run.sh` uses four containers, each with only what it needs:

0. **fetch** (`fetch-shipped.sh`, once per kernel release): the kernel and
   headers packages Proxmox shipped (config, System.map, Module.symvers,
   modules, vmlinuz, build-id). Every later stage gets them read-only, so a
   build cannot change what it is checked against.
1. **build** (`build.sh`), repository read-only, no keys: the Proxmox
   source at the locked commit with Proxmox's patch queue, the config and
   toolchain gate, catalog
   resolution (each patch, then all of them in order), `klp-build`, Gate A
   (including: the module patches exactly the functions the catalog entries
   list), and the GPL source bundle.
2. **sign** (`sign-module.sh`), no kernel tree, no catalog, no network:
   treats the build output as untrusted (regular files only, values
   checked), runs Gate A again, signs with Debian's `sign-file` (not the
   one built from the tree), verifies the signature against the
   certificate with openssl, and writes the manifest.
3. **test** (`qemu-test.sh`), no tree, no keys, no network, nothing from
   the tree executed (own initramfs writer): boots the unmodified
   shipped kernel; runs the catalog reproducers before the patch; loads the
   livepatch (replacing the previous level if given); loads the target
   modules afterwards and checks they are patched; runs the reproducers
   with the patch, after removing it and after loading it again; patches
   and unpatches `CYCLES` times under load; checks `replace=1`, the
   functions in sysfs, the kernel log and the build-id. Writes
   `out/qemu.ok`.

Output: `build/7.3.5-1-pve/out/`. One build tree needs about 52 GB;
`run.sh` checks for 60 GB free (15 GB when the tree is cached) before it
starts. Remove trees of kernels you no longer serve.

For level 2 and later, also test the atomic replace of the previous level:

```bash
KEYS=~/hvpatch-keys builder/run.sh 7.3.5-1-pve 2 /srv/klp/v1/7.3.5-1-pve/klp_hvp_7_3_5_1_p1.ko
```

## 5. Publish and promote

On the signing host, with the manifest key:

```bash
MANIFEST_KEY=~/hvpatch-keys/manifest.secret builder/publish.sh build/7.3.5-1-pve/out /srv/klp
```

`publish.sh` puts a build into ring `canary`. It refuses unless the QEMU
stage passed for exactly this module, the manifest matches the build
output, the level is higher than the one canary has, and nothing already
published would be overwritten with different bytes. `--skip-qemu-stage`
is for emergencies and is recorded in the signature.

Promote what canary serves, after the canary nodes look good:

```bash
MANIFEST_KEY=… builder/promote.sh /srv/klp 7.3.5-1-pve early ~/hvpatch-keys/manifest.pub
MANIFEST_KEY=… builder/promote.sh /srv/klp 7.3.5-1-pve stable ~/hvpatch-keys/manifest.pub
```

`promote.sh` verifies the lower ring's signed manifest and the module's
hash in the repository; nothing from a build directory is involved. With
`MINISIGN_KEY` instead of `MANIFEST_KEY` both scripts sign with the
`minisign` tool (e.g. an offline key).

Each ring is a symlink to a versioned directory
(`canary -> canary.versions/<level>-<time>/`), switched atomically; older
versions stay for audits. Serve `/srv/klp` over HTTPS with a server that
follows symlinks, or sync a dereferenced copy (`rsync -L`) to object
storage.

### Status page

```bash
hvpatch-tool status-page --repo /srv/klp --title "Example livepatches" --out /srv/klp/index.html
```

writes a static overview from the signed manifests: what each ring serves
per kernel, the CVEs fixed live, what needs a reboot, revoked levels. Run
it after every publish, promote or revoke.

### What goes into the repository

```
v1/<kver>/<module>.ko                    signed module (never overwritten)
v1/<kver>/<module>.source.tar.gz         patches, config, toolchain, scripts (GPL)
v1/<kver>/source/linux-<kver>-<sha>.tar.xz   the complete kernel source (once per commit)
v1/<kver>/<level>/                       build.log, functions, Gate A, QEMU log
v1/<kver>/<ring> -> <ring>.versions/…    manifest.json + manifest.json.minisig
```

The source bundle and the kernel tarball are the corresponding source the
GPL requires when you distribute modules beyond your own machines.

## 6. Nodes

```bash
apt install ./hvpatch_amd64.deb
hvpatch setup --repository https://klp.example.org --key manifest.pub --ring canary
install -m 0644 ~/hvpatch-keys/module-cert.der /etc/hvpatch/module-cert.der
hvpatch apply
```

With Secure Boot, enroll the module certificate once (`hvpatch mok enroll`,
confirm at the console on the next boot). `mok enroll` asks for a one-time
password on a terminal (mokutil reads it from the TTY, not from a pipe); for
automation run it under `expect` or call `mokutil --import` yourself. Without Secure Boot the kernel
loads the module anyway but cannot verify the signature: every load taints
the kernel with `E` ("signature and/or required key missing"). The agent's
manifest signature check is what protects these hosts.

## 7. Withdrawing a level

If a level misbehaves in the field, revoke it:

```bash
MANIFEST_KEY=~/hvpatch-keys/manifest.secret \
  builder/revoke.sh /srv/klp 7.3.5-1-pve 2 "regression: soft lockups under heavy vhost load"
```

Nodes stop loading level 2 and, on their next timer run, put the highest
cached level below it back (or unload it if there is none). Then publish a
fixed level 3. The list's sequence number only goes up, so an attacker who
can only replay old files cannot un-revoke anything.

## 8. Rollout

The agent only knows its ring. The fleet order comes from your configuration
management: canary node first, then one node per cluster, then the rest,
each with a waiting time. Stop at the first `hvpatch apply` exit code other
than 0. Never patch all nodes of a cluster at once.
