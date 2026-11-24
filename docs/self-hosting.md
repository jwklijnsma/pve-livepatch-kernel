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

```bash
mkdir -p keys && cd keys

# Module signing certificate (X.509), like for DKMS modules.
openssl req -new -x509 -newkey rsa:4096 -sha512 -days 3650 -nodes \
  -subj "/CN=hvpatch module signing/" \
  -keyout module.priv -outform DER -out module-cert.der

# Manifest signing key (minisign-compatible): create it on the signing
# host, not on the build host (`minisign -G` works too; the agent accepts
# both). Only manifest.pub goes to the nodes.
hvpatch-tool keygen --secret manifest.secret --public manifest.pub
```

`keys/` is ignored by git.

## 3. Build and test a module

```bash
builder/run.sh 7.3.5-1-pve 1
```

This runs, inside the container:

1. `fetch-source.sh`: `proxmox-kernel.git` at tag `proxmox/7.3.5-1` with
   Proxmox's patch queue applied.
2. `fetch-shipped.sh`: the shipped kernel and headers packages from the
   Proxmox repository (config, System.map, Module.symvers, modules,
   vmlinuz, vmlinux build-id).
3. `build.sh`: config and toolchain gate, catalog resolution, `klp-build`,
   Gate A (including: the module patches exactly the functions the catalog
   entries list), module signing, unsigned manifest.
4. `qemu-test.sh`: boots the unmodified shipped kernel, loads the module,
   waits for the transition, compares the functions in sysfs, disables,
   unloads, loads again, checks the kernel log, and compares the booted
   kernel's build-id with the manifest. Writes `out/qemu.ok`.

Output: `build/7.3.5-1-pve/out/`. One build tree needs about 52 GB;
`run.sh` checks for 60 GB free (15 GB when the tree is cached) before it
starts. Remove trees of kernels you no longer serve.

For level 2 and later, also test the atomic replace of the previous level:

```bash
builder/run.sh 7.3.5-1-pve 2 build/7.3.5-1-pve-level1/klp_hvp_7_3_5_1_p1.ko
```

## 4. Sign and publish

On the signing host, with the manifest key:

```bash
MANIFEST_KEY=keys/manifest.secret \
  builder/sign-manifest.sh build/7.3.5-1-pve/out /srv/klp canary
```

`sign-manifest.sh` refuses unless `qemu.ok` belongs to exactly this module
(SHA-256). `--skip-qemu-stage` overrides that for emergencies and is
recorded in the signature's trusted comment.

Promote after the canary nodes look good:

```bash
MANIFEST_KEY=keys/manifest.secret builder/sign-manifest.sh build/7.3.5-1-pve/out /srv/klp early
MANIFEST_KEY=keys/manifest.secret builder/sign-manifest.sh build/7.3.5-1-pve/out /srv/klp stable
```

Serve `/srv/klp` over HTTPS (any static web server or object store).

## 5. Nodes

```bash
apt install ./hvpatch_amd64.deb
hvpatch setup --repository https://klp.example.org --key manifest.pub --ring canary
install -m 0644 keys/module-cert.der /etc/hvpatch/module-cert.der
hvpatch apply
```

With Secure Boot, enroll the module certificate once (`hvpatch mok enroll`,
confirm at the console on the next boot). `mok enroll` asks for a one-time
password on a terminal (mokutil reads it from the TTY, not from a pipe); for
automation run it under `expect` or call `mokutil --import` yourself. Without Secure Boot the kernel
loads the module anyway but cannot verify the signature: every load taints
the kernel with `E` ("signature and/or required key missing"). The agent's
manifest signature check is what protects these hosts.

## 6. Rollout

The agent only knows its ring. The fleet order comes from your configuration
management: canary node first, then one node per cluster, then the rest,
each with a waiting time. Stop at the first `hvpatch apply` exit code other
than 0. Never patch all nodes of a cluster at once.
