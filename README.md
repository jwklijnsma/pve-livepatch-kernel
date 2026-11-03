# pve-livepatch-kernel

Live patch the **running kernel without a reboot** on **Proxmox VE** and **Ubuntu**.

`pve-livepatch.sh` wraps [kpatch](https://github.com/dynup/kpatch) to turn a kernel source patch (for example a CVE fix from git.kernel.org) into a live-patch module, built against the *exact* source of the kernel you are running. On Ubuntu it can also enable Canonical Livepatch for Canonical's official fixes.

| Platform | Custom patches (kpatch) | Official vendor live patches |
|---|---|---|
| Proxmox VE (`*-pve` kernels) | ✅ source from `pve-kernel` git + Proxmox patches | ❌ Proxmox does not ship any |
| Ubuntu (`generic`, `lowlatency`, cloud flavours) | ✅ source from `apt-get source` | ✅ `canonical enable` (Ubuntu Pro) |

## Small nodes: build in GitHub Actions (like Ubuntu Pro)

Ubuntu Pro and RHEL build live patches centrally and nodes only download a small signed module. This repo can do the same for Proxmox kernels:

1. **Build in the cloud.** Actions → **build live patch** → Run workflow, with the node's `uname -r` (e.g. `7.0.14-26-pve`), a patch (URL, or a path in this repo) and a name. GitHub's runner takes the exact kernel config and version from Proxmox's package repository, checks the compiler is the one Proxmox used, builds the module in a Debian container and publishes it as release `lp-<name>-<kernel>`.
2. **On the node (a few MB, no compiler):**
   ```bash
   sudo pve-livepatch setup --minimal              # kpatch loader only
   sudo pve-livepatch mok setup                    # once, if Secure Boot is on
   sudo pve-livepatch fetch lp-<name>-<kernel>     # ~1 MB: sha256 + kernel check, then signs it
   sudo pve-livepatch apply /var/lib/pve-livepatch/out/<kernel>/livepatch-<name>.ko --persist
   ```

Modules are published **unsigned** and each node signs them with its own MOK key, so your private key never leaves your nodes. Signing uses only `openssl` and produces exactly the same bytes as the kernel's `scripts/sign-file`. To try the whole flow safely, build `patches/examples/proc-cmdline-demo.patch`: it only appends ` kpatch_demo=1` to `/proc/cmdline`.

## Install

From a release (`.deb`, installs `/usr/sbin/pve-livepatch`):

```bash
wget https://github.com/jwklijnsma/pve-livepatch-kernel/releases/latest/download/pve-livepatch_<version>_all.deb
sudo apt install ./pve-livepatch_<version>_all.deb
```

Build the package yourself: `packaging/build-deb.sh [version]` → `dist/`.
Releases are built by GitHub Actions — push a tag `vX.Y.Z`, or run **Actions → release .deb → Run workflow** (creates the tag for you). It builds `pve-livepatch_X.Y.Z_all.deb`, test-installs it and attaches it (plus `SHA256SUMS`) to a GitHub Release.

## Quick start

```bash
git clone https://github.com/jwklijnsma/pve-livepatch-kernel.git
cd pve-livepatch-kernel
sudo ./pve-livepatch.sh check        # can this kernel be live patched?
sudo ./pve-livepatch.sh setup        # build deps + kpatch / kpatch-build
sudo ./pve-livepatch.sh source       # exact source for `uname -r`
sudo ./pve-livepatch.sh build fix.patch --name cve_2026_1234
sudo ./pve-livepatch.sh apply /var/lib/pve-livepatch/out/$(uname -r)/livepatch-cve_2026_1234.ko --persist
sudo ./pve-livepatch.sh status
```

Or run all of it in one go: `sudo ./pve-livepatch.sh all <patch-file-or-URL> --name <name>`.

### Ubuntu: Canonical Livepatch

```bash
sudo UBUNTU_PRO_TOKEN=<token> ./pve-livepatch.sh canonical enable
sudo ./pve-livepatch.sh canonical status
```

Get the token from <https://ubuntu.com/pro/dashboard>. Canonical Livepatch only covers Canonical's own kernels; it does **not** work on Proxmox kernels.

## Commands

| Command | What it does |
|---|---|
| `check` | Checks `CONFIG_LIVEPATCH`, ftrace, reliable stacktrace, gcc match, Secure Boot/MOK, disk space, loaded patches |
| `setup [--minimal]` | Installs build dependencies and kpatch; `--minimal` installs only the loader (for nodes that use `fetch`) |
| `source` | **PVE:** finds the `bump version to <pkgver>` commit in pve-kernel, checks out the ubuntu-kernel submodule, applies `patches/kernel/*`. **Ubuntu:** enables `deb-src` if needed (asks first) and runs `apt-get source`. Both: sets `EXTRAVERSION` and verifies `make kernelrelease == uname -r` |
| `build <patch\|URL>` | Dry-runs the patch, runs `kpatch-build`, signs the module with the MOK key when present |
| `apply <ko> [--persist]` | Checks vermagic, warns if other live patches would be replaced, loads it; `--persist` re-applies on boot via `kpatch.service` |
| `fetch <tag\|URL>` | Download a CI-built module (release `lp-<name>-<kernel>`), verify sha256 and kernel version, sign it locally |
| `status` / `remove <name>` | Show / unload live patches |
| `clean` | Delete kernel sources and build trees to free disk; keeps built modules |
| `mok setup\|status` | Secure Boot: create the module signing key and request enrollment; show enrollment state |
| `canonical enable\|status\|disable` | Ubuntu only: Canonical Livepatch via Ubuntu Pro |

Global options: `-y` (no prompts), `-j N` (build jobs), `--full` (full source history and build vmlinux + modules, ~30 GB; default is small mode, ~8 GB).
Environment: `PLATFORM` (`pve`/`ubuntu`, auto-detected), `PVE_LIVEPATCH_DIR` (default `/var/lib/pve-livepatch`), `PVE_COMMIT`, `KPATCH_REF`, `MOK_KEY`, `MOK_CERT`, `UBUNTU_PRO_TOKEN`.

## Things to know

- **Disk space and build time.** By default the tool runs in **small mode**: it downloads only the one kernel commit it needs, deletes the git checkout once the source is copied, and builds only `vmlinux` (the kernel image, no modules). That needs about **8 GB** and 15–45 minutes for the first build; later builds only recompile what the patch changes. Most CVE fixes live in built-in code. If a fix is in module code, `build` stops and tells you to rerun it with `--full`, which builds all modules too and needs about **30 GB**. `pve-livepatch clean` deletes the sources and build trees afterwards (keeps your built modules). You can also build on a test node with the identical kernel and copy the `.ko` to production.
- **Atomic replace.** kpatch modules replace *all* previously loaded live patches by default, including Canonical's. Make each patch cumulative, or build with `--non-replace`. `apply` warns when this would happen.
- **Secure Boot.** Live-patch modules must be signed with a key the firmware trusts. Run `sudo pve-livepatch mok setup` once: it creates the key (PVE `/var/lib/dkms/mok.{key,pub}`, Ubuntu `/var/lib/shim-signed/mok/MOK.{priv,der}`) and requests enrollment. Enrolling needs **one** reboot to confirm the key in the blue MOK Manager screen; after that, live patches load without rebooting. Copy the same key pair to your other nodes and run `mok setup` there too, so one signed module works everywhere. `check` and `mok status` show whether the key is enrolled, and `apply` refuses unsigned modules on Secure Boot hosts.
- **Disk space.** If the default `/var/lib/pve-livepatch` is too small, point the work directory at a bigger disk: `export PVE_LIVEPATCH_DIR=/mnt/pve/<storage>/pve-livepatch`.
- **The patch must apply to your kernel.** Upstream fixes may need a backport to the PVE/Ubuntu tree; `build` stops if the dry run fails.
- **Not everything can be live patched.** Data-structure layout changes, `__init` code and out-of-tree modules (such as ZFS on PVE) can't. kpatch-build refuses those.
- **It's a bridge, not a replacement.** Still install the real kernel update and reboot later. On a PVE cluster, live-migrate guests off each node first so VMs see no downtime.

## Tests

The [bats](https://github.com/bats-core/bats-core) suite in `tests/` runs without root and without a real kernel: each test gets a fake host (kernel config, `/proc/version`, `/etc/os-release`, `/sys/kernel/livepatch`) and stub `kpatch`, `kpatch-build`, `modinfo`, `gcc`, `mokutil`, `pro`… that record how they were called.

```bash
sudo apt install bats
bats tests/
```

| File | Covers |
|---|---|
| `cli.bats` | help/version, argument errors, PVE vs Ubuntu detection, MOK paths |
| `check.bats` | every readiness check: config options, sysfs, gcc mismatch, Secure Boot |
| `build.bats` | kpatch-build arguments, name sanitising, URL patches, dry-run, signing |
| `mok.bats` | Secure Boot key creation, permissions, enrollment states, no overwriting |
| `source_e2e.bats` | `source` end to end on local git repos / fake apt: Proxmox patches, shallow vs full, cleanup |
| `clean.bats` | freeing disk while keeping modules and patches |
| `fetch.bats` | downloading CI-built modules: checksum, kernel and tag checks, signing, `setup --minimal`, fetch-only `check` |
| `sign.bats` | built-in signer: kernel module signature format, sha512 CMS without attributes, PEM/DER certs |
| `apply.bats` | vermagic/livepatch checks, confirm prompt, `--persist`, atomic-replace warning, status/remove |
| `source.bats` | exact pve-kernel commit lookup, kernelrelease check, Canonical Livepatch |
| `package.bats` | the released `.deb`: name, metadata, contents, ownership, version stamp |

CI runs them on every push and pull request; the release workflow won't publish if a test fails.
For tests, `KREL`, `KCONFIG`, `SYSFS_LP`, `PROC_VERSION` and `OS_RELEASE` can be overridden; don't set them on real hosts.

## License

MIT, see [LICENSE](LICENSE). kpatch itself is GPL-2.0 and is downloaded and built separately.
