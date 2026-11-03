# pve-livepatch-kernel

Live patch the **running kernel without a reboot** on **Proxmox VE** and **Ubuntu**.

`pve-livepatch.sh` wraps [kpatch](https://github.com/dynup/kpatch) to turn a kernel source patch (for example a CVE fix from git.kernel.org) into a live-patch module, built against the *exact* source of the kernel you are running. On Ubuntu it can also enable Canonical Livepatch for Canonical's official fixes.

| Platform | Custom patches (kpatch) | Official vendor live patches |
|---|---|---|
| Proxmox VE (`*-pve` kernels) | ✅ source from `pve-kernel` git + Proxmox patches | ❌ Proxmox does not ship any |
| Ubuntu (`generic`, `lowlatency`, cloud flavours) | ✅ source from `apt-get source` | ✅ `canonical enable` (Ubuntu Pro) |

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
| `setup` | Installs build dependencies, builds and installs kpatch from GitHub |
| `source` | **PVE:** finds the `bump version to <pkgver>` commit in pve-kernel, checks out the ubuntu-kernel submodule, applies `patches/kernel/*`. **Ubuntu:** enables `deb-src` if needed (asks first) and runs `apt-get source`. Both: sets `EXTRAVERSION` and verifies `make kernelrelease == uname -r` |
| `build <patch\|URL>` | Dry-runs the patch, runs `kpatch-build`, signs the module with the MOK key when present |
| `apply <ko> [--persist]` | Checks vermagic, warns if other live patches would be replaced, loads it; `--persist` re-applies on boot via `kpatch.service` |
| `status` / `remove <name>` | Show / unload live patches |
| `canonical enable\|status\|disable` | Ubuntu only: Canonical Livepatch via Ubuntu Pro |

Global options: `-y` (no prompts), `-j N` (build jobs).
Environment: `PLATFORM` (`pve`/`ubuntu`, auto-detected), `PVE_LIVEPATCH_DIR` (default `/var/lib/pve-livepatch`), `PVE_COMMIT`, `KPATCH_REF`, `MOK_KEY`, `MOK_CERT`, `UBUNTU_PRO_TOKEN`.

## Things to know

- **Build cost.** The first build compiles the whole original kernel: plan for ~30 GB disk and 30–90 minutes. Build on a test host running the *identical* kernel and gcc, then copy the `.ko` to production and `apply` there.
- **Atomic replace.** kpatch modules replace *all* previously loaded live patches by default, including Canonical's. Make each patch cumulative, or build with `--non-replace`. `apply` warns when this would happen.
- **Secure Boot.** Modules are signed with the MOK key if found: PVE `/var/lib/dkms/mok.{key,pub}`, Ubuntu `/var/lib/shim-signed/mok/MOK.{priv,der}`. The key must be enrolled.
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
| `apply.bats` | vermagic/livepatch checks, confirm prompt, `--persist`, atomic-replace warning, status/remove |
| `source.bats` | exact pve-kernel commit lookup, kernelrelease check, Canonical Livepatch |
| `package.bats` | the released `.deb`: name, metadata, contents, ownership, version stamp |

CI runs them on every push and pull request; the release workflow won't publish if a test fails.
For tests, `KREL`, `KCONFIG`, `SYSFS_LP`, `PROC_VERSION` and `OS_RELEASE` can be overridden; don't set them on real hosts.

## License

MIT, see [LICENSE](LICENSE). kpatch itself is GPL-2.0 and is downloaded and built separately.
