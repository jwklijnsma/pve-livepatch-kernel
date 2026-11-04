# pve-livepatch-kernel

Live patch the **running kernel without a reboot** on **Proxmox VE** and **Ubuntu**.

`pve-livepatch.sh` uses the kernel's own live-patch builder, [`scripts/livepatch/klp-build`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/scripts/livepatch/klp-build). It turns a kernel source patch (for example a CVE fix from git.kernel.org) into a live-patch module, built against the *exact* source of the kernel you are running. Modules are loaded with plain `insmod` and managed through `/sys/kernel/livepatch`, so no extra tools are needed. On Ubuntu it can also enable Canonical Livepatch for Canonical's official fixes.

klp-build is part of the kernel from **6.19** on, and the kernel must be built with `CONFIG_KLP_BUILD=y`. Proxmox VE 9's 7.x kernels and Ubuntu 26.04 qualify. Older kernels, such as PVE 8's 6.8, can't be patched with this tool.

| Platform | Custom patches (klp-build) | Official vendor live patches |
|---|---|---|
| Proxmox VE (`*-pve`, ≥ 6.19) | ✅ source from `pve-kernel` git + Proxmox patches | ❌ Proxmox does not ship any |
| Ubuntu (`generic`, `lowlatency`, cloud flavours, ≥ 6.19) | ✅ source from `apt-get source` | ✅ `canonical enable` (Ubuntu Pro) |

## Automatic: a live patch for every new Proxmox kernel

This works like Ubuntu Pro: GitHub builds the patches, and your nodes only download a small signed module.

1. **Put the fixes in [`patches/auto/`](patches/auto/).** The workflow **auto live patch** checks Proxmox's repository every 6 hours. For each new kernel (the newest 2 by default), it builds **one cumulative module** from every patch there that still applies. Fixes the new kernel already contains are left out automatically. The module is published as release `lp-auto-<kernel>`. When you add or change a patch, every kernel is rebuilt. Each build takes about 2.5 hours on GitHub's runner.
2. **Turn it on once per node:**
   ```bash
   sudo pve-livepatch setup --minimal     # curl, kmod, openssl, mokutil — no compiler
   sudo pve-livepatch mok setup           # once, if Secure Boot is on (one reboot to enroll the key)
   sudo pve-livepatch auto enable         # at boot and every 6 h: fetch, verify, sign, load
   ```
   After you update Proxmox and reboot into a new kernel, the node loads that kernel's live patch by itself as soon as it's published. `sudo pve-livepatch auto run` checks right away. `journalctl -u pve-livepatch-auto` shows what happened.

Each patch set gets its own id in the module name (`livepatch_auto_<id>`). A new set therefore replaces the old one atomically, without unloading anything first. Settings are the repository variables `LIVEPATCH_DIST` (default `trixie`) and `LIVEPATCH_KEEP` (default `2`). GitHub pauses scheduled workflows in repositories with no activity for 60 days; re-enable it under Actions if that happens.

## One patch by hand: build in GitHub Actions

Go to Actions → **build live patch** → Run workflow. Enter the node's `uname -r` (for example `7.0.14-26-pve`), a patch (a URL, or a path in this repo) and a name. The runner takes the exact kernel config and version from Proxmox's package repository, checks that the compiler is the one Proxmox used, builds with klp-build in a Debian container and publishes release `lp-<name>-<kernel>`. On the node:

```bash
sudo pve-livepatch fetch lp-<name>-<kernel>     # sha256 + kernel check, then signs it
sudo pve-livepatch apply /var/lib/pve-livepatch/out/<kernel>/livepatch-<name>.ko --persist
```

Modules are published **unsigned**, and each node signs them with its own MOK key, so your private key never leaves your nodes. Signing uses only `openssl` and produces exactly the same bytes as the kernel's `scripts/sign-file`. To try the whole flow safely, use `patches/examples/proc-cmdline-demo.patch`: it only appends ` kpatch_demo=1` to `/proc/cmdline`.

## Install

From a release (`.deb`, installs `/usr/sbin/pve-livepatch`):

```bash
wget https://github.com/jwklijnsma/pve-livepatch-kernel/releases/latest/download/pve-livepatch_<version>_all.deb
sudo apt install ./pve-livepatch_<version>_all.deb
```

To build the package yourself, run `packaging/build-deb.sh [version]`; the result goes to `dist/`. Releases are built by GitHub Actions: push a tag `vX.Y.Z`, or run **Actions → release .deb → Run workflow**, which creates the tag for you.

## Build on your own machine

This needs ~30 GB of disk and the same gcc that built the kernel. klp-build compiles the original and the patched kernel, so the first build takes a few hours.

```bash
sudo pve-livepatch check        # can this kernel be live patched?
sudo pve-livepatch setup        # kernel build toolchain
sudo pve-livepatch source       # exact source for `uname -r`
sudo pve-livepatch build fix.patch --name cve_2026_1234
sudo pve-livepatch apply /var/lib/pve-livepatch/out/$(uname -r)/livepatch-cve_2026_1234.ko --persist
sudo pve-livepatch status
```

Or run all of it in one go: `sudo pve-livepatch all <patch-file-or-URL> --name <name>`.

### Ubuntu: Canonical Livepatch

```bash
sudo UBUNTU_PRO_TOKEN=<token> pve-livepatch canonical enable
sudo pve-livepatch canonical status
```

## Commands

| Command | What it does |
|---|---|
| `check` | Checks `CONFIG_LIVEPATCH`, `CONFIG_KLP_BUILD`, ftrace, reliable stacktrace, Secure Boot/MOK, and for local builds gcc and disk space |
| `setup [--minimal]` | Installs the build toolchain; `--minimal` installs only what loading needs (for `fetch`/`auto`) |
| `auto [run\|enable\|disable]` | Automatic live patches from GitHub Actions: `run` checks now, `enable` adds a boot + 6-hourly timer |
| `fetch <tag\|URL>` | Downloads one CI-built module (release `lp-<name>-<kernel>`), verifies sha256 and kernel version, signs it locally |
| `source` | **PVE:** finds the `bump version to <pkgver>` commit in pve-kernel, checks out the ubuntu-kernel submodule, applies `patches/kernel/*`. **Ubuntu:** enables `deb-src` if needed (asks first) and runs `apt-get source`. Both: set `EXTRAVERSION` and verify `make kernelrelease == uname -r` |
| `build <patch\|URL>` | Dry-runs the patch, runs the kernel's `klp-build`, signs the module with the MOK key when present |
| `apply <ko> [--persist]` | Checks vermagic and signature, warns if other live patches would be replaced, then loads it with `insmod`. `--persist` loads it again on boot via `pve-livepatch.service` |
| `status` / `remove <name>` | Show live patches / disable one through sysfs and unload it |
| `clean` | Deletes kernel sources and build trees to free disk; keeps built modules |
| `mok setup\|status` | Secure Boot: creates the module signing key and requests enrollment; shows enrollment state |
| `canonical enable\|status\|disable` | Ubuntu only: Canonical Livepatch via Ubuntu Pro |

Global options:
- `-y` (no prompts)
- `-j N` (build jobs)
- `--full` (full kernel source history; by default only the needed commit is downloaded)

Environment:
- `PLATFORM` (`pve`/`ubuntu`, auto-detected)
- `PVE_LIVEPATCH_DIR` (default `/var/lib/pve-livepatch`)
- `PVE_LIVEPATCH_REPO` (where `fetch`/`auto` download from)
- `PVE_COMMIT`
- `MOK_KEY`, `MOK_CERT`
- `UBUNTU_PRO_TOKEN`

## Things to know

- **Atomic replace.** klp-build makes patches that replace *all* previously loaded live patches, including Canonical's and manual ones, unless built with `--non-replace`. That's why the automatic patch is one cumulative module. `apply` warns when this would happen.
- **Secure Boot.** Live-patch modules must be signed with a key the firmware trusts. Run `sudo pve-livepatch mok setup` once. It creates the key (PVE `/var/lib/dkms/mok.{key,pub}`, Ubuntu `/var/lib/shim-signed/mok/MOK.{priv,der}`) and requests enrollment. Enrolling needs **one** reboot to confirm the key in the blue MOK Manager screen; after that, live patches load without rebooting. Copy the same key pair to your other nodes and run `mok setup` there too.
- **The patch must apply to your kernel.** Upstream fixes may need a backport to the PVE/Ubuntu tree; `build` stops if the dry run fails. A fix the kernel already contains is reported as such.
- **objtool.** If a distro tree carries a klp-build/objtool that doesn't compile (seen in Proxmox 7.0), `build` uses the matching upstream stable copy instead.
- **Not everything can be live patched.** Data-structure layout changes, `__init` code and out-of-tree modules (such as ZFS on PVE) can't. klp-build refuses those.
- **It's a bridge, not a replacement.** Still install the real kernel update and reboot later. On a PVE cluster, live-migrate guests off each node first so VMs see no downtime.

## Tests

The [bats](https://github.com/bats-core/bats-core) suite in `tests/` runs without root and without a real kernel. Each test gets a fake host (kernel config, `/proc/version`, `/etc/os-release`, `/sys/kernel/livepatch`, `/sys/module`, a systemd directory) and stub `insmod`, `rmmod`, `modinfo`, `gcc`, `mokutil`, `curl`, `pro`… that record how they were called.

```bash
sudo apt install bats
bats tests/
```

| File | Covers |
|---|---|
| `cli.bats` | help/version, argument errors, PVE vs Ubuntu detection, MOK paths |
| `check.bats` | every readiness check: config options incl. `CONFIG_KLP_BUILD`, sysfs, gcc, Secure Boot, disk |
| `build.bats` | klp-build arguments and errors, objtool fallback, name sanitising, URL patches, dry-run, signing |
| `apply.bats` | insmod loading, transitions, replaced modules, `--persist` + boot service, status/remove |
| `auto.bats` | automatic patches: no release, nothing to patch, fetch + load, up to date, replacing a set, timer |
| `ci.bats` | `ci/discover-kernels.sh`: newest kernels, patch-set ids, skipping up-to-date releases |
| `fetch.bats` | downloading CI-built modules: checksum, kernel and tag checks, signing, `setup --minimal` |
| `mok.bats` | Secure Boot key creation, permissions, enrollment states, no overwriting |
| `sign.bats` | built-in signer: kernel module signature format, sha512 CMS without attributes, PEM/DER certs |
| `source.bats` / `source_e2e.bats` | exact pve-kernel commit lookup, kernelrelease check, `source` end to end, Canonical Livepatch |
| `clean.bats` | freeing disk while keeping modules and patches |
| `package.bats` | the released `.deb`: name, metadata, dependencies, maintainer scripts |

CI runs them on every push and pull request, and the release workflow won't publish if a test fails.

## License

MIT, see [LICENSE](LICENSE). klp-build and objtool are part of the Linux kernel (GPL-2.0) and are used from the kernel source being patched.
