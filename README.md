# pve-livepatch-kernel

Live patch the **running kernel without a reboot** on **Proxmox VE** (and Ubuntu), the way Ubuntu Pro does it: **everything is built and signed on GitHub, and nothing is compiled or signed on your nodes.**

- **GitHub Actions** builds each live patch with the kernel's own [`scripts/livepatch/klp-build`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/scripts/livepatch/klp-build). It uses the exact Proxmox source, config and compiler for each kernel. It then signs the module with your key, stored as a GitHub secret, and publishes it as a release.
- **The node** (`pve-livepatch`, a few KB plus curl, kmod and mokutil) only downloads it and checks the checksum, kernel version and signature. It then loads it with `insmod`.

klp-build is part of the kernel from **6.19** on, and the kernel must be built with `CONFIG_KLP_BUILD=y`. Proxmox VE 9's 7.x kernels and Ubuntu 26.04 qualify. Older kernels, such as PVE 8's 6.8, can't be patched.

## Set up once

**1. (Optional) signing key → GitHub secret.** Without it, modules are built **unsigned** and load only on nodes with Secure Boot **off**. For Secure Boot nodes, run this on any computer with `openssl` and the [GitHub CLI](https://cli.github.com/):

```bash
./signing/new-signing-key.sh | gh secret set MODULE_SIGNING_PEM -R jwklijnsma/pve-livepatch-kernel
```

Or run `./signing/new-signing-key.sh` on its own and paste the whole output (key and certificate) into **Settings → Secrets and variables → Actions → New repository secret**, name `MODULE_SIGNING_PEM`. Nothing is kept on disk. Anyone who can change this repository's workflows can sign kernel code your nodes trust, so keep write access tight. With a new key, everything is rebuilt and signed with it, and nodes must enroll the new certificate.

**2. Each node:**

```bash
wget https://github.com/jwklijnsma/pve-livepatch-kernel/releases/latest/download/pve-livepatch_<version>_all.deb
sudo apt install ./pve-livepatch_<version>_all.deb
sudo pve-livepatch setup               # curl, kmod, mokutil
sudo pve-livepatch mok setup           # Secure Boot only: enroll GitHub's certificate, reboot ONCE to confirm
sudo pve-livepatch auto enable         # at boot and every 6 h: load the live patch for the running kernel
```

That's all. `sudo pve-livepatch auto run` checks right away, `pve-livepatch status` shows what is loaded, and `journalctl -u pve-livepatch-auto` shows what happened.

## Automatic: a live patch for every new Proxmox kernel

Put the fixes in [`patches/auto/`](patches/auto/). The workflow **auto live patch** checks Proxmox's repository every 6 hours. For each new kernel (the newest 2 by default), it builds **one cumulative, signed module** from every patch there that still applies. Fixes the new kernel already contains are left out automatically. The module is published as release `lp-auto-<kernel>`. When you add or change a patch, or change the signing key, every kernel is rebuilt. Each build takes about 2.5 hours on GitHub's runner.

After you update Proxmox and reboot into a new kernel, the node loads that kernel's live patch by itself as soon as it's published. Each patch set gets its own id in the module name (`livepatch_auto_<id>`), so a new set replaces the old one atomically. Settings are the repository variables `LIVEPATCH_DIST` (default `trixie`) and `LIVEPATCH_KEEP` (default `2`). GitHub pauses scheduled workflows in repositories with no activity for 60 days; re-enable it under Actions if that happens.

## One patch by hand

Go to Actions → **build live patch** → Run workflow. Enter the kernel (`uname -r` of the node), a patch (a URL, or a path in this repo) and a name. The result is release `lp-<name>-<kernel>`. On the node:

```bash
sudo pve-livepatch fetch lp-<name>-<kernel>
sudo pve-livepatch apply /var/lib/pve-livepatch/out/<kernel>/livepatch-<name>.ko --persist
```

To try the flow safely, use `patches/examples/proc-cmdline-demo.patch`: it only appends ` kpatch_demo=1` to `/proc/cmdline`.

## Commands (node)

| Command | What it does |
|---|---|
| `check` | Checks `CONFIG_LIVEPATCH`, `CONFIG_KLP_BUILD`, ftrace, reliable stacktrace, sysfs, Secure Boot and certificate enrollment, curl/insmod |
| `setup` | Installs curl, kmod and mokutil (no compiler, no openssl) |
| `mok setup\|status` | Secure Boot: downloads GitHub's signing certificate (release `signing-cert`) and enrolls it with `mokutil` (one reboot) |
| `auto [run\|enable\|disable]` | Automatic live patches: `run` checks now, `enable` adds a boot + 6-hourly timer |
| `fetch <tag\|URL>` | Downloads one live patch, verifies sha256, kernel version and signature |
| `apply <ko> [--persist]` | Loads it with `insmod`, waits for the transition; `--persist` loads it again on boot via `pve-livepatch.service` |
| `status` / `remove <name>` | Shows live patches / disables one through sysfs and unloads it |
| `canonical enable\|status\|disable` | Ubuntu only: Canonical Livepatch via Ubuntu Pro |

Options: `-y` (no prompts). Environment: `PVE_LIVEPATCH_REPO` (where to download from), `PVE_LIVEPATCH_DIR` (default `/var/lib/pve-livepatch`), `PLATFORM`, `UBUNTU_PRO_TOKEN`.

## Build side (GitHub Actions)

`pve-livepatch-build.sh` is not part of the .deb. GitHub runs it through `ci/build-livepatch.sh` in a Debian container:
- `setup` installs the toolchain.
- `source` prepares the exact Proxmox source: the pve-kernel `bump version to <pkgver>` commit, the ubuntu-kernel submodule and the Proxmox patches. It checks `make kernelrelease` against the kernel.
- `build` runs klp-build and signs the module with `MOK_KEY`/`MOK_CERT`.

The CI script checks first that the compiler matches the one Proxmox used and that the key in `MODULE_SIGNING_PEM` matches its certificate. If a distro tree's objtool doesn't compile with live-patch support (seen in Proxmox 7.0), the matching upstream stable copy is used.

## Things to know

- **Atomic replace.** klp-build makes patches that replace *all* previously loaded live patches, including manual ones and Canonical's, unless built with `--non-replace`. That's why the automatic patch is one cumulative module.
- **The patch must apply to the kernel.** Upstream fixes may need a backport to the Proxmox tree. The build stops if the dry run fails, and a fix the kernel already contains is left out.
- **Not everything can be live patched.** Data-structure layout changes, `__init` code and out-of-tree modules (such as ZFS on PVE) can't. klp-build refuses those.
- **It's a bridge, not a replacement.** Still install the real kernel update and reboot later. On a PVE cluster, live-migrate guests off each node first so VMs see no downtime.

## Tests

The [bats](https://github.com/bats-core/bats-core) suite in `tests/` runs without root and without a real kernel. Each test gets a fake host (kernel config, `/proc/version`, `/etc/os-release`, `/sys/kernel/livepatch`, `/sys/module`, a systemd directory) and stub `insmod`, `rmmod`, `modinfo`, `mokutil`, `curl`, `pro`… that record how they were called. Run it with `sudo apt install bats && bats tests/`.

| File | Covers |
|---|---|
| `cli.bats` | help/version, argument errors, platform detection, no build or key code on the node |
| `check.bats` | every readiness check: config options incl. `CONFIG_KLP_BUILD`, sysfs, Secure Boot and certificate |
| `mok.bats` | downloading and enrolling GitHub's certificate, enrollment states, no private key on the node |
| `fetch.bats` | checksum, kernel, tag and signature checks; `setup` installs no compiler |
| `auto.bats` | automatic patches: no release, nothing to patch, fetch + load, up to date, replacing a set, timer |
| `apply.bats` | insmod loading, transitions, replaced modules, `--persist` + boot service, status/remove |
| `ci.bats` | `ci/discover-kernels.sh` (newest kernels, patch-set ids, signing key required) and `signing/new-signing-key.sh` |
| `build.bats` | builder: klp-build arguments and errors, objtool fallback, URL patches, dry-run, signing |
| `sign.bats` | builder's signer: kernel module signature format, sha512 CMS without attributes, PEM/DER certs |
| `source.bats` / `source_e2e.bats` | builder: exact pve-kernel commit lookup, kernelrelease check, `source` end to end; Canonical Livepatch |
| `clean.bats` | builder: freeing disk |
| `package.bats` | the released `.deb`: metadata, small dependencies, no builder inside, maintainer scripts |

CI runs them on every push and pull request, and the release workflow won't publish if a test fails.

## License

MIT, see [LICENSE](LICENSE). klp-build and objtool are part of the Linux kernel (GPL-2.0) and are used from the kernel source being patched.
