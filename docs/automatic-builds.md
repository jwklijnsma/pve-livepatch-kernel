# Automatic builds on GitHub Actions

The [`livepatch`](https://github.com/jwklijnsma/pve-livepatch-kernel/blob/main/github/workflows/livepatch.yml) workflow runs every 6
hours, on changes to `catalog/`, `builder/` or the build tool, and by hand
(Actions → livepatch → Run workflow, optionally with kernel releases and
*force*):

1. It reads Proxmox's package lists (`pve-no-subscription`, `pve-test`) and
   takes the newest 2 releases of each series (7.3 and 7.0).
2. A release that is not in [`builder/kernels.lock`](https://github.com/jwklijnsma/pve-livepatch-kernel/blob/main/builder/kernels.lock)
   yet is locked to the commit of Proxmox's release tag on git.proxmox.com,
   committed to `main` (or as a pull request with `LIVEPATCH_LOCK=pr`).
3. A kernel is built when its locked commit, the catalog, the builder or
   the build tool changed since its last publish. `builder/run.sh` runs
   unchanged in the runner: fetch, build (no keys), sign, QEMU test with
   KVM, including the atomic replace of the previous level. One build takes
   a few hours and about 55 GB, which the job makes from the runner's free
   disk.
4. The module goes to ring `canary` of the repository, which lives on the
   branch `klp-repo` and is served on GitHub Pages together with the status
   page, `manifest.pub` and `module-cert.der`. The complete kernel source
   (GPL) is attached to the release `klp-source`.

Promote with Actions → **livepatch-admin** (canary → early → stable), or
revoke a level there. Set `LIVEPATCH_AUTO_PROMOTE=stable` to skip the rings
and serve new builds to every node right away.

**Set up once** (keys, Actions secrets, Pages), on a machine with `gh` and
Rust or a downloaded `hvpatch-tool`:

```bash
builder/ci-setup.sh jwklijnsma/pve-livepatch-kernel        # keys stay in ~/pve-livepatch-keys: back them up
gh workflow run livepatch -R jwklijnsma/pve-livepatch-kernel -f force=true
```

Anyone who can change this repository's workflows can sign modules your
nodes load: keep write access tight. Repository variables for tuning
(series, number of releases, components, QEMU cycles) are listed at the top
of the workflow.
