# Automatic live patches

Every `*.patch` in this folder goes into **one cumulative live patch** that GitHub Actions
(`.github/workflows/auto-livepatch.yml`) builds for each new Proxmox VE kernel, as release
`lp-auto-<kernel>`. Nodes with `pve-livepatch auto enable` download and load it by themselves.

- Add a fix: put its kernel source patch here (e.g. from git.kernel.org stable), named
  `NNNN-short-name.patch`; files are applied in name order. Pushing it rebuilds every kernel.
- A patch that a newer kernel already contains (or that no longer applies) is left out for
  that kernel automatically; the release notes list what went in.
- Remove a patch once every node runs a kernel that has the fix.

`0001-demo-proc-cmdline.patch` is a harmless test: it only appends ` kpatch_demo=1` to
`/proc/cmdline`. Delete it when you add real fixes.
