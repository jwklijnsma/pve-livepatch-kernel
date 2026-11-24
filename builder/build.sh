#!/usr/bin/env bash
# Build one cumulative livepatch module for one kernel release, unsigned.
#
# usage: build.sh <kver> <level> <workdir>
#
# Runs without any key; run.sh mounts the repository read-only and only
# <workdir> writable. Steps: shipped artifacts -> source (locked commit) ->
# config/toolchain gate -> catalog -> klp-build -> Gate A -> source bundle.
# Next steps (separate containers): sign-module.sh, qemu-test.sh, then
# publish.sh on the signing host.
#
# Environment:
#   CATALOG          catalog directory (default: ./catalog)
#   JOBS             parallel jobs (default: nproc)
#   BUILDER_IMAGE    builder image id, recorded in the source bundle
source "$(dirname "$0")/lib.sh"
KVER=${1:?kver}; LEVEL=${2:?level}; WORK=${3:?workdir}
CATALOG=${CATALOG:-$PWD/catalog}
JOBS=${JOBS:-$(nproc)}
HERE=$(cd "$(dirname "$0")" && pwd)
require hvpatch-tool make git gawk python3 tar xz
mkdir -p "$WORK"
SHIPPED="$WORK/shipped"; TREE="$WORK/src"; OUT="$WORK/out"
NAME=$(hvpatch-tool module-name --kernel "$KVER" --level "$LEVEL")

# The shipped config already carries the release suffix
# (CONFIG_LOCALVERSION="-1-pve"). An unset LOCALVERSION makes
# scripts/setlocalversion append "+" for a git tree; an empty one does not.
export LOCALVERSION=
# linux_banner contains user@host of the build. In a container the host is
# random per run, which makes the reused original build differ from the
# patched one ("changed data: linux_banner"). Fix both.
export KBUILD_BUILD_USER=hvpatch KBUILD_BUILD_HOST=hvpatch-builder

# The shipped artifacts come from fetch-shipped.sh in its own container;
# run.sh mounts them read-only here.
for f in config System.map Module.symvers build-id vmlinuz modules; do
  [ -e "$SHIPPED/$f" ] || die "missing $SHIPPED/$f (run fetch-shipped.sh first; run.sh does)"
done
"$HERE/fetch-source.sh" "$KVER" "$TREE"
# Left behind by v0.1.0 of this script; it doubles the suffix.
rm -f "$TREE/localversion-pve"

# A fresh output directory: nothing from an earlier build can end up
# signed or published by mistake.
mkdir -p "$OUT"
find "$OUT" -mindepth 1 -delete

log "config and toolchain gate"
cp "$SHIPPED/config" "$TREE/.config"
make -C "$TREE" -s olddefconfig
hvpatch-tool config-check --built "$TREE/.config" --shipped "$SHIPPED/config" | tee "$OUT/config-check.txt"
REL=$(make -C "$TREE" -s kernelrelease)
[ "$REL" = "$KVER" ] || die "tree builds $REL, expected $KVER"

log "resolving catalog"
hvpatch-tool lint --catalog "$CATALOG"
hvpatch-tool resolve --catalog "$CATALOG" --kernel "$KVER" --tree "$TREE" --out "$OUT/resolved.json"
python3 -I -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["patches"]))' "$OUT/resolved.json" > "$OUT/patches.list"
mapfile -t PATCHES < <(grep -v '^$' "$OUT/patches.list" || true)
[ "${#PATCHES[@]}" -gt 0 ] || { log "nothing to livepatch for $KVER"; exit 0; }

CAT_COMMIT=$(git -C "$CATALOG" rev-parse HEAD 2>/dev/null || echo unknown)
if [ "$CAT_COMMIT" != unknown ] && ! git -C "$CATALOG" diff --quiet HEAD -- . 2>/dev/null; then
  CAT_COMMIT="$CAT_COMMIT-dirty"
fi
printf '%s\n' "$CAT_COMMIT" > "$OUT/catalog-commit"

[ -z "$(git -C "$TREE" status --porcelain --untracked-files=no)" ] || die "$TREE has uncommitted changes"

# The original build does not change for a kernel release, so klp-build
# can reuse it (klp-tmp/1-orig in 7.3, klp-tmp/orig in 6.19/7.0), but only
# if it was made with the same config, toolchain and build identity.
STAMP="$TREE/klp-tmp/.hvpatch-orig-stamp"
WANT_STAMP=$(
  echo "user=$KBUILD_BUILD_USER host=$KBUILD_BUILD_HOST"
  sha256sum "$TREE/.config" | cut -d' ' -f1
  gcc --version | head -n1
  rustc --version 2>/dev/null || true
  git -C "$TREE" rev-parse HEAD
)
SC=()
if compgen -G "$TREE/klp-tmp/*orig" >/dev/null; then
  if [ "$(cat "$STAMP" 2>/dev/null)" = "$WANT_STAMP" ]; then
    SC=(--short-circuit=2)
    log "reusing the original build from klp-tmp"
  else
    log "cached original build has a different stamp: rebuilding it"
    rm -rf "$TREE/klp-tmp"
  fi
fi

log "klp-build: ${#PATCHES[@]} patch(es) -> $NAME.ko"
( cd "$TREE" && ./scripts/livepatch/klp-build -j "$JOBS" -T ${SC[@]+"${SC[@]}"} -o "$OUT/$NAME.ko" "${PATCHES[@]}" ) 2>&1 | tee "$OUT/build.log"
printf '%s\n' "$WANT_STAMP" > "$STAMP"
[ -z "$(git -C "$TREE" status --porcelain --untracked-files=no)" ] || die "klp-build left $TREE modified"

# Patched functions as reported by objtool klp diff, e.g.
#   vmlinux.o: changed function: cmdline_proc_show
#   fs/overlayfs/overlay.o: changed function: ovl_fileattr_set
# become vmlinux:cmdline_proc_show and overlay:ovl_fileattr_set.
DIFFLOG=$(compgen -G "$TREE/klp-tmp/*diff/diff.log" | head -n1 || true)
[ -n "$DIFFLOG" ] || die "klp-build left no diff.log in $TREE/klp-tmp"
FUNCS="$OUT/functions.txt"
gawk -F': changed function: ' 'NF == 2 {
    obj = $1; sub(/^.*\//, "", obj); sub(/\.k?o$/, "", obj); gsub(/-/, "_", obj)
    print obj ":" $2
  }' "$DIFFLOG" | sort -u > "$FUNCS"
[ -s "$FUNCS" ] || die "no changed functions in $DIFFLOG"
log "patched functions: $(paste -sd' ' "$FUNCS")"

log "gate A"
hvpatch-tool gate-a --module "$OUT/$NAME.ko" --kernel "$KVER" --expected-name "$NAME" \
  --system-map "$SHIPPED/System.map" --symvers "$SHIPPED/Module.symvers" \
  --modules-dir "$SHIPPED/modules" \
  --functions "$FUNCS" --resolved "$OUT/resolved.json" | tee "$OUT/gate-a.txt"

# GPL-2.0 §3: the module is a derived work of the kernel. Ship its complete
# corresponding source: the patches, the exact kernel source (once per
# kernel commit, shared by all levels), the config, the toolchain versions
# and the scripts used to build it.
log "source bundle"
BASE=$(git -C "$TREE" rev-parse 'HEAD~1')
PATCHED=$(git -C "$TREE" rev-parse HEAD)
mkdir -p "$WORK/cache"
KSRC="$WORK/cache/linux-$KVER-$PATCHED.tar.xz"
if [ ! -s "$KSRC" ]; then
  git -C "$TREE" archive --format=tar --prefix="linux-$KVER/" HEAD | xz -T0 -6 > "$KSRC.tmp"
  mv "$KSRC.tmp" "$KSRC"
fi
cp "$KSRC" "$OUT/"
SRC="$OUT/source"
mkdir -p "$SRC/patches" "$SRC/builder"
i=0
for p in "${PATCHES[@]}"; do
  i=$((i + 1))
  cp "$p" "$SRC/patches/$(printf '%02d' "$i")-$(basename "$(dirname "$p")")-$(basename "$p")"
done
cp "$OUT/resolved.json" "$OUT/config-check.txt" "$OUT/functions.txt" "$SRC/"
cp "$TREE/.config" "$SRC/config"
cp "$HERE"/*.sh "$HERE"/*.py "$HERE/kernels.lock" "$SRC/builder/"
[ -f "$HERE/Containerfile" ] && cp "$HERE/Containerfile" "$SRC/builder/"
cat > "$SRC/SOURCE.md" <<EOF
# Corresponding source of $NAME.ko

- Kernel: $KVER, Proxmox source ${PROXMOX_KERNEL_GIT:-https://git.proxmox.com/git/proxmox-kernel.git}
  tag proxmox/$(pkgver "$KVER"), commit $BASE, with debian/patches applied
  (commit $PATCHED in the build tree). The complete tree is
  $(basename "$KSRC") next to this bundle.
- Livepatch patches, in the order applied: patches/
- Kernel config: config. Toolchain versions: config-check.txt.
- klp-build and objtool: scripts/livepatch and tools/objtool of that tree.
- Build scripts and container definition: builder/ (builder image ${BUILDER_IMAGE:-unknown}).
- Catalog commit: $CAT_COMMIT

Rebuild: builder/run.sh $KVER $LEVEL (see docs/self-hosting.md).
EOF
tar -C "$OUT" --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -czf "$OUT/$NAME.source.tar.gz" source

log "done: unsigned $OUT/$NAME.ko (next: sign-module.sh $KVER $LEVEL $WORK)"
