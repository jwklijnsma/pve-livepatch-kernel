#!/usr/bin/env bash
# Build one cumulative livepatch module for one kernel release.
#
# usage: build.sh <kver> <level> <workdir>
#
# Environment:
#   CATALOG          catalog directory (default: ./catalog)
#   MODULE_KEY       module signing key (PEM) for scripts/sign-file
#   MODULE_CERT      matching certificate (DER or PEM)
#   BUILDER_IMAGE    digest of the builder image, recorded in the manifest
#                    (set by run.sh; ALLOW_UNKNOWN_BUILDER=1 to skip)
#   JOBS             parallel jobs (default: nproc)
#
# Steps: shipped artifacts -> source -> config/toolchain gate -> catalog ->
# klp-build -> Gate A -> sign module -> unsigned manifest.
# Next: qemu-test.sh, then sign-manifest.sh (which requires the QEMU pass).
source "$(dirname "$0")/lib.sh"
KVER=${1:?kver}; LEVEL=${2:?level}; WORK=${3:?workdir}
CATALOG=${CATALOG:-$PWD/catalog}
JOBS=${JOBS:-$(nproc)}
HERE=$(cd "$(dirname "$0")" && pwd)
require hvpatch-tool make git gawk python3
if [ -z "${BUILDER_IMAGE:-}" ]; then
  [ "${ALLOW_UNKNOWN_BUILDER:-0}" = 1 ] || die "BUILDER_IMAGE is not set (run via builder/run.sh, or ALLOW_UNKNOWN_BUILDER=1)"
  BUILDER_IMAGE=unknown
fi
mkdir -p "$WORK"
SHIPPED="$WORK/shipped"; TREE="$WORK/src"; OUT="$WORK/out"
mkdir -p "$OUT"
NAME=$(hvpatch-tool module-name --kernel "$KVER" --level "$LEVEL")

# The shipped config already carries the release suffix
# (CONFIG_LOCALVERSION="-1-pve"). An unset LOCALVERSION makes
# scripts/setlocalversion append "+" for a git tree; an empty one does not.
export LOCALVERSION=
# linux_banner contains user@host of the build. In a container the host is
# random per run, which makes the reused original build differ from the
# patched one ("changed data: linux_banner"). Fix both.
export KBUILD_BUILD_USER=hvpatch KBUILD_BUILD_HOST=hvpatch-builder

"$HERE/fetch-source.sh" "$KVER" "$TREE"
# Fetch again unless every artifact the later stages use is there
# (workdirs from older versions lack some of them).
for f in config System.map Module.symvers build-id vmlinuz modules; do
  if [ ! -e "$SHIPPED/$f" ]; then
    TREE="$TREE" "$HERE/fetch-shipped.sh" "$KVER" "$SHIPPED"
    break
  fi
done
# Left behind by v0.1.0 of this script; it doubles the suffix.
rm -f "$TREE/localversion-pve"

log "config and toolchain gate"
cp "$SHIPPED/config" "$TREE/.config"
make -C "$TREE" -s olddefconfig
hvpatch-tool config-check --built "$TREE/.config" --shipped "$SHIPPED/config" | tee "$OUT/config-check.txt"
REL=$(make -C "$TREE" -s kernelrelease)
[ "$REL" = "$KVER" ] || die "tree builds $REL, expected $KVER"

log "resolving catalog"
hvpatch-tool lint --catalog "$CATALOG"
hvpatch-tool resolve --catalog "$CATALOG" --kernel "$KVER" --tree "$TREE" --out "$OUT/resolved.json"
mapfile -t PATCHES < <(python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["patches"]))' "$OUT/resolved.json")
[ "${#PATCHES[@]}" -gt 0 ] && [ -n "${PATCHES[0]}" ] || { log "nothing to livepatch for $KVER"; exit 0; }

log "klp-build: ${#PATCHES[@]} patch(es) -> $NAME.ko"
# The original build does not change for a kernel release, so klp-build
# can reuse it (klp-tmp/1-orig in 7.3, klp-tmp/orig in 6.19/7.0), but only
# if it was made with the same config, toolchain and build identity. A
# cache without a matching stamp (e.g. from 0.1.1) is rebuilt once.
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
( cd "$TREE" && ./scripts/livepatch/klp-build -j "$JOBS" -T ${SC[@]+"${SC[@]}"} -o "$OUT/$NAME.ko" "${PATCHES[@]}" ) 2>&1 | tee "$OUT/build.log"
printf '%s\n' "$WANT_STAMP" > "$STAMP"

# Patched functions as reported by objtool klp diff, e.g.
#   vmlinux.o: changed function: cmdline_proc_show
#   arch/x86/kvm/kvm-amd.o: changed function: svm_foo
# become vmlinux:cmdline_proc_show and kvm_amd:svm_foo.
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

log "signing module"
: "${MODULE_KEY:?MODULE_KEY not set}" "${MODULE_CERT:?MODULE_CERT not set}"
"$TREE/scripts/sign-file" sha512 "$MODULE_KEY" "$MODULE_CERT" "$OUT/$NAME.ko"
rm -f "$OUT/qemu.ok"

log "manifest (unsigned, ring canary)"
BUILD_ID=$(cat "$SHIPPED/build-id" 2>/dev/null || true)
hvpatch-tool manifest --resolved "$OUT/resolved.json" --module "$OUT/$NAME.ko" \
  --level "$LEVEL" --ring canary \
  ${BUILD_ID:+--build-id "$BUILD_ID"} --functions "$FUNCS" \
  --builder-image "$BUILDER_IMAGE" \
  --catalog-commit "$(git -C "$CATALOG" rev-parse HEAD 2>/dev/null || echo unknown)" \
  --out "$OUT/manifest.json"
log "done: $OUT (next: qemu-test.sh $KVER $WORK)"
