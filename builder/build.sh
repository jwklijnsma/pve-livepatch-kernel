#!/usr/bin/env bash
# Build one cumulative livepatch module for one kernel release.
#
# usage: build.sh <kver> <level> <workdir>
#
# Environment:
#   CATALOG          catalog directory (default: ./catalog)
#   MODULE_KEY       module signing key (PEM) for scripts/sign-file
#   MODULE_CERT      matching certificate (DER or PEM)
#   JOBS             parallel jobs (default: nproc)
#
# Steps: shipped artifacts -> source -> config/toolchain gate -> catalog ->
# klp-build -> Gate A -> sign module -> unsigned manifest.
# The manifest is signed in a separate step (sign-manifest.sh), ideally on a
# different machine, after the QEMU stage passed.
source "$(dirname "$0")/lib.sh"
KVER=${1:?kver}; LEVEL=${2:?level}; WORK=${3:?workdir}
CATALOG=${CATALOG:-$PWD/catalog}
JOBS=${JOBS:-$(nproc)}
HERE=$(cd "$(dirname "$0")" && pwd)
require pve-klp-tool make git
mkdir -p "$WORK"
SHIPPED="$WORK/shipped"; TREE="$WORK/src"; OUT="$WORK/out"
mkdir -p "$OUT"
NAME=$(pve-klp-tool module-name --kernel "$KVER" --level "$LEVEL")

"$HERE/fetch-source.sh" "$KVER" "$TREE"
[ -f "$SHIPPED/config" ] || TREE="$TREE" "$HERE/fetch-shipped.sh" "$KVER" "$SHIPPED"

log "config and toolchain gate"
cp "$SHIPPED/config" "$TREE/.config"
make -C "$TREE" -s olddefconfig
pve-klp-tool config-check --built "$TREE/.config" --shipped "$SHIPPED/config" | tee "$OUT/config-check.txt"
REL=$(make -C "$TREE" -s kernelrelease)
if [ "$REL" != "$KVER" ]; then
  # Proxmox sets the "-<abi>-pve" suffix at package build time. M0: confirm
  # the mechanism (EXTRAVERSION vs. localversion) and keep it in one place.
  printf '%s' "${KVER#"$(make -C "$TREE" -s kernelversion)"}" > "$TREE/localversion-pve"
  REL=$(make -C "$TREE" -s kernelrelease)
fi
[ "$REL" = "$KVER" ] || die "tree builds $REL, expected $KVER"

log "resolving catalog"
pve-klp-tool lint --catalog "$CATALOG"
pve-klp-tool resolve --catalog "$CATALOG" --kernel "$KVER" --tree "$TREE" --out "$OUT/resolved.json"
mapfile -t PATCHES < <(python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["patches"]))' "$OUT/resolved.json")
[ "${#PATCHES[@]}" -gt 0 ] || { log "nothing to livepatch for $KVER"; exit 0; }

log "klp-build: ${#PATCHES[@]} patch(es) -> $NAME.ko"
SC=()
# The original build never changes for a kernel release: reuse it.
[ -d "$TREE/klp-tmp/orig" ] && SC=(--short-circuit=2)
( cd "$TREE" && ./scripts/livepatch/klp-build -j "$JOBS" -T "${SC[@]}" -o "$OUT/$NAME.ko" "${PATCHES[@]}" ) 2>&1 | tee "$OUT/build.log"

# Patched functions as reported by objtool klp diff. M0: confirm where
# klp-build keeps this list in klp-tmp and adjust the extraction.
FUNCS="$OUT/functions.txt"
if compgen -G "$TREE/klp-tmp/diff/*.txt" >/dev/null; then
  cat "$TREE"/klp-tmp/diff/*.txt | sort -u > "$FUNCS"
else
  : > "$FUNCS"
fi

FUNC_ARGS=()
[ -s "$FUNCS" ] && FUNC_ARGS=(--functions "$FUNCS")

log "gate A"
pve-klp-tool gate-a --module "$OUT/$NAME.ko" --kernel "$KVER" --expected-name "$NAME" \
  --system-map "$SHIPPED/System.map" --symvers "$SHIPPED/Module.symvers" \
  --modules-dir "$SHIPPED/modules" "${FUNC_ARGS[@]}" | tee "$OUT/gate-a.txt"

log "signing module"
: "${MODULE_KEY:?MODULE_KEY not set}" "${MODULE_CERT:?MODULE_CERT not set}"
"$TREE/scripts/sign-file" sha512 "$MODULE_KEY" "$MODULE_CERT" "$OUT/$NAME.ko"

log "manifest (unsigned, ring canary)"
BUILD_ID=$(cat "$SHIPPED/build-id" 2>/dev/null || true)
pve-klp-tool manifest --resolved "$OUT/resolved.json" --module "$OUT/$NAME.ko" \
  --level "$LEVEL" --ring canary \
  ${BUILD_ID:+--build-id "$BUILD_ID"} "${FUNC_ARGS[@]}" \
  --builder-image "${BUILDER_IMAGE:-unknown}" \
  --catalog-commit "$(git -C "$CATALOG" rev-parse HEAD 2>/dev/null || echo unknown)" \
  --out "$OUT/manifest.json"
log "done: $OUT"
