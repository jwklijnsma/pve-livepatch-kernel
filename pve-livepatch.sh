#!/usr/bin/env bash
# =============================================================================
# pve-livepatch.sh — live patch the running kernel WITHOUT a reboot on
#                    Proxmox VE (and Ubuntu). Nothing is built on the node:
#
#   GitHub Actions builds every live patch with the kernel's own klp-build,
#   signs it with the module signing key stored as a GitHub secret and
#   publishes it as a release. This tool only downloads, checks and loads:
#
#   setup            – install what loading needs (curl, kmod, mokutil)
#   mok setup        – Secure Boot: enroll the repository's signing
#                      certificate once (one reboot to confirm it)
#   auto enable      – at boot and every 6 h: load the automatic live patch
#                      GitHub built for the running kernel (lp-auto-<kernel>)
#   fetch <tag>      – download one live patch (lp-<name>-<kernel>)
#   apply / status / remove – load, show, unload (plain insmod + sysfs)
#
# Ubuntu only: canonical enable|status|disable – Canonical Livepatch via Ubuntu Pro
# The build side is pve-livepatch-build.sh (used by GitHub Actions).
# =============================================================================
readonly SCRIPT_VERSION="3.0.0"
readonly WORKDIR="${PVE_LIVEPATCH_DIR:-/var/lib/pve-livepatch}"
readonly RELEASE_REPO="${PVE_LIVEPATCH_REPO:-jwklijnsma/pve-livepatch-kernel}"   # where fetch/auto/mok download from
readonly GH_DOWNLOAD="${PVE_LIVEPATCH_GH:-https://github.com}/${RELEASE_REPO}/releases/download"
# paths are overridable so the test suite can point them at fixtures
KREL="${KREL:-$(uname -r)}"; readonly KREL
readonly KCONFIG="${KCONFIG:-/boot/config-${KREL}}"
readonly SYSFS_LP="${SYSFS_LP:-/sys/kernel/livepatch}"
readonly SYS_MODULE="${SYS_MODULE:-/sys/module}"
readonly SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
readonly OS_RELEASE="${OS_RELEASE:-/etc/os-release}"
readonly LP_WAIT="${LP_WAIT:-60}"                     # seconds to wait for a patch transition
# certificate GitHub signs modules with (public); enrolled as MOK on Secure Boot nodes
readonly MOK_CERT="${MOK_CERT:-${WORKDIR}/module-signing.der}"
SELF="${PVE_LIVEPATCH_SELF:-$(readlink -f "${BASH_SOURCE[0]}")}"; readonly SELF
ASSUME_YES=0

# ----------------------------------------------------------------------------- helpers
if [[ -t 1 ]]; then C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[34m'; C_0=$'\e[0m'
else C_R=; C_G=; C_Y=; C_B=; C_0=; fi
log()  { printf '%s==>%s %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '  %s✔%s %s\n'  "$C_G" "$C_0" "$*"; }
warn() { printf '  %s!%s %s\n'  "$C_Y" "$C_0" "$*" >&2; }
bad()  { printf '  %s✘%s %s\n'  "$C_R" "$C_0" "$*" >&2; }
die()  { printf '%sERROR:%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "run as root"; }
need_cmd()  { command -v "$1" >/dev/null 2>&1 || die "'$1' not found — run: $0 setup"; }

confirm() {
  (( ASSUME_YES )) && return 0
  local a; read -r -p "$1 [y/N] " a
  [[ $a =~ ^[Yy]$ ]]
}

cfg_val() { grep -E "^$1=" "$KCONFIG" 2>/dev/null | cut -d= -f2- || true; }
installed_dir() { echo "${WORKDIR}/installed/${KREL}"; }

secure_boot_on() {
  command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null | grep -qi 'enabled'
}

# enrolled | pending | not-enrolled | missing
mok_state() {
  [[ -r $MOK_CERT ]] || { echo missing; return; }
  local out; out=$(mokutil --test-key "$MOK_CERT" 2>&1 || true)
  case $out in
    *"already enrolled"*)                 echo enrolled ;;
    *"already in the enrollment request"*) echo pending ;;
    *)                                    echo not-enrolled ;;
  esac
}

# ----------------------------------------------------------------------------- platform
# PLATFORM = pve | ubuntu
detect_platform() {
  if [[ -n ${PLATFORM:-} ]]; then :
  elif command -v pveversion >/dev/null 2>&1 || [[ $KREL == *-pve ]]; then PLATFORM=pve
  elif [[ -r $OS_RELEASE ]] && grep -qE '^ID="?ubuntu"?$' "$OS_RELEASE"; then PLATFORM=ubuntu
  else die "unsupported platform (need Proxmox VE or Ubuntu); override with PLATFORM=pve|ubuntu"
  fi
  [[ $PLATFORM == pve || $PLATFORM == ubuntu ]] || die "PLATFORM must be pve or ubuntu"
  readonly PLATFORM
}

platform_name() {
  case $PLATFORM in
    pve)    command -v pveversion >/dev/null 2>&1 && pveversion || echo "Proxmox VE" ;;
    ubuntu) sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$OS_RELEASE" | grep . || echo Ubuntu ;;
  esac
}

# live patches loaded that were NOT made by this tool (e.g. Canonical's lkp_*)
foreign_patches() {
  local d n
  for d in "$SYSFS_LP"/*/; do
    [[ -d $d ]] || continue
    n=$(basename "$d")
    [[ $n == livepatch_* ]] || echo "$n"
  done
}

# ----------------------------------------------------------------------------- check
cmd_check() {
  local fail=0
  log "Checking live-patch readiness for kernel ${KREL} (${PLATFORM})"
  ok "$(platform_name)"

  case $PLATFORM in
    pve)    [[ $KREL == *-pve ]] && ok "running a Proxmox kernel" || warn "kernel release does not end in -pve" ;;
    ubuntu) [[ $KREL =~ -(generic|lowlatency|virtual|kvm|aws|azure|gcp|oracle) ]] \
              && ok "running an Ubuntu kernel flavour" || warn "unusual Ubuntu kernel flavour: ${KREL}" ;;
  esac

  [[ -r $KCONFIG ]] || die "kernel config $KCONFIG not found"

  [[ $(cfg_val CONFIG_LIVEPATCH) == y ]] && ok "CONFIG_LIVEPATCH=y" \
    || { bad "CONFIG_LIVEPATCH not enabled — this kernel cannot be live patched"; fail=1; }
  [[ $(cfg_val CONFIG_KLP_BUILD) == y ]] && ok "CONFIG_KLP_BUILD=y (GitHub can build live patches for this kernel)" \
    || { bad "CONFIG_KLP_BUILD not enabled — klp-build needs a kernel >= 6.19 built with it"; fail=1; }
  if [[ $(cfg_val CONFIG_DYNAMIC_FTRACE_WITH_REGS) == y || $(cfg_val CONFIG_DYNAMIC_FTRACE_WITH_ARGS) == y ]]; then
    ok "dynamic ftrace (WITH_REGS/ARGS) available"
  else bad "dynamic ftrace with regs/args missing"; fail=1; fi
  [[ $(cfg_val CONFIG_HAVE_RELIABLE_STACKTRACE) == y ]] && ok "reliable stacktrace (consistency model)" \
    || warn "no reliable stacktrace — patch transitions may stall"
  [[ -d $SYSFS_LP ]] && ok "${SYSFS_LP} present" \
    || { bad "${SYSFS_LP} missing"; fail=1; }

  # secure boot: modules are signed on GitHub; the node must trust that certificate
  if secure_boot_on; then
    warn "Secure Boot enabled — live patches must be signed with an enrolled key"
    case $(mok_state) in
      enrolled)     ok "GitHub signing certificate is enrolled" ;;
      pending)      bad "certificate enrollment is pending — reboot once and confirm it in MOK Manager"; fail=1 ;;
      not-enrolled) bad "GitHub signing certificate is not enrolled — run: $0 mok setup"; fail=1 ;;
      missing)      bad "GitHub signing certificate not downloaded yet — run: $0 mok setup"; fail=1 ;;
    esac
  else ok "Secure Boot off — signatures are not required"
  fi
  [[ -r /sys/kernel/security/lockdown ]] && ok "lockdown: $(< /sys/kernel/security/lockdown)"

  if [[ $PLATFORM == ubuntu ]] && command -v canonical-livepatch >/dev/null 2>&1; then
    warn "Canonical Livepatch is installed — atomic-replace patches from this tool would replace its fixes"
  fi
  for c in curl insmod; do
    if command -v "$c" >/dev/null 2>&1; then ok "${c} available"
    else bad "${c} not found — run: $0 setup"; fail=1; fi
  done

  cmd_status || true
  (( fail == 0 )) && log "${C_G}Ready.${C_0}" || die "host is not ready for live patching (see above)"
}

# ----------------------------------------------------------------------------- setup
cmd_setup() {
  need_root
  local a; for a in "$@"; do [[ $a == --minimal ]] || die "unknown setup option: $a"; done
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  log "Installing what loading live patches needs (nothing is built on this node)"
  apt-get install -y --no-install-recommends curl ca-certificates kmod mokutil
  ok "ready — next: $0 mok setup (Secure Boot), then $0 auto enable"
}

# ----------------------------------------------------------------------------- fetch
# Download a module that GitHub Actions built (see .github/workflows/build-livepatch.yml),
# and check it (checksum, kernel version, livepatch flag, signature). Sets FETCHED_KO.
#   fetch_verified <url> <SHA256SUMS-url|""> <asset-file-name> <name>
fetch_verified() {
  local url=$1 sums=$2 asset=$3 name=$4 out ko want have
  out="$WORKDIR/out/$KREL"; mkdir -p "$out"
  name=$(echo "$name" | tr -c 'A-Za-z0-9_\n' '_' | cut -c1-40)
  ko="$out/livepatch-${name}.ko"

  log "Downloading ${url}"
  curl -fsSL "$url" -o "$ko.part" || { rm -f "$ko.part"; die "download failed: ${url}"; }
  if [[ -n $sums ]]; then
    curl -fsSL "$sums" -o "$out/SHA256SUMS.part" || { rm -f "$ko.part" "$out/SHA256SUMS.part"; die "could not download SHA256SUMS"; }
    want=$(awk -v f="$asset" '{n=$2; sub(/^[*]/,"",n); sub(/^[.][/]/,"",n)} n==f {print $1}' "$out/SHA256SUMS.part")
    rm -f "$out/SHA256SUMS.part"
    [[ -n $want ]] || { rm -f "$ko.part"; die "SHA256SUMS has no entry for ${asset}"; }
    have=$(sha256sum "$ko.part" | cut -d' ' -f1)
    [[ $want == "$have" ]] || { rm -f "$ko.part"; die "checksum mismatch for ${asset} — not using it"; }
    ok "sha256 verified"
  else
    warn "direct URL: no SHA256SUMS to verify against"
  fi

  local vm; vm=$(modinfo -F vermagic "$ko.part" 2>/dev/null | awk '{print $1}')
  [[ $vm == "$KREL" ]] || { rm -f "$ko.part"; die "module is for kernel '${vm:-?}', running ${KREL}"; }
  modinfo -F livepatch "$ko.part" 2>/dev/null | grep -qx Y || { rm -f "$ko.part"; die "${asset} is not a livepatch module"; }
  mv -f "$ko.part" "$ko"
  ok "module matches running kernel ${KREL}"

  if [[ -n $(modinfo -F signer "$ko" 2>/dev/null) ]]; then
    ok "signed by: $(modinfo -F signer "$ko" 2>/dev/null)"
  elif secure_boot_on; then
    die "${asset} is not signed and Secure Boot is on — add the MODULE_SIGNING_PEM secret in GitHub and rebuild (module kept at ${ko})"
  else
    warn "module is not signed (fine while Secure Boot is off)"
  fi
  FETCHED_KO=$ko
}

# Release tags look like lp-<name>-<kernel>, assets livepatch-<name>-<kernel>.ko + SHA256SUMS.
cmd_fetch() {
  need_root; need_cmd curl
  local ref=${1:-} name url sums="" asset
  [[ -n $ref ]] || die "usage: $0 fetch <release-tag|URL-to-.ko>"

  if [[ $ref =~ ^https?:// ]]; then
    url=$ref
    asset=$(basename "${url%%\?*}")
    name=${asset%.ko}; name=${name#livepatch-}; name=${name%-"$KREL"}
  else
    [[ $ref == lp-* ]] || die "'${ref}' is not a live-patch release tag (expected lp-<name>-${KREL})"
    [[ $ref == *-"$KREL" ]] || die "release '${ref}' was not built for this kernel (${KREL})"
    [[ $ref != "lp-auto-${KREL}" ]] || die "automatic patches are handled by: $0 auto"
    name=${ref#lp-}; name=${name%-"$KREL"}
    asset="livepatch-${name}-${KREL}.ko"
    url="${GH_DOWNLOAD}/${ref}/${asset}"
    sums="${GH_DOWNLOAD}/${ref}/SHA256SUMS"
  fi
  fetch_verified "$url" "$sums" "$asset" "$name"
  ok "ready: ${FETCHED_KO}"
  echo "  load it with: $0 apply ${FETCHED_KO} --persist" >&2
  echo "$FETCHED_KO"
}

# ----------------------------------------------------------------------------- auto
# GitHub Actions (.github/workflows/auto-livepatch.yml) builds one cumulative
# live patch from patches/auto/ for every new Proxmox kernel and publishes it
# as release lp-auto-<kernel>, asset livepatch-auto_<patchset-id>-<kernel>.ko.
# The id changes whenever the patch set changes, so a new module never clashes
# with the loaded one and atomically replaces it.
readonly AUTO_UNIT=pve-livepatch-auto

auto_run() {
  need_cmd curl
  local tag="lp-auto-${KREL}" base sums asset name mod f
  base="${GH_DOWNLOAD}/${tag}"
  sums=$(mktemp)
  log "Looking for ${tag} in ${RELEASE_REPO}"
  if ! curl -fsSL "$base/SHA256SUMS" -o "$sums"; then
    rm -f "$sums"
    ok "no automatic live patch for ${KREL} (not published yet, or no network) — nothing to do"
    return 0
  fi
  asset=$(awk '{n=$2; sub(/^[*]/,"",n); sub(/^[.][/]/,"",n)} n ~ /^livepatch-auto_[0-9a-f]+-.*[.]ko$/ {print n}' "$sums" | head -1)
  rm -f "$sums"
  if [[ -z $asset ]]; then
    ok "nothing to patch: every fix in the patch set is already part of ${KREL}"
    return 0
  fi
  name=${asset#livepatch-}; name=${name%-"$KREL".ko}
  [[ $name =~ ^auto_[0-9a-f]+$ && $asset == "livepatch-${name}-${KREL}.ko" ]] \
    || die "unexpected file ${asset} in release ${tag}"
  mod="livepatch_${name}"
  if [[ -d $SYSFS_LP/$mod ]]; then
    ok "up to date: ${mod} is loaded"
    return 0
  fi

  fetch_verified "$base/$asset" "$base/SHA256SUMS" "$asset" "$name"
  ASSUME_YES=1 cmd_apply "$FETCHED_KO" --persist
  # the new module replaced the older automatic ones: stop loading those at boot
  for f in "$(installed_dir)"/livepatch-auto_*.ko "$WORKDIR/out/$KREL"/livepatch-auto_*.ko; do
    if [[ -e $f && $(basename "$f") != "livepatch-${name}.ko" ]]; then rm -f "$f"; fi
  done
  ok "automatic live patch ${mod} is active"
}

auto_enable() {
  write_boot_unit
  cat > "$SYSTEMD_DIR/${AUTO_UNIT}.service" <<EOF
[Unit]
Description=Fetch and load the automatic live patch for the running kernel
Wants=network-online.target
After=network-online.target pve-livepatch.service

[Service]
Type=oneshot
ExecStart=${SELF} -y auto run
EOF
  cat > "$SYSTEMD_DIR/${AUTO_UNIT}.timer" <<EOF
[Unit]
Description=Check for new automatic live patches (pve-livepatch)

[Timer]
OnBootSec=2min
OnUnitActiveSec=6h
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload || true
  systemctl enable pve-livepatch.service >/dev/null 2>&1 || warn "could not enable pve-livepatch.service"
  systemctl enable --now "${AUTO_UNIT}.timer" || die "could not enable ${AUTO_UNIT}.timer"
  ok "automatic live patching on: checks ${RELEASE_REPO} at boot and every 6 hours"
  echo "  run it now:   $0 auto run"
  echo "  see the log:  journalctl -u ${AUTO_UNIT}.service"
}

auto_disable() {
  systemctl disable --now "${AUTO_UNIT}.timer" >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_DIR/${AUTO_UNIT}.service" "$SYSTEMD_DIR/${AUTO_UNIT}.timer"
  systemctl daemon-reload || true
  ok "automatic live patching off (patches that are loaded stay loaded; '$0 remove <name>' unloads one)"
}

cmd_auto() {
  need_root
  local action=${1:-run}
  case $action in
    run)     auto_run ;;
    enable)  auto_enable ;;
    disable) auto_disable ;;
    *)       die "usage: $0 auto [run|enable|disable]" ;;
  esac
}

# ----------------------------------------------------------------------------- loading
# Plain kernel interfaces, no extra tools: insmod loads and enables a live-patch
# module; /sys/kernel/livepatch/<mod>/{enabled,transition} show its state.
module_name() {
  local n; n=$(modinfo -F name "$1" 2>/dev/null || true)
  [[ -n $n ]] || n=$(basename "$1" .ko | tr - _)
  echo "$n"
}

# wait until <mod> finished its transition (enabled) — 0 ok, 1 timeout
wait_enabled() {
  local d="$SYSFS_LP/$1" i
  for (( i = 0; i <= LP_WAIT; i++ )); do
    [[ -f $d/transition && $(< "$d/transition") == 0 ]] && return 0
    sleep 1
  done
  return 1
}

# wait until <mod> is disabled and gone from sysfs — 0 ok, 1 timeout
wait_disabled() {
  local d="$SYSFS_LP/$1" i
  for (( i = 0; i <= LP_WAIT; i++ )); do
    [[ ! -d $d ]] && return 0
    [[ $(cat "$d/enabled" 2>/dev/null) == 0 && $(cat "$d/transition" 2>/dev/null) == 0 ]] && return 0
    sleep 1
  done
  return 1
}

load_module() {
  local ko=$1 mod; mod=$(module_name "$ko")
  if [[ -d $SYSFS_LP/$mod ]]; then ok "${mod} is already loaded"; return 0; fi
  insmod "$ko" || die "insmod $(basename "$ko") failed — see: dmesg | tail"
  if wait_enabled "$mod"; then ok "${mod} enabled"
  else warn "${mod} is still in transition (a task is busy in a patched function); check: $0 status"; fi
}

# modules of patches that an atomic-replace patch disabled: unload them
unload_replaced() {
  local m n
  for m in "$SYS_MODULE"/livepatch_*; do
    [[ -d $m ]] || continue
    n=$(basename "$m")
    [[ -d $SYSFS_LP/$n ]] && continue
    if rmmod "$n" 2>/dev/null; then ok "unloaded replaced patch module ${n}"; fi
  done
}

write_boot_unit() {
  mkdir -p "$SYSTEMD_DIR"
  cat > "$SYSTEMD_DIR/pve-livepatch.service" <<EOF
[Unit]
Description=Load installed live patches for the running kernel (pve-livepatch)
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${SELF} -y boot

[Install]
WantedBy=multi-user.target
EOF
}

# `boot`: load what `apply --persist` installed for this kernel, oldest first
cmd_boot() {
  local dir ko n=0; dir=$(installed_dir)
  [[ -d $dir ]] || { ok "no live patches installed for ${KREL}"; return 0; }
  while IFS= read -r ko; do
    [[ -n $ko ]] || continue
    ( load_module "$ko" ) || warn "could not load $(basename "$ko")"
    n=$((n+1))
  done < <(compgen -G "$dir/*.ko" >/dev/null && ls -tr -- "$dir"/*.ko)
  unload_replaced
  ok "${n} installed live patch(es) processed for ${KREL}"
}

# ----------------------------------------------------------------------------- apply
cmd_apply() {
  need_root; need_cmd insmod
  local ko="" persist=0
  while [[ $# -gt 0 ]]; do
    case $1 in
      --persist) persist=1; shift ;;
      -*)        die "unknown apply option: $1" ;;
      *)         ko=$1; shift ;;
    esac
  done
  [[ -f $ko ]] || die "usage: $0 apply <livepatch-*.ko> [--persist]"

  local vm; vm=$(modinfo -F vermagic "$ko" | awk '{print $1}')
  [[ $vm == "$KREL" ]] || die "module vermagic '${vm}' does not match running kernel '${KREL}'"
  modinfo -F livepatch "$ko" | grep -qx Y || die "$(basename "$ko") is not a livepatch module"
  if secure_boot_on; then
    [[ -n $(modinfo -F signer "$ko" 2>/dev/null) ]] \
      || die "Secure Boot is on and $(basename "$ko") is not signed — GitHub must sign it (MODULE_SIGNING_PEM secret)"
    [[ $(mok_state) == enrolled ]] \
      || warn "GitHub's signing certificate is not enrolled (yet) — run '$0 mok setup'; the kernel will probably reject this module"
  fi

  local foreign; foreign=$(foreign_patches | tr '\n' ' ')
  if [[ -n $foreign ]] && [[ $(modinfo -F livepatch_replace "$ko" 2>/dev/null || echo Y) != N ]]; then
    warn "other live patches are loaded: ${foreign}"
    warn "an atomic-replace patch (klp-build's default) DISABLES them (build with --non-replace to keep them)"
  fi

  confirm "Load $(basename "$ko") into the RUNNING kernel ${KREL}?" || die "aborted"
  log "Loading live patch"
  load_module "$ko"
  unload_replaced
  if (( persist )); then
    install -D -m 0644 "$ko" "$(installed_dir)/$(basename "$ko")"
    write_boot_unit
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable pve-livepatch.service >/dev/null 2>&1 || warn "could not enable pve-livepatch.service"
    ok "installed — loaded again on every boot of ${KREL} (pve-livepatch.service)"
  fi
  cmd_status
}

# ----------------------------------------------------------------------------- status / remove
cmd_status() {
  log "Live patches on ${KREL}"
  local d any=0 f
  for d in "$SYSFS_LP"/*/; do
    [[ -d $d ]] || continue
    any=1
    printf '  %-40s enabled=%s transition=%s\n' "$(basename "$d")" \
      "$(cat "$d/enabled")" "$(cat "$d/transition" 2>/dev/null || echo -)"
  done
  (( any )) || echo "  (none loaded)"
  for f in "$(installed_dir)"/*.ko; do
    [[ -e $f ]] && echo "  loaded at boot: $(basename "$f")"
  done
  [[ -e $SYSTEMD_DIR/${AUTO_UNIT}.timer ]] && echo "  automatic updates: on (${AUTO_UNIT}.timer)"
  echo "  taint: $(< /proc/sys/kernel/tainted)"
}

cmd_remove() {
  need_root
  local name=${1:-}; [[ -n $name ]] || die "usage: $0 remove <livepatch_name>"
  [[ -d $SYSFS_LP/$name || ! -d $SYSFS_LP/livepatch_$name ]] || name="livepatch_$name"
  confirm "Disable and unload live patch '${name}'?" || die "aborted"
  if [[ -d $SYSFS_LP/$name ]]; then
    log "Disabling ${name}"
    echo 0 > "$SYSFS_LP/$name/enabled"
    wait_disabled "$name" || die "${name} is still in transition — try again in a minute"
    ok "${name} disabled"
  else
    warn "${name} is not loaded"
  fi
  if [[ -d $SYS_MODULE/$name ]]; then
    rmmod "$name" && ok "module ${name} unloaded" || warn "could not unload module ${name}"
  fi
  local f; f="$(installed_dir)/livepatch-${name#livepatch_}.ko"
  if [[ -e $f ]]; then rm -f "$f"; ok "no longer loaded at boot"; fi
  cmd_status
}

# ----------------------------------------------------------------------------- mok (Secure Boot)
# GitHub Actions signs every module with the key in the MODULE_SIGNING_PEM
# secret and publishes the public certificate as release "signing-cert".
get_cert() {
  need_cmd curl
  local url="${GH_DOWNLOAD}/signing-cert/module-signing.der"
  mkdir -p "$(dirname "$MOK_CERT")"
  log "Downloading the signing certificate from ${url}"
  curl -fsSL "$url" -o "$MOK_CERT.part" \
    || { rm -f "$MOK_CERT.part"; die "no signing certificate published yet — add the MODULE_SIGNING_PEM secret in GitHub and run a build (see README)"; }
  mv -f "$MOK_CERT.part" "$MOK_CERT"
}

cmd_mok() {
  local action=${1:-status}
  case $action in
    status)
      echo "  certificate: ${MOK_CERT}"
      if secure_boot_on; then ok "Secure Boot enabled — modules must be signed"
      else ok "Secure Boot disabled — signing optional"; fi
      case $(mok_state) in
        enrolled)     ok "certificate is enrolled" ;;
        pending)      warn "enrollment pending — reboot once and confirm it in MOK Manager" ;;
        not-enrolled) warn "certificate is not enrolled — run: $0 mok setup" ;;
        missing)      warn "certificate not downloaded yet — run: $0 mok setup" ;;
      esac ;;
    setup)
      need_root; need_cmd mokutil
      get_cert
      case $(mok_state) in
        enrolled) ok "certificate is already enrolled — nothing to do"; return 0 ;;
        pending)  warn "enrollment already pending — reboot once and confirm it in MOK Manager"; return 0 ;;
      esac
      log "Requesting enrollment — choose a one-time password, you need it at the next boot"
      mokutil --import "$MOK_CERT"
      cat <<EOF

  Next steps (one-time, needs ONE reboot because Secure Boot keys live in firmware):
    1. Reboot this node (live-migrate guests off first).
    2. At the blue "MOK management" screen: Enroll MOK → Continue → Yes,
       enter the password you just chose → Reboot.
    3. Check: $0 mok status   (should say: certificate is enrolled)
  After that, every live patch GitHub builds loads without any reboot.
EOF
      ;;
    *) die "usage: $0 mok setup|status" ;;
  esac
}

# ----------------------------------------------------------------------------- canonical (Ubuntu)
cmd_canonical() {
  [[ $PLATFORM == ubuntu ]] || die "Canonical Livepatch only works on Ubuntu kernels, not on ${PLATFORM}"
  local action=${1:-status}
  case $action in
    enable)
      need_root
      command -v pro >/dev/null 2>&1 || { apt-get update -qq; apt-get install -y ubuntu-pro-client; }
      if ! pro status --format json 2>/dev/null | grep -q '"attached": true'; then
        [[ -n ${UBUNTU_PRO_TOKEN:-} ]] \
          || die "set UBUNTU_PRO_TOKEN (from https://ubuntu.com/pro/dashboard) to attach this machine"
        log "Attaching machine to Ubuntu Pro"
        pro attach "$UBUNTU_PRO_TOKEN" --no-auto-enable
      fi
      if compgen -G "$SYSFS_LP/livepatch_*" >/dev/null; then
        warn "live patches from this tool are loaded; Canonical Livepatch may replace them"
      fi
      log "Enabling Canonical Livepatch"
      pro enable livepatch --assume-yes
      cmd_canonical status ;;
    status)
      if command -v canonical-livepatch >/dev/null 2>&1; then
        canonical-livepatch status --verbose
      else
        warn "Canonical Livepatch not installed (run: $0 canonical enable)"
      fi ;;
    disable)
      need_root
      confirm "Disable Canonical Livepatch on this machine?" || die "aborted"
      pro disable livepatch --assume-yes ;;
    *) die "usage: $0 canonical enable|status|disable" ;;
  esac
}


usage() {
  cat <<EOF
pve-livepatch ${SCRIPT_VERSION} — live patch the running kernel (${KREL}) without a reboot
Live patches are built and signed by GitHub Actions (${RELEASE_REPO}); this node only loads them.

Usage: $0 [-y] <command> [args]

  check                               verify this node can load live patches
  setup                               install what loading needs (curl, kmod, mokutil)
  mok setup|status                    Secure Boot: enroll GitHub's signing certificate (once)
  auto [run|enable|disable]           automatic live patch for every new Proxmox kernel
                                      (enable = at boot + every 6 h)
  fetch <release-tag|URL>             download one live patch (lp-<name>-${KREL}), verify it
  apply <livepatch-*.ko> [--persist]  load into running kernel (persist = load again on boot)
  status                              show loaded live patches
  remove <name>                       disable and unload a live patch
  canonical enable|status|disable     (Ubuntu) Canonical Livepatch via Ubuntu Pro

Options:
  -y        don't ask for confirmation

Env: PVE_LIVEPATCH_REPO (${RELEASE_REPO}), PVE_LIVEPATCH_DIR (${WORKDIR}),
     PLATFORM (pve|ubuntu, auto-detected), UBUNTU_PRO_TOKEN
EOF
}

# ----------------------------------------------------------------------------- main
main() {
  set -Eeuo pipefail
  trap 'die "failed at line $LINENO: $BASH_COMMAND"' ERR
  while [[ $# -gt 0 ]]; do
    case $1 in
      -y|--yes) ASSUME_YES=1; shift ;;
      -h|--help) usage; exit 0 ;;
      -V|--version) echo "$SCRIPT_VERSION"; exit 0 ;;
      *) break ;;
    esac
  done

  cmd=${1:-}; shift || true
  case $cmd in
    ""|help) usage; exit 0 ;;
  esac
  detect_platform
  case $cmd in
    check)     cmd_check ;;
    setup)     cmd_setup "$@" ;;
    fetch)     cmd_fetch "$@" ;;
    auto)      cmd_auto "$@" ;;
    boot)      cmd_boot ;;
    apply)     cmd_apply "$@" ;;
    status)    cmd_status ;;
    remove)    cmd_remove "$@" ;;
    mok)       cmd_mok "$@" ;;
    canonical) cmd_canonical "$@" ;;
    source|build|clean|all)
      die "'${cmd}' is gone: live patches are built by GitHub Actions now (see README; build side: pve-livepatch-build.sh)" ;;
    *) die "unknown command: $cmd (see --help)" ;;
  esac
}

# run main unless the file is being sourced (the test suite sources it)
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
