# Shared fixtures for the bats suite.
#
# Every test gets an isolated fake host under $BATS_TEST_TMPDIR:
#   fake kernel config, /proc/version, /etc/os-release, /sys/kernel/livepatch,
#   a work dir, and stub binaries (gcc, mokutil, modinfo, insmod, …) first on PATH.
# Stubs append their argv to $STUB_LOG so tests can assert what was called.

REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/.." && pwd)"
SCRIPT="$REPO_ROOT/pve-livepatch.sh"            # node: download, check, load
BUILDER="$REPO_ROOT/pve-livepatch-build.sh"     # GitHub Actions: source, klp-build, sign

setup_fake_host() {
  local platform=${1:-pve}
  T="$BATS_TEST_TMPDIR"
  export STUB_LOG="$T/stub.log"; : > "$STUB_LOG"
  export STUB_BIN="$T/bin"; rm -rf "$STUB_BIN" "$T/sys"; mkdir -p "$STUB_BIN"
  export PATH="$STUB_BIN:$PATH"

  export PVE_LIVEPATCH_DIR="$T/work"; mkdir -p "$PVE_LIVEPATCH_DIR"
  export SYSFS_LP="$T/sys/kernel/livepatch"; mkdir -p "$SYSFS_LP"
  export SYS_MODULE="$T/sys/module"; mkdir -p "$SYS_MODULE"
  export SYSTEMD_DIR="$T/etc/systemd/system"
  export PVE_LIVEPATCH_SELF=/usr/sbin/pve-livepatch
  export LP_WAIT=2
  export PROC_VERSION="$T/proc_version"
  export OS_RELEASE="$T/os-release"
  export KCONFIG="$T/config"
  unset PLATFORM MOK_KEY MOK_CERT PVE_COMMIT UBUNTU_PRO_TOKEN PVE_LIVEPATCH_CERT

  case $platform in
    pve)
      export KREL="6.8.12-4-pve"
      printf 'ID=debian\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n' > "$OS_RELEASE"
      stub pveversion 'echo "pve-manager/8.4.1/2a5fa54a8503f96d (running kernel: 6.8.12-4-pve)"'
      ;;
    ubuntu)
      export KREL="6.8.0-45-generic"
      printf 'ID=ubuntu\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n' > "$OS_RELEASE"
      ;;
  esac

  echo "Linux version ${KREL} (build@host) (gcc (Debian 12.2.0-14) 12.2.0, GNU ld 2.40) #1 SMP" > "$PROC_VERSION"
  write_kconfig

  # default stubs: a healthy, live-patchable host with Secure Boot off
  stub gcc       '[[ $1 == -dumpfullversion ]] && echo "${FAKE_GCC:-12.2.0}"'
  stub mokutil '
case $1 in
  --sb-state) echo "SecureBoot ${FAKE_SB:-disabled}" ;;
  --test-key)
    case ${FAKE_MOK:-enrolled} in
      enrolled) echo "$2 is already enrolled" ;;
      pending)  echo "$2 is already in the enrollment request" ;;
      *)        echo "$2 is not enrolled" ;;
    esac ;;
  *) log_call mokutil "$@" ;;
esac'
  stub systemctl 'log_call systemctl "$@"'
  # insmod of a live-patch module: the kernel creates its sysfs entries
  stub insmod '
log_call insmod "$@"
[[ -n ${FAKE_INSMOD_FAIL:-} ]] && { echo "insmod: ERROR: could not insert module: Key was rejected by service" >&2; exit 1; }
n=$(basename "$1" .ko); n=${n//-/_}
mkdir -p "$SYS_MODULE/$n" "$SYSFS_LP/$n"
echo 1 > "$SYSFS_LP/$n/enabled"; echo "${FAKE_TRANSITION:-0}" > "$SYSFS_LP/$n/transition"'
  stub rmmod 'log_call rmmod "$@"; rm -rf "$SYS_MODULE/$1"'
  stub modinfo '
field=$2
case $field in
  vermagic)          echo "${FAKE_VERMAGIC:-$KREL} SMP preempt mod_unload modversions" ;;
  livepatch)         echo "${FAKE_LIVEPATCH-Y}" ;;
  livepatch_replace) echo "${FAKE_REPLACE:-Y}" ;;
  signer)            echo "${FAKE_SIGNER-pve-livepatch module signing key}" ;;
esac'
}

write_kconfig() {
  cat > "$KCONFIG" <<'EOF'
CONFIG_MODULES=y
CONFIG_LIVEPATCH=y
CONFIG_KLP_BUILD=y
CONFIG_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_HAVE_RELIABLE_STACKTRACE=y
CONFIG_KALLSYMS_ALL=y
EOF
}

# stub NAME 'bash body'  — creates an executable on PATH
stub() {
  local name=$1 body=$2
  {
    printf '%s\n' '#!/usr/bin/env bash'
    printf '%s\n' 'log_call() { printf "%s\n" "$*" >> "$STUB_LOG"; }'
    printf '%s\n' "$body"
  } > "$STUB_BIN/$name"
  chmod +x "$STUB_BIN/$name"
}

# fake loaded live patch in sysfs
add_livepatch() {
  mkdir -p "$SYSFS_LP/$1"
  echo "${2:-1}" > "$SYSFS_LP/$1/enabled"
  echo 0 > "$SYSFS_LP/$1/transition"
}

# run the CLI with the real strict-mode main(), only the root check bypassed
lp() {
  bash -c 'source "$1"; shift; need_root() { :; }; main "$@"' _ "$SCRIPT" "$@"
}

# run the builder CLI the same way
lpb() {
  bash -c 'source "$1"; shift; need_root() { :; }; main "$@"' _ "$BUILDER" "$@"
}

# run a snippet with the builder's functions loaded (no main)
in_builder() {
  bash -c 'set -Eeuo pipefail; source "$1"; need_root() { :; }; eval "$2"' _ "$BUILDER" "$1"
}

# run a snippet with the script's functions loaded (no main)
in_script() {
  bash -c 'set -Eeuo pipefail; source "$1"; need_root() { :; }; eval "$2"' _ "$SCRIPT" "$1"
}

assert_success() { [[ $status -eq 0 ]] || { echo "expected success, got $status"; echo "$output"; return 1; }; }
assert_failure() { [[ $status -ne 0 ]] || { echo "expected failure, got 0"; echo "$output"; return 1; }; }
assert_output_contains() { [[ $output == *"$1"* ]] || { echo "output does not contain: $1"; echo "---"; echo "$output"; return 1; }; }
refute_output_contains() { [[ $output != *"$1"* ]] || { echo "output unexpectedly contains: $1"; echo "---"; echo "$output"; return 1; }; }
assert_called() { grep -qxF -- "$1" "$STUB_LOG" || { echo "not called: $1"; echo "--- calls:"; cat "$STUB_LOG"; return 1; }; }
refute_called_match() { ! grep -q -- "$1" "$STUB_LOG" || { echo "unexpected call matching: $1"; cat "$STUB_LOG"; return 1; }; }

# real throw-away MOK key pair (DER cert, like PVE's /var/lib/dkms/mok.pub)
make_test_key() {
  export MOK_KEY="$BATS_TEST_TMPDIR/mok.key" MOK_CERT="$BATS_TEST_TMPDIR/mok.pub"
  openssl req -new -x509 -nodes -days 30 -newkey rsa:2048 -subj "/CN=bats test key/" \
    -keyout "$MOK_KEY" -outform DER -out "$MOK_CERT" >/dev/null 2>&1
}
