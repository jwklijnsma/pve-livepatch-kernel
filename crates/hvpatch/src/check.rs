//! `hvpatch check`: is this node able to take livepatches?

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use crate::agent::Agent;
use crate::kernel::KernelOps;
use crate::repo::RepoError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Info,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub check: &'static str,
    pub level: Level,
    pub detail: String,
}

pub struct Checker<'a, K: KernelOps> {
    pub agent: &'a Agent<K>,
    /// Filesystem root for /boot, /proc, /sys (tests use a temp tree).
    pub root: PathBuf,
}

/// Kernel options a livepatch needs at runtime.
const REQUIRED: &[(&str, &str)] = &[
    ("CONFIG_LIVEPATCH", "livepatch core"),
    (
        "CONFIG_HAVE_RELIABLE_STACKTRACE",
        "per-task consistency model; without it transitions only finish at kernel exit",
    ),
    ("CONFIG_MODULES", "loadable modules"),
    ("CONFIG_KALLSYMS_ALL", "symbol lookup for livepatch relocations"),
];

/// EFI_GLOBAL_VARIABLE vendor GUID (UEFI spec), owner of SecureBoot.
pub const EFI_GLOBAL_VARIABLE_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

fn secure_boot_var() -> String {
    format!("/sys/firmware/efi/efivars/SecureBoot-{EFI_GLOBAL_VARIABLE_GUID}")
}

impl<K: KernelOps> Checker<'_, K> {
    fn p(&self, rel: &str) -> PathBuf {
        self.root.join(rel.trim_start_matches('/'))
    }

    fn read(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.p(rel)).ok().map(|s| s.trim().to_owned())
    }

    pub fn run(&self) -> Vec<Item> {
        let mut out = Vec::new();
        let mut add = |check, level, detail: String| out.push(Item { check, level, detail });

        let release = match self.agent.kernel.release() {
            Ok(r) => r,
            Err(e) => {
                add("kernel", Level::Fail, format!("{e:#}"));
                return out;
            }
        };
        add("kernel", Level::Info, release.clone());

        match self.agent.kernel.build_id() {
            Ok(Some(id)) => add("build-id", Level::Ok, id),
            _ => add(
                "build-id",
                Level::Warn,
                "kernel build-id not readable from /sys/kernel/notes; manifests bound to a build-id will be rejected"
                    .into(),
            ),
        }

        match self.read(&format!("/boot/config-{release}")) {
            Some(cfg) => {
                let set = |k: &str| cfg.lines().any(|l| l == format!("{k}=y"));
                for (k, why) in REQUIRED {
                    if set(k) {
                        add("kernel-config", Level::Ok, format!("{k}=y"));
                    } else {
                        add("kernel-config", Level::Fail, format!("{k} is not set ({why})"));
                    }
                }
                if set("CONFIG_DYNAMIC_FTRACE_WITH_ARGS") || set("CONFIG_DYNAMIC_FTRACE_WITH_REGS") {
                    add("kernel-config", Level::Ok, "ftrace with args/regs".into());
                } else {
                    add(
                        "kernel-config",
                        Level::Fail,
                        "neither CONFIG_DYNAMIC_FTRACE_WITH_ARGS nor _WITH_REGS is set".into(),
                    );
                }
                if set("CONFIG_MODULE_SIG_FORCE") {
                    add(
                        "kernel-config",
                        Level::Info,
                        "CONFIG_MODULE_SIG_FORCE=y: modules must be signed with a trusted key".into(),
                    );
                }
            }
            None => add(
                "kernel-config",
                Level::Warn,
                format!("/boot/config-{release} not found; cannot check kernel options"),
            ),
        }

        if self.p("/sys/kernel/livepatch").is_dir() {
            add("livepatch-sysfs", Level::Ok, "/sys/kernel/livepatch present".into());
        } else {
            add("livepatch-sysfs", Level::Fail, "/sys/kernel/livepatch missing".into());
        }
        match self.read("/proc/sys/kernel/ftrace_enabled").as_deref() {
            Some("0") => {
                add("ftrace", Level::Fail, "kernel.ftrace_enabled=0: livepatches cannot redirect functions".into())
            }
            Some(_) => add("ftrace", Level::Ok, "ftrace enabled".into()),
            None => add("ftrace", Level::Warn, "kernel.ftrace_enabled not readable".into()),
        }
        if self.read("/proc/sys/kernel/modules_disabled").as_deref() == Some("1") {
            add("modules", Level::Fail, "kernel.modules_disabled=1: no module can be loaded until reboot".into());
        }

        // efivarfs: 4 bytes of attributes, then the value (1 = enabled).
        let secure_boot = std::fs::read(self.p(&secure_boot_var())).ok().and_then(|b| b.get(4).copied()) == Some(1);
        add("secure-boot", Level::Info, if secure_boot { "enabled" } else { "disabled or not EFI" }.into());
        if let Some(l) = self.read("/sys/kernel/security/lockdown") {
            add("lockdown", Level::Info, l);
        }
        if secure_boot {
            out.extend(self.check_mok());
        }

        let mut add = |check, level, detail: String| out.push(Item { check, level, detail });
        let keys: Vec<_> = self.agent.trust.keys().map(|k| format!("{} ({})", k.name, k.key_id)).collect();
        if keys.is_empty() {
            add("trusted-keys", Level::Fail, format!("no keys in {}", self.agent.cfg.trusted_keys_dir.display()));
        } else {
            add("trusted-keys", Level::Ok, keys.join(", "));
        }

        match &self.agent.repo {
            None => add("repository", Level::Fail, "no repository configured".into()),
            Some(r) => {
                let rel = format!("v1/{release}/{}/manifest.json", self.agent.cfg.ring);
                match r.get(&rel, 1 << 20) {
                    Ok(_) => add("repository", Level::Ok, format!("{} has a manifest for this kernel", r.describe())),
                    Err(RepoError::NotFound(_)) => add(
                        "repository",
                        Level::Warn,
                        format!(
                            "{} is reachable but has no manifest for {release} in ring {}",
                            r.describe(),
                            self.agent.cfg.ring
                        ),
                    ),
                    Err(RepoError::Other(e)) => add("repository", Level::Fail, format!("{}: {e:#}", r.describe())),
                }
            }
        }

        if let Ok(patches) = self.agent.kernel.livepatches() {
            for p in patches.iter().filter(|p| !klp_core::naming::is_ours(&p.name)) {
                add(
                    "foreign-livepatch",
                    Level::Warn,
                    format!("{} is loaded and would be replaced by atomic replace", p.name),
                );
            }
        }
        if let Ok(mods) = self.agent.kernel.modules() {
            let lp: Vec<_> = self.agent.kernel.livepatches().unwrap_or_default();
            for m in mods.iter().filter(|m| m.is_livepatch() && m.refcnt > 0 && !lp.iter().any(|p| p.name == m.name)) {
                add(
                    "forced-patch",
                    Level::Fail,
                    format!("{} looks like a force-transitioned livepatch; reboot before loading more", m.name),
                );
            }
        }

        for f in ["/sys/kernel/tracing/kprobe_events", "/sys/kernel/debug/tracing/kprobe_events"] {
            if let Some(ev) = self.read(f) {
                let n = ev.lines().filter(|l| !l.trim().is_empty()).count();
                if n > 0 {
                    add(
                        "tracing",
                        Level::Warn,
                        format!(
                            "{n} kprobe event(s) defined; kretprobes on patched functions conflict with livepatches \
                         and kprobes in replaced functions stop firing"
                        ),
                    );
                }
                break;
            }
        }
        out
    }

    fn check_mok(&self) -> Vec<Item> {
        let item = |level, detail: String| Item { check: "mok", level, detail };
        let Some(cert) = &self.agent.cfg.module_cert else {
            return vec![item(Level::Warn, "Secure Boot is on, but no module_cert is configured".into())];
        };
        if !cert.exists() {
            return vec![item(Level::Fail, format!("module certificate {} not found", cert.display()))];
        }
        match mok_state(cert) {
            Some(MokState::Enrolled) => vec![item(Level::Ok, format!("{} is enrolled", cert.display()))],
            Some(MokState::Pending) => vec![item(
                Level::Warn,
                format!(
                    "{} enrollment is pending: confirm it in MokManager on the next boot (console or BMC); \
                     until then the kernel rejects the modules",
                    cert.display()
                ),
            )],
            Some(MokState::NotEnrolled) => vec![item(
                Level::Fail,
                format!(
                    "{} is not enrolled; the kernel will reject the modules. Run `hvpatch mok enroll` and confirm in MokManager on the next boot",
                    cert.display()
                ),
            )],
            None => vec![item(Level::Warn, "mokutil not available; cannot check MOK enrollment".into())],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MokState {
    Enrolled,
    /// Imported with `mokutil --import`, waiting for confirmation in
    /// MokManager on the next boot.
    Pending,
    NotEnrolled,
}

/// Interpret `mokutil --test-key` output.
pub fn parse_mok_test_key(text: &str) -> MokState {
    if text.contains("already enrolled") {
        MokState::Enrolled
    } else if text.contains("enrollment request") {
        MokState::Pending
    } else {
        MokState::NotEnrolled
    }
}

/// `None` if mokutil is not available.
pub fn mok_state(cert: &Path) -> Option<MokState> {
    let out = Command::new("mokutil").arg("--test-key").arg(cert).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout) + String::from_utf8_lossy(&out.stderr);
    Some(parse_mok_test_key(&text))
}

pub fn worst(items: &[Item]) -> Level {
    items.iter().map(|i| i.level).max().unwrap_or(Level::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::fake::FakeKernel;
    use klp_core::sig::TrustStore;

    fn checker_items(root: &Path, cert: Option<PathBuf>) -> Vec<Item> {
        let cfg = Config { module_cert: cert, repository: String::new(), ..Default::default() };
        let agent = Agent::new(cfg, FakeKernel::new("7.3.5-1-pve"), None, TrustStore::default());
        Checker { agent: &agent, root: root.to_path_buf() }.run()
    }

    #[test]
    fn mokutil_test_key_output() {
        assert_eq!(parse_mok_test_key("/etc/hvpatch/module-cert.der is already enrolled\n"), MokState::Enrolled);
        assert_eq!(
            parse_mok_test_key("/etc/hvpatch/module-cert.der is already in the enrollment request\n"),
            MokState::Pending
        );
        assert_eq!(parse_mok_test_key("/etc/hvpatch/module-cert.der is not enrolled\n"), MokState::NotEnrolled);
    }

    #[test]
    fn detects_secure_boot_from_the_real_efivar_and_requires_mok() {
        let t = tempfile::tempdir().unwrap();
        let var = t.path().join("sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
        std::fs::create_dir_all(var.parent().unwrap()).unwrap();
        // Bytes as read from a Secure Boot host: attributes 0x06, value 1.
        std::fs::write(&var, [0x06, 0x00, 0x00, 0x00, 0x01]).unwrap();

        let items = checker_items(t.path(), Some(t.path().join("missing-cert.der")));
        let sb = items.iter().find(|i| i.check == "secure-boot").unwrap();
        assert_eq!(sb.detail, "enabled");
        let mok = items.iter().find(|i| i.check == "mok").expect("MOK is checked when Secure Boot is on");
        assert_eq!(mok.level, Level::Fail);

        std::fs::write(&var, [0x06, 0x00, 0x00, 0x00, 0x00]).unwrap();
        let items = checker_items(t.path(), None);
        assert_eq!(items.iter().find(|i| i.check == "secure-boot").unwrap().detail, "disabled or not EFI");
        assert!(!items.iter().any(|i| i.check == "mok"));
    }
}
