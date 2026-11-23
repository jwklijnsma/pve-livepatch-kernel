//! `pve-klp check`: is this node able to take livepatches?

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

const SECURE_BOOT_VAR: &str = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-e098032b8c4c";

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

        let secure_boot = std::fs::read(self.p(SECURE_BOOT_VAR)).ok().and_then(|b| b.get(4).copied()) == Some(1);
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
            for p in patches.iter().filter(|p| !p.name.starts_with(klp_core::naming::MODULE_PREFIX)) {
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
        match mok_enrolled(cert) {
            Some(true) => vec![item(Level::Ok, format!("{} is enrolled", cert.display()))],
            Some(false) => vec![item(
                Level::Fail,
                format!(
                    "{} is not enrolled; the kernel will reject the modules. Run `pve-klp mok enroll` and confirm in MokManager on the next boot",
                    cert.display()
                ),
            )],
            None => vec![item(Level::Warn, "mokutil not available; cannot check MOK enrollment".into())],
        }
    }
}

/// `Some(true)` if `mokutil --test-key` reports the key as enrolled.
pub fn mok_enrolled(cert: &Path) -> Option<bool> {
    let out = Command::new("mokutil").arg("--test-key").arg(cert).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout) + String::from_utf8_lossy(&out.stderr);
    Some(text.contains("already enrolled"))
}

pub fn worst(items: &[Item]) -> Level {
    items.iter().map(|i| i.level).max().unwrap_or(Level::Ok)
}
