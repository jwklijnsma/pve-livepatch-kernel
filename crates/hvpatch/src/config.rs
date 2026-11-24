//! Agent configuration, `/etc/hvpatch/hvpatch.toml`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

pub const DEFAULT_CONFIG: &str = "/etc/hvpatch/hvpatch.toml";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Base URL of the release repository (contains `v1/`).
    /// `https://…`, `file:///…` or a plain absolute path.
    pub repository: String,
    /// Release ring of this node: canary, early or stable.
    pub ring: String,
    /// Directory with trusted minisign public keys (`*.pub`).
    pub trusted_keys_dir: PathBuf,
    /// Persistent state and module cache.
    pub state_dir: PathBuf,
    /// node_exporter textfile collector directory; empty disables it.
    pub textfile_dir: Option<PathBuf>,
    /// Executables run after a successful transition. A non-zero exit
    /// reverts the patch.
    pub hooks_dir: PathBuf,
    /// DER certificate the modules are signed with (for `check` / `mok`).
    pub module_cert: Option<PathBuf>,
    /// Seconds to wait for a transition before backing out.
    pub transition_timeout: u64,
    /// Seconds to watch the kernel log after the transition finished.
    pub settle_time: u64,
    /// Reload the previously active module after a reboot into the same
    /// kernel even if its manifest has expired meanwhile.
    pub allow_expired_on_boot: bool,
    /// Allow plain http:// repositories. Integrity is still protected by
    /// the manifest signature, but https is strongly preferred.
    pub allow_http: bool,
    /// HTTP timeout in seconds for one download.
    pub http_timeout: u64,
    /// Seconds a hook may run before it is killed (and counts as failed).
    pub hook_timeout: u64,
    /// Seconds the boot reload waits for another hvpatch run to finish.
    pub boot_lock_wait: u64,
    /// In a Proxmox VE cluster, only one node loads a livepatch at a time
    /// (a cluster-wide lock in pmxcfs). Off: nodes do not coordinate.
    pub cluster_lock: bool,
    /// Where the cluster-wide lock lives (pmxcfs).
    pub cluster_lock_dir: PathBuf,
    /// The timer applies a level only this many hours after it was built.
    /// An explicit `apply` ignores the delay.
    pub delay_hours: u64,
    /// The timer never goes beyond this level (an explicit `apply` can).
    pub pin_level: Option<u32>,
    /// Refuse to load when kprobes or BPF programs are attached to a
    /// function the patch replaces (otherwise only warn).
    pub refuse_on_trace_conflict: bool,
    /// Runtime files for other tools, e.g. the effective kernel version
    /// for vulnerability scanners.
    pub run_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            repository: String::new(),
            ring: "stable".into(),
            trusted_keys_dir: "/etc/hvpatch/trusted.d".into(),
            state_dir: "/var/lib/hvpatch".into(),
            textfile_dir: Some("/var/lib/prometheus/node-exporter".into()),
            hooks_dir: "/etc/hvpatch/hooks.d".into(),
            module_cert: Some("/etc/hvpatch/module-cert.der".into()),
            transition_timeout: 120,
            settle_time: 10,
            allow_expired_on_boot: true,
            allow_http: false,
            http_timeout: 300,
            hook_timeout: 120,
            boot_lock_wait: 300,
            cluster_lock: true,
            cluster_lock_dir: "/etc/pve/priv/lock".into(),
            delay_hours: 0,
            pin_level: None,
            refuse_on_trace_conflict: false,
            run_dir: "/run/hvpatch".into(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let cfg: Config = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if !klp_core::manifest::RINGS.contains(&self.ring.as_str()) {
            bail!("ring must be one of {:?}, got {:?}", klp_core::manifest::RINGS, self.ring);
        }
        if self.transition_timeout < 10 {
            bail!("transition_timeout below 10 s makes no sense: blocked tasks only get a fake signal every 15 s");
        }
        Ok(())
    }

    pub fn transition_timeout(&self) -> Duration {
        Duration::from_secs(self.transition_timeout)
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.state_dir.join("cache")
    }

    /// Last accepted revocation list (+ `.minisig`).
    pub fn revocation_file(&self) -> PathBuf {
        self.state_dir.join("revoked.json")
    }

    pub fn state_file(&self) -> PathBuf {
        self.state_dir.join("state.json")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.state_dir.join("lock")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_gives_defaults() {
        let c = Config::load(Path::new("/nonexistent/hvpatch.toml")).unwrap();
        assert_eq!(c.ring, "stable");
        assert_eq!(c.transition_timeout, 120);
    }

    #[test]
    fn parses_and_validates() {
        let c: Config = toml::from_str("repository = \"https://klp.example.org\"\nring = \"canary\"\n").unwrap();
        c.validate().unwrap();
        let bad: Config = toml::from_str("ring = \"yolo\"").unwrap();
        assert!(bad.validate().is_err());
        assert!(toml::from_str::<Config>("force = true").is_err());
    }
}
