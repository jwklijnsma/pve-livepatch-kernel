//! Persistent agent state, `/var/lib/hvpatch/state.json`.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    #[default]
    None,
    Fetched,
    Verified,
    Loading,
    Active,
    Reverted,
    Failed,
    /// Reported only, never stored: the state says active, but the kernel
    /// has no livepatch of ours loaded (after a reboot, before the boot
    /// unit has run, or after a manual rmmod).
    Pending,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::None => "none",
            Phase::Fetched => "fetched",
            Phase::Verified => "verified",
            Phase::Loading => "loading",
            Phase::Active => "active",
            Phase::Reverted => "reverted",
            Phase::Failed => "failed",
            Phase::Pending => "pending",
        }
    }
}

/// A load that has started but not finished. If it is still recorded when
/// the agent starts, the host crashed, rebooted or the agent was killed
/// while loading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub level: u32,
    pub sha256: String,
    pub module: String,
    pub started: DateTime<Utc>,
}

/// A module that failed or was interrupted. The timer and the boot unit do
/// not load it again; an explicit `apply` retries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quarantine {
    pub level: u32,
    pub reason: String,
    pub since: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct KernelState {
    /// Highest level ever accepted for this kernel (anti-rollback).
    pub highest_accepted: u32,
    /// Level that should be active; reloaded by the boot unit.
    pub desired_level: Option<u32>,
    /// Set by `revert`; cleared by an explicit `apply`.
    pub held: bool,
    pub phase: Phase,
    pub last_error: Option<String>,
    /// A transition could neither complete nor be reversed: only a reboot
    /// gives a known state again. Cleared by the next state change.
    pub stuck: bool,
    pub signed_by: Option<String>,
    pub updated: Option<DateTime<Utc>>,
    pub attempt: Option<Attempt>,
    /// sha256 of the module -> why it is quarantined.
    pub quarantined: BTreeMap<String, Quarantine>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub kernels: BTreeMap<String, KernelState>,
    /// Highest revocation list sequence accepted; older lists are replays.
    pub revocation_sequence: u64,
}

/// Keep state for this many kernels; older entries are dropped.
const MAX_KERNELS: usize = 16;

impl State {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| {
                format!(
                    "parsing {}. The file is damaged; hvpatch will not guess. Move it away to start \
                     fresh (this loses the anti-rollback history and quarantine of this node)",
                    path.display()
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&mut self, path: &Path) -> Result<()> {
        while self.kernels.len() > MAX_KERNELS {
            let oldest = self.kernels.iter().min_by_key(|(_, k)| k.updated).map(|(n, _)| n.clone()).expect("non-empty");
            self.kernels.remove(&oldest);
        }
        let data = serde_json::to_vec_pretty(self)?;
        write_atomic(path, &data)
    }

    pub fn kernel(&mut self, release: &str) -> &mut KernelState {
        self.kernels.entry(release.to_owned()).or_default()
    }

    pub fn get(&self, release: &str) -> KernelState {
        self.kernels.get(release).cloned().unwrap_or_default()
    }
}

/// Write via temp file + rename so a crash never leaves half a file.
///
/// The temp file gets a random name and is created with O_EXCL|O_NOFOLLOW,
/// so a less privileged user who can write to the directory (e.g. the
/// node_exporter textfile directory) cannot redirect root's write through a
/// planted symlink. rename(2) replaces a symlink at `path` itself instead of
/// following it.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let dir = path.parent().context("path has no parent")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let mut tmp = tempfile::Builder::new()
        .prefix(&format!(".{name}."))
        .suffix(".tmp")
        .tempfile_in(dir)
        .with_context(|| format!("creating temp file in {}", dir.display()))?;
    tmp.write_all(data)?;
    tmp.as_file().set_permissions(std::fs::Permissions::from_mode(0o644))?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error).with_context(|| format!("renaming to {}", path.display()))?;
    // Make the rename itself durable (power loss right after an update).
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_prune() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("state.json");
        let mut s = State::load(&p).unwrap();
        for i in 0..20 {
            let k = s.kernel(&format!("7.3.{i}-1-pve"));
            k.highest_accepted = i;
            k.updated = Some(DateTime::from_timestamp(1_800_000_000 + i as i64, 0).unwrap());
        }
        s.save(&p).unwrap();
        let back = State::load(&p).unwrap();
        assert_eq!(back.kernels.len(), MAX_KERNELS);
        assert!(!back.kernels.contains_key("7.3.0-1-pve"));
        assert_eq!(back.get("7.3.19-1-pve").highest_accepted, 19);
    }

    #[test]
    fn planted_symlinks_are_not_followed() {
        let t = tempfile::tempdir().unwrap();
        let victim = t.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        let target = t.path().join("hvpatch.prom");
        // The old fixed temp name, and the target itself, point at the victim.
        std::os::unix::fs::symlink(&victim, t.path().join(".hvpatch.prom.tmp")).unwrap();
        std::os::unix::fs::symlink(&victim, &target).unwrap();
        write_atomic(&target, b"metrics").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(!std::fs::symlink_metadata(&target).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"metrics");
    }
}
