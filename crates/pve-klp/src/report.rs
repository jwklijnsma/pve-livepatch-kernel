//! `pve-klp status`: human output, JSON, Prometheus textfile, exit code.

use std::fmt::Write as _;

use anyhow::Result;
use chrono::{DateTime, Utc};
use klp_core::manifest::NotCovered;
use klp_core::naming::{MODULE_PREFIX, level_from_module_name};
use serde::Serialize;

use crate::agent::Agent;
use crate::kernel::KernelOps;
use crate::state::{Phase, State};

/// Exit codes of `pve-klp status`, stable for monitoring and Ansible.
pub mod exit {
    pub const OK: i32 = 0;
    pub const REBOOT_REQUIRED: i32 = 10;
    pub const NOT_ACTIVE: i32 = 11;
    pub const EXPIRED: i32 = 12;
    pub const FAILED: i32 = 20;
}

#[derive(Debug, Serialize)]
pub struct ActiveInfo {
    pub module: String,
    pub level: Option<u32>,
    pub transition: bool,
    pub functions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ManifestInfo {
    pub level: u32,
    pub ring: String,
    pub signed_by: String,
    pub built: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub age_days: i64,
    pub expired: bool,
    pub superseded_by_kernel: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub kernel: String,
    pub kernel_build_id: Option<String>,
    pub ring: String,
    pub phase: Phase,
    pub held: bool,
    pub highest_accepted: u32,
    pub active: Option<ActiveInfo>,
    pub foreign_patches: Vec<String>,
    pub manifest: Option<ManifestInfo>,
    pub covered: Vec<String>,
    pub not_covered: Vec<NotCovered>,
    pub reboot_required: bool,
    pub reboot_reasons: Vec<String>,
    pub last_error: Option<String>,
}

pub fn collect<K: KernelOps>(agent: &Agent<K>) -> Result<StatusReport> {
    let kernel = agent.kernel.release()?;
    let state = State::load(&agent.cfg.state_file())?;
    let ks = state.get(&kernel);
    let patches = agent.kernel.livepatches()?;
    let now = (agent.now)();

    let ours = patches
        .iter()
        .filter(|p| p.name.starts_with(MODULE_PREFIX) && p.enabled)
        .max_by_key(|p| level_from_module_name(&p.name));
    let active = ours.map(|p| ActiveInfo {
        module: p.name.clone(),
        level: level_from_module_name(&p.name),
        transition: p.transition,
        functions: agent.kernel.patched_functions(&p.name).unwrap_or_default().into_iter().map(|(f, _)| f).collect(),
    });
    let foreign_patches =
        patches.iter().filter(|p| !p.name.starts_with(MODULE_PREFIX)).map(|p| p.name.clone()).collect();

    let level = active.as_ref().and_then(|a| a.level).or(ks.desired_level);
    let cached = level.and_then(|l| agent.cached_manifest(&kernel, l));

    let mut reboot_reasons = Vec::new();
    let (manifest, covered, not_covered) = match &cached {
        Some((m, signer)) => {
            if let Some(k) = &m.superseded_by_kernel {
                reboot_reasons.push(format!("kernel {k} is available and contains all fixes natively"));
            }
            if !m.not_covered.is_empty() {
                let ids: Vec<_> = m.not_covered.iter().map(|n| n.id.as_str()).collect();
                reboot_reasons.push(format!("not fixable by livepatch: {}", ids.join(", ")));
            }
            (
                Some(ManifestInfo {
                    level: m.level,
                    ring: m.ring.clone(),
                    signed_by: signer.clone(),
                    built: m.built,
                    expires: m.expires,
                    age_days: (now - m.built).num_days(),
                    expired: now >= m.expires,
                    superseded_by_kernel: m.superseded_by_kernel.clone(),
                }),
                m.fixes.iter().map(|f| f.id.clone()).collect(),
                m.not_covered.clone(),
            )
        }
        None => (None, vec![], vec![]),
    };
    if ks.phase == Phase::Failed {
        reboot_reasons.push("the last livepatch operation failed; see last_error".into());
    }

    Ok(StatusReport {
        kernel,
        kernel_build_id: agent.kernel.build_id()?,
        ring: agent.cfg.ring.clone(),
        phase: ks.phase,
        held: ks.held,
        highest_accepted: ks.highest_accepted,
        active,
        foreign_patches,
        manifest,
        covered,
        not_covered,
        reboot_required: !reboot_reasons.is_empty(),
        reboot_reasons,
        last_error: ks.last_error,
    })
}

impl StatusReport {
    pub fn exit_code(&self) -> i32 {
        if self.phase == Phase::Failed || self.active.as_ref().is_some_and(|a| a.transition) {
            exit::FAILED
        } else if self.manifest.as_ref().is_some_and(|m| m.expired) {
            exit::EXPIRED
        } else if self.active.is_none() {
            exit::NOT_ACTIVE
        } else if self.reboot_required {
            exit::REBOOT_REQUIRED
        } else {
            exit::OK
        }
    }

    pub fn to_text(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "kernel:        {}", self.kernel);
        let _ = writeln!(s, "build-id:      {}", self.kernel_build_id.as_deref().unwrap_or("unknown"));
        let _ = writeln!(s, "ring:          {}", self.ring);
        let _ = writeln!(
            s,
            "state:         {}{}",
            self.phase.as_str(),
            if self.held { " (on hold after revert)" } else { "" }
        );
        match &self.active {
            Some(a) => {
                let _ = writeln!(
                    s,
                    "livepatch:     {} (level {}){}",
                    a.module,
                    a.level.map(|l| l.to_string()).unwrap_or("?".into()),
                    if a.transition { ", TRANSITION IN PROGRESS" } else { "" }
                );
                let _ = writeln!(s, "functions:     {}", a.functions.len());
            }
            None => {
                let _ = writeln!(s, "livepatch:     none active");
            }
        }
        if !self.foreign_patches.is_empty() {
            let _ = writeln!(s, "foreign:       {}", self.foreign_patches.join(", "));
        }
        if let Some(m) = &self.manifest {
            let _ = writeln!(
                s,
                "manifest:      level {}, signed by {}, built {} ({} days ago), expires {}{}",
                m.level,
                m.signed_by,
                m.built.format("%Y-%m-%d %H:%M"),
                m.age_days,
                m.expires.format("%Y-%m-%d"),
                if m.expired { " - EXPIRED" } else { "" }
            );
        }
        if !self.covered.is_empty() {
            let _ = writeln!(s, "fixed live:    {}", self.covered.join(", "));
        }
        for n in &self.not_covered {
            let _ = write!(s, "NOT covered:   {} ({})", n.id, n.reason);
            if let Some(k) = &n.fixed_in {
                let _ = write!(s, ", fixed in {k}");
            }
            if let Some(mi) = &n.mitigation {
                let _ = write!(s, "; mitigation: {mi}");
            }
            s.push('\n');
        }
        if self.reboot_required {
            let _ = writeln!(s, "reboot:        REQUIRED");
            for r in &self.reboot_reasons {
                let _ = writeln!(s, "               - {r}");
            }
        } else {
            let _ = writeln!(s, "reboot:        not required by known fixes");
        }
        if let Some(e) = &self.last_error {
            let _ = writeln!(s, "last error:    {}", e.replace('\n', "\n               "));
        }
        s
    }

    pub fn to_prometheus(&self) -> String {
        let esc = |v: &str| v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
        let mut s = String::new();
        let _ = writeln!(
            s,
            "# HELP pve_klp_info Kernel, ring and agent state.\n# TYPE pve_klp_info gauge\n\
             pve_klp_info{{kernel=\"{}\",ring=\"{}\",state=\"{}\"}} 1",
            esc(&self.kernel),
            esc(&self.ring),
            self.phase.as_str()
        );
        let mut g = |name: &str, help: &str, v: String| {
            let _ = writeln!(s, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
        };
        let level = self.active.as_ref().and_then(|a| a.level).unwrap_or(0);
        g("pve_klp_active_level", "Active livepatch level, 0 if none.", level.to_string());
        g(
            "pve_klp_transition_in_progress",
            "1 while a livepatch transition is running.",
            (self.active.as_ref().is_some_and(|a| a.transition) as u8).to_string(),
        );
        g("pve_klp_failed", "1 if the last operation failed.", ((self.phase == Phase::Failed) as u8).to_string());
        g(
            "pve_klp_reboot_required",
            "1 if a reboot into a newer kernel is required.",
            (self.reboot_required as u8).to_string(),
        );
        g("pve_klp_cves_covered", "CVEs fixed by the active livepatch.", self.covered.len().to_string());
        g(
            "pve_klp_cves_not_covered",
            "Known CVEs for this kernel that need a reboot.",
            self.not_covered.len().to_string(),
        );
        if let Some(m) = &self.manifest {
            g(
                "pve_klp_manifest_built_timestamp_seconds",
                "Build time of the manifest.",
                m.built.timestamp().to_string(),
            );
            g(
                "pve_klp_manifest_expiry_timestamp_seconds",
                "Expiry of the manifest.",
                m.expires.timestamp().to_string(),
            );
        }
        s
    }

    /// Write the node_exporter textfile atomically.
    pub fn write_textfile(&self, dir: &std::path::Path) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }
        crate::state::write_atomic(&dir.join("pve_klp.prom"), self.to_prometheus().as_bytes())
    }
}
