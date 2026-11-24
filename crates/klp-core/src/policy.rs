//! The decision whether a verified manifest may be applied on this node.
//!
//! Signature and hash checks happen before this; this module only decides
//! on the *content* of an authentic manifest.

use chrono::{DateTime, Duration, Utc};

use crate::manifest::Manifest;

/// How the agent got here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `hvpatch apply` or the auto timer: fresh manifest from the repo.
    Fetch,
    /// Boot unit: reload the module that was active before the reboot,
    /// from the local cache, into the same kernel.
    BootFromCache,
}

#[derive(Debug, Clone)]
pub struct NodeFacts {
    pub kernel_release: String,
    pub kernel_build_id: Option<String>,
    pub ring: String,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct Context {
    /// Highest level ever accepted for this kernel on this node (persisted).
    /// Survives `revert`, so a revert cannot be abused to roll back.
    pub highest_accepted: u32,
    /// Level of the livepatch currently enabled, if any of ours is.
    pub active_level: Option<u32>,
    /// Operator ran `revert`; nothing is loaded automatically until an
    /// explicit `apply`.
    pub held: bool,
    /// The operator explicitly asked for this run (not timer, not boot).
    pub explicit: bool,
    /// `apply --level N`: only accept exactly this level.
    pub requested_level: Option<u32>,
    /// Policy for expired manifests in [`Mode::BootFromCache`].
    pub allow_expired_on_boot: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Apply {
        warnings: Vec<String>,
    },
    AlreadyActive,
    /// Not an error: e.g. held after revert.
    Skip(String),
    Reject(Rejection),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Rejection {
    #[error("manifest is for kernel {manifest}, running kernel is {running}")]
    KernelMismatch { manifest: String, running: String },
    #[error("manifest is bound to kernel build-id {manifest}, running kernel has {running}")]
    BuildIdMismatch { manifest: String, running: String },
    #[error("manifest is bound to a kernel build-id, but the running kernel's build-id is unknown")]
    BuildIdUnknown,
    #[error("manifest is for ring {manifest}, node is in ring {node}")]
    RingMismatch { manifest: String, node: String },
    #[error("manifest expired at {0}")]
    Expired(DateTime<Utc>),
    #[error("manifest level {offered} is lower than level {highest} already accepted on this node (rollback)")]
    Rollback { offered: u32, highest: u32 },
    #[error("manifest level {offered} is lower than the active level {active}")]
    Downgrade { offered: u32, active: u32 },
    #[error("repository offers level {offered}, but level {requested} was requested")]
    LevelNotOffered { offered: u32, requested: u32 },
    #[error("manifest was built at {0}, which is in the future; check the node clock")]
    FromTheFuture(DateTime<Utc>),
}

/// Allowed clock skew between builder and node.
const MAX_SKEW: Duration = Duration::hours(1);

pub fn decide(m: &Manifest, node: &NodeFacts, ctx: &Context, mode: Mode) -> Decision {
    use Rejection::*;
    let reject = |r| Decision::Reject(r);
    let mut warnings = Vec::new();

    if m.kernel != node.kernel_release {
        return reject(KernelMismatch { manifest: m.kernel.clone(), running: node.kernel_release.clone() });
    }
    if let Some(want) = &m.kernel_build_id {
        match &node.kernel_build_id {
            None => return reject(BuildIdUnknown),
            Some(have) if !have.eq_ignore_ascii_case(want) => {
                return reject(BuildIdMismatch { manifest: want.clone(), running: have.clone() });
            }
            Some(_) => {}
        }
    }
    if m.ring != node.ring {
        return reject(RingMismatch { manifest: m.ring.clone(), node: node.ring.clone() });
    }
    if m.built > node.now + MAX_SKEW {
        return reject(FromTheFuture(m.built));
    }
    if node.now >= m.expires {
        match mode {
            Mode::BootFromCache if ctx.allow_expired_on_boot => warnings.push(format!(
                "manifest expired at {}; reloading the previously active module anyway, \
                 because running without it is not safer. No newer patches are coming: \
                 schedule the kernel update.",
                m.expires
            )),
            _ => return reject(Expired(m.expires)),
        }
    }
    if let Some(req) = ctx.requested_level {
        if req != m.level {
            return reject(LevelNotOffered { offered: m.level, requested: req });
        }
    }
    if m.level < ctx.highest_accepted {
        return reject(Rollback { offered: m.level, highest: ctx.highest_accepted });
    }
    match ctx.active_level {
        Some(a) if a == m.level => return Decision::AlreadyActive,
        Some(a) if a > m.level => return reject(Downgrade { offered: m.level, active: a }),
        _ => {}
    }
    if ctx.held && !ctx.explicit {
        return Decision::Skip("livepatching is on hold after `hvpatch revert`; run `hvpatch apply` to resume".into());
    }
    let days_left = (m.expires - node.now).num_days();
    if (0..7).contains(&days_left) {
        warnings.push(format!("manifest expires in {days_left} day(s)"));
    }
    Decision::Apply { warnings }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            format: 1,
            kernel: "7.3.5-1-pve".into(),
            kernel_build_id: Some("aabb".into()),
            level: 3,
            ring: "stable".into(),
            module: "klp_hvp_7_3_5_1_p3.ko".into(),
            module_name: "klp_hvp_7_3_5_1_p3".into(),
            sha256: "0".repeat(64),
            built: "2026-11-23T09:00:00Z".parse().unwrap(),
            expires: "2026-12-23T09:00:00Z".parse().unwrap(),
            fixes: vec![],
            not_covered: vec![],
            superseded_by_kernel: None,
            builder_image: None,
            catalog_commit: None,
        }
    }

    fn node() -> NodeFacts {
        NodeFacts {
            kernel_release: "7.3.5-1-pve".into(),
            kernel_build_id: Some("AABB".into()),
            ring: "stable".into(),
            now: "2026-11-24T00:00:00Z".parse().unwrap(),
        }
    }

    fn ok(d: Decision) -> bool {
        matches!(d, Decision::Apply { .. })
    }

    #[test]
    fn happy_path() {
        assert!(ok(decide(&manifest(), &node(), &Context::default(), Mode::Fetch)));
    }

    #[test]
    fn other_kernel_is_rejected() {
        let mut n = node();
        n.kernel_release = "7.3.6-1-pve".into();
        assert!(matches!(
            decide(&manifest(), &n, &Context::default(), Mode::Fetch),
            Decision::Reject(Rejection::KernelMismatch { .. })
        ));
    }

    #[test]
    fn rebuilt_kernel_with_same_release_is_rejected() {
        let mut n = node();
        n.kernel_build_id = Some("ccdd".into());
        assert!(matches!(
            decide(&manifest(), &n, &Context::default(), Mode::Fetch),
            Decision::Reject(Rejection::BuildIdMismatch { .. })
        ));
        n.kernel_build_id = None;
        assert_eq!(
            decide(&manifest(), &n, &Context::default(), Mode::Fetch),
            Decision::Reject(Rejection::BuildIdUnknown)
        );
    }

    #[test]
    fn expired_is_rejected_on_fetch_but_reloaded_on_boot() {
        let mut n = node();
        n.now = "2027-01-01T00:00:00Z".parse().unwrap();
        let ctx = Context { allow_expired_on_boot: true, ..Default::default() };
        assert!(matches!(decide(&manifest(), &n, &ctx, Mode::Fetch), Decision::Reject(Rejection::Expired(_))));
        match decide(&manifest(), &n, &ctx, Mode::BootFromCache) {
            Decision::Apply { warnings } => assert!(warnings[0].contains("expired")),
            d => panic!("{d:?}"),
        }
        let strict = Context { allow_expired_on_boot: false, ..Default::default() };
        assert!(matches!(decide(&manifest(), &n, &strict, Mode::BootFromCache), Decision::Reject(_)));
    }

    #[test]
    fn rollback_below_highest_accepted_is_rejected_even_after_revert() {
        let ctx = Context { highest_accepted: 4, active_level: None, held: true, explicit: true, ..Default::default() };
        assert_eq!(
            decide(&manifest(), &node(), &ctx, Mode::Fetch),
            Decision::Reject(Rejection::Rollback { offered: 3, highest: 4 })
        );
    }

    #[test]
    fn same_level_is_noop_and_lower_active_upgrades() {
        let ctx = Context { highest_accepted: 3, active_level: Some(3), ..Default::default() };
        assert_eq!(decide(&manifest(), &node(), &ctx, Mode::Fetch), Decision::AlreadyActive);
        let ctx = Context { highest_accepted: 2, active_level: Some(2), ..Default::default() };
        assert!(ok(decide(&manifest(), &node(), &ctx, Mode::Fetch)));
    }

    #[test]
    fn ring_must_match() {
        let mut n = node();
        n.ring = "canary".into();
        assert!(matches!(
            decide(&manifest(), &n, &Context::default(), Mode::Fetch),
            Decision::Reject(Rejection::RingMismatch { .. })
        ));
    }

    #[test]
    fn hold_blocks_timer_and_boot_but_not_operator() {
        let held = Context { held: true, ..Default::default() };
        assert!(matches!(decide(&manifest(), &node(), &held, Mode::Fetch), Decision::Skip(_)));
        assert!(matches!(decide(&manifest(), &node(), &held, Mode::BootFromCache), Decision::Skip(_)));
        let explicit = Context { held: true, explicit: true, ..Default::default() };
        assert!(ok(decide(&manifest(), &node(), &explicit, Mode::Fetch)));
    }

    #[test]
    fn pinned_level() {
        let ctx = Context { requested_level: Some(2), ..Default::default() };
        assert!(matches!(
            decide(&manifest(), &node(), &ctx, Mode::Fetch),
            Decision::Reject(Rejection::LevelNotOffered { .. })
        ));
    }

    #[test]
    fn future_manifest_is_rejected() {
        let mut n = node();
        n.now = "2026-11-20T00:00:00Z".parse().unwrap();
        assert!(matches!(
            decide(&manifest(), &n, &Context::default(), Mode::Fetch),
            Decision::Reject(Rejection::FromTheFuture(_))
        ));
    }
}
