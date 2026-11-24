//! The agent's workflows: apply, boot, revert.
//!
//! Invariants:
//! * Nothing is loaded that was not verified against a trusted signature,
//!   the running kernel release and build-id, and the manifest hash.
//! * `force` is never written. A stuck transition is reversed; if the
//!   reversal is stuck too, the agent stops and reports.
//! * A node is never left worse than before: if a new level misbehaves
//!   after its transition, the previous level is put back by atomic
//!   replace, so the node has a livepatch throughout.
//! * A level that failed, or whose load was interrupted (crash, reboot,
//!   killed agent), is quarantined: neither the timer nor the boot unit
//!   loads it again. Only an explicit `apply` retries it.
//! * A revoked level (signed `v1/revoked.json`) is never loaded, not even
//!   explicitly; if it is active, `apply` puts the highest cached level
//!   below it back, or unloads it.

use std::cell::RefCell;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use chrono::{DateTime, Utc};
use klp_core::manifest::Manifest;
use klp_core::naming::{is_ours, level_from_module_name};
use klp_core::policy::{self, Decision, Mode, NodeFacts};
use klp_core::revocation::{self, RevocationList};
use klp_core::sig::TrustStore;
use sha2::{Digest, Sha256};

use crate::cluster::ClusterLock;
use crate::config::Config;
use crate::kernel::{KernelOps, KmsgRecord, is_bad_kmsg, taint};
use crate::repo::{Repo, RepoError};
use crate::state::{Attempt, Phase, Quarantine, State, write_atomic};

const MAX_MANIFEST: u64 = 1 << 20;
const REVOCATION_LIST: &str = "v1/revoked.json";
const MAX_SIGNATURE: u64 = 64 << 10;
/// Livepatch modules are a few MB; anything this big is not one.
const MAX_MODULE: u64 = 32 << 20;
const POLL: Duration = Duration::from_millis(500);
const BLOCKER_REPORT_EVERY: Duration = Duration::from_secs(15);
const CLUSTER_LOCK_POLL: Duration = Duration::from_secs(5);
const CLUSTER_LOCK_MAX_WAIT: Duration = Duration::from_secs(15 * 60);
/// Levels kept in the local cache per kernel (current, previous, one more).
const CACHE_KEEP_LEVELS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Applied {
        level: u32,
        warnings: Vec<String>,
    },
    AlreadyActive {
        level: u32,
    },
    Skipped(String),
    /// The repository has no manifest for this kernel and ring.
    NothingPublished,
    /// Nothing cached to reload after boot.
    NothingToLoad,
    Reverted {
        levels: Vec<u32>,
    },
    NothingActive,
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// Verification or policy said no. Nothing was loaded.
    #[error("rejected: {0}")]
    Rejected(String),
    /// The node is not in a state where loading is safe.
    #[error("precondition failed: {0}")]
    Precondition(String),
    /// Loading or the transition failed; the agent backed out.
    #[error("failed: {0}")]
    Failed(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl ApplyError {
    pub fn exit_code(&self) -> i32 {
        match self {
            ApplyError::Failed(_) => 2,
            ApplyError::Rejected(_) => 3,
            ApplyError::Precondition(_) => 4,
            ApplyError::Other(_) => 1,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ApplyOpts {
    pub level: Option<u32>,
    /// Allow atomic replace to also replace livepatches not built by us.
    pub replace_foreign: bool,
    /// Started by an operator (clears a hold, retries a quarantined level,
    /// ignores delay and pin), not by the timer.
    pub explicit: bool,
}

/// Why a module is being loaded; passed to hooks as `HVPATCH_MODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadKind {
    Apply,
    Boot,
    Restore,
}

impl LoadKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LoadKind::Apply => "apply",
            LoadKind::Boot => "boot",
            LoadKind::Restore => "restore",
        }
    }
}

/// A manifest whose signature has been checked, plus who signed it.
struct Verified {
    manifest: Manifest,
    raw: Vec<u8>,
    sig: String,
    signer: String,
}

pub struct Agent<K: KernelOps> {
    pub cfg: Config,
    pub kernel: K,
    pub repo: Option<Box<dyn Repo>>,
    pub trust: TrustStore,
    pub now: Box<dyn Fn() -> DateTime<Utc>>,
    /// Also print log lines to stderr.
    pub echo: bool,
    log: RefCell<Vec<String>>,
    cluster: RefCell<Option<ClusterLock>>,
}

enum Go {
    Apply(Vec<String>),
    AlreadyActive,
    Skip(String),
}

enum Wait {
    Done,
    Gone,
    Timeout(String),
}

impl<K: KernelOps> Agent<K> {
    pub fn new(cfg: Config, kernel: K, repo: Option<Box<dyn Repo>>, trust: TrustStore) -> Self {
        Self {
            cfg,
            kernel,
            repo,
            trust,
            now: Box::new(Utc::now),
            echo: false,
            log: RefCell::new(vec![]),
            cluster: RefCell::new(None),
        }
    }

    pub fn log(&self, msg: impl Into<String>) {
        let msg = msg.into();
        if self.echo {
            eprintln!("hvpatch: {msg}");
        }
        self.log.borrow_mut().push(msg);
    }

    pub fn log_lines(&self) -> Vec<String> {
        self.log.borrow().clone()
    }

    fn cache_dir(&self, release: &str, level: u32) -> PathBuf {
        self.cfg.cache_dir().join(release).join(level.to_string())
    }

    fn save_phase(&self, state: &mut State, release: &str, phase: Phase, err: Option<String>) -> anyhow::Result<()> {
        let k = state.kernel(release);
        k.phase = phase;
        k.last_error = err;
        k.stuck = false;
        k.updated = Some((self.now)());
        state.save(&self.cfg.state_file())
    }

    /// Failed, and backing out did not finish either.
    fn save_stuck(&self, state: &mut State, release: &str, err: String) -> anyhow::Result<()> {
        self.save_phase(state, release, Phase::Failed, Some(err))?;
        state.kernel(release).stuck = true;
        state.save(&self.cfg.state_file())
    }

    /// Remember that this module failed so that no automatic run loads it
    /// again. Saved with the next `save_phase`.
    fn quarantine(&self, state: &mut State, release: &str, m: &Manifest, reason: &str) {
        let reason: String = reason.lines().next().unwrap_or(reason).chars().take(300).collect();
        let k = state.kernel(release);
        k.attempt = None;
        k.quarantined.insert(m.sha256.clone(), Quarantine { level: m.level, reason, since: (self.now)() });
    }

    // ------------------------------------------------------------------
    // apply

    pub fn apply(&self, opts: &ApplyOpts) -> Result<Outcome, ApplyError> {
        let release = self.kernel.release()?;
        let mut state = State::load(&self.cfg.state_file())?;
        // On hold after `revert`: the timer does nothing at all, not even
        // contact the repository. Only an explicit `apply` resumes.
        if state.get(&release).held && !opts.explicit {
            self.log("livepatching is on hold after `hvpatch revert`; run `hvpatch apply` to resume");
            return Ok(Outcome::Skipped("held after revert".into()));
        }
        self.reconcile(&mut state, &release)?;
        let repo = self.repo.as_ref().ok_or_else(|| anyhow!("no repository configured"))?;
        let (revoked, fresh) = self.refresh_revocations(repo.as_ref(), &mut state)?;
        self.withdraw_revoked(&mut state, &release, &revoked)?;
        // Once a list was published, a missing one may be a mirror hiding
        // a newer revocation: keep what runs, load nothing new.
        if !fresh && state.revocation_sequence > 0 {
            return Err(ApplyError::Rejected(format!(
                "the revocation list (sequence {} accepted before) is not available from the repository; \
                 not loading anything new until it is",
                state.revocation_sequence
            )));
        }
        let active = self.preflight(opts.replace_foreign)?;

        let base = format!("v1/{release}/{}", self.cfg.ring);
        let v = match self.fetch_verified(repo.as_ref(), &base) {
            Ok(Some(v)) => v,
            Ok(None) => {
                self.log(format!("no livepatch published for {release} in ring {}", self.cfg.ring));
                return Ok(Outcome::NothingPublished);
            }
            Err(e) => {
                let _ = self.save_phase(&mut state, &release, Phase::Failed, Some(e.to_string()));
                return Err(e);
            }
        };
        let m = &v.manifest;
        self.log(format!("manifest {} level {} ring {} signed by {}", m.kernel, m.level, m.ring, v.signer));

        if let Some(r) = revoked_entry(&revoked, &release, m) {
            let why = format!("level {} is revoked: {}", m.level, r.reason);
            self.log(why.clone());
            return Ok(Outcome::Skipped(why));
        }
        if let Some(q) = state.get(&release).quarantined.get(&m.sha256).cloned() {
            if !opts.explicit {
                let why = format!(
                    "level {} is quarantined since {}: {}. Run `hvpatch apply` to retry it",
                    q.level,
                    q.since.format("%Y-%m-%d %H:%M"),
                    q.reason
                );
                self.log(why.clone());
                return Ok(Outcome::Skipped(why));
            }
            self.log(format!("retrying quarantined level {} on request", q.level));
            state.kernel(&release).quarantined.remove(&m.sha256);
            state.save(&self.cfg.state_file())?;
        }
        if !opts.explicit {
            if let Some(pin) = self.cfg.pin_level
                && m.level > pin
            {
                return Ok(Outcome::Skipped(format!("pinned at level {pin}; the repository offers {}", m.level)));
            }
            let eligible = m.built + chrono::Duration::hours(self.cfg.delay_hours as i64);
            if (self.now)() < eligible {
                return Ok(Outcome::Skipped(format!(
                    "level {} becomes eligible at {} (delay_hours = {})",
                    m.level,
                    eligible.format("%Y-%m-%d %H:%M UTC"),
                    self.cfg.delay_hours
                )));
            }
        }

        let mut warnings = match self.decide(m, &state, active.as_ref().map(|a| a.1), Mode::Fetch, opts)? {
            Go::Apply(w) => w,
            Go::AlreadyActive => {
                self.mark_active(&mut state, &release, m)?;
                return Ok(Outcome::AlreadyActive { level: m.level });
            }
            Go::Skip(why) => return Ok(Outcome::Skipped(why)),
        };
        self.check_states(&release, m).map_err(ApplyError::Rejected)?;
        self.save_phase(&mut state, &release, Phase::Fetched, None)?;

        let res = self.download_and_activate(&mut state, &release, &v, repo.as_ref(), active.map(|a| a.1));
        if let Err(e) = &res {
            self.fail_if_in_progress(&mut state, &release, e);
        }
        warnings.extend(res?);
        for w in &warnings {
            self.log(format!("warning: {w}"));
        }
        Ok(Outcome::Applied { level: m.level, warnings })
    }

    /// Fetch and verify the manifest. A signature that does not match is
    /// fetched once more: a reader can catch the publisher between writing
    /// the signature and the manifest.
    fn fetch_verified(&self, repo: &dyn Repo, base: &str) -> Result<Option<Verified>, ApplyError> {
        let mut last = None;
        for attempt in 0..2 {
            let raw = match repo.get(&format!("{base}/manifest.json"), MAX_MANIFEST) {
                Ok(b) => b,
                Err(RepoError::NotFound(_)) => return Ok(None),
                Err(RepoError::Other(e)) => return Err(e.into()),
            };
            let sig = repo
                .get(&format!("{base}/manifest.json.minisig"), MAX_SIGNATURE)
                .map_err(|e| ApplyError::Rejected(format!("manifest signature missing: {e}")))?;
            match self.verify_manifest(raw, &sig) {
                Ok(v) => return Ok(Some(v)),
                Err(e) => {
                    if attempt == 0 {
                        self.log(format!("{e}; fetching the manifest once more"));
                        self.kernel.sleep(Duration::from_secs(2));
                    }
                    last = Some(e);
                }
            }
        }
        Err(last.expect("two attempts"))
    }

    /// Everything after the manifest was accepted. Returns extra warnings.
    fn download_and_activate(
        &self,
        state: &mut State,
        release: &str,
        v: &Verified,
        repo: &dyn Repo,
        previous: Option<u32>,
    ) -> Result<Vec<String>, ApplyError> {
        let m = &v.manifest;
        let ko = repo
            .get(&format!("v1/{release}/{}", m.module), MAX_MODULE)
            .map_err(|e| ApplyError::Rejected(format!("module download failed: {e}")))?;
        if sha256_hex(&ko) != m.sha256 {
            return Err(ApplyError::Rejected(format!("module {} does not match the manifest hash", m.module)));
        }
        let dir = self.cache_dir(release, m.level);
        write_atomic(&dir.join(&m.module), &ko)?;
        write_atomic(&dir.join("manifest.json"), &v.raw)?;
        write_atomic(&dir.join("manifest.json.minisig"), v.sig.as_bytes())?;

        let file = self.open_verified_module(m, release, &dir)?;
        self.save_phase(state, release, Phase::Verified, None)?;
        state.kernel(release).signed_by = Some(v.signer.clone());

        let mut warnings = Vec::new();
        let conflicts = self.trace_conflicts(m);
        if !conflicts.is_empty() {
            let msg = format!(
                "kprobes or BPF programs are attached to function(s) this livepatch replaces: {}. \
                 kretprobes conflict with livepatches, and kprobes in the old function stop firing",
                conflicts.join(", ")
            );
            if self.cfg.refuse_on_trace_conflict {
                return Err(ApplyError::Precondition(msg));
            }
            warnings.push(msg);
        }

        let lock = self.acquire_cluster_lock()?;
        *self.cluster.borrow_mut() = lock;
        let res = self.activate(state, release, m, &file, previous, LoadKind::Apply);
        self.cluster.borrow_mut().take();
        res?;
        Ok(warnings)
    }

    /// Fetch, verify and cache the revocation list. Returns the list to
    /// apply and whether it came from the repository just now. Without one
    /// in the repository (or when it is unreachable) the cached list
    /// applies; a list older than one accepted before is a replay and is
    /// ignored; a list with a bad signature stops the run.
    fn refresh_revocations(&self, repo: &dyn Repo, state: &mut State) -> Result<(RevocationList, bool), ApplyError> {
        let cached = self.cached_revocations();
        let mut fetched = None;
        // List and signature are two files: a reader can catch the publisher
        // between them, so a mismatch is fetched once more.
        for attempt in 0..2 {
            let raw = match repo.get(REVOCATION_LIST, revocation::MAX_SIZE) {
                Ok(b) => b,
                Err(RepoError::NotFound(_)) => return Ok((cached, false)),
                Err(RepoError::Other(e)) => {
                    self.log(format!("revocation list not available ({e:#}); using the cached one"));
                    return Ok((cached, false));
                }
            };
            let sig = repo
                .get(&format!("{REVOCATION_LIST}.minisig"), MAX_SIGNATURE)
                .map_err(|e| ApplyError::Rejected(format!("revocation list signature missing: {e}")))?;
            match self.verify_revocations(&raw, &sig) {
                Ok(list) => {
                    fetched = Some((list, raw, sig));
                    break;
                }
                Err(e) if attempt == 0 => {
                    self.log(format!("{e:#}; fetching the revocation list once more"));
                    self.kernel.sleep(Duration::from_secs(2));
                }
                Err(e) => return Err(ApplyError::Rejected(format!("{e:#}"))),
            }
        }
        let (list, raw, sig) = fetched.expect("verified or returned");
        if list.sequence < state.revocation_sequence {
            self.log(format!(
                "ignoring revocation list {}: older than {} accepted before",
                list.sequence, state.revocation_sequence
            ));
            return Ok((cached, false));
        }
        if list.sequence > state.revocation_sequence || cached.sequence != list.sequence {
            let f = self.cfg.revocation_file();
            write_atomic(&f, &raw)?;
            write_atomic(&f.with_extension("json.minisig"), &sig)?;
            state.revocation_sequence = list.sequence;
            state.save(&self.cfg.state_file())?;
        }
        Ok((list, true))
    }

    fn verify_revocations(&self, raw: &[u8], sig: &[u8]) -> anyhow::Result<RevocationList> {
        let sig = std::str::from_utf8(sig).context("revocation list signature is not text")?;
        self.trust.verify(raw, sig).context("revocation list signature")?;
        RevocationList::from_json(raw).context("revocation list")
    }

    /// The last accepted revocation list, verified again (boot works from
    /// it without network).
    pub fn cached_revocations(&self) -> RevocationList {
        let f = self.cfg.revocation_file();
        let (Ok(raw), Ok(sig)) = (std::fs::read(&f), std::fs::read(f.with_extension("json.minisig"))) else {
            return RevocationList::default();
        };
        self.verify_revocations(&raw, &sig).unwrap_or_else(|e| {
            self.log(format!("ignoring the cached revocation list: {e:#}"));
            RevocationList::default()
        })
    }

    /// Take an active level that was revoked out of service: put the
    /// highest cached level below it back by atomic replace, or unload it.
    fn withdraw_revoked(&self, state: &mut State, release: &str, revoked: &RevocationList) -> Result<(), ApplyError> {
        if revoked.revoked.is_empty() {
            return Ok(());
        }
        let Some(active) = self.kernel.livepatches()?.into_iter().find(|p| is_ours(&p.name) && p.enabled) else {
            return Ok(());
        };
        let Some(level) = level_from_module_name(&active.name) else { return Ok(()) };
        let entry = match self.cached_manifest(release, level) {
            Some((m, _)) => revoked_entry(revoked, release, &m).cloned(),
            None => revoked.revoked.iter().find(|r| r.kernel == release && r.level == level).cloned(),
        };
        let Some(r) = entry else { return Ok(()) };
        self.log(format!("active level {level} is revoked ({}); taking it out of service", r.reason));
        let fallback = self.cached_levels(release).into_iter().filter(|l| *l < level).find(|l| {
            self.cached_manifest(release, *l).is_some_and(|(m, _)| {
                revoked_entry(revoked, release, &m).is_none() && !state.get(release).quarantined.contains_key(&m.sha256)
            })
        });
        if let Some(prev) = fallback {
            let lock = self.acquire_cluster_lock()?;
            *self.cluster.borrow_mut() = lock;
            let res = self.restore(state, release, prev);
            self.cluster.borrow_mut().take();
            match res {
                Ok(()) => return Ok(()),
                Err(e) => self.log(format!("putting level {prev} back failed: {e}")),
            }
        }
        if self.kernel.patch(&active.name)?.is_some_and(|p| p.enabled) {
            if let Err(e) = self.back_out(&active.name) {
                self.save_stuck(state, release, e.clone())?;
                return Err(ApplyError::Failed(e));
            }
        }
        state.kernel(release).desired_level = None;
        self.save_phase(state, release, Phase::Reverted, Some(format!("level {level} was revoked: {}", r.reason)))?;
        self.write_runtime_files(release, None);
        Ok(())
    }

    /// Atomic replace hands the active level's states (shadow variables
    /// and the like, set up by its callbacks) to the new one. klp-build
    /// modules do not declare states to the kernel, so check the manifests.
    fn check_states(&self, release: &str, new: &Manifest) -> Result<(), String> {
        let Ok(patches) = self.kernel.livepatches() else { return Ok(()) };
        let Some(level) =
            patches.iter().filter(|p| is_ours(&p.name) && p.enabled).find_map(|p| level_from_module_name(&p.name))
        else {
            return Ok(());
        };
        if level == new.level {
            return Ok(());
        }
        match self.cached_manifest(release, level) {
            Some((active, _)) => klp_core::manifest::states_compatible(&active.states, &new.states),
            None => {
                self.log(format!(
                    "the manifest of the active level {level} is not cached; its states cannot be checked"
                ));
                Ok(())
            }
        }
    }

    /// After an error, never leave the stored phase at "in progress".
    fn fail_if_in_progress(&self, state: &mut State, release: &str, e: &ApplyError) {
        if matches!(state.get(release).phase, Phase::Fetched | Phase::Verified | Phase::Loading) {
            state.kernel(release).attempt = None;
            let _ = self.save_phase(state, release, Phase::Failed, Some(e.to_string()));
        }
    }

    /// The kernel says `m` is active; make the stored state agree.
    fn mark_active(&self, state: &mut State, release: &str, m: &Manifest) -> anyhow::Result<()> {
        let k = state.get(release);
        if k.phase == Phase::Active && k.desired_level == Some(m.level) && k.highest_accepted >= m.level && !k.held {
            return Ok(());
        }
        let k = state.kernel(release);
        k.highest_accepted = k.highest_accepted.max(m.level);
        k.desired_level = Some(m.level);
        k.held = false;
        k.attempt = None;
        self.save_phase(state, release, Phase::Active, None)?;
        self.write_runtime_files(release, Some(m));
        Ok(())
    }

    /// A load recorded as started but never finished: the host crashed or
    /// rebooted, or the agent was killed.
    fn reconcile(&self, state: &mut State, release: &str) -> Result<(), ApplyError> {
        let Some(a) = state.get(release).attempt else { return Ok(()) };
        match self.kernel.patch(&a.module)? {
            Some(p) if p.enabled && !p.transition => {
                self.log(format!(
                    "the load of level {} completed after an interrupted run; recording it as active \
                     (its post-checks were not repeated)",
                    a.level
                ));
                let k = state.kernel(release);
                k.attempt = None;
                k.highest_accepted = k.highest_accepted.max(a.level);
                k.desired_level = Some(a.level);
                self.save_phase(state, release, Phase::Active, None)?;
            }
            // Still in transition: preflight() reports it.
            Some(_) => {}
            None => {
                let reason = format!(
                    "loading level {} was interrupted at {} (host crash, reboot or the agent was killed)",
                    a.level,
                    a.started.format("%Y-%m-%d %H:%M:%S UTC")
                );
                self.log(format!("{reason}; quarantining it"));
                let k = state.kernel(release);
                k.attempt = None;
                k.quarantined.insert(
                    a.sha256.clone(),
                    Quarantine { level: a.level, reason: reason.clone(), since: (self.now)() },
                );
                self.save_phase(state, release, Phase::Failed, Some(reason))?;
            }
        }
        Ok(())
    }

    fn acquire_cluster_lock(&self) -> Result<Option<ClusterLock>, ApplyError> {
        if !self.cfg.cluster_lock || !self.cfg.cluster_lock_dir.is_dir() {
            return Ok(None);
        }
        let mut waited = Duration::ZERO;
        let mut told = false;
        loop {
            match ClusterLock::try_acquire(&self.cfg.cluster_lock_dir) {
                Ok(Some(l)) => return Ok(Some(l)),
                Ok(None) if waited >= CLUSTER_LOCK_MAX_WAIT => {
                    return Err(ApplyError::Precondition(format!(
                        "another node of the cluster has been loading a livepatch for over {} minutes \
                         ({} exists); try again later",
                        CLUSTER_LOCK_MAX_WAIT.as_secs() / 60,
                        self.cfg.cluster_lock_dir.join(crate::cluster::LOCK_NAME).display()
                    )));
                }
                Ok(None) => {
                    if !told {
                        self.log("another node of the cluster is loading a livepatch; waiting for it");
                        told = true;
                    }
                    self.kernel.sleep(CLUSTER_LOCK_POLL);
                    waited += CLUSTER_LOCK_POLL;
                }
                Err(e) => return Err(ApplyError::Precondition(format!("{e:#}"))),
            }
        }
    }

    /// Functions this patch replaces that kprobes/BPF are attached to.
    fn trace_conflicts(&self, m: &Manifest) -> Vec<String> {
        let traced = self.kernel.traced_functions().unwrap_or_default();
        let mut out: Vec<String> = m
            .fixes
            .iter()
            .flat_map(|f| f.functions.iter())
            .map(|f| strip_sympos(f.split_once(':').map(|(_, n)| n).unwrap_or(f)).to_owned())
            .filter(|f| traced.iter().any(|t| t == f))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    fn decide(
        &self,
        m: &Manifest,
        state: &State,
        active_level: Option<u32>,
        mode: Mode,
        opts: &ApplyOpts,
    ) -> Result<Go, ApplyError> {
        let release = self.kernel.release()?;
        let ks = state.get(&release);
        let node = NodeFacts {
            kernel_release: release,
            kernel_build_id: self.kernel.build_id()?,
            ring: self.cfg.ring.clone(),
            now: (self.now)(),
        };
        let ctx = policy::Context {
            highest_accepted: ks.highest_accepted,
            active_level,
            held: ks.held,
            explicit: opts.explicit,
            requested_level: opts.level,
            allow_expired_on_boot: self.cfg.allow_expired_on_boot,
        };
        match policy::decide(m, &node, &ctx, mode) {
            Decision::Apply { warnings } => Ok(Go::Apply(warnings)),
            Decision::AlreadyActive => {
                self.log(format!("level {} is already active", m.level));
                Ok(Go::AlreadyActive)
            }
            Decision::Skip(why) => {
                self.log(why.clone());
                Ok(Go::Skip(why))
            }
            Decision::Reject(r) => Err(ApplyError::Rejected(r.to_string())),
        }
    }

    fn verify_manifest(&self, raw: Vec<u8>, sig: &[u8]) -> Result<Verified, ApplyError> {
        let sig = String::from_utf8(sig.to_vec()).map_err(|_| ApplyError::Rejected("signature is not text".into()))?;
        let signer = self
            .trust
            .verify(&raw, &sig)
            .map_err(|e| ApplyError::Rejected(format!("manifest signature: {e:#}")))?
            .name
            .clone();
        let manifest = Manifest::from_json(&raw).map_err(|e| ApplyError::Rejected(format!("manifest: {e:#}")))?;
        Ok(Verified { manifest, raw, sig, signer })
    }

    /// Open the cached module, re-hash exactly the bytes behind the file
    /// descriptor that will be passed to finit_module, and check .modinfo.
    fn open_verified_module(&self, m: &Manifest, release: &str, dir: &Path) -> Result<File, ApplyError> {
        let path = dir.join(&m.module);
        let mut file = File::open(&path).with_context(|| format!("opening {}", path.display()))?;
        let mut bytes = Vec::new();
        (&mut file).take(MAX_MODULE + 1).read_to_end(&mut bytes).context("reading module")?;
        if sha256_hex(&bytes) != m.sha256 {
            return Err(ApplyError::Rejected(format!(
                "cached module {} does not match the manifest hash",
                path.display()
            )));
        }
        let info = klp_core::elf::parse_modinfo(&bytes).map_err(|e| ApplyError::Rejected(format!("{e:#}")))?;
        if !info.is_livepatch() {
            return Err(ApplyError::Rejected("module is not a livepatch module (livepatch=Y missing)".into()));
        }
        if info.name() != Some(m.module_name.as_str()) {
            return Err(ApplyError::Rejected(format!(
                "module name {:?} does not match manifest {:?}",
                info.name(),
                m.module_name
            )));
        }
        if info.vermagic_release() != Some(release) {
            return Err(ApplyError::Rejected(format!(
                "module vermagic {:?} does not match running kernel {release}",
                info.vermagic()
            )));
        }
        Ok(file)
    }

    /// Checks that must pass before any module is loaded. Returns the
    /// currently active patch of ours, if any.
    fn preflight(&self, replace_foreign: bool) -> Result<Option<(String, u32)>, ApplyError> {
        let patches = self.kernel.livepatches()?;
        if let Some(p) = patches.iter().find(|p| p.transition) {
            return Err(ApplyError::Precondition(format!(
                "livepatch {} is in transition; wait for it to finish or run `hvpatch revert`",
                p.name
            )));
        }
        let foreign: Vec<_> = patches.iter().filter(|p| !is_ours(&p.name)).collect();
        if !foreign.is_empty() && !replace_foreign {
            let names: Vec<_> = foreign.iter().map(|p| p.name.as_str()).collect();
            return Err(ApplyError::Precondition(format!(
                "foreign livepatch(es) loaded: {}; atomic replace would disable them. \
                 Use --replace-foreign if that is intended",
                names.join(", ")
            )));
        }
        let active = patches
            .iter()
            .filter(|p| p.enabled && is_ours(&p.name))
            .filter_map(|p| level_from_module_name(&p.name).map(|l| (p.name.clone(), l)))
            .max_by_key(|(_, l)| *l);

        for m in self.kernel.modules()? {
            if !m.is_livepatch() || patches.iter().any(|p| p.name == m.name) {
                continue;
            }
            // The kernel frees a disabled or replaced patch asynchronously:
            // the sysfs entry goes first, the module reference a moment
            // later. Look again before calling it a forced leftover.
            if m.refcnt > 0 && self.still_referenced(&m.name)? {
                return Err(ApplyError::Precondition(format!(
                    "module {} is a livepatch without sysfs entry that is still referenced; this is \
                     what a forced transition leaves behind. Do not load further patches; reboot.",
                    m.name
                )));
            }
            if is_ours(&m.name) {
                self.log(format!("removing leftover module {}", m.name));
                self.kernel.unload_module(&m.name)?;
            }
        }
        Ok(active)
    }

    fn still_referenced(&self, module: &str) -> anyhow::Result<bool> {
        for _ in 0..6 {
            self.kernel.sleep(POLL);
            let refcnt = self.kernel.modules()?.into_iter().find(|m| m.name == module).map(|m| m.refcnt);
            if refcnt.unwrap_or(0) == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Load, wait for the transition, run post-checks. On any failure the
    /// module is quarantined and backed out; if it had replaced an older
    /// level, that level is put back by atomic replace.
    fn activate(
        &self,
        state: &mut State,
        release: &str,
        m: &Manifest,
        file: &File,
        previous: Option<u32>,
        kind: LoadKind,
    ) -> Result<(), ApplyError> {
        let name = &m.module_name;
        let taint_before = self.kernel.tainted()?;
        let mut kmsg = match self.kernel.kmsg_watch() {
            Ok(w) => Some(w),
            Err(e) => {
                self.log(format!("warning: cannot watch kernel log: {e:#}"));
                None
            }
        };
        state.kernel(release).attempt =
            Some(Attempt { level: m.level, sha256: m.sha256.clone(), module: name.clone(), started: (self.now)() });
        self.save_phase(state, release, Phase::Loading, None)?;
        self.log(format!("loading {name} ({})", kind.as_str()));

        if let Err(e) = self.kernel.load_module(file) {
            let mut msg = e.to_string();
            if let Some(k) = kmsg.as_mut() {
                // Only what concerns this load; unrelated drivers log too.
                let lines: Vec<String> = k
                    .drain()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|r| is_load_related(&r.msg, name))
                    .map(|r| r.msg)
                    .collect();
                if !lines.is_empty() {
                    msg.push_str("\nkernel log:\n  ");
                    msg.push_str(&lines.join("\n  "));
                }
            }
            self.quarantine(state, release, m, &msg);
            self.save_phase(state, release, Phase::Failed, Some(msg.clone()))?;
            return Err(ApplyError::Failed(msg));
        }

        match self.wait_transition(name, true)? {
            Wait::Done => {}
            Wait::Gone => {
                let msg = format!("{name} disappeared during its transition");
                self.quarantine(state, release, m, &msg);
                self.save_phase(state, release, Phase::Failed, Some(msg.clone()))?;
                return Err(ApplyError::Failed(msg));
            }
            Wait::Timeout(blockers) => {
                let mut msg = format!(
                    "transition of {name} did not finish within {} s; blocking tasks:\n{blockers}",
                    self.cfg.transition_timeout
                );
                self.quarantine(
                    state,
                    release,
                    m,
                    &format!("transition did not finish within {} s", self.cfg.transition_timeout),
                );
                // Reversing an unfinished transition keeps the previous
                // level active, so no restore is needed here.
                match self.back_out(name) {
                    Ok(()) => {
                        msg.push_str("\nthe transition was reversed; the previous state is active again");
                        // A failed apply, even if cleanly backed out: monitoring
                        // must see it. "reverted" is the operator's revert.
                        self.save_phase(state, release, Phase::Failed, Some(msg.clone()))?;
                    }
                    Err(e) => {
                        msg.push_str(&format!("\n{e}"));
                        self.save_stuck(state, release, msg.clone())?;
                    }
                }
                return Err(ApplyError::Failed(msg));
            }
        }

        if let Err(why) = self.post_checks(m, taint_before, kmsg.as_deref_mut(), kind) {
            let mut msg = format!("{name} activated, but post-checks failed: {why}");
            self.log(&msg);
            self.quarantine(state, release, m, &format!("post-checks failed: {why}"));
            let mut stuck = false;
            let restored = match (previous, kind) {
                (Some(prev), LoadKind::Apply) => match self.restore(state, release, prev) {
                    Ok(()) => {
                        msg.push_str(&format!(
                            "\nlevel {prev} was put back by atomic replace; the node had a livepatch throughout"
                        ));
                        true
                    }
                    Err(e) => {
                        msg.push_str(&format!("\nputting level {prev} back failed: {e}"));
                        false
                    }
                },
                _ => false,
            };
            if !restored && self.kernel.patch(name)?.is_some() {
                match self.back_out(name) {
                    Ok(()) => msg.push_str(&format!("\n{name} was disabled and unloaded")),
                    Err(e) => {
                        msg.push_str(&format!("\n{e}"));
                        stuck = true;
                    }
                }
            }
            // The restore saved its own state; this records the failure.
            self.quarantine(state, release, m, &format!("post-checks failed: {why}"));
            if stuck {
                self.save_stuck(state, release, msg.clone())?;
            } else {
                self.save_phase(state, release, Phase::Failed, Some(msg.clone()))?;
            }
            return Err(ApplyError::Failed(msg));
        }

        self.cleanup_replaced(name);
        let k = state.kernel(release);
        k.attempt = None;
        k.highest_accepted = k.highest_accepted.max(m.level);
        k.desired_level = Some(m.level);
        k.held = false;
        self.save_phase(state, release, Phase::Active, None)?;
        self.log(format!("{name} is active (level {})", m.level));
        self.prune_cache(state, release);
        self.write_runtime_files(release, Some(m));
        Ok(())
    }

    fn post_checks(
        &self,
        m: &Manifest,
        taint_before: u64,
        kmsg: Option<&mut (dyn crate::kernel::KmsgWatch + 'static)>,
        kind: LoadKind,
    ) -> Result<(), String> {
        let name = &m.module_name;
        match self.kernel.patch(name).map_err(|e| e.to_string())? {
            Some(p) if p.enabled && !p.transition => {}
            other => return Err(format!("unexpected patch state after transition: {other:?}")),
        }

        // Levels replace each other; a module built without atomic replace
        // would stack instead and break restore and rollback.
        if self.kernel.patch_replaces(name).map_err(|e| e.to_string())? == Some(false) {
            return Err("the module was built without atomic replace (klp-build --no-replace)".into());
        }

        // Every function the manifest promises must show up in sysfs.
        let present: Vec<String> = self
            .kernel
            .patched_functions(name)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|(f, _)| strip_sympos(&f).to_owned())
            .collect();
        let missing: Vec<&str> = m
            .fixes
            .iter()
            .flat_map(|f| f.functions.iter())
            .map(|f| strip_sympos(f))
            .filter(|f| !present.iter().any(|p| p == f))
            .collect();
        if !missing.is_empty() {
            return Err(format!("functions listed in the manifest are not patched: {}", missing.join(", ")));
        }

        if self.cfg.settle_time > 0 {
            self.kernel.sleep(Duration::from_secs(self.cfg.settle_time));
        }
        if let Some(k) = kmsg {
            let bad: Vec<KmsgRecord> = k.drain().map_err(|e| e.to_string())?.into_iter().filter(is_bad_kmsg).collect();
            if !bad.is_empty() {
                let lines: Vec<&str> = bad.iter().map(|r| r.msg.as_str()).collect();
                return Err(format!("kernel log since loading:\n  {}", lines.join("\n  ")));
            }
        }
        // Flags the livepatch module itself reports (/sys/module/<m>/taint,
        // typically "OK" or "OEK") are explained by loading it. Anything
        // else that appeared since (W, D, L, ...) is not.
        let own = self
            .kernel
            .modules()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|md| md.name == m.module_name)
            .map(|md| taint::from_letters(&md.taint) & taint::MODULE_ATTRIBUTABLE)
            .unwrap_or(0);
        let explained = taint::EXPECTED | own;
        let new_taint = self.kernel.tainted().map_err(|e| e.to_string())? & !taint_before & !explained;
        if new_taint != 0 {
            return Err(format!("kernel gained taint flags {}", taint::letters(new_taint)));
        }
        self.run_hooks(m, kind)
    }

    /// Run the executables in hooks_dir like run-parts: in name order, only
    /// names of letters, digits, `-` and `_` (no `*.dpkg-old`, no backups),
    /// each with a timeout. A hook that root does not own or that others
    /// can write is refused, because it would run as root.
    fn run_hooks(&self, m: &Manifest, kind: LoadKind) -> Result<(), String> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::os::unix::process::CommandExt;
        let Ok(entries) = std::fs::read_dir(&self.cfg.hooks_dir) else { return Ok(()) };
        let mut hooks: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                })
            })
            .collect();
        hooks.sort();
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        let timeout = Duration::from_secs(self.cfg.hook_timeout);
        for h in hooks {
            let Ok(meta) = std::fs::metadata(&h) else { continue };
            if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
                continue;
            }
            if meta.uid() != 0 && meta.uid() != euid {
                return Err(format!("hook {} is not owned by root; refusing to run it", h.display()));
            }
            if meta.mode() & 0o022 != 0 {
                return Err(format!("hook {} is writable by group or others; refusing to run it", h.display()));
            }
            self.log(format!("running hook {}", h.display()));
            let mut child = std::process::Command::new(&h)
                .env("HVPATCH_KERNEL", &m.kernel)
                .env("HVPATCH_LEVEL", m.level.to_string())
                .env("HVPATCH_MODULE", &m.module_name)
                .env("HVPATCH_MODE", kind.as_str())
                .stdin(std::process::Stdio::null())
                .process_group(0)
                .spawn()
                .map_err(|e| format!("hook {}: {e}", h.display()))?;
            let start = Instant::now();
            let status = loop {
                match child.try_wait() {
                    Ok(Some(st)) => break st,
                    Ok(None) if start.elapsed() >= timeout => {
                        // SAFETY: kill the hook's own process group.
                        unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                        let _ = child.wait();
                        return Err(format!(
                            "hook {} did not finish within {} s and was killed",
                            h.display(),
                            self.cfg.hook_timeout
                        ));
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                    Err(e) => return Err(format!("hook {}: {e}", h.display())),
                }
            };
            if !status.success() {
                return Err(format!("hook {} failed with {status}", h.display()));
            }
        }
        Ok(())
    }

    fn wait_transition(&self, name: &str, target: bool) -> anyhow::Result<Wait> {
        let timeout = self.cfg.transition_timeout();
        let start = Instant::now();
        let mut waited = Duration::ZERO;
        let mut last_report = Duration::ZERO;
        loop {
            match self.kernel.patch(name)? {
                None => return Ok(Wait::Gone),
                Some(p) if !p.transition => return Ok(Wait::Done),
                Some(_) => {}
            }
            // Wall clock counts too: scanning /proc for blockers takes time.
            let elapsed = waited.max(start.elapsed());
            if elapsed >= timeout {
                let tasks = self.kernel.blocking_tasks(target).unwrap_or_default();
                let list = if tasks.is_empty() {
                    "  (none found)".to_owned()
                } else {
                    tasks.iter().map(|t| format!("  {t}")).collect::<Vec<_>>().join("\n")
                };
                return Ok(Wait::Timeout(list));
            }
            if elapsed >= last_report + BLOCKER_REPORT_EVERY {
                last_report = elapsed;
                let tasks = self.kernel.blocking_tasks(target).unwrap_or_default();
                let names: Vec<String> = tasks.iter().take(10).map(|t| format!("{}[{}]", t.comm, t.tid)).collect();
                self.log(format!(
                    "{name}: transition still running after {} s, waiting for: {}",
                    elapsed.as_secs(),
                    names.join(" ")
                ));
            }
            if let Some(l) = self.cluster.borrow_mut().as_mut() {
                l.refresh();
            }
            self.kernel.sleep(POLL);
            waited += POLL;
        }
    }

    /// Disable a patch (reversing a running transition if needed), wait
    /// for it, and unload the module. Never uses `force`.
    fn back_out(&self, name: &str) -> Result<(), String> {
        self.log(format!("disabling {name}"));
        if let Some(p) = self.kernel.patch(name).map_err(|e| e.to_string())?
            && p.enabled
        {
            self.kernel.set_enabled(name, false).map_err(|e| format!("disabling {name}: {e:#}"))?;
        }
        match self.wait_transition(name, false).map_err(|e| e.to_string())? {
            Wait::Done | Wait::Gone => {}
            Wait::Timeout(blockers) => {
                return Err(format!(
                    "disabling {name} is stuck as well; blocking tasks:\n{blockers}\n\
                     hvpatch does not use `force`. Leave the node as it is, collect the task list \
                     above and plan a reboot."
                ));
            }
        }
        // The sysfs entry is removed asynchronously after the transition.
        for _ in 0..20 {
            if self.kernel.patch(name).map_err(|e| e.to_string())?.is_none() {
                break;
            }
            self.kernel.sleep(POLL);
        }
        let mut last = String::new();
        for _ in 0..10 {
            match self.kernel.unload_module(name) {
                Ok(()) => return Ok(()),
                Err(e) => last = format!("{e:#}"),
            }
            self.kernel.sleep(POLL);
        }
        Err(format!("{name} is disabled but could not be unloaded: {last}"))
    }

    /// After atomic replace, the replaced modules stay loaded without a
    /// reference once the kernel has freed their patch. Remove ours.
    fn cleanup_replaced(&self, current: &str) {
        for _ in 0..20 {
            let (Ok(mods), Ok(patches)) = (self.kernel.modules(), self.kernel.livepatches()) else { return };
            let others: Vec<_> = mods.into_iter().filter(|m| is_ours(&m.name) && m.name != current).collect();
            if others.is_empty() {
                return;
            }
            for m in others {
                if m.refcnt == 0 && !patches.iter().any(|p| p.name == m.name) {
                    match self.kernel.unload_module(&m.name) {
                        Ok(()) => self.log(format!("unloaded replaced module {}", m.name)),
                        Err(e) => self.log(format!("could not unload replaced module {} yet: {e:#}", m.name)),
                    }
                }
            }
            self.kernel.sleep(POLL);
        }
        self.log("some replaced modules are still loaded; they are inactive and go away with the next reboot");
    }

    /// Put a previously accepted level back while the failed one is still
    /// active: loading it replaces the failed one atomically, so the node
    /// is never without a livepatch.
    fn restore(&self, state: &mut State, release: &str, level: u32) -> Result<(), ApplyError> {
        let dir = self.cache_dir(release, level);
        let v = self.load_cached(&dir)?;
        if state.get(release).quarantined.contains_key(&v.manifest.sha256) {
            return Err(ApplyError::Precondition(format!("level {level} is quarantined itself")));
        }
        match self.decide(&v.manifest, state, None, Mode::Restore, &ApplyOpts::default())? {
            Go::Apply(_) => {}
            _ => return Err(ApplyError::Precondition(format!("level {level} cannot be restored"))),
        }
        self.check_states(release, &v.manifest)
            .map_err(|e| ApplyError::Precondition(format!("level {level} cannot replace the active one: {e}")))?;
        let file = self.open_verified_module(&v.manifest, release, &dir)?;
        self.log(format!("putting level {level} back by atomic replace"));
        // The old module is still loaded without a patch after it was
        // replaced; preflight() unloads such leftovers of ours.
        self.preflight(true)?;
        self.activate(state, release, &v.manifest, &file, None, LoadKind::Restore)
    }

    fn load_cached(&self, dir: &Path) -> Result<Verified, ApplyError> {
        let raw =
            std::fs::read(dir.join("manifest.json")).with_context(|| format!("reading cache {}", dir.display()))?;
        let sig = std::fs::read(dir.join("manifest.json.minisig")).context("reading cached signature")?;
        self.verify_manifest(raw, &sig)
    }

    /// Cached levels for this kernel, highest first.
    fn cached_levels(&self, release: &str) -> Vec<u32> {
        let mut levels: Vec<u32> = std::fs::read_dir(self.cfg.cache_dir().join(release))
            .map(|d| d.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect())
            .unwrap_or_default();
        levels.sort_unstable_by(|a, b| b.cmp(a));
        levels
    }

    /// Keep a few levels of the running kernel and nothing of kernels the
    /// state no longer knows.
    fn prune_cache(&self, state: &State, release: &str) {
        let root = self.cfg.cache_dir();
        if let Ok(kernels) = std::fs::read_dir(&root) {
            for k in kernels.flatten() {
                let name = k.file_name().to_string_lossy().into_owned();
                if name != release && !state.kernels.contains_key(&name) {
                    let _ = std::fs::remove_dir_all(k.path());
                }
            }
        }
        for level in self.cached_levels(release).into_iter().skip(CACHE_KEEP_LEVELS) {
            let _ = std::fs::remove_dir_all(self.cache_dir(release, level));
        }
    }

    /// `<run_dir>/effective_version` and `fixed_cves`, for vulnerability
    /// scanners and inventory tools. Best effort.
    fn write_runtime_files(&self, release: &str, m: Option<&Manifest>) {
        let dir = &self.cfg.run_dir;
        let res = match m {
            Some(m) => {
                let ids: Vec<&str> = m.fixes.iter().map(|f| f.id.as_str()).collect();
                write_atomic(&dir.join("effective_version"), format!("{release}+hvpatch.{}\n", m.level).as_bytes())
                    .and_then(|_| write_atomic(&dir.join("fixed_cves"), format!("{}\n", ids.join("\n")).as_bytes()))
            }
            None => {
                let _ = std::fs::remove_file(dir.join("effective_version"));
                let _ = std::fs::remove_file(dir.join("fixed_cves"));
                Ok(())
            }
        };
        if let Err(e) = res {
            self.log(format!("warning: cannot write {}: {e:#}", dir.display()));
        }
    }

    // ------------------------------------------------------------------
    // boot

    /// After a reboot into the same kernel: reload the level that was
    /// active before, from the local cache, without network. A quarantined
    /// level is skipped in favour of the highest cached one below it.
    pub fn boot(&self) -> Result<Outcome, ApplyError> {
        let release = self.kernel.release()?;
        let mut state = State::load(&self.cfg.state_file())?;
        if state.get(&release).held {
            return Ok(Outcome::Skipped("held after revert".into()));
        }
        self.reconcile(&mut state, &release)?;
        let Some(desired) = state.get(&release).desired_level else {
            self.log(format!("nothing to reload for {release}"));
            return Ok(Outcome::NothingToLoad);
        };
        let active = self.preflight(false)?;
        let revoked = self.cached_revocations();
        for level in self.cached_levels(&release).into_iter().filter(|l| *l <= desired) {
            let dir = self.cache_dir(&release, level);
            let Ok(v) = self.load_cached(&dir) else { continue };
            if let Some(r) = revoked_entry(&revoked, &release, &v.manifest) {
                self.log(format!("level {level} is revoked ({}); not reloading it", r.reason));
                continue;
            }
            if let Some(q) = state.get(&release).quarantined.get(&v.manifest.sha256) {
                self.log(format!("level {level} is quarantined ({}); not reloading it", q.reason));
                continue;
            }
            // Below the highest accepted level, the agent itself went back
            // (post-check restore, revocation): reload it as a restore,
            // not as a rollback.
            let highest = state.get(&release).highest_accepted;
            let mode = if level == desired && level >= highest { Mode::BootFromCache } else { Mode::Restore };
            if mode == Mode::Restore {
                self.log(format!("reloading level {level} instead of {desired}"));
            }
            let warnings =
                match self.decide(&v.manifest, &state, active.as_ref().map(|a| a.1), mode, &ApplyOpts::default())? {
                    Go::Apply(w) => w,
                    Go::AlreadyActive => {
                        self.mark_active(&mut state, &release, &v.manifest)?;
                        return Ok(Outcome::AlreadyActive { level });
                    }
                    Go::Skip(why) => return Ok(Outcome::Skipped(why)),
                };
            let file = self.open_verified_module(&v.manifest, &release, &dir)?;
            let res =
                self.activate(&mut state, &release, &v.manifest, &file, active.as_ref().map(|a| a.1), LoadKind::Boot);
            if let Err(e) = &res {
                self.fail_if_in_progress(&mut state, &release, e);
            }
            res?;
            for w in &warnings {
                self.log(format!("warning: {w}"));
            }
            return Ok(Outcome::Applied { level, warnings });
        }
        self.log(format!("no usable cached level for {release}"));
        Ok(Outcome::NothingToLoad)
    }

    // ------------------------------------------------------------------
    // revert

    /// Disable and unload our livepatch and put the node on hold, so
    /// neither the timer nor the boot unit loads it again.
    pub fn revert(&self) -> Result<Outcome, ApplyError> {
        let release = self.kernel.release()?;
        let mut state = State::load(&self.cfg.state_file())?;
        let ours: Vec<_> = self.kernel.livepatches()?.into_iter().filter(|p| is_ours(&p.name)).collect();
        {
            let k = state.kernel(&release);
            k.held = true;
            k.desired_level = None;
        }
        self.write_runtime_files(&release, None);
        if ours.is_empty() {
            self.save_phase(&mut state, &release, Phase::Reverted, None)?;
            return Ok(Outcome::NothingActive);
        }
        let mut levels = Vec::new();
        for p in ours {
            if let Err(e) = self.back_out(&p.name) {
                self.save_stuck(&mut state, &release, e.clone())?;
                return Err(ApplyError::Failed(e));
            }
            levels.extend(level_from_module_name(&p.name));
        }
        self.save_phase(&mut state, &release, Phase::Reverted, None)?;
        Ok(Outcome::Reverted { levels })
    }

    /// The cached manifest for the level that should be active.
    pub fn cached_manifest(&self, release: &str, level: u32) -> Option<(Manifest, String)> {
        let v = self.load_cached(&self.cache_dir(release, level)).ok()?;
        Some((v.manifest, v.signer))
    }
}

/// The revocation entry for this manifest: by module hash, or by kernel and
/// level (a level is never published twice with different bytes).
pub fn revoked_entry<'a>(
    list: &'a RevocationList,
    release: &str,
    m: &Manifest,
) -> Option<&'a klp_core::revocation::Revoked> {
    list.find(&m.sha256).or_else(|| list.revoked.iter().find(|r| r.kernel == release && r.level == m.level))
}

/// Kernel log lines that explain a failed module load.
fn is_load_related(line: &str, module: &str) -> bool {
    const MARKERS: &[&str] = &[
        "livepatch",
        "module verification",
        "module signature",
        "Loading of",
        "Lockdown",
        "PKCS#7",
        "X.509",
        "Key was rejected",
        "Unknown symbol",
        "disagrees about version",
        "version magic",
        "BTF",
    ];
    line.contains(module) || MARKERS.iter().any(|m| line.contains(m))
}

fn strip_sympos(f: &str) -> &str {
    f.split_once(',').map(|(a, _)| a).unwrap_or(f)
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
