//! The agent's workflows: apply, boot, revert.
//!
//! Invariants:
//! * Nothing is loaded that was not verified against a trusted signature,
//!   the running kernel release and build-id, and the manifest hash.
//! * `force` is never written. A stuck transition is reversed; if the
//!   reversal is stuck too, the agent stops and reports.
//! * A node is never left worse than before: if a new level misbehaves
//!   after its transition, it is disabled and the previous level is
//!   restored from the local cache.

use std::cell::RefCell;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow};
use chrono::{DateTime, Utc};
use klp_core::manifest::Manifest;
use klp_core::naming::{MODULE_PREFIX, level_from_module_name};
use klp_core::policy::{self, Decision, Mode, NodeFacts};
use klp_core::sig::TrustStore;
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::kernel::{KernelOps, is_bad_kmsg, taint};
use crate::repo::{Repo, RepoError};
use crate::state::{Phase, State, write_atomic};

const MAX_MANIFEST: u64 = 1 << 20;
const MAX_SIGNATURE: u64 = 64 << 10;
const MAX_MODULE: u64 = 256 << 20;
const POLL: Duration = Duration::from_millis(500);
const BLOCKER_REPORT_EVERY: Duration = Duration::from_secs(15);

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
    /// Started by an operator (clears a hold), not by the timer.
    pub explicit: bool,
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
        Self { cfg, kernel, repo, trust, now: Box::new(Utc::now), echo: false, log: RefCell::new(vec![]) }
    }

    pub fn log(&self, msg: impl Into<String>) {
        let msg = msg.into();
        if self.echo {
            eprintln!("pve-klp: {msg}");
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

    // ------------------------------------------------------------------
    // apply

    pub fn apply(&self, opts: &ApplyOpts) -> Result<Outcome, ApplyError> {
        let release = self.kernel.release()?;
        let mut state = State::load(&self.cfg.state_file())?;
        // On hold after `revert`: the timer does nothing at all, not even
        // contact the repository. Only an explicit `apply` resumes.
        if state.get(&release).held && !opts.explicit {
            self.log("livepatching is on hold after `pve-klp revert`; run `pve-klp apply` to resume");
            return Ok(Outcome::Skipped("held after revert".into()));
        }
        let active = self.preflight(opts.replace_foreign)?;
        let repo = self.repo.as_ref().ok_or_else(|| anyhow!("no repository configured"))?;

        let base = format!("v1/{release}/{}", self.cfg.ring);
        let raw = match repo.get(&format!("{base}/manifest.json"), MAX_MANIFEST) {
            Ok(b) => b,
            Err(RepoError::NotFound(_)) => {
                self.log(format!("no livepatch published for {release} in ring {}", self.cfg.ring));
                return Ok(Outcome::NothingPublished);
            }
            Err(RepoError::Other(e)) => return Err(e.into()),
        };
        let sig = repo
            .get(&format!("{base}/manifest.json.minisig"), MAX_SIGNATURE)
            .map_err(|e| ApplyError::Rejected(format!("manifest signature missing: {e}")))?;

        let v = self.verify_manifest(raw, &sig).inspect_err(|e| {
            let _ = self.save_phase(&mut state, &release, Phase::Failed, Some(e.to_string()));
        })?;
        let m = &v.manifest;
        self.log(format!("manifest {} level {} ring {} signed by {}", m.kernel, m.level, m.ring, v.signer));

        let warnings = match self.decide(m, &state, active.as_ref().map(|a| a.1), Mode::Fetch, opts)? {
            Go::Apply(w) => w,
            Go::AlreadyActive => return Ok(Outcome::AlreadyActive { level: m.level }),
            Go::Skip(why) => return Ok(Outcome::Skipped(why)),
        };
        self.save_phase(&mut state, &release, Phase::Fetched, None)?;

        let ko = repo
            .get(&format!("v1/{release}/{}", m.module), MAX_MODULE)
            .map_err(|e| ApplyError::Rejected(format!("module download failed: {e}")))?;
        if sha256_hex(&ko) != m.sha256 {
            let msg = format!("module {} does not match the manifest hash", m.module);
            self.save_phase(&mut state, &release, Phase::Failed, Some(msg.clone()))?;
            return Err(ApplyError::Rejected(msg));
        }
        let dir = self.cache_dir(&release, m.level);
        write_atomic(&dir.join(&m.module), &ko)?;
        write_atomic(&dir.join("manifest.json"), &v.raw)?;
        write_atomic(&dir.join("manifest.json.minisig"), v.sig.as_bytes())?;

        let file = self.open_verified_module(m, &release, &dir).inspect_err(|e| {
            let _ = self.save_phase(&mut state, &release, Phase::Failed, Some(e.to_string()));
        })?;
        self.save_phase(&mut state, &release, Phase::Verified, None)?;
        state.kernel(&release).signed_by = Some(v.signer.clone());

        self.activate(&mut state, &release, m, &file, active.map(|a| a.1), true)?;
        for w in &warnings {
            self.log(format!("warning: {w}"));
        }
        Ok(Outcome::Applied { level: m.level, warnings })
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
        file.read_to_end(&mut bytes).context("reading module")?;
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
                "livepatch {} is in transition; wait for it to finish or run `pve-klp revert`",
                p.name
            )));
        }
        let foreign: Vec<_> = patches.iter().filter(|p| !p.name.starts_with(MODULE_PREFIX)).collect();
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
            .filter(|p| p.enabled && p.name.starts_with(MODULE_PREFIX))
            .filter_map(|p| level_from_module_name(&p.name).map(|l| (p.name.clone(), l)))
            .max_by_key(|(_, l)| *l);

        for m in self.kernel.modules()? {
            if !m.is_livepatch() || patches.iter().any(|p| p.name == m.name) {
                continue;
            }
            if m.refcnt > 0 {
                return Err(ApplyError::Precondition(format!(
                    "module {} is a livepatch without sysfs entry that is still referenced; this is \
                     what a forced transition leaves behind. Do not load further patches; reboot.",
                    m.name
                )));
            }
            if m.name.starts_with(MODULE_PREFIX) {
                self.log(format!("removing leftover module {}", m.name));
                self.kernel.unload_module(&m.name)?;
            }
        }
        Ok(active)
    }

    /// Load, wait for the transition, run post-checks. On any failure the
    /// patch is backed out and, if it had replaced an older level, that
    /// level is restored from cache.
    fn activate(
        &self,
        state: &mut State,
        release: &str,
        m: &Manifest,
        file: &File,
        previous: Option<u32>,
        restore_on_failure: bool,
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
        self.save_phase(state, release, Phase::Loading, None)?;
        self.log(format!("loading {name}"));

        if let Err(e) = self.kernel.load_module(file) {
            let mut msg = e.to_string();
            if let Some(k) = kmsg.as_mut() {
                let lines = k.drain().unwrap_or_default();
                if !lines.is_empty() {
                    msg.push_str("\nkernel log:\n  ");
                    msg.push_str(&lines.join("\n  "));
                }
            }
            self.save_phase(state, release, Phase::Failed, Some(msg.clone()))?;
            return Err(ApplyError::Failed(msg));
        }

        match self.wait_transition(name, true)? {
            Wait::Done => {}
            Wait::Gone => {
                let msg = format!("{name} disappeared during its transition");
                self.save_phase(state, release, Phase::Failed, Some(msg.clone()))?;
                return Err(ApplyError::Failed(msg));
            }
            Wait::Timeout(blockers) => {
                let mut msg = format!(
                    "transition of {name} did not finish within {} s; blocking tasks:\n{blockers}",
                    self.cfg.transition_timeout
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

        if let Err(why) = self.post_checks(m, taint_before, kmsg.as_deref_mut()) {
            let mut msg = format!("{name} activated, but post-checks failed: {why}");
            self.log(&msg);
            if let Err(e) = self.back_out(name) {
                msg.push_str(&format!("\n{e}"));
                self.save_stuck(state, release, msg.clone())?;
                return Err(ApplyError::Failed(msg));
            }
            msg.push_str(&format!("\n{name} was disabled and unloaded"));
            if let (Some(prev), true) = (previous, restore_on_failure) {
                match self.restore(state, release, prev) {
                    Ok(()) => msg.push_str(&format!("; level {prev} was restored from cache")),
                    Err(e) => msg.push_str(&format!("; restoring level {prev} failed: {e}")),
                }
            }
            self.save_phase(state, release, Phase::Failed, Some(msg.clone()))?;
            return Err(ApplyError::Failed(msg));
        }

        self.cleanup_replaced(name);
        let k = state.kernel(release);
        k.highest_accepted = k.highest_accepted.max(m.level);
        k.desired_level = Some(m.level);
        k.held = false;
        self.save_phase(state, release, Phase::Active, None)?;
        self.log(format!("{name} is active (level {})", m.level));
        Ok(())
    }

    fn post_checks(
        &self,
        m: &Manifest,
        taint_before: u64,
        kmsg: Option<&mut (dyn crate::kernel::KmsgWatch + 'static)>,
    ) -> Result<(), String> {
        let name = &m.module_name;
        match self.kernel.patch(name).map_err(|e| e.to_string())? {
            Some(p) if p.enabled && !p.transition => {}
            other => return Err(format!("unexpected patch state after transition: {other:?}")),
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
            let bad: Vec<String> =
                k.drain().map_err(|e| e.to_string())?.into_iter().filter(|l| is_bad_kmsg(l)).collect();
            if !bad.is_empty() {
                return Err(format!("kernel log since loading:\n  {}", bad.join("\n  ")));
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
        self.run_hooks(m)
    }

    fn run_hooks(&self, m: &Manifest) -> Result<(), String> {
        let Ok(entries) = std::fs::read_dir(&self.cfg.hooks_dir) else { return Ok(()) };
        let mut hooks: Vec<PathBuf> = entries.flatten().map(|e| e.path()).filter(|p| is_executable(p)).collect();
        hooks.sort();
        for h in hooks {
            self.log(format!("running hook {}", h.display()));
            let status = std::process::Command::new(&h)
                .env("PVE_KLP_KERNEL", &m.kernel)
                .env("PVE_KLP_LEVEL", m.level.to_string())
                .env("PVE_KLP_MODULE", &m.module_name)
                .status()
                .map_err(|e| format!("hook {}: {e}", h.display()))?;
            if !status.success() {
                return Err(format!("hook {} failed with {status}", h.display()));
            }
        }
        Ok(())
    }

    fn wait_transition(&self, name: &str, target: bool) -> anyhow::Result<Wait> {
        let timeout = self.cfg.transition_timeout();
        let mut waited = Duration::ZERO;
        let mut last_report = Duration::ZERO;
        loop {
            match self.kernel.patch(name)? {
                None => return Ok(Wait::Gone),
                Some(p) if !p.transition => return Ok(Wait::Done),
                Some(_) => {}
            }
            if waited >= timeout {
                let tasks = self.kernel.blocking_tasks(target).unwrap_or_default();
                let list = if tasks.is_empty() {
                    "  (none found)".to_owned()
                } else {
                    tasks.iter().map(|t| format!("  {t}")).collect::<Vec<_>>().join("\n")
                };
                return Ok(Wait::Timeout(list));
            }
            if waited >= last_report + BLOCKER_REPORT_EVERY {
                last_report = waited;
                let tasks = self.kernel.blocking_tasks(target).unwrap_or_default();
                let names: Vec<String> = tasks.iter().take(10).map(|t| format!("{}[{}]", t.comm, t.tid)).collect();
                self.log(format!(
                    "{name}: transition still running after {} s, waiting for: {}",
                    waited.as_secs(),
                    names.join(" ")
                ));
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
                     pve-klp does not use `force`. Leave the node as it is, collect the task list \
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
            let others: Vec<_> =
                mods.into_iter().filter(|m| m.name.starts_with(MODULE_PREFIX) && m.name != current).collect();
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

    /// Reload a previously accepted level from the local cache.
    fn restore(&self, state: &mut State, release: &str, level: u32) -> Result<(), ApplyError> {
        let dir = self.cache_dir(release, level);
        let v = self.load_cached(&dir)?;
        let file = self.open_verified_module(&v.manifest, release, &dir)?;
        self.log(format!("restoring level {level}"));
        // After atomic replace the old module is still loaded, just without
        // a patch. preflight() unloads such leftovers of ours.
        self.preflight(true)?;
        self.activate(state, release, &v.manifest, &file, None, false)
    }

    fn load_cached(&self, dir: &Path) -> Result<Verified, ApplyError> {
        let raw =
            std::fs::read(dir.join("manifest.json")).with_context(|| format!("reading cache {}", dir.display()))?;
        let sig = std::fs::read(dir.join("manifest.json.minisig")).context("reading cached signature")?;
        self.verify_manifest(raw, &sig)
    }

    // ------------------------------------------------------------------
    // boot

    /// After a reboot into the same kernel: reload the level that was
    /// active before, from the local cache, without network.
    pub fn boot(&self) -> Result<Outcome, ApplyError> {
        let release = self.kernel.release()?;
        let mut state = State::load(&self.cfg.state_file())?;
        let ks = state.get(&release);
        let Some(level) = ks.desired_level else {
            self.log(format!("nothing to reload for {release}"));
            return Ok(Outcome::NothingToLoad);
        };
        if ks.held {
            return Ok(Outcome::Skipped("held after revert".into()));
        }
        let active = self.preflight(false)?;
        let dir = self.cache_dir(&release, level);
        if !dir.join("manifest.json").exists() {
            self.log(format!("level {level} for {release} is not in the cache"));
            return Ok(Outcome::NothingToLoad);
        }
        let v = self.load_cached(&dir)?;
        let opts = ApplyOpts::default();
        let warnings =
            match self.decide(&v.manifest, &state, active.as_ref().map(|a| a.1), Mode::BootFromCache, &opts)? {
                Go::Apply(w) => w,
                Go::AlreadyActive => return Ok(Outcome::AlreadyActive { level }),
                Go::Skip(why) => return Ok(Outcome::Skipped(why)),
            };
        let file = self.open_verified_module(&v.manifest, &release, &dir)?;
        self.activate(&mut state, &release, &v.manifest, &file, active.map(|a| a.1), false)?;
        for w in &warnings {
            self.log(format!("warning: {w}"));
        }
        Ok(Outcome::Applied { level, warnings })
    }

    // ------------------------------------------------------------------
    // revert

    /// Disable and unload our livepatch and put the node on hold, so
    /// neither the timer nor the boot unit loads it again.
    pub fn revert(&self) -> Result<Outcome, ApplyError> {
        let release = self.kernel.release()?;
        let mut state = State::load(&self.cfg.state_file())?;
        let ours: Vec<_> =
            self.kernel.livepatches()?.into_iter().filter(|p| p.name.starts_with(MODULE_PREFIX)).collect();
        {
            let k = state.kernel(&release);
            k.held = true;
            k.desired_level = None;
        }
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

fn strip_sympos(f: &str) -> &str {
    f.split_once(',').map(|(a, _)| a).unwrap_or(f)
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}
