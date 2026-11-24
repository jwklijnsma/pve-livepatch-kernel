//! End-to-end tests of the agent against the emulated kernel, including
//! the negative tests from the design document.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use hvpatch::agent::{Agent, ApplyError, ApplyOpts, Outcome};
use hvpatch::config::Config;
use hvpatch::fake::FakeKernel;
use hvpatch::repo::FileRepo;
use hvpatch::report;
use hvpatch::state::{Phase, State};
use klp_core::manifest::{Fix, Manifest, NotCovered};
use klp_core::naming::module_name;
use klp_core::sig::{SecretKey, TrustStore};
use object::write::{Object as WObject, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope};

const KVER: &str = "7.3.5-1-pve";
const BUILD_ID: &str = "00112233445566778899aabbccddeeff00112233";

fn key() -> SecretKey {
    SecretKey::from_seed([1; 8], [1; 32])
}

fn now() -> DateTime<Utc> {
    "2026-11-24T12:00:00Z".parse().unwrap()
}

fn ko(name: &str, kver: &str, signed: bool) -> Vec<u8> {
    let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let s = obj.add_section(vec![], b".modinfo".to_vec(), SectionKind::ReadOnlyData);
    let mut mi = Vec::new();
    for kv in [
        format!("name={name}"),
        format!("vermagic={kver} SMP preempt mod_unload modversions "),
        "livepatch=Y".into(),
        "license=GPL".into(),
    ] {
        mi.extend_from_slice(kv.as_bytes());
        mi.push(0);
    }
    obj.append_section_data(s, &mi, 1);
    let t = obj.add_section(vec![], b".text".to_vec(), SectionKind::Text);
    obj.append_section_data(t, &[0xc3; 8], 16);
    obj.add_symbol(Symbol {
        name: b"tcp_fix_me".to_vec(),
        value: 0,
        size: 1,
        kind: SymbolKind::Text,
        scope: SymbolScope::Compilation,
        weak: false,
        section: SymbolSection::Section(t),
        flags: SymbolFlags::None,
    });
    let mut b = obj.write().unwrap();
    if signed {
        b.extend_from_slice(b"fake-pkcs7");
        b.extend_from_slice(klp_core::elf::MODULE_SIG_MAGIC);
    }
    b
}

struct Env {
    _tmp: tempfile::TempDir,
    repo: PathBuf,
    cfg: Config,
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let cfg = Config {
            repository: repo.display().to_string(),
            ring: "stable".into(),
            state_dir: tmp.path().join("state"),
            textfile_dir: None,
            hooks_dir: tmp.path().join("hooks"),
            trusted_keys_dir: tmp.path().join("trusted"),
            module_cert: None,
            transition_timeout: 30,
            settle_time: 1,
            ..Default::default()
        };
        Env { _tmp: tmp, repo, cfg }
    }

    fn manifest(&self, level: u32) -> Manifest {
        let name = module_name(KVER, level);
        Manifest {
            format: 1,
            kernel: KVER.into(),
            kernel_build_id: Some(BUILD_ID.into()),
            level,
            ring: "stable".into(),
            module: format!("{name}.ko"),
            module_name: name,
            sha256: String::new(),
            built: "2026-11-23T09:00:00Z".parse().unwrap(),
            expires: "2026-12-23T09:00:00Z".parse().unwrap(),
            fixes: vec![Fix { id: "CVE-2026-0001".into(), title: None, functions: vec!["vmlinux:tcp_fix_me".into()] }],
            not_covered: vec![NotCovered {
                id: "CVE-2026-0002".into(),
                reason: "struct change".into(),
                fixed_in: Some("7.3.6-1-pve".into()),
                mitigation: None,
            }],
            superseded_by_kernel: None,
            builder_image: None,
            catalog_commit: None,
        }
    }

    /// Write module, manifest and signature like the pipeline would.
    fn publish(&self, mut m: Manifest, module: &[u8]) -> Manifest {
        let dir = self.repo.join("v1").join(&m.kernel);
        std::fs::create_dir_all(dir.join(&m.ring)).unwrap();
        std::fs::write(dir.join(&m.module), module).unwrap();
        if m.sha256.is_empty() {
            m.sha256 = hvpatch::agent::sha256_hex(module);
        }
        let json = m.to_json_pretty();
        std::fs::write(dir.join(&m.ring).join("manifest.json"), &json).unwrap();
        let sig = key().sign(json.as_bytes(), &format!("kernel:{} level:{}", m.kernel, m.level)).unwrap();
        std::fs::write(dir.join(&m.ring).join("manifest.json.minisig"), sig).unwrap();
        m
    }

    fn publish_level(&self, level: u32) -> Manifest {
        let m = self.manifest(level);
        let ko = ko(&m.module_name, KVER, true);
        self.publish(m, &ko)
    }

    fn agent(&self, k: FakeKernel) -> Agent<FakeKernel> {
        let mut trust = TrustStore::default();
        trust.add("project", &key().public_key_file()).unwrap();
        let mut a = Agent::new(self.cfg.clone(), k, Some(Box::new(FileRepo { base: self.repo.clone() })), trust);
        a.now = Box::new(now);
        a
    }

    fn state(&self) -> State {
        State::load(&self.cfg.state_file()).unwrap()
    }
}

fn explicit() -> ApplyOpts {
    ApplyOpts { explicit: true, ..Default::default() }
}

fn kernel() -> FakeKernel {
    FakeKernel::new(KVER)
}

#[test]
fn apply_happy_path_and_status() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { level: 1, .. }));
    assert_eq!(a.kernel.active(), vec!["klp_hvp_7_3_5_1_p1"]);
    let st = env.state();
    assert_eq!(st.get(KVER).phase, Phase::Active);
    assert_eq!(st.get(KVER).highest_accepted, 1);

    // Idempotent.
    assert_eq!(a.apply(&explicit()).unwrap(), Outcome::AlreadyActive { level: 1 });

    let r = report::collect(&a).unwrap();
    assert_eq!(r.covered, vec!["CVE-2026-0001"]);
    assert!(r.reboot_required, "not_covered must surface as reboot required");
    assert_eq!(r.exit_code(), report::exit::REBOOT_REQUIRED);
    assert_eq!(r.manifest.as_ref().unwrap().signed_by, "project");
    let prom = r.to_prometheus();
    assert!(prom.contains("hvpatch_info{kernel=\"7.3.5-1-pve\",ring=\"stable\",state=\"active\"} 1"), "{prom}");
    assert!(r.to_text().contains("NOT covered:   CVE-2026-0002"));
}

#[test]
fn atomic_replace_upgrades_and_unloads_old_module() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    env.publish_level(2);
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { level: 2, .. }));
    assert_eq!(a.kernel.active(), vec!["klp_hvp_7_3_5_1_p2"]);
    assert_eq!(a.kernel.loaded(), vec!["klp_hvp_7_3_5_1_p2"], "replaced module must be unloaded");
}

#[test]
fn nothing_published_is_not_an_error() {
    let env = Env::new();
    let a = env.agent(kernel());
    assert_eq!(a.apply(&explicit()).unwrap(), Outcome::NothingPublished);
}

// --- Negative tests from the design document ------------------------------

#[test]
fn module_for_other_kernel_is_rejected() {
    let env = Env::new();
    let mut m = env.manifest(1);
    m.kernel = "7.3.4-1-pve".into();
    // Published under the running kernel's path, but for another kernel.
    let ko = ko(&m.module_name, "7.3.4-1-pve", true);
    let mut m = env.publish(m.clone(), &ko);
    let dir = env.repo.join("v1").join(KVER).join("stable");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(env.repo.join("v1/7.3.4-1-pve/stable/manifest.json"), dir.join("manifest.json")).unwrap();
    std::fs::copy(env.repo.join("v1/7.3.4-1-pve/stable/manifest.json.minisig"), dir.join("manifest.json.minisig"))
        .unwrap();
    let a = env.agent(kernel());
    let e = a.apply(&explicit()).unwrap_err();
    assert!(matches!(e, ApplyError::Rejected(ref s) if s.contains("running kernel is 7.3.5-1-pve")), "{e}");
    assert!(a.kernel.loaded().is_empty());

    // Correct manifest, but the module inside has the wrong vermagic.
    m.kernel = KVER.into();
    m.sha256.clear();
    env.publish(m, &ko);
    let e = a.apply(&explicit()).unwrap_err();
    assert!(matches!(e, ApplyError::Rejected(ref s) if s.contains("vermagic")), "{e}");
    assert!(a.kernel.loaded().is_empty());
}

#[test]
fn rebuilt_kernel_with_same_release_is_rejected() {
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    k.st.borrow_mut().build_id = Some("ffff".into());
    let a = env.agent(k);
    let e = a.apply(&explicit()).unwrap_err();
    assert!(matches!(e, ApplyError::Rejected(ref s) if s.contains("build-id")), "{e}");
}

#[test]
fn tampered_module_is_rejected() {
    let env = Env::new();
    let m = env.publish_level(1);
    let p = env.repo.join("v1").join(KVER).join(&m.module);
    let mut b = std::fs::read(&p).unwrap();
    b[100] ^= 0xff;
    std::fs::write(&p, b).unwrap();
    let a = env.agent(kernel());
    let e = a.apply(&explicit()).unwrap_err();
    assert!(matches!(e, ApplyError::Rejected(ref s) if s.contains("hash")), "{e}");
    assert!(a.kernel.loaded().is_empty());
    assert_eq!(env.state().get(KVER).phase, Phase::Failed);
}

#[test]
fn tampered_manifest_is_rejected() {
    let env = Env::new();
    env.publish_level(1);
    let p = env.repo.join("v1").join(KVER).join("stable/manifest.json");
    let s = std::fs::read_to_string(&p).unwrap().replace("\"level\": 1", "\"level\": 9");
    std::fs::write(&p, s).unwrap();
    let a = env.agent(kernel());
    let e = a.apply(&explicit()).unwrap_err();
    assert!(matches!(e, ApplyError::Rejected(ref s) if s.contains("signature")), "{e}");
}

#[test]
fn manifest_signed_by_unknown_key_is_rejected() {
    let env = Env::new();
    let m = env.publish_level(1);
    let dir = env.repo.join("v1").join(KVER).join("stable");
    let json = std::fs::read(dir.join("manifest.json")).unwrap();
    let evil = SecretKey::from_seed([9; 8], [9; 32]).sign(&json, "x").unwrap();
    std::fs::write(dir.join("manifest.json.minisig"), evil).unwrap();
    let a = env.agent(kernel());
    assert!(matches!(a.apply(&explicit()), Err(ApplyError::Rejected(_))), "{m:?}");
}

#[test]
fn expired_manifest_is_rejected() {
    let env = Env::new();
    let mut m = env.manifest(1);
    m.expires = "2026-11-24T00:00:00Z".parse().unwrap();
    let ko = ko(&m.module_name, KVER, true);
    env.publish(m, &ko);
    let a = env.agent(kernel());
    let e = a.apply(&explicit()).unwrap_err();
    assert!(matches!(e, ApplyError::Rejected(ref s) if s.contains("expired")), "{e}");
}

#[test]
fn lower_level_is_rejected_even_after_revert() {
    let env = Env::new();
    env.publish_level(3);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    a.revert().unwrap();
    // An attacker (or a stale mirror) serves an older, validly signed level.
    env.publish_level(2);
    let e = a.apply(&explicit()).unwrap_err();
    assert!(matches!(e, ApplyError::Rejected(ref s) if s.contains("rollback")), "{e}");
    assert!(a.kernel.loaded().is_empty());
}

#[test]
fn secure_boot_without_mok_fails_cleanly() {
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    // Secure Boot on, certificate not enrolled: the kernel rejects it.
    k.st.borrow_mut().require_signature = true;
    k.st.borrow_mut().kmsg_on_load = vec![
        "softdog: soft_reboot_cmd=<not set> soft_active_on_boot=0".into(),
        "Loading of module with unavailable key is rejected".into(),
    ];
    let m = env.manifest(1);
    let unsigned = ko(&m.module_name, KVER, false);
    env.publish(m, &unsigned);
    let a = env.agent(k);
    let e = a.apply(&explicit()).unwrap_err();
    assert!(matches!(e, ApplyError::Failed(ref s) if s.contains("mok enroll")), "{e}");
    assert!(e.to_string().contains("unavailable key is rejected"), "{e}");
    assert!(!e.to_string().contains("softdog"), "unrelated kernel log lines must not end up in the error: {e}");
    assert!(a.kernel.loaded().is_empty(), "no half-loaded state");
    assert!(a.kernel.active().is_empty());
    let st = env.state().get(KVER);
    assert_eq!(st.phase, Phase::Failed);
    assert_eq!(st.highest_accepted, 0);
}

#[test]
fn stuck_transition_is_reversed_after_timeout_never_forced() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();

    env.publish_level(2);
    {
        let mut st = a.kernel.st.borrow_mut();
        st.stuck = true;
        st.blockers =
            vec![hvpatch::kernel::BlockingTask { pid: 4242, tid: 4250, comm: "CPU 3/KVM".into(), stack: None }];
    }
    let e = a.apply(&explicit()).unwrap_err();
    let msg = e.to_string();
    assert!(matches!(e, ApplyError::Failed(_)));
    assert!(msg.contains("CPU 3/KVM (pid 4242 tid 4250)"), "{msg}");
    assert!(msg.contains("reversed"), "{msg}");
    // Level 1 stays active, level 2 is gone, nothing was forced.
    assert_eq!(a.kernel.active(), vec!["klp_hvp_7_3_5_1_p1"]);
    assert_eq!(a.kernel.loaded(), vec!["klp_hvp_7_3_5_1_p1"]);
    assert!(a.kernel.st.borrow().calls.iter().all(|c| !c.contains("force")));
    let st = env.state().get(KVER);
    assert_eq!(st.phase, Phase::Failed, "an automatic reversal is a failed apply");
    assert!(!st.held, "only the operator's revert holds");
    assert_eq!(st.highest_accepted, 1);
    let r = report::collect(&a).unwrap();
    assert_eq!(r.exit_code(), report::exit::FAILED);
    assert!(!r.reboot_reasons.iter().any(|x| x.contains("neither complete")), "{:?}", r.reboot_reasons);
    assert!(r.hints.iter().any(|h| h.contains("run `hvpatch apply` again")), "{:?}", r.hints);
    assert!(r.last_error.unwrap().contains("CPU 3/KVM"));
    assert_eq!(st.desired_level, Some(1));
}

#[test]
fn stuck_reversal_is_reported_not_forced() {
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    k.st.borrow_mut().stuck = true;
    k.st.borrow_mut().reverse_stuck = true;
    let a = env.agent(k);
    let e = a.apply(&explicit()).unwrap_err();
    assert!(e.to_string().contains("does not use `force`"), "{e}");
    assert_eq!(env.state().get(KVER).phase, Phase::Failed);
    assert!(env.state().get(KVER).stuck);
    assert!(report::collect(&a).unwrap().reboot_reasons.iter().any(|x| x.contains("neither complete")));
    assert!(report::collect(&a).unwrap().hints.is_empty(), "still in transition: no leftover yet");

    // Later the blocking task goes away and the kernel finishes the
    // reversal on its own: the module stays loaded, unused.
    {
        let mut st = a.kernel.st.borrow_mut();
        st.reverse_stuck = false;
        st.stuck = false;
    }
    for _ in 0..5 {
        let _ = hvpatch::kernel::KernelOps::patch(&a.kernel, "klp_hvp_7_3_5_1_p1");
    }
    let r = report::collect(&a).unwrap();
    assert_eq!(r.hints.len(), 1, "{:?}", r.hints);
    assert!(r.hints[0].contains("transition has completed") && r.hints[0].contains("rmmod klp_hvp_7_3_5_1_p1"));
    assert!(r.to_text().contains("note:"));
    // The next apply cleans it up and loads again.
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { level: 1, .. }));
    assert!(report::collect(&a).unwrap().hints.is_empty());
}

#[test]
fn old_module_is_not_loaded_after_kernel_update() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    // Reboot into a new kernel: fresh kernel, same state dir.
    let a = env.agent(FakeKernel::new("7.3.6-1-pve"));
    assert_eq!(a.boot().unwrap(), Outcome::NothingToLoad);
    assert!(a.kernel.loaded().is_empty());
}

// --- Further behaviour ----------------------------------------------------

#[test]
fn boot_reloads_from_cache_without_network() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    std::fs::remove_dir_all(&env.repo).unwrap();
    let a = env.agent(kernel());
    assert!(matches!(a.boot().unwrap(), Outcome::Applied { level: 1, .. }));
    assert_eq!(a.kernel.active(), vec!["klp_hvp_7_3_5_1_p1"]);
}

#[test]
fn status_reports_pending_after_reboot_until_boot_unit_ran() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    assert_eq!(report::collect(&a).unwrap().phase, Phase::Active);
    // Reboot into the same kernel: state says active, kernel has nothing.
    let b = env.agent(kernel());
    let r = report::collect(&b).unwrap();
    assert_eq!(r.phase, Phase::Pending);
    assert_eq!(r.exit_code(), report::exit::NOT_ACTIVE);
    assert!(serde_json::to_string(&r).unwrap().contains("\"phase\":\"pending\""));
    b.boot().unwrap();
    assert_eq!(report::collect(&b).unwrap().phase, Phase::Active);
}

#[test]
fn boot_reloads_expired_manifest_with_warning() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    let mut a = env.agent(kernel());
    a.now = Box::new(|| "2027-02-01T00:00:00Z".parse().unwrap());
    match a.boot().unwrap() {
        Outcome::Applied { warnings, .. } => assert!(warnings[0].contains("expired")),
        o => panic!("{o:?}"),
    }
}

#[test]
fn bad_kernel_log_after_transition_restores_previous_level() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    env.publish_level(2);
    a.kernel.st.borrow_mut().kmsg_on_load = vec!["WARNING: CPU: 5 PID: 1 at net/ipv4/tcp.c:42 tcp_fix_me".into()];
    let e = a.apply(&explicit()).unwrap_err();
    let msg = e.to_string();
    assert!(msg.contains("post-checks failed") && msg.contains("level 1 was restored"), "{msg}");
    assert_eq!(a.kernel.active(), vec!["klp_hvp_7_3_5_1_p1"]);
    assert_eq!(a.kernel.loaded(), vec!["klp_hvp_7_3_5_1_p1"]);
    let st = env.state().get(KVER);
    assert_eq!(st.highest_accepted, 1, "a failed level must not count as accepted");
    assert_eq!(st.desired_level, Some(1));
}

#[test]
fn new_taint_triggers_back_out() {
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    k.st.borrow_mut().taint_on_load = hvpatch::kernel::taint::WARN;
    let a = env.agent(k);
    let e = a.apply(&explicit()).unwrap_err();
    assert!(e.to_string().contains("taint flags W"), "{e}");
    assert!(a.kernel.loaded().is_empty());
}

#[test]
fn host_without_zfs_accepts_the_modules_own_oot_taint() {
    // No ZFS/spl loaded: the kernel is untainted until the livepatch module
    // itself sets O, K (and E). That must not count as a new problem.
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    k.st.borrow_mut().tainted = 0;
    let a = env.agent(k);
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { level: 1, .. }));
    // Same after a reboot into the same kernel.
    let k = kernel();
    k.st.borrow_mut().tainted = 0;
    let b = env.agent(k);
    assert!(matches!(b.boot().unwrap(), Outcome::Applied { level: 1, .. }));
}

#[test]
fn unexplained_taint_still_fails_on_untainted_host() {
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    {
        let mut st = k.st.borrow_mut();
        st.tainted = 0;
        st.taint_on_load = hvpatch::kernel::taint::WARN;
    }
    let a = env.agent(k);
    let e = a.apply(&explicit()).unwrap_err();
    assert!(e.to_string().contains("taint flags W") && !e.to_string().contains('O'), "{e}");
}

#[test]
fn missing_function_triggers_back_out() {
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    k.st.borrow_mut().functions_on_load = vec![("vmlinux:something_else,1".into(), true)];
    let a = env.agent(k);
    let e = a.apply(&explicit()).unwrap_err();
    assert!(e.to_string().contains("vmlinux:tcp_fix_me"), "{e}");
    assert!(a.kernel.loaded().is_empty());
}

#[test]
fn failing_hook_triggers_back_out() {
    let env = Env::new();
    env.publish_level(1);
    std::fs::create_dir_all(&env.cfg.hooks_dir).unwrap();
    write_script(&env.cfg.hooks_dir.join("10-check"), "#!/bin/sh\n[ \"$HVPATCH_LEVEL\" = 1 ] && exit 3\nexit 0\n");
    let a = env.agent(kernel());
    let e = a.apply(&explicit()).unwrap_err();
    assert!(e.to_string().contains("10-check failed"), "{e}");
    assert!(a.kernel.loaded().is_empty());
}

#[test]
fn foreign_livepatch_blocks_unless_allowed() {
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    k.load_foreign("kpatch_vendor_fix");
    let a = env.agent(k);
    assert!(matches!(a.apply(&explicit()), Err(ApplyError::Precondition(ref s)) if s.contains("kpatch_vendor_fix")));
    let opts = ApplyOpts { replace_foreign: true, explicit: true, ..Default::default() };
    assert!(matches!(a.apply(&opts).unwrap(), Outcome::Applied { .. }));
    assert_eq!(a.kernel.active(), vec!["klp_hvp_7_3_5_1_p1"]);
}

#[test]
fn livepatch_from_before_the_rename_is_ours_and_gets_replaced() {
    let env = Env::new();
    env.publish_level(4);
    let k = kernel();
    k.load_foreign("klp_pve_7_3_5_1_p3"); // built by pve-klp 0.1.x
    let a = env.agent(k);
    assert_eq!(report::collect(&a).unwrap().active.unwrap().level, Some(3));
    assert!(report::collect(&a).unwrap().foreign_patches.is_empty());
    // No --replace-foreign needed.
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { level: 4, .. }));
    assert_eq!(a.kernel.active(), vec!["klp_hvp_7_3_5_1_p4"]);
    assert_eq!(a.kernel.loaded(), vec!["klp_hvp_7_3_5_1_p4"], "the old module is unloaded");
}

#[test]
fn forced_leftover_blocks_further_loading() {
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    k.st.borrow_mut().modules.push(hvpatch::kernel::ModuleInfo {
        name: "klp_hvp_7_3_5_1_p0".into(),
        taint: "K".into(),
        refcnt: 1,
    });
    let a = env.agent(k);
    assert!(matches!(a.apply(&explicit()), Err(ApplyError::Precondition(ref s)) if s.contains("forced")));
}

#[test]
fn revert_holds_until_explicit_apply() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    assert_eq!(a.revert().unwrap(), Outcome::Reverted { levels: vec![1] });
    assert!(a.kernel.loaded().is_empty());
    // Timer run respects the hold, without even reading the repository.
    let moved = env.repo.with_extension("away");
    std::fs::rename(&env.repo, &moved).unwrap();
    assert!(matches!(a.apply(&ApplyOpts::default()).unwrap(), Outcome::Skipped(_)));
    std::fs::rename(&moved, &env.repo).unwrap();
    // Boot respects the hold.
    let b = env.agent(kernel());
    assert_eq!(b.boot().unwrap(), Outcome::NothingToLoad);
    // Operator resumes.
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { level: 1, .. }));
    assert!(!env.state().get(KVER).held);
}

#[test]
fn ring_is_part_of_the_signed_manifest() {
    let env = Env::new();
    let mut m = env.manifest(1);
    m.ring = "canary".into();
    let ko = ko(&m.module_name, KVER, true);
    env.publish(m, &ko);
    // Copy the canary manifest into the stable path.
    let base = env.repo.join("v1").join(KVER);
    std::fs::create_dir_all(base.join("stable")).unwrap();
    for f in ["manifest.json", "manifest.json.minisig"] {
        std::fs::copy(base.join("canary").join(f), base.join("stable").join(f)).unwrap();
    }
    let a = env.agent(kernel());
    let e = a.apply(&explicit()).unwrap_err();
    assert!(e.to_string().contains("ring canary"), "{e}");
}

fn write_script(p: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(p, body).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}
