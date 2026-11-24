//! End-to-end tests of the agent against the emulated kernel, including
//! the negative tests from the design document.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use hvpatch::agent::{Agent, ApplyError, ApplyOpts, Outcome};
use hvpatch::config::Config;
use hvpatch::fake::FakeKernel;
use hvpatch::kernel::KmsgRecord;
use hvpatch::repo::FileRepo;
use hvpatch::report;
use hvpatch::state::{Attempt, Phase, State};
use klp_core::manifest::{Fix, Manifest, NotCovered};
use klp_core::naming::module_name;
use klp_core::revocation::{RevocationList, Revoked};
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
            run_dir: tmp.path().join("run"),
            cluster_lock_dir: tmp.path().join("pve-lock"),
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
            states: vec![],
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

    /// Sign and publish a revocation list like `hvpatch-tool revoke` + `sign`.
    fn publish_revocations(&self, list: &RevocationList) {
        let dir = self.repo.join("v1");
        std::fs::create_dir_all(&dir).unwrap();
        let json = list.to_json_pretty();
        std::fs::write(dir.join("revoked.json"), &json).unwrap();
        let sig = key().sign(json.as_bytes(), &format!("revocations:{}", list.sequence)).unwrap();
        std::fs::write(dir.join("revoked.json.minisig"), sig).unwrap();
    }
}

fn revocations(entries: &[&Manifest], sequence: u64) -> RevocationList {
    RevocationList {
        format: 1,
        sequence,
        issued: now(),
        revoked: entries
            .iter()
            .map(|m| Revoked {
                sha256: m.sha256.clone(),
                kernel: m.kernel.clone(),
                level: m.level,
                reason: "regression in the field".into(),
                revoked: now(),
            })
            .collect(),
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
fn newer_installed_kernel_recommends_reboot() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    assert!(report::collect(&a).unwrap().newer_kernel_installed.is_none());
    a.kernel.st.borrow_mut().installed =
        vec!["7.0.14-1-pve".into(), KVER.into(), "7.3.9-1-pve".into(), "7.3.10-1-pve".into()];
    let r = report::collect(&a).unwrap();
    assert_eq!(r.newer_kernel_installed.as_deref(), Some("7.3.10-1-pve"));
    assert!(r.reboot_reasons.iter().any(|x| x.contains("7.3.10-1-pve is installed")), "{:?}", r.reboot_reasons);
    assert!(r.to_prometheus().contains("hvpatch_newer_kernel_installed 1"));
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
        KmsgRecord::kernel(6, "softdog: soft_reboot_cmd=<not set> soft_active_on_boot=0"),
        KmsgRecord::kernel(3, "Loading of module with unavailable key is rejected"),
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
    a.kernel.st.borrow_mut().kmsg_on_load =
        vec![KmsgRecord::kernel(4, "WARNING: CPU: 5 PID: 1 at net/ipv4/tcp.c:42 tcp_fix_me+0x1/0x2")];
    let e = a.apply(&explicit()).unwrap_err();
    let msg = e.to_string();
    assert!(msg.contains("post-checks failed") && msg.contains("put back by atomic replace"), "{msg}");
    // Never without a livepatch: level 2 was never simply disabled.
    let calls = a.kernel.st.borrow().calls.clone();
    assert!(!calls.iter().any(|c| c == "enabled klp_hvp_7_3_5_1_p2=0"), "{calls:?}");
    assert_eq!(a.kernel.active(), vec!["klp_hvp_7_3_5_1_p1"]);
    assert_eq!(a.kernel.loaded(), vec!["klp_hvp_7_3_5_1_p1"]);
    let st = env.state().get(KVER);
    assert_eq!(st.highest_accepted, 1, "a failed level must not count as accepted");
    assert_eq!(st.desired_level, Some(1));
    assert_eq!(st.quarantined.len(), 1, "level 2 is quarantined");
    // The timer does not try level 2 again; an operator can.
    assert!(matches!(a.apply(&ApplyOpts::default()).unwrap(), Outcome::Skipped(ref s) if s.contains("quarantined")));
    assert_eq!(a.kernel.active(), vec!["klp_hvp_7_3_5_1_p1"]);
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { level: 2, .. }));
    assert!(env.state().get(KVER).quarantined.is_empty());
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
    assert_eq!(b.boot().unwrap(), Outcome::Skipped("held after revert".into()));
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

// --- Robustness (review findings A1-A6, A12) -----------------------------

#[test]
fn unrelated_or_tenant_controlled_log_lines_do_not_back_out() {
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    k.st.borrow_mut().kmsg_on_load = vec![
        // A crashing user process, and a tenant naming its process "BUG:".
        KmsgRecord::kernel(6, "traps: foo[123] general protection fault ip:7f0 sp:7ff error:0 in libc.so"),
        KmsgRecord::kernel(6, "BUG:[4242]: segfault at 0 ip 0 sp 0 error 6 in x"),
        // Written into /dev/kmsg from user space.
        KmsgRecord { facility: 1, level: 0, msg: "Oops: fake".into() },
    ];
    let a = env.agent(k);
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { level: 1, .. }));
}

fn manifest_sha(env: &Env, level: u32) -> String {
    let p = env.repo.join("v1").join(KVER).join("stable/manifest.json");
    let m: serde_json::Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    assert_eq!(m["level"], level);
    m["sha256"].as_str().unwrap().to_owned()
}

fn edit_state(env: &Env, f: impl FnOnce(&mut State)) {
    let mut st = env.state();
    f(&mut st);
    st.save(&env.cfg.state_file()).unwrap();
}

#[test]
fn crash_while_loading_quarantines_the_level() {
    let env = Env::new();
    env.publish_level(1);
    env.agent(kernel()).apply(&explicit()).unwrap();
    env.publish_level(2);
    let sha2 = manifest_sha(&env, 2);
    // The host died while level 2 was loading: the attempt is still recorded.
    edit_state(&env, |st| {
        let k = st.kernel(KVER);
        k.attempt =
            Some(Attempt { level: 2, sha256: sha2.clone(), module: "klp_hvp_7_3_5_1_p2".into(), started: now() });
        k.phase = Phase::Loading;
    });
    // Reboot: the boot unit reloads level 1, not the level that crashed.
    let a = env.agent(kernel());
    assert!(matches!(a.boot().unwrap(), Outcome::Applied { level: 1, .. }));
    assert!(env.state().get(KVER).quarantined.contains_key(&sha2));
    // The timer does not try level 2 again.
    assert!(matches!(a.apply(&ApplyOpts::default()).unwrap(), Outcome::Skipped(ref s) if s.contains("interrupted")));
    assert_eq!(a.kernel.active(), vec!["klp_hvp_7_3_5_1_p1"]);
}

#[test]
fn run_interrupted_after_the_transition_is_reconciled() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    // The agent was killed after the transition, before recording it.
    let sha = manifest_sha(&env, 1);
    edit_state(&env, |st| {
        let k = st.kernel(KVER);
        k.attempt = Some(Attempt { level: 1, sha256: sha, module: "klp_hvp_7_3_5_1_p1".into(), started: now() });
        k.phase = Phase::Loading;
        k.desired_level = None;
        k.highest_accepted = 0;
    });
    assert_eq!(a.apply(&ApplyOpts::default()).unwrap(), Outcome::AlreadyActive { level: 1 });
    let st = env.state().get(KVER);
    assert_eq!((st.phase, st.desired_level, st.highest_accepted), (Phase::Active, Some(1), 1));
    assert!(st.attempt.is_none());
    assert_eq!(report::collect(&a).unwrap().exit_code(), report::exit::REBOOT_REQUIRED);
}

#[test]
fn stalled_level_is_quarantined_for_the_timer() {
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    k.st.borrow_mut().stuck = true;
    let a = env.agent(k);
    assert!(a.apply(&explicit()).is_err());
    assert_eq!(env.state().get(KVER).quarantined.len(), 1);
    assert!(matches!(a.apply(&ApplyOpts::default()).unwrap(), Outcome::Skipped(ref s) if s.contains("quarantined")));
}

#[test]
fn download_failure_is_recorded_as_failed() {
    let env = Env::new();
    let m = env.publish_level(1);
    std::fs::remove_file(env.repo.join("v1").join(KVER).join(&m.module)).unwrap();
    let a = env.agent(kernel());
    assert!(matches!(a.apply(&explicit()), Err(ApplyError::Rejected(ref s)) if s.contains("download")));
    let st = env.state().get(KVER);
    assert_eq!(st.phase, Phase::Failed);
    assert!(st.last_error.unwrap().contains("download"));
    assert_eq!(report::collect(&a).unwrap().exit_code(), report::exit::FAILED);
}

#[test]
fn hooks_time_out_and_are_permission_checked() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    env.publish_level(1);
    std::fs::create_dir_all(&env.cfg.hooks_dir).unwrap();
    let marker = env.cfg.state_dir.join("hook-env");
    std::fs::create_dir_all(&env.cfg.state_dir).unwrap();
    // Runs, and sees the mode.
    write_script(
        &env.cfg.hooks_dir.join("10-env"),
        &format!("#!/bin/sh\necho \"$HVPATCH_MODE $HVPATCH_LEVEL\" > {}\n", marker.display()),
    );
    // Ignored like run-parts does.
    write_script(&env.cfg.hooks_dir.join("20-fail.dpkg-old"), "#!/bin/sh\nexit 1\n");
    write_script(&env.cfg.hooks_dir.join(".hidden"), "#!/bin/sh\nexit 1\n");
    let a = env.agent(kernel());
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { .. }));
    assert_eq!(std::fs::read_to_string(&marker).unwrap().trim(), "apply 1");

    // A hook that hangs is killed after hook_timeout.
    let env = Env::new();
    env.publish_level(1);
    std::fs::create_dir_all(&env.cfg.hooks_dir).unwrap();
    write_script(&env.cfg.hooks_dir.join("10-hang"), "#!/bin/sh\nsleep 30\n");
    let mut a = env.agent(kernel());
    a.cfg.hook_timeout = 1;
    let start = std::time::Instant::now();
    let e = a.apply(&explicit()).unwrap_err();
    assert!(e.to_string().contains("did not finish within 1 s"), "{e}");
    assert!(start.elapsed() < std::time::Duration::from_secs(10));

    // A hook others can write is refused.
    let env = Env::new();
    env.publish_level(1);
    std::fs::create_dir_all(&env.cfg.hooks_dir).unwrap();
    let h = env.cfg.hooks_dir.join("10-open");
    write_script(&h, "#!/bin/sh\nexit 0\n");
    std::fs::set_permissions(&h, std::fs::Permissions::from_mode(0o777)).unwrap();
    let e = env.agent(kernel()).apply(&explicit()).unwrap_err();
    assert!(e.to_string().contains("writable by group or others"), "{e}");
}

#[test]
fn asynchronous_freeing_is_not_mistaken_for_a_forced_patch() {
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    k.st.borrow_mut().put_delay = 3;
    let a = env.agent(k);
    a.apply(&explicit()).unwrap();
    env.publish_level(2);
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { level: 2, .. }));
    env.publish_level(3);
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { level: 3, .. }));
}

#[test]
fn only_one_node_per_cluster_loads_at_a_time() {
    let env = Env::new();
    env.publish_level(1);
    std::fs::create_dir_all(&env.cfg.cluster_lock_dir).unwrap();
    // Another node holds the lock.
    std::fs::create_dir(env.cfg.cluster_lock_dir.join(hvpatch::cluster::LOCK_NAME)).unwrap();
    let a = env.agent(kernel());
    let e = a.apply(&explicit()).unwrap_err();
    assert!(matches!(e, ApplyError::Precondition(ref s) if s.contains("another node")), "{e}");
    assert!(a.kernel.loaded().is_empty());
    // Released: this node takes it, loads, and releases it again.
    std::fs::remove_dir(env.cfg.cluster_lock_dir.join(hvpatch::cluster::LOCK_NAME)).unwrap();
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { .. }));
    assert!(!env.cfg.cluster_lock_dir.join(hvpatch::cluster::LOCK_NAME).exists());
}

#[test]
fn delay_and_pin_only_hold_back_the_timer() {
    let env = Env::new();
    env.publish_level(1);
    let mut a = env.agent(kernel());
    a.cfg.delay_hours = 48;
    assert!(matches!(a.apply(&ApplyOpts::default()).unwrap(), Outcome::Skipped(ref s) if s.contains("eligible")));
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { level: 1, .. }));
    a.cfg.delay_hours = 0;
    a.cfg.pin_level = Some(1);
    env.publish_level(2);
    assert!(matches!(a.apply(&ApplyOpts::default()).unwrap(), Outcome::Skipped(ref s) if s.contains("pinned")));
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { level: 2, .. }));
}

#[test]
fn trace_conflicts_warn_or_refuse() {
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    k.st.borrow_mut().traced = vec!["tcp_fix_me".into()];
    let mut a = env.agent(k);
    a.cfg.refuse_on_trace_conflict = true;
    assert!(matches!(a.apply(&explicit()), Err(ApplyError::Precondition(ref s)) if s.contains("tcp_fix_me")));
    a.cfg.refuse_on_trace_conflict = false;
    match a.apply(&explicit()).unwrap() {
        Outcome::Applied { warnings, .. } => assert!(warnings.iter().any(|w| w.contains("tcp_fix_me")), "{warnings:?}"),
        o => panic!("{o:?}"),
    }
}

#[test]
fn effective_version_for_scanners() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    let ev = std::fs::read_to_string(env.cfg.run_dir.join("effective_version")).unwrap();
    assert_eq!(ev.trim(), "7.3.5-1-pve+hvpatch.1");
    assert_eq!(std::fs::read_to_string(env.cfg.run_dir.join("fixed_cves")).unwrap().trim(), "CVE-2026-0001");
    a.revert().unwrap();
    assert!(!env.cfg.run_dir.join("effective_version").exists());
}

#[test]
fn boot_skips_a_quarantined_level_for_the_one_below() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    env.publish_level(2);
    a.apply(&explicit()).unwrap();
    let sha2 = manifest_sha(&env, 2);
    edit_state(&env, |st| {
        st.kernel(KVER)
            .quarantined
            .insert(sha2, hvpatch::state::Quarantine { level: 2, reason: "test".into(), since: now() });
    });
    let b = env.agent(kernel());
    assert!(matches!(b.boot().unwrap(), Outcome::Applied { level: 1, .. }));
    assert_eq!(b.kernel.active(), vec!["klp_hvp_7_3_5_1_p1"]);
}

#[test]
fn cache_keeps_only_recent_levels() {
    let env = Env::new();
    let a = env.agent(kernel());
    for level in 1..=5 {
        env.publish_level(level);
        a.apply(&explicit()).unwrap();
    }
    let mut levels: Vec<String> = std::fs::read_dir(env.cfg.cache_dir().join(KVER))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    levels.sort();
    assert_eq!(levels, vec!["3", "4", "5"]);
}

#[test]
fn module_without_atomic_replace_is_backed_out() {
    let env = Env::new();
    env.publish_level(1);
    let k = kernel();
    k.st.borrow_mut().no_replace = true;
    let a = env.agent(k);
    let e = a.apply(&explicit()).unwrap_err();
    assert!(e.to_string().contains("without atomic replace"), "{e}");
    assert!(a.kernel.loaded().is_empty());
}

// --- Revocation ------------------------------------------------------------

#[test]
fn revoked_active_level_is_replaced_by_the_one_below() {
    let env = Env::new();
    env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    let m2 = env.publish_level(2);
    a.apply(&explicit()).unwrap();
    assert_eq!(a.kernel.active(), vec!["klp_hvp_7_3_5_1_p2"]);

    env.publish_revocations(&revocations(&[&m2], 1));
    // The ring still offers level 2: it is not loaded again, level 1 is back.
    let out = a.apply(&ApplyOpts::default()).unwrap();
    assert!(matches!(&out, Outcome::Skipped(why) if why.contains("revoked")), "{out:?}");
    assert_eq!(a.kernel.active(), vec!["klp_hvp_7_3_5_1_p1"]);
    assert_eq!(env.state().get(KVER).desired_level, Some(1));
    // Not even an explicit apply loads a revoked level.
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Skipped(_)));
    // Boot after a reboot skips it as well (cached list, no network).
    std::fs::remove_dir_all(&env.repo).unwrap();
    let b = env.agent(kernel());
    assert!(matches!(b.boot().unwrap(), Outcome::Applied { level: 1, .. }));
    // A fixed level 3 is picked up normally.
}

#[test]
fn revoked_only_level_is_unloaded() {
    let env = Env::new();
    let m1 = env.publish_level(1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    env.publish_revocations(&revocations(&[&m1], 1));
    let r = report::collect(&a).unwrap();
    assert!(r.hints.is_empty() || !r.hints.iter().any(|h| h.contains("revoked")), "list not fetched yet");
    a.apply(&ApplyOpts::default()).unwrap();
    assert!(a.kernel.active().is_empty());
    let st = env.state();
    assert_eq!(st.get(KVER).phase, Phase::Reverted);
    assert!(st.get(KVER).last_error.as_deref().unwrap().contains("revoked"));
    assert!(!st.get(KVER).held, "a revocation is not an operator hold: level 2 may come");
    env.publish_level(2);
    assert!(matches!(a.apply(&ApplyOpts::default()).unwrap(), Outcome::Applied { level: 2, .. }));
}

#[test]
fn revocation_list_replay_and_bad_signature() {
    let env = Env::new();
    let m1 = env.publish_level(1);
    let a = env.agent(kernel());
    env.publish_revocations(&revocations(&[&m1], 5));
    a.apply(&explicit()).unwrap();
    assert!(a.kernel.active().is_empty(), "revoked level 1 must not load");
    assert_eq!(env.state().revocation_sequence, 5);
    // An older, empty list (replay) does not un-revoke it, and nothing new
    // is loaded while the current list is withheld.
    env.publish_revocations(&revocations(&[], 4));
    assert!(matches!(a.apply(&explicit()), Err(ApplyError::Rejected(e)) if e.contains("not available")));
    assert!(a.kernel.active().is_empty());
    assert!(a.log_lines().iter().any(|l| l.contains("older than 5")));
    // Same when the list disappears from the repository.
    std::fs::remove_file(env.repo.join("v1/revoked.json")).unwrap();
    env.publish_level(2);
    assert!(matches!(a.apply(&explicit()), Err(ApplyError::Rejected(e)) if e.contains("not available")));
    assert!(a.kernel.active().is_empty());
    // A tampered list is rejected.
    env.publish_revocations(&revocations(&[&m1], 6));
    let f = env.repo.join("v1/revoked.json");
    let tampered = std::fs::read_to_string(&f).unwrap().replace("\"sequence\": 6", "\"sequence\": 9");
    std::fs::write(&f, tampered).unwrap();
    assert!(matches!(a.apply(&explicit()), Err(ApplyError::Rejected(e)) if e.contains("revocation list")));
}

// --- States ----------------------------------------------------------------

#[test]
fn a_level_must_carry_the_states_of_the_active_one() {
    use klp_core::manifest::KlpState;
    let env = Env::new();
    let mut m1 = env.manifest(1);
    m1.states = vec![KlpState { id: 7, version: 2 }];
    let ko1 = ko(&m1.module_name, KVER, true);
    env.publish(m1, &ko1);
    let a = env.agent(kernel());
    a.apply(&explicit()).unwrap();
    // Level 2 dropped state 7: refused before anything is loaded.
    env.publish_level(2);
    let e = a.apply(&explicit()).unwrap_err();
    assert!(matches!(&e, ApplyError::Rejected(s) if s.contains("state 7")), "{e}");
    assert_eq!(a.kernel.active(), vec!["klp_hvp_7_3_5_1_p1"]);
    assert!(env.state().get(KVER).quarantined.is_empty(), "a policy refusal is not a failed load");
    // Level 3 carries it at a higher version.
    let mut m3 = env.manifest(3);
    m3.states = vec![KlpState { id: 7, version: 3 }];
    let ko3 = ko(&m3.module_name, KVER, true);
    env.publish(m3, &ko3);
    assert!(matches!(a.apply(&explicit()).unwrap(), Outcome::Applied { level: 3, .. }));
}
