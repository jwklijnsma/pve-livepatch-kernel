//! Gate A against a synthetic livepatch module and shipped artifacts.

use std::process::Command;

use object::write::{Object as WObject, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope};

fn module(vermagic: &str, versions: &[(&str, u32)], klp: &[&str]) -> Vec<u8> {
    let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let s = obj.add_section(vec![], b".modinfo".to_vec(), SectionKind::ReadOnlyData);
    let mut mi = Vec::new();
    for kv in ["name=klp_pve_7_3_5_1_p1".to_owned(), format!("vermagic={vermagic}"), "livepatch=Y".into()] {
        mi.extend_from_slice(kv.as_bytes());
        mi.push(0);
    }
    obj.append_section_data(s, &mi, 1);
    let v = obj.add_section(vec![], b"__versions".to_vec(), SectionKind::ReadOnlyData);
    let mut vd = Vec::new();
    for (n, c) in versions {
        let mut e = [0u8; 64];
        e[..8].copy_from_slice(&(*c as u64).to_le_bytes());
        e[8..8 + n.len()].copy_from_slice(n.as_bytes());
        vd.extend_from_slice(&e);
    }
    obj.append_section_data(v, &vd, 8);
    for k in klp {
        obj.add_symbol(Symbol {
            name: k.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });
    }
    obj.write().unwrap()
}

fn gate(dir: &std::path::Path, ko: &[u8], functions: &str) -> (bool, String) {
    std::fs::write(dir.join("m.ko"), ko).unwrap();
    std::fs::write(dir.join("functions.txt"), functions).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_pve-klp-tool"))
        .args(["gate-a", "--kernel", "7.3.5-1-pve", "--expected-name", "klp_pve_7_3_5_1_p1"])
        .arg("--module")
        .arg(dir.join("m.ko"))
        .arg("--system-map")
        .arg(dir.join("System.map"))
        .arg("--symvers")
        .arg(dir.join("Module.symvers"))
        .arg("--functions")
        .arg(dir.join("functions.txt"))
        .output()
        .unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn gate_a() {
    let t = tempfile::tempdir().unwrap();
    std::fs::write(
        t.path().join("System.map"),
        "ffffffff81000000 T _stext\nffffffff81001000 t tcp_fix_me\nffffffff81002000 t helper\nffffffff81003000 t helper\n",
    )
    .unwrap();
    std::fs::write(t.path().join("Module.symvers"), "0x12345678\tklp_enable_patch\tvmlinux\tEXPORT_SYMBOL_GPL\t\n")
        .unwrap();
    let vm = "7.3.5-1-pve SMP preempt mod_unload modversions ";

    let good = module(vm, &[("klp_enable_patch", 0x12345678)], &[".klp.sym.vmlinux.helper,2"]);
    let (ok, out) = gate(t.path(), &good, "vmlinux:tcp_fix_me\n");
    assert!(ok, "{out}");

    let bad_crc = module(vm, &[("klp_enable_patch", 0x1)], &[]);
    let (ok, out) = gate(t.path(), &bad_crc, "");
    assert!(!ok && out.contains("crc"), "{out}");

    let ambiguous = module(vm, &[("klp_enable_patch", 0x12345678)], &[".klp.sym.vmlinux.helper,0"]);
    let (ok, out) = gate(t.path(), &ambiguous, "");
    assert!(!ok && out.contains("ambiguous"), "{out}");

    let missing_fn = module(vm, &[("klp_enable_patch", 0x12345678)], &[]);
    let (ok, out) = gate(t.path(), &missing_fn, "vmlinux:tcp_fix_me.isra.0\n");
    assert!(!ok && out.contains("does not exist"), "{out}");

    let wrong_kernel = module("7.3.4-1-pve SMP", &[("klp_enable_patch", 0x12345678)], &[]);
    let (ok, out) = gate(t.path(), &wrong_kernel, "");
    assert!(!ok && out.contains("vermagic"), "{out}");
}

#[test]
fn keygen_sign_verify_roundtrip() {
    let t = tempfile::tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_pve-klp-tool");
    let sk = t.path().join("k.key");
    let pk = t.path().join("k.pub");
    assert!(
        Command::new(bin).args(["keygen", "--secret"]).arg(&sk).arg("--public").arg(&pk).status().unwrap().success()
    );
    // Refuses to overwrite.
    assert!(
        !Command::new(bin).args(["keygen", "--secret"]).arg(&sk).arg("--public").arg(&pk).status().unwrap().success()
    );
    let f = t.path().join("manifest.json");
    std::fs::write(&f, b"{}").unwrap();
    assert!(Command::new(bin).args(["sign", "--key"]).arg(&sk).arg(&f).status().unwrap().success());
    assert!(Command::new(bin).args(["verify", "--pubkey"]).arg(&pk).arg(&f).status().unwrap().success());
    std::fs::write(&f, b"{ }").unwrap();
    assert!(!Command::new(bin).args(["verify", "--pubkey"]).arg(&pk).arg(&f).status().unwrap().success());
}

#[test]
fn gate_a_requires_module_to_patch_exactly_the_reviewed_functions() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    std::fs::write(d.join("System.map"), "ffffffff81001000 t cmdline_proc_show\nffffffff81002000 T tcp_v4_rcv\n")
        .unwrap();
    std::fs::write(d.join("Module.symvers"), "0x12345678\tklp_enable_patch\tvmlinux\tEXPORT_SYMBOL_GPL\t\n").unwrap();
    std::fs::write(d.join("m.ko"), module("7.3.5-1-pve SMP", &[("klp_enable_patch", 0x12345678)], &[])).unwrap();
    // What objtool klp diff reported for the module.
    std::fs::write(d.join("functions.txt"), "vmlinux:cmdline_proc_show\n").unwrap();

    let run = |reviewed: &str| {
        std::fs::write(
            d.join("resolved.json"),
            format!(
                r#"{{"kernel":"7.3.5-1-pve","patches":[],"fixes":[{{"id":"CVE-2026-0001","functions":[{reviewed}]}}],"not_covered":[],"skipped":[]}}"#
            ),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_pve-klp-tool"))
            .args(["gate-a", "--kernel", "7.3.5-1-pve"])
            .arg("--module")
            .arg(d.join("m.ko"))
            .arg("--system-map")
            .arg(d.join("System.map"))
            .arg("--symvers")
            .arg(d.join("Module.symvers"))
            .arg("--functions")
            .arg(d.join("functions.txt"))
            .arg("--resolved")
            .arg(d.join("resolved.json"))
            .output()
            .unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
    };

    let (ok, out) = run(r#""vmlinux:cmdline_proc_show""#);
    assert!(ok && out.contains("equal to the reviewed catalog"), "{out}");

    // The reviewed list names a function that exists in the kernel but is
    // not what the module patches: this used to pass.
    let (ok, out) = run(r#""vmlinux:tcp_v4_rcv""#);
    assert!(!ok, "{out}");
    assert!(out.contains("cmdline_proc_show is patched by the module but not listed"), "{out}");
    assert!(out.contains("tcp_v4_rcv is listed in the reviewed catalog entries but not patched"), "{out}");
}
