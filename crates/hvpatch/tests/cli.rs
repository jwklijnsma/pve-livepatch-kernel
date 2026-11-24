//! The CLI's exit codes, against a prepared /proc and /sys tree.

use std::path::Path;
use std::process::Command;

fn tree(root: &Path) {
    let w = |rel: &str, s: &str| {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    };
    w("proc/sys/kernel/osrelease", "7.3.5-1-pve\n");
    w("proc/sys/kernel/tainted", "0\n");
    std::fs::create_dir_all(root.join("sys/kernel/livepatch")).unwrap();
    std::fs::create_dir_all(root.join("sys/module")).unwrap();
}

fn status(root: &Path, cfg: &Path, json: bool) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_hvpatch"));
    c.env("HVPATCH_SYSROOT", root).arg("--config").arg(cfg).arg("status");
    if json {
        c.arg("--json");
    }
    let out = c.output().unwrap();
    (out.status.code().unwrap(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn status_exit_code_is_the_same_for_text_and_json() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("root");
    tree(&root);
    let state = t.path().join("state");
    let cfg = t.path().join("hvpatch.toml");
    std::fs::write(
        &cfg,
        format!(
            "state_dir = \"{}\"\ntrusted_keys_dir = \"{}\"\ntextfile_dir = \"\"\n",
            state.display(),
            t.path().join("trusted").display()
        ),
    )
    .unwrap();

    // Nothing active: 11 in both modes.
    let (code, text) = status(&root, &cfg, false);
    assert_eq!(code, 11, "{text}");
    assert!(text.contains("none active"));
    let (code, json) = status(&root, &cfg, true);
    assert_eq!(code, 11, "{json}");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["kernel"], "7.3.5-1-pve");

    // Boot reload still running: 20 in both modes.
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("state.json"), r#"{"kernels":{"7.3.5-1-pve":{"phase":"loading"}}}"#).unwrap();
    assert_eq!(status(&root, &cfg, false).0, 20);
    assert_eq!(status(&root, &cfg, true).0, 20);
}
