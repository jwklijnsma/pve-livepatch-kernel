//! `pve-klp setup`: configure repository, ring and trusted key in one step.

use std::path::Path;

use anyhow::{Context, Result, bail};
use klp_core::sig::TrustStore;

use crate::config::Config;

/// The documented example configuration, used when no config exists yet.
pub const CONFIG_TEMPLATE: &str = include_str!("../../../etc/pve-klp.toml");

/// Set `key = value` in a TOML config text, keeping comments and layout.
/// Replaces the first active or commented-out `key = …` line, or appends.
pub fn set_key(text: &str, key: &str, value: &str) -> String {
    let line = format!("{key} = {}", toml_string(value));
    let mut out = Vec::new();
    let mut done = false;
    for l in text.lines() {
        let t = l.trim_start().trim_start_matches('#').trim_start();
        let is_key = t.strip_prefix(key).is_some_and(|rest| rest.trim_start().starts_with('='));
        if !done && is_key {
            out.push(line.clone());
            done = true;
        } else {
            out.push(l.to_owned());
        }
    }
    if !done {
        out.push(line);
    }
    let mut s = out.join("\n");
    s.push('\n');
    s
}

fn toml_string(v: &str) -> String {
    let mut s = String::from('"');
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            c if c.is_control() => s.push_str(&format!("\\u{:04X}", c as u32)),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

/// Write the config with repository and ring set. Returns the new text.
pub fn write_config(path: &Path, repository: &str, ring: &str) -> Result<String> {
    let current = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => CONFIG_TEMPLATE.to_owned(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let text = set_key(&set_key(&current, "repository", repository), "ring", ring);
    let cfg: Config = toml::from_str(&text).context("resulting configuration is invalid")?;
    cfg.validate()?;
    crate::state::write_atomic(path, text.as_bytes())?;
    Ok(text)
}

/// Validate a minisign public key and install it as `<dir>/<name>.pub`.
/// Returns the key id, which the operator should compare with the
/// fingerprint published by the repository owner.
pub fn install_key(dir: &Path, name: &str, text: &str) -> Result<String> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        bail!("key name {name:?} may only contain letters, digits, - and _");
    }
    let mut store = TrustStore::default();
    store.add(name, text).context("not a valid minisign public key")?;
    let id = store.keys().next().expect("just added").key_id.clone();
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    crate::state::write_atomic(&dir.join(format!("{name}.pub")), text.as_bytes())?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_key_replaces_commented_example_and_keeps_comments() {
        let out = set_key(CONFIG_TEMPLATE, "repository", "https://klp.example.org");
        assert!(out.contains("\nrepository = \"https://klp.example.org\"\n"));
        assert!(out.contains("# Release ring of this node"));
        let out = set_key(&out, "ring", "canary");
        let cfg: Config = toml::from_str(&out).unwrap();
        assert_eq!(cfg.ring, "canary");
        assert_eq!(cfg.repository, "https://klp.example.org");
        // Idempotent.
        assert_eq!(set_key(&out, "ring", "canary"), out);
    }

    #[test]
    fn set_key_does_not_touch_similar_keys() {
        let out = set_key("ringtone = \"x\"\n", "ring", "early");
        assert_eq!(out, "ringtone = \"x\"\nring = \"early\"\n");
    }

    #[test]
    fn write_config_validates() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("pve-klp.toml");
        write_config(&p, "https://klp.example.org", "stable").unwrap();
        assert!(write_config(&p, "https://klp.example.org", "yolo").is_err());
        let cfg = Config::load(&p).unwrap();
        assert_eq!(cfg.ring, "stable");
    }

    #[test]
    fn install_key_rejects_garbage() {
        let t = tempfile::tempdir().unwrap();
        assert!(install_key(t.path(), "project", "not a key").is_err());
        assert!(install_key(t.path(), "../evil", "x").is_err());
        let k = klp_core::sig::SecretKey::from_seed([3; 8], [3; 32]);
        let id = install_key(t.path(), "project", &k.public_key_file()).unwrap();
        assert_eq!(id, k.key_id());
        assert!(t.path().join("project.pub").exists());
    }
}
