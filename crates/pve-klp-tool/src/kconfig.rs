//! Compare the kernel config of the build tree with the shipped one.
//!
//! The shipped `/boot/config-<kver>` also records the toolchain
//! (`CONFIG_CC_VERSION_TEXT`, `CONFIG_GCC_VERSION`, `CONFIG_AS_VERSION`,
//! `CONFIG_LD_VERSION`, `CONFIG_PAHOLE_VERSION`, `CONFIG_RUSTC_VERSION`,
//! ...). If the builder's toolchain differs, `make olddefconfig` changes
//! these values, so a byte-exact config comparison also pins the toolchain.

use std::collections::BTreeMap;

use serde::Serialize;

pub type KConfig = BTreeMap<String, String>;

pub fn parse(text: &str) -> KConfig {
    let mut m = KConfig::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("# ").and_then(|l| l.strip_suffix(" is not set")) {
            if rest.starts_with("CONFIG_") {
                m.insert(rest.to_owned(), "n".into());
            }
        } else if let Some((k, v)) = line.split_once('=')
            && k.starts_with("CONFIG_")
        {
            m.insert(k.to_owned(), v.to_owned());
        }
    }
    m
}

/// Options that describe the toolchain rather than the kernel.
pub fn is_toolchain_key(k: &str) -> bool {
    k == "CONFIG_CC_VERSION_TEXT"
        || k.ends_with("_VERSION")
        || k.starts_with("CONFIG_CC_IS_")
        || k.starts_with("CONFIG_RUSTC_")
        || k.starts_with("CONFIG_BINDGEN_")
        || k.starts_with("CONFIG_TOOLS_SUPPORT_")
        || k.starts_with("CONFIG_AS_HAS_")
        || k.starts_with("CONFIG_CC_HAS_")
        || k.starts_with("CONFIG_LD_")
}

#[derive(Debug, Serialize)]
pub struct Diff {
    pub key: String,
    pub built: Option<String>,
    pub shipped: Option<String>,
    pub toolchain: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub ok: bool,
    pub diffs: Vec<Diff>,
    /// Requirements of klp-build on the config itself.
    pub problems: Vec<String>,
}

pub fn compare(built: &KConfig, shipped: &KConfig) -> Report {
    let mut diffs = Vec::new();
    let keys: std::collections::BTreeSet<&String> = built.keys().chain(shipped.keys()).collect();
    for k in keys {
        // "not set" and absent are equivalent.
        let b = built.get(k).filter(|v| *v != "n");
        let s = shipped.get(k).filter(|v| *v != "n");
        if b != s {
            diffs.push(Diff { key: k.clone(), built: b.cloned(), shipped: s.cloned(), toolchain: is_toolchain_key(k) });
        }
    }
    let mut problems = Vec::new();
    let y = |k: &str| shipped.get(k).map(String::as_str) == Some("y");
    for k in ["CONFIG_LIVEPATCH", "CONFIG_KLP_BUILD", "CONFIG_HAVE_RELIABLE_STACKTRACE"] {
        if !y(k) {
            problems.push(format!("{k} is not enabled in the shipped kernel"));
        }
    }
    for k in [
        "CONFIG_GCC_PLUGIN_LATENT_ENTROPY",
        "CONFIG_RANDSTRUCT",
        "CONFIG_GCC_PLUGIN_RANDSTRUCT",
        "CONFIG_LD_DEAD_CODE_DATA_ELIMINATION",
    ] {
        if y(k) {
            problems.push(format!("{k}=y: klp-build refuses this configuration"));
        }
    }
    Report { ok: diffs.is_empty() && problems.is_empty(), diffs, problems }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHIPPED: &str = "CONFIG_CC_VERSION_TEXT=\"gcc (Debian 14.2.0-19) 14.2.0\"\nCONFIG_LIVEPATCH=y\nCONFIG_KLP_BUILD=y\nCONFIG_HAVE_RELIABLE_STACKTRACE=y\n# CONFIG_RANDSTRUCT is not set\nCONFIG_RUSTC_VERSION=109401\nCONFIG_PAHOLE_VERSION=130\n";

    #[test]
    fn identical_is_ok() {
        let r = compare(&parse(SHIPPED), &parse(SHIPPED));
        assert!(r.ok, "{r:?}");
    }

    #[test]
    fn toolchain_drift_is_flagged() {
        let built = SHIPPED.replace("109401", "108500").replace("14.2.0-19", "14.2.0-20");
        let r = compare(&parse(&built), &parse(SHIPPED));
        assert!(!r.ok);
        assert_eq!(r.diffs.len(), 2);
        assert!(r.diffs.iter().all(|d| d.toolchain));
    }

    #[test]
    fn not_set_equals_absent_and_klp_requirements() {
        let built = SHIPPED.replace("# CONFIG_RANDSTRUCT is not set\n", "");
        assert!(compare(&parse(&built), &parse(SHIPPED)).ok);
        let bad = SHIPPED.replace("CONFIG_KLP_BUILD=y", "# CONFIG_KLP_BUILD is not set");
        let r = compare(&parse(&bad), &parse(&bad));
        assert!(!r.ok);
        assert!(r.problems[0].contains("CONFIG_KLP_BUILD"));
    }
}
