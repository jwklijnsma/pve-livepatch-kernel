//! The signed manifest that describes exactly one livepatch module for
//! exactly one kernel build and one release ring.
//!
//! Repository layout (static files, any web server or object store):
//!
//! ```text
//! v1/<kernel-release>/<ring>/manifest.json
//! v1/<kernel-release>/<ring>/manifest.json.minisig
//! v1/<kernel-release>/<module>.ko
//! v1/<kernel-release>/build.log, provenance.json, functions.txt
//! ```
//!
//! One manifest per ring instead of time-based rings: promotion from
//! `canary` to `early` to `stable` is an explicit, signed act of a maintainer
//! and not something that happens automatically after N hours, even if the
//! canary nodes are on fire.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const FORMAT_VERSION: u32 = 1;

/// Release rings in promotion order.
pub const RINGS: &[&str] = &["canary", "early", "stable"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Manifest format version. Agents refuse unknown versions.
    pub format: u32,
    /// `uname -r` of the target kernel, e.g. `7.3.5-1-pve`.
    pub kernel: String,
    /// GNU build-id of the shipped vmlinux (hex), as exposed by
    /// `/sys/kernel/notes`. Binds the manifest to one concrete kernel binary,
    /// not just a release string that a rebuilt package could reuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_build_id: Option<String>,
    /// Monotonic patch level for this kernel. Never decreases.
    pub level: u32,
    /// Release ring this manifest is published to.
    pub ring: String,
    /// File name of the module, relative to `v1/<kernel>/`.
    pub module: String,
    /// Kernel module name (`name=` in .modinfo) and thus the directory
    /// name below `/sys/kernel/livepatch/`.
    pub module_name: String,
    /// SHA-256 of the signed module file (hex).
    pub sha256: String,
    pub built: DateTime<Utc>,
    /// After this point the agent refuses to apply the manifest. Protects
    /// against freeze attacks and against a project that silently stopped.
    pub expires: DateTime<Utc>,
    #[serde(default)]
    pub fixes: Vec<Fix>,
    #[serde(default)]
    pub not_covered: Vec<NotCovered>,
    /// Newer kernel package that contains all fixes natively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by_kernel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_commit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fix {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Patched functions as `object:function[,sympos]`.
    #[serde(default)]
    pub functions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotCovered {
    pub id: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_in: Option<String>,
    /// Documented mitigation, shown to the operator, never applied
    /// automatically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitigation: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("unsupported manifest format {0}, agent supports {FORMAT_VERSION}")]
    Format(u32),
    #[error("unknown ring {0:?}")]
    Ring(String),
    #[error("module file name {0:?} is not a plain .ko file name")]
    ModulePath(String),
    #[error("module name {0:?} is not a valid kernel module name")]
    ModuleName(String),
    #[error("sha256 must be 64 lowercase hex characters")]
    Sha256,
    #[error("kernel build-id must be lowercase hex")]
    BuildId,
    #[error("expires ({expires}) is not after built ({built})")]
    Validity { built: DateTime<Utc>, expires: DateTime<Utc> },
    #[error("level 0 is reserved for \"no livepatch\"")]
    LevelZero,
}

impl Manifest {
    pub fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        let m: Manifest = serde_json::from_slice(bytes)?;
        m.validate()?;
        Ok(m)
    }

    /// Structural checks that do not depend on the node. Everything that
    /// ends up in a path or a syscall argument is checked here.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.format != FORMAT_VERSION {
            return Err(ManifestError::Format(self.format));
        }
        if !RINGS.contains(&self.ring.as_str()) {
            return Err(ManifestError::Ring(self.ring.clone()));
        }
        if !is_plain_ko_name(&self.module) {
            return Err(ManifestError::ModulePath(self.module.clone()));
        }
        if !crate::naming::is_valid_module_name(&self.module_name) {
            return Err(ManifestError::ModuleName(self.module_name.clone()));
        }
        if !is_lower_hex(&self.sha256) || self.sha256.len() != 64 {
            return Err(ManifestError::Sha256);
        }
        if let Some(id) = &self.kernel_build_id {
            if !is_lower_hex(id) || id.is_empty() || id.len() % 2 != 0 {
                return Err(ManifestError::BuildId);
            }
        }
        if self.expires <= self.built {
            return Err(ManifestError::Validity { built: self.built, expires: self.expires });
        }
        if self.level == 0 {
            return Err(ManifestError::LevelZero);
        }
        Ok(())
    }

    /// The node needs a reboot into a newer kernel even with this patch.
    pub fn reboot_required(&self) -> bool {
        !self.not_covered.is_empty()
    }

    pub fn to_json_pretty(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).expect("manifest serializes");
        s.push('\n');
        s
    }
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_plain_ko_name(s: &str) -> bool {
    s.ends_with(".ko")
        && s.len() > 3
        && s.len() <= 128
        && !s.starts_with('.')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        && !s.contains("..")
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn sample() -> Manifest {
        Manifest {
            format: 1,
            kernel: "7.3.5-1-pve".into(),
            kernel_build_id: Some("ab12".into()),
            level: 3,
            ring: "canary".into(),
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

    #[test]
    fn roundtrip() {
        let m = sample();
        let back = Manifest::from_json(m.to_json_pretty().as_bytes()).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn rejects_path_traversal_in_module() {
        let mut m = sample();
        m.module = "../../etc/x.ko".into();
        assert_eq!(m.validate(), Err(ManifestError::ModulePath(m.module.clone())));
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut v = serde_json::to_value(sample()).unwrap();
        v["force"] = serde_json::Value::Bool(true);
        assert!(Manifest::from_json(v.to_string().as_bytes()).is_err());
    }

    #[test]
    fn rejects_unknown_ring_and_format() {
        let mut m = sample();
        m.ring = "yolo".into();
        assert!(m.validate().is_err());
        let mut m = sample();
        m.format = 2;
        assert_eq!(m.validate(), Err(ManifestError::Format(2)));
    }
}
