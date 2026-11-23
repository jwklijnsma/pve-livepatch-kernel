//! The reviewed CVE catalog and its resolution for one kernel.
//!
//! ```text
//! catalog/CVE-2026-XXXXX/meta.yaml
//! catalog/CVE-2026-XXXXX/0001-fix.patch
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use klp_core::manifest::{Fix, NotCovered};
use klp_core::naming::{cmp_version, package_version};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    /// Pure function change, klp-build builds it, tests are green.
    Livepatchable,
    /// Needs shadow variables or callbacks; not in v1.
    NeedsManual,
    /// Hits a hard limit (data structures, __init, lib/, asm, out-of-tree).
    NotLivepatchable,
    /// No patch, but a documented mitigation (e.g. blacklisting a module).
    MitigationOnly,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub psa: Option<String>,
    pub upstream_commits: Vec<String>,
    /// First Proxmox kernel package version that contains the fix, e.g. "7.3.6-1".
    #[serde(default)]
    pub fixed_in_pve: Option<String>,
    pub severity: String,
    pub class: Class,
    #[serde(default)]
    pub reason: String,
    /// "default" plus optional per-package-version backports.
    #[serde(default)]
    pub patches: BTreeMap<String, String>,
    /// Reviewed list of functions this fix patches (`object:function`).
    #[serde(default)]
    pub functions: Vec<String>,
    #[serde(default)]
    pub mitigation: Option<String>,
    #[serde(default)]
    pub tests: BTreeMap<String, String>,
    #[serde(default)]
    pub reviewed_by: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Loaded {
    pub entry: Entry,
    pub dir: PathBuf,
}

pub fn load(catalog: &Path) -> Result<Vec<Loaded>> {
    let mut out = Vec::new();
    let mut dirs: Vec<_> = std::fs::read_dir(catalog)
        .with_context(|| format!("reading {}", catalog.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("meta.yaml").is_file())
        .collect();
    dirs.sort();
    for dir in dirs {
        let text = std::fs::read_to_string(dir.join("meta.yaml"))?;
        let entry: Entry =
            serde_norway::from_str(&text).with_context(|| format!("parsing {}/meta.yaml", dir.display()))?;
        let dir_name = dir.file_name().unwrap_or_default().to_string_lossy();
        if entry.id != dir_name {
            bail!("{}: id {:?} does not match directory name", dir.display(), entry.id);
        }
        out.push(Loaded { entry, dir });
    }
    Ok(out)
}

/// Static lint for one entry (CI stage 0, before merge).
pub fn lint(l: &Loaded) -> Vec<String> {
    let e = &l.entry;
    let mut p = Vec::new();
    if e.upstream_commits.is_empty() {
        p.push("upstream_commits is empty".into());
    }
    for c in &e.upstream_commits {
        if !is_commit_id(c) {
            p.push(format!("upstream commit {c:?} is not a hex sha (12-40 chars)"));
        }
    }
    if !["low", "medium", "high", "critical"].contains(&e.severity.as_str()) {
        p.push(format!("severity {:?} must be low, medium, high or critical", e.severity));
    }
    if let Some(psa) = &e.psa
        && !psa.starts_with("PSA-")
    {
        p.push(format!("psa {psa:?} must look like PSA-2026-00068-1"));
    }
    for (k, v) in &e.tests {
        if !["required", "optional", "none"].contains(&v.as_str()) && !v.starts_with("tests/") {
            p.push(format!("tests.{k}: {v:?} must be required, optional, none or a path below tests/"));
        }
    }
    match e.class {
        Class::Livepatchable => {
            if !e.patches.contains_key("default") {
                p.push("class livepatchable needs patches.default".into());
            }
            if e.reviewed_by.len() < 2 {
                p.push(format!("class livepatchable needs two reviewers, has {}", e.reviewed_by.len()));
            }
        }
        Class::NeedsManual | Class::NotLivepatchable => {
            if e.reason.trim().is_empty() {
                p.push("a reason is required for classes needs-manual and not-livepatchable".into());
            }
        }
        Class::MitigationOnly => {
            if e.mitigation.as_deref().unwrap_or("").trim().is_empty() {
                p.push("class mitigation-only needs a mitigation".into());
            }
        }
    }
    for (k, f) in &e.patches {
        if f.contains('/') || f.contains("..") {
            p.push(format!("patch {k}: file name {f:?} must be a plain file in the entry directory"));
        } else if !l.dir.join(f).is_file() {
            p.push(format!("patch {k}: {f} does not exist"));
        }
    }
    for f in &e.functions {
        if !f.contains(':') {
            p.push(format!("function {f:?} must be object:function"));
        }
    }
    p
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Resolved {
    pub kernel: String,
    /// Patch files for klp-build, in catalog order.
    pub patches: Vec<PathBuf>,
    pub fixes: Vec<Fix>,
    pub not_covered: Vec<NotCovered>,
    /// Entries left out on purpose, with the reason (for the build log).
    pub skipped: Vec<(String, String)>,
}

#[derive(Debug, PartialEq, Eq)]
enum Applies {
    Yes,
    AlreadyContained,
    No,
}

fn git_apply_check(tree: &Path, patch: &Path, reverse: bool) -> Result<bool> {
    let mut c = Command::new("git");
    c.arg("-C").arg(tree).args(["apply", "--check"]);
    if reverse {
        c.arg("-R");
    }
    let st = c.arg(patch).output().context("running git apply")?;
    Ok(st.status.success())
}

fn applies(tree: &Path, patch: &Path) -> Result<Applies> {
    if git_apply_check(tree, patch, false)? {
        Ok(Applies::Yes)
    } else if git_apply_check(tree, patch, true)? {
        Ok(Applies::AlreadyContained)
    } else {
        Ok(Applies::No)
    }
}

/// Which catalog entries does `kernel_release` still need, and how?
///
/// With `tree`, every candidate patch is test-applied: a patch that applies
/// in reverse is already contained; a patch that applies neither way is a
/// hard error (it needs a backport), never a silent drop.
pub fn resolve(
    entries: &[Loaded],
    kernel_release: &str,
    tree: Option<&Path>,
    allow_conflicts: bool,
) -> Result<Resolved> {
    let pkg = package_version(kernel_release);
    let mut r = Resolved { kernel: kernel_release.to_owned(), ..Default::default() };
    for l in entries {
        let e = &l.entry;
        if let Some(fixed) = &e.fixed_in_pve
            && cmp_version(pkg, fixed).is_ge()
        {
            r.skipped.push((e.id.clone(), format!("kernel {pkg} already contains the fix (fixed in {fixed})")));
            continue;
        }
        let fixed_in = e.fixed_in_pve.as_ref().map(|v| format!("{v}-pve"));
        let not_covered = |reason: String| NotCovered {
            id: e.id.clone(),
            reason,
            fixed_in: fixed_in.clone(),
            mitigation: e.mitigation.clone(),
        };
        match e.class {
            Class::Livepatchable => {}
            Class::NeedsManual => {
                r.not_covered.push(not_covered(format!("needs manual livepatch work: {}", e.reason)));
                continue;
            }
            Class::NotLivepatchable => {
                r.not_covered.push(not_covered(e.reason.clone()));
                continue;
            }
            Class::MitigationOnly => {
                r.not_covered.push(not_covered("no livepatch; mitigation available".into()));
                continue;
            }
        }
        let file = e.patches.get(pkg).or_else(|| e.patches.get("default")).context(format!("{}: no patch", e.id))?;
        let patch = l.dir.join(file);
        if let Some(tree) = tree {
            match applies(tree, &patch)? {
                Applies::Yes => {}
                Applies::AlreadyContained => {
                    r.skipped.push((e.id.clone(), "patch applies in reverse: already contained in this kernel".into()));
                    continue;
                }
                Applies::No if allow_conflicts => {
                    r.not_covered
                        .push(not_covered(format!("{file} does not apply to {kernel_release}; backport needed")));
                    continue;
                }
                Applies::No => {
                    bail!("{}: {file} does not apply to {kernel_release} in either direction; add a backport", e.id)
                }
            }
        }
        r.patches.push(patch);
        r.fixes.push(Fix { id: e.id.clone(), title: Some(e.title.clone()), functions: e.functions.clone() });
    }
    Ok(r)
}

fn is_commit_id(c: &str) -> bool {
    (12..=40).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `git patch-id --stable` of some diff text.
fn patch_id_of(diff: &[u8]) -> Result<Option<String>> {
    use std::io::Write;
    let mut child = Command::new("git")
        .args(["patch-id", "--stable"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("running git patch-id")?;
    child.stdin.take().unwrap().write_all(diff)?;
    let out = child.wait_with_output()?;
    Ok(String::from_utf8_lossy(&out.stdout).split_whitespace().next().map(str::to_owned))
}

/// Compare the catalog's default patch with the upstream commit(s) by
/// `git patch-id`. Returns a problem description on mismatch.
pub fn check_patch_id(l: &Loaded, upstream: &Path) -> Result<Option<String>> {
    let Some(file) = l.entry.patches.get("default") else { return Ok(None) };
    let ours = patch_id_of(&std::fs::read(l.dir.join(file))?)?;
    let mut theirs = Vec::new();
    for c in &l.entry.upstream_commits {
        // Catalog content is untrusted input until reviewed: never let a
        // "commit" reach git as an option.
        if !is_commit_id(c) {
            return Ok(Some(format!("upstream commit {c:?} is not a hex sha (12-40 chars)")));
        }
        let out =
            Command::new("git").arg("-C").arg(upstream).args(["show", "--format=", "--end-of-options", c]).output()?;
        if !out.status.success() {
            return Ok(Some(format!("upstream commit {c} not found in {}", upstream.display())));
        }
        theirs.extend_from_slice(&out.stdout);
    }
    let theirs = patch_id_of(&theirs)?;
    if ours.is_none() || ours != theirs {
        return Ok(Some(format!(
            "{file}: patch-id {} differs from upstream {} (a justified deviation must be documented in `reason`)",
            ours.as_deref().unwrap_or("-"),
            theirs.as_deref().unwrap_or("-")
        )));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, id: &str, yaml: &str) {
        let d = dir.join(id);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("meta.yaml"), yaml).unwrap();
        std::fs::write(d.join("0001-fix.patch"), "--- a/x\n+++ b/x\n").unwrap();
    }

    fn catalog() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        write(
            t.path(),
            "CVE-2026-0001",
            r#"
id: CVE-2026-0001
title: Use-after-free in tcp_fix_me
upstream_commits: ["0123456789abcdef"]
fixed_in_pve: "7.3.6-1"
severity: high
class: livepatchable
patches:
  default: 0001-fix.patch
functions: ["vmlinux:tcp_fix_me"]
reviewed_by: ["alice", "bob"]
"#,
        );
        write(
            t.path(),
            "CVE-2026-0002",
            r#"
id: CVE-2026-0002
title: KVM struct change
upstream_commits: ["fedcba9876543210"]
fixed_in_pve: "7.3.6-1"
severity: critical
class: not-livepatchable
reason: changes struct kvm_vcpu_arch
"#,
        );
        write(
            t.path(),
            "CVE-2026-0003",
            r#"
id: CVE-2026-0003
title: Old bug
upstream_commits: ["aaaaaaaaaaaaaaaa"]
fixed_in_pve: "7.3.5-1"
severity: high
class: livepatchable
patches:
  default: 0001-fix.patch
reviewed_by: ["alice", "bob"]
"#,
        );
        t
    }

    #[test]
    fn resolve_without_tree() {
        let t = catalog();
        let entries = load(t.path()).unwrap();
        assert!(entries.iter().all(|l| lint(l).is_empty()), "{:?}", entries.iter().map(lint).collect::<Vec<_>>());
        let r = resolve(&entries, "7.3.5-1-pve", None, false).unwrap();
        assert_eq!(r.fixes.len(), 1);
        assert_eq!(r.fixes[0].id, "CVE-2026-0001");
        assert_eq!(r.not_covered.len(), 1);
        assert_eq!(r.not_covered[0].fixed_in.as_deref(), Some("7.3.6-1-pve"));
        assert_eq!(r.skipped.len(), 1, "CVE-2026-0003 is already in 7.3.5-1");
        // A newer kernel needs none of it.
        let r = resolve(&entries, "7.3.6-1-pve", None, false).unwrap();
        assert!(r.fixes.is_empty() && r.not_covered.is_empty());
    }

    #[test]
    fn lint_catches_missing_reviews_and_reason() {
        let t = tempfile::tempdir().unwrap();
        write(
            t.path(),
            "CVE-2026-0009",
            r#"
id: CVE-2026-0009
title: x
upstream_commits: ["xyz"]
severity: low
class: not-livepatchable
"#,
        );
        let e = load(t.path()).unwrap();
        let p = lint(&e[0]);
        assert!(p.iter().any(|m| m.contains("hex sha")));
        // An option-looking "commit" never reaches git.
        let mut evil = e[0].clone();
        evil.entry.upstream_commits = vec!["--output=/tmp/pwned".into()];
        evil.entry.patches.insert("default".into(), "0001-fix.patch".into());
        let msg = check_patch_id(&evil, t.path()).unwrap().unwrap();
        assert!(msg.contains("not a hex sha"), "{msg}");
        assert!(p.iter().any(|m| m.contains("reason")));
    }

    #[test]
    fn id_must_match_directory() {
        let t = tempfile::tempdir().unwrap();
        write(
            t.path(),
            "CVE-2026-0010",
            "id: CVE-2026-9999\ntitle: x\nupstream_commits: []\nseverity: low\nclass: needs-manual\n",
        );
        assert!(load(t.path()).is_err());
    }
}
