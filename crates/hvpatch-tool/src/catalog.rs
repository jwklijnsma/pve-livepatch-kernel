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
    /// First Proxmox kernel package version that contains the fix, per
    /// kernel series: "7.3.6-1", or a list like ["7.3.6-1", "7.0.15-3"].
    /// Versions are only compared within their series.
    #[serde(default, deserialize_with = "one_or_many")]
    pub fixed_in_pve: Vec<String>,
    pub severity: String,
    pub class: Class,
    #[serde(default)]
    pub reason: String,
    /// "default" plus optional backports per series ("7.0") or package
    /// version ("7.0.14-30"); the most specific one wins.
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
    // Absolute paths: patch files are later handed to `git -C <tree>`, which
    // would resolve a relative path against the tree, not the caller's cwd.
    let catalog = &std::fs::canonicalize(catalog).with_context(|| format!("reading {}", catalog.display()))?;
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
        let mut entry: Entry =
            serde_norway::from_str(&text).with_context(|| format!("parsing {}/meta.yaml", dir.display()))?;
        // Optional fields: an empty value means the same as omitting the key.
        for f in [&mut entry.psa, &mut entry.mitigation] {
            if f.as_deref().is_some_and(|v| v.trim().is_empty()) {
                *f = None;
            }
        }
        let dir_name = dir.file_name().unwrap_or_default().to_string_lossy();
        if entry.id != dir_name {
            bail!("{}: id {:?} does not match directory name", dir.display(), entry.id);
        }
        out.push(Loaded { entry, dir });
    }
    Ok(out)
}

/// Reviewers a livepatchable entry needs. The project has one maintainer
/// so far; this goes back to 2 as soon as there is a second one (see
/// CONTRIBUTING.md).
pub const MIN_REVIEWERS: usize = 1;

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
            if e.functions.is_empty() {
                p.push("class livepatchable needs the reviewed list of patched functions (`functions`)".into());
            }
            if e.reviewed_by.len() < MIN_REVIEWERS {
                p.push(format!("class livepatchable needs {MIN_REVIEWERS} reviewer(s), has {}", e.reviewed_by.len()));
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
    /// Reproducer scripts of the included fixes (CVE id, absolute path), run
    /// by the QEMU stage before and after the livepatch.
    #[serde(default)]
    pub reproducers: Vec<(String, PathBuf)>,
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
/// `fixed_in_pve` as a string, a list, null or "".
fn one_or_many<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    let v: Option<OneOrMany> = Option::deserialize(d)?;
    Ok(match v {
        None => vec![],
        Some(OneOrMany::One(s)) => vec![s],
        Some(OneOrMany::Many(v)) => v,
    }
    .into_iter()
    .map(|s| s.trim().to_owned())
    .filter(|s| !s.is_empty())
    .collect())
}

fn series_of(pkg: &str) -> String {
    pkg.split('.').take(2).collect::<Vec<_>>().join(".")
}

impl Entry {
    /// The version in this package's series that contains the fix.
    pub fn fixed_in_series(&self, pkg: &str) -> Option<&str> {
        let s = series_of(pkg);
        self.fixed_in_pve.iter().find(|f| series_of(f) == s).map(String::as_str)
    }
}

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
        let fixed_here = e.fixed_in_series(pkg);
        if let Some(fixed) = fixed_here
            && cmp_version(pkg, fixed).is_ge()
        {
            r.skipped.push((e.id.clone(), format!("kernel {pkg} already contains the fix (fixed in {fixed})")));
            continue;
        }
        // For "reboot into": the fixed kernel of this series, else any
        // series that has it (e.g. the opt-in kernel).
        let fixed_in = fixed_here.or_else(|| e.fixed_in_pve.last().map(String::as_str)).map(|v| format!("{v}-pve"));
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
        // Most specific first: package version (7.0.14-30), series (7.0),
        // then the default.
        let series = series_of(pkg);
        let file = e
            .patches
            .get(pkg)
            .or_else(|| e.patches.get(&series))
            .or_else(|| e.patches.get("default"))
            .context(format!("{}: no patch", e.id))?;
        let patch = l.dir.join(file);
        if let Some(tree) = tree {
            match applies(tree, &patch)? {
                Applies::Yes => {}
                Applies::AlreadyContained => {
                    // Only plausible if the catalog agrees that this kernel
                    // already has the fix; otherwise a dirty tree or a
                    // coincidental reverse match would silently drop it.
                    if let Some(f) = fixed_here.filter(|f| cmp_version(pkg, f).is_lt()) {
                        bail!(
                            "{}: the patch applies in reverse to {kernel_release}, but fixed_in_pve says {f} \
                             (later). Check the tree is clean and the entry is right",
                            e.id
                        );
                    }
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
        if let Some(rep) = e.tests.get("reproducer").filter(|v| v.starts_with("tests/")) {
            r.reproducers.push((e.id.clone(), l.dir.join(rep)));
        }
    }
    // Each patch applies on its own; klp-build applies them all, in this
    // order. Two fixes in the same function can still conflict together.
    if let Some(tree) = tree {
        if r.patches.len() > 1 {
            check_cumulative(tree, &r)?;
        }
    }
    Ok(r)
}

fn is_commit_id(c: &str) -> bool {
    (12..=40).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Apply all patches one after another to a throwaway index built from
/// the tree's HEAD. `git apply --check` with several patches would check
/// each against the original instead. Index and new objects go to a
/// temporary directory; the tree, including its object store, is only read,
/// so this works on read-only trees too.
fn check_cumulative(tree: &Path, r: &Resolved) -> Result<()> {
    let tmp =
        tempfile::Builder::new().prefix("hvpatch-resolve-").tempdir().context("creating a temporary directory")?;
    let out = Command::new("git").arg("-C").arg(tree).args(["rev-parse", "--absolute-git-dir"]).output()?;
    if !out.status.success() {
        bail!("{} is not a git tree: {}", tree.display(), String::from_utf8_lossy(&out.stderr).trim());
    }
    let objects = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()).join("objects");
    let git = |args: &[&std::ffi::OsStr]| {
        Command::new("git")
            .arg("-C")
            .arg(tree)
            .env("GIT_INDEX_FILE", tmp.path().join("index"))
            .env("GIT_OBJECT_DIRECTORY", tmp.path().join("objects"))
            .env("GIT_ALTERNATE_OBJECT_DIRECTORIES", &objects)
            .args(args)
            .output()
    };
    std::fs::create_dir_all(tmp.path().join("objects"))?;
    let out = git(&["read-tree".as_ref(), "HEAD".as_ref()]).context("running git read-tree")?;
    if !out.status.success() {
        bail!(
            "cannot check the patch order in {} (git read-tree HEAD failed): {}",
            tree.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    for (patch, fix) in r.patches.iter().zip(&r.fixes) {
        let out = git(&["apply".as_ref(), "--cached".as_ref(), patch.as_os_str()]).context("running git apply")?;
        if out.status.success() {
            continue;
        }
        let err = String::from_utf8_lossy(&out.stderr);
        // Only a patch that does not fit is an ordering conflict; anything
        // else (I/O, permissions) is a problem of this environment.
        if err.contains("patch failed") || err.contains("does not apply") || err.contains("already exists") {
            bail!(
                "{}: applies to {} on its own, but not after the patches before it in catalog order ({}):\n{}",
                fix.id,
                r.kernel,
                r.fixes.iter().map(|f| f.id.as_str()).collect::<Vec<_>>().join(", "),
                err.trim()
            );
        }
        bail!("cannot check the patch order in {} ({}): {}", tree.display(), fix.id, err.trim());
    }
    Ok(())
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
        // Either a directory of `<sha>.diff` files (downloaded per commit,
        // which avoids shallow-clone pitfalls) or a git checkout.
        let diff_file = upstream.join(format!("{c}.diff"));
        if diff_file.is_file() {
            theirs.extend_from_slice(&std::fs::read(&diff_file)?);
            continue;
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
functions: ["vmlinux:old_bug"]
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
    fn fixed_in_and_patches_per_series() {
        let t = tempfile::tempdir().unwrap();
        write(
            t.path(),
            "CVE-2026-0011",
            r#"
id: CVE-2026-0011
title: t
upstream_commits: ["0123456789abcdef"]
fixed_in_pve: ["7.3.6-1", "7.0.15-3"]
severity: high
class: livepatchable
patches:
  default: 0001-fix.patch
  "7.0": 0001-fix.patch.70
functions: ["vmlinux:f"]
"#,
        );
        std::fs::write(t.path().join("CVE-2026-0011/0001-fix.patch.70"), "--- a/x\n+++ b/x\n").unwrap();
        let e = load(t.path()).unwrap();
        // 7.0.15-3 fixes it for 7.0 only; a 7.3 kernel before 7.3.6 still needs it.
        let r = resolve(&e, "7.3.4-1-pve", None, false).unwrap();
        assert_eq!(r.fixes.len(), 1);
        assert!(r.patches[0].ends_with("0001-fix.patch"), "{:?}", r.patches);
        let r = resolve(&e, "7.0.14-30-pve", None, false).unwrap();
        assert_eq!(r.fixes.len(), 1);
        assert!(r.patches[0].ends_with("0001-fix.patch.70"), "series patch wins: {:?}", r.patches);
        assert!(resolve(&e, "7.0.15-3-pve", None, false).unwrap().fixes.is_empty());
        assert!(resolve(&e, "7.3.6-1-pve", None, false).unwrap().fixes.is_empty());
        // A single string still works.
        let one: Entry = serde_norway::from_str(
            "id: x\ntitle: t\nupstream_commits: []\nfixed_in_pve: \"7.3.6-1\"\nseverity: low\nclass: needs-manual\n",
        )
        .unwrap();
        assert_eq!(one.fixed_in_pve, vec!["7.3.6-1"]);
        assert_eq!(one.fixed_in_series("7.0.14-30"), None);
    }

    /// A git tree with f.c and g.c ("a b c") committed.
    fn git_tree(tree: &Path) {
        std::fs::create_dir_all(tree).unwrap();
        let git = |args: &[&str]| {
            let st = Command::new("git").arg("-C").arg(tree).args(args).output().unwrap();
            assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
        };
        git(&["init", "-q"]);
        std::fs::write(tree.join("f.c"), "a\nb\nc\n").unwrap();
        std::fs::write(tree.join("g.c"), "a\nb\nc\n").unwrap();
        git(&["add", "f.c", "g.c"]);
        git(&["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base"]);
    }

    /// 0001 and 0002 change the same line of f.c; 0003 changes g.c.
    fn conflict_catalog(cat: &Path) -> Vec<Loaded> {
        for (id, file, new) in
            [("CVE-2026-0001", "f.c", "x"), ("CVE-2026-0002", "f.c", "y"), ("CVE-2026-0003", "g.c", "z")]
        {
            let d = cat.join(id);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("0001-fix.patch"),
                format!("--- a/{file}\n+++ b/{file}\n@@ -1,3 +1,3 @@\n a\n-b\n+{new}\n c\n"),
            )
            .unwrap();
            std::fs::write(
                d.join("meta.yaml"),
                format!(
                    "id: {id}\ntitle: t\nupstream_commits: [\"0123456789abcdef\"]\nseverity: high\n\
                     class: livepatchable\npatches:\n  default: 0001-fix.patch\nfunctions: [\"vmlinux:f\"]\n\
                     reviewed_by: [\"a\", \"b\"]\n"
                ),
            )
            .unwrap();
        }
        load(cat).unwrap()
    }

    #[test]
    fn patches_that_conflict_together_are_refused() {
        let t = tempfile::tempdir().unwrap();
        let tree = t.path().join("tree");
        git_tree(&tree);
        let entries = conflict_catalog(&t.path().join("catalog"));
        // Each one applies alone ...
        for e in &entries {
            assert!(resolve(std::slice::from_ref(e), "7.3.5-1-pve", Some(&tree), false).is_ok());
        }
        let conflicting = [entries[0].clone(), entries[1].clone()];
        let compatible = [entries[0].clone(), entries[2].clone()];
        assert!(resolve(&compatible, "7.3.5-1-pve", Some(&tree), false).is_ok());
        // ... but 0001 and 0002 not together, and never with --allow-conflicts.
        for allow in [false, true] {
            let err = resolve(&conflicting, "7.3.5-1-pve", Some(&tree), allow).unwrap_err().to_string();
            assert!(err.contains("CVE-2026-0002") && err.contains("not after the patches before it"), "{err}");
        }
        // The working tree was not touched.
        assert_eq!(std::fs::read_to_string(tree.join("f.c")).unwrap(), "a\nb\nc\n");
    }

    #[test]
    fn already_contained_must_agree_with_fixed_in_pve() {
        let t = tempfile::tempdir().unwrap();
        let tree = t.path().join("tree");
        git_tree(&tree);
        // The tree already has the fix: f.c reads "a x c".
        std::fs::write(tree.join("f.c"), "a\nx\nc\n").unwrap();
        let st = Command::new("git")
            .arg("-C")
            .arg(&tree)
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "fix"])
            .output()
            .unwrap();
        assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
        let entries = conflict_catalog(&t.path().join("catalog"));
        let first = &entries[..1];
        // No fixed_in_pve: plausible, skipped.
        let r = resolve(first, "7.3.5-1-pve", Some(&tree), false).unwrap();
        assert!(r.fixes.is_empty() && r.skipped.len() == 1);
        // fixed_in_pve later than this kernel contradicts the tree.
        let mut e = first[0].clone();
        e.entry.fixed_in_pve = vec!["7.3.9-1".into()];
        let err = resolve(&[e], "7.3.5-1-pve", Some(&tree), false).unwrap_err().to_string();
        assert!(err.contains("applies in reverse") && err.contains("7.3.9-1"), "{err}");
    }

    #[test]
    fn order_check_works_on_a_read_only_tree() {
        let t = tempfile::tempdir().unwrap();
        let tree = t.path().join("tree");
        git_tree(&tree);
        let entries = conflict_catalog(&t.path().join("catalog"));
        let chmod =
            |mode: &str| assert!(Command::new("chmod").args(["-R", mode]).arg(&tree).status().unwrap().success());
        // Read-only before anything ran against it (e.g. a :ro mount), so the
        // blobs the patches create are not in the tree's object store yet.
        chmod("a-w");
        let ok = resolve(&[entries[0].clone(), entries[2].clone()], "7.3.5-1-pve", Some(&tree), false);
        let bad = resolve(&[entries[0].clone(), entries[1].clone()], "7.3.5-1-pve", Some(&tree), false);
        chmod("u+w");
        assert!(ok.is_ok(), "two compatible patches on a read-only tree: {ok:?}");
        let err = bad.unwrap_err().to_string();
        assert!(err.contains("not after the patches before it"), "{err}");
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
psa: ""
mitigation: ""
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
        assert!(!p.iter().any(|m| m.contains("psa")), "empty psa means none: {p:?}");
        assert!(e[0].entry.psa.is_none() && e[0].entry.mitigation.is_none());
    }

    #[test]
    fn patch_id_from_diff_directory() {
        let t = tempfile::tempdir().unwrap();
        let diff = "diff --git a/mm/gup.c b/mm/gup.c\nindex 1..2 100644\n--- a/mm/gup.c\n+++ b/mm/gup.c\n\
@@ -1,3 +1,5 @@\n a\n+\tif (!n)\n+\t\treturn 0;\n b\n c\n";
        write(
            t.path(),
            "CVE-2026-0010",
            "id: CVE-2026-0010\ntitle: x\nupstream_commits: [\"0123456789abcdef\"]\nseverity: low\nclass: needs-manual\n",
        );
        let e = load(t.path()).unwrap();
        let mut l = e[0].clone();
        std::fs::write(l.dir.join("0001-fix.patch"), diff).unwrap();
        l.entry.patches.insert("default".into(), "0001-fix.patch".into());
        let up = t.path().join("upstream");
        std::fs::create_dir(&up).unwrap();
        std::fs::write(up.join("0123456789abcdef.diff"), diff).unwrap();
        assert_eq!(check_patch_id(&l, &up).unwrap(), None);
        std::fs::write(up.join("0123456789abcdef.diff"), diff.replace("return 0", "return 1")).unwrap();
        assert!(check_patch_id(&l, &up).unwrap().unwrap().contains("differs"));
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
