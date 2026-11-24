//! `cve-scan`: which kernel CVEs affect a Proxmox kernel and are not in the
//! catalog yet, by priority.
//!
//! Sources, all read from local files (fetching is `builder/cve-feeds.sh`'s
//! job, so this runs offline and reproducibly):
//! * the kernel CNA's `vulns.git` (`cve/published/<year>/CVE-*.{dyad,sha1,json,cvss}`),
//! * optionally CISA's Known Exploited Vulnerabilities JSON,
//! * optionally FIRST's EPSS scores (CSV).
//!
//! `.dyad` lines are `vuln_ver:vuln_sha:fixed_ver:fixed_sha`; `0` means "since
//! the beginning" or "not fixed". A version with two components (7.3) is a
//! mainline release, three (7.3.5) a stable release.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use klp_core::naming::cmp_version;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dyad {
    pub vuln: Option<String>,
    pub fixed: Option<String>,
}

pub fn parse_dyad(text: &str) -> Vec<Dyad> {
    let opt = |v: &str| (v != "0" && !v.is_empty()).then(|| v.to_owned());
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let f: Vec<&str> = l.trim().split(':').collect();
            (f.len() == 4).then(|| Dyad { vuln: opt(f[0]), fixed: opt(f[2]) })
        })
        .collect()
}

fn series(v: &str) -> String {
    v.split('.').take(2).collect::<Vec<_>>().join(".")
}

fn is_mainline(v: &str) -> bool {
    v.split('.').count() == 2
}

/// Is upstream version `v` (e.g. 7.3.5) affected, according to the dyads?
/// Returns the stable release of v's series that fixes it, if any.
pub fn affected(dyads: &[Dyad], v: &str) -> (bool, Option<String>) {
    let s = series(v);
    // Lines that say something about v's series: fixes in that series, in
    // a mainline release (inherited by later series), or no fix at all.
    // Fixes in other stable series (6.12.113) do not.
    let relevant: Vec<&Dyad> = dyads
        .iter()
        .filter(|d| match &d.fixed {
            None => true,
            Some(f) => series(f) == s || is_mainline(f),
        })
        .collect();
    let covers = |f: &str| {
        if series(f) == s && !is_mainline(f) {
            cmp_version(f, v).is_le()
        } else {
            // Mainline release: contained in every later series and in all
            // stable releases of its own series.
            is_mainline(f) && cmp_version(f, &s).is_le()
        }
    };
    if relevant.iter().any(|d| d.fixed.as_deref().is_some_and(covers)) {
        return (false, None);
    }
    let introduced = relevant.iter().any(|d| d.vuln.as_deref().is_none_or(|vu| cmp_version(vu, v).is_le()));
    let fix_in_series = relevant
        .iter()
        .filter_map(|d| d.fixed.as_deref())
        .filter(|f| series(f) == s && !is_mainline(f))
        .min_by(|a, b| cmp_version(a, b))
        .map(str::to_owned);
    (introduced, fix_in_series)
}

/// CVSS 3.x base score from a vector string.
pub fn cvss3_base(vector: &str) -> Option<f64> {
    let m: HashMap<&str, &str> = vector.split('/').filter_map(|p| p.split_once(':')).collect();
    let av = match *m.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match *m.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let changed = *m.get("S")? == "C";
    let pr = match (*m.get("PR")?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match *m.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |k: &str| match m.get(k).copied() {
        Some("H") => Some(0.56),
        Some("L") => Some(0.22),
        Some("N") => Some(0.0),
        _ => None,
    };
    let iss = 1.0 - (1.0 - cia("C")?) * (1.0 - cia("I")?) * (1.0 - cia("A")?);
    let impact = if changed { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15) } else { 6.42 * iss };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let expl = 8.22 * av * ac * pr * ui;
    let raw = if changed { (1.08 * (impact + expl)).min(10.0) } else { (impact + expl).min(10.0) };
    // CVSS "round up" to one decimal.
    let i = (raw * 100_000.0).round() as i64;
    Some(if i % 10_000 == 0 { i as f64 / 100_000.0 } else { ((i / 10_000) + 1) as f64 / 10.0 })
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub priority: String,
    pub title: String,
    pub cvss: Option<f64>,
    pub vector: Option<String>,
    pub kev: bool,
    pub epss: Option<f64>,
    /// Touches code a guest can reach on a hypervisor (KVM, vhost, vfio,
    /// virtio, networking).
    pub hypervisor_relevant: bool,
    pub files: Vec<String>,
    /// Mainline commit(s) of the fix (`.sha1`, one per line).
    pub mainline_fix: Vec<String>,
    /// Upstream stable release of this series that fixes it, if any.
    pub fixed_upstream_stable: Option<String>,
}

/// Code a guest reaches on a KVM host: the hypervisor itself, its device
/// backends, and the host network path guest traffic takes (bridge,
/// firewall, IP stack, Open vSwitch).
const HYPERVISOR_PATHS: &[&str] = &[
    "arch/x86/kvm/",
    "virt/kvm/",
    "drivers/vhost/",
    "drivers/vfio/",
    "drivers/virtio/",
    "drivers/net/tun.c",
    "drivers/net/tap.c",
    "drivers/net/macvtap.c",
    "net/core/",
    "net/ipv4/",
    "net/ipv6/",
    "net/bridge/",
    "net/netfilter/",
    "net/openvswitch/",
    "net/8021q/",
];

pub struct Feeds {
    pub kev: HashSet<String>,
    pub epss: HashMap<String, f64>,
    /// Mainline commits known to be in the kernel tree (backports name
    /// them in their commit message). A finding whose fix is in here is
    /// dropped. Needed for 7.0: the Ubuntu base backports fixes without
    /// changing the upstream version.
    pub contained: HashSet<String>,
}

/// All 40-hex commit ids in a text (e.g. `git log --format=%B` of a tree).
pub fn commit_ids(text: &str) -> HashSet<String> {
    text.split(|c: char| !c.is_ascii_hexdigit()).filter(|w| w.len() == 40).map(|w| w.to_ascii_lowercase()).collect()
}

pub fn load_kev(path: &Path) -> Result<HashSet<String>> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?).context("parsing KEV JSON")?;
    Ok(v["vulnerabilities"]
        .as_array()
        .context("KEV JSON has no vulnerabilities array")?
        .iter()
        .filter_map(|x| x["cveID"].as_str().map(str::to_owned))
        .collect())
}

pub fn load_epss(path: &Path) -> Result<HashMap<String, f64>> {
    let text = std::fs::read_to_string(path)?;
    Ok(text
        .lines()
        .filter(|l| l.starts_with("CVE-"))
        .filter_map(|l| {
            let mut f = l.split(',');
            Some((f.next()?.to_owned(), f.next()?.trim().parse().ok()?))
        })
        .collect())
}

/// P0: exploited in the wild, or critical and reachable from a guest.
/// P1: high, likely exploited, or reachable from a guest.
/// P2: everything else.
pub fn priority(cvss: Option<f64>, kev: bool, epss: Option<f64>, hv: bool) -> &'static str {
    let c = cvss.unwrap_or(0.0);
    if kev || (c >= 9.0 && hv) {
        "P0"
    } else if c >= 7.0 || epss.unwrap_or(0.0) >= 0.1 || hv {
        "P1"
    } else {
        "P2"
    }
}

/// Scan `vulns/cve/published/*/` for CVEs affecting upstream version
/// `upstream` that are not in `known`.
pub fn scan(vulns: &Path, upstream: &str, known: &HashSet<String>, feeds: &Feeds) -> Result<Vec<Finding>> {
    let root = vulns.join("cve/published");
    let mut out = Vec::new();
    let mut years: Vec<PathBuf> = std::fs::read_dir(&root)
        .with_context(|| format!("reading {} (a vulns.git checkout?)", root.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    years.sort();
    for y in years {
        for e in std::fs::read_dir(&y)?.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("dyad") {
                continue;
            }
            let id = p.file_stem().unwrap_or_default().to_string_lossy().into_owned();
            if known.contains(&id) {
                continue;
            }
            let (hit, fix_stable) = affected(&parse_dyad(&std::fs::read_to_string(&p)?), upstream);
            if !hit {
                continue;
            }
            let mainline_fix: Vec<String> = std::fs::read_to_string(p.with_extension("sha1"))
                .map(|s| s.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default();
            if !mainline_fix.is_empty() && mainline_fix.iter().all(|c| feeds.contained.contains(c)) {
                continue;
            }
            let json: serde_json::Value = std::fs::read(p.with_extension("json"))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            let cna = &json["containers"]["cna"];
            let title = cna["title"].as_str().unwrap_or_default().to_owned();
            let files: Vec<String> = cna["affected"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|a| a["programFiles"].as_array())
                .map(|f| f.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
                .unwrap_or_default();
            // CNA CVSS: the .cvss file ("<uuid> CVSS:3.1/..."), else the JSON.
            let vector = std::fs::read_to_string(p.with_extension("cvss"))
                .ok()
                .and_then(|t| {
                    t.lines()
                        .next()
                        .and_then(|l| l.split_whitespace().find(|w| w.starts_with("CVSS:")))
                        .map(str::to_owned)
                })
                .or_else(|| {
                    cna["metrics"]
                        .as_array()
                        .and_then(|m| m.iter().find_map(|x| x["cvssV3_1"]["vectorString"].as_str().map(str::to_owned)))
                });
            let cvss = vector.as_deref().and_then(cvss3_base);
            let hv = files.iter().any(|f| HYPERVISOR_PATHS.iter().any(|h| f.starts_with(h)));
            let kev = feeds.kev.contains(&id);
            let epss = feeds.epss.get(&id).copied();
            out.push(Finding {
                priority: priority(cvss, kev, epss, hv).into(),
                mainline_fix,
                id,
                title,
                cvss,
                vector,
                kev,
                epss,
                hypervisor_relevant: hv,
                files,
                fixed_upstream_stable: fix_stable,
            });
        }
    }
    out.sort_by(|a, b| {
        a.priority.cmp(&b.priority).then(b.cvss.unwrap_or(0.0).total_cmp(&a.cvss.unwrap_or(0.0))).then(a.id.cmp(&b.id))
    });
    Ok(out)
}

/// A catalog entry skeleton for review (not in catalog/: it does not lint
/// until someone decides class, patch and functions).
pub fn draft_meta(f: &Finding) -> String {
    let severity = match f.cvss.unwrap_or(0.0) {
        c if c >= 9.0 => "critical",
        c if c >= 7.0 => "high",
        c if c >= 4.0 => "medium",
        _ => "low",
    };
    format!(
        "# Draft from `hvpatch-tool cve-scan` ({prio}{kev}). Review before moving it\n\
         # to catalog/: decide the class, add the patch and the patched functions.\n\
         # Files: {files}\n\
         # Fixed in upstream stable: {stable}\n\
         id: {id}\n\
         title: {title}\n\
         psa: \"\"\n\
         upstream_commits: [{commits}]\n\
         fixed_in_pve: \"\"\n\
         severity: {severity}\n\
         class: needs-manual\n\
         reason: \"draft: livepatchability not reviewed yet\"\n\
         patches:\n  default: 0001-fix.patch\n\
         functions: []\n\
         tests:\n  qemu_load: required\n  reproducer: none\n\
         reviewed_by: []\n",
        prio = f.priority,
        kev = if f.kev { ", known exploited" } else { "" },
        files = f.files.join(", "),
        stable = f.fixed_upstream_stable.as_deref().unwrap_or("not yet"),
        id = f.id,
        title = serde_json::to_string(&f.title).unwrap_or_default(),
        commits = f.mainline_fix.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(", "),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const DYAD: &str = "# dyad version: 1.2.0\n\
        2.6.27:aaa:6.12.113:bbb\n\
        2.6.27:aaa:7.2.11:ccc\n\
        2.6.27:aaa:7.3:ddd\n";

    #[test]
    fn dyad_semantics() {
        let d = parse_dyad(DYAD);
        assert_eq!(d.len(), 3);
        // Fixed in mainline 7.3: every 7.3.x and later has it.
        assert_eq!(affected(&d, "7.3.5"), (false, None));
        assert_eq!(affected(&d, "7.4.1"), (false, None));
        // 7.2 is fixed from 7.2.11 on.
        assert_eq!(affected(&d, "7.2.10"), (true, Some("7.2.11".into())));
        assert!(!affected(&d, "7.2.11").0);
        // 7.0 has no fix in its series and none inherited: affected.
        assert_eq!(affected(&d, "7.0.14"), (true, None));

        // Introduced in 7.3.4 (a stable backport), fixed in 7.3.6.
        let d = parse_dyad("7.3.4:x:7.3.6:y\n7.3.4:x:7.4:z\n");
        assert!(!affected(&d, "7.3.3").0);
        assert_eq!(affected(&d, "7.3.5"), (true, Some("7.3.6".into())));
        assert!(!affected(&d, "7.3.6").0);

        // Not fixed anywhere yet.
        let d = parse_dyad("6.16.10:x:0:0\n");
        assert!(affected(&d, "7.3.5").0);
        assert!(!affected(&d, "6.15.1").0);
    }

    #[test]
    fn cvss_scores() {
        assert_eq!(cvss3_base("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), Some(9.3));
        assert_eq!(cvss3_base("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), Some(7.8));
        assert_eq!(cvss3_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Some(9.8));
        assert_eq!(cvss3_base("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"), Some(5.5));
        assert_eq!(cvss3_base("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N"), Some(0.0));
        assert_eq!(cvss3_base("garbage"), None);
    }

    #[test]
    fn priorities() {
        assert_eq!(priority(Some(5.5), true, None, false), "P0");
        assert_eq!(priority(Some(9.3), false, None, true), "P0");
        assert_eq!(priority(Some(9.3), false, None, false), "P1");
        assert_eq!(priority(Some(5.5), false, Some(0.2), false), "P1");
        assert_eq!(priority(Some(5.5), false, None, true), "P1");
        assert_eq!(priority(Some(5.5), false, Some(0.01), false), "P2");
    }

    #[test]
    fn scan_tree() {
        let t = tempfile::tempdir().unwrap();
        let y = t.path().join("cve/published/2026");
        std::fs::create_dir_all(&y).unwrap();
        std::fs::write(y.join("CVE-2026-1.dyad"), DYAD).unwrap();
        std::fs::write(y.join("CVE-2026-1.sha1"), "ddd\n").unwrap();
        std::fs::write(y.join("CVE-2026-1.cvss"), "uuid CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\nwhy\n").unwrap();
        std::fs::write(
            y.join("CVE-2026-1.json"),
            r#"{"containers":{"cna":{"title":"ipv4: x","affected":[{"programFiles":["net/ipv4/ip_output.c"]}]}}}"#,
        )
        .unwrap();
        std::fs::write(y.join("CVE-2026-2.dyad"), "7.3.6:x:0:0\n").unwrap();
        let mut feeds = Feeds { kev: HashSet::new(), epss: HashMap::new(), contained: HashSet::new() };
        let f = scan(t.path(), "7.0.14", &HashSet::new(), &feeds).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].priority, "P0");
        assert_eq!(f[0].cvss, Some(9.3));
        assert_eq!(f[0].mainline_fix, vec!["ddd"]);
        assert!(draft_meta(&f[0]).contains("upstream_commits: [\"ddd\"]"));
        let known: HashSet<String> = ["CVE-2026-1".to_string()].into();
        assert!(scan(t.path(), "7.0.14", &known, &feeds).unwrap().is_empty());
        // A backport in the tree names the mainline commit.
        let d = "d".repeat(40);
        std::fs::write(y.join("CVE-2026-1.sha1"), format!("{d}\n")).unwrap();
        feeds.contained = commit_ids(&format!("ipv4: x\n\n(cherry picked from commit {d})\n"));
        assert!(scan(t.path(), "7.0.14", &HashSet::new(), &feeds).unwrap().is_empty());
    }
}
