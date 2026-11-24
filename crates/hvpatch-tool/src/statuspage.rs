//! `status-page`: a static HTML overview of a livepatch repository (what
//! each ring serves per kernel, which CVEs are fixed live, what needs a
//! reboot, what was revoked). Reads only the published files, so it can run
//! on the repository host after every publish.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use klp_core::manifest::{Manifest, RINGS};
use klp_core::naming::cmp_version;
use klp_core::revocation::RevocationList;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// CVE ids link to the kernel CNA's record.
fn cve(id: &str) -> String {
    if id.starts_with("CVE-") && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        format!("<a href=\"https://www.cve.org/CVERecord?id={id}\">{id}</a>")
    } else {
        esc(id)
    }
}

pub struct Repo {
    /// kernel -> ring -> manifest
    pub kernels: BTreeMap<String, BTreeMap<String, Manifest>>,
    pub revoked: Option<RevocationList>,
}

pub fn load(root: &Path) -> Result<Repo> {
    let v1 = root.join("v1");
    let mut kernels = BTreeMap::new();
    for e in std::fs::read_dir(&v1).with_context(|| format!("reading {}", v1.display()))?.flatten() {
        if !e.path().is_dir() {
            continue;
        }
        let kernel = e.file_name().to_string_lossy().into_owned();
        let mut rings = BTreeMap::new();
        for ring in RINGS {
            let f = e.path().join(ring).join("manifest.json");
            if let Ok(b) = std::fs::read(&f) {
                let m = Manifest::from_json(&b).with_context(|| format!("parsing {}", f.display()))?;
                rings.insert(ring.to_string(), m);
            }
        }
        if !rings.is_empty() {
            kernels.insert(kernel, rings);
        }
    }
    let revoked = match std::fs::read(v1.join("revoked.json")) {
        Ok(b) => Some(RevocationList::from_json(&b)?),
        Err(_) => None,
    };
    Ok(Repo { kernels, revoked })
}

pub fn render(repo: &Repo, title: &str, now: DateTime<Utc>) -> String {
    let mut h = String::new();
    let _ = write!(
        h,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{t}</title><style>\
         body{{font:15px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1d2125}}\
         h1{{font-size:1.6rem}}h2{{margin-top:2.2rem;font-size:1.2rem}}\
         table{{border-collapse:collapse;width:100%;margin:.6rem 0}}\
         th,td{{text-align:left;padding:.35rem .6rem;border-bottom:1px solid #e3e6e8;vertical-align:top}}\
         th{{font-weight:600;background:#f6f7f8}}code{{font-size:.9em}}\
         .ok{{color:#1a7f37}}.warn{{color:#9a6700}}.bad{{color:#cf222e}}.muted{{color:#6e7781}}\
         @media (prefers-color-scheme:dark){{body{{background:#0d1117;color:#e6edf3}}th{{background:#161b22}}\
         th,td{{border-color:#30363d}}a{{color:#58a6ff}}}}\
         </style></head><body><h1>{t}</h1>\
         <p class=\"muted\">Generated {now} from the signed manifests in this repository. \
         Verify on a node with <code>hvpatch status</code>.</p>",
        t = esc(title),
        now = now.format("%Y-%m-%d %H:%M UTC")
    );

    let mut kernels: Vec<_> = repo.kernels.iter().collect();
    kernels.sort_by(|a, b| cmp_version(b.0, a.0));
    let _ = write!(h, "<h2>Kernels</h2><table><tr><th>Kernel</th>");
    for r in RINGS {
        let _ = write!(h, "<th>{r}</th>");
    }
    let _ = write!(h, "<th>Fixed live</th><th>Needs a reboot</th></tr>");
    for (k, rings) in &kernels {
        let _ = write!(h, "<tr><td><code>{}</code></td>", esc(k));
        for r in RINGS {
            match rings.get(*r) {
                Some(m) => {
                    let revoked = repo.revoked.as_ref().and_then(|l| l.find(&m.sha256)).is_some();
                    let expired = now >= m.expires;
                    let (class, note) = if revoked {
                        ("bad", " revoked")
                    } else if expired {
                        ("warn", " expired")
                    } else {
                        ("ok", "")
                    };
                    let _ = write!(
                        h,
                        "<td class=\"{class}\">level {}{note}<br><span class=\"muted\">{}</span></td>",
                        m.level,
                        m.built.format("%Y-%m-%d")
                    );
                }
                None => {
                    let _ = write!(h, "<td class=\"muted\">–</td>");
                }
            }
        }
        // The most advanced ring a node can be on: stable, else early, else canary.
        let m = RINGS.iter().rev().find_map(|r| rings.get(*r)).expect("non-empty");
        let fixed: Vec<String> = m.fixes.iter().map(|f| cve(&f.id)).collect();
        let reboot: Vec<String> = m
            .not_covered
            .iter()
            .map(|n| {
                format!(
                    "{} <span class=\"muted\">({}{})</span>",
                    cve(&n.id),
                    esc(&n.reason),
                    n.fixed_in.as_deref().map(|f| format!(", fixed in {}", esc(f))).unwrap_or_default()
                )
            })
            .collect();
        let _ = write!(
            h,
            "<td>{}</td><td>{}</td></tr>",
            if fixed.is_empty() { "–".into() } else { fixed.join(", ") },
            if reboot.is_empty() { "–".into() } else { reboot.join("<br>") }
        );
    }
    let _ = write!(h, "</table><p class=\"muted\">Fixed live / needs a reboot: as of the most advanced ring.</p>");

    if let Some(l) = &repo.revoked {
        let _ = write!(h, "<h2>Revoked levels</h2>");
        if l.revoked.is_empty() {
            let _ = write!(h, "<p>None.</p>");
        } else {
            let _ = write!(h, "<table><tr><th>Kernel</th><th>Level</th><th>Since</th><th>Reason</th></tr>");
            for r in &l.revoked {
                let _ = write!(
                    h,
                    "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(&r.kernel),
                    r.level,
                    r.revoked.format("%Y-%m-%d"),
                    esc(&r.reason)
                );
            }
            let _ = write!(h, "</table>");
        }
        let _ = write!(h, "<p class=\"muted\">Revocation list sequence {}.</p>", l.sequence);
    }
    let _ = writeln!(
        h,
        "<p class=\"muted\">Livepatches bridge the time to the next maintenance window; \
         they do not replace booting a fixed kernel.</p></body></html>"
    );
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use klp_core::manifest::{Fix, NotCovered};

    #[test]
    fn renders_rings_fixes_and_revocations() {
        let t = tempfile::tempdir().unwrap();
        let mut m = Manifest {
            format: 1,
            kernel: "7.3.5-1-pve".into(),
            kernel_build_id: Some("aa".into()),
            level: 2,
            ring: "canary".into(),
            module: "klp_hvp_7_3_5_1_p2.ko".into(),
            module_name: "klp_hvp_7_3_5_1_p2".into(),
            sha256: "a".repeat(64),
            built: "2026-11-23T09:00:00Z".parse().unwrap(),
            expires: "2026-12-23T09:00:00Z".parse().unwrap(),
            fixes: vec![Fix { id: "CVE-2026-1".into(), title: None, functions: vec![] }],
            not_covered: vec![NotCovered {
                id: "CVE-2026-2".into(),
                reason: "struct <change>".into(),
                fixed_in: Some("7.3.6-1-pve".into()),
                mitigation: None,
            }],
            superseded_by_kernel: None,
            builder_image: None,
            catalog_commit: None,
            states: vec![],
        };
        let d = t.path().join("v1/7.3.5-1-pve/canary");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("manifest.json"), m.to_json_pretty()).unwrap();
        m.ring = "stable".into();
        m.level = 1;
        m.sha256 = "b".repeat(64);
        let d = t.path().join("v1/7.3.5-1-pve/stable");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("manifest.json"), m.to_json_pretty()).unwrap();
        let mut l = RevocationList::default();
        l.revoke(
            klp_core::revocation::Revoked {
                sha256: "a".repeat(64),
                kernel: "7.3.5-1-pve".into(),
                level: 2,
                reason: "regression".into(),
                revoked: Utc::now(),
            },
            Utc::now(),
        );
        std::fs::write(t.path().join("v1/revoked.json"), l.to_json_pretty()).unwrap();

        let html = render(&load(t.path()).unwrap(), "Livepatches <test>", "2026-11-24T12:00:00Z".parse().unwrap());
        assert!(html.contains("Livepatches &lt;test&gt;"));
        assert!(html.contains("level 2 revoked"));
        assert!(html.contains("level 1<br>"));
        assert!(html.contains("CVERecord?id=CVE-2026-1"));
        assert!(html.contains("struct &lt;change&gt;"));
        assert!(html.contains("fixed in 7.3.6-1-pve"));
    }
}
