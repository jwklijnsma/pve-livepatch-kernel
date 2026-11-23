//! Gate A: does a livepatch module built against our own kernel build
//! fit the kernel Proxmox actually shipped?
//!
//! Checks, all against artifacts of the shipped packages:
//! 1. `.modinfo`: `livepatch=Y`, vermagic release, module name.
//! 2. Modversions: every imported symbol's CRC equals `Module.symvers`
//!    from proxmox-headers.
//! 3. Livepatch relocations (`.klp.sym.<obj>.<sym>,<pos>`): these are
//!    resolved through kallsyms at patch time, not through modversions.
//!    Each must exist in the shipped `System.map` (vmlinux) or the shipped
//!    module, and the position must be resolvable (unique if 0).
//! 4. Patched functions (from `objtool klp diff`) exist in the shipped
//!    kernel under exactly that name.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use klp_core::elf;
use serde::Serialize;

#[derive(Debug, Serialize, Default)]
pub struct Report {
    pub ok: bool,
    pub module: String,
    pub checked_versions: usize,
    pub checked_klp_symbols: usize,
    pub checked_functions: usize,
    /// Patched functions were compared with the reviewed catalog lists.
    pub compared_with_catalog: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

pub struct Inputs<'a> {
    pub module: &'a Path,
    pub kernel_release: &'a str,
    pub expected_name: Option<&'a str>,
    pub system_map: &'a Path,
    pub symvers: &'a Path,
    /// `/lib/modules/<kver>` of the extracted shipped package.
    pub modules_dir: Option<&'a Path>,
    /// One `object:function[,sympos]` per line, from `objtool klp diff`.
    pub functions: Option<&'a Path>,
    /// Resolved catalog: the union of its reviewed `functions` must equal
    /// the function list above exactly.
    pub resolved: Option<&'a Path>,
}

/// Read a function list: one `object:function[,sympos]` per line.
pub fn read_function_list(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_owned).collect())
}

/// `object:function` without the sympos suffix.
fn normalize(f: &str) -> String {
    f.split(',').next().unwrap_or(f).trim().to_owned()
}

/// Compare what the module patches (objtool diff) with what reviewers
/// signed off (catalog). Both directions matter: an extra function in the
/// diff was never reviewed, a missing one means the reviewed fix is not
/// (fully) in the module. Returns one error line per difference.
pub fn compare_function_sets(diff: &[String], reviewed: &[String]) -> Vec<String> {
    use std::collections::BTreeSet;
    let d: BTreeSet<String> = diff.iter().map(|f| normalize(f)).collect();
    let r: BTreeSet<String> = reviewed.iter().map(|f| normalize(f)).collect();
    let mut errs = Vec::new();
    if d.is_empty() {
        errs.push("the objtool diff lists no changed functions".to_owned());
    }
    for f in d.difference(&r) {
        errs.push(format!("function {f} is patched by the module but not listed in the reviewed catalog entries"));
    }
    for f in r.difference(&d) {
        errs.push(format!("function {f} is listed in the reviewed catalog entries but not patched by the module"));
    }
    if !errs.is_empty() {
        errs.push(format!(
            "module patches: [{}]; catalog lists: [{}]",
            d.into_iter().collect::<Vec<_>>().join(", "),
            r.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    errs
}

/// Lazily loaded symbol tables of the shipped kernel and its modules.
struct Shipped {
    vmlinux: HashMap<String, u32>,
    modules_dir: Option<PathBuf>,
    index: Option<HashMap<String, PathBuf>>,
    cache: HashMap<String, Option<HashMap<String, u32>>>,
}

impl Shipped {
    fn counts(&mut self, object: &str) -> Result<Option<&HashMap<String, u32>>> {
        if object == "vmlinux" {
            return Ok(Some(&self.vmlinux));
        }
        let Some(dir) = &self.modules_dir else { return Ok(None) };
        if self.index.is_none() {
            let mut idx = HashMap::new();
            index_modules(dir, &mut idx)?;
            self.index = Some(idx);
        }
        if !self.cache.contains_key(object) {
            let entry = match self.index.as_ref().unwrap().get(object) {
                Some(p) => {
                    let b = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
                    Some(elf::symbol_counts(&b)?)
                }
                None => None,
            };
            self.cache.insert(object.to_owned(), entry);
        }
        Ok(self.cache[object].as_ref())
    }
}

fn index_modules(dir: &Path, idx: &mut HashMap<String, PathBuf>) -> Result<()> {
    for e in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?.flatten() {
        let p = e.path();
        if e.file_type()?.is_dir() {
            index_modules(&p, idx)?;
        } else if let Some(n) = p.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".ko")) {
            idx.insert(klp_core::naming::normalize_module_name(n), p);
        }
    }
    Ok(())
}

fn check_symbol(sh: &mut Shipped, object: &str, name: &str, sympos: u32, what: &str, r: &mut Report) -> Result<()> {
    let Some(counts) = sh.counts(object)? else {
        r.warnings.push(format!("{what} {object}:{name}: shipped module {object} not available, not checked"));
        return Ok(());
    };
    let n = counts.get(name).copied().unwrap_or(0);
    if n == 0 {
        r.errors.push(format!("{what} {object}:{name} does not exist in the shipped kernel"));
    } else if sympos == 0 && n > 1 {
        r.errors
            .push(format!("{what} {object}:{name} is ambiguous in the shipped kernel ({n} symbols) but has sympos 0"));
    } else if sympos > n {
        r.errors.push(format!("{what} {object}:{name},{sympos}: the shipped kernel has only {n} such symbol(s)"));
    }
    Ok(())
}

pub fn run(i: &Inputs) -> Result<Report> {
    let bytes = std::fs::read(i.module).with_context(|| format!("reading {}", i.module.display()))?;
    let mut r = Report { module: i.module.display().to_string(), ..Default::default() };

    // 1. modinfo
    let info = elf::parse_modinfo(&bytes)?;
    if !info.is_livepatch() {
        r.errors.push("modinfo: livepatch=Y missing".into());
    }
    match info.vermagic_release() {
        Some(v) if v == i.kernel_release => {}
        v => r.errors.push(format!("modinfo: vermagic release {v:?} != {}", i.kernel_release)),
    }
    if let Some(want) = i.expected_name
        && info.name() != Some(want)
    {
        r.errors.push(format!("modinfo: name {:?} != {want:?}", info.name()));
    }

    // 2. modversions
    let symvers = elf::parse_symvers(
        &std::fs::read_to_string(i.symvers).with_context(|| format!("reading {}", i.symvers.display()))?,
    );
    let versions = elf::parse_versions(&bytes)?;
    if versions.is_empty() {
        r.warnings.push("module has no modversions table; is CONFIG_MODVERSIONS off?".into());
    }
    for (sym, crc) in &versions {
        match symvers.get(sym) {
            Some(c) if c == crc => {}
            Some(c) => r.errors.push(format!("modversions: {sym} crc {crc:#010x} != shipped {c:#010x}")),
            None => r.errors.push(format!("modversions: {sym} is not exported by the shipped kernel")),
        }
    }
    r.checked_versions = versions.len();

    // 3. klp relocation symbols
    let map_text =
        std::fs::read_to_string(i.system_map).with_context(|| format!("reading {}", i.system_map.display()))?;
    let mut sh = Shipped {
        vmlinux: elf::system_map_counts(&map_text),
        modules_dir: i.modules_dir.map(Path::to_path_buf),
        index: None,
        cache: HashMap::new(),
    };
    let klp = elf::klp_symbols(&bytes)?;
    for s in &klp {
        check_symbol(&mut sh, &s.object, &s.name, s.sympos, "klp symbol", &mut r)?;
    }
    r.checked_klp_symbols = klp.len();

    // 4. patched functions
    if let Some(f) = i.functions {
        let list = read_function_list(f)?;
        for line in &list {
            let Some((obj, rest)) = line.split_once(':') else {
                r.errors.push(format!("functions: malformed line {line:?}, want object:function[,sympos]"));
                continue;
            };
            let (name, pos) = match rest.rsplit_once(',') {
                Some((n, p)) => (n, p.parse().unwrap_or(0)),
                None => (rest, 0),
            };
            check_symbol(&mut sh, obj, name, pos, "patched function", &mut r)?;
            r.checked_functions += 1;
        }
        // 5. the module patches exactly what was reviewed
        if let Some(res) = i.resolved {
            let resolved: crate::catalog::Resolved =
                serde_json::from_slice(&std::fs::read(res).with_context(|| format!("reading {}", res.display()))?)
                    .context("parsing resolved catalog")?;
            let reviewed: Vec<String> = resolved.fixes.iter().flat_map(|f| f.functions.iter().cloned()).collect();
            r.errors.extend(compare_function_sets(&list, &reviewed));
            r.compared_with_catalog = true;
        }
    } else if i.resolved.is_some() {
        r.errors.push("--resolved needs --functions: cannot compare the module with the catalog".into());
    } else {
        r.warnings.push("no function list given; patched functions not checked".into());
    }

    if !elf::has_module_signature(&bytes) {
        r.warnings.push("module is not signed yet (expected before the signing step)".into());
    }
    r.ok = r.errors.is_empty();
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(x: &[&str]) -> Vec<String> {
        x.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn function_sets_must_match_exactly() {
        assert!(
            compare_function_sets(&v(&["vmlinux:cmdline_proc_show"]), &v(&["vmlinux:cmdline_proc_show,1"])).is_empty()
        );
        let e = compare_function_sets(&v(&["vmlinux:cmdline_proc_show"]), &v(&["vmlinux:tcp_v4_rcv"]));
        assert!(e.iter().any(|l| l.contains("cmdline_proc_show is patched by the module but not listed")));
        assert!(e.iter().any(|l| l.contains("tcp_v4_rcv is listed") && l.contains("not patched")));
        assert!(compare_function_sets(&v(&[]), &v(&[])).iter().any(|l| l.contains("no changed functions")));
    }
}
