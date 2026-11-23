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
    /// One `object:function[,sympos]` per line.
    pub functions: Option<&'a Path>,
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
        let text = std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
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
    } else {
        r.warnings.push("no function list given; patched functions not checked".into());
    }

    if !elf::has_module_signature(&bytes) {
        r.warnings.push("module is not signed yet (expected before the signing step)".into());
    }
    r.ok = r.errors.is_empty();
    Ok(r)
}
