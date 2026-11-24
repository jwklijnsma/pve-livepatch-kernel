//! Inspection of kernel module ELF files and kernel ELF notes.
//!
//! Used by the agent (vermagic, livepatch flag, name) and by Gate A in the
//! pipeline (modversions CRCs, livepatch relocation symbols).

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Result, bail};
use object::{Object, ObjectSection, ObjectSymbol};

/// Trailer of a module with an appended signature (`scripts/sign-file`).
pub const MODULE_SIG_MAGIC: &[u8] = b"~Module signature appended~\n";

/// Section index the kernel uses for livepatch relocation symbols.
pub const SHN_LIVEPATCH: u16 = 0xff20;

#[derive(Debug, Clone, Default)]
pub struct ModInfo {
    pub fields: BTreeMap<String, Vec<String>>,
}

impl ModInfo {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).and_then(|v| v.first()).map(String::as_str)
    }

    pub fn name(&self) -> Option<&str> {
        self.get("name")
    }

    pub fn vermagic(&self) -> Option<&str> {
        self.get("vermagic")
    }

    /// First token of vermagic is the kernel release (`uname -r`).
    pub fn vermagic_release(&self) -> Option<&str> {
        self.vermagic().and_then(|v| v.split_whitespace().next())
    }

    pub fn is_livepatch(&self) -> bool {
        self.get("livepatch") == Some("Y")
    }
}

pub fn has_module_signature(bytes: &[u8]) -> bool {
    bytes.ends_with(MODULE_SIG_MAGIC)
}

pub fn parse_modinfo(bytes: &[u8]) -> Result<ModInfo> {
    let file = object::File::parse(bytes).context("module is not a valid ELF file")?;
    let sec = file.section_by_name(".modinfo").context("module has no .modinfo section")?;
    let data = sec.data().context("reading .modinfo")?;
    let mut info = ModInfo::default();
    for entry in data.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let s = String::from_utf8_lossy(entry);
        if let Some((k, v)) = s.split_once('=') {
            info.fields.entry(k.to_owned()).or_default().push(v.to_owned());
        }
    }
    Ok(info)
}

/// Modversions of the symbols a module imports: `(symbol, crc)`.
///
/// Supports the classic `__versions` table and the extended format
/// (`__version_ext_crcs` / `__version_ext_names`) used for long symbol names.
pub fn parse_versions(bytes: &[u8]) -> Result<Vec<(String, u32)>> {
    let file = object::File::parse(bytes).context("module is not a valid ELF file")?;
    if !file.is_64() || !file.is_little_endian() {
        bail!("only 64-bit little-endian modules are supported");
    }
    let mut out = Vec::new();
    if let Some(sec) = file.section_by_name("__versions") {
        let data = sec.data()?;
        // struct modversion_info { unsigned long crc; char name[64 - 8]; }
        if data.len() % 64 != 0 {
            bail!("__versions has unexpected size {}", data.len());
        }
        for e in data.as_chunks::<64>().0 {
            let crc = u64::from_le_bytes(e[..8].try_into().unwrap());
            let name_raw = &e[8..];
            let end = name_raw.iter().position(|b| *b == 0).unwrap_or(name_raw.len());
            out.push((String::from_utf8_lossy(&name_raw[..end]).into_owned(), crc as u32));
        }
    }
    if let (Some(crcs), Some(names)) =
        (file.section_by_name("__version_ext_crcs"), file.section_by_name("__version_ext_names"))
    {
        let crcs = crcs.data()?;
        let names: Vec<&[u8]> = names.data()?.split(|b| *b == 0).filter(|n| !n.is_empty()).collect();
        if crcs.len() != names.len() * 4 {
            bail!("extended modversions: {} crcs for {} names", crcs.len() / 4, names.len());
        }
        for (c, n) in crcs.as_chunks::<4>().0.iter().zip(names) {
            out.push((String::from_utf8_lossy(n).into_owned(), u32::from_le_bytes(*c)));
        }
    }
    Ok(out)
}

/// A livepatch relocation symbol: `.klp.sym.<objname>.<symbol>,<sympos>`
/// (see Documentation/livepatch/module-elf-format.rst). These are resolved
/// by name through kallsyms when the patch is applied, not through
/// modversions, so they need their own check against the shipped kernel.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KlpSym {
    pub object: String,
    pub name: String,
    pub sympos: u32,
}

impl KlpSym {
    pub fn parse(full: &str) -> Option<Self> {
        let rest = full.strip_prefix(".klp.sym.")?;
        let (object, rest) = rest.split_once('.')?;
        let (name, pos) = rest.rsplit_once(',')?;
        Some(KlpSym { object: object.to_owned(), name: name.to_owned(), sympos: pos.parse().ok()? })
    }
}

impl std::fmt::Display for KlpSym {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{},{}", self.object, self.name, self.sympos)
    }
}

pub fn klp_symbols(bytes: &[u8]) -> Result<Vec<KlpSym>> {
    let file = object::File::parse(bytes).context("module is not a valid ELF file")?;
    let mut out: Vec<KlpSym> = file.symbols().filter_map(|s| s.name().ok().and_then(KlpSym::parse)).collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// Number of symbols per name in a module's symbol table (for sympos checks
/// against shipped in-tree modules).
pub fn symbol_counts(bytes: &[u8]) -> Result<HashMap<String, u32>> {
    let file = object::File::parse(bytes).context("not a valid ELF file")?;
    let mut map = HashMap::new();
    for s in file.symbols() {
        if let Ok(n) = s.name() {
            if !n.is_empty() && !s.is_undefined() && !n.starts_with(".klp.sym.") {
                *map.entry(n.to_owned()).or_insert(0) += 1;
            }
        }
    }
    Ok(map)
}

/// Extract the GNU build-id from a raw ELF note stream, as found in
/// `/sys/kernel/notes` (vmlinux) or `/sys/module/<m>/notes/.note.gnu.build-id`.
pub fn build_id_from_notes(notes: &[u8]) -> Option<String> {
    const NT_GNU_BUILD_ID: u32 = 3;
    let mut off = 0usize;
    let rd = |o: usize| notes.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let align4 = |n: usize| (n + 3) & !3;
    while off + 12 <= notes.len() {
        let namesz = rd(off)? as usize;
        let descsz = rd(off + 4)? as usize;
        let ntype = rd(off + 8)?;
        let name_off = off + 12;
        let desc_off = name_off.checked_add(align4(namesz))?;
        let next = desc_off.checked_add(align4(descsz))?;
        if next > notes.len() {
            return None;
        }
        let name = &notes[name_off..name_off + namesz];
        if ntype == NT_GNU_BUILD_ID && name == b"GNU\0" && descsz > 0 {
            return Some(hex::encode(&notes[desc_off..desc_off + descsz]));
        }
        off = next;
    }
    None
}

/// Parse `System.map` (`address type name`) into symbol counts per name.
pub fn system_map_counts(text: &str) -> HashMap<String, u32> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(_addr), Some(_ty), Some(name)) = (it.next(), it.next(), it.next()) else { continue };
        *map.entry(name.to_owned()).or_insert(0) += 1;
    }
    map
}

/// Parse `Module.symvers`: `0xCRC<TAB>symbol<TAB>module<TAB>export<TAB>ns`.
pub fn parse_symvers(text: &str) -> HashMap<String, u32> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let mut it = line.split('\t');
        let (Some(crc), Some(sym)) = (it.next(), it.next()) else { continue };
        if let Ok(c) = u32::from_str_radix(crc.trim_start_matches("0x"), 16) {
            map.insert(sym.to_owned(), c);
        }
    }
    map
}

#[cfg(test)]
pub(crate) mod testelf {
    use object::write::{Object as WObject, Symbol, SymbolSection};
    use object::{Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope};

    /// Build a minimal x86-64 relocatable that looks like a livepatch module.
    pub fn livepatch_module(name: &str, vermagic: &str, versions: &[(&str, u32)], klp_syms: &[&str]) -> Vec<u8> {
        let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let modinfo = obj.add_section(vec![], b".modinfo".to_vec(), SectionKind::ReadOnlyData);
        let mut mi = Vec::new();
        for kv in [format!("name={name}"), format!("vermagic={vermagic}"), "livepatch=Y".into(), "license=GPL".into()] {
            mi.extend_from_slice(kv.as_bytes());
            mi.push(0);
        }
        obj.append_section_data(modinfo, &mi, 1);

        let vers = obj.add_section(vec![], b"__versions".to_vec(), SectionKind::ReadOnlyData);
        let mut vd = Vec::new();
        for (sym, crc) in versions {
            let mut e = [0u8; 64];
            e[..8].copy_from_slice(&(*crc as u64).to_le_bytes());
            e[8..8 + sym.len()].copy_from_slice(sym.as_bytes());
            vd.extend_from_slice(&e);
        }
        obj.append_section_data(vers, &vd, 8);

        let text = obj.add_section(vec![], b".text".to_vec(), SectionKind::Text);
        obj.append_section_data(text, &[0xc3; 16], 16);
        obj.add_symbol(Symbol {
            name: b"patched_tcp_fn".to_vec(),
            value: 0,
            size: 1,
            kind: SymbolKind::Text,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
        for s in klp_syms {
            obj.add_symbol(Symbol {
                name: s.as_bytes().to_vec(),
                value: 0,
                size: 0,
                kind: SymbolKind::Text,
                scope: SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Undefined,
                flags: SymbolFlags::None,
            });
        }
        obj.write().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modinfo_versions_klpsyms() {
        let ko = testelf::livepatch_module(
            "klp_hvp_7_3_5_1_p3",
            "7.3.5-1-pve SMP preempt mod_unload modversions ",
            &[("printk", 0xdeadbeef), ("klp_enable_patch", 0x1234)],
            &[".klp.sym.vmlinux.tcp_foo.isra.0,0", ".klp.sym.kvm_amd.svm_bar,2"],
        );
        let mi = parse_modinfo(&ko).unwrap();
        assert_eq!(mi.name(), Some("klp_hvp_7_3_5_1_p3"));
        assert_eq!(mi.vermagic_release(), Some("7.3.5-1-pve"));
        assert!(mi.is_livepatch());
        assert!(!has_module_signature(&ko));

        let v = parse_versions(&ko).unwrap();
        assert_eq!(v, vec![("printk".into(), 0xdeadbeef), ("klp_enable_patch".into(), 0x1234)]);

        let k = klp_symbols(&ko).unwrap();
        assert_eq!(
            k,
            vec![
                KlpSym { object: "kvm_amd".into(), name: "svm_bar".into(), sympos: 2 },
                KlpSym { object: "vmlinux".into(), name: "tcp_foo.isra.0".into(), sympos: 0 },
            ]
        );
    }

    #[test]
    fn build_id_note() {
        let mut n = Vec::new();
        // An unrelated note first.
        n.extend_from_slice(&4u32.to_le_bytes());
        n.extend_from_slice(&4u32.to_le_bytes());
        n.extend_from_slice(&6u32.to_le_bytes());
        n.extend_from_slice(b"Xen\0");
        n.extend_from_slice(&[1, 2, 3, 4]);
        // GNU build-id.
        n.extend_from_slice(&4u32.to_le_bytes());
        n.extend_from_slice(&5u32.to_le_bytes());
        n.extend_from_slice(&3u32.to_le_bytes());
        n.extend_from_slice(b"GNU\0");
        n.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0, 0, 0]);
        assert_eq!(build_id_from_notes(&n).as_deref(), Some("deadbeef01"));
        assert_eq!(build_id_from_notes(&n[..20]), None);
    }

    #[test]
    fn symvers_and_system_map() {
        let sv = parse_symvers(
            "0xdeadbeef\tprintk\tvmlinux\tEXPORT_SYMBOL\t\n0x00001234\tfoo\tkvm\tEXPORT_SYMBOL_GPL\tKVM\n",
        );
        assert_eq!(sv["printk"], 0xdeadbeef);
        assert_eq!(sv["foo"], 0x1234);
        let sm = system_map_counts("ffffffff81000000 T _stext\nffffffff81000010 t helper\nffffffff81000020 t helper\n");
        assert_eq!(sm["helper"], 2);
        assert_eq!(sm["_stext"], 1);
    }
}
