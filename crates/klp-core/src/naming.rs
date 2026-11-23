//! Module naming and version comparison.

/// Prefix of every module this project builds. The agent only ever touches
/// livepatches with this prefix.
pub const MODULE_PREFIX: &str = "klp_pve_";

/// `MODULE_NAME_LEN` is `64 - sizeof(unsigned long)` on 64-bit kernels.
pub const MODULE_NAME_MAX: usize = 55;

/// Module name for a kernel release and level, e.g.
/// `7.3.5-1-pve`, 3 -> `klp_pve_7_3_5_1_p3`.
///
/// Every level gets a distinct name: a module with the same name cannot be
/// loaded twice, and atomic replace needs the new module loaded while the old
/// one is still active.
pub fn module_name(kernel_release: &str, level: u32) -> String {
    let base = kernel_release.strip_suffix("-pve").unwrap_or(kernel_release);
    let tag: String = base.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    format!("{MODULE_PREFIX}{tag}_p{level}")
}

/// Extract the level from a module name produced by [`module_name`].
pub fn level_from_module_name(name: &str) -> Option<u32> {
    if !name.starts_with(MODULE_PREFIX) {
        return None;
    }
    let (_, lvl) = name.rsplit_once("_p")?;
    lvl.parse().ok()
}

pub fn is_valid_module_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MODULE_NAME_MAX && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The kernel normalizes `-` to `_` in module names.
pub fn normalize_module_name(name: &str) -> String {
    name.replace('-', "_")
}

/// Package version of a Proxmox kernel release: `7.3.5-1-pve` -> `7.3.5-1`.
pub fn package_version(kernel_release: &str) -> &str {
    kernel_release.strip_suffix("-pve").unwrap_or(kernel_release)
}

/// Compare Proxmox kernel package versions like `7.3.5-1` and `7.3.10-2`
/// numerically, segment by segment.
pub fn cmp_version(a: &str, b: &str) -> std::cmp::Ordering {
    fn parts(s: &str) -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse().unwrap_or(u64::MAX))
            .collect()
    }
    parts(a).cmp(&parts(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    #[test]
    fn names() {
        assert_eq!(module_name("7.3.5-1-pve", 3), "klp_pve_7_3_5_1_p3");
        assert_eq!(level_from_module_name("klp_pve_7_3_5_1_p3"), Some(3));
        assert_eq!(level_from_module_name("livepatch_foo"), None);
        assert!(is_valid_module_name(&module_name("7.3.15-12-pve", 1234)));
    }

    #[test]
    fn versions() {
        assert_eq!(cmp_version("7.3.5-1", "7.3.10-1"), Less);
        assert_eq!(cmp_version("7.3.5-2", "7.3.5-1"), Greater);
        assert_eq!(cmp_version("7.3.5-1", "7.3.5-1"), Equal);
        assert_eq!(package_version("7.3.5-1-pve"), "7.3.5-1");
    }
}
