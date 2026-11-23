//! Abstraction over the kernel interfaces the agent touches.
//!
//! [`crate::linux::LinuxKernel`] is the real implementation (sysfs, procfs,
//! `finit_module`, `delete_module`, `/dev/kmsg`); [`crate::fake::FakeKernel`]
//! emulates the livepatch semantics for tests.

use std::fs::File;
use std::time::Duration;

use anyhow::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchInfo {
    /// Directory name below /sys/kernel/livepatch (= module name).
    pub name: String,
    pub enabled: bool,
    pub transition: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    pub name: String,
    /// Content of /sys/module/<m>/taint, e.g. "K" or "OE".
    pub taint: String,
    pub refcnt: u32,
}

impl ModuleInfo {
    pub fn is_livepatch(&self) -> bool {
        self.taint.contains('K')
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockingTask {
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    pub stack: Option<String>,
}

impl std::fmt::Display for BlockingTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (pid {} tid {})", self.comm, self.pid, self.tid)?;
        if let Some(s) = &self.stack {
            for l in s.lines().take(8) {
                write!(f, "\n      {l}")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(
        "the kernel rejected the module signature ({0}). With Secure Boot the signing certificate must be enrolled as MOK: `pve-klp mok enroll`"
    )]
    Signature(String),
    #[error("a module with this name is already loaded")]
    AlreadyLoaded,
    #[error("module loading is not permitted ({0}); check kernel.modules_disabled and lockdown")]
    NotPermitted(String),
    #[error("the kernel rejected the module format ({0}); vermagic or modversions do not match the running kernel")]
    Format(String),
    #[error("loading the module failed: {0}")]
    Other(String),
}

/// Reads kernel log records that appeared after the watch was created.
pub trait KmsgWatch {
    fn drain(&mut self) -> Result<Vec<String>>;
}

pub trait KernelOps {
    /// `uname -r`
    fn release(&self) -> Result<String>;
    /// GNU build-id of the running vmlinux, if the kernel exposes it.
    fn build_id(&self) -> Result<Option<String>>;
    fn livepatches(&self) -> Result<Vec<PatchInfo>>;
    /// `None` once the patch is gone from sysfs.
    fn patch(&self, name: &str) -> Result<Option<PatchInfo>>;
    fn set_enabled(&self, name: &str, enabled: bool) -> Result<()>;
    /// Patched functions as `object:function,sympos` and whether the
    /// object is currently patched (`false` for modules not loaded).
    fn patched_functions(&self, name: &str) -> Result<Vec<(String, bool)>>;
    fn load_module(&self, file: &File) -> std::result::Result<(), LoadError>;
    fn unload_module(&self, name: &str) -> Result<()>;
    fn modules(&self) -> Result<Vec<ModuleInfo>>;
    fn tainted(&self) -> Result<u64>;
    fn kmsg_watch(&self) -> Result<Box<dyn KmsgWatch>>;
    /// Tasks whose patch_state is not yet `target` (1 = patched,
    /// 0 = unpatched) during a transition.
    fn blocking_tasks(&self, target: bool) -> Result<Vec<BlockingTask>>;
    fn sleep(&self, d: Duration);
}

/// Taint bits (include/linux/panic.h).
pub mod taint {
    pub const PROPRIETARY_MODULE: u64 = 1 << 0;
    pub const DIE: u64 = 1 << 7;
    pub const WARN: u64 = 1 << 9;
    pub const OOT_MODULE: u64 = 1 << 12;
    pub const UNSIGNED_MODULE: u64 = 1 << 13;
    pub const SOFTLOCKUP: u64 = 1 << 14;
    pub const LIVEPATCH: u64 = 1 << 15;

    /// Taints a livepatch load always adds, even if the module's own
    /// taint cannot be read.
    pub const EXPECTED: u64 = LIVEPATCH | UNSIGNED_MODULE;

    const LETTERS: &[(u64, char)] = &[
        (1 << 0, 'P'),
        (1 << 1, 'F'),
        (1 << 2, 'S'),
        (1 << 3, 'R'),
        (1 << 4, 'M'),
        (1 << 5, 'B'),
        (1 << 6, 'U'),
        (1 << 7, 'D'),
        (1 << 8, 'A'),
        (1 << 9, 'W'),
        (1 << 10, 'C'),
        (1 << 11, 'I'),
        (1 << 12, 'O'),
        (1 << 13, 'E'),
        (1 << 14, 'L'),
        (1 << 15, 'K'),
        (1 << 16, 'X'),
        (1 << 17, 'T'),
        (1 << 18, 'N'),
    ];

    pub fn letters(bits: u64) -> String {
        LETTERS.iter().filter(|(b, _)| bits & b != 0).map(|(_, c)| *c).collect()
    }

    /// Bits for a taint string like `/sys/module/<m>/taint` ("OEK").
    pub fn from_letters(s: &str) -> u64 {
        s.chars().filter_map(|c| LETTERS.iter().find(|(_, l)| *l == c).map(|(b, _)| *b)).fold(0, |a, b| a | b)
    }

    /// Module-level taints a livepatch module may legitimately carry:
    /// klp-build output is always an out-of-tree module (O), is a
    /// livepatch (K) and is unsigned for the kernel unless its certificate
    /// is trusted (E).
    pub const MODULE_ATTRIBUTABLE: u64 = OOT_MODULE | UNSIGNED_MODULE | LIVEPATCH;
}

/// Kernel log lines that make a freshly loaded patch suspicious.
pub fn is_bad_kmsg(line: &str) -> bool {
    const PATTERNS: &[&str] = &[
        "Oops",
        "BUG:",
        "WARNING:",
        "general protection fault",
        "Kernel panic",
        "soft lockup",
        "hard LOCKUP",
        "rcu_sched self-detected stall",
        "rcu: INFO:",
        "livepatch: failed",
        "Call Trace:",
    ];
    PATTERNS.iter().any(|p| line.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taint_letters() {
        assert_eq!(taint::letters(taint::LIVEPATCH | taint::OOT_MODULE | taint::PROPRIETARY_MODULE), "POK");
        assert_eq!(taint::from_letters("OEK"), taint::OOT_MODULE | taint::UNSIGNED_MODULE | taint::LIVEPATCH);
        assert_eq!(taint::from_letters(""), 0);
    }

    #[test]
    fn bad_kmsg() {
        assert!(is_bad_kmsg("BUG: kernel NULL pointer dereference, address: 0000000000000000"));
        assert!(is_bad_kmsg("WARNING: CPU: 3 PID: 1 at kernel/livepatch/core.c:123"));
        assert!(!is_bad_kmsg("livepatch: enabling patch 'klp_pve_7_3_5_1_p3'"));
    }
}
