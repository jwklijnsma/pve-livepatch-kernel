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
        "the kernel rejected the module signature ({0}). With Secure Boot the signing certificate must be enrolled as MOK: `hvpatch mok enroll`"
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

/// One record of the kernel log (`/dev/kmsg`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsgRecord {
    /// Syslog facility: 0 is the kernel, everything else came from user
    /// space via /dev/kmsg.
    pub facility: u8,
    /// Syslog level: 0 emerg .. 4 warning .. 6 info, 7 debug.
    pub level: u8,
    pub msg: String,
}

impl KmsgRecord {
    pub fn kernel(level: u8, msg: impl Into<String>) -> Self {
        Self { facility: 0, level, msg: msg.into() }
    }

    /// Parse the header of a /dev/kmsg record: "prio,seq,usec,flags;message".
    /// `prio` is `facility * 8 + level`. Only the first message line is kept.
    pub fn parse(record: &str) -> Option<Self> {
        let (head, msg) = record.split_once(';')?;
        let prio: u32 = head.split(',').next()?.trim().parse().ok()?;
        Some(Self {
            facility: u8::try_from(prio >> 3).unwrap_or(u8::MAX),
            level: (prio & 7) as u8,
            msg: msg.lines().next().unwrap_or_default().to_owned(),
        })
    }
}

/// Reads kernel log records that appeared after the watch was created.
pub trait KmsgWatch {
    fn drain(&mut self) -> Result<Vec<KmsgRecord>>;
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
    /// Functions that kprobes or ftrace users other than livepatch (BPF
    /// trampolines, function tracers) are attached to. Best effort: empty
    /// if tracefs/debugfs is not mounted.
    fn traced_functions(&self) -> Result<Vec<String>>;
    fn sleep(&self, d: Duration);
}

/// Parse `/sys/kernel/tracing/enabled_functions`: one function per line,
/// followed by flags and the attached ops. Lines whose only user is the
/// livepatch handler are ours (a previous level) and do not conflict.
pub fn parse_enabled_functions(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !l.contains("klp_ftrace_handler"))
        .filter_map(|l| l.split_whitespace().next())
        .map(|f| f.split_once('.').map(|(a, _)| a).unwrap_or(f).to_owned())
        .collect()
}

/// Parse `/sys/kernel/debug/kprobes/list`: "addr  k  function+offset ...".
pub fn parse_kprobes_list(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().nth(2))
        .map(|f| f.split('+').next().unwrap_or(f).to_owned())
        .collect()
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

/// Kernel log records that make a freshly loaded patch suspicious.
///
/// Only records the kernel itself logged (facility 0) at warning or worse
/// count, and only when the message *starts* with a known marker. Lines
/// like "traps: foo[123] general protection fault" (info level, a crashing
/// user process) or a process named "BUG:" that segfaults must not back a
/// patch out: any tenant could trigger that. Taint flags (W, D, L) remain
/// the primary signal; this catches what does not taint, like RCU stalls.
pub fn is_bad_kmsg(r: &KmsgRecord) -> bool {
    const PREFIXES: &[&str] = &[
        "BUG: ",
        "Oops",
        "WARNING: CPU:",
        "WARNING: at ",
        "general protection fault",
        "Kernel panic",
        "watchdog: BUG: soft lockup",
        "watchdog: Watchdog detected hard LOCKUP",
        "rcu: INFO: rcu_",
        "INFO: rcu_",
    ];
    if r.facility != 0 || r.level > 4 {
        return false;
    }
    let m = r.msg.trim_start();
    PREFIXES.iter().any(|p| m.starts_with(p)) || (m.starts_with("livepatch: ") && r.level <= 3)
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
        let k = |level, m: &str| KmsgRecord::kernel(level, m);
        assert!(is_bad_kmsg(&k(1, "BUG: kernel NULL pointer dereference, address: 0000000000000000")));
        assert!(is_bad_kmsg(&k(4, "WARNING: CPU: 3 PID: 1 at kernel/livepatch/core.c:123 foo+0x1/0x2")));
        assert!(is_bad_kmsg(&k(3, "rcu: INFO: rcu_preempt self-detected stall on CPU")));
        assert!(is_bad_kmsg(&k(3, "livepatch: failed to enable patch 'x'")));
        assert!(!is_bad_kmsg(&k(6, "livepatch: enabling patch 'klp_hvp_7_3_5_1_p3'")));
        // A crashing user process (info level) and a tenant naming its
        // process "BUG:" must not count.
        assert!(!is_bad_kmsg(&k(6, "traps: foo[123] general protection fault ip:7f0 sp:7ff error:0 in libc.so")));
        assert!(!is_bad_kmsg(&k(6, "BUG:[4242]: segfault at 0 ip 0000 sp 0000 error 6")));
        // Messages written into /dev/kmsg from user space (facility != 0).
        assert!(!is_bad_kmsg(&KmsgRecord { facility: 1, level: 0, msg: "BUG: fake".into() }));
        // Not anchored: a marker in the middle of a message.
        assert!(!is_bad_kmsg(&k(4, "eth0: link flapping, see BUG: 123 in vendor tracker")));
    }

    #[test]
    fn traced_function_parsing() {
        let ef = "tcp_v4_rcv (1)   R  I    tramp: 0xffffffffc0201000 (bpf_trampoline_6442+0x0/0x60) ->bpf_trampoline\n\
                  gup_fast_fallback (1)  R I  tramp: 0xffffffffc0300000 (klp_ftrace_handler+0x0/0x1d0) ->klp_ftrace_handler\n\
                  ovl_fileattr_set.cold (1)\n";
        assert_eq!(parse_enabled_functions(ef), vec!["tcp_v4_rcv", "ovl_fileattr_set"]);
        let kp =
            "ffffffff8143a2c0  k  do_sys_openat2+0x0    [FTRACE]\nffffffff81a00000  r  tcp_sendmsg+0x0    [FTRACE]\n";
        assert_eq!(parse_kprobes_list(kp), vec!["do_sys_openat2", "tcp_sendmsg"]);
    }

    #[test]
    fn kmsg_record_parsing() {
        let r = KmsgRecord::parse("4,1234,5678901,-;WARNING: CPU: 0 PID: 1 at x\n SUBSYSTEM=foo").unwrap();
        assert_eq!((r.facility, r.level), (0, 4));
        assert!(r.msg.starts_with("WARNING: CPU: 0"));
        // facility 1 (user), level 6
        let r = KmsgRecord::parse("14,1,2,-;hello").unwrap();
        assert_eq!((r.facility, r.level, r.msg.as_str()), (1, 6, "hello"));
        assert!(KmsgRecord::parse("garbage").is_none());
    }
}
