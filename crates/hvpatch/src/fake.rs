//! In-memory emulation of the kernel's livepatch behaviour, used by the
//! test suite. It models what matters for the agent: per-patch
//! transitions, atomic replace, reversal, module refcounts, taint and
//! kernel log output.

use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Result, bail};

use crate::kernel::{BlockingTask, KernelOps, KmsgRecord, KmsgWatch, LoadError, ModuleInfo, PatchInfo, taint};

#[derive(Debug, Clone)]
pub struct FakePatch {
    pub name: String,
    pub enabled: bool,
    pub transition: bool,
    polls_left: u32,
    pub functions: Vec<(String, bool)>,
}

#[derive(Debug)]
pub struct FakeState {
    pub release: String,
    pub build_id: Option<String>,
    pub patches: Vec<FakePatch>,
    pub modules: Vec<ModuleInfo>,
    pub tainted: u64,
    /// Emulate Secure Boot: unsigned modules are rejected.
    pub require_signature: bool,
    /// Polls of `patch()` until a transition completes.
    pub transition_polls: u32,
    /// The enable transition never completes (e.g. a vCPU thread sleeps
    /// in a patched function).
    pub stuck: bool,
    /// The reverse transition never completes either.
    pub reverse_stuck: bool,
    /// Kernel log records emitted by the next module load.
    pub kmsg_on_load: Vec<KmsgRecord>,
    /// Like a real kernel, drop the module reference of a freed patch only
    /// this many `modules()` calls after its sysfs entry disappeared.
    pub put_delay: u32,
    pending_puts: Vec<(String, u32)>,
    pub taint_on_load: u64,
    /// Functions every loaded patch reports in sysfs.
    pub functions_on_load: Vec<(String, bool)>,
    pub blockers: Vec<BlockingTask>,
    /// Functions with kprobes/BPF attached (see KernelOps::traced_functions).
    pub traced: Vec<String>,
    /// Chronological record of mutating calls, for assertions.
    pub calls: Vec<String>,
    pub slept: Duration,
}

pub struct FakeKernel {
    pub st: RefCell<FakeState>,
    kmsg: Rc<RefCell<Vec<KmsgRecord>>>,
}

impl FakeKernel {
    pub fn new(release: &str) -> Self {
        Self {
            st: RefCell::new(FakeState {
                release: release.into(),
                build_id: Some("00112233445566778899aabbccddeeff00112233".into()),
                patches: vec![],
                modules: vec![],
                tainted: taint::PROPRIETARY_MODULE | taint::OOT_MODULE, // ZFS
                require_signature: false,
                transition_polls: 3,
                stuck: false,
                reverse_stuck: false,
                kmsg_on_load: vec![],
                put_delay: 0,
                pending_puts: vec![],
                taint_on_load: 0,
                functions_on_load: vec![("vmlinux:tcp_fix_me,1".into(), true)],
                blockers: vec![],
                traced: vec![],
                calls: vec![],
                slept: Duration::ZERO,
            }),
            kmsg: Rc::new(RefCell::new(vec![])),
        }
    }

    /// A livepatch from another vendor, already active.
    pub fn load_foreign(&self, name: &str) {
        let mut st = self.st.borrow_mut();
        st.modules.push(ModuleInfo { name: name.into(), taint: "K".into(), refcnt: 1 });
        st.patches.push(FakePatch {
            name: name.into(),
            enabled: true,
            transition: false,
            polls_left: 0,
            functions: vec![],
        });
        st.tainted |= taint::LIVEPATCH;
    }

    /// A kernel warning-level log line.
    pub fn log_kmsg(&self, line: &str) {
        self.kmsg.borrow_mut().push(KmsgRecord::kernel(4, line));
    }

    pub fn active(&self) -> Vec<String> {
        self.st.borrow().patches.iter().filter(|p| p.enabled).map(|p| p.name.clone()).collect()
    }

    pub fn loaded(&self) -> Vec<String> {
        self.st.borrow().modules.iter().map(|m| m.name.clone()).collect()
    }

    fn complete(st: &mut FakeState, name: &str) {
        let Some(i) = st.patches.iter().position(|p| p.name == name) else { return };
        let p = &mut st.patches[i];
        p.transition = false;
        if p.enabled {
            // Atomic replace: every other patch is discarded and its module
            // reference dropped.
            let others: Vec<String> = st.patches.iter().filter(|q| q.name != name).map(|q| q.name.clone()).collect();
            st.patches.retain(|q| q.name == name);
            for o in others {
                Self::put(st, &o);
            }
        } else {
            st.patches.remove(i);
            Self::put(st, name);
        }
    }

    fn put(st: &mut FakeState, module: &str) {
        if st.put_delay > 0 {
            let delay = st.put_delay;
            st.pending_puts.push((module.to_owned(), delay));
            return;
        }
        if let Some(m) = st.modules.iter_mut().find(|m| m.name == module) {
            m.refcnt = m.refcnt.saturating_sub(1);
        }
    }

    fn tick_puts(st: &mut FakeState) {
        let mut due = Vec::new();
        for (name, left) in st.pending_puts.iter_mut() {
            *left = left.saturating_sub(1);
            if *left == 0 {
                due.push(name.clone());
            }
        }
        st.pending_puts.retain(|(_, left)| *left > 0);
        for name in due {
            if let Some(m) = st.modules.iter_mut().find(|m| m.name == name) {
                m.refcnt = m.refcnt.saturating_sub(1);
            }
        }
    }
}

impl KernelOps for FakeKernel {
    fn release(&self) -> Result<String> {
        Ok(self.st.borrow().release.clone())
    }

    fn build_id(&self) -> Result<Option<String>> {
        Ok(self.st.borrow().build_id.clone())
    }

    fn livepatches(&self) -> Result<Vec<PatchInfo>> {
        Ok(self
            .st
            .borrow()
            .patches
            .iter()
            .map(|p| PatchInfo { name: p.name.clone(), enabled: p.enabled, transition: p.transition })
            .collect())
    }

    fn patch(&self, name: &str) -> Result<Option<PatchInfo>> {
        let mut st = self.st.borrow_mut();
        let (stuck, reverse_stuck) = (st.stuck, st.reverse_stuck);
        let Some(p) = st.patches.iter_mut().find(|p| p.name == name) else { return Ok(None) };
        if p.transition {
            let blocked = if p.enabled { stuck } else { reverse_stuck };
            if !blocked {
                p.polls_left = p.polls_left.saturating_sub(1);
                if p.polls_left == 0 {
                    Self::complete(&mut st, name);
                }
            }
        }
        Ok(st.patches.iter().find(|p| p.name == name).map(|p| PatchInfo {
            name: p.name.clone(),
            enabled: p.enabled,
            transition: p.transition,
        }))
    }

    fn set_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        let mut st = self.st.borrow_mut();
        st.calls.push(format!("enabled {name}={}", enabled as u8));
        let polls = st.transition_polls;
        let Some(p) = st.patches.iter_mut().find(|p| p.name == name) else { bail!("no such patch {name}") };
        if p.enabled == enabled {
            bail!("write error: Invalid argument");
        }
        p.enabled = enabled;
        p.transition = true;
        p.polls_left = polls;
        Ok(())
    }

    fn patched_functions(&self, name: &str) -> Result<Vec<(String, bool)>> {
        let st = self.st.borrow();
        Ok(st.patches.iter().find(|p| p.name == name).map(|p| p.functions.clone()).unwrap_or_default())
    }

    fn load_module(&self, file: &File) -> Result<(), LoadError> {
        let mut f = file.try_clone().map_err(|e| LoadError::Other(e.to_string()))?;
        let mut bytes = Vec::new();
        f.seek(SeekFrom::Start(0))
            .and_then(|_| f.read_to_end(&mut bytes))
            .map_err(|e| LoadError::Other(e.to_string()))?;
        let info = klp_core::elf::parse_modinfo(&bytes).map_err(|e| LoadError::Format(e.to_string()))?;
        let name = info.name().unwrap_or_default().to_owned();
        let signed = klp_core::elf::has_module_signature(&bytes);
        let mut st = self.st.borrow_mut();
        st.calls.push(format!("load {name}"));
        if st.require_signature && !signed {
            let lines = std::mem::take(&mut st.kmsg_on_load);
            drop(st);
            self.kmsg.borrow_mut().extend(lines);
            return Err(LoadError::Signature("Key was rejected by service".into()));
        }
        if info.vermagic_release() != Some(st.release.as_str()) {
            return Err(LoadError::Format("Exec format error".into()));
        }
        if st.modules.iter().any(|m| m.name == name) {
            return Err(LoadError::AlreadyLoaded);
        }
        let polls = st.transition_polls;
        // klp-build output is an out-of-tree module, like the real thing.
        st.modules.push(ModuleInfo { name: name.clone(), taint: if signed { "OK" } else { "OEK" }.into(), refcnt: 1 });
        st.tainted |= taint::LIVEPATCH | taint::OOT_MODULE | if signed { 0 } else { taint::UNSIGNED_MODULE };
        st.tainted |= st.taint_on_load;
        let functions = st.functions_on_load.clone();
        st.patches.push(FakePatch { name, enabled: true, transition: true, polls_left: polls, functions });
        // Emitted once, by the next load only.
        let lines = std::mem::take(&mut st.kmsg_on_load);
        drop(st);
        self.kmsg.borrow_mut().extend(lines);
        Ok(())
    }

    fn unload_module(&self, name: &str) -> Result<()> {
        let mut st = self.st.borrow_mut();
        st.calls.push(format!("unload {name}"));
        let Some(i) = st.modules.iter().position(|m| m.name == name) else { bail!("{name}: not loaded") };
        if st.modules[i].refcnt > 0 {
            bail!("delete_module({name}): Resource temporarily unavailable");
        }
        st.modules.remove(i);
        Ok(())
    }

    fn modules(&self) -> Result<Vec<ModuleInfo>> {
        let mut st = self.st.borrow_mut();
        Self::tick_puts(&mut st);
        Ok(st.modules.clone())
    }

    fn tainted(&self) -> Result<u64> {
        Ok(self.st.borrow().tainted)
    }

    fn kmsg_watch(&self) -> Result<Box<dyn KmsgWatch>> {
        let pos = self.kmsg.borrow().len();
        Ok(Box::new(FakeKmsg { buf: self.kmsg.clone(), pos }))
    }

    fn blocking_tasks(&self, _target: bool) -> Result<Vec<BlockingTask>> {
        Ok(self.st.borrow().blockers.clone())
    }

    fn traced_functions(&self) -> Result<Vec<String>> {
        Ok(self.st.borrow().traced.clone())
    }

    fn sleep(&self, d: Duration) {
        self.st.borrow_mut().slept += d;
    }
}

struct FakeKmsg {
    buf: Rc<RefCell<Vec<KmsgRecord>>>,
    pos: usize,
}

impl KmsgWatch for FakeKmsg {
    fn drain(&mut self) -> Result<Vec<KmsgRecord>> {
        let b = self.buf.borrow();
        let out = b[self.pos..].to_vec();
        self.pos = b.len();
        Ok(out)
    }
}
