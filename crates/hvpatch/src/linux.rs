//! Real kernel interface: sysfs, procfs, module syscalls and /dev/kmsg.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::kernel::{BlockingTask, KernelOps, KmsgWatch, LoadError, ModuleInfo, PatchInfo};

pub struct LinuxKernel {
    /// Prefix for /sys, /proc, /dev. `/` in production; a directory tree in
    /// tests of the read-only paths.
    root: PathBuf,
}

impl Default for LinuxKernel {
    fn default() -> Self {
        Self { root: PathBuf::from("/") }
    }
}

impl LinuxKernel {
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.root.join(rel.trim_start_matches('/'))
    }

    fn lp_dir(&self, name: &str) -> PathBuf {
        self.p("/sys/kernel/livepatch").join(name)
    }
}

fn read_trim(p: &Path) -> Result<String> {
    Ok(fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?.trim().to_owned())
}

fn read_bool(p: &Path) -> Result<bool> {
    Ok(read_trim(p)? == "1")
}

impl KernelOps for LinuxKernel {
    fn release(&self) -> Result<String> {
        read_trim(&self.p("/proc/sys/kernel/osrelease"))
    }

    fn build_id(&self) -> Result<Option<String>> {
        match fs::read(self.p("/sys/kernel/notes")) {
            Ok(b) => Ok(klp_core::elf::build_id_from_notes(&b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("reading /sys/kernel/notes"),
        }
    }

    fn livepatches(&self) -> Result<Vec<PatchInfo>> {
        let dir = self.p("/sys/kernel/livepatch");
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e).context("reading /sys/kernel/livepatch"),
        };
        let mut out = Vec::new();
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(p) = self.patch(&name)? {
                out.push(p);
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn patch(&self, name: &str) -> Result<Option<PatchInfo>> {
        let d = self.lp_dir(name);
        // The directory disappears asynchronously after a disable: a missing
        // attribute means "gone". Any other error (EIO, EACCES) is an error,
        // not a finished transition.
        let read = |attr: &str| -> Result<Option<bool>> {
            let p = d.join(attr);
            match fs::read_to_string(&p) {
                Ok(s) => Ok(Some(s.trim() == "1")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
            }
        };
        let (Some(enabled), Some(transition)) = (read("enabled")?, read("transition")?) else {
            return Ok(None);
        };
        Ok(Some(PatchInfo { name: name.to_owned(), enabled, transition }))
    }

    fn patch_replaces(&self, name: &str) -> Result<Option<bool>> {
        match fs::read_to_string(self.lp_dir(name).join("replace")) {
            Ok(s) => Ok(Some(s.trim() == "1")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("reading replace"),
        }
    }

    fn set_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        let p = self.lp_dir(name).join("enabled");
        fs::write(&p, if enabled { "1" } else { "0" }).with_context(|| format!("writing {}", p.display()))
    }

    fn patched_functions(&self, name: &str) -> Result<Vec<(String, bool)>> {
        let mut out = Vec::new();
        for obj in fs::read_dir(self.lp_dir(name))?.flatten() {
            if !obj.file_type()?.is_dir() {
                continue;
            }
            let oname = obj.file_name().to_string_lossy().into_owned();
            let patched = read_bool(&obj.path().join("patched")).unwrap_or(false);
            for f in fs::read_dir(obj.path())?.flatten() {
                if f.file_type()?.is_dir() {
                    out.push((format!("{oname}:{}", f.file_name().to_string_lossy()), patched));
                }
            }
        }
        out.sort();
        Ok(out)
    }

    fn load_module(&self, file: &File) -> Result<(), LoadError> {
        sys::finit_module(file)
    }

    fn unload_module(&self, name: &str) -> Result<()> {
        sys::delete_module(name)
    }

    fn modules(&self) -> Result<Vec<ModuleInfo>> {
        let mut out = Vec::new();
        for e in fs::read_dir(self.p("/sys/module"))?.flatten() {
            let d = e.path();
            // Only loadable modules have refcnt; built-ins have neither.
            let Ok(refcnt) = read_trim(&d.join("refcnt")) else { continue };
            out.push(ModuleInfo {
                name: e.file_name().to_string_lossy().into_owned(),
                taint: read_trim(&d.join("taint")).unwrap_or_default(),
                refcnt: refcnt.parse().unwrap_or(0),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn tainted(&self) -> Result<u64> {
        Ok(read_trim(&self.p("/proc/sys/kernel/tainted"))?.parse()?)
    }

    fn kmsg_watch(&self) -> Result<Box<dyn KmsgWatch>> {
        sys::kmsg_watch(&self.p("/dev/kmsg"))
    }

    fn blocking_tasks(&self, target: bool) -> Result<Vec<BlockingTask>> {
        let want = if target { 1 } else { 0 };
        let mut out = Vec::new();
        for p in fs::read_dir(self.p("/proc"))?.flatten() {
            let Ok(pid) = p.file_name().to_string_lossy().parse::<u32>() else { continue };
            // patch_state is per task, so look at every thread, not only
            // /proc/<pid>/patch_state of the thread group leader.
            let Ok(tasks) = fs::read_dir(p.path().join("task")) else { continue };
            for t in tasks.flatten() {
                let Ok(tid) = t.file_name().to_string_lossy().parse::<u32>() else { continue };
                let Ok(state) = read_trim(&t.path().join("patch_state")) else { continue };
                let Ok(state) = state.parse::<i32>() else { continue };
                if state != -1 && state != want {
                    out.push(BlockingTask {
                        pid,
                        tid,
                        comm: read_trim(&t.path().join("comm")).unwrap_or_default(),
                        stack: fs::read_to_string(t.path().join("stack")).ok(),
                    });
                }
            }
        }
        Ok(out)
    }

    fn traced_functions(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for f in ["/sys/kernel/tracing/enabled_functions", "/sys/kernel/debug/tracing/enabled_functions"] {
            if let Ok(t) = fs::read_to_string(self.p(f)) {
                out.extend(crate::kernel::parse_enabled_functions(&t));
                break;
            }
        }
        if let Ok(t) = fs::read_to_string(self.p("/sys/kernel/debug/kprobes/list")) {
            out.extend(crate::kernel::parse_kprobes_list(&t));
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    fn installed_kernels(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let dir = match fs::read_dir(self.p("/boot")) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e).context("reading /boot"),
        };
        for e in dir.flatten() {
            if let Some(r) = e.file_name().to_str().and_then(|n| n.strip_prefix("vmlinuz-")) {
                out.push(r.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d)
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use std::ffi::CString;
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::path::Path;

    use anyhow::{Context, Result, bail};

    use crate::kernel::{KmsgRecord, KmsgWatch, LoadError};

    pub fn finit_module(file: &File) -> Result<(), LoadError> {
        let params = c"";
        // SAFETY: valid fd and NUL-terminated parameter string.
        let rc = unsafe { libc::syscall(libc::SYS_finit_module, file.as_raw_fd(), params.as_ptr(), 0) };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        let msg = err.to_string();
        Err(match err.raw_os_error().unwrap_or(0) {
            libc::ENOKEY | libc::EKEYREJECTED | libc::EKEYEXPIRED | libc::EBADMSG => LoadError::Signature(msg),
            libc::EEXIST => LoadError::AlreadyLoaded,
            libc::EPERM => LoadError::NotPermitted(msg),
            libc::ENOEXEC => LoadError::Format(msg),
            _ => LoadError::Other(msg),
        })
    }

    pub fn delete_module(name: &str) -> Result<()> {
        let c = CString::new(name)?;
        // SAFETY: NUL-terminated name; O_NONBLOCK never waits for refcount.
        let rc = unsafe { libc::syscall(libc::SYS_delete_module, c.as_ptr(), libc::O_NONBLOCK) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            bail!("delete_module({name}): {err}");
        }
        Ok(())
    }

    struct Kmsg {
        file: File,
    }

    impl KmsgWatch for Kmsg {
        fn drain(&mut self) -> Result<Vec<KmsgRecord>> {
            use std::io::Read;
            let mut out = Vec::new();
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match self.file.read(&mut buf) {
                    Ok(0) => break,
                    // One read() returns exactly one record:
                    // "prio,seq,timestamp,flags;message\n" plus continuation lines.
                    Ok(n) => {
                        if let Some(r) = KmsgRecord::parse(&String::from_utf8_lossy(&buf[..n])) {
                            out.push(r);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    // EPIPE: records were overwritten; the next read continues.
                    Err(e) if e.raw_os_error() == Some(libc::EPIPE) => continue,
                    Err(e) => return Err(e).context("reading /dev/kmsg"),
                }
            }
            Ok(out)
        }
    }

    pub fn kmsg_watch(path: &Path) -> Result<Box<dyn KmsgWatch>> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        // SAFETY: valid fd. SEEK_END on /dev/kmsg skips existing records.
        if unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_END) } < 0 {
            bail!("seeking /dev/kmsg: {}", std::io::Error::last_os_error());
        }
        Ok(Box::new(Kmsg { file }))
    }
}

#[cfg(not(target_os = "linux"))]
mod sys {
    use std::fs::File;
    use std::path::Path;

    use anyhow::{Result, bail};

    use crate::kernel::{KmsgWatch, LoadError};

    pub fn finit_module(_: &File) -> Result<(), LoadError> {
        Err(LoadError::Other("module loading is only supported on Linux".into()))
    }

    pub fn delete_module(_: &str) -> Result<()> {
        bail!("module unloading is only supported on Linux")
    }

    pub fn kmsg_watch(_: &Path) -> Result<Box<dyn KmsgWatch>> {
        bail!("/dev/kmsg is only available on Linux")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_sysfs_and_procfs_tree() {
        let t = tempfile::tempdir().unwrap();
        let w = |rel: &str, s: &str| {
            let p = t.path().join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, s).unwrap();
        };
        w("proc/sys/kernel/osrelease", "7.3.5-1-pve\n");
        w("proc/sys/kernel/tainted", "36865\n");
        w("sys/kernel/livepatch/klp_hvp_7_3_5_1_p3/enabled", "1\n");
        w("sys/kernel/livepatch/klp_hvp_7_3_5_1_p3/transition", "0\n");
        w("sys/kernel/livepatch/klp_hvp_7_3_5_1_p3/vmlinux/patched", "1\n");
        fs::create_dir_all(t.path().join("sys/kernel/livepatch/klp_hvp_7_3_5_1_p3/vmlinux/tcp_foo,1")).unwrap();
        w("sys/module/klp_hvp_7_3_5_1_p3/refcnt", "0\n");
        w("sys/module/klp_hvp_7_3_5_1_p3/taint", "K\n");
        w("sys/module/zfs/refcnt", "12\n");
        w("sys/module/zfs/taint", "PO\n");
        fs::create_dir_all(t.path().join("sys/module/printk")).unwrap();
        w("proc/42/task/42/patch_state", "1\n");
        w("proc/42/task/43/patch_state", "0\n");
        w("proc/42/task/43/comm", "CPU 0/KVM\n");
        w("proc/7/task/7/patch_state", "-1\n");

        let k = LinuxKernel::with_root(t.path());
        assert_eq!(k.release().unwrap(), "7.3.5-1-pve");
        assert_eq!(k.tainted().unwrap(), 36865);
        assert_eq!(k.build_id().unwrap(), None);
        assert_eq!(
            k.livepatches().unwrap(),
            vec![PatchInfo { name: "klp_hvp_7_3_5_1_p3".into(), enabled: true, transition: false }]
        );
        assert_eq!(k.patched_functions("klp_hvp_7_3_5_1_p3").unwrap(), vec![("vmlinux:tcp_foo,1".into(), true)]);
        let mods = k.modules().unwrap();
        assert_eq!(mods.len(), 2);
        assert!(mods[0].is_livepatch());
        let blockers = k.blocking_tasks(true).unwrap();
        assert_eq!(blockers.len(), 1);
        assert_eq!((blockers[0].tid, blockers[0].comm.as_str()), (43, "CPU 0/KVM"));
        assert_eq!(k.patch("gone").unwrap(), None);
    }
}
