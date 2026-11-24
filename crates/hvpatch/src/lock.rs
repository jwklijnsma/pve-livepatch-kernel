//! Exclusive lock so that the timer, the boot unit and an operator never
//! run a transition at the same time.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{Context, Result, bail};

pub struct Lock {
    _file: File,
}

impl Lock {
    /// Wait up to `wait` for another run to finish (used by the boot unit,
    /// which must not give up just because the timer is running).
    pub fn acquire_wait(path: &Path, wait: std::time::Duration) -> Result<Self> {
        let start = std::time::Instant::now();
        loop {
            match Self::acquire(path) {
                Ok(l) => return Ok(l),
                Err(e) if start.elapsed() >= wait => return Err(e),
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(500)),
            }
        }
    }

    pub fn acquire(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        // SAFETY: valid fd; the lock is released when the file is closed.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("another hvpatch process holds {}", path.display());
        }
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_lock_fails() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("lock");
        let a = Lock::acquire(&p).unwrap();
        assert!(Lock::acquire(&p).is_err());
        assert!(Lock::acquire_wait(&p, std::time::Duration::from_millis(600)).is_err());
        drop(a);
        Lock::acquire(&p).unwrap();
    }
}
