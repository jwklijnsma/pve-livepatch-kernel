//! One node per Proxmox VE cluster at a time.
//!
//! pmxcfs (`/etc/pve`) is replicated to every cluster node. Proxmox uses
//! directories below `/etc/pve/priv/lock/` as cluster-wide locks: `mkdir` is
//! atomic across the cluster, and pmxcfs expires a lock that is not
//! refreshed (its mtime updated) for about two minutes, so a crashed holder
//! does not block the cluster forever. Without quorum `/etc/pve` is
//! read-only and the lock cannot be taken.
//!
//! On a host without `/etc/pve` (not a PVE node, or tests) the lock is a
//! no-op.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

pub const LOCK_NAME: &str = "hvpatch-load";

pub struct ClusterLock {
    path: PathBuf,
    last_refresh: Instant,
}

/// How often the holder refreshes the lock (pmxcfs expires it at ~120 s).
const REFRESH_EVERY: Duration = Duration::from_secs(30);

impl ClusterLock {
    /// Try to take the lock once. `Ok(None)`: another node holds it.
    pub fn try_acquire(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(LOCK_NAME);
        match std::fs::create_dir(&path) {
            Ok(()) => Ok(Some(Self { path, last_refresh: Instant::now() })),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => bail!(
                "cannot take the cluster lock {}: {e}. Without quorum /etc/pve is read-only; \
                 hvpatch does not load livepatches on a node that is not part of a quorate cluster \
                 (set cluster_lock = false to override)",
                path.display()
            ),
        }
    }

    /// Keep pmxcfs from expiring the lock during a long transition.
    pub fn refresh(&mut self) {
        if self.last_refresh.elapsed() < REFRESH_EVERY {
            return;
        }
        if let Ok(d) = std::fs::File::open(&self.path) {
            let _ = d.set_modified(std::time::SystemTime::now());
        }
        self.last_refresh = Instant::now();
    }

    pub fn holder_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ClusterLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_holder() {
        let t = tempfile::tempdir().unwrap();
        let a = ClusterLock::try_acquire(t.path()).unwrap().unwrap();
        assert!(ClusterLock::try_acquire(t.path()).unwrap().is_none());
        drop(a);
        assert!(ClusterLock::try_acquire(t.path()).unwrap().is_some());
    }

    #[test]
    fn read_only_cluster_fs_is_an_error() {
        let t = tempfile::tempdir().unwrap();
        let missing = t.path().join("no/such/dir");
        assert!(ClusterLock::try_acquire(&missing).is_err());
    }
}
