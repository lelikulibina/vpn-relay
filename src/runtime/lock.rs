use super::RuntimeError;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(super) struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    /// Key the lock by the current network namespace inode. This allows
    /// independent daemons in separate namespaces while preventing duplicate
    /// instances inside the same namespace.
    pub(super) fn path_for_netns_inode(inode: u64) -> PathBuf {
        PathBuf::from(format!("/run/vpn-relay-netns-{inode}.lock"))
    }

    pub(super) fn current_netns_path() -> Result<PathBuf, RuntimeError> {
        let metadata = std::fs::metadata("/proc/self/ns/net")
            .map_err(|error| RuntimeError::InstanceLock(error.to_string()))?;
        Ok(Self::path_for_netns_inode(metadata.ino()))
    }

    pub(super) fn current_control_path() -> Result<PathBuf, RuntimeError> {
        let lock_path = Self::current_netns_path()?;
        Ok(lock_path.with_extension("sock"))
    }

    pub(super) fn current_conntrack_mark_state_path() -> Result<PathBuf, RuntimeError> {
        let lock_path = Self::current_netns_path()?;
        Ok(lock_path.with_extension("marks"))
    }

    pub(super) fn current_forwarding_state_path() -> Result<PathBuf, RuntimeError> {
        let lock_path = Self::current_netns_path()?;
        Ok(lock_path.with_extension("forwarding"))
    }

    pub(super) fn current_netns_inode() -> Result<u64, RuntimeError> {
        std::fs::metadata("/proc/self/ns/net")
            .map(|metadata| metadata.ino())
            .map_err(|error| RuntimeError::InstanceLock(error.to_string()))
    }

    pub(super) fn acquire(path: &Path) -> Result<Self, RuntimeError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|error| RuntimeError::InstanceLock(error.to_string()))?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(RuntimeError::AlreadyRunning(path.display().to_string()));
            }
            return Err(RuntimeError::InstanceLock(error.to_string()));
        }
        Ok(Self { _file: file })
    }
}
