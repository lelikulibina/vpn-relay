//! Ownership-safe Unix control socket lifecycle.

use super::RuntimeError;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

pub(super) struct ControlSocket {
    pub(super) listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl ControlSocket {
    pub(super) fn bind(path: PathBuf) -> Result<Self, RuntimeError> {
        if path.exists() {
            match UnixStream::connect(&path) {
                Ok(_) => {
                    return Err(RuntimeError::Control(format!(
                        "control socket is already accepting connections: {}",
                        path.display()
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    let metadata = fs::symlink_metadata(&path)
                        .map_err(|error| RuntimeError::Control(error.to_string()))?;
                    if !metadata.file_type().is_socket() {
                        return Err(RuntimeError::Control(format!(
                            "refusing to replace non-socket path {}",
                            path.display()
                        )));
                    }
                    fs::remove_file(&path)
                        .map_err(|error| RuntimeError::Control(error.to_string()))?;
                }
                Err(error) => {
                    return Err(RuntimeError::Control(format!(
                        "cannot inspect existing control socket {}: {error}",
                        path.display()
                    )));
                }
            }
        }
        Self::bind_with(path, |path, listener| {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            listener.set_nonblocking(true)
        })
    }

    pub(super) fn bind_with(
        path: PathBuf,
        configure: impl FnOnce(&Path, &UnixListener) -> std::io::Result<()>,
    ) -> Result<Self, RuntimeError> {
        let listener =
            UnixListener::bind(&path).map_err(|error| RuntimeError::Control(error.to_string()))?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| RuntimeError::Control(error.to_string()))?;
        if !metadata.file_type().is_socket() {
            return Err(RuntimeError::Control(format!(
                "control socket path was replaced during bind: {}",
                path.display()
            )));
        }
        let device = metadata.dev();
        let inode = metadata.ino();
        if let Err(error) = configure(&path, &listener) {
            drop(listener);
            remove_owned_socket_path(&path, device, inode);
            return Err(RuntimeError::Control(error.to_string()));
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                drop(listener);
                remove_owned_socket_path(&path, device, inode);
                return Err(RuntimeError::Control(error.to_string()));
            }
        };
        if !metadata.file_type().is_socket() || metadata.dev() != device || metadata.ino() != inode
        {
            return Err(RuntimeError::Control(format!(
                "control socket path changed while being configured: {}",
                path.display()
            )));
        }
        Ok(Self {
            listener,
            path,
            device,
            inode,
        })
    }
}

pub(super) fn remove_owned_socket_path(path: &Path, device: u64, inode: u64) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "failed to inspect control socket before unlink");
            return;
        }
    };
    if !metadata.file_type().is_socket() || metadata.dev() != device || metadata.ino() != inode {
        tracing::warn!(path = %path.display(), "control socket path no longer refers to the daemon-owned socket; refusing to unlink it");
        return;
    }
    if let Err(error) = fs::remove_file(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(path = %path.display(), %error, "failed to remove control socket");
        }
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        remove_owned_socket_path(&self.path, self.device, self.inode);
    }
}

