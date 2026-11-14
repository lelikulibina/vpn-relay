use super::api::{
    ControlApi, ControlError, ControlErrorKind, ControlRequest, ControlResponse, InterfaceStats,
};
use super::dispatch;
use super::ControlTransport;
use crate::config::PeerConfig;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) struct ControlSocket {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl ControlSocket {
    pub(crate) fn bind(path: PathBuf) -> Result<Self, ControlError> {
        if path.exists() {
            match UnixStream::connect(&path) {
                Ok(_) => {
                    return Err(ControlError::new(
                        ControlErrorKind::Conflict,
                        format!(
                            "control socket is already accepting connections: {}",
                            path.display()
                        ),
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    let metadata = fs::symlink_metadata(&path).map_err(|error| {
                        ControlError::new(ControlErrorKind::Internal, error.to_string())
                    })?;
                    if !metadata.file_type().is_socket() {
                        return Err(ControlError::new(
                            ControlErrorKind::Conflict,
                            format!("refusing to replace non-socket path {}", path.display()),
                        ));
                    }
                    fs::remove_file(&path).map_err(|error| {
                        ControlError::new(ControlErrorKind::Internal, error.to_string())
                    })?;
                }
                Err(error) => {
                    return Err(ControlError::new(
                        ControlErrorKind::Conflict,
                        format!(
                            "cannot inspect existing control socket {}: {error}",
                            path.display()
                        ),
                    ));
                }
            }
        }

        Self::bind_with(path, |path, listener| {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            listener.set_nonblocking(true)
        })
    }

    pub(crate) fn bind_with(
        path: PathBuf,
        configure: impl FnOnce(&Path, &UnixListener) -> std::io::Result<()>,
    ) -> Result<Self, ControlError> {
        let listener = UnixListener::bind(&path)
            .map_err(|error| ControlError::new(ControlErrorKind::Internal, error.to_string()))?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| ControlError::new(ControlErrorKind::Internal, error.to_string()))?;
        if !metadata.file_type().is_socket() {
            return Err(ControlError::new(
                ControlErrorKind::Conflict,
                format!(
                    "control socket path was replaced during bind: {}",
                    path.display()
                ),
            ));
        }
        let device = metadata.dev();
        let inode = metadata.ino();
        if let Err(error) = configure(&path, &listener) {
            drop(listener);
            remove_owned_socket_path(&path, device, inode);
            return Err(ControlError::new(
                ControlErrorKind::Internal,
                error.to_string(),
            ));
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                drop(listener);
                remove_owned_socket_path(&path, device, inode);
                return Err(ControlError::new(
                    ControlErrorKind::Internal,
                    error.to_string(),
                ));
            }
        };
        if !metadata.file_type().is_socket() || metadata.dev() != device || metadata.ino() != inode
        {
            return Err(ControlError::new(
                ControlErrorKind::Conflict,
                format!(
                    "control socket path changed while being configured: {}",
                    path.display()
                ),
            ));
        }
        Ok(Self {
            listener,
            path,
            device,
            inode,
        })
    }
}

fn remove_owned_socket_path(path: &Path, device: u64, inode: u64) {
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

/// Server-side Unix domain socket transport.
pub struct UnixTransport {
    socket: ControlSocket,
}

impl UnixTransport {
    pub fn bind(path: PathBuf) -> Result<Self, ControlError> {
        Ok(Self {
            socket: ControlSocket::bind(path)?,
        })
    }

    fn handle_connection(&self, mut stream: UnixStream, api: &mut dyn ControlApi) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut payload = Vec::new();
        let response = match (&mut stream)
            .take(1024 * 1024 + 1)
            .read_to_end(&mut payload)
        {
            Ok(_) if payload.len() > 1024 * 1024 => {
                dispatch::invalid_request("request exceeds 1 MiB limit")
            }
            Ok(_) => match serde_json::from_slice::<ControlRequest>(&payload) {
                Ok(request) => dispatch::handle(api, request),
                Err(error) => {
                    dispatch::invalid_request(format!("invalid control request: {error}"))
                },
            },
            Err(error) => {
                dispatch::invalid_request(format!("failed to read control request: {error}"))
            },
        };

        let write_result = serde_json::to_vec(&response)
            .map_err(|error| error.to_string())
            .and_then(|payload| {
                stream
                    .write_all(&payload)
                    .map_err(|error| error.to_string())
            });
        if let Err(error) = write_result {
            tracing::warn!(%error, "failed to send control response");
        }
    }
}

impl ControlTransport for UnixTransport {
    fn poll(&mut self, api: &mut dyn ControlApi) {
        if api.is_fatal() {
            return;
        }
        loop {
            match self.socket.listener.accept() {
                Ok((stream, _)) => {
                    self.handle_connection(stream, api);
                    if api.is_fatal() {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    tracing::warn!(%error, "failed to accept control connection");
                    break;
                }
            }
        }
    }
}

/// Client helper for the Unix transport. Runtime wrappers preserve the old public API.
pub struct UnixClient;

impl UnixClient {
    pub(crate) fn send(
        path: &Path,
        request: ControlRequest,
    ) -> Result<ControlResponse, ControlError> {
        let mut stream = UnixStream::connect(path)
            .map_err(|error| ControlError::new(ControlErrorKind::Unavailable, error.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(300)))
            .map_err(|error| ControlError::new(ControlErrorKind::Unavailable, error.to_string()))?;
        serde_json::to_writer(&mut stream, &request)
            .map_err(|error| ControlError::new(ControlErrorKind::Internal, error.to_string()))?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|error| ControlError::new(ControlErrorKind::Unavailable, error.to_string()))?;
        let mut response = Vec::new();
        (&mut stream)
            .take(4 * 1024 * 1024)
            .read_to_end(&mut response)
            .map_err(|error| ControlError::new(ControlErrorKind::Unavailable, error.to_string()))?;
        let response: ControlResponse = serde_json::from_slice(&response)
            .map_err(|error| ControlError::new(ControlErrorKind::Internal, error.to_string()))?;
        if response.ok {
            Ok(response)
        } else {
            Err(ControlError::new(
                response.error_kind.unwrap_or(ControlErrorKind::Internal),
                response
                    .error
                    .unwrap_or_else(|| "daemon rejected request".to_owned()),
            ))
        }
    }

    pub(crate) fn request_stats(path: &Path) -> Result<Vec<InterfaceStats>, ControlError> {
        Self::send(path, ControlRequest::GetStats)?
            .stats
            .ok_or_else(|| {
                ControlError::new(ControlErrorKind::Internal, "daemon returned no statistics")
            })
    }

    pub(crate) fn replace_peers(
        path: &Path,
        interface: String,
        peers: Vec<PeerConfig>,
    ) -> Result<(), ControlError> {
        Self::send(path, ControlRequest::ReplacePeers { interface, peers }).map(|_| ())
    }

    pub(crate) fn reload_config(path: &Path, toml: String) -> Result<(), ControlError> {
        Self::send(path, ControlRequest::ReloadConfig { toml }).map(|_| ())
    }
}
