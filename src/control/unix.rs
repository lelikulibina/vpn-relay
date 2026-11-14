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

const MAX_REQUEST_SIZE: usize = 1024 * 1024;
const MAX_RESPONSE_SIZE: usize = 4 * 1024 * 1024;

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
            .take(MAX_REQUEST_SIZE as u64 + 1)
            .read_to_end(&mut payload)
        {
            Ok(_) if payload.len() > MAX_REQUEST_SIZE => {
                dispatch::invalid_request("request exceeds 1 MiB limit")
            }
            Ok(_) => match serde_json::from_slice::<ControlRequest>(&payload) {
                Ok(request) => dispatch::handle(api, request),
                Err(error) => {
                    dispatch::invalid_request(format!("invalid control request: {error}"))
                }
            },
            Err(error) => {
                dispatch::transport_unavailable(format!("failed to read control request: {error}"))
            }
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
        let payload = serde_json::to_vec(&request)
            .map_err(|error| ControlError::new(ControlErrorKind::Internal, error.to_string()))?;
        if payload.len() > MAX_REQUEST_SIZE {
            return Err(ControlError::new(
                ControlErrorKind::InvalidRequest,
                "request exceeds 1 MiB limit",
            ));
        }
        let mut stream = UnixStream::connect(path)
            .map_err(|error| ControlError::new(ControlErrorKind::Unavailable, error.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(300)))
            .map_err(|error| ControlError::new(ControlErrorKind::Unavailable, error.to_string()))?;
        stream
            .write_all(&payload)
            .map_err(|error| ControlError::new(ControlErrorKind::Unavailable, error.to_string()))?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|error| ControlError::new(ControlErrorKind::Unavailable, error.to_string()))?;
        let mut response = Vec::new();
        (&mut stream)
            .take(MAX_RESPONSE_SIZE as u64 + 1)
            .read_to_end(&mut response)
            .map_err(|error| ControlError::new(ControlErrorKind::Unavailable, error.to_string()))?;
        if response.len() > MAX_RESPONSE_SIZE {
            return Err(ControlError::new(
                ControlErrorKind::Internal,
                "daemon response exceeds 4 MiB limit",
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{Read, Write};

    #[derive(Default)]
    struct MockApi {
        fatal: bool,
        stats_calls: Cell<usize>,
    }

    impl ControlApi for MockApi {
        fn get_stats(&self) -> Result<Vec<InterfaceStats>, ControlError> {
            self.stats_calls.set(self.stats_calls.get() + 1);
            Ok(Vec::new())
        }

        fn replace_peers(
            &mut self,
            _interface: &str,
            _peers: Vec<PeerConfig>,
        ) -> Result<(), ControlError> {
            self.fatal = true;
            Ok(())
        }

        fn reload_config(&mut self, _toml: &str) -> Result<(), ControlError> {
            Ok(())
        }

        fn is_fatal(&self) -> bool {
            self.fatal
        }
    }

    fn socket_path(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vpn-relay-control-{label}-{}-{nonce}.sock",
            std::process::id()
        ))
    }

    #[test]
    fn client_accepts_legacy_error_response_without_error_kind() {
        let path = socket_path("legacy-client");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            let request: ControlRequest = serde_json::from_slice(&request).unwrap();
            assert_eq!(request, ControlRequest::GetStats);
            stream
                .write_all(br#"{"ok":false,"error":"legacy rejected","stats":null}"#)
                .unwrap();
        });

        let error = UnixClient::send(&path, ControlRequest::GetStats).unwrap_err();
        assert_eq!(error.kind, ControlErrorKind::Internal);
        assert_eq!(error.message(), "legacy rejected");
        server.join().unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn client_rejects_oversized_request_before_connecting() {
        let path = socket_path("client-oversized-request");
        let error = UnixClient::send(
            &path,
            ControlRequest::ReloadConfig {
                toml: "x".repeat(MAX_REQUEST_SIZE),
            },
        )
        .unwrap_err();

        assert_eq!(error.kind, ControlErrorKind::InvalidRequest);
        assert_eq!(error.message(), "request exceeds 1 MiB limit");
    }

    #[test]
    fn client_rejects_oversized_response() {
        let path = socket_path("client-oversized-response");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            let request: ControlRequest = serde_json::from_slice(&request).unwrap();
            assert_eq!(request, ControlRequest::GetStats);
            stream
                .write_all(&vec![b' '; MAX_RESPONSE_SIZE + 1])
                .unwrap();
        });

        let error = UnixClient::send(&path, ControlRequest::GetStats).unwrap_err();
        assert_eq!(error.kind, ControlErrorKind::Internal);
        assert_eq!(error.message(), "daemon response exceeds 4 MiB limit");
        server.join().unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn oversized_request_is_rejected_without_dispatch() {
        let path = socket_path("oversized");
        let mut transport = UnixTransport::bind(path.clone()).unwrap();
        let client = UnixStream::connect(&path).unwrap();
        let client = std::thread::spawn(move || {
            let mut client = client;
            client.write_all(&vec![b' '; MAX_REQUEST_SIZE + 1]).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();

            let mut response = Vec::new();
            client.read_to_end(&mut response).unwrap();
            response
        });

        let mut api = MockApi::default();
        transport.poll(&mut api);

        let response = client.join().unwrap();
        let response: ControlResponse = serde_json::from_slice(&response).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error_kind, Some(ControlErrorKind::InvalidRequest));
        assert_eq!(
            response.error.as_deref(),
            Some("request exceeds 1 MiB limit")
        );
        assert_eq!(api.stats_calls.get(), 0);
    }

    #[test]
    fn fatal_transition_stops_dispatching_queued_requests() {
        let path = socket_path("fatal");
        let mut transport = UnixTransport::bind(path.clone()).unwrap();

        let mut fatal_request = UnixStream::connect(&path).unwrap();
        serde_json::to_writer(
            &mut fatal_request,
            &ControlRequest::ReplacePeers {
                interface: "wg0".to_owned(),
                peers: Vec::new(),
            },
        )
        .unwrap();
        fatal_request.shutdown(std::net::Shutdown::Write).unwrap();

        let mut queued_request = UnixStream::connect(&path).unwrap();
        serde_json::to_writer(&mut queued_request, &ControlRequest::GetStats).unwrap();
        queued_request.shutdown(std::net::Shutdown::Write).unwrap();
        queued_request
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();

        let mut api = MockApi::default();
        transport.poll(&mut api);

        let mut response = Vec::new();
        fatal_request.read_to_end(&mut response).unwrap();
        let response: ControlResponse = serde_json::from_slice(&response).unwrap();
        assert!(response.ok);
        assert!(api.is_fatal());
        assert_eq!(api.stats_calls.get(), 0);

        let mut byte = [0u8; 1];
        assert!(matches!(
            queued_request.read(&mut byte),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                )
        ));
    }
}
