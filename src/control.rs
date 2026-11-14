//! Transport-independent application control API and Unix wire contracts.
//!
//! The API exposes three stable operations. Transport adapters serialize the
//! wire request types and invoke the same `ControlApi` implementation;
//! application errors and domain results do not depend on Unix sockets.

use crate::import::ImportReport;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::time::Duration;

/// Error returned by a Control API implementation.
#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
#[error("{message}")]
pub struct ControlError {
    message: String,
}

impl ControlError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Request to validate and transactionally apply a complete configuration.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ReloadConfigMode {
    #[default]
    Full,
    /// Preserve the legacy --replace-peers behavior: copy only this interface's
    /// peer set from the supplied file, ignoring all other file changes.
    ReplacePeers { interface: String },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub struct ReloadConfigRequest {
    pub toml: String,
    #[serde(default)]
    pub mode: ReloadConfigMode,
}

/// Request to import one WireGuard/AmneziaWG interface into the active config.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub struct ImportConfigRequest {
    /// Source configuration contents (not a path owned by the transport).
    pub source: String,
    pub interface: String,
    pub replace: bool,
}

/// Transport-independent control operations exposed by the daemon.
pub trait ControlApi {
    fn reload_config(&mut self, request: ReloadConfigRequest) -> Result<(), ControlError>;
    fn get_stats(&self) -> Result<Vec<InterfaceStats>, ControlError>;
    fn import_config(&mut self, request: ImportConfigRequest)
        -> Result<ImportReport, ControlError>;
}

/// Request DTO used by the current Unix Domain Socket transport.
#[cfg(target_os = "linux")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Eq, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum ControlRequest {
    GetStats,
    ReloadConfig {
        toml: String,
        #[serde(default)]
        mode: ReloadConfigMode,
    },
    ImportConfig {
        source: String,
        interface: String,
        replace: bool,
    },
}

/// Statistics for one managed tunnel interface.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InterfaceStats {
    pub name: String,
    pub peers: Vec<PeerStats>,
}

/// Statistics for one WireGuard/AmneziaWG peer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PeerStats {
    pub public_key: String,
    pub client_ips: Vec<String>,
    pub endpoint: Option<std::net::SocketAddr>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub handshake_age_secs: Option<u64>,
}

#[cfg(target_os = "linux")]
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct ControlResponse {
    pub(crate) ok: bool,
    pub(crate) error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) stats: Option<Vec<InterfaceStats>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) import_report: Option<ImportReport>,
}



/// Serve one already-accepted Unix socket connection through the application
/// API. Framing, limits, JSON decoding and response encoding live in this
/// transport adapter; application operations remain on \`ControlApi\`.
pub(crate) fn handle_unix_connection(
    api: &mut impl ControlApi,
    mut stream: UnixStream,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut payload = Vec::new();
    let read_result = (&mut stream)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut payload);
    let response = match read_result {
        Ok(_) if payload.len() > 1024 * 1024 => ControlResponse {
            ok: false,
            error: Some("request exceeds 1 MiB limit".to_owned()),
            stats: None,
            import_report: None,
        },
        Ok(_) => match serde_json::from_slice::<ControlRequest>(&payload) {
            Ok(request) => {
                let mut stats = None;
                let mut import_report = None;
                let result = match request {
                    ControlRequest::GetStats => match api.get_stats() {
                        Ok(value) => {
                            stats = Some(value);
                            Ok(())
                        }
                        Err(error) => Err(error),
                    },
                    ControlRequest::ReloadConfig { toml, mode } => {
                        api.reload_config(ReloadConfigRequest { toml, mode })
                    }
                    ControlRequest::ImportConfig {
                        source,
                        interface,
                        replace,
                    } => match api.import_config(ImportConfigRequest {
                        source,
                        interface,
                        replace,
                    }) {
                        Ok(report) => {
                            import_report = Some(report);
                            Ok(())
                        }
                        Err(error) => Err(error),
                    },
                };
                match result {
                    Ok(()) => ControlResponse {
                        ok: true,
                        error: None,
                        stats,
                        import_report,
                    },
                    Err(error) => ControlResponse {
                        ok: false,
                        error: Some(error.to_string()),
                        stats: None,
                        import_report: None,
                    },
                }
            }
            Err(error) => ControlResponse {
                ok: false,
                error: Some(format!("invalid control request: {error}")),
                stats: None,
                import_report: None,
            },
        },
        Err(error) => ControlResponse {
            ok: false,
            error: Some(format!("failed to read control request: {error}")),
            stats: None,
            import_report: None,
        },
    };
    if let Err(error) = serde_json::to_vec(&response)
        .map_err(|error| error.to_string())
        .and_then(|payload| {
            stream
                .write_all(&payload)
                .map_err(|error| error.to_string())
        })
    {
        tracing::warn!(%error, "failed to send control response");
    }
}

/// Unix socket client transport. The caller supplies the namespace-scoped
/// socket path; this module does not discover runtime or filesystem state.
#[cfg(target_os = "linux")]
pub(crate) fn send_unix_request(
    path: &Path,
    request: ControlRequest,
) -> Result<ControlResponse, String> {
    let mut stream = UnixStream::connect(path).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .map_err(|error| error.to_string())?;
    serde_json::to_writer(&mut stream, &request).map_err(|error| error.to_string())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    (&mut stream)
        .take(4 * 1024 * 1024)
        .read_to_end(&mut response)
        .map_err(|error| error.to_string())?;
    let response: ControlResponse =
        serde_json::from_slice(&response).map_err(|error| error.to_string())?;
    if response.ok {
        Ok(response)
    } else {
        Err(response
            .error
            .unwrap_or_else(|| "daemon rejected request".to_owned()))
    }
}
