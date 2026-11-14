//! Transport-independent application control API contracts.
//!
//! Application operations and their domain request/error types are defined
//! here. Concrete transports live in small adapters and depend on this API,
//! never the other way around.

use crate::import::ImportReport;

#[cfg(target_os = "linux")]
mod unix;
#[cfg(target_os = "linux")]
pub(crate) use unix::{
    handle_unix_connection, send_unix_request, ControlRequest, ControlResponse,
};

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
    /// Preserve legacy --replace-peers semantics without adding a fourth API operation.
    ReplacePeers { interface: String },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub struct ReloadConfigRequest {
    pub toml: String,
    #[serde(default)]
    pub mode: ReloadConfigMode,
}

/// Import one WireGuard/AmneziaWG profile into a candidate daemon configuration.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub struct ImportConfigRequest {
    /// Profile contents, not a filesystem path supplied by the transport.
    pub source: String,
    pub interface: String,
    pub replace: bool,
}

/// Transport-independent application operations exposed by the daemon.
pub trait ControlApi {
    fn reload_config(&mut self, request: ReloadConfigRequest) -> Result<(), ControlError>;
    fn get_stats(&self) -> Result<Vec<InterfaceStats>, ControlError>;
    fn import_config(
        &mut self,
        request: ImportConfigRequest,
    ) -> Result<ImportReport, ControlError>;
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
