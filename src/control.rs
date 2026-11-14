//! Transport-independent application control API and Unix wire contracts.
//!
//! The API exposes three stable operations. Transport adapters serialize the
//! wire request types and invoke the same `ControlApi` implementation;
//! application errors and domain results do not depend on Unix sockets.

use crate::import::ImportReport;

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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub struct ReloadConfigRequest {
    pub toml: String,
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
    fn import_config(
        &mut self,
        request: ImportConfigRequest,
    ) -> Result<ImportReport, ControlError>;
}

/// Request DTO used by the current Unix Domain Socket transport.
#[derive(serde::Serialize, serde::Deserialize, Debug, Eq, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum ControlRequest {
    GetStats,
    ReloadConfig {
        toml: String,
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

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct ControlResponse {
    pub(crate) ok: bool,
    pub(crate) error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) stats: Option<Vec<InterfaceStats>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) import_report: Option<ImportReport>,
}

