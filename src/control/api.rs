use crate::config::PeerConfig;
use std::net::SocketAddr;

/// Backend-neutral peer counters returned by the daemon control plane.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InterfaceStats {
    pub name: String,
    pub peers: Vec<PeerStats>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PeerStats {
    pub public_key: String,
    pub client_ips: Vec<String>,
    pub endpoint: Option<SocketAddr>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub handshake_age_secs: Option<u64>,
}

/// Stable error categories for transports to map onto their native status model.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlErrorKind {
    InvalidRequest,
    Configuration,
    Conflict,
    Unavailable,
    Fatal,
    Internal,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ControlError {
    pub kind: ControlErrorKind,
    message: String,
}

impl ControlError {
    pub fn new(kind: ControlErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Operations exposed by a running daemon, independent of the transport.
pub trait ControlApi {
    fn get_stats(&self) -> Result<Vec<InterfaceStats>, ControlError>;
    fn replace_peers(
        &mut self,
        interface: &str,
        peers: Vec<PeerConfig>,
    ) -> Result<(), ControlError>;
    fn reload_config(&mut self, toml: &str) -> Result<(), ControlError>;
    fn is_fatal(&self) -> bool;
}

/// Stable JSON request envelope used by the Unix transport and future transports.
#[derive(Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ControlRequest {
    GetStats,
    ReplacePeers {
        interface: String,
        peers: Vec<PeerConfig>,
    },
    ReloadConfig {
        toml: String,
    },
}

/// Response remains wire-compatible: error_kind is optional for old clients/daemons.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<Vec<InterfaceStats>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<ControlErrorKind>,
}

impl ControlResponse {
    pub(crate) fn success(stats: Option<Vec<InterfaceStats>>) -> Self {
        Self {
            ok: true,
            error: None,
            stats,
            error_kind: None,
        }
    }

    pub(crate) fn failure(error: ControlError) -> Self {
        Self {
            ok: false,
            error: Some(error.to_string()),
            stats: None,
            error_kind: Some(error.kind),
        }
    }
}
