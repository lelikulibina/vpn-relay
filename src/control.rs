//! Transport-independent control-plane data types shared by the daemon and CLI.
//!
//! The Unix socket currently serializes the request/response DTOs below. Keeping
//! them outside Runtime is the first boundary toward a transport-neutral
//! Control API. Transport handling and application operations can now be
//! migrated without making these contracts depend on Runtime internals.

use crate::config::PeerConfig;

/// Request DTO used by the existing local control protocol.
///
/// Existing operations remain available during the staged migration so the
/// current CLI contract is not broken before all consumers are migrated.
#[derive(serde::Serialize, serde::Deserialize, Debug, Eq, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum ControlRequest {
    GetStats,
    ReplacePeers {
        interface: String,
        peers: Vec<PeerConfig>,
    },
    ReloadConfig {
        toml: String,
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
}
