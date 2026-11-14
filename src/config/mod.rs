use std::fs;
use std::path::Path;

/// Number of unique routing decisions representable in vpn-relay's reserved
/// conntrack mark field (12 decision bits plus a 4-bit namespace prefix).
pub(crate) const MAX_ROUTING_DECISIONS: usize = 0x0fff;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read configuration: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid TOML configuration: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("configuration validation failed: {0}")]
    Validation(String),
}

mod parse;
mod reload;
mod validate;
mod schema;
pub use parse::{decode_key, EndpointHost, PeerEndpoint};
pub use schema::{
    Config, DaemonConfig, FirewallConfig, FirewallProtocol, FirewallRule, FirewallRuleSet,
    InterfaceConfig, NatAction, NatMode, PeerConfig, PersistentKeepaliveConfig, RoutingConfig,
    RoutingRule, TunnelType,
};
use parse::{canonical_prefix, parse_prefix, valid_nft_table_name, validate_interface_name};
use schema::DEFAULT_SOCKET_FWMARK_BASE;

/// Validate interface keys before deserializing the flattened AWG parameter
/// set. Serde's flatten cannot be combined with deny_unknown_fields, so
/// this explicit check preserves the daemon's fail-closed typo handling.
fn validate_interface_table_keys(value: &toml::Value) -> Result<(), ConfigError> {
    const ALLOWED: &[&str] = &[
        "type",
        "address",
        "mtu",
        "listen_port",
        "private_key",
        "socket_fwmark",
        "peers",
        "jc",
        "jmin",
        "jmax",
        "s1",
        "s2",
        "s3",
        "s4",
        "h1",
        "h2",
        "h3",
        "h4",
        "disable_cookies",
        "random_trailers",
        "i1",
        "i2",
        "i3",
        "i4",
        "i5",
        "header_protection_key",
        "content_padding_addition",
        "rekey_after_time",
        "rekey_timeout",
        "reject_after_time",
        "keepalive_timeout",
        "max_handshake_attempts",
    ];

    let Some(interfaces) = value.get("interfaces").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    for (name, interface) in interfaces {
        let Some(fields) = interface.as_table() else {
            continue;
        };
        if fields.contains_key("awg") {
            return invalid(format!(
                "interfaces.{name}.awg is not a valid table; move AWG parameters directly into [interfaces.{name}]"
            ));
        }
        if let Some(unknown) = fields.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
            return invalid(format!("unknown field 'interfaces.{name}.{unknown}'"));
        }
    }
    Ok(())
}

impl InterfaceConfig {
    /// Whether this interface has any explicit AmneziaWG parameter.
    /// A default (empty) AWG config is stored for every interface because
    /// serde's flattened struct cannot distinguish an absent Option reliably.
    fn has_awg_parameters(&self) -> bool {
        let awg = &self.awg;
        awg.jc.is_some()
            || awg.jmin.is_some()
            || awg.jmax.is_some()
            || awg.s1.is_some()
            || awg.s2.is_some()
            || awg.s3.is_some()
            || awg.s4.is_some()
            || awg.h1.is_some()
            || awg.h2.is_some()
            || awg.h3.is_some()
            || awg.h4.is_some()
            || awg.disable_cookies.is_some()
            || awg.random_trailers.is_some()
            || awg.i1.is_some()
            || awg.i2.is_some()
            || awg.i3.is_some()
            || awg.i4.is_some()
            || awg.i5.is_some()
            || awg.header_protection_key.is_some()
            || awg.content_padding_addition.is_some()
            || awg.rekey_after_time.is_some()
            || awg.rekey_timeout.is_some()
            || awg.reject_after_time.is_some()
            || awg.keepalive_timeout.is_some()
            || awg.max_handshake_attempts.is_some()
    }
}

impl Config {
    /// Parse TOML and validate the complete configuration before any system
    /// resource (TUN, UDP socket, nftables rule, or route) is created.
    pub fn parse_toml(input: &str) -> Result<Self, ConfigError> {
        let value: toml::Value = toml::from_str(input)?;
        validate_interface_table_keys(&value)?;
        let config: Self = value.try_into()?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let input = fs::read_to_string(path)?;
        Self::parse_toml(&input)
    }


}

fn invalid<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Validation(message.into()))
}

#[cfg(test)]
mod tests;
