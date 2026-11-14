use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use super::{invalid, ConfigError};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;

/// Parsed peer endpoint. DNS names are validated but deliberately not resolved
/// while loading configuration; resolution belongs to daemon startup/reconnect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerEndpoint {
    pub host: EndpointHost,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointHost {
    Ip(Ipv4Addr),
    Dns(String),
}

impl PeerEndpoint {
    pub fn parse(value: &str) -> Result<Self, String> {
        if let Ok(address) = SocketAddr::from_str(value) {
            let SocketAddr::V4(address) = address else {
                return Err("IPv4 endpoints only are supported by vpn-relay".to_owned());
            };
            return Ok(Self {
                host: EndpointHost::Ip(*address.ip()),
                port: address.port(),
            });
        }

        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| "expected IPv4 host:port".to_owned())?;
        let port = port
            .parse::<u16>()
            .map_err(|_| "port must be an integer in 1..=65535".to_owned())?;
        if port == 0 {
            return Err("port must be in 1..=65535".to_owned());
        }
        if host.is_empty() || host.starts_with('[') || host.ends_with(']') || host.contains(':') {
            return Err("invalid host; IPv4 literals or DNS names are supported".to_owned());
        }

        if let Ok(address) = host.parse::<Ipv4Addr>() {
            return Ok(Self {
                host: EndpointHost::Ip(address),
                port,
            });
        }
        if !valid_ascii_dns_name(host) {
            return Err(
                "host must be an IP address or a valid ASCII DNS name (use punycode for IDNs)"
                    .to_owned(),
            );
        }
        Ok(Self {
            host: EndpointHost::Dns(host.to_ascii_lowercase()),
            port,
        })
    }
}

fn valid_ascii_dns_name(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

/// Decode a WireGuard key from standard Base64 and require exactly 32 bytes.
pub fn decode_key(value: &str, field: &str) -> Result<[u8; 32], ConfigError> {
    let decoded = STANDARD.decode(value).map_err(|error| {
        ConfigError::Validation(format!("{} is not valid standard Base64: {}", field, error))
    })?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        ConfigError::Validation(format!(
            "{} must decode to exactly 32 bytes (got {})",
            field,
            bytes.len()
        ))
    })
}

pub(super) fn canonical_prefix(value: &str, field: &str) -> Result<(Ipv4Addr, u8), ConfigError> {
    let (address, prefix) = parse_prefix(value, field)?;
    let bits = u32::from(address);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok((Ipv4Addr::from(bits & mask), prefix))
}

pub(super) fn parse_prefix(value: &str, field: &str) -> Result<(Ipv4Addr, u8), ConfigError> {
    let (address, prefix) = value.split_once('/').ok_or_else(|| {
        ConfigError::Validation(format!(
            "{} contains invalid CIDR '{}': expected IPv4 address/prefix",
            field, value
        ))
    })?;
    let address = address.parse::<Ipv4Addr>().map_err(|error| {
        ConfigError::Validation(format!(
            "{} contains invalid IPv4 CIDR '{}': {}",
            field, value, error
        ))
    })?;
    let prefix = prefix.parse::<u8>().map_err(|error| {
        ConfigError::Validation(format!(
            "{} contains invalid CIDR '{}': {}",
            field, value, error
        ))
    })?;
    if prefix > 32 {
        return Err(ConfigError::Validation(format!(
            "{} contains invalid CIDR '{}': prefix exceeds 32",
            field, value
        )));
    }
    Ok((address, prefix))
}

pub(super) fn validate_interface_name(name: &str) -> Result<(), ConfigError> {
    // BoringTun interprets a numeric Linux interface name as an inherited
    // file descriptor. vpn-relay owns its TUN descriptors and must not accept
    // this alternate constructor mode from configuration.
    if name.parse::<i32>().is_ok() {
        return invalid(format!(
            "interface name '{}' must not be a numeric file descriptor",
            name
        ));
    }
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 15
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return invalid(format!(
            "interface name '{}' must be 1..=15 ASCII letters, digits, '.', '_' or '-'",
            name
        ));
    }
    Ok(())
}

pub(super) fn valid_nft_table_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

