//! Peer endpoint parsing and DNS-name validation.

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
