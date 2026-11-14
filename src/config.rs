use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use boringtun::noise::amnezia::AmneziaWgConfig;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

mod endpoint;
mod validation;
pub use endpoint::{EndpointHost, PeerEndpoint};

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

/// Complete daemon configuration. Unknown keys are rejected so a typo cannot
/// silently disable a security or routing setting.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,
    pub interfaces: BTreeMap<String, InterfaceConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
    /// Explicit exceptions to the managed-interface INPUT/OUTPUT deny policies.
    #[serde(default)]
    pub firewall: FirewallConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Deprecated; retained for configuration compatibility and ignored.
    #[serde(default = "default_stats_interval")]
    pub stats_interval_secs: u64,
    #[serde(default = "default_nft_table")]
    pub nft_table: String,
    #[serde(default)]
    pub manage_ip_forwarding: bool,
    /// Interfaces whose link-scoped forwarding sysctls vpn-relay manages.
    /// When non-empty, namespace-wide forwarding must already be enabled by
    /// the container/runtime; only these links are changed by vpn-relay.
    #[serde(default)]
    pub forwarding_interfaces: Vec<String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            stats_interval_secs: default_stats_interval(),
            nft_table: default_nft_table(),
            manage_ip_forwarding: false,
            forwarding_interfaces: Vec::new(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_owned()
}

fn default_stats_interval() -> u64 {
    10
}

fn default_nft_table() -> String {
    "vpn_relay".to_owned()
}

fn default_mtu() -> u16 {
    1380
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelType {
    #[serde(rename = "wg")]
    WireGuard,
    #[serde(rename = "awg")]
    AmneziaWg,
}

/// Source NAT is a property of a selected routing rule, not of an interface.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NatMode {
    #[default]
    None,
    Masquerade,
    Snat,
}

/// Fully-resolved source NAT action used by the routing and firewall layers.
/// The TOML representation keeps the backward-compatible `nat` + `nat_to`
/// fields, while this type makes it impossible to represent SNAT without an IP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NatAction {
    None,
    Masquerade,
    Snat(Ipv4Addr),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InterfaceConfig {
    #[serde(rename = "type")]
    pub tunnel_type: TunnelType,
    pub address: Vec<String>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    pub private_key: String,
    /// Optional mark for encrypted UDP sockets; assigned automatically when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_fwmark: Option<u32>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    /// AWG protocol parameters share the interface table with the standard
    /// tunnel fields, matching AmneziaWG's [Interface] configuration model.
    #[serde(flatten, default)]
    pub awg: AmneziaWgConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum PersistentKeepaliveConfig {
    Seconds(u16),
    Range(String),
}

impl PersistentKeepaliveConfig {
    pub fn to_range(&self) -> Result<(u32, u32), String> {
        match self {
            Self::Seconds(seconds) => Ok((u32::from(*seconds), u32::from(*seconds))),
            Self::Range(value) => {
                let (min, max) = value
                    .split_once('-')
                    .ok_or_else(|| format!("invalid PersistentKeepalive range '{value}'"))?;
                if max.contains('-') {
                    return Err(format!("invalid PersistentKeepalive range '{value}'"));
                }
                let min = min
                    .parse::<u32>()
                    .map_err(|_| format!("invalid PersistentKeepalive range '{value}'"))?;
                let max = max
                    .parse::<u32>()
                    .map_err(|_| format!("invalid PersistentKeepalive range '{value}'"))?;
                if min == 0 || max == 0 || min > max {
                    return Err(format!(
                        "invalid PersistentKeepalive range '{value}': expected 1 <= min <= max"
                    ));
                }
                Ok((min, max))
            }
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive_secs: Option<PersistentKeepaliveConfig>,
    /// Inclusive AmneziaWG keepalive interval range in seconds. Mutually exclusive with the legacy field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive_range: Option<(u32, u32)>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    #[serde(default)]
    pub input: FirewallRuleSet,
    #[serde(default)]
    pub output: FirewallRuleSet,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRuleSet {
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallProtocol {
    Tcp,
    Udp,
    Icmp,
}

/// An allow exception scoped to one managed interface. INPUT rules may use
/// source CIDRs; OUTPUT rules may use destination CIDRs. Missing selectors
/// intentionally mean any address/protocol on that interface.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRule {
    pub interface: String,
    #[serde(default, deserialize_with = "deserialize_optional_cidrs")]
    pub source: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_cidrs")]
    pub destination: Option<Vec<String>>,
    #[serde(default)]
    pub protocol: Option<FirewallProtocol>,
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    /// Base mark range reserved for inner packets classified by nftables.
    /// This is intentionally separate from each interface socket_fwmark,
    /// which marks the outer encrypted UDP packets.
    #[serde(default = "default_routing_mark_base")]
    pub mark_base: u32,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            mark_base: default_routing_mark_base(),
            rules: Vec::new(),
        }
    }
}

fn default_routing_mark_base() -> u32 {
    0x8000_0000
}

/// First mark considered for automatically assigned encrypted-socket marks.
const DEFAULT_SOCKET_FWMARK_BASE: u32 = 0x1000;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    pub priority: u32,
    pub ingress: String,
    #[serde(default, deserialize_with = "deserialize_optional_cidrs")]
    pub source: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_cidrs")]
    pub destination: Option<Vec<String>>,
    pub egress: String,
    #[serde(default)]
    pub nat: NatMode,
    /// Required only for static source NAT.
    #[serde(default)]
    pub nat_to: Option<Ipv4Addr>,
}

impl RoutingRule {
    /// Resolve the validated TOML fields into one exhaustive, typed action.
    pub fn nat_action(&self) -> NatAction {
        match self.nat {
            NatMode::None => NatAction::None,
            NatMode::Masquerade => NatAction::Masquerade,
            NatMode::Snat => NatAction::Snat(
                self.nat_to
                    .expect("validated SNAT routing rule must contain nat_to"),
            ),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrManyStrings {
    One(String),
    Many(Vec<String>),
}

/// Accept both a single CIDR (backward compatibility) and a list of CIDRs.
fn deserialize_optional_cidrs<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<OneOrManyStrings>::deserialize(deserializer).map(|value| {
        value.map(|value| match value {
            OneOrManyStrings::One(prefix) => vec![prefix],
            OneOrManyStrings::Many(prefixes) => prefixes,
        })
    })
}

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

    /// Ensure a candidate configuration can be applied without recreating
    /// tunnel devices or changing resources whose lifecycle is owned by start().
    ///
    /// Peer sets, routing decisions and firewall rules are intentionally
    /// mutable. Interface identity and tunnel construction parameters are not.
    pub fn validate_reload_compatibility(&self, next: &Self) -> Result<(), ConfigError> {
        if self.interfaces.keys().ne(next.interfaces.keys()) {
            return invalid(
                "reload cannot add or remove interfaces; tunnel lifecycle changes require a restart",
            );
        }

        for (name, current) in &self.interfaces {
            let candidate = &next.interfaces[name];
            if current.tunnel_type != candidate.tunnel_type
                || current.address != candidate.address
                || current.mtu != candidate.mtu
                || current.listen_port != candidate.listen_port
                || current.private_key != candidate.private_key
                || current.socket_fwmark != candidate.socket_fwmark
                || current.awg != candidate.awg
            {
                return invalid(format!(
                    "reload cannot change immutable tunnel parameters for interface '{name}'; restart vpn-relay to apply them",
                ));
            }
        }

        if self.resolved_socket_fwmarks()? != next.resolved_socket_fwmarks()? {
            return invalid(
                "reload cannot change resolved socket fwmarks; restart vpn-relay to apply them",
            );
        }
        let current_egresses: std::collections::BTreeSet<_> = self
            .routing
            .rules
            .iter()
            .map(|rule| rule.egress.as_str())
            .collect();
        let next_egresses: std::collections::BTreeSet<_> = next
            .routing
            .rules
            .iter()
            .map(|rule| rule.egress.as_str())
            .collect();
        let current_marks: std::collections::BTreeSet<_> =
            self.resolved_routing_fwmarks()?.into_iter().collect();
        let next_marks: std::collections::BTreeSet<_> =
            next.resolved_routing_fwmarks()?.into_iter().collect();
        let policy_resources_unchanged =
            current_egresses == next_egresses && current_marks == next_marks;
        if !policy_resources_unchanged && current_marks.intersection(&next_marks).next().is_some() {
            return invalid(
                "reload requires old and new routing mark ranges to be disjoint when policy-routing resources change",
            );
        }

        if self.daemon.nft_table != next.daemon.nft_table {
            return invalid("reload cannot change daemon.nft_table while the daemon is running");
        }
        if self.daemon.manage_ip_forwarding != next.daemon.manage_ip_forwarding
            || self.daemon.forwarding_interfaces != next.daemon.forwarding_interfaces
        {
            return invalid(
                "reload cannot change daemon.manage_ip_forwarding or daemon.forwarding_interfaces while the daemon is running",
            );
        }
        if self.daemon.log_level != next.daemon.log_level {
            return invalid("reload cannot change daemon.log_level; restart vpn-relay to apply it");
        }

        Ok(())
    }

    /// Resolve one packet mark for each distinct egress referenced by routing rules.
    /// The order matches the lexicographically sorted egress list in RoutingPlan.
    pub fn resolved_routing_fwmarks(&self) -> Result<Vec<u32>, ConfigError> {
        let egress_count = self
            .routing
            .rules
            .iter()
            .map(|rule| rule.egress.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        (0..egress_count)
            .map(|index| {
                self.routing
                    .mark_base
                    .checked_add(index as u32)
                    .filter(|mark| *mark != 0)
                    .ok_or_else(|| {
                        ConfigError::Validation(
                            "[routing].mark_base leaves no room for all client routing marks"
                                .to_owned(),
                        )
                    })
            })
            .collect()
    }

    /// Resolve explicit and automatically assigned socket marks in interface-name order.
    /// The socket and packet mark spaces are disjoint by exact 32-bit value.
    /// Explicit marks are reserved first so automatic allocation never displaces them.
    pub fn resolved_socket_fwmarks(&self) -> Result<Vec<u32>, ConfigError> {
        let routing_marks: HashSet<_> = self.resolved_routing_fwmarks()?.into_iter().collect();

        let mut used = HashSet::new();
        for (interface_name, interface) in &self.interfaces {
            if let Some(mark) = interface.socket_fwmark {
                if mark == 0 {
                    return invalid(format!(
                        "interfaces.{}.socket_fwmark must be non-zero",
                        interface_name
                    ));
                }
                if !used.insert(mark) {
                    return invalid(format!(
                        "socket fwmark 0x{mark:x} is used by more than one interface"
                    ));
                }
                if routing_marks.contains(&mark) {
                    return invalid(
                        "[routing].mark_base range overlaps an interface socket_fwmark; outer UDP and inner packet marks must be distinct",
                    );
                }
            }
        }

        let mut next_candidate = DEFAULT_SOCKET_FWMARK_BASE;
        let mut resolved = Vec::with_capacity(self.interfaces.len());
        for interface in self.interfaces.values() {
            let mark = if let Some(mark) = interface.socket_fwmark {
                mark
            } else {
                loop {
                    if next_candidate == 0 {
                        return invalid("no available non-zero socket fwmark remains");
                    }
                    let candidate = next_candidate;
                    next_candidate = next_candidate.checked_add(1).unwrap_or(0);
                    if !routing_marks.contains(&candidate) && used.insert(candidate) {
                        break candidate;
                    }
                }
            };
            resolved.push(mark);
        }
        Ok(resolved)
    }
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

fn invalid<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Validation(message.into()))
}

#[cfg(test)]
mod tests;
