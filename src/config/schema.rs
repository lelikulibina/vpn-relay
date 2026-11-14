use boringtun::noise::amnezia::AmneziaWgConfig;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

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
pub(super) const DEFAULT_SOCKET_FWMARK_BASE: u32 = 0x1000;

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
