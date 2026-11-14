use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::Ipv4Addr;
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

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.routing.rules.len() > MAX_ROUTING_DECISIONS {
            return invalid(format!(
                "[routing].rules supports at most {MAX_ROUTING_DECISIONS} entries because conntrack decision marks have a reserved 12-bit id field"
            ));
        }
        if self.interfaces.is_empty() {
            return invalid("at least one interface must be configured");
        }
        if !self.daemon.forwarding_interfaces.is_empty() && !self.daemon.manage_ip_forwarding {
            return invalid("[daemon].forwarding_interfaces requires manage_ip_forwarding = true");
        }
        let mut forwarding_names = HashSet::new();
        for name in &self.daemon.forwarding_interfaces {
            validate_interface_name(name)?;
            if !forwarding_names.insert(name) {
                return invalid(format!(
                    "[daemon].forwarding_interfaces contains duplicate interface '{name}'"
                ));
            }
        }
        if !valid_nft_table_name(&self.daemon.nft_table) {
            return invalid(
                "[daemon].nft_table must contain only ASCII letters, digits, or underscores",
            );
        }
        if !matches!(
            self.daemon.log_level.as_str(),
            "trace" | "debug" | "info" | "warn" | "error"
        ) {
            return invalid("[daemon].log_level must be trace, debug, info, warn, or error");
        }

        let mut listen_ports = HashSet::new();

        for (interface_name, interface) in &self.interfaces {
            validate_interface_name(interface_name)?;
            if let Some(port) = interface.listen_port {
                if port == 0 {
                    return invalid(format!(
                        "interfaces.{}.listen_port must be in 1..=65535 when specified",
                        interface_name
                    ));
                }
                if !listen_ports.insert(port) {
                    return invalid(format!(
                        "UDP listen port {} is used by more than one interface",
                        port
                    ));
                }
            }
            if !(576..=65535).contains(&interface.mtu) {
                return invalid(format!(
                    "interfaces.{}.mtu must be in 576..=65535",
                    interface_name
                ));
            }
            decode_key(
                &interface.private_key,
                &format!("interfaces.{}.private_key", interface_name),
            )?;

            for address in &interface.address {
                parse_prefix(address, &format!("interfaces.{}.address", interface_name))?;
            }

            if interface.tunnel_type == TunnelType::WireGuard && interface.has_awg_parameters() {
                return invalid(format!(
                    "AWG parameters on interface '{}' are not valid for tunnel type 'wg'",
                    interface_name
                ));
            }
            let mut peer_keys = HashSet::new();
            let mut owned_prefixes = HashSet::new();
            for (peer_index, peer) in interface.peers.iter().enumerate() {
                let peer_path = format!("interfaces.{}.peers[{}]", interface_name, peer_index);
                let public_key = decode_key(&peer.public_key, &format!("{peer_path}.public_key"))?;
                if !peer_keys.insert(public_key) {
                    return invalid(format!(
                        "interfaces.{} contains duplicate peer public keys",
                        interface_name
                    ));
                }
                if let Some(psk) = &peer.preshared_key {
                    decode_key(psk, &format!("{peer_path}.preshared_key"))?;
                }
                if peer.persistent_keepalive_secs.is_some()
                    && peer.persistent_keepalive_range.is_some()
                {
                    return invalid(format!(
                        "{peer_path} must not set both persistent_keepalive_secs and persistent_keepalive_range"
                    ));
                }
                if let Some(value) = &peer.persistent_keepalive_secs {
                    value.to_range().map_err(|error| {
                        ConfigError::Validation(format!(
                            "{peer_path}.persistent_keepalive_secs: {error}"
                        ))
                    })?;
                }
                if let Some((min, max)) = peer.persistent_keepalive_range {
                    if min == 0 || max == 0 || min > max {
                        return invalid(format!(
                            "{peer_path}.persistent_keepalive_range must satisfy 1 <= min <= max"
                        ));
                    }
                }
                if let Some(endpoint) = &peer.endpoint {
                    PeerEndpoint::parse(endpoint).map_err(|error| {
                        ConfigError::Validation(format!(
                            "{peer_path}.endpoint is invalid: {}",
                            error
                        ))
                    })?;
                }
                for prefix in &peer.allowed_ips {
                    let parsed = parse_prefix(prefix, &format!("{peer_path}.allowed_ips"))?;
                    if !owned_prefixes.insert(parsed) {
                        return invalid(format!(
                            "interfaces.{} assigns AllowedIP {} to more than one peer",
                            interface_name, prefix
                        ));
                    }
                }
            }
        }

        if self.routing.mark_base == 0 {
            return invalid("[routing].mark_base must be non-zero");
        }
        self.resolved_socket_fwmarks()?;

        let mut route_priorities = HashSet::new();
        for (index, rule) in self.routing.rules.iter().enumerate() {
            if !route_priorities.insert((rule.ingress.as_str(), rule.priority)) {
                return invalid(format!(
                    "routing contains duplicate priority {} for ingress '{}'",
                    rule.priority, rule.ingress
                ));
            }
            if !self.interfaces.contains_key(rule.ingress.as_str()) {
                return invalid(format!(
                    "routing rule references unknown ingress '{}'",
                    rule.ingress
                ));
            }
            if !self.interfaces.contains_key(rule.egress.as_str()) {
                return invalid(format!(
                    "routing rule references unknown egress '{}'",
                    rule.egress
                ));
            }
            if rule.ingress == rule.egress {
                return invalid(format!(
                    "routing rule cannot use '{}' as both ingress and egress",
                    rule.ingress
                ));
            }
            let path = format!("routing.rules[{index}]");
            for (field, prefixes) in [
                ("source", rule.source.as_ref()),
                ("destination", rule.destination.as_ref()),
            ] {
                if let Some(prefixes) = prefixes {
                    if prefixes.is_empty() {
                        return invalid(format!("{path}.{field} must not be an empty list"));
                    }
                    let mut unique = HashSet::new();
                    for prefix in prefixes {
                        if !unique.insert(canonical_prefix(prefix, &format!("{path}.{field}"))?) {
                            return invalid(format!(
                                "{path}.{field} must not contain duplicate CIDR selectors (including equivalent CIDR networks)"
                            ));
                        }
                    }
                }
            }
            match rule.nat {
                NatMode::Snat => {
                    if rule.nat_to.is_none() {
                        return invalid("routing.rules.nat_to is required when nat = \"snat\"");
                    }
                }
                NatMode::None | NatMode::Masquerade if rule.nat_to.is_some() => {
                    return invalid("routing.rules.nat_to is valid only when nat = \"snat\"");
                }
                NatMode::None | NatMode::Masquerade => {}
            }
        }

        for (direction, rules, is_input) in [
            ("firewall.input", &self.firewall.input.rules, true),
            ("firewall.output", &self.firewall.output.rules, false),
        ] {
            for (index, rule) in rules.iter().enumerate() {
                let path = format!("{direction}.rules[{index}]");
                if !self.interfaces.contains_key(&rule.interface) {
                    return invalid(format!(
                        "{path} references unknown interface '{}'",
                        rule.interface
                    ));
                }
                if is_input && rule.destination.is_some() {
                    return invalid(format!("{path}.destination is not valid for INPUT rules"));
                }
                if !is_input && rule.source.is_some() {
                    return invalid(format!("{path}.source is not valid for OUTPUT rules"));
                }
                for (field, prefixes) in [
                    ("source", rule.source.as_ref()),
                    ("destination", rule.destination.as_ref()),
                ] {
                    if let Some(prefixes) = prefixes {
                        if prefixes.is_empty() {
                            return invalid(format!("{path}.{field} must not be an empty list"));
                        }
                        let mut unique = HashSet::new();
                        for prefix in prefixes {
                            if !unique.insert(canonical_prefix(prefix, &format!("{path}.{field}"))?)
                            {
                                return invalid(format!(
                                    "{path}.{field} must not contain duplicate CIDR selectors (including equivalent CIDR networks)"
                                ));
                            }
                        }
                        for prefix in prefixes {
                            parse_prefix(prefix, &format!("{path}.{field}"))?;
                        }
                    }
                }
                if let Some(ports) = &rule.ports {
                    if ports.is_empty() || ports.contains(&0) {
                        return invalid(format!(
                            "{path}.ports must contain one or more ports in 1..=65535"
                        ));
                    }
                    if !matches!(
                        rule.protocol,
                        Some(FirewallProtocol::Tcp | FirewallProtocol::Udp)
                    ) {
                        return invalid(format!(
                            "{path}.ports requires protocol = \"tcp\" or \"udp\""
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Validation(message.into()))
}

#[cfg(test)]
mod tests;
