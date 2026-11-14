use super::*;
use std::collections::HashSet;

impl Config {
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
