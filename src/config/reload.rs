use super::{invalid, Config, ConfigError};

impl Config {
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
}
