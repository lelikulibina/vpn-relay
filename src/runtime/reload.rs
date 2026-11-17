//! Transactional peer replacement and live configuration reload.

use super::*;

pub(super) fn commit_peer_replacements(
    devices: &mut [Box<dyn TunnelHandle>],
    changed_interfaces: &[(usize, String)],
    candidate: &Config,
    prepared: &std::collections::BTreeMap<String, PreparedInterface>,
) -> Result<Vec<usize>, (Vec<usize>, RuntimeError)> {
    let mut committed = Vec::with_capacity(changed_interfaces.len());
    for (index, name) in changed_interfaces {
        let Some(interface) = candidate.interfaces.get(name) else {
            return Err((
                committed,
                RuntimeError::Configuration(format!(
                    "candidate is missing interface '{name}' during peer commit"
                )),
            ));
        };
        let Some(prepared_interface) = prepared.get(name) else {
            return Err((
                committed,
                RuntimeError::Configuration(format!(
                    "candidate is missing prepared backend configuration for '{name}'"
                )),
            ));
        };
        let Some(device) = devices.get_mut(*index) else {
            return Err((
                committed,
                RuntimeError::Configuration(format!(
                    "candidate interface '{name}' has no matching tunnel device"
                )),
            ));
        };
        if let Err(error) = device.replace_peers(interface, prepared_interface) {
            return Err((committed, RuntimeError::Backend(error)));
        }
        committed.push(*index);
    }
    Ok(committed)
}

pub(super) fn rollback_peer_replacements(
    devices: &mut [Box<dyn TunnelHandle>],
    committed: &[usize],
    previous_config: &Config,
    previous_prepared: &std::collections::BTreeMap<String, PreparedInterface>,
) -> Vec<String> {
    let mut failures = Vec::new();
    for index in committed.iter().rev().copied() {
        let Some((name, interface)) = previous_config.interfaces.iter().nth(index) else {
            failures.push(format!(
                "missing previous interface at device index {index}"
            ));
            continue;
        };
        let Some(prepared) = previous_prepared.get(name) else {
            failures.push(format!(
                "missing previous prepared configuration for '{name}'"
            ));
            continue;
        };
        let Some(device) = devices.get_mut(index) else {
            failures.push(format!(
                "missing tunnel device for '{name}' at index {index}"
            ));
            continue;
        };
        if let Err(error) = device.replace_peers(interface, prepared) {
            failures.push(format!("{name}: {error}"));
        }
    }
    failures
}

impl Runtime {
    /// Replace only the peer set of an existing interface. Endpoint DNS,
    /// keys and AllowedIPs are prepared before the live backend is changed;
    /// routing, firewall, interface identity and socket marks remain fixed.
    pub fn replace_peers(
        &mut self,
        interface_name: &str,
        peers: Vec<PeerConfig>,
    ) -> Result<(), RuntimeError> {
        let mut candidate = self.config.clone();
        let interface = candidate
            .interfaces
            .get_mut(interface_name)
            .ok_or_else(|| {
                RuntimeError::Configuration(format!("unknown interface '{interface_name}'"))
            })?;
        interface.peers = peers;
        self.reload_config(candidate)
    }

    /// Apply mutable peer, routing-decision and firewall configuration.
    ///
    /// The compatibility check guarantees that policy-routing tables, marks,
    /// tunnel devices and forwarding ownership remain stable. Peer sets are
    /// committed first; the nftables table is then replaced in one kernel
    /// transaction. Any later failure restores already committed peer sets.
    pub fn reload_config(&mut self, candidate: Config) -> Result<(), RuntimeError> {
        self.verify_tunnel_identities()?;
        if let Some(error) = &self.fatal_error {
            return Err(RuntimeError::FatalTransition(error.clone()));
        }
        candidate
            .validate()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        self.config
            .validate_reload_compatibility(&candidate)
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;

        let mut next_routing = RoutingPlan::from_config(&candidate);
        let mut next_conntrack_mark_history = self.conntrack_mark_history.clone();
        next_routing
            .assign_stable_conntrack_marks(&mut next_conntrack_mark_history)
            .map_err(RuntimeError::ConntrackMarkState)?;
        if let Some(indices) = self.routing.interface_indices.clone() {
            next_routing
                .bind_interface_indices(indices)
                .map_err(RuntimeError::Configuration)?;
        }
        if self.routing.socket_marks != next_routing.socket_marks {
            return Err(RuntimeError::Configuration(
                "candidate changes live socket fwmarks; restart vpn-relay".to_owned(),
            ));
        }

        // RoutingPlan::from_config starts with the default table/priority
        // numbers. Preserve the dynamically allocated live slots when the
        // actual egress identity and fwmark are unchanged; otherwise every
        // peer-only or firewall-only reload would look like a route migration.
        let same_egress_resources = self.routing.egresses.len() == next_routing.egresses.len()
            && next_routing.egresses.iter().all(|next| {
                self.routing
                    .egresses
                    .iter()
                    .any(|current| current.interface == next.interface && current.mark == next.mark)
            });
        if same_egress_resources {
            for next in &mut next_routing.egresses {
                if let Some(current) = self
                    .routing
                    .egresses
                    .iter()
                    .find(|current| current.interface == next.interface)
                {
                    next.table_id = current.table_id;
                    next.ip_rule_priority = current.ip_rule_priority;
                }
            }
        }
        let route_resources_changed = !same_egress_resources;
        if route_resources_changed {
            let mut occupied = self.retired_routing.clone();
            occupied.push(self.routing.clone());
            linux::allocate_policy_routing_resources(&mut next_routing, &occupied)?;
        }

        // Resolve and validate every changed peer set before the first live
        // device or routing resource is touched. Keep exact old endpoint
        // resolutions for unchanged peers so rollback never depends on DNS.
        let mut prepared = self.prepared_interfaces.clone();
        let mut changed_interfaces = Vec::new();
        for (index, (name, next_interface)) in candidate.interfaces.iter().enumerate() {
            let current_interface = &self.config.interfaces[name];
            if current_interface.peers == next_interface.peers {
                continue;
            }
            let next_prepared = self.backends.prepare_interface(name, next_interface)?;
            prepared.insert(name.clone(), next_prepared);
            changed_interfaces.push((index, name.clone()));
        }

        if next_conntrack_mark_history != self.conntrack_mark_history {
            // Reserve new decision IDs before they can be written into conntrack.
            // Failed reloads may leave unused IDs reserved; that is safe, while
            // reusing an ID still present in conntrack would not be.
            if let Err(error) = persist_conntrack_mark_history(
                &self.conntrack_mark_state_path,
                &next_conntrack_mark_history,
            ) {
                let details = format!("failed to persist conntrack decision marks: {error}");
                self.fatal_error = Some(details.clone());
                return Err(RuntimeError::FatalTransition(details));
            }
            self.conntrack_mark_history = next_conntrack_mark_history.clone();
        }

        // New policy routes use disjoint marks, tables and priorities. They are
        // installed while the old nft classifier still emits only old marks.
        if route_resources_changed {
            if let Err(error) = linux::apply_egress_policy_routing(&next_routing) {
                self.rollback_reload(&[], Some(&next_routing))?;
                return Err(error.into());
            }
        }

        let committed = match commit_peer_replacements(
            &mut self.devices,
            &changed_interfaces,
            &candidate,
            &prepared,
        ) {
            Ok(committed) => committed,
            Err((committed, error)) => {
                self.rollback_reload(&committed, route_resources_changed.then_some(&next_routing))?;
                return Err(error);
            }
        };

        if self.routing != next_routing {
            if let Err(error) = self.nft_applier.apply(&next_routing) {
                self.rollback_reload(&committed, route_resources_changed.then_some(&next_routing))?;
                return Err(error.into());
            }
        }

        let previous_routing = self.routing.clone();
        self.config = candidate;
        self.prepared_interfaces = prepared;
        self.routing = next_routing;
        // Only after nftables selects the new marks can old policy routes be
        // removed. Retain the old plan until cleanup succeeds so Drop can retry.
        if route_resources_changed {
            self.retired_routing.push(previous_routing.clone());
            if let Err(error) = linux::remove_egress_policy_routing(&previous_routing) {
                let details = format!(
                    "new routing plan is active but old policy routes could not be removed: {error}"
                );
                self.fatal_error = Some(details.clone());
                return Err(RuntimeError::FatalTransition(details));
            }
            self.retired_routing.pop();
        }

        tracing::info!("runtime configuration reloaded");
        Ok(())
    }

    fn rollback_reload(
        &mut self,
        committed: &[usize],
        staged_routing: Option<&RoutingPlan>,
    ) -> Result<(), RuntimeError> {
        let mut failures = self.rollback_peer_replacements(committed);
        if let Some(plan) = staged_routing {
            self.retired_routing.push(plan.clone());
            if let Err(error) = linux::remove_egress_policy_routing(plan) {
                failures.push(format!("staged policy routes: {error}"));
            } else {
                self.retired_routing.pop();
            }
        }

        if failures.is_empty() {
            return Ok(());
        }

        let details = failures.join("; ");
        self.fatal_error = Some(details.clone());
        Err(RuntimeError::FatalTransition(details))
    }
}
