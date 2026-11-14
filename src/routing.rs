//! Pure routing-plan generation for the Linux daemon.
//!
//! This module deliberately does not execute privileged commands. It turns a
//! validated TOML configuration into deterministic nftables and policy-routing
//! operations; the runtime layer can apply these operations transactionally.

use crate::config::{Config, FirewallProtocol, FirewallRule, NatAction, NatMode};
use std::collections::BTreeMap;

mod conntrack;
mod nft;

pub(crate) const FIRST_ROUTING_TABLE: u32 = 10_000;
pub(crate) const FIRST_IP_RULE_PRIORITY: u32 = 10_000;
const SOCKET_MAIN_RULE_PRIORITY: u32 = 9_000;
// vpn-relay owns the high 16 bits of ct mark for routing decision identity
// and managed host-flow authorization; the low 16 bits remain host policy/QoS.
const CONNTRACK_MARK_MASK: u32 = 0xffff_0000;
const CONNTRACK_MARK_PRESERVE_MASK: u32 = !CONNTRACK_MARK_MASK;
// A new namespace prevents pre-state-file conntrack entries from being reinterpreted after upgrade.
const LOCAL_FLOW_CONNTRACK_MARK: u32 = 0x8000_0000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressPlan {
    pub interface: String,
    pub mark: u32,
    pub table_id: u32,
    pub ip_rule_priority: u32,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct RoutingDecision {
    pub priority: u32,
    pub ingress: String,
    pub source: Option<Vec<String>>,
    pub destination: Option<Vec<String>>,
    pub egress: String,
    pub routing_mark: u32,
    /// Unique decision id persisted in conntrack for reverse filtering and NAT.
    pub conntrack_mark: u32,
    pub nat: NatMode,
    pub nat_to: Option<std::net::Ipv4Addr>,
}

impl RoutingDecision {
    /// Resolve persisted routing-decision fields into one exhaustive NAT action.
    fn nat_action(&self) -> NatAction {
        match self.nat {
            NatMode::None => NatAction::None,
            NatMode::Masquerade => NatAction::Masquerade,
            NatMode::Snat => NatAction::Snat(
                self.nat_to
                    .expect("validated SNAT routing decision must contain nat_to"),
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NftFirewallRule {
    pub interface: String,
    pub source: Option<Vec<String>>,
    pub destination: Option<Vec<String>>,
    pub protocol: Option<FirewallProtocol>,
    pub ports: Option<Vec<u16>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingPlan {
    pub nft_family: String,
    pub nft_table: String,
    pub managed_interfaces: Vec<String>,
    pub egresses: Vec<EgressPlan>,
    pub decisions: Vec<RoutingDecision>,
    /// Explicit INPUT exceptions; all other managed ingress is denied.
    pub input_rules: Vec<NftFirewallRule>,
    /// Explicit OUTPUT exceptions; all other managed egress is denied.
    pub output_rules: Vec<NftFirewallRule>,
    /// Socket marks that force outer encrypted UDP through the main table.
    pub socket_marks: Vec<u32>,
    /// TUN interfaces on which inner IPv6 traffic is blocked.
    pub ipv6_drop_interfaces: Vec<String>,
    /// Kernel interface indices captured from the original TUN descriptors.
    pub interface_indices: Option<BTreeMap<String, u32>>,
}

impl RoutingPlan {
    /// Assign stable conntrack IDs while preserving the routing-plan facade.
    pub(crate) fn assign_stable_conntrack_marks(&mut self, history: &mut Vec<RoutingDecision>) -> Result<(), String> {
        conntrack::assign_stable_conntrack_marks(self, history)
    }

    pub(crate) fn validate_conntrack_mark_history(history: &[RoutingDecision]) -> Result<(), String> {
        conntrack::validate_conntrack_mark_history(history)
    }

    /// Build a deterministic plan from a fully validated configuration.
    pub fn from_config(config: &Config) -> Self {
        let egress_names: Vec<_> = config
            .interfaces
            .keys()
            .filter(|name| {
                config
                    .routing
                    .rules
                    .iter()
                    .any(|rule| &rule.egress == *name)
            })
            .map(String::as_str)
            .collect();
        let routing_marks = config
            .resolved_routing_fwmarks()
            .expect("RoutingPlan::from_config requires a validated configuration");
        let egresses: Vec<_> = egress_names
            .iter()
            .enumerate()
            .map(|(index, name)| EgressPlan {
                interface: (*name).to_owned(),
                mark: routing_marks[index],
                table_id: FIRST_ROUTING_TABLE + index as u32,
                ip_rule_priority: FIRST_IP_RULE_PRIORITY + index as u32,
            })
            .collect();

        let egress_marks: BTreeMap<_, _> = egresses
            .iter()
            .map(|egress| (egress.interface.as_str(), egress.mark))
            .collect();

        let mut decisions: Vec<_> = config
            .routing
            .rules
            .iter()
            .map(|rule| RoutingDecision {
                priority: rule.priority,
                ingress: rule.ingress.clone(),
                source: rule.source.clone(),
                destination: rule.destination.clone(),
                egress: rule.egress.clone(),
                routing_mark: egress_marks[rule.egress.as_str()],
                conntrack_mark: 0,
                nat: rule.nat,
                nat_to: rule.nat_to,
            })
            .collect();
        decisions.sort_by(|left, right| {
            left.ingress
                .cmp(&right.ingress)
                .then(left.priority.cmp(&right.priority))
        });
        // Persist the exact selected rule in conntrack. Decisions sharing an
        // egress still need distinct identifiers when their NAT differs.
        for (index, decision) in decisions.iter_mut().enumerate() {
            let decision_id = u32::try_from(index + 1)
                .expect("validated routing decision count must fit in a conntrack mark");
            decision.conntrack_mark = FIRST_CONNTRACK_MARK | (decision_id << 16);
        }

        let to_firewall_rule = |rule: &FirewallRule| NftFirewallRule {
            interface: rule.interface.clone(),
            source: rule.source.clone(),
            destination: rule.destination.clone(),
            protocol: rule.protocol,
            ports: rule.ports.clone(),
        };
        let input_rules = config
            .firewall
            .input
            .rules
            .iter()
            .map(to_firewall_rule)
            .collect();
        let output_rules = config
            .firewall
            .output
            .rules
            .iter()
            .map(to_firewall_rule)
            .collect();

        let mut socket_marks = config
            .resolved_socket_fwmarks()
            .expect("RoutingPlan::from_config requires a validated configuration");
        socket_marks.sort_unstable();

        let managed_interfaces: Vec<_> = config.interfaces.keys().cloned().collect();
        // IPv6 is unsupported by vpn-relay. Keep only a per-TUN drop guard;
        // do not apply IPv6 policy to BoringTun's outer UDP sockets.
        let ipv6_drop_interfaces: Vec<_> = config.interfaces.keys().cloned().collect();

        Self {
            nft_family: "inet".to_owned(),
            nft_table: config.daemon.nft_table.clone(),
            managed_interfaces,
            egresses,
            decisions,
            input_rules,
            output_rules,
            socket_marks,
            ipv6_drop_interfaces,
            interface_indices: None,
        }
    }

    /// Build a drop-only policy for the startup window before TUN descriptors
    /// and their kernel interface indices have been established.
    pub fn fail_closed_bootstrap(&self) -> Self {
        let mut bootstrap = self.clone();
        bootstrap.decisions.clear();
        bootstrap.input_rules.clear();
        bootstrap.output_rules.clear();
        bootstrap
    }

    /// Bind firewall selectors to the kernel identities of the original interfaces.
    pub fn bind_interface_indices(&mut self, indices: BTreeMap<String, u32>) -> Result<(), String> {
        if indices.len() != self.managed_interfaces.len()
            || self
                .managed_interfaces
                .iter()
                .any(|name| indices.get(name).is_none_or(|index| *index == 0))
        {
            return Err("interface index map does not cover all managed interfaces".into());
        }
        let unique: std::collections::BTreeSet<_> = indices.values().copied().collect();
        if unique.len() != indices.len() {
            return Err("two managed interfaces resolved to the same kernel index".into());
        }
        self.interface_indices = Some(indices);
        Ok(())
    }

    /// vpn-relay owns IPv4 policy routing only.
    pub fn ip_families_for_egress(&self, _egress: &EgressPlan) -> &'static [&'static str] {
        &["-4"]
    }

    pub fn ip_policy_families(&self) -> &'static [&'static str] {
        &["-4"]
    }

    pub fn ip_families(_egress: &EgressPlan) -> &'static [&'static str] {
        &["-4"]
    }

    /// Render a fail-closed transit policy. New flows require an explicit
    /// ingress/egress rule and any configured IP selectors; conntrack permits
    /// only their replies. Unmatched packets entering or leaving a managed TUN
    /// are dropped.
    pub fn nft_script(&self) -> String {
        nft::render(self)
    }

    /// Commands needed to populate egress tables and select them by packet
    /// mark. Socket marks explicitly use the main table to avoid tunnel loops.
    pub fn ip_commands(&self) -> Vec<Vec<String>> {
        let mut commands =
            Vec::with_capacity(self.egresses.len() * 4 + self.socket_marks.len() * 2);
        for mark in &self.socket_marks {
            let families: &[&str] = &["-4"];
            for &family in families {
                commands.push(vec![
                    family.into(),
                    "rule".into(),
                    "add".into(),
                    "priority".into(),
                    SOCKET_MAIN_RULE_PRIORITY.to_string(),
                    "fwmark".into(),
                    format!("0x{:x}", mark),
                    "lookup".into(),
                    "main".into(),
                ]);
            }
        }
        for egress in &self.egresses {
            for &family in self.ip_families_for_egress(egress) {
                commands.push(vec![
                    family.into(),
                    "route".into(),
                    "replace".into(),
                    "default".into(),
                    "dev".into(),
                    egress.interface.clone(),
                    "table".into(),
                    egress.table_id.to_string(),
                ]);
                commands.push(vec![
                    family.into(),
                    "rule".into(),
                    "add".into(),
                    "priority".into(),
                    egress.ip_rule_priority.to_string(),
                    "fwmark".into(),
                    format!("0x{:x}", egress.mark),
                    "lookup".into(),
                    egress.table_id.to_string(),
                ]);
            }
        }
        commands
    }
}

#[cfg(test)]
mod tests;
