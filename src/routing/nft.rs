//! Deterministic nftables policy rendering from a validated routing plan.

use super::*;

pub(super) fn render(plan: &RoutingPlan) -> String {
    let interfaces = plan
        .managed_interfaces
        .iter()
        .map(|interface| format!("\"{}\"", interface))
        .collect::<Vec<_>>()
        .join(", ");

    let mut output = format!(
        "add table {} {} {{ comment \"managed by vpn-relay\"; }}\n\
         add set {} {} managed_interfaces {{ type ifname; elements = {{ {} }}; }}\n\
         add chain {} {} prerouting {{ type filter hook prerouting priority mangle; policy accept; }}\n\
         add chain {} {} input {{ type filter hook input priority filter; policy accept; }}\n\
         add chain {} {} forward {{ type filter hook forward priority filter; policy accept; }}\n\
         add chain {} {} output {{ type filter hook output priority filter; policy accept; }}\n\
         add chain {} {} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}\n",
        plan.nft_family, plan.nft_table,
        plan.nft_family, plan.nft_table, interfaces,
        plan.nft_family, plan.nft_table,
        plan.nft_family, plan.nft_table,
        plan.nft_family, plan.nft_table,
        plan.nft_family, plan.nft_table,
        plan.nft_family, plan.nft_table
    );

    if !plan.ipv6_drop_interfaces.is_empty() {
        let (set_type, elements, input_selector, output_selector) =
            if let Some(indices) = &plan.interface_indices {
                let elements = plan
                    .ipv6_drop_interfaces
                    .iter()
                    .filter_map(|name| indices.get(name))
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                ("iface_index", elements, "iif", "oif")
            } else {
                let elements = plan
                    .ipv6_drop_interfaces
                    .iter()
                    .map(|name| format!("\"{}\"", name))
                    .collect::<Vec<_>>()
                    .join(", ");
                ("ifname", elements, "iifname", "oifname")
            };
        output.push_str(&format!(
            "add set {} {} ipv6_drop_interfaces {{ type {}; elements = {{ {} }}; }}\n",
            plan.nft_family, plan.nft_table, set_type, elements
        ));
        output.push_str(&format!(
            "add rule {} {} prerouting {} @ipv6_drop_interfaces meta nfproto ipv6 counter drop\n",
            plan.nft_family, plan.nft_table, input_selector
        ));
        output.push_str(&format!(
            "add rule {} {} forward {} @ipv6_drop_interfaces meta nfproto ipv6 counter drop\n",
            plan.nft_family, plan.nft_table, output_selector
        ));
        output.push_str(&format!(
            "add rule {} {} output {} @ipv6_drop_interfaces meta nfproto ipv6 counter drop\n",
            plan.nft_family, plan.nft_table, output_selector
        ));
    }

    // Invalid conntrack state must never reach an explicit allow rule.
    // Keep the drop scoped to managed ingress so unrelated host traffic
    // remains outside vpn-relay's firewall ownership.
    output.push_str(&format!(
        "add rule {} {} input iifname @managed_interfaces ct state invalid drop\n",
        plan.nft_family, plan.nft_table
    ));
    // INPUT is scoped to managed ingress. Explicit allow rules admit
    // original-direction client traffic and tag the conntrack entry. The
    // tag prevents unrelated host-initiated flows from being accepted as
    // replies merely because conntrack reports an established state.
    for rule in &plan.input_rules {
        for (family, sources, _) in firewall_rule_family_variants(rule, true) {
            let mut selectors = format!("iifname \"{}\"", rule.interface);
            if let Some(family) = family {
                if sources.is_empty() {
                    selectors.push_str(" meta nfproto ipv4");
                }
                append_cidr_selector(&mut selectors, family, "saddr", &sources);
            }
            append_firewall_protocol_selector(&mut selectors, rule);
            output.push_str(&format!(
                "add rule {} {} input {} ct state new,established,related ct direction original ct mark set (ct mark & 0x{:08x}) | 0x{:08x} accept\n",
                plan.nft_family,
                plan.nft_table,
                selectors,
                CONNTRACK_MARK_PRESERVE_MASK,
                LOCAL_FLOW_CONNTRACK_MARK
            ));
        }
    }
    // Only replies to explicitly admitted host-initiated flows may enter
    // through managed interfaces without a separate INPUT allow rule.
    output.push_str(&format!(
        "add rule {} {} input iifname @managed_interfaces ct state established,related ct direction reply ct mark & 0x{:08x} == 0x{:08x} accept\n",
        plan.nft_family,
        plan.nft_table,
        CONNTRACK_MARK_MASK,
        LOCAL_FLOW_CONNTRACK_MARK
    ));
    output.push_str(&format!(
        "add rule {} {} input iifname @managed_interfaces drop\n",
        plan.nft_family, plan.nft_table
    ));

    // Invalid conntrack state must not be admitted by a broad protocol
    // or address allow rule on a managed TUN egress.
    output.push_str(&format!(
        "add rule {} {} output oifname @managed_interfaces ct state invalid drop\n",
        plan.nft_family, plan.nft_table
    ));
    // OUTPUT is scoped to the actual managed TUN egress. Socket-marked
    // outer UDP routed through the underlay is therefore unaffected.
    for rule in &plan.output_rules {
        for (family, _, destinations) in firewall_rule_family_variants(rule, false) {
            let mut selectors = format!("oifname \"{}\"", rule.interface);
            if let Some(family) = family {
                if destinations.is_empty() {
                    selectors.push_str(" meta nfproto ipv4");
                }
                append_cidr_selector(&mut selectors, family, "daddr", &destinations);
            }
            append_firewall_protocol_selector(&mut selectors, rule);
            output.push_str(&format!(
                "add rule {} {} output {} ct state new,established,related ct direction original ct mark set (ct mark & 0x{:08x}) | 0x{:08x} accept\n",
                plan.nft_family,
                plan.nft_table,
                selectors,
                CONNTRACK_MARK_PRESERVE_MASK,
                LOCAL_FLOW_CONNTRACK_MARK
            ));
        }
    }
    // Permit replies to client-initiated flows only after INPUT admitted
    // their original-direction packets and tagged the conntrack entry.
    output.push_str(&format!(
        "add rule {} {} output oifname @managed_interfaces ct state established,related ct direction reply ct mark & 0x{:08x} == 0x{:08x} accept\n",
        plan.nft_family,
        plan.nft_table,
        CONNTRACK_MARK_MASK,
        LOCAL_FLOW_CONNTRACK_MARK
    ));
    output.push_str(&format!(
        "add rule {} {} output oifname @managed_interfaces drop\n",
        plan.nft_family, plan.nft_table
    ));

    // The reply direction must use the main table to reach the ingress TUN.
    // Original-direction packets restore the egress mark saved on the first
    // packet of the connection.
    output.push_str(&format!(
        "add rule {} {} prerouting iifname @managed_interfaces meta mark set 0\n\
         add rule {} {} prerouting iifname @managed_interfaces ct state established,related ct direction reply meta mark set 0 return\n",
        plan.nft_family, plan.nft_table,
        plan.nft_family, plan.nft_table
    ));
    for decision in &plan.decisions {
        output.push_str(&format!(
            "add rule {} {} prerouting iifname @managed_interfaces ct state established,related ct direction original ct mark & 0x{:08x} == 0x{:08x} meta mark set 0x{:x} return\n",
            plan.nft_family, plan.nft_table, CONNTRACK_MARK_MASK, decision.conntrack_mark, decision.routing_mark
        ));
    }

    for rule in &plan.decisions {
        for (family, sources, destinations) in rule_family_variants(rule) {
            let mut selectors = format!("iifname \"{}\" ct state new", rule.ingress);
            if let Some(family) = family {
                if sources.is_empty() && destinations.is_empty() {
                    selectors.push_str(" meta nfproto ipv4");
                }
                append_cidr_selector(&mut selectors, family, "saddr", &sources);
                append_cidr_selector(&mut selectors, family, "daddr", &destinations);
            }
            output.push_str(&format!(
                "add rule {} {} prerouting {} meta mark set 0x{:x} ct mark set (ct mark & 0x{:08x}) | 0x{:08x} return\n",
                plan.nft_family,
                plan.nft_table,
                selectors,
                rule.routing_mark,
                CONNTRACK_MARK_PRESERVE_MASK,
                rule.conntrack_mark
            ));
        }
    }

    output.push_str(&format!(
        "add rule {} {} forward iifname @managed_interfaces ct state invalid drop\n",
        plan.nft_family, plan.nft_table
    ));
    for rule in &plan.decisions {
        output.push_str(&format!(
            "add rule {} {} forward iifname \"{}\" oifname \"{}\" ct state new,established,related meta mark 0x{:x} accept\n",
            plan.nft_family, plan.nft_table, rule.ingress, rule.egress, rule.routing_mark
        ));
    }
    for rule in &plan.decisions {
        output.push_str(&format!(
            "add rule {} {} forward iifname \"{}\" oifname \"{}\" ct state established,related ct mark & 0x{:08x} == 0x{:08x} accept\n",
            plan.nft_family, plan.nft_table, rule.egress, rule.ingress, CONNTRACK_MARK_MASK, rule.conntrack_mark
        ));
    }
    output.push_str(&format!(
        "add rule {} {} forward iifname @managed_interfaces drop\n\
         add rule {} {} forward oifname @managed_interfaces drop\n",
        plan.nft_family, plan.nft_table, plan.nft_family, plan.nft_table
    ));

    // NAT consumes the selected decision id from conntrack instead of
    // repeating selector matching and risking a different overlapping rule.
    for rule in &plan.decisions {
        let family_guard = " meta nfproto ipv4";
        let selector = format!(
            "iifname \"{}\" oifname \"{}\" ct mark & 0x{:08x} == 0x{:08x}{}",
            rule.ingress, rule.egress, CONNTRACK_MARK_MASK, rule.conntrack_mark, family_guard
        );
        match rule.nat_action() {
            NatAction::None => output.push_str(&format!(
                "add rule {} {} postrouting {} return\n",
                plan.nft_family, plan.nft_table, selector
            )),
            NatAction::Masquerade => output.push_str(&format!(
                "add rule {} {} postrouting {} masquerade\n",
                plan.nft_family, plan.nft_table, selector
            )),
            NatAction::Snat(address) => {
                output.push_str(&format!(
                    "add rule {} {} postrouting {} snat ip to {}\n",
                    plan.nft_family, plan.nft_table, selector, address
                ));
            }
        }
    }

    if let Some(indices) = &plan.interface_indices {
        // Translate every name-based selector and set element only after
        // the runtime has resolved indices from verified TUN descriptors.
        for (name, index) in indices {
            output = output.replace(&format!("\"{name}\""), &index.to_string());
        }
        output = output
            .replace("type ifname;", "type iface_index;")
            .replace("iifname @managed_interfaces", "iif @managed_interfaces")
            .replace("oifname @managed_interfaces", "oif @managed_interfaces")
            .replace("iifname @ipv6_drop_interfaces", "iif @ipv6_drop_interfaces")
            .replace("oifname @ipv6_drop_interfaces", "oif @ipv6_drop_interfaces")
            .replace("iifname", "iif")
            .replace("oifname", "oif");

        // Reject both identity mismatch directions before any allow/drop
        // policy: the configured name resolving to another index, and a
        // different link reusing the configured numeric ifindex.
        let mut guards = String::new();
        for (name, index) in indices {
            guards.push_str(&format!(
                "add rule {} {} prerouting iifname \"{}\" iif != {} counter drop\n\
                 add rule {} {} prerouting iif {} iifname != \"{}\" counter drop\n\
                 add rule {} {} input iifname \"{}\" iif != {} counter drop\n\
                 add rule {} {} input iif {} iifname != \"{}\" counter drop\n\
                 add rule {} {} forward iifname \"{}\" iif != {} counter drop\n\
                 add rule {} {} forward iif {} iifname != \"{}\" counter drop\n\
                 add rule {} {} forward oifname \"{}\" oif != {} counter drop\n\
                 add rule {} {} forward oif {} oifname != \"{}\" counter drop\n\
                 add rule {} {} output oifname \"{}\" oif != {} counter drop\n\
                 add rule {} {} output oif {} oifname != \"{}\" counter drop\n",
                plan.nft_family,
                plan.nft_table,
                name,
                index,
                plan.nft_family,
                plan.nft_table,
                index,
                name,
                plan.nft_family,
                plan.nft_table,
                name,
                index,
                plan.nft_family,
                plan.nft_table,
                index,
                name,
                plan.nft_family,
                plan.nft_table,
                name,
                index,
                plan.nft_family,
                plan.nft_table,
                index,
                name,
                plan.nft_family,
                plan.nft_table,
                name,
                index,
                plan.nft_family,
                plan.nft_table,
                index,
                name,
                plan.nft_family,
                plan.nft_table,
                name,
                index,
                plan.nft_family,
                plan.nft_table,
                index,
                name,
            ));
        }
        let first_rule = output.find("add rule ").unwrap_or(output.len());
        output.insert_str(first_rule, &guards);
    }
    output
}

fn firewall_rule_family_variants(
    rule: &NftFirewallRule,
    input: bool,
) -> Vec<(Option<&'static str>, Vec<String>, Vec<String>)> {
    let prefixes = if input {
        rule.source.as_ref()
    } else {
        rule.destination.as_ref()
    };
    let Some(prefixes) = prefixes else {
        return vec![(Some("ip"), Vec::new(), Vec::new())];
    };
    prefixes
        .iter()
        .map(|prefix| nft_family_match(prefix))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|family| {
            let selected = prefixes
                .iter()
                .filter(|prefix| nft_family_match(prefix) == family)
                .cloned()
                .collect::<Vec<_>>();
            if input {
                (Some(family), selected, Vec::new())
            } else {
                (Some(family), Vec::new(), selected)
            }
        })
        .collect()
}

fn append_firewall_protocol_selector(selectors: &mut String, rule: &NftFirewallRule) {
    if let Some(protocol) = rule.protocol {
        selectors.push_str(match protocol {
            FirewallProtocol::Tcp if rule.ports.is_some() => " tcp",
            FirewallProtocol::Tcp => " meta l4proto tcp",
            FirewallProtocol::Udp if rule.ports.is_some() => " udp",
            FirewallProtocol::Udp => " meta l4proto udp",
            FirewallProtocol::Icmp => " meta l4proto icmp",
        });
    }
    if let Some(ports) = &rule.ports {
        let ports = ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        selectors.push_str(&format!(" dport {{ {ports} }}"));
    }
}

fn nft_family_match(prefix: &str) -> &'static str {
    let _ = prefix;
    "ip"
}

fn rule_family_variants(
    rule: &RoutingDecision,
) -> Vec<(Option<&'static str>, Vec<String>, Vec<String>)> {
    let sources = rule.source.clone().unwrap_or_default();
    let destinations = rule.destination.clone().unwrap_or_default();
    vec![(Some("ip"), sources, destinations)]
}

fn append_cidr_selector(
    selectors: &mut String,
    family: &str,
    direction: &str,
    prefixes: &[String],
) {
    if prefixes.is_empty() {
        return;
    }
    if prefixes.len() == 1 {
        selectors.push_str(&format!(" {} {} {}", family, direction, prefixes[0]));
    } else {
        selectors.push_str(&format!(
            " {} {} {{ {} }}",
            family,
            direction,
            prefixes.join(", ")
        ));
    }
}
