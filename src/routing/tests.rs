use super::*;

const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn sample_config() -> Config {
    let toml = format!(
        r#"
[interfaces.wg-server]
type = "wg"
address = ["10.0.0.1/24"]
listen_port = 51820
private_key = "{KEY}"
socket_fwmark = 4097

[interfaces.awg-primary]
type = "awg"
address = ["10.1.0.2/32"]
listen_port = 51821
private_key = "{KEY}"
socket_fwmark = 4098

[interfaces.awg-secondary]
type = "awg"
address = ["10.2.0.2/32"]
listen_port = 51822
private_key = "{KEY}"
socket_fwmark = 4099

[[routing.rules]]
priority = 10
ingress = "wg-server"
destination = "195.142.0.0/16"
egress = "awg-secondary"

[[routing.rules]]
priority = 20
ingress = "wg-server"
destination = "79.100.22.0/24"
egress = "awg-secondary"

[[routing.rules]]
priority = 100
ingress = "wg-server"
destination = "0.0.0.0/0"
egress = "awg-primary"
"#
    );
    Config::parse_toml(&toml).unwrap()
}

#[test]
fn selector_free_routing_firewall_and_masquerade_are_generated() {
    let mut config = sample_config();
    config.routing.rules[0].source = None;
    config.routing.rules[0].destination = None;
    config.routing.rules[0].nat = NatMode::Masquerade;
    config.firewall.input.rules.push(FirewallRule {
        interface: "wg-server".to_owned(),
        source: None,
        destination: None,
        protocol: Some(FirewallProtocol::Tcp),
        ports: Some(vec![22]),
    });
    config.firewall.output.rules.push(FirewallRule {
        interface: "awg-secondary".to_owned(),
        source: None,
        destination: None,
        protocol: Some(FirewallProtocol::Udp),
        ports: Some(vec![53]),
    });

    let script = RoutingPlan::from_config(&config).nft_script();
    assert!(script
        .contains("prerouting iifname \"wg-server\" ct state new meta nfproto ipv4 meta mark"));
    assert!(script.contains("input iifname \"wg-server\" meta nfproto ipv4 tcp dport { 22 }"));
    assert!(script.contains("output oifname \"awg-secondary\" meta nfproto ipv4 udp dport { 53 }"));
    assert!(script.contains("postrouting iifname \"wg-server\" oifname \"awg-secondary\""));
    assert!(script.contains("meta nfproto ipv4 masquerade"));
    assert!(script
        .lines()
        .filter(|line| line.starts_with("add rule inet vpn_relay postrouting"))
        .all(|line| line.contains("meta nfproto ipv4")));
}

#[test]
fn managed_input_and_output_default_to_deny_with_explicit_allow_exceptions() {
    let mut config = sample_config();
    config.firewall.input.rules.push(FirewallRule {
        interface: "wg-server".to_owned(),
        source: Some(vec!["10.0.0.2/32".to_owned()]),
        destination: None,
        protocol: Some(FirewallProtocol::Tcp),
        ports: Some(vec![22, 443]),
    });
    config.firewall.output.rules.push(FirewallRule {
        interface: "awg-primary".to_owned(),
        source: None,
        destination: Some(vec!["10.0.0.0/24".to_owned()]),
        protocol: Some(FirewallProtocol::Udp),
        ports: Some(vec![53]),
    });

    let script = RoutingPlan::from_config(&config).nft_script();
    assert!(script.contains("input iifname \"wg-server\" ip saddr 10.0.0.2/32 tcp dport { 22, 443 } ct state new,established,related ct direction original ct mark set (ct mark & 0x0000ffff) | 0x80000000 accept"));
    assert!(script.contains("input iifname @managed_interfaces ct state invalid drop"));
    assert!(script.contains("output oifname @managed_interfaces ct state invalid drop"));
    assert!(script.contains("input iifname @managed_interfaces ct state established,related ct direction reply ct mark & 0xffff0000 == 0x80000000 accept"));
    assert!(script.contains("input iifname @managed_interfaces drop"));
    assert!(script.contains("output oifname \"awg-primary\" ip daddr 10.0.0.0/24 udp dport { 53 } ct state new,established,related ct direction original ct mark set (ct mark & 0x0000ffff) | 0x80000000 accept"));
    assert!(script.contains("output oifname @managed_interfaces ct state established,related ct direction reply ct mark & 0xffff0000 == 0x80000000 accept"));
    assert!(script.contains("output oifname @managed_interfaces drop"));
    assert!(script.contains("forward iifname @managed_interfaces drop"));
}

#[test]
fn icmp_firewall_rules_use_valid_l4_protocol_selectors() {
    let mut config = sample_config();
    config.firewall.input.rules.push(FirewallRule {
        interface: "wg-server".to_owned(),
        source: Some(vec!["10.0.0.2/32".to_owned()]),
        destination: None,
        protocol: Some(FirewallProtocol::Icmp),
        ports: None,
    });
    config.firewall.output.rules.push(FirewallRule {
        interface: "awg-primary".to_owned(),
        source: None,
        destination: Some(vec!["203.0.113.1/32".to_owned()]),
        protocol: Some(FirewallProtocol::Icmp),
        ports: None,
    });

    let script = RoutingPlan::from_config(&config).nft_script();
    assert!(script
        .contains("input iifname \"wg-server\" ip saddr 10.0.0.2/32 meta l4proto icmp ct state"));
    assert!(script.contains(
        "output oifname \"awg-primary\" ip daddr 203.0.113.1/32 meta l4proto icmp ct state"
    ));
}

#[test]
fn rule_without_source_or_destination_matches_entire_ingress_interface() {
    let mut config = sample_config();
    config.routing.rules[0].source = None;
    config.routing.rules[0].destination = None;
    // Keep this test focused on the selector-free rule. Other rules on
    // the same ingress legitimately contain destination selectors.
    config.routing.rules.truncate(1);
    let script = RoutingPlan::from_config(&config).nft_script();
    assert!(script.contains(
        "prerouting iifname \"wg-server\" ct state new meta nfproto ipv4 meta mark set 0x80000000 ct mark set (ct mark & 0x0000ffff) | 0x50010000 return"
    ));
    assert!(!script.contains("prerouting iifname \"wg-server\" ct state new ip saddr"));
    assert!(!script.contains("prerouting iifname \"wg-server\" ct state new ip daddr"));
    assert!(script.contains(
        "postrouting iifname \"wg-server\" oifname \"awg-secondary\" ct mark & 0xffff0000 == 0x50010000 meta nfproto ipv4 return"
    ));
}

#[test]
fn nft_rule_supports_multiple_cidrs_for_both_selectors() {
    let mut config = sample_config();
    config.routing.rules[0].source = Some(vec!["10.0.0.0/24".to_owned(), "10.1.0.0/24".to_owned()]);
    config.routing.rules[0].destination = Some(vec![
        "195.142.0.0/16".to_owned(),
        "79.100.22.0/24".to_owned(),
    ]);
    let script = RoutingPlan::from_config(&config).nft_script();
    assert!(script.contains("ip saddr { 10.0.0.0/24, 10.1.0.0/24 }"));
    assert!(script.contains("ip daddr { 195.142.0.0/16, 79.100.22.0/24 }"));
}

#[test]
fn bootstrap_firewall_drops_all_managed_traffic_until_descriptors_are_bound() {
    let plan = RoutingPlan::from_config(&sample_config()).fail_closed_bootstrap();
    let script = plan.nft_script();
    assert!(script.contains("input iifname @managed_interfaces drop"));
    assert!(script.contains("output oifname @managed_interfaces drop"));
    assert!(script.contains("forward iifname @managed_interfaces drop"));
    assert!(script.contains("forward oifname @managed_interfaces drop"));
    assert!(!script.contains(" ct direction original ct mark set "));
    assert!(!script.contains(" meta mark set 0x"));
    assert!(!script.contains(" masquerade"));
    assert!(!script.contains(" snat "));
}

#[test]
fn nft_policy_binds_managed_interfaces_to_numeric_kernel_indices() {
    let mut plan = RoutingPlan::from_config(&sample_config());
    plan.bind_interface_indices(BTreeMap::from([
        ("wg-server".to_owned(), 17),
        ("awg-primary".to_owned(), 18),
        ("awg-secondary".to_owned(), 19),
    ]))
    .unwrap();

    let script = plan.nft_script();
    assert!(script.contains("managed_interfaces { type iface_index; elements = { 18, 19, 17 }"));
    assert!(script.contains("ipv6_drop_interfaces { type iface_index; elements = { 18, 19, 17 }"));
    assert!(script.contains("prerouting iif @ipv6_drop_interfaces meta nfproto ipv6 counter drop"));
    assert!(script.contains("forward oif @ipv6_drop_interfaces meta nfproto ipv6 counter drop"));
    assert!(script.contains("output oif @ipv6_drop_interfaces meta nfproto ipv6 counter drop"));
    assert_eq!(script.matches("meta nfproto ipv6").count(), 3);
    assert!(script.contains("prerouting iif 17 ct state new"));
    assert!(script.contains("forward iif 17 oif 18"));
    assert!(script.contains("postrouting iif 17 oif 18"));
    assert!(script.contains("prerouting iifname \"wg-server\" iif != 17 counter drop"));
    assert!(script.contains("prerouting iif 17 iifname != \"wg-server\" counter drop"));
    assert!(script.contains("input iifname \"wg-server\" iif != 17 counter drop"));
    assert!(script.contains("input iif 17 iifname != \"wg-server\" counter drop"));
    assert!(script.contains("forward iifname \"wg-server\" iif != 17 counter drop"));
    assert!(script.contains("forward iif 17 iifname != \"wg-server\" counter drop"));
    assert!(script.contains("forward oifname \"awg-primary\" oif != 18 counter drop"));
    assert!(script.contains("forward oif 18 oifname != \"awg-primary\" counter drop"));
    assert!(script.contains("output oifname \"awg-secondary\" oif != 19 counter drop"));
    assert!(script.contains("output oif 19 oifname != \"awg-secondary\" counter drop"));
    assert!(!script.contains("\\n\\"));
    assert!(!script.contains("type ifname"));
}

#[test]
fn nft_policy_drops_unmatched_managed_interface_transit() {
    let plan = RoutingPlan::from_config(&sample_config());
    let script = plan.nft_script();
    assert!(script.contains("elements = { \"awg-primary\", \"awg-secondary\", \"wg-server\" }"));
    assert!(script.contains("forward iifname @managed_interfaces drop"));
    assert!(script.contains("add chain inet vpn_relay output { type filter hook output priority filter; policy accept; }"));
    assert!(script.contains("forward oifname @managed_interfaces drop"));
    assert!(script.contains("iifname @managed_interfaces meta mark set 0"));
    assert!(script.contains("ct direction reply meta mark set 0"));
    assert!(script.contains(
        "ct direction original ct mark & 0xffff0000 == 0x50010000 meta mark set 0x80000001"
    ));
}

#[test]
fn nft_static_snat_is_emitted_for_ipv4() {
    let mut config = sample_config();
    config.routing.rules[0].nat = NatMode::Snat;
    config.routing.rules[0].nat_to = Some("203.0.113.10".parse().unwrap());
    let script = RoutingPlan::from_config(&config).nft_script();
    assert!(script.contains(
        "postrouting iifname \"wg-server\" oifname \"awg-secondary\" ct mark & 0xffff0000 == 0x50010000 meta nfproto ipv4 snat ip to 203.0.113.10"
    ));
}

#[test]
fn nft_masquerade_is_limited_to_the_selected_rule() {
    let mut config = sample_config();
    config.routing.rules[0].source = Some(vec!["10.0.0.0/24".to_owned()]);
    config.routing.rules[0].nat = NatMode::Masquerade;
    let script = RoutingPlan::from_config(&config).nft_script();
    assert!(script.contains(
        "postrouting iifname \"wg-server\" oifname \"awg-secondary\" ct mark & 0xffff0000 == 0x50010000 meta nfproto ipv4 masquerade"
    ));
    assert!(!script.contains("masquerade return"));
}

#[test]
fn nft_nat_is_rule_scoped_and_disabled_by_default() {
    let plan = RoutingPlan::from_config(&sample_config());
    let script = plan.nft_script();
    assert!(script.contains("postrouting iifname \"wg-server\" oifname \"awg-secondary\""));
    assert!(script.contains("postrouting iifname \"wg-server\" oifname \"awg-primary\""));
    assert!(!script.contains(" masquerade "));
}

#[test]
fn assigns_stable_tables_and_marks_to_egresses() {
    let plan = RoutingPlan::from_config(&sample_config());
    assert_eq!(plan.egresses.len(), 2);
    assert_eq!(plan.egresses[0].interface, "awg-primary");
    assert_eq!(plan.egresses[0].table_id, FIRST_ROUTING_TABLE);
    assert_eq!(plan.egresses[1].interface, "awg-secondary");
    assert_eq!(plan.egresses[1].table_id, FIRST_ROUTING_TABLE + 1);
    assert_eq!(plan.egresses[0].mark, 0x8000_0000);
    assert_eq!(plan.egresses[1].mark, 0x8000_0001);
    assert_ne!(plan.egresses[1].mark, 4099);
}

#[test]
fn routing_plan_guarantees_socket_and_packet_mark_spaces_are_disjoint() {
    let plan = RoutingPlan::from_config(&sample_config());
    let packet_marks: std::collections::HashSet<_> =
        plan.egresses.iter().map(|egress| egress.mark).collect();
    let socket_marks: std::collections::HashSet<_> = plan.socket_marks.iter().copied().collect();

    assert_eq!(packet_marks.len(), plan.egresses.len());
    assert_eq!(socket_marks.len(), plan.socket_marks.len());
    assert!(packet_marks.is_disjoint(&socket_marks));
}

#[test]
fn automatic_socket_marks_skip_the_complete_multi_egress_packet_mark_range() {
    let mut config = sample_config();
    config.routing.mark_base = 0x1000;
    for interface in config.interfaces.values_mut() {
        interface.socket_fwmark = None;
    }

    let plan = RoutingPlan::from_config(&config);
    assert_eq!(
        plan.egresses
            .iter()
            .map(|egress| egress.mark)
            .collect::<Vec<_>>(),
        vec![0x1000, 0x1001]
    );
    assert_eq!(plan.socket_marks, vec![0x1002, 0x1003, 0x1004]);
    assert!(plan.socket_marks.iter().all(|socket_mark| plan
        .egresses
        .iter()
        .all(|egress| egress.mark != *socket_mark)));
}

#[test]
fn routing_plan_uses_automatically_resolved_socket_marks() {
    let mut config = sample_config();
    for interface in config.interfaces.values_mut() {
        interface.socket_fwmark = None;
    }
    let plan = RoutingPlan::from_config(&config);
    assert_eq!(plan.socket_marks, vec![0x1000, 0x1001, 0x1002]);
}

#[test]
fn routing_decisions_preserve_explicit_priority_and_mark_selection() {
    let plan = RoutingPlan::from_config(&sample_config());
    assert_eq!(
        plan.decisions[0].destination.as_deref(),
        Some(&["195.142.0.0/16".to_owned()][..])
    );
    assert_eq!(
        plan.decisions[1].destination.as_deref(),
        Some(&["79.100.22.0/24".to_owned()][..])
    );
    assert_eq!(
        plan.decisions[2].destination.as_deref(),
        Some(&["0.0.0.0/0".to_owned()][..])
    );
    assert_eq!(plan.decisions[0].routing_mark, 0x8000_0001);
    assert_eq!(plan.decisions[0].conntrack_mark, 0x5001_0000);
    assert_eq!(plan.decisions[2].routing_mark, 0x8000_0000);
    assert_eq!(plan.decisions[2].conntrack_mark, 0x5003_0000);
    let script = plan.nft_script();
    assert!(script.contains(
        "ip daddr 195.142.0.0/16 meta mark set 0x80000001 ct mark set (ct mark & 0x0000ffff) | 0x50010000 return"
    ));
    assert!(script.contains("iifname \"wg-server\""));
}

#[test]
fn rejects_overlap_between_inner_packet_and_udp_socket_marks() {
    let mut config = sample_config();
    config.routing.mark_base = 4098;
    assert!(config.validate().is_err());
}

#[test]
fn overlapping_rules_sharing_egress_keep_distinct_conntrack_decisions() {
    let mut config = sample_config();
    config.routing.rules[0].source = None;
    config.routing.rules[0].destination = Some(vec!["0.0.0.0/0".to_owned()]);
    config.routing.rules[0].nat = NatMode::None;
    config.routing.rules[1].source = None;
    config.routing.rules[1].destination = Some(vec!["195.142.0.0/16".to_owned()]);
    config.routing.rules[1].nat = NatMode::Masquerade;

    let plan = RoutingPlan::from_config(&config);
    assert_ne!(
        plan.decisions[0].conntrack_mark,
        plan.decisions[1].conntrack_mark
    );
    assert_eq!(
        plan.decisions[0].routing_mark,
        plan.decisions[1].routing_mark
    );
    let script = plan.nft_script();
    assert!(script.contains(
        "postrouting iifname \"wg-server\" oifname \"awg-secondary\" ct mark & 0xffff0000 == 0x50010000 meta nfproto ipv4 return"
    ));
    assert!(script.contains(
        "postrouting iifname \"wg-server\" oifname \"awg-secondary\" ct mark & 0xffff0000 == 0x50020000 meta nfproto ipv4 masquerade"
    ));
    assert!(!script.contains(
        "postrouting iifname \"wg-server\" oifname \"awg-secondary\" ct mark & 0xffff0000 == 0x50010000 meta nfproto ipv4 masquerade"
    ));
}
#[test]
fn conntrack_decision_marks_are_stable_across_rule_reordering() {
    let original_config = sample_config();
    let original_plan = RoutingPlan::from_config(&original_config);
    let original_marks: Vec<_> = original_plan
        .decisions
        .iter()
        .map(|decision| (decision.priority, decision.conntrack_mark))
        .collect();
    let mut history = original_plan.decisions.clone();

    let mut changed_config = sample_config();
    changed_config.routing.rules[0].priority = 150;
    changed_config.validate().unwrap();
    let mut changed_plan = RoutingPlan::from_config(&changed_config);
    changed_plan
        .assign_stable_conntrack_marks(&mut history)
        .unwrap();

    assert_eq!(
        changed_plan
            .decisions
            .iter()
            .find(|decision| decision.priority == 20)
            .unwrap()
            .conntrack_mark,
        original_marks[1].1
    );
    assert_eq!(
        changed_plan
            .decisions
            .iter()
            .find(|decision| decision.priority == 100)
            .unwrap()
            .conntrack_mark,
        original_marks[2].1
    );
    let changed_mark = changed_plan
        .decisions
        .iter()
        .find(|decision| decision.priority == 150)
        .unwrap()
        .conntrack_mark;
    assert!(!original_marks.iter().any(|(_, mark)| *mark == changed_mark));
    assert_eq!(changed_mark, 0x5004_0000);

    // Restoring an exact historical decision is safe: old conntrack
    // entries still describe the same ingress/selectors/egress/NAT action.
    let mut restored_plan = RoutingPlan::from_config(&original_config);
    restored_plan
        .assign_stable_conntrack_marks(&mut history)
        .unwrap();
    for (decision, (_, mark)) in restored_plan.decisions.iter().zip(original_marks) {
        assert_eq!(decision.conntrack_mark, mark);
    }
}

#[test]
fn conntrack_decision_marks_remain_stable_when_routing_mark_base_changes() {
    let original_config = sample_config();
    let original_plan = RoutingPlan::from_config(&original_config);
    let original_marks: Vec<_> = original_plan
        .decisions
        .iter()
        .map(|decision| decision.conntrack_mark)
        .collect();
    let original_routing_marks: Vec<_> = original_plan
        .decisions
        .iter()
        .map(|decision| decision.routing_mark)
        .collect();
    let mut history = original_plan.decisions.clone();

    let mut changed_config = sample_config();
    changed_config.routing.mark_base = 0x9000_0000;
    changed_config.validate().unwrap();
    let mut changed_plan = RoutingPlan::from_config(&changed_config);
    changed_plan
        .assign_stable_conntrack_marks(&mut history)
        .unwrap();

    assert_eq!(
        changed_plan
            .decisions
            .iter()
            .map(|decision| decision.conntrack_mark)
            .collect::<Vec<_>>(),
        original_marks
    );
    assert_ne!(
        changed_plan
            .decisions
            .iter()
            .map(|decision| decision.routing_mark)
            .collect::<Vec<_>>(),
        original_routing_marks
    );
    assert_eq!(history.len(), original_marks.len());
    RoutingPlan::validate_conntrack_mark_history(&history).unwrap();
}

#[test]
fn legacy_conntrack_marks_remain_valid_but_new_decisions_use_new_namespace() {
    let config = sample_config();
    let mut legacy_history = RoutingPlan::from_config(&config).decisions;
    for (index, decision) in legacy_history.iter_mut().enumerate() {
        decision.conntrack_mark = 0x4000_0000 | (((index as u32) + 1) << 16);
    }
    RoutingPlan::validate_conntrack_mark_history(&legacy_history).unwrap();

    let mut unchanged = RoutingPlan::from_config(&config);
    unchanged
        .assign_stable_conntrack_marks(&mut legacy_history)
        .unwrap();
    for (decision, previous) in unchanged.decisions.iter().zip(&legacy_history) {
        assert_eq!(decision.conntrack_mark, previous.conntrack_mark);
    }

    let mut changed_config = sample_config();
    changed_config.routing.rules[0].priority = 150;
    changed_config.validate().unwrap();
    let mut changed = RoutingPlan::from_config(&changed_config);
    changed
        .assign_stable_conntrack_marks(&mut legacy_history)
        .unwrap();
    let new_decision_mark = changed
        .decisions
        .iter()
        .find(|decision| decision.priority == 150)
        .unwrap()
        .conntrack_mark;
    assert_eq!(new_decision_mark, 0x5001_0000);
}

#[test]
fn conntrack_mark_history_accepts_legacy_routing_mark_aliases() {
    let config = sample_config();
    let mut history = RoutingPlan::from_config(&config).decisions;
    RoutingPlan::from_config(&config)
        .assign_stable_conntrack_marks(&mut history)
        .unwrap();

    let mut legacy_alias = history[0].clone();
    legacy_alias.conntrack_mark = 0x500f_0000;
    legacy_alias.routing_mark = legacy_alias.routing_mark.wrapping_add(0x1000);
    history.push(legacy_alias);
    assert!(RoutingPlan::validate_conntrack_mark_history(&history).is_ok());

    let mut exact_duplicate = history[0].clone();
    exact_duplicate.conntrack_mark = 0x500e_0000;
    history.push(exact_duplicate);
    assert!(RoutingPlan::validate_conntrack_mark_history(&history)
        .unwrap_err()
        .contains("duplicate persisted conntrack decision identity"));
}

#[test]
fn conntrack_mark_history_rejects_duplicate_or_invalid_ids() {
    let mut history = RoutingPlan::from_config(&sample_config()).decisions;
    history[1].conntrack_mark = history[0].conntrack_mark;
    assert!(RoutingPlan::validate_conntrack_mark_history(&history)
        .unwrap_err()
        .contains("invalid or duplicate"));

    let mut history = RoutingPlan::from_config(&sample_config()).decisions;
    history[0].conntrack_mark = 0x8000_0000;
    assert!(RoutingPlan::validate_conntrack_mark_history(&history)
        .unwrap_err()
        .contains("invalid or duplicate"));
}

#[test]
fn policy_routing_commands_use_ipv4_family() {
    let plan = RoutingPlan::from_config(&sample_config());

    assert_eq!(plan.ip_policy_families(), &["-4"]);
    for egress in &plan.egresses {
        assert_eq!(plan.ip_families_for_egress(egress), &["-4"]);
    }
    for command in plan.ip_commands() {
        assert_eq!(command.first().map(String::as_str), Some("-4"));
    }
}

#[test]
fn source_only_and_destination_only_rules_generate_ipv4_matches() {
    let mut config = sample_config();
    config.routing.rules.truncate(2);
    config.routing.rules[0].source = Some(vec!["10.10.0.0/24".to_owned()]);
    config.routing.rules[0].destination = None;
    config.routing.rules[1].source = None;
    config.routing.rules[1].destination = Some(vec!["203.0.113.0/24".to_owned()]);

    let script = RoutingPlan::from_config(&config).nft_script();
    assert!(script.contains("ct state new ip saddr 10.10.0.0/24 meta mark set"));
    assert!(script.contains("ct state new ip daddr 203.0.113.0/24 meta mark set"));
    assert!(script.contains("ip saddr 10.10.0.0/24 meta mark set"));
}

#[test]
fn nft_json_preserves_interface_identity_and_ownership_metadata() {
    let mut plan = RoutingPlan::from_config(&sample_config());
    plan.bind_interface_indices(BTreeMap::from([
        ("wg-server".to_owned(), 11),
        ("awg-primary".to_owned(), 12),
        ("awg-secondary".to_owned(), 13),
    ]))
    .unwrap();

    let document: serde_json::Value =
        serde_json::from_str(&plan.nftables_json(false).unwrap()).unwrap();
    let objects = document["nftables"].as_array().unwrap();
    let table = objects
        .iter()
        .find_map(|object| object.get("add").and_then(|add| add.get("table")))
        .unwrap();
    assert_eq!(table["comment"], "managed by vpn-relay");

    let sets = objects
        .iter()
        .filter_map(|object| object.get("add").and_then(|add| add.get("set")))
        .collect::<Vec<_>>();
    let managed = sets
        .iter()
        .find(|set| set["name"] == "managed_interfaces")
        .unwrap();
    assert_eq!(managed["type"], "iface_index");
    assert_eq!(managed["elem"], serde_json::json!([12, 13, 11]));
    let ipv6 = sets
        .iter()
        .find(|set| set["name"] == "ipv6_drop_interfaces")
        .unwrap();
    assert_eq!(ipv6["type"], "iface_index");
    assert_eq!(ipv6["elem"], serde_json::json!([12, 13, 11]));

    let replace: serde_json::Value =
        serde_json::from_str(&plan.nftables_json(true).unwrap()).unwrap();
    assert!(replace["nftables"][0].get("delete").is_some());
    assert!(replace["nftables"][1]
        .get("add")
        .and_then(|add| add.get("table"))
        .is_some());
}

#[test]
fn nft_json_uses_ifname_sets_before_verified_indices_are_bound() {
    let plan = RoutingPlan::from_config(&sample_config());
    let document: serde_json::Value =
        serde_json::from_str(&plan.nftables_json(false).unwrap()).unwrap();
    let managed = document["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|object| object.get("add").and_then(|add| add.get("set")))
        .unwrap();
    assert_eq!(managed["type"], "ifname");
    assert_eq!(
        managed["elem"],
        serde_json::json!(["awg-primary", "awg-secondary", "wg-server"])
    );
}
