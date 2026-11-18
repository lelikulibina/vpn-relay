use super::*;
use crate::config::FirewallRule as ConfigFirewallRule;

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
fn firewall_model_preserves_table_chain_and_set_identity() {
    let plan = RoutingPlan::from_config(&sample_config());
    let model = plan.firewall_ruleset().unwrap();

    assert_eq!(model.family, "inet");
    assert_eq!(model.table, "vpn_relay");
    assert_eq!(model.comment, "managed by vpn-relay");
    assert_eq!(
        model
            .chains
            .iter()
            .map(|chain| chain.name.as_str())
            .collect::<Vec<_>>(),
        ["prerouting", "input", "forward", "output", "postrouting"]
    );
    assert_eq!(
        model
            .chains
            .iter()
            .map(|chain| chain.hook.as_str())
            .collect::<Vec<_>>(),
        ["prerouting", "input", "forward", "output", "postrouting"]
    );
    assert_eq!(
        model
            .chains
            .iter()
            .map(|chain| chain.chain_type.as_str())
            .collect::<Vec<_>>(),
        ["filter", "filter", "filter", "filter", "nat"]
    );
    assert_eq!(
        model
            .chains
            .iter()
            .map(|chain| chain.priority.as_str())
            .collect::<Vec<_>>(),
        ["mangle", "filter", "filter", "filter", "srcnat"]
    );
    assert!(model.chains.iter().all(|chain| chain.policy == "accept"));

    let managed = model
        .sets
        .iter()
        .find(|set| set.name == "managed_interfaces")
        .unwrap();
    assert_eq!(managed.data_type, FirewallSetType::IfName);
    assert_eq!(
        managed.elements,
        ["awg-primary", "awg-secondary", "wg-server"]
            .into_iter()
            .map(|name| InterfaceSelector::Name(name.to_owned()))
            .collect::<Vec<_>>()
    );

    let ipv6 = model
        .sets
        .iter()
        .find(|set| set.name == "ipv6_drop_interfaces")
        .unwrap();
    assert_eq!(ipv6.data_type, FirewallSetType::IfName);
    assert_eq!(ipv6.elements, managed.elements);

    let mut indexed_plan = RoutingPlan::from_config(&sample_config());
    indexed_plan
        .bind_interface_indices(BTreeMap::from([
            ("wg-server".to_owned(), 17),
            ("awg-primary".to_owned(), 18),
            ("awg-secondary".to_owned(), 19),
        ]))
        .unwrap();
    let indexed = indexed_plan.firewall_ruleset().unwrap();
    let indexed_managed = indexed
        .sets
        .iter()
        .find(|set| set.name == "managed_interfaces")
        .unwrap();
    assert_eq!(indexed_managed.data_type, FirewallSetType::IfaceIndex);
    assert_eq!(
        indexed_managed.elements,
        [
            InterfaceSelector::Index(18),
            InterfaceSelector::Index(19),
            InterfaceSelector::Index(17),
        ]
    );
    let indexed_ipv6 = indexed
        .sets
        .iter()
        .find(|set| set.name == "ipv6_drop_interfaces")
        .unwrap();
    assert_eq!(indexed_ipv6.data_type, FirewallSetType::IfaceIndex);
    assert_eq!(indexed_ipv6.elements, indexed_managed.elements);

    let bootstrap = plan.fail_closed_bootstrap().firewall_ruleset().unwrap();
    assert!(bootstrap.is_bootstrap);
    assert!(bootstrap
        .sets
        .iter()
        .any(|set| set.name == "managed_interfaces"));
    assert!(bootstrap
        .sets
        .iter()
        .any(|set| set.name == "ipv6_drop_interfaces"));
}

#[test]
fn firewall_model_rejects_incomplete_interface_index_map() {
    let mut plan = RoutingPlan::from_config(&sample_config());

    plan.interface_indices = Some(BTreeMap::from([
        ("wg-server".to_owned(), 17),
        ("awg-primary".to_owned(), 18),
    ]));
    assert!(matches!(
        plan.firewall_ruleset(),
        Err(FirewallModelError::IncompleteInterfaceIndexMap)
    ));

    plan.interface_indices = Some(BTreeMap::from([
        ("wg-server".to_owned(), 17),
        ("awg-primary".to_owned(), 0),
        ("awg-secondary".to_owned(), 19),
    ]));
    assert!(matches!(
        plan.firewall_ruleset(),
        Err(FirewallModelError::ZeroInterfaceIndex { .. })
    ));

    plan.interface_indices = Some(BTreeMap::from([
        ("wg-server".to_owned(), 17),
        ("awg-primary".to_owned(), 17),
        ("awg-secondary".to_owned(), 19),
    ]));
    assert!(matches!(
        plan.firewall_ruleset(),
        Err(FirewallModelError::DuplicateInterfaceIndex { .. })
    ));

    plan.interface_indices = Some(BTreeMap::from([
        ("wg-server".to_owned(), 17),
        ("awg-primary".to_owned(), 18),
        ("awg-secondary".to_owned(), 19),
        ("unexpected".to_owned(), 20),
    ]));
    assert!(matches!(
        plan.firewall_ruleset(),
        Err(FirewallModelError::IncompleteInterfaceIndexMap)
    ));
}

#[test]
fn firewall_model_preserves_managed_host_policy_order() {
    let mut config = sample_config();
    config.firewall.input.rules.push(ConfigFirewallRule {
        interface: "wg-server".to_owned(),
        source: None,
        destination: None,
        protocol: Some(FirewallProtocol::Tcp),
        ports: Some(vec![22]),
    });
    config.firewall.output.rules.push(ConfigFirewallRule {
        interface: "awg-secondary".to_owned(),
        source: None,
        destination: None,
        protocol: Some(FirewallProtocol::Udp),
        ports: Some(vec![53]),
    });

    let model = RoutingPlan::from_config(&config)
        .firewall_ruleset()
        .unwrap();
    let input = model
        .chains
        .iter()
        .find(|chain| chain.name == "input")
        .unwrap();
    let output = model
        .chains
        .iter()
        .find(|chain| chain.name == "output")
        .unwrap();

    assert_eq!(input.rules.len(), 4);
    assert_eq!(input.rules[0].actions, [FirewallAction::Drop]);
    assert!(matches!(
        input.rules[1].actions.as_slice(),
        [FirewallAction::Mangle { .. }, FirewallAction::Accept]
    ));
    assert_eq!(input.rules[2].actions, [FirewallAction::Accept]);
    assert_eq!(input.rules[3].actions, [FirewallAction::Drop]);

    // OUTPUT also carries the IPv6 egress guard, before the managed-host
    // conntrack policy. Keep that rule distinct from the invalid-state guard.
    assert_eq!(output.rules.len(), 5);
    assert_eq!(
        output.rules[0].actions,
        [FirewallAction::Counter, FirewallAction::Drop]
    );
    assert!(output.rules[0]
        .expressions
        .iter()
        .any(|expression| matches!(
            expression,
            FirewallExpression::InSet { set, .. } if set == "ipv6_drop_interfaces"
        )));
    assert_eq!(output.rules[1].actions, [FirewallAction::Drop]);
    assert!(matches!(
        output.rules[2].actions.as_slice(),
        [FirewallAction::Mangle { .. }, FirewallAction::Accept]
    ));
    assert_eq!(output.rules[3].actions, [FirewallAction::Accept]);
    assert_eq!(output.rules[4].actions, [FirewallAction::Drop]);

    assert!(input.rules[1].expressions.iter().any(|expression| matches!(
        expression,
        FirewallExpression::Compare {
            left,
            operator: FirewallCompareOperator::Equal,
            right: FirewallValue::String(interface),
        } if matches!(left.as_ref(), FirewallExpression::Meta(FirewallMetaKey::IifName))
            && interface == "wg-server"
    )));
    assert!(output.rules[2]
        .expressions
        .iter()
        .any(|expression| matches!(
            expression,
            FirewallExpression::Compare {
                left,
                operator: FirewallCompareOperator::Equal,
                right: FirewallValue::String(interface),
            } if matches!(left.as_ref(), FirewallExpression::Meta(FirewallMetaKey::OifName))
                && interface == "awg-secondary"
        )));
}

#[test]
fn firewall_model_preserves_conntrack_decision_and_nat_pairing() {
    let mut config = sample_config();
    config.routing.rules[0].nat = NatMode::None;
    config.routing.rules[1].nat = NatMode::Masquerade;
    config.routing.rules[2].nat = NatMode::Snat;
    config.routing.rules[2].nat_to = Some("198.51.100.10".parse().unwrap());

    let plan = RoutingPlan::from_config(&config);
    let model = plan.firewall_ruleset().unwrap();
    let prerouting = model
        .chains
        .iter()
        .find(|chain| chain.name == "prerouting")
        .unwrap();
    let postrouting = model
        .chains
        .iter()
        .find(|chain| chain.name == "postrouting")
        .unwrap();

    assert_eq!(postrouting.rules.len(), plan.decisions.len());
    for (rule, decision) in postrouting.rules.iter().zip(&plan.decisions) {
        assert!(rule.expressions.iter().any(|expression| matches!(
            expression,
            FirewallExpression::Compare {
                left,
                operator: FirewallCompareOperator::Equal,
                right: FirewallValue::Number(mark),
            } if *mark == decision.conntrack_mark
                && matches!(
                    left.as_ref(),
                    FirewallExpression::BitwiseAnd {
                        expression,
                        mask: 0xffff_0000,
                    } if matches!(
                        expression.as_ref(),
                        FirewallExpression::Ct(FirewallCtKey::Mark)
                    )
                )
        )));
        match decision.nat {
            NatMode::None => assert_eq!(rule.actions, [FirewallAction::Return]),
            NatMode::Masquerade => assert_eq!(rule.actions, [FirewallAction::Masquerade]),
            NatMode::Snat => assert_eq!(
                rule.actions,
                [FirewallAction::Snat(decision.nat_to.unwrap())]
            ),
        }
    }

    assert!(prerouting
        .rules
        .iter()
        .any(|rule| rule.actions.iter().any(|action| matches!(
            action,
            FirewallAction::Mangle {
                key: FirewallMangleKey::ConntrackMark,
                value: FirewallExpression::BitwiseOr { .. },
            }
        ))));
    assert!(prerouting
        .rules
        .iter()
        .any(|rule| rule.actions.iter().any(|action| matches!(
            action,
            FirewallAction::Mangle {
                key: FirewallMangleKey::MetaMark,
                value: FirewallExpression::Number(0),
            }
        ))));
}

#[test]
fn firewall_model_preserves_numeric_identity_guards() {
    let mut plan = RoutingPlan::from_config(&sample_config());
    plan.bind_interface_indices(BTreeMap::from([
        ("wg-server".to_owned(), 17),
        ("awg-primary".to_owned(), 18),
        ("awg-secondary".to_owned(), 19),
    ]))
    .unwrap();

    let model = plan.firewall_ruleset().unwrap();
    for (chain_name, name_key, index_key) in [
        ("prerouting", FirewallMetaKey::IifName, FirewallMetaKey::Iif),
        ("input", FirewallMetaKey::IifName, FirewallMetaKey::Iif),
        ("forward", FirewallMetaKey::IifName, FirewallMetaKey::Iif),
        ("forward", FirewallMetaKey::OifName, FirewallMetaKey::Oif),
        ("output", FirewallMetaKey::OifName, FirewallMetaKey::Oif),
    ] {
        let chain = model
            .chains
            .iter()
            .find(|chain| chain.name == chain_name)
            .unwrap();
        let guards: Vec<_> = chain
            .rules
            .iter()
            .filter(|rule| {
                rule.actions == [FirewallAction::Counter, FirewallAction::Drop]
                    && rule.expressions.iter().any(|expression| matches!(
                        expression,
                        FirewallExpression::Compare {
                            left,
                            operator: FirewallCompareOperator::NotEqual,
                            ..
                        } if matches!(left.as_ref(), FirewallExpression::Meta(key) if *key == index_key || *key == name_key)
                    ))
            })
            .collect();

        let name_to_wrong_index: Vec<_> = guards
            .iter()
            .filter(|rule| {
                rule.expressions.iter().any(|expression| matches!(
                    expression,
                    FirewallExpression::Compare {
                        left,
                        operator: FirewallCompareOperator::Equal,
                        right: FirewallValue::String(_),
                    } if matches!(left.as_ref(), FirewallExpression::Meta(key) if *key == name_key)
                )) && rule.expressions.iter().any(|expression| matches!(
                    expression,
                    FirewallExpression::Compare {
                        left,
                        operator: FirewallCompareOperator::NotEqual,
                        right: FirewallValue::Number(_),
                    } if matches!(left.as_ref(), FirewallExpression::Meta(key) if *key == index_key)
                ))
            })
            .collect();
        let wrong_name_to_index: Vec<_> = guards
            .iter()
            .filter(|rule| {
                rule.expressions.iter().any(|expression| matches!(
                    expression,
                    FirewallExpression::Compare {
                        left,
                        operator: FirewallCompareOperator::Equal,
                        right: FirewallValue::Number(_),
                    } if matches!(left.as_ref(), FirewallExpression::Meta(key) if *key == index_key)
                )) && rule.expressions.iter().any(|expression| matches!(
                    expression,
                    FirewallExpression::Compare {
                        left,
                        operator: FirewallCompareOperator::NotEqual,
                        right: FirewallValue::String(_),
                    } if matches!(left.as_ref(), FirewallExpression::Meta(key) if *key == name_key)
                ))
            })
            .collect();

        assert_eq!(
            name_to_wrong_index.len(),
            3,
            "{chain_name} name-to-index guards"
        );
        assert_eq!(
            wrong_name_to_index.len(),
            3,
            "{chain_name} index-to-name guards"
        );
        for (name, index) in [
            ("wg-server", 17),
            ("awg-primary", 18),
            ("awg-secondary", 19),
        ] {
            assert!(
                name_to_wrong_index.iter().any(|rule| {
                    rule.expressions.iter().any(|expression| matches!(
                        expression,
                        FirewallExpression::Compare {
                            left,
                            operator: FirewallCompareOperator::Equal,
                            right: FirewallValue::String(value),
                        } if matches!(left.as_ref(), FirewallExpression::Meta(key) if *key == name_key)
                            && value == name
                    )) && rule.expressions.iter().any(|expression| matches!(
                        expression,
                        FirewallExpression::Compare {
                            left,
                            operator: FirewallCompareOperator::NotEqual,
                            right: FirewallValue::Number(value),
                        } if matches!(left.as_ref(), FirewallExpression::Meta(key) if *key == index_key)
                            && *value == index
                    ))
                }),
                "{chain_name} missing name/index mismatch guard for {name}"
            );
            assert!(
                wrong_name_to_index.iter().any(|rule| {
                    rule.expressions.iter().any(|expression| matches!(
                        expression,
                        FirewallExpression::Compare {
                            left,
                            operator: FirewallCompareOperator::Equal,
                            right: FirewallValue::Number(value),
                        } if matches!(left.as_ref(), FirewallExpression::Meta(key) if *key == index_key)
                            && *value == index
                    )) && rule.expressions.iter().any(|expression| matches!(
                        expression,
                        FirewallExpression::Compare {
                            left,
                            operator: FirewallCompareOperator::NotEqual,
                            right: FirewallValue::String(value),
                        } if matches!(left.as_ref(), FirewallExpression::Meta(key) if *key == name_key)
                            && value == name
                    ))
                }),
                "{chain_name} missing index/name mismatch guard for {name}"
            );
        }
    }
    let forward = model
        .chains
        .iter()
        .find(|chain| chain.name == "forward")
        .unwrap();
    let name_guard_order: Vec<_> = forward
        .rules
        .iter()
        .filter_map(|rule| match rule.expressions.first()? {
            FirewallExpression::Compare {
                left,
                operator: FirewallCompareOperator::Equal,
                right: FirewallValue::String(interface),
            } if matches!(
                left.as_ref(),
                FirewallExpression::Meta(FirewallMetaKey::IifName | FirewallMetaKey::OifName)
            ) =>
            {
                Some(interface.as_str())
            }
            _ => None,
        })
        .filter(|interface| ["awg-primary", "awg-secondary", "wg-server"].contains(interface))
        .collect();
    assert_eq!(
        name_guard_order,
        [
            "awg-primary",
            "awg-primary",
            "awg-secondary",
            "awg-secondary",
            "wg-server",
            "wg-server"
        ]
    );
}

#[test]
fn firewall_model_serializes_typed_nftables_schema() {
    let mut config = sample_config();
    config.firewall.input.rules.push(ConfigFirewallRule {
        interface: "wg-server".to_owned(),
        source: Some(vec!["10.0.0.0/24".to_owned(), "10.1.0.0/24".to_owned()]),
        destination: None,
        protocol: Some(FirewallProtocol::Tcp),
        ports: Some(vec![22, 443]),
    });
    let plan = RoutingPlan::from_config(&config);
    let model = plan.firewall_ruleset().unwrap();
    let schema = model.to_nftables().unwrap();
    let json = serde_json::to_value(schema).unwrap();
    let objects = json["nftables"].as_array().unwrap();

    assert_eq!(objects[0]["add"]["table"]["family"], "inet");
    assert_eq!(objects[0]["add"]["table"]["name"], "vpn_relay");

    let set_positions: Vec<_> = objects
        .iter()
        .enumerate()
        .filter(|(_, object)| object["add"]["set"].is_object())
        .map(|(index, _)| index)
        .collect();
    let chain_positions: Vec<_> = objects
        .iter()
        .enumerate()
        .filter(|(_, object)| object["add"]["chain"].is_object())
        .map(|(index, _)| index)
        .collect();
    let rule_positions: Vec<_> = objects
        .iter()
        .enumerate()
        .filter(|(_, object)| object["add"]["rule"].is_object())
        .map(|(index, _)| index)
        .collect();

    assert_eq!(set_positions.len(), 2);
    assert_eq!(chain_positions.len(), 5);
    assert!(!rule_positions.is_empty());
    assert!(set_positions
        .iter()
        .all(|position| *position < chain_positions[0]));
    assert!(chain_positions
        .iter()
        .all(|position| *position < rule_positions[0]));

    let input_rules: Vec<_> = objects
        .iter()
        .filter_map(|object| {
            let rule = object.get("add")?.get("rule")?;
            (rule["chain"] == "input").then_some(rule)
        })
        .collect();
    assert!(!input_rules.is_empty());
    let expressions: Vec<_> = input_rules
        .iter()
        .flat_map(|rule| rule["expr"].as_array().into_iter().flatten())
        .collect();
    assert!(expressions
        .iter()
        .any(|expression| expression.get("match").is_some()));
    assert!(expressions.iter().any(|expression| {
        expression["match"]["op"] == "in"
            && expression["match"]["left"]["payload"]["protocol"] == "ip"
            && expression["match"]["left"]["payload"]["field"] == "saddr"
            && expression["match"]["right"]["set"]
                == serde_json::json!([
                    {"prefix": {"addr": "10.0.0.0", "len": 24}},
                    {"prefix": {"addr": "10.1.0.0", "len": 24}}
                ])
    }));
    assert!(expressions.iter().any(|expression| {
        expression["match"]["op"] == "in"
            && expression["match"]["left"]["payload"]["protocol"] == "th"
            && expression["match"]["left"]["payload"]["field"] == "dport"
            && expression["match"]["right"]["set"] == serde_json::json!([22, 443])
    }));

    let all_rules: Vec<_> = objects
        .iter()
        .filter_map(|object| object.get("add")?.get("rule"))
        .collect();
    assert!(all_rules.iter().any(|rule| {
        rule["expr"].as_array().is_some_and(|items| {
            items.iter().any(|expression| {
                expression["match"]["left"]["payload"]["protocol"] == "ip"
                    && expression["match"]["right"]["set"]
                        .as_array()
                        .is_some_and(|values| {
                            values.iter().any(|value| value["prefix"].is_object())
                        })
            })
        })
    }));
    assert!(expressions.iter().any(|expression| {
        expression["match"]["op"] == "in"
            && expression["match"]["left"]["ct"]["key"] == "state"
            && expression["match"]["right"] == serde_json::json!(["new", "established", "related"])
    }));
}

#[test]
fn firewall_model_preserves_raw_compatibility_fields() {
    let mut plan = RoutingPlan::from_config(&sample_config());
    plan.bind_interface_indices(BTreeMap::from([
        ("wg-server".to_owned(), 17),
        ("awg-primary".to_owned(), 18),
        ("awg-secondary".to_owned(), 19),
    ]))
    .unwrap();

    let model = plan.firewall_ruleset().unwrap();
    let json = model.to_json_value().unwrap();
    let objects = json["nftables"].as_array().unwrap();

    let table = objects
        .iter()
        .find_map(|object| object.get("add")?.get("table"))
        .unwrap();
    assert_eq!(table["comment"], "managed by vpn-relay");

    let managed_set = objects
        .iter()
        .find_map(|object| {
            let set = object.get("add")?.get("set")?;
            (set["name"] == "managed_interfaces").then_some(set)
        })
        .unwrap();
    assert_eq!(managed_set["type"], "iface_index");
    assert_eq!(managed_set["elem"], serde_json::json!([18, 19, 17]));
}
