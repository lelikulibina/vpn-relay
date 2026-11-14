//! Typed nftables JSON API construction from a validated routing plan.
//!
//! Objects are deserialized into the upstream `nftables` crate schema and
//! assembled with its atomic `Batch`. Version 0.6.3 does not model table
//! comments or the kernel's `iface_index` set datatype; those two wire fields
//! are patched into the serialized JSON only, without introducing local copies
//! of the upstream schema types.

use super::{
    FirewallProtocol, NatAction, RoutingDecision, RoutingPlan, CONNTRACK_MARK_MASK,
    CONNTRACK_MARK_PRESERVE_MASK, LOCAL_FLOW_CONNTRACK_MARK,
};
use nftables::batch::Batch;
use nftables::schema::NfListObject;
use serde_json::{json, Value};
use std::net::Ipv4Addr;

const OWNERSHIP_COMMENT: &str = "managed by vpn-relay";

fn parse_object(value: Value) -> Result<NfListObject<'static>, String> {
    serde_json::from_value(value)
        .map_err(|error| format!("invalid nftables schema object: {error}"))
}

fn add_object(batch: &mut Batch<'static>, value: Value) -> Result<(), String> {
    batch.add(parse_object(value)?);
    Ok(())
}

fn add_rule(
    batch: &mut Batch<'static>,
    plan: &RoutingPlan,
    chain: &str,
    expressions: Vec<Value>,
) -> Result<(), String> {
    add_object(
        batch,
        json!({
            "rule": {
                "family": plan.nft_family,
                "table": plan.nft_table,
                "chain": chain,
                "expr": expressions,
            }
        }),
    )
}

fn add_owner_marker(batch: &mut Batch<'static>, plan: &RoutingPlan) -> Result<(), String> {
    add_object(
        batch,
        json!({
            "chain": {
                "family": plan.nft_family,
                "table": plan.nft_table,
                "name": "vpn_relay_owner",
            }
        }),
    )?;
    add_object(
        batch,
        json!({
            "rule": {
                "family": plan.nft_family,
                "table": plan.nft_table,
                "chain": "vpn_relay_owner",
                "expr": [return_verdict()],
                "comment": OWNERSHIP_COMMENT,
            }
        }),
    )
}

fn add_chain(
    batch: &mut Batch<'static>,
    plan: &RoutingPlan,
    name: &str,
    chain_type: &str,
    hook: &str,
    priority: i32,
) -> Result<(), String> {
    add_object(
        batch,
        json!({
            "chain": {
                "family": plan.nft_family,
                "table": plan.nft_table,
                "name": name,
                "type": chain_type,
                "hook": hook,
                "prio": priority,
                "policy": "accept",
            }
        }),
    )
}

fn meta(key: &str) -> Value {
    json!({ "meta": { "key": key } })
}

fn ct(key: &str) -> Value {
    json!({ "ct": { "key": key } })
}

fn payload(protocol: &str, field: &str) -> Value {
    json!({ "payload": { "protocol": protocol, "field": field } })
}

fn matching(left: Value, operator: &str, right: Value) -> Value {
    json!({ "match": { "left": left, "op": operator, "right": right } })
}

fn in_set(values: Vec<Value>) -> Value {
    json!({ "set": values })
}

fn ct_state(values: &[&str]) -> Value {
    matching(
        ct("state"),
        "in",
        in_set(values.iter().map(|value| json!(value)).collect()),
    )
}

fn ct_direction(direction: &str) -> Value {
    matching(ct("direction"), "==", json!(direction))
}

fn counter() -> Value {
    json!({ "counter": null })
}

fn drop_verdict() -> Value {
    json!({ "drop": null })
}

fn accept_verdict() -> Value {
    json!({ "accept": null })
}

fn return_verdict() -> Value {
    json!({ "return": null })
}

fn mangle(key: Value, value: Value) -> Value {
    json!({ "mangle": { "key": key, "value": value } })
}

fn masked_conntrack_mark() -> Value {
    json!({ "&": [ct("mark"), CONNTRACK_MARK_MASK] })
}

fn conntrack_mark_match(mark: u32) -> Value {
    matching(masked_conntrack_mark(), "==", json!(mark))
}

fn conntrack_mark_write(mark: u32) -> Value {
    mangle(
        ct("mark"),
        json!({
            "|": [
                { "&": [ct("mark"), CONNTRACK_MARK_PRESERVE_MASK] },
                mark,
            ]
        }),
    )
}

fn prefix_expression(prefix: &str) -> Result<Value, String> {
    let (address, length) = prefix.split_once('/').unwrap_or((prefix, "32"));
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|error| format!("invalid IPv4 prefix {prefix}: {error}"))?;
    let length = length
        .parse::<u32>()
        .map_err(|error| format!("invalid IPv4 prefix length in {prefix}: {error}"))?;
    if length > 32 {
        return Err(format!("invalid IPv4 prefix length in {prefix}"));
    }
    Ok(json!({ "prefix": { "addr": address.to_string(), "len": length } }))
}

fn append_prefix_match(
    expressions: &mut Vec<Value>,
    direction: &str,
    prefixes: &[String],
) -> Result<(), String> {
    if prefixes.is_empty() {
        return Ok(());
    }
    let values = prefixes
        .iter()
        .map(|prefix| prefix_expression(prefix))
        .collect::<Result<Vec<_>, _>>()?;
    let (operator, right) = if values.len() == 1 {
        ("==", values.into_iter().next().expect("one prefix"))
    } else {
        ("in", in_set(values))
    };
    expressions.push(matching(payload("ip", direction), operator, right));
    Ok(())
}

fn append_protocol_match(
    expressions: &mut Vec<Value>,
    protocol: Option<FirewallProtocol>,
    ports: Option<&[u16]>,
) -> Result<(), String> {
    match (protocol, ports) {
        (Some(FirewallProtocol::Tcp), None) => {
            expressions.push(matching(meta("l4proto"), "==", json!("tcp")));
        }
        (Some(FirewallProtocol::Udp), None) => {
            expressions.push(matching(meta("l4proto"), "==", json!("udp")));
        }
        (Some(FirewallProtocol::Icmp), None) => {
            expressions.push(matching(meta("l4proto"), "==", json!("icmp")));
        }
        (Some(FirewallProtocol::Tcp), Some(ports)) => {
            append_ports(expressions, "tcp", ports)?;
        }
        (Some(FirewallProtocol::Udp), Some(ports)) => {
            append_ports(expressions, "udp", ports)?;
        }
        (Some(FirewallProtocol::Icmp), Some(_)) => {
            return Err("ICMP firewall rules cannot contain transport ports".into());
        }
        (None, Some(_)) => {
            return Err("firewall ports require an explicit TCP or UDP protocol".into());
        }
        (None, None) => {}
    }
    Ok(())
}

fn append_ports(expressions: &mut Vec<Value>, protocol: &str, ports: &[u16]) -> Result<(), String> {
    if ports.is_empty() {
        return Err("firewall port selector cannot be empty".into());
    }
    let values = ports.iter().map(|port| json!(port)).collect::<Vec<_>>();
    let (operator, right) = if values.len() == 1 {
        ("==", values.into_iter().next().expect("one port"))
    } else {
        ("in", in_set(values))
    };
    expressions.push(matching(payload(protocol, "dport"), operator, right));
    Ok(())
}

fn interface_match(plan: &RoutingPlan, direction: &str, interface: &str) -> Result<Value, String> {
    if let Some(indices) = &plan.interface_indices {
        let index = indices
            .get(interface)
            .ok_or_else(|| format!("missing verified ifindex for managed interface {interface}"))?;
        Ok(matching(meta(direction), "==", json!(index)))
    } else {
        let key = match direction {
            "iif" => "iifname",
            "oif" => "oifname",
            _ => return Err(format!("unsupported interface direction {direction}")),
        };
        Ok(matching(meta(key), "==", json!(interface)))
    }
}

fn managed_set_match(plan: &RoutingPlan, direction: &str, set: &str) -> Result<Value, String> {
    let key = if plan.interface_indices.is_some() {
        direction
    } else {
        match direction {
            "iif" => "iifname",
            "oif" => "oifname",
            _ => return Err(format!("unsupported interface direction {direction}")),
        }
    };
    Ok(matching(meta(key), "in", json!(format!("@{set}"))))
}

fn append_firewall_rule(
    batch: &mut Batch<'static>,
    plan: &RoutingPlan,
    chain: &str,
    direction: &str,
    rule: &super::NftFirewallRule,
    prefixes: Option<&[String]>,
) -> Result<(), String> {
    let mut expressions = vec![interface_match(plan, direction, &rule.interface)?];
    let prefixes = prefixes.unwrap_or_default();
    if prefixes.is_empty() {
        expressions.push(matching(meta("nfproto"), "==", json!("ipv4")));
    } else {
        append_prefix_match(
            &mut expressions,
            if direction == "iif" { "saddr" } else { "daddr" },
            prefixes,
        )?;
    }
    append_protocol_match(&mut expressions, rule.protocol, rule.ports.as_deref())?;
    expressions.push(ct_state(&["new", "established", "related"]));
    expressions.push(ct_direction("original"));
    expressions.push(conntrack_mark_write(LOCAL_FLOW_CONNTRACK_MARK));
    expressions.push(accept_verdict());
    add_rule(batch, plan, chain, expressions)
}

fn append_identity_guards(batch: &mut Batch<'static>, plan: &RoutingPlan) -> Result<(), String> {
    let Some(indices) = &plan.interface_indices else {
        return Ok(());
    };
    for (name, index) in indices {
        for chain in ["prerouting", "input", "forward"] {
            add_rule(
                batch,
                plan,
                chain,
                vec![
                    matching(meta("iifname"), "==", json!(name)),
                    matching(meta("iif"), "!=", json!(index)),
                    counter(),
                    drop_verdict(),
                ],
            )?;
            add_rule(
                batch,
                plan,
                chain,
                vec![
                    matching(meta("iif"), "==", json!(index)),
                    matching(meta("iifname"), "!=", json!(name)),
                    counter(),
                    drop_verdict(),
                ],
            )?;
        }
        for chain in ["forward", "output"] {
            add_rule(
                batch,
                plan,
                chain,
                vec![
                    matching(meta("oifname"), "==", json!(name)),
                    matching(meta("oif"), "!=", json!(index)),
                    counter(),
                    drop_verdict(),
                ],
            )?;
            add_rule(
                batch,
                plan,
                chain,
                vec![
                    matching(meta("oif"), "==", json!(index)),
                    matching(meta("oifname"), "!=", json!(name)),
                    counter(),
                    drop_verdict(),
                ],
            )?;
        }
    }
    Ok(())
}

fn add_managed_interface_set(batch: &mut Batch<'static>, plan: &RoutingPlan) -> Result<(), String> {
    let indexed = plan.interface_indices.is_some();
    let elements = if let Some(indices) = &plan.interface_indices {
        plan.managed_interfaces
            .iter()
            .map(|name| {
                indices
                    .get(name)
                    .copied()
                    .map(|index| json!(index))
                    .ok_or_else(|| format!("missing verified ifindex for managed interface {name}"))
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        plan.managed_interfaces
            .iter()
            .map(|name| json!(name))
            .collect()
    };
    add_object(
        batch,
        json!({
            "set": {
                "family": plan.nft_family,
                "table": plan.nft_table,
                "name": "managed_interfaces",
                // The upstream 0.6.3 SetType enum lacks iface_index. A valid
                // placeholder is patched to the kernel JSON API spelling later.
                "type": if indexed { "mark" } else { "ifname" },
                "elem": elements,
            }
        }),
    )
}

fn add_ipv6_drop_set(batch: &mut Batch<'static>, plan: &RoutingPlan) -> Result<(), String> {
    let indexed = plan.interface_indices.is_some();
    let elements = if let Some(indices) = &plan.interface_indices {
        plan.ipv6_drop_interfaces
            .iter()
            .filter_map(|name| indices.get(name).copied().map(|index| json!(index)))
            .collect::<Vec<_>>()
    } else {
        plan.ipv6_drop_interfaces
            .iter()
            .map(|name| json!(name))
            .collect()
    };
    add_object(
        batch,
        json!({
            "set": {
                "family": plan.nft_family,
                "table": plan.nft_table,
                "name": "ipv6_drop_interfaces",
                "type": if indexed { "mark" } else { "ifname" },
                "elem": elements,
            }
        }),
    )
}

fn append_ipv6_drop_rules(batch: &mut Batch<'static>, plan: &RoutingPlan) -> Result<(), String> {
    if plan.ipv6_drop_interfaces.is_empty() {
        return Ok(());
    }
    add_ipv6_drop_set(batch, plan)?;
    for (chain, direction) in [("prerouting", "iif"), ("forward", "oif"), ("output", "oif")] {
        add_rule(
            batch,
            plan,
            chain,
            vec![
                managed_set_match(plan, direction, "ipv6_drop_interfaces")?,
                matching(meta("nfproto"), "==", json!("ipv6")),
                counter(),
                drop_verdict(),
            ],
        )?;
    }
    Ok(())
}

fn append_decision_prefixes(
    expressions: &mut Vec<Value>,
    decision: &RoutingDecision,
) -> Result<(), String> {
    let sources = decision.source.as_deref().unwrap_or_default();
    let destinations = decision.destination.as_deref().unwrap_or_default();
    if sources.is_empty() && destinations.is_empty() {
        expressions.push(matching(meta("nfproto"), "==", json!("ipv4")));
    }
    append_prefix_match(expressions, "saddr", sources)?;
    append_prefix_match(expressions, "daddr", destinations)?;
    Ok(())
}

fn append_nat_rule(
    batch: &mut Batch<'static>,
    plan: &RoutingPlan,
    decision: &RoutingDecision,
) -> Result<(), String> {
    let mut expressions = vec![
        interface_match(plan, "iif", &decision.ingress)?,
        interface_match(plan, "oif", &decision.egress)?,
        conntrack_mark_match(decision.conntrack_mark),
        matching(meta("nfproto"), "==", json!("ipv4")),
    ];
    match decision.nat_action() {
        NatAction::None => expressions.push(return_verdict()),
        NatAction::Masquerade => expressions.push(json!({ "masquerade": null })),
        NatAction::Snat(address) => expressions.push(json!({
            "snat": { "addr": address.to_string(), "family": "ip" }
        })),
    }
    add_rule(batch, plan, "postrouting", expressions)
}

fn serialize_batch(
    batch: Batch<'static>,
    plan: &RoutingPlan,
    patch_interface_index: bool,
) -> Result<String, String> {
    let mut document = serde_json::to_value(batch.to_nftables())
        .map_err(|error| format!("failed to serialize nftables batch: {error}"))?;
    let objects = document
        .get_mut("nftables")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "serialized nftables batch has no nftables array".to_owned())?;
    for object in objects {
        if patch_interface_index {
            if let Some(set) = object.get_mut("add").and_then(|add| add.get_mut("set")) {
                let name = set.get("name").and_then(Value::as_str);
                if matches!(name, Some("managed_interfaces" | "ipv6_drop_interfaces")) {
                    set["type"] = json!("iface_index");
                }
            }
        }
    }
    serde_json::to_string(&document)
        .map_err(|error| format!("failed to encode nftables JSON batch: {error}"))
}

pub(super) fn render(plan: &RoutingPlan, replace_owned: bool) -> Result<String, String> {
    let mut batch: Batch<'static> = Batch::new();
    let table = parse_object(json!({
        "table": { "family": plan.nft_family, "name": plan.nft_table }
    }))?;
    if replace_owned {
        batch.delete(table.clone());
    }
    batch.add(table);
    add_owner_marker(&mut batch, plan)?;
    add_managed_interface_set(&mut batch, plan)?;
    add_chain(&mut batch, plan, "prerouting", "filter", "prerouting", -150)?;
    add_chain(&mut batch, plan, "input", "filter", "input", 0)?;
    add_chain(&mut batch, plan, "forward", "filter", "forward", 0)?;
    add_chain(&mut batch, plan, "output", "filter", "output", 0)?;
    add_chain(&mut batch, plan, "postrouting", "nat", "postrouting", 100)?;

    // Interface identity guards precede every allow/drop selector.
    append_identity_guards(&mut batch, plan)?;
    append_ipv6_drop_rules(&mut batch, plan)?;

    // Invalid conntrack state must never reach an explicit allow rule.
    add_rule(
        &mut batch,
        plan,
        "input",
        vec![
            managed_set_match(plan, "iif", "managed_interfaces")?,
            matching(ct("state"), "==", json!("invalid")),
            drop_verdict(),
        ],
    )?;
    for rule in &plan.input_rules {
        append_firewall_rule(
            &mut batch,
            plan,
            "input",
            "iif",
            rule,
            rule.source.as_deref(),
        )?;
    }
    add_rule(
        &mut batch,
        plan,
        "input",
        vec![
            managed_set_match(plan, "iif", "managed_interfaces")?,
            ct_state(&["established", "related"]),
            ct_direction("reply"),
            conntrack_mark_match(LOCAL_FLOW_CONNTRACK_MARK),
            accept_verdict(),
        ],
    )?;
    add_rule(
        &mut batch,
        plan,
        "input",
        vec![
            managed_set_match(plan, "iif", "managed_interfaces")?,
            drop_verdict(),
        ],
    )?;

    add_rule(
        &mut batch,
        plan,
        "output",
        vec![
            managed_set_match(plan, "oif", "managed_interfaces")?,
            matching(ct("state"), "==", json!("invalid")),
            drop_verdict(),
        ],
    )?;
    for rule in &plan.output_rules {
        append_firewall_rule(
            &mut batch,
            plan,
            "output",
            "oif",
            rule,
            rule.destination.as_deref(),
        )?;
    }
    add_rule(
        &mut batch,
        plan,
        "output",
        vec![
            managed_set_match(plan, "oif", "managed_interfaces")?,
            ct_state(&["established", "related"]),
            ct_direction("reply"),
            conntrack_mark_match(LOCAL_FLOW_CONNTRACK_MARK),
            accept_verdict(),
        ],
    )?;
    add_rule(
        &mut batch,
        plan,
        "output",
        vec![
            managed_set_match(plan, "oif", "managed_interfaces")?,
            drop_verdict(),
        ],
    )?;

    // Restore the original routing mark for admitted replies; replies use the
    // main table to return through the ingress tunnel.
    add_rule(
        &mut batch,
        plan,
        "prerouting",
        vec![
            managed_set_match(plan, "iif", "managed_interfaces")?,
            mangle(meta("mark"), json!(0)),
        ],
    )?;
    add_rule(
        &mut batch,
        plan,
        "prerouting",
        vec![
            managed_set_match(plan, "iif", "managed_interfaces")?,
            ct_state(&["established", "related"]),
            ct_direction("reply"),
            mangle(meta("mark"), json!(0)),
            return_verdict(),
        ],
    )?;
    for decision in &plan.decisions {
        add_rule(
            &mut batch,
            plan,
            "prerouting",
            vec![
                managed_set_match(plan, "iif", "managed_interfaces")?,
                ct_state(&["established", "related"]),
                ct_direction("original"),
                conntrack_mark_match(decision.conntrack_mark),
                mangle(meta("mark"), json!(decision.routing_mark)),
                return_verdict(),
            ],
        )?;
    }
    for decision in &plan.decisions {
        let mut expressions = vec![
            interface_match(plan, "iif", &decision.ingress)?,
            matching(ct("state"), "==", json!("new")),
        ];
        append_decision_prefixes(&mut expressions, decision)?;
        expressions.push(mangle(meta("mark"), json!(decision.routing_mark)));
        expressions.push(conntrack_mark_write(decision.conntrack_mark));
        expressions.push(return_verdict());
        add_rule(&mut batch, plan, "prerouting", expressions)?;
    }

    add_rule(
        &mut batch,
        plan,
        "forward",
        vec![
            managed_set_match(plan, "iif", "managed_interfaces")?,
            matching(ct("state"), "==", json!("invalid")),
            drop_verdict(),
        ],
    )?;
    for decision in &plan.decisions {
        add_rule(
            &mut batch,
            plan,
            "forward",
            vec![
                interface_match(plan, "iif", &decision.ingress)?,
                interface_match(plan, "oif", &decision.egress)?,
                ct_state(&["new", "established", "related"]),
                matching(meta("mark"), "==", json!(decision.routing_mark)),
                accept_verdict(),
            ],
        )?;
    }
    for decision in &plan.decisions {
        add_rule(
            &mut batch,
            plan,
            "forward",
            vec![
                interface_match(plan, "iif", &decision.egress)?,
                interface_match(plan, "oif", &decision.ingress)?,
                ct_state(&["established", "related"]),
                conntrack_mark_match(decision.conntrack_mark),
                accept_verdict(),
            ],
        )?;
    }
    add_rule(
        &mut batch,
        plan,
        "forward",
        vec![
            managed_set_match(plan, "iif", "managed_interfaces")?,
            drop_verdict(),
        ],
    )?;
    add_rule(
        &mut batch,
        plan,
        "forward",
        vec![
            managed_set_match(plan, "oif", "managed_interfaces")?,
            drop_verdict(),
        ],
    )?;

    for decision in &plan.decisions {
        append_nat_rule(&mut batch, plan, decision)?;
    }

    serialize_batch(batch, plan.interface_indices.is_some())
}

pub(super) fn delete_table(plan: &RoutingPlan) -> Result<String, String> {
    let mut batch: Batch<'static> = Batch::new();
    batch.delete(parse_object(json!({
        "table": { "family": plan.nft_family, "name": plan.nft_table }
    }))?);
    serialize_batch(batch, false)
}
