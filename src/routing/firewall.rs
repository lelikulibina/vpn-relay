//! Backend-neutral typed nftables firewall objects and policy rules.

use super::{NftFirewallRule, RoutingDecision, RoutingPlan};
use crate::config::{FirewallProtocol, NatMode};
use std::collections::{BTreeSet, HashSet};
use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;

const TABLE_COMMENT: &str = "managed by vpn-relay";
const CONNTRACK_MARK_MASK: u32 = 0xffff_0000;
const CONNTRACK_MARK_PRESERVE_MASK: u32 = !CONNTRACK_MARK_MASK;
const LOCAL_FLOW_CONNTRACK_MARK: u32 = 0x8000_0000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InterfaceSelector {
    Name(String),
    Index(u32),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirewallSetType {
    IfName,
    IfaceIndex,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FirewallSet {
    pub name: String,
    pub data_type: FirewallSetType,
    pub elements: Vec<InterfaceSelector>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FirewallChain {
    pub name: String,
    pub hook: String,
    pub chain_type: String,
    pub priority: String,
    pub policy: String,
    pub rules: Vec<FirewallRule>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FirewallRuleset {
    pub family: String,
    pub table: String,
    pub comment: String,
    pub sets: Vec<FirewallSet>,
    pub chains: Vec<FirewallChain>,
    pub is_bootstrap: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FirewallModelError {
    IncompleteInterfaceIndexMap,
    ZeroInterfaceIndex { interface: String },
    DuplicateInterfaceIndex { interface: String, index: u32 },
}
impl fmt::Display for FirewallModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteInterfaceIndexMap => write!(
                f,
                "interface index map does not exactly cover managed interfaces"
            ),
            Self::ZeroInterfaceIndex { interface } => {
                write!(f, "interface {interface:?} has a zero kernel index")
            }
            Self::DuplicateInterfaceIndex { interface, index } => {
                write!(f, "interface {interface:?} shares kernel index {index}")
            }
        }
    }
}
impl Error for FirewallModelError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirewallMetaKey {
    IifName,
    OifName,
    Iif,
    Oif,
    NfProto,
    Mark,
    L4Proto,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirewallCtKey {
    Mark,
    State,
    Direction,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirewallCompareOperator {
    Equal,
    NotEqual,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FirewallValue {
    String(String),
    Number(u32),
    State(Vec<String>),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FirewallExpression {
    Meta(FirewallMetaKey),
    Ct(FirewallCtKey),
    Number(u32),
    Payload {
        protocol: String,
        field: String,
    },
    Compare {
        left: Box<FirewallExpression>,
        operator: FirewallCompareOperator,
        right: FirewallValue,
    },
    BitwiseAnd {
        expression: Box<FirewallExpression>,
        mask: u32,
    },
    BitwiseOr {
        left: Box<FirewallExpression>,
        right: Box<FirewallExpression>,
    },
    Set(Vec<FirewallValue>),
    InSet {
        expression: Box<FirewallExpression>,
        set: String,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirewallMangleKey {
    ConntrackMark,
    MetaMark,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FirewallAction {
    Mangle {
        key: FirewallMangleKey,
        value: FirewallExpression,
    },
    Counter,
    Accept,
    Drop,
    Return,
    Masquerade,
    Snat(Ipv4Addr),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FirewallRule {
    pub expressions: Vec<FirewallExpression>,
    pub actions: Vec<FirewallAction>,
}

fn meta(key: FirewallMetaKey) -> FirewallExpression {
    FirewallExpression::Meta(key)
}
fn ct(key: FirewallCtKey) -> FirewallExpression {
    FirewallExpression::Ct(key)
}
fn cmp(
    left: FirewallExpression,
    operator: FirewallCompareOperator,
    right: FirewallValue,
) -> FirewallExpression {
    FirewallExpression::Compare {
        left: Box::new(left),
        operator,
        right,
    }
}
fn eq(left: FirewallExpression, right: FirewallValue) -> FirewallExpression {
    cmp(left, FirewallCompareOperator::Equal, right)
}
fn rule(expressions: Vec<FirewallExpression>, actions: Vec<FirewallAction>) -> FirewallRule {
    FirewallRule {
        expressions,
        actions,
    }
}
fn named(name: &str) -> FirewallValue {
    FirewallValue::String(name.to_owned())
}
fn number(value: u32) -> FirewallValue {
    FirewallValue::Number(value)
}
fn managed(key: FirewallMetaKey) -> FirewallExpression {
    FirewallExpression::InSet {
        expression: Box::new(meta(key)),
        set: "managed_interfaces".into(),
    }
}
fn interface_expr(
    key: FirewallMetaKey,
    name: &str,
    indices: &Option<std::collections::BTreeMap<String, u32>>,
) -> FirewallExpression {
    match indices {
        Some(map) => eq(
            meta(if key == FirewallMetaKey::IifName {
                FirewallMetaKey::Iif
            } else {
                FirewallMetaKey::Oif
            }),
            number(*map.get(name).expect("validated interface index map")),
        ),
        None => eq(meta(key), named(name)),
    }
}
fn managed_expr(key: FirewallMetaKey, _indexed: bool) -> FirewallExpression {
    managed(if key == FirewallMetaKey::IifName && _indexed {
        FirewallMetaKey::Iif
    } else if key == FirewallMetaKey::OifName && _indexed {
        FirewallMetaKey::Oif
    } else {
        key
    })
}
fn host_allow(
    rule: &NftFirewallRule,
    input: bool,
    indices: &Option<std::collections::BTreeMap<String, u32>>,
) -> FirewallRule {
    let key = if input {
        FirewallMetaKey::IifName
    } else {
        FirewallMetaKey::OifName
    };
    let mut expressions = vec![interface_expr(key, &rule.interface, indices)];
    let prefixes = if input {
        &rule.source
    } else {
        &rule.destination
    };
    if let Some(prefixes) = prefixes {
        expressions.push(eq(meta(FirewallMetaKey::NfProto), named("ipv4")));
        if !prefixes.is_empty() {
            expressions.push(FirewallExpression::Payload {
                protocol: "ip".into(),
                field: if input { "saddr" } else { "daddr" }.into(),
            });
            expressions.push(FirewallExpression::Set(
                prefixes.iter().map(|s| named(s)).collect(),
            ));
        }
    }
    if let Some(protocol) = rule.protocol {
        expressions.push(eq(
            meta(FirewallMetaKey::L4Proto),
            named(match protocol {
                FirewallProtocol::Tcp => "tcp",
                FirewallProtocol::Udp => "udp",
                FirewallProtocol::Icmp => "icmp",
            }),
        ));
    }
    if let Some(ports) = &rule.ports {
        expressions.push(FirewallExpression::Payload {
            protocol: "th".into(),
            field: "dport".into(),
        });
        expressions.push(FirewallExpression::Set(
            ports.iter().map(|p| number(*p as u32)).collect(),
        ));
    }
    expressions.extend([
        eq(
            ct(FirewallCtKey::State),
            FirewallValue::State(vec!["new".into(), "established".into(), "related".into()]),
        ),
        eq(ct(FirewallCtKey::Direction), named("original")),
    ]);
    rule_fn(
        expressions,
        vec![
            FirewallAction::Mangle {
                key: FirewallMangleKey::ConntrackMark,
                value: FirewallExpression::BitwiseOr {
                    left: Box::new(FirewallExpression::BitwiseAnd {
                        expression: Box::new(ct(FirewallCtKey::Mark)),
                        mask: CONNTRACK_MARK_PRESERVE_MASK,
                    }),
                    right: Box::new(FirewallExpression::Number(LOCAL_FLOW_CONNTRACK_MARK)),
                },
            },
            FirewallAction::Accept,
        ],
    )
}
fn rule_fn(expressions: Vec<FirewallExpression>, actions: Vec<FirewallAction>) -> FirewallRule {
    rule(expressions, actions)
}
fn nat_expr(
    decision: &RoutingDecision,
    indices: &Option<std::collections::BTreeMap<String, u32>>,
) -> Vec<FirewallExpression> {
    vec![
        interface_expr(FirewallMetaKey::IifName, &decision.ingress, indices),
        interface_expr(FirewallMetaKey::OifName, &decision.egress, indices),
        eq(
            FirewallExpression::BitwiseAnd {
                expression: Box::new(ct(FirewallCtKey::Mark)),
                mask: CONNTRACK_MARK_MASK,
            },
            number(decision.conntrack_mark),
        ),
        eq(meta(FirewallMetaKey::NfProto), named("ipv4")),
    ]
}
fn append_identity_guards(
    rules: &mut Vec<FirewallRule>,
    interfaces: &[String],
    input: bool,
    indices: &std::collections::BTreeMap<String, u32>,
    output: bool,
) {
    for name in interfaces {
        let index = indices[name];
        let (name_key, index_key) = if output {
            (FirewallMetaKey::OifName, FirewallMetaKey::Oif)
        } else {
            (FirewallMetaKey::IifName, FirewallMetaKey::Iif)
        };
        rules.push(rule(
            vec![
                eq(meta(name_key), named(name)),
                cmp(
                    meta(index_key),
                    FirewallCompareOperator::NotEqual,
                    number(index),
                ),
            ],
            vec![FirewallAction::Counter, FirewallAction::Drop],
        ));
        rules.push(rule(
            vec![
                eq(meta(index_key), number(index)),
                cmp(
                    meta(name_key),
                    FirewallCompareOperator::NotEqual,
                    named(name),
                ),
            ],
            vec![FirewallAction::Counter, FirewallAction::Drop],
        ));
    }
    let _ = input;
}
impl RoutingPlan {
    /// Build the complete deterministic typed firewall policy for this routing plan.
    pub(crate) fn firewall_ruleset(&self) -> Result<FirewallRuleset, FirewallModelError> {
        let (set_type, selectors) = match &self.interface_indices {
            None => (
                FirewallSetType::IfName,
                self.managed_interfaces
                    .iter()
                    .cloned()
                    .map(InterfaceSelector::Name)
                    .collect(),
            ),
            Some(indices) => {
                let expected: BTreeSet<_> = self.managed_interfaces.iter().collect();
                let actual: BTreeSet<_> = indices.keys().collect();
                if expected != actual || indices.len() != self.managed_interfaces.len() {
                    return Err(FirewallModelError::IncompleteInterfaceIndexMap);
                }
                let mut seen = HashSet::with_capacity(indices.len());
                let mut selectors = Vec::with_capacity(self.managed_interfaces.len());
                for interface in &self.managed_interfaces {
                    let index = *indices
                        .get(interface)
                        .ok_or(FirewallModelError::IncompleteInterfaceIndexMap)?;
                    if index == 0 {
                        return Err(FirewallModelError::ZeroInterfaceIndex {
                            interface: interface.clone(),
                        });
                    }
                    if !seen.insert(index) {
                        return Err(FirewallModelError::DuplicateInterfaceIndex {
                            interface: interface.clone(),
                            index,
                        });
                    }
                    selectors.push(InterfaceSelector::Index(index));
                }
                (FirewallSetType::IfaceIndex, selectors)
            }
        };
        let ipv6 = self
            .ipv6_drop_interfaces
            .iter()
            .map(|name| match &self.interface_indices {
                Some(map) => map
                    .get(name)
                    .copied()
                    .map(InterfaceSelector::Index)
                    .ok_or(FirewallModelError::IncompleteInterfaceIndexMap),
                None => Ok(InterfaceSelector::Name(name.clone())),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let sets = vec![
            FirewallSet {
                name: "managed_interfaces".into(),
                data_type: set_type,
                elements: selectors,
            },
            FirewallSet {
                name: "ipv6_drop_interfaces".into(),
                data_type: set_type,
                elements: ipv6,
            },
        ];
        let indexed = self.interface_indices.is_some();
        let mut prerouting = Vec::new();
        let mut input = Vec::new();
        let mut forward = Vec::new();
        let mut output = Vec::new();
        let mut postrouting = Vec::new();
        if let Some(indices) = &self.interface_indices {
            append_identity_guards(
                &mut prerouting,
                &self.managed_interfaces,
                false,
                indices,
                false,
            );
            append_identity_guards(&mut input, &self.managed_interfaces, true, indices, false);
            append_identity_guards(
                &mut forward,
                &self.managed_interfaces,
                false,
                indices,
                false,
            );
            append_identity_guards(&mut forward, &self.managed_interfaces, false, indices, true);
            append_identity_guards(&mut output, &self.managed_interfaces, false, indices, true);
        }
        if !self.ipv6_drop_interfaces.is_empty() {
            for (chain, key) in [
                ("prerouting", FirewallMetaKey::IifName),
                ("forward", FirewallMetaKey::OifName),
                ("output", FirewallMetaKey::OifName),
            ] {
                let _ = chain;
                let selector_key = if indexed && key == FirewallMetaKey::IifName {
                    FirewallMetaKey::Iif
                } else if indexed {
                    FirewallMetaKey::Oif
                } else {
                    key
                };
                let expressions = vec![
                    FirewallExpression::InSet {
                        expression: Box::new(meta(selector_key)),
                        set: "ipv6_drop_interfaces".into(),
                    },
                    eq(meta(FirewallMetaKey::NfProto), named("ipv6")),
                ];
                let target = match key {
                    FirewallMetaKey::IifName => &mut prerouting,
                    _ if chain == "forward" => &mut forward,
                    _ => &mut output,
                };
                target.push(rule(
                    expressions,
                    vec![FirewallAction::Counter, FirewallAction::Drop],
                ));
            }
        }
        // INPUT: invalid state, explicit original-direction allows, tagged replies, deny.
        input.push(rule(
            vec![
                managed_expr(FirewallMetaKey::IifName, indexed),
                eq(ct(FirewallCtKey::State), named("invalid")),
            ],
            vec![FirewallAction::Drop],
        ));
        for allow in &self.input_rules {
            input.push(host_allow(allow, true, &self.interface_indices));
        }
        input.push(rule(
            vec![
                managed_expr(FirewallMetaKey::IifName, indexed),
                eq(
                    ct(FirewallCtKey::State),
                    FirewallValue::State(vec!["established".into(), "related".into()]),
                ),
                eq(ct(FirewallCtKey::Direction), named("reply")),
                eq(
                    FirewallExpression::BitwiseAnd {
                        expression: Box::new(ct(FirewallCtKey::Mark)),
                        mask: CONNTRACK_MARK_MASK,
                    },
                    number(LOCAL_FLOW_CONNTRACK_MARK),
                ),
            ],
            vec![FirewallAction::Accept],
        ));
        input.push(rule(
            vec![managed_expr(FirewallMetaKey::IifName, indexed)],
            vec![FirewallAction::Drop],
        ));
        // OUTPUT mirrors INPUT, scoped to actual managed TUN egress.
        output.push(rule(
            vec![
                managed_expr(FirewallMetaKey::OifName, indexed),
                eq(ct(FirewallCtKey::State), named("invalid")),
            ],
            vec![FirewallAction::Drop],
        ));
        for allow in &self.output_rules {
            output.push(host_allow(allow, false, &self.interface_indices));
        }
        output.push(rule(
            vec![
                managed_expr(FirewallMetaKey::OifName, indexed),
                eq(
                    ct(FirewallCtKey::State),
                    FirewallValue::State(vec!["established".into(), "related".into()]),
                ),
                eq(ct(FirewallCtKey::Direction), named("reply")),
                eq(
                    FirewallExpression::BitwiseAnd {
                        expression: Box::new(ct(FirewallCtKey::Mark)),
                        mask: CONNTRACK_MARK_MASK,
                    },
                    number(LOCAL_FLOW_CONNTRACK_MARK),
                ),
            ],
            vec![FirewallAction::Accept],
        ));
        output.push(rule(
            vec![managed_expr(FirewallMetaKey::OifName, indexed)],
            vec![FirewallAction::Drop],
        ));
        // Restore routing marks for original flows and keep replies on the main table.
        prerouting.push(rule(
            vec![managed_expr(FirewallMetaKey::IifName, indexed)],
            vec![FirewallAction::Mangle {
                key: FirewallMangleKey::MetaMark,
                value: FirewallExpression::Number(0),
            }],
        ));
        prerouting.push(rule(
            vec![
                managed_expr(FirewallMetaKey::IifName, indexed),
                eq(
                    ct(FirewallCtKey::State),
                    FirewallValue::State(vec!["established".into(), "related".into()]),
                ),
                eq(ct(FirewallCtKey::Direction), named("reply")),
            ],
            vec![
                FirewallAction::Mangle {
                    key: FirewallMangleKey::MetaMark,
                    value: FirewallExpression::Number(0),
                },
                FirewallAction::Return,
            ],
        ));
        for d in &self.decisions {
            prerouting.push(rule(
                vec![
                    managed_expr(FirewallMetaKey::IifName, indexed),
                    eq(
                        ct(FirewallCtKey::State),
                        FirewallValue::State(vec!["established".into(), "related".into()]),
                    ),
                    eq(ct(FirewallCtKey::Direction), named("original")),
                    eq(
                        FirewallExpression::BitwiseAnd {
                            expression: Box::new(ct(FirewallCtKey::Mark)),
                            mask: CONNTRACK_MARK_MASK,
                        },
                        number(d.conntrack_mark),
                    ),
                ],
                vec![
                    FirewallAction::Mangle {
                        key: FirewallMangleKey::MetaMark,
                        value: FirewallExpression::Number(d.routing_mark),
                    },
                    FirewallAction::Return,
                ],
            ));
        }
        for d in &self.decisions {
            let mut expressions = vec![
                interface_expr(
                    FirewallMetaKey::IifName,
                    &d.ingress,
                    &self.interface_indices,
                ),
                eq(ct(FirewallCtKey::State), named("new")),
            ];
            if let Some(src) = &d.source {
                expressions.push(FirewallExpression::Payload {
                    protocol: "ip".into(),
                    field: "saddr".into(),
                });
                expressions.push(FirewallExpression::Set(
                    src.iter().map(|s| named(s)).collect(),
                ));
            }
            if let Some(dst) = &d.destination {
                expressions.push(FirewallExpression::Payload {
                    protocol: "ip".into(),
                    field: "daddr".into(),
                });
                expressions.push(FirewallExpression::Set(
                    dst.iter().map(|s| named(s)).collect(),
                ));
            }
            prerouting.push(rule(
                expressions,
                vec![
                    FirewallAction::Mangle {
                        key: FirewallMangleKey::MetaMark,
                        value: FirewallExpression::Number(d.routing_mark),
                    },
                    FirewallAction::Mangle {
                        key: FirewallMangleKey::ConntrackMark,
                        value: FirewallExpression::BitwiseOr {
                            left: Box::new(FirewallExpression::BitwiseAnd {
                                expression: Box::new(ct(FirewallCtKey::Mark)),
                                mask: CONNTRACK_MARK_PRESERVE_MASK,
                            }),
                            right: Box::new(FirewallExpression::Number(d.conntrack_mark)),
                        },
                    },
                    FirewallAction::Return,
                ],
            ));
        }
        forward.push(rule(
            vec![
                managed_expr(FirewallMetaKey::IifName, indexed),
                eq(ct(FirewallCtKey::State), named("invalid")),
            ],
            vec![FirewallAction::Drop],
        ));
        for d in &self.decisions {
            forward.push(rule(
                vec![
                    interface_expr(
                        FirewallMetaKey::IifName,
                        &d.ingress,
                        &self.interface_indices,
                    ),
                    interface_expr(FirewallMetaKey::OifName, &d.egress, &self.interface_indices),
                    eq(
                        ct(FirewallCtKey::State),
                        FirewallValue::State(vec![
                            "new".into(),
                            "established".into(),
                            "related".into(),
                        ]),
                    ),
                    eq(meta(FirewallMetaKey::Mark), number(d.routing_mark)),
                ],
                vec![FirewallAction::Accept],
            ));
        }
        for d in &self.decisions {
            forward.push(rule(
                vec![
                    interface_expr(FirewallMetaKey::IifName, &d.egress, &self.interface_indices),
                    interface_expr(
                        FirewallMetaKey::OifName,
                        &d.ingress,
                        &self.interface_indices,
                    ),
                    eq(
                        ct(FirewallCtKey::State),
                        FirewallValue::State(vec!["established".into(), "related".into()]),
                    ),
                    eq(
                        FirewallExpression::BitwiseAnd {
                            expression: Box::new(ct(FirewallCtKey::Mark)),
                            mask: CONNTRACK_MARK_MASK,
                        },
                        number(d.conntrack_mark),
                    ),
                ],
                vec![FirewallAction::Accept],
            ));
        }
        forward.push(rule(
            vec![managed_expr(FirewallMetaKey::IifName, indexed)],
            vec![FirewallAction::Drop],
        ));
        forward.push(rule(
            vec![managed_expr(FirewallMetaKey::OifName, indexed)],
            vec![FirewallAction::Drop],
        ));
        for d in &self.decisions {
            let action = match d.nat {
                NatMode::None => FirewallAction::Return,
                NatMode::Masquerade => FirewallAction::Masquerade,
                NatMode::Snat => FirewallAction::Snat(d.nat_to.expect("validated SNAT decision")),
            };
            postrouting.push(rule(nat_expr(d, &self.interface_indices), vec![action]));
        }
        let chains = [
            ("prerouting", "filter", "mangle", prerouting),
            ("input", "filter", "filter", input),
            ("forward", "filter", "filter", forward),
            ("output", "filter", "filter", output),
            ("postrouting", "nat", "srcnat", postrouting),
        ]
        .into_iter()
        .map(|(name, chain_type, priority, rules)| FirewallChain {
            name: name.into(),
            hook: name.into(),
            chain_type: chain_type.into(),
            priority: priority.into(),
            policy: "accept".into(),
            rules,
        })
        .collect();
        Ok(FirewallRuleset {
            family: self.nft_family.clone(),
            table: self.nft_table.clone(),
            comment: TABLE_COMMENT.into(),
            sets,
            chains,
            is_bootstrap: self.decisions.is_empty()
                && self.input_rules.is_empty()
                && self.output_rules.is_empty(),
        })
    }
}

impl FirewallRuleset {
    /// Convert the supported portion of this model into nftables-rs 0.6.3 schema.
    /// The upstream schema cannot represent table comments or iface_index sets.
    /// Those values are retained by to_json_value; numeric sets are rejected
    /// rather than silently misrepresented as interface-name sets.
    pub(crate) fn to_nftables(&self) -> Result<nftables::schema::Nftables<'static>, String> {
        if self
            .sets
            .iter()
            .any(|set| set.data_type == FirewallSetType::IfaceIndex)
        {
            return Err("nftables 0.6.3 schema does not support iface_index".into());
        }
        let mut value = self.to_json_value().map_err(|error| error.to_string())?;
        if let Some(table) = value["nftables"]
            .as_array_mut()
            .and_then(|objects| objects.first_mut())
            .and_then(|object| object.get_mut("add"))
            .and_then(|add| add.get_mut("table"))
        {
            if let Some(fields) = table.as_object_mut() {
                fields.remove("comment");
            }
        }
        let objects = value["nftables"]
            .as_array()
            .ok_or_else(|| "serialized nftables document has no object array".to_owned())?;
        for (index, object) in objects.iter().enumerate() {
            serde_json::from_value::<nftables::schema::NfObject<'static>>(object.clone())
                .map_err(|error| {
                    format!("nftables object {index} is not supported by nftables 0.6.3: {error}; object={object}")
                })?;
        }
        serde_json::from_value(value).map_err(|error| error.to_string())
    }

    /// Serialize the model and preserve the two compatibility fields absent
    /// from nftables-rs 0.6.3: table ownership comment and iface_index.
    pub(crate) fn to_json_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        use serde_json::{json, Value};

        fn value(value: &FirewallValue) -> Value {
            match value {
                FirewallValue::String(value) => json!(value),
                FirewallValue::Number(value) => json!(value),
                FirewallValue::State(values) => json!({"set": values}),
            }
        }

        fn expression(node: &FirewallExpression) -> Value {
            match node {
                FirewallExpression::Meta(key) => json!({"meta": {"key": match key {
                    FirewallMetaKey::IifName => "iifname",
                    FirewallMetaKey::OifName => "oifname",
                    FirewallMetaKey::Iif => "iif",
                    FirewallMetaKey::Oif => "oif",
                    FirewallMetaKey::NfProto => "nfproto",
                    FirewallMetaKey::Mark => "mark",
                    FirewallMetaKey::L4Proto => "l4proto",
                }}}),
                FirewallExpression::Ct(key) => json!({"ct": {"key": match key {
                    FirewallCtKey::Mark => "mark",
                    FirewallCtKey::State => "state",
                    FirewallCtKey::Direction => "direction",
                }}}),
                FirewallExpression::Number(number) => json!(number),
                FirewallExpression::Payload { protocol, field } => {
                    json!({"payload": {"protocol": protocol, "field": field}})
                }
                FirewallExpression::Compare {
                    left,
                    operator,
                    right,
                } => json!({
                    "match": {
                        "op": match operator {
                            FirewallCompareOperator::Equal => "==",
                            FirewallCompareOperator::NotEqual => "!=",
                        },
                        "left": expression(left),
                        "right": value(right),
                    }
                }),
                FirewallExpression::BitwiseAnd {
                    expression: inner,
                    mask,
                } => {
                    json!({"&": [expression(inner), mask]})
                }
                FirewallExpression::BitwiseOr { left, right } => {
                    json!({"|": [expression(left), expression(right)]})
                }
                FirewallExpression::Set(values) => {
                    json!({"set": values.iter().map(value).collect::<Vec<_>>()})
                }
                FirewallExpression::InSet {
                    expression: inner,
                    set,
                } => json!({
                    "match": {
                        "op": "in",
                        "left": expression(inner),
                        "right": format!("@{}", set),
                    }
                }),
            }
        }

        fn action(action: &FirewallAction) -> Value {
            match action {
                FirewallAction::Mangle { key, value } => json!({
                    "mangle": {
                        "key": match key {
                            FirewallMangleKey::ConntrackMark => json!({"ct": {"key": "mark"}}),
                            FirewallMangleKey::MetaMark => json!({"meta": {"key": "mark"}}),
                        },
                        "value": expression(value),
                    }
                }),
                FirewallAction::Counter => json!({"counter": null}),
                FirewallAction::Accept => json!({"accept": null}),
                FirewallAction::Drop => json!({"drop": null}),
                FirewallAction::Return => json!({"return": null}),
                FirewallAction::Masquerade => json!({"masquerade": null}),
                FirewallAction::Snat(address) => json!({"snat": {"addr": address.to_string()}}),
            }
        }

        let mut objects = vec![json!({"add": {"table": {
            "family": self.family,
            "name": self.table,
            "comment": self.comment,
        }}})];

        for set in &self.sets {
            let data_type = match set.data_type {
                FirewallSetType::IfName => "ifname",
                FirewallSetType::IfaceIndex => "iface_index",
            };
            let elements = set
                .elements
                .iter()
                .map(|selector| match selector {
                    InterfaceSelector::Name(name) => json!(name),
                    InterfaceSelector::Index(index) => json!(index),
                })
                .collect::<Vec<_>>();
            objects.push(json!({"add": {"set": {
                "family": self.family,
                "table": self.table,
                "name": set.name,
                "type": data_type,
                "elem": elements,
            }}}));
        }

        for chain in &self.chains {
            let priority = match chain.priority.as_str() {
                "raw" => -300,
                "mangle" => -150,
                "dstnat" => -100,
                "filter" => 0,
                "security" => 50,
                "srcnat" => 100,
                other => other.parse::<i32>().unwrap_or(0),
            };
            objects.push(json!({"add": {"chain": {
                "family": self.family,
                "table": self.table,
                "name": chain.name,
                "type": chain.chain_type,
                "hook": chain.hook,
                "prio": priority,
                "policy": chain.policy,
            }}}));
        }

        for chain in &self.chains {
            for rule in &chain.rules {
                let mut statements = Vec::with_capacity(rule.expressions.len() + rule.actions.len());
                let mut index = 0;
                while index < rule.expressions.len() {
                    if matches!(
                        (&rule.expressions[index], rule.expressions.get(index + 1)),
                        (FirewallExpression::Payload { .. }, Some(FirewallExpression::Set(_)))
                    ) {
                        statements.push(json!({
                            "match": {
                                "op": "in",
                                "left": expression(&rule.expressions[index]),
                                "right": expression(&rule.expressions[index + 1]),
                            }
                        }));
                        index += 2;
                    } else {
                        statements.push(expression(&rule.expressions[index]));
                        index += 1;
                    }
                }
                statements.extend(rule.actions.iter().map(action));
                objects.push(json!({"add": {"rule": {
                    "family": self.family,
                    "table": self.table,
                    "chain": chain.name,
                    "expr": statements,
                }}}));
            }
        }

        Ok(json!({"nftables": objects}))
    }
}
