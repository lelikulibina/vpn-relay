//! Backend-neutral typed nftables firewall objects.
//!
//! This first layer deliberately models only table, sets and base chains.
//! Rules and their expressions are added in the next migration step.

use super::RoutingPlan;
use std::collections::{BTreeSet, HashSet};
use std::error::Error;
use std::fmt;

const TABLE_COMMENT: &str = "managed by vpn-relay";

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

impl RoutingPlan {
    /// Build deterministic table, set and base-chain objects for this plan.
    ///
    /// Numeric selectors are only emitted when the complete, one-to-one map
    /// captured from verified TUN descriptors is available.
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

        let sets = vec![
            FirewallSet {
                name: "managed_interfaces".to_owned(),
                data_type: set_type,
                elements: selectors.clone(),
            },
            FirewallSet {
                name: "ipv6_drop_interfaces".to_owned(),
                data_type: set_type,
                elements: self
                    .ipv6_drop_interfaces
                    .iter()
                    .map(|interface| match &self.interface_indices {
                        Some(indices) => indices
                            .get(interface)
                            .copied()
                            .map(InterfaceSelector::Index)
                            .ok_or(FirewallModelError::IncompleteInterfaceIndexMap),
                        None => Ok(InterfaceSelector::Name(interface.clone())),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            },
        ];

        let chains = [
            ("prerouting", "filter", "mangle"),
            ("input", "filter", "filter"),
            ("forward", "filter", "filter"),
            ("output", "filter", "filter"),
            ("postrouting", "nat", "srcnat"),
        ]
        .into_iter()
        .map(|(name, chain_type, priority)| FirewallChain {
            name: name.to_owned(),
            hook: name.to_owned(),
            chain_type: chain_type.to_owned(),
            priority: priority.to_owned(),
            policy: "accept".to_owned(),
        })
        .collect();

        Ok(FirewallRuleset {
            family: self.nft_family.clone(),
            table: self.nft_table.clone(),
            comment: TABLE_COMMENT.to_owned(),
            sets,
            chains,
            is_bootstrap: self.decisions.is_empty()
                && self.input_rules.is_empty()
                && self.output_rules.is_empty(),
        })
    }
}
