//! Linux command execution for daemon-owned network resources.
mod exec;
mod link;
mod netlink;
mod nft;
mod policy;
pub use exec::run_ip;
#[cfg(test)]
use link::verify_interface_identity_with;
pub use link::{configure_interface, interface_index, interface_name, verify_interface_identity};
#[cfg(test)]
use netlink::{
    align_netlink, append_netlink_attribute, build_link_message, netlink_extended_ack,
    parse_link_ipv4_forwarding, set_ipv4_interface_forwarding_with, AF_INET_ATTR, IFLA_AF_SPEC,
    IFLA_INET_CONF, IPV4_DEVCONF_MAX, NLA_F_NESTED, NLA_F_NET_BYTEORDER, NLMSGERR_ATTR_MSG,
    NLMSG_ERROR, NLM_F_ACK, NLM_F_ACK_TLVS, NLM_F_CAPPED, NLM_F_REQUEST, RTM_NEWLINK,
};
pub use netlink::{ipv4_interface_forwarding, set_ipv4_interface_forwarding};
pub use nft::{apply_nft, remove_nft};
pub use policy::{
    allocate_policy_routing_resources, apply_egress_policy_routing, apply_policy_routing,
    remove_egress_policy_routing, remove_policy_routing,
};
#[cfg(test)]
use policy::{
    apply_egress_policy_routing_with, apply_policy_routing_with, remove_egress_policy_routing_with,
    remove_policy_routing_with, route_has_owned_identity, rule_has_owned_identity,
    rule_matches_fwmark,
};

// Reserved iproute2 protocol tag identifying resources owned by vpn-relay.
const ROUTING_PROTOCOL: &str = "242";

#[derive(Debug, thiserror::Error)]
pub enum LinuxError {
    #[error("failed to execute {program}: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{program} failed ({status}): {stderr}")]
    Command {
        program: String,
        status: String,
        stderr: String,
    },
    #[error("refusing to modify non-daemon network resource {resource}: {details}")]
    Conflict { resource: String, details: String },
    #[error("policy-routing cleanup failed: {0}")]
    Cleanup(String),
    #[error("{operation}; rollback failed: {rollback}")]
    Rollback { operation: String, rollback: String },
}

#[cfg(test)]
mod tests;
