//! Linux command execution for daemon-owned network resources.
#[cfg(test)]
use crate::routing::RoutingPlan;
use std::process::Command;

mod netlink;
pub use netlink::{ipv4_interface_forwarding, set_ipv4_interface_forwarding};
#[cfg(test)]
use netlink::{
    align_netlink, append_netlink_attribute, build_link_message, netlink_extended_ack,
    parse_link_ipv4_forwarding, set_ipv4_interface_forwarding_with, AF_INET_ATTR, IFLA_AF_SPEC,
    IFLA_INET_CONF, IPV4_DEVCONF_MAX, NLA_F_NESTED, NLA_F_NET_BYTEORDER, NLMSGERR_ATTR_MSG,
    NLMSG_ERROR, NLM_F_ACK, NLM_F_ACK_TLVS, NLM_F_CAPPED, NLM_F_REQUEST, RTM_GETLINK,
    RTM_NEWLINK,
};

mod nftables;
pub use nftables::{apply_nft, remove_nft};
mod policy_routing;
#[cfg(test)]
use nftables::{apply_nft_with, remove_nft_with, table_is_owned};
pub use policy_routing::{
    allocate_policy_routing_resources, apply_egress_policy_routing, apply_policy_routing,
    remove_egress_policy_routing, remove_policy_routing,
};
#[cfg(test)]
use policy_routing::{
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

fn output(program: &str, args: &[String]) -> Result<std::process::Output, LinuxError> {
    Command::new(program)
        .args(args)
        .output()
        .map_err(|source| LinuxError::Spawn {
            program: program.to_owned(),
            source,
        })
}

fn run(program: &str, args: &[String]) -> Result<(), LinuxError> {
    let output = output(program, args)?;
    if output.status.success() {
        return Ok(());
    }
    Err(LinuxError::Command {
        program: format!("{} {}", program, args.join(" ")),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

pub fn run_ip(args: &[String]) -> Result<(), LinuxError> {
    run("ip", args)
}

pub fn interface_index(name: &str) -> Result<u32, LinuxError> {
    let name_c = std::ffi::CString::new(name).map_err(|_| LinuxError::Conflict {
        resource: format!("network interface '{name}'"),
        details: "interface name contains an interior NUL byte".into(),
    })?;
    let index = unsafe { libc::if_nametoindex(name_c.as_ptr()) };
    if index == 0 {
        return Err(LinuxError::Command {
            program: "if_nametoindex".into(),
            status: "failed".into(),
            stderr: std::io::Error::last_os_error().to_string(),
        });
    }
    Ok(index)
}

/// Resolve an interface index back to its current name in this process' network namespace.
/// This reverse lookup is used by durable forwarding-state recovery to avoid
/// restoring sysctls onto a different link that later reused an interface name.
pub fn interface_name(index: u32) -> Result<String, LinuxError> {
    if index == 0 {
        return Err(LinuxError::Conflict {
            resource: "network interface index 0".into(),
            details: "zero is not a valid Linux interface index".into(),
        });
    }
    let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
    let result = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
    if result.is_null() {
        return Err(LinuxError::Command {
            program: "if_indextoname".into(),
            status: "failed".into(),
            stderr: std::io::Error::last_os_error().to_string(),
        });
    }
    let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) };
    Ok(name.to_string_lossy().into_owned())
}

/// Verify both directions of the name/index mapping. A matching name alone is
/// insufficient because Linux may recycle an ifindex after a link disappears.
pub fn verify_interface_identity(name: &str, expected_index: u32) -> Result<(), LinuxError> {
    verify_interface_identity_with(name, expected_index, interface_index, interface_name)
}

fn verify_interface_identity_with(
    name: &str,
    expected_index: u32,
    mut index_for_name: impl FnMut(&str) -> Result<u32, LinuxError>,
    mut name_for_index: impl FnMut(u32) -> Result<String, LinuxError>,
) -> Result<(), LinuxError> {
    let current_index = index_for_name(name)?;
    let current_name = name_for_index(expected_index)?;
    if current_index != expected_index || current_name != name {
        return Err(LinuxError::Conflict {
            resource: format!("network interface '{name}' (ifindex {expected_index})"),
            details: format!(
                "interface identity changed: name resolves to ifindex {current_index}, while saved ifindex resolves to '{current_name}'"
            ),
        });
    }
    Ok(())
}

fn validate_ipv4_interface_addresses(name: &str, addresses: &[String]) -> Result<(), LinuxError> {
    for address in addresses {
        if address.contains(':') {
            return Err(LinuxError::Conflict {
                resource: format!("IPv6 address {address} on interface {name}"),
                details: "vpn-relay supports IPv4 interface addresses only".to_owned(),
            });
        }
    }
    Ok(())
}

pub fn configure_interface(name: &str, mtu: u16, addresses: &[String]) -> Result<(), LinuxError> {
    validate_ipv4_interface_addresses(name, addresses)?;
    run(
        "ip",
        &[
            "link".into(),
            "set".into(),
            "dev".into(),
            name.into(),
            "mtu".into(),
            mtu.to_string(),
            "up".into(),
        ],
    )?;
    for address in addresses {
        run(
            "ip",
            &[
                "-4".into(),
                "address".into(),
                "replace".into(),
                address.clone(),
                "dev".into(),
                name.into(),
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
