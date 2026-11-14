//! Linux command execution for daemon-owned network resources.
use crate::routing::{RoutingPlan, FIRST_IP_RULE_PRIORITY, FIRST_ROUTING_TABLE};
mod exec;
mod nft;
pub use exec::run_ip;
pub use nft::{apply_nft, remove_nft};
use exec::{output, run};

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

fn rule_has_owned_identity(line: &str, mark: u32, table: &str) -> bool {
    let Some((_, selector)) = line.split_once(':') else {
        return false;
    };
    selector.trim() == format!("from all fwmark 0x{mark:x} lookup {table} proto {ROUTING_PROTOCOL}")
}

fn rule_uses_table(line: &str, table_id: u32) -> bool {
    let fields: Vec<_> = line.split_whitespace().collect();
    let Some(index) = fields.iter().position(|field| *field == "lookup") else {
        return false;
    };
    let table = table_id.to_string();
    fields.get(index + 1).copied() == Some(table.as_str())
}

fn parse_fwmark_value(value: &str) -> Option<u32> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

/// Return true when an ip rule's fwmark selector matches the supplied mark,
/// including selectors that use a partial mask or a wildcard mask.
fn rule_matches_fwmark(line: &str, mark: u32) -> bool {
    let fields: Vec<_> = line.split_whitespace().collect();
    let Some(index) = fields.iter().position(|field| *field == "fwmark") else {
        return false;
    };
    let Some(specification) = fields.get(index + 1) else {
        return false;
    };
    let (value, mask) = specification
        .split_once('/')
        .unwrap_or((specification, "0xffffffff"));
    let (Some(value), Some(mask)) = (parse_fwmark_value(value), parse_fwmark_value(mask)) else {
        return false;
    };
    mark & mask == value & mask
}

fn route_has_owned_identity(line: &str, interface: &str) -> bool {
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() < 5
        || fields[0] != "default"
        || fields[1] != "dev"
        || fields[2] != interface
        || fields[3] != "proto"
        || fields[4] != ROUTING_PROTOCOL
    {
        return false;
    }

    // iproute2 may display kernel-default metric/preference attributes.
    // Accept only those metadata fields; a gateway or other route mutation is
    // not part of the daemon-owned default route identity.
    let mut index = 5;
    while index < fields.len() {
        match fields[index] {
            "scope" if fields.get(index + 1) == Some(&"link") => index += 2,
            "metric"
                if fields
                    .get(index + 1)
                    .is_some_and(|value| value.parse::<u32>().is_ok()) =>
            {
                index += 2;
            }
            "pref"
                if fields
                    .get(index + 1)
                    .is_some_and(|value| matches!(*value, "low" | "medium" | "high")) =>
            {
                index += 2;
            }
            _ => return false,
        }
    }
    true
}

fn ensure_policy_slots_available(plan: &RoutingPlan) -> Result<(), LinuxError> {
    for &family in plan.ip_policy_families() {
        let args = vec![family.into(), "rule".into(), "show".into()];
        let rules = output("ip", &args)?;
        if !rules.status.success() {
            return Err(LinuxError::Command {
                program: format!("ip {}", args.join(" ")),
                status: rules.status.to_string(),
                stderr: String::from_utf8_lossy(&rules.stderr).trim().to_owned(),
            });
        }

        for line in String::from_utf8_lossy(&rules.stdout).lines() {
            let Some((priority, _)) = line.split_once(':') else {
                continue;
            };
            let Ok(priority) = priority.trim().parse::<u32>() else {
                continue;
            };
            for mark in &plan.socket_marks {
                if rule_matches_fwmark(line, *mark) {
                    let expected =
                        priority == 9_000 && rule_has_owned_identity(line, *mark, "main");
                    if !expected {
                        return Err(LinuxError::Conflict {
                            resource: format!("IPv{family} rule matching socket fwmark 0x{mark:x}"),
                            details: line.trim().to_owned(),
                        });
                    }
                }
            }
            for egress in &plan.egresses {
                if rule_uses_table(line, egress.table_id) {
                    let expected = priority == egress.ip_rule_priority
                        && rule_has_owned_identity(line, egress.mark, &egress.table_id.to_string());
                    if !expected {
                        return Err(LinuxError::Conflict {
                            resource: format!(
                                "IPv{family} rule referencing route table {}",
                                egress.table_id
                            ),
                            details: line.trim().to_owned(),
                        });
                    }
                }
                if rule_matches_fwmark(line, egress.mark) {
                    let expected = priority == egress.ip_rule_priority
                        && rule_has_owned_identity(line, egress.mark, &egress.table_id.to_string());
                    if !expected {
                        return Err(LinuxError::Conflict {
                            resource: format!(
                                "IPv{family} rule matching routing fwmark 0x{:x}",
                                egress.mark
                            ),
                            details: line.trim().to_owned(),
                        });
                    }
                }
            }
            if priority == 9_000 {
                let ours = plan
                    .socket_marks
                    .iter()
                    .any(|mark| rule_has_owned_identity(line, *mark, "main"));
                if !ours {
                    return Err(LinuxError::Conflict {
                        resource: format!("IPv{family} rule priority 9000"),
                        details: line.trim().to_owned(),
                    });
                }
            }
            if let Some(egress) = plan
                .egresses
                .iter()
                .find(|egress| egress.ip_rule_priority == priority)
            {
                let expected =
                    rule_has_owned_identity(line, egress.mark, &egress.table_id.to_string());
                if !expected {
                    return Err(LinuxError::Conflict {
                        resource: format!("IPv{family} rule priority {priority}"),
                        details: line.trim().to_owned(),
                    });
                }
            }
        }

        for egress in &plan.egresses {
            let args = vec![
                family.into(),
                "route".into(),
                "show".into(),
                "table".into(),
                egress.table_id.to_string(),
            ];
            let routes = output("ip", &args)?;
            if !routes.status.success() {
                let stderr = String::from_utf8_lossy(&routes.stderr);
                // iproute2 returns status 2 when a routing table has not been
                // created yet. That is the normal first-start state.
                if stderr.contains("FIB table does not exist") {
                    continue;
                }
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: routes.status.to_string(),
                    stderr: stderr.trim().to_owned(),
                });
            }
            for line in String::from_utf8_lossy(&routes.stdout).lines() {
                let owned_route = route_has_owned_identity(line, &egress.interface);
                if !owned_route {
                    return Err(LinuxError::Conflict {
                        resource: format!("IPv{family} route table {}", egress.table_id),
                        details: line.trim().to_owned(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Allocate a second, disjoint set of table IDs and rule priorities for a
/// live routing-plan transition. Existing plans are never reused while active.
pub fn allocate_policy_routing_resources(
    plan: &mut RoutingPlan,
    occupied: &[RoutingPlan],
) -> Result<(), LinuxError> {
    if plan.egresses.is_empty() {
        return Ok(());
    }

    let last_index = u32::try_from(plan.egresses.len() - 1).map_err(|_| LinuxError::Conflict {
        resource: "policy-routing slots".to_owned(),
        details: "egress count does not fit in an iproute2 slot index".to_owned(),
    })?;
    let max_offset = 32_765u32
        .saturating_sub(FIRST_IP_RULE_PRIORITY)
        .saturating_sub(last_index);
    if max_offset < 1_000 {
        return Err(LinuxError::Conflict {
            resource: "policy-routing slots".to_owned(),
            details: "no dynamic rule-priority range remains below the main-table rule".to_owned(),
        });
    }

    for offset in 1_000..=max_offset {
        let mut candidate = plan.clone();
        for (index, egress) in candidate.egresses.iter_mut().enumerate() {
            let slot = offset + index as u32;
            egress.table_id = FIRST_ROUTING_TABLE + slot;
            egress.ip_rule_priority = FIRST_IP_RULE_PRIORITY + slot;
        }

        let overlaps_active_resources = candidate.egresses.iter().any(|candidate_egress| {
            occupied.iter().any(|active| {
                active.egresses.iter().any(|active_egress| {
                    candidate_egress.table_id == active_egress.table_id
                        || candidate_egress.ip_rule_priority == active_egress.ip_rule_priority
                })
            })
        });
        if overlaps_active_resources {
            continue;
        }

        match ensure_policy_slots_available(&candidate) {
            Ok(()) => {
                plan.egresses = candidate.egresses;
                return Ok(());
            }
            Err(LinuxError::Conflict { resource, .. })
                if candidate.egresses.iter().any(|egress| {
                    resource.ends_with(&format!("rule priority {}", egress.ip_rule_priority))
                        || resource.ends_with(&format!("route table {}", egress.table_id))
                }) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    Err(LinuxError::Conflict {
        resource: "dynamic policy-routing slots".to_owned(),
        details: "no unused route-table and rule-priority pair was found".to_owned(),
    })
}

/// Install only egress routes and fwmark rules. Socket-mark rules are deliberately
/// left untouched so they remain continuously active during a plan transition.
pub fn apply_egress_policy_routing(plan: &RoutingPlan) -> Result<(), LinuxError> {
    ensure_policy_slots_available(plan)?;
    apply_egress_policy_routing_with(plan, &mut run)
}

fn apply_egress_policy_routing_with<F>(
    plan: &RoutingPlan,
    run_command: &mut F,
) -> Result<(), LinuxError>
where
    F: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    // Treat the complete multi-egress install as one transaction. Keep the
    // runner injectable so every partial-apply and rollback boundary is tested.
    let install_result = (|| -> Result<(), LinuxError> {
        for egress in &plan.egresses {
            for &family in plan.ip_families_for_egress(egress) {
                let priority = egress.ip_rule_priority.to_string();
                let mark = format!("0x{:x}", egress.mark);
                let table = egress.table_id.to_string();
                let stale_rule = [
                    family.into(),
                    "rule".into(),
                    "del".into(),
                    "priority".into(),
                    priority.clone(),
                    "fwmark".into(),
                    mark.clone(),
                    "lookup".into(),
                    table.clone(),
                    "protocol".into(),
                    ROUTING_PROTOCOL.into(),
                ];
                run_ip_cleanup_with(&stale_rule, run_command)?;
                run_command(
                    "ip",
                    &[
                        family.into(),
                        "route".into(),
                        "replace".into(),
                        "default".into(),
                        "dev".into(),
                        egress.interface.clone(),
                        "table".into(),
                        table.clone(),
                        "proto".into(),
                        ROUTING_PROTOCOL.into(),
                    ],
                )?;
                run_command(
                    "ip",
                    &[
                        family.into(),
                        "rule".into(),
                        "add".into(),
                        "priority".into(),
                        priority,
                        "fwmark".into(),
                        mark,
                        "lookup".into(),
                        table,
                        "protocol".into(),
                        ROUTING_PROTOCOL.into(),
                    ],
                )?;
            }
        }
        Ok(())
    })();

    match install_result {
        Ok(()) => Ok(()),
        Err(operation) => match remove_egress_policy_routing_with(plan, run_command) {
            Ok(()) => Err(operation),
            Err(rollback) => Err(LinuxError::Rollback {
                operation: operation.to_string(),
                rollback: rollback.to_string(),
            }),
        },
    }
}

fn run_ip_cleanup_with<F>(args: &[String], run_command: &mut F) -> Result<(), LinuxError>
where
    F: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    match run_command("ip", args) {
        Ok(()) => Ok(()),
        Err(LinuxError::Command { stderr, .. })
            if stderr.contains("No such file or directory")
                || stderr.contains("No such process")
                || stderr.contains("FIB table does not exist") =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Remove only egress rules/routes tagged with vpn-relay's protocol marker.
/// Missing resources are already clean; any other failure is reported.
fn remove_egress_policy_routing_with<F>(
    plan: &RoutingPlan,
    run_command: &mut F,
) -> Result<(), LinuxError>
where
    F: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    let mut failures = Vec::new();
    for egress in &plan.egresses {
        for &family in plan.ip_policy_families() {
            let rule = [
                family.into(),
                "rule".into(),
                "del".into(),
                "priority".into(),
                egress.ip_rule_priority.to_string(),
                "fwmark".into(),
                format!("0x{:x}", egress.mark),
                "lookup".into(),
                egress.table_id.to_string(),
                "protocol".into(),
                ROUTING_PROTOCOL.into(),
            ];
            if let Err(error) = run_ip_cleanup_with(&rule, run_command) {
                failures.push(error.to_string());
            }

            let route = [
                family.into(),
                "route".into(),
                "del".into(),
                "default".into(),
                "dev".into(),
                egress.interface.clone(),
                "table".into(),
                egress.table_id.to_string(),
                "proto".into(),
                ROUTING_PROTOCOL.into(),
            ];
            if let Err(error) = run_ip_cleanup_with(&route, run_command) {
                failures.push(error.to_string());
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(LinuxError::Cleanup(failures.join("; ")))
    }
}

pub fn remove_egress_policy_routing(plan: &RoutingPlan) -> Result<(), LinuxError> {
    remove_egress_policy_routing_with(plan, &mut run)
}

pub fn apply_policy_routing(plan: &RoutingPlan) -> Result<(), LinuxError> {
    ensure_policy_slots_available(plan)?;
    apply_policy_routing_with(plan, &mut run)
}

fn apply_policy_routing_with<F>(plan: &RoutingPlan, run_command: &mut F) -> Result<(), LinuxError>
where
    F: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    let install_result = (|| -> Result<(), LinuxError> {
        // Remove every stale socket rule before installing any replacement.
        // Interleaving delete/add per family could leave a partially refreshed
        // policy when a later stale-rule deletion fails.
        for mark in &plan.socket_marks {
            for &family in plan.ip_policy_families() {
                let args = vec![
                    family.into(),
                    "rule".into(),
                    "del".into(),
                    "priority".into(),
                    "9000".into(),
                    "fwmark".into(),
                    format!("0x{:x}", mark),
                    "lookup".into(),
                    "main".into(),
                    "protocol".into(),
                    ROUTING_PROTOCOL.into(),
                ];
                run_ip_cleanup_with(&args, run_command)?;
            }
        }
        // Keep marked encrypted UDP transport on the main table.
        for mark in &plan.socket_marks {
            for &family in plan.ip_policy_families() {
                let args = vec![
                    family.into(),
                    "rule".into(),
                    "add".into(),
                    "priority".into(),
                    "9000".into(),
                    "fwmark".into(),
                    format!("0x{:x}", mark),
                    "lookup".into(),
                    "main".into(),
                    "protocol".into(),
                    ROUTING_PROTOCOL.into(),
                ];
                run_command("ip", &args)?;
            }
        }
        apply_egress_policy_routing_with(plan, run_command)
    })();

    match install_result {
        Ok(()) => Ok(()),
        // Egress installation owns its rollback. Only unwind socket rules
        // here, avoiding duplicate route/rule deletions by the outer layer.
        Err(operation) => match remove_socket_mark_rules_with(plan, run_command) {
            Ok(()) => Err(operation),
            Err(rollback) => Err(LinuxError::Rollback {
                operation: operation.to_string(),
                rollback: rollback.to_string(),
            }),
        },
    }
}

fn remove_socket_mark_rules_with<F>(
    plan: &RoutingPlan,
    run_command: &mut F,
) -> Result<(), LinuxError>
where
    F: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    let mut failures = Vec::new();
    for mark in &plan.socket_marks {
        for &family in plan.ip_policy_families() {
            let args = [
                family.into(),
                "rule".into(),
                "del".into(),
                "priority".into(),
                "9000".into(),
                "fwmark".into(),
                format!("0x{:x}", mark),
                "lookup".into(),
                "main".into(),
                "protocol".into(),
                ROUTING_PROTOCOL.into(),
            ];
            if let Err(error) = run_ip_cleanup_with(&args, run_command) {
                failures.push(error.to_string());
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(LinuxError::Cleanup(failures.join("; ")))
    }
}

pub fn remove_policy_routing(plan: &RoutingPlan) -> Result<(), LinuxError> {
    remove_policy_routing_with(plan, &mut run)
}

fn remove_policy_routing_with<F>(plan: &RoutingPlan, run_command: &mut F) -> Result<(), LinuxError>
where
    F: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    let mut failures = Vec::new();
    if let Err(error) = remove_socket_mark_rules_with(plan, run_command) {
        failures.push(error.to_string());
    }
    if let Err(error) = remove_egress_policy_routing_with(plan, run_command) {
        failures.push(error.to_string());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(LinuxError::Cleanup(failures.join("; ")))
    }
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

const NETLINK_ROUTE: libc::c_int = 0;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLMSG_ERROR: u16 = 2;
const NLM_F_CAPPED: u16 = 0x100;
const NLM_F_ACK_TLVS: u16 = 0x200;
const NLMSGERR_ATTR_MSG: u16 = 1;
const SOL_NETLINK: libc::c_int = 270;
const NETLINK_EXT_ACK: libc::c_int = 11;
const IFLA_AF_SPEC: u16 = 26;
const IFLA_INET_CONF: u16 = 1;
const IPV4_DEVCONF_FORWARDING: u16 = 1;
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);
const AF_INET_ATTR: u16 = libc::AF_INET as u16;
#[cfg(test)]
const IPV4_DEVCONF_MAX: usize = 33;

#[repr(C)]
struct NetlinkAddress {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

fn align_netlink(length: usize) -> usize {
    (length + 3) & !3
}

fn append_netlink_attribute(buffer: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let length = 4 + payload.len();
    buffer.extend_from_slice(&(length as u16).to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(payload);
    buffer.resize(align_netlink(buffer.len()), 0);
}

fn build_link_message(
    message_type: u16,
    flags: u16,
    ifindex: u32,
    sequence: u32,
    attributes: &[u8],
) -> Result<Vec<u8>, LinuxError> {
    let index = i32::try_from(ifindex).map_err(|_| LinuxError::Conflict {
        resource: format!("network interface index {ifindex}"),
        details: "ifindex does not fit the rtnetlink interface index field".into(),
    })?;
    let mut message = Vec::with_capacity(32 + attributes.len());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.push(libc::AF_UNSPEC as u8);
    message.push(0);
    message.extend_from_slice(&0u16.to_ne_bytes());
    message.extend_from_slice(&index.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.extend_from_slice(attributes);
    let length = u32::try_from(message.len()).map_err(|_| LinuxError::Conflict {
        resource: "rtnetlink message".into(),
        details: "message length overflow".into(),
    })?;
    message[0..4].copy_from_slice(&length.to_ne_bytes());
    Ok(message)
}

fn netlink_extended_ack(response: &[u8], offset: usize, length: usize) -> Option<String> {
    // NLMSG_ERROR contains the outer header, errno, and the original
    // nlmsghdr before any optional extended-ACK attributes.
    let end = offset.checked_add(length)?;
    if length < 36 || end > response.len() {
        return None;
    }
    let flags = u16::from_ne_bytes(response[offset + 6..offset + 8].try_into().ok()?);
    if flags & NLM_F_ACK_TLVS == 0 {
        return None;
    }
    let original_length =
        u32::from_ne_bytes(response[offset + 20..offset + 24].try_into().ok()?) as usize;
    if original_length < 16 {
        return None;
    }
    let original_payload_length = if flags & NLM_F_CAPPED != 0 {
        16
    } else {
        original_length
    };
    let attributes_offset = offset.checked_add(16 + align_netlink(4 + original_payload_length))?;
    let end = offset.checked_add(length)?;
    if attributes_offset > end {
        return None;
    }
    let mut attributes = &response[attributes_offset..end];
    while !attributes.is_empty() {
        if attributes.len() < 4 {
            return None;
        }
        let attribute_length = u16::from_ne_bytes(attributes[0..2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(attributes[2..4].try_into().ok()?) & NLA_TYPE_MASK;
        if attribute_length < 4 || attribute_length > attributes.len() {
            return None;
        }
        if kind == NLMSGERR_ATTR_MSG {
            let message = attributes[4..attribute_length]
                .split(|byte| *byte == 0)
                .next()?;
            let message = String::from_utf8_lossy(message).trim().to_owned();
            if !message.is_empty() {
                return Some(message);
            }
            return None;
        }
        let aligned = align_netlink(attribute_length);
        if aligned > attributes.len() {
            return None;
        }
        attributes = &attributes[aligned..];
    }
    None
}

fn netlink_request(
    ifindex: u32,
    message_type: u16,
    flags: u16,
    attributes: &[u8],
) -> Result<Vec<u8>, LinuxError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    static NEXT_SEQUENCE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    let sequence = NEXT_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let message = build_link_message(message_type, flags, ifindex, sequence, attributes)?;
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(LinuxError::Spawn {
            program: "rtnetlink socket".into(),
            source: std::io::Error::last_os_error(),
        });
    }
    let socket = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    // Extended ACKs provide kernel-side context (for example, the rejected
    // attribute) when supported. Keep the request functional on older kernels.
    let enabled: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            SOL_NETLINK,
            NETLINK_EXT_ACK,
            &enabled as *const libc::c_int as *const libc::c_void,
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        );
    }
    let local = NetlinkAddress {
        family: libc::AF_NETLINK as u16,
        pad: 0,
        pid: 0,
        groups: 0,
    };
    let bind_result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            &local as *const NetlinkAddress as *const libc::sockaddr,
            std::mem::size_of::<NetlinkAddress>() as libc::socklen_t,
        )
    };
    if bind_result < 0 {
        return Err(LinuxError::Command {
            program: "rtnetlink bind".into(),
            status: "failed".into(),
            stderr: std::io::Error::last_os_error().to_string(),
        });
    }
    let timeout = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    let timeout_result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if timeout_result < 0 {
        return Err(LinuxError::Command {
            program: "rtnetlink receive timeout".into(),
            status: "failed".into(),
            stderr: std::io::Error::last_os_error().to_string(),
        });
    }
    let kernel = NetlinkAddress {
        family: libc::AF_NETLINK as u16,
        pad: 0,
        pid: 0,
        groups: 0,
    };
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            message.as_ptr() as *const libc::c_void,
            message.len(),
            0,
            &kernel as *const NetlinkAddress as *const libc::sockaddr,
            std::mem::size_of::<NetlinkAddress>() as libc::socklen_t,
        )
    };
    if sent < 0 || sent as usize != message.len() {
        return Err(LinuxError::Command {
            program: "rtnetlink send".into(),
            status: "failed".into(),
            stderr: std::io::Error::last_os_error().to_string(),
        });
    }
    let mut response = vec![0u8; 16 * 1024];
    loop {
        let received = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                response.as_mut_ptr() as *mut libc::c_void,
                response.len(),
                0,
            )
        };
        if received < 0 {
            return Err(LinuxError::Command {
                program: "rtnetlink receive".into(),
                status: "failed".into(),
                stderr: std::io::Error::last_os_error().to_string(),
            });
        }
        let received = received as usize;
        let mut offset = 0usize;
        while offset + 16 <= received {
            let length =
                u32::from_ne_bytes(response[offset..offset + 4].try_into().unwrap()) as usize;
            if length < 16 || offset + length > received {
                return Err(LinuxError::Conflict {
                    resource: "rtnetlink response".into(),
                    details: "kernel returned a malformed netlink message".into(),
                });
            }
            let kind = u16::from_ne_bytes(response[offset + 4..offset + 6].try_into().unwrap());
            let seq = u32::from_ne_bytes(response[offset + 8..offset + 12].try_into().unwrap());
            if seq == sequence {
                if kind == NLMSG_ERROR {
                    if length < 20 {
                        return Err(LinuxError::Conflict {
                            resource: "rtnetlink acknowledgement".into(),
                            details: "kernel returned a truncated netlink error".into(),
                        });
                    }
                    let code =
                        i32::from_ne_bytes(response[offset + 16..offset + 20].try_into().unwrap());
                    if code == 0 {
                        return Ok(response[..received].to_vec());
                    }
                    let errno = std::io::Error::from_raw_os_error(-code).to_string();
                    let extended = netlink_extended_ack(&response, offset, length);
                    return Err(LinuxError::Command {
                        program: "rtnetlink request".into(),
                        status: "kernel rejected request".into(),
                        stderr: extended
                            .map_or(errno.clone(), |message| format!("{errno}: {message}")),
                    });
                }
                if message_type == RTM_GETLINK && kind == RTM_NEWLINK {
                    return Ok(response[offset..offset + length].to_vec());
                }
            }
            offset += align_netlink(length);
        }
    }
}

fn parse_link_ipv4_forwarding(response: &[u8], expected_ifindex: u32) -> Result<bool, LinuxError> {
    fn attributes(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, LinuxError> {
        let mut result = Vec::new();
        while !bytes.is_empty() {
            if bytes.len() < 4 {
                return Err(LinuxError::Conflict {
                    resource: "rtnetlink link attributes".into(),
                    details: "truncated attribute header".into(),
                });
            }
            let length = u16::from_ne_bytes(bytes[0..2].try_into().unwrap()) as usize;
            let kind = u16::from_ne_bytes(bytes[2..4].try_into().unwrap()) & !NLA_F_NESTED;
            if length < 4 || length > bytes.len() {
                return Err(LinuxError::Conflict {
                    resource: "rtnetlink link attributes".into(),
                    details: "invalid attribute length".into(),
                });
            }
            result.push((kind, &bytes[4..length]));
            let aligned = align_netlink(length);
            if aligned > bytes.len() {
                if length != bytes.len() {
                    return Err(LinuxError::Conflict {
                        resource: "rtnetlink link attributes".into(),
                        details: "invalid attribute alignment".into(),
                    });
                }
                break;
            }
            bytes = &bytes[aligned..];
        }
        Ok(result)
    }
    if response.len() < 32 {
        return Err(LinuxError::Conflict {
            resource: "rtnetlink link response".into(),
            details: "truncated RTM_NEWLINK response".into(),
        });
    }
    let response_ifindex = i32::from_ne_bytes(response[20..24].try_into().unwrap());
    if response_ifindex <= 0 || response_ifindex as u32 != expected_ifindex {
        return Err(LinuxError::Conflict {
            resource: format!("IPv4 forwarding interface index {expected_ifindex}"),
            details: format!("RTM_GETLINK response identifies ifindex {response_ifindex}"),
        });
    }
    let link_attributes = attributes(&response[32..])?;
    let af_spec = link_attributes
        .iter()
        .find(|(kind, _)| *kind == IFLA_AF_SPEC)
        .ok_or_else(|| LinuxError::Conflict {
            resource: "IPv4 link configuration".into(),
            details: "kernel omitted IFLA_AF_SPEC".into(),
        })?;
    let families = attributes(af_spec.1)?;
    let inet = families
        .iter()
        .find(|(kind, _)| *kind == AF_INET_ATTR)
        .ok_or_else(|| LinuxError::Conflict {
            resource: "IPv4 link configuration".into(),
            details: "kernel omitted AF_INET configuration".into(),
        })?;
    let inet_attributes = attributes(inet.1)?;
    let conf = inet_attributes
        .iter()
        .find(|(kind, _)| *kind == IFLA_INET_CONF)
        .ok_or_else(|| LinuxError::Conflict {
            resource: "IPv4 link configuration".into(),
            details: "kernel omitted IFLA_INET_CONF".into(),
        })?;
    if conf.1.len() < 4 {
        return Err(LinuxError::Conflict {
            resource: "IPv4 link configuration".into(),
            details: "kernel omitted the IPv4 forwarding devconf value".into(),
        });
    }
    match u32::from_ne_bytes(conf.1[0..4].try_into().unwrap()) {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(LinuxError::Conflict {
            resource: "IPv4 forwarding".into(),
            details: format!("kernel returned unexpected forwarding value {value}"),
        }),
    }
}

/// Read IPv4 forwarding by ifindex using RTM_GETLINK (no name-based sysctl lookup).
pub fn ipv4_interface_forwarding(ifindex: u32) -> Result<bool, LinuxError> {
    if ifindex == 0 {
        return Err(LinuxError::Conflict {
            resource: "IPv4 forwarding interface".into(),
            details: "ifindex 0 is not valid".into(),
        });
    }
    let response = netlink_request(ifindex, RTM_GETLINK, NLM_F_REQUEST, &[])?;
    parse_link_ipv4_forwarding(&response, ifindex)
}

/// Set IPv4 forwarding by ifindex using RTM_NEWLINK and verify it with RTM_GETLINK.
///
/// The name/index identity guard is deliberately performed after constructing
/// the netlink attributes and immediately before RTM_NEWLINK. It narrows the
/// userspace race window but cannot make the identity check atomic with the
/// kernel's later ifindex lookup. The post-ACK readback is followed by another
/// identity check so a replacement link is not silently accepted as the owner.
pub fn set_ipv4_interface_forwarding(
    name: &str,
    ifindex: u32,
    enabled: bool,
) -> Result<(), LinuxError> {
    set_ipv4_interface_forwarding_with(
        name,
        ifindex,
        enabled,
        verify_interface_identity,
        netlink_request,
        ipv4_interface_forwarding,
    )
}

fn set_ipv4_interface_forwarding_with(
    name: &str,
    ifindex: u32,
    enabled: bool,
    mut verify: impl FnMut(&str, u32) -> Result<(), LinuxError>,
    mut request: impl FnMut(u32, u16, u16, &[u8]) -> Result<Vec<u8>, LinuxError>,
    mut readback: impl FnMut(u32) -> Result<bool, LinuxError>,
) -> Result<(), LinuxError> {
    if ifindex == 0 {
        return Err(LinuxError::Conflict {
            resource: "IPv4 forwarding interface".into(),
            details: "ifindex 0 is not valid".into(),
        });
    }
    let value = u32::from(enabled);
    let mut conf = Vec::new();
    append_netlink_attribute(&mut conf, IPV4_DEVCONF_FORWARDING, &value.to_ne_bytes());
    let mut inet = Vec::new();
    append_netlink_attribute(&mut inet, IFLA_INET_CONF | NLA_F_NESTED, &conf);
    let mut af_spec = Vec::new();
    append_netlink_attribute(&mut af_spec, AF_INET_ATTR | NLA_F_NESTED, &inet);
    let mut attributes = Vec::new();
    append_netlink_attribute(&mut attributes, IFLA_AF_SPEC | NLA_F_NESTED, &af_spec);

    // RTM_NEWLINK is addressed by ifindex, so check the saved name/index pair
    // as late as possible before the kernel resolves that index.
    verify(name, ifindex)?;
    request(ifindex, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, &attributes)?;
    let actual = readback(ifindex)?;
    verify(name, ifindex)?;
    if actual != enabled {
        return Err(LinuxError::Conflict {
            resource: format!("IPv4 forwarding on ifindex {ifindex}"),
            details: format!(
                "kernel acknowledged update but reports forwarding={}",
                u8::from(actual)
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
