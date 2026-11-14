//! iproute2 policy-routing lifecycle and ownership verification.

use super::{output, run, LinuxError, ROUTING_PROTOCOL};
use crate::routing::{RoutingPlan, FIRST_IP_RULE_PRIORITY, FIRST_ROUTING_TABLE};

pub(super) fn rule_has_owned_identity(line: &str, mark: u32, table: &str) -> bool {
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
pub(super) fn rule_matches_fwmark(line: &str, mark: u32) -> bool {
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

pub(super) fn route_has_owned_identity(line: &str, interface: &str) -> bool {
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

pub(super) fn apply_egress_policy_routing_with<F>(
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
pub(super) fn remove_egress_policy_routing_with<F>(
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

pub(super) fn apply_policy_routing_with<F>(
    plan: &RoutingPlan,
    run_command: &mut F,
) -> Result<(), LinuxError>
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

pub(super) fn remove_policy_routing_with<F>(
    plan: &RoutingPlan,
    run_command: &mut F,
) -> Result<(), LinuxError>
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
