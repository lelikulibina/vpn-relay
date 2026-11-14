//! nft command adapter and ownership-safe table lifecycle.

use super::LinuxError;
use crate::routing::RoutingPlan;
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

/// Return true only when the table contains vpn-relay's inert owner marker rule.
pub(super) fn table_is_owned(json: &str, family: &str, name: &str) -> bool {
    let Ok(document) = serde_json::from_str::<Value>(json) else {
        return false;
    };
    let Some(items) = document.get("nftables").and_then(Value::as_array) else {
        return false;
    };
    let table_exists = items.iter().any(|item| {
        item.get("table").is_some_and(|table| {
            table.get("family").and_then(Value::as_str) == Some(family)
                && table.get("name").and_then(Value::as_str) == Some(name)
        })
    });
    let marker_exists = items.iter().any(|item| {
        item.get("rule").is_some_and(|rule| {
            rule.get("family").and_then(Value::as_str) == Some(family)
                && rule.get("table").and_then(Value::as_str) == Some(name)
                && rule.get("chain").and_then(Value::as_str) == Some("vpn_relay_owner")
                && rule.get("comment").and_then(Value::as_str) == Some("managed by vpn-relay")
        })
    });
    table_exists && marker_exists
}

fn inspect_nft_table(plan: &RoutingPlan) -> Result<bool, LinuxError> {
    let existing = Command::new("nft")
        .args(["-j", "list", "table", &plan.nft_family, &plan.nft_table])
        .output()
        .map_err(|source| LinuxError::Spawn {
            program: "nft".into(),
            source,
        })?;
    if !existing.status.success() {
        let stderr = String::from_utf8_lossy(&existing.stderr);
        if stderr.contains("No such file or directory") || stderr.contains("does not exist") {
            return Ok(false);
        }
        return Err(LinuxError::Command {
            program: "nft -j list table".into(),
            status: existing.status.to_string(),
            stderr: stderr.trim().into(),
        });
    }

    let json = String::from_utf8_lossy(&existing.stdout);
    if table_is_owned(&json, &plan.nft_family, &plan.nft_table) {
        Ok(true)
    } else {
        Err(LinuxError::Conflict {
            resource: format!("nft table {} {}", plan.nft_family, plan.nft_table),
            details: "table exists but its vpn_relay_owner marker rule is absent or invalid".into(),
        })
    }
}

/// Replace only a table whose dedicated owner marker rule proves ownership.
pub fn apply_nft(plan: &RoutingPlan) -> Result<(), LinuxError> {
    apply_nft_with(plan, &mut inspect_nft_table, &mut run_nft_json)
}

pub(super) fn apply_nft_with<I, R>(
    plan: &RoutingPlan,
    inspect_table: &mut I,
    run_json: &mut R,
) -> Result<(), LinuxError>
where
    I: FnMut(&RoutingPlan) -> Result<bool, LinuxError>,
    R: FnMut(&str) -> Result<(), LinuxError>,
{
    let replace_owned = inspect_table(plan)?;
    let payload = plan
        .nftables_json(replace_owned)
        .map_err(|error| LinuxError::Command {
            program: "nftables JSON builder".into(),
            status: "invalid generated ruleset".into(),
            stderr: error,
        })?;
    run_json(&payload)
}

/// Submit one complete JSON ruleset batch. nft applies it transactionally:
/// a rejected batch leaves the previous table intact.
fn run_nft_json(payload: &str) -> Result<(), LinuxError> {
    let mut child = Command::new("nft")
        .args(["-j", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| LinuxError::Spawn {
            program: "nft".into(),
            source,
        })?;
    let write_result = child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload.as_bytes());
    if let Err(source) = write_result {
        // Always reap the child even when the pipe breaks.
        let _ = child.wait_with_output();
        return Err(LinuxError::Spawn {
            program: "nft stdin".into(),
            source,
        });
    }
    let output = child
        .wait_with_output()
        .map_err(|source| LinuxError::Spawn {
            program: "nft".into(),
            source,
        })?;
    if output.status.success() {
        return Ok(());
    }
    Err(LinuxError::Command {
        program: "nft -j -f -".into(),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().into(),
    })
}

pub fn remove_nft(plan: &RoutingPlan) -> Result<(), LinuxError> {
    remove_nft_with(plan, &mut inspect_nft_table, &mut run_nft_json)
}

pub(super) fn remove_nft_with<I, R>(
    plan: &RoutingPlan,
    inspect_table: &mut I,
    run_json: &mut R,
) -> Result<(), LinuxError>
where
    I: FnMut(&RoutingPlan) -> Result<bool, LinuxError>,
    R: FnMut(&str) -> Result<(), LinuxError>,
{
    if !inspect_table(plan)? {
        return Ok(());
    }
    let payload = plan
        .nft_delete_json()
        .map_err(|error| LinuxError::Command {
            program: "nftables JSON builder".into(),
            status: "invalid delete batch".into(),
            stderr: error,
        })?;
    run_json(&payload)
}
