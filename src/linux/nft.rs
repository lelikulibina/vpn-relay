//! nftables table ownership and transactional policy application.
use super::exec::run;
use super::LinuxError;
use crate::routing::RoutingPlan;
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

/// Serialize the typed firewall model as one nftables JSON transaction.
/// When replacing an existing owned table, delete it before adding the new
/// objects so nftables applies the replacement atomically.
pub(super) fn build_nftables_batch(
    plan: &RoutingPlan,
    replace_owned: bool,
) -> Result<Value, LinuxError> {
    let ruleset = plan.firewall_ruleset().map_err(|error| LinuxError::Command {
        program: "nft JSON batch".into(),
        status: "invalid firewall model".into(),
        stderr: error.to_string(),
    })?;
    let mut batch = ruleset.to_json_value().map_err(|error| LinuxError::Command {
        program: "nft JSON batch".into(),
        status: "serialization failed".into(),
        stderr: error.to_string(),
    })?;

    let objects = batch
        .get_mut("nftables")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| LinuxError::Command {
            program: "nft JSON batch".into(),
            status: "invalid serialized ruleset".into(),
            stderr: "serialized ruleset has no nftables object array".into(),
        })?;

    if replace_owned {
        objects.insert(
            0,
            serde_json::json!({
                "delete": {
                    "table": {
                        "family": plan.nft_family,
                        "name": plan.nft_table,
                    }
                }
            }),
        );
    }

    Ok(batch)
}

/// Return true only when the nftables table object itself carries our ownership marker.
pub(super) fn table_is_owned(json: &str, family: &str, name: &str) -> bool {
    let Ok(document) = serde_json::from_str::<Value>(json) else {
        return false;
    };
    document
        .get("nftables")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                let Some(table) = item.get("table") else {
                    return false;
                };
                table.get("family").and_then(Value::as_str) == Some(family)
                    && table.get("name").and_then(Value::as_str) == Some(name)
                    && table.get("comment").and_then(Value::as_str) == Some("managed by vpn-relay")
            })
        })
}

/// Older nftables releases omit table comments from JSON output. Fall back to
/// the human-readable representation, but accept only the table-level comment
/// (four-space indentation), never a similarly named comment inside a chain.
pub(super) fn table_is_owned_text(output: &str, family: &str, name: &str) -> bool {
    let expected_header = format!("table {family} {name} {{");
    let expected_comment = "comment \"managed by vpn-relay\"";
    let mut in_table = false;

    for line in output.lines() {
        if !in_table {
            in_table = line.trim() == expected_header;
            continue;
        }

        // The table's closing brace is the only closing brace at column zero.
        if line.starts_with('}') {
            return false;
        }

        // nftables 1.0.2 prints tabs; newer releases commonly print spaces.
        let top_level_indentation = (line.starts_with('\t') && !line.starts_with("\t\t"))
            || (line.starts_with("    ") && !line.starts_with("        "));
        if top_level_indentation && line.trim() == expected_comment {
            return true;
        }
    }

    false
}

fn get_current_ruleset_json(plan: &RoutingPlan) -> Result<String, nftables::helper::NftablesError> {
    nftables::helper::get_current_ruleset_raw(
        Some("nft"),
        [
            "list",
            "table",
            plan.nft_family.as_str(),
            plan.nft_table.as_str(),
        ],
    )
}

fn get_nft_table_text(plan: &RoutingPlan) -> Result<String, LinuxError> {
    let textual = Command::new("nft")
        .args([
            "list",
            "table",
            plan.nft_family.as_str(),
            plan.nft_table.as_str(),
        ])
        .output()
        .map_err(|source| LinuxError::Spawn {
            program: "nft".into(),
            source,
        })?;
    if !textual.status.success() {
        return Err(LinuxError::Command {
            program: "nft list table".into(),
            status: textual.status.to_string(),
            stderr: String::from_utf8_lossy(&textual.stderr).trim().into(),
        });
    }
    Ok(String::from_utf8_lossy(&textual.stdout).into_owned())
}

pub(super) fn map_nftables_error(error: nftables::helper::NftablesError) -> LinuxError {
    use nftables::helper::NftablesError;

    match error {
        NftablesError::NftExecution { program, inner } => LinuxError::Spawn {
            program: program.to_string_lossy().into_owned(),
            source: inner,
        },
        NftablesError::NftFailed {
            program,
            hint,
            stdout,
            stderr,
        } => {
            let diagnostic = match (stderr.is_empty(), stdout.is_empty()) {
                (false, false) => format!("{stderr}\nstdout: {stdout}"),
                (false, true) => stderr,
                (true, false) => format!("stdout: {stdout}"),
                (true, true) => "nft command failed without diagnostic output".into(),
            };
            LinuxError::Command {
                program: format!("{} {hint}", program.to_string_lossy()),
                status: "failed".into(),
                stderr: diagnostic,
            }
        }
        NftablesError::NftOutputEncoding { program, inner } => LinuxError::Command {
            program: program.to_string_lossy().into_owned(),
            status: "invalid UTF-8 output".into(),
            stderr: inner.to_string(),
        },
        NftablesError::NftInvalidJson(error) => LinuxError::Command {
            program: "nft -j list table".into(),
            status: "invalid JSON".into(),
            stderr: error.to_string(),
        },
    }
}

pub(super) fn is_missing_table_error(error: &nftables::helper::NftablesError) -> bool {
    matches!(
        error,
        nftables::helper::NftablesError::NftFailed { stderr, .. }
            if stderr.contains("No such file or directory") || stderr.contains("does not exist")
    )
}

pub(super) fn inspect_nft_table_with<J, T>(
    plan: &RoutingPlan,
    get_json: &mut J,
    get_text: &mut T,
) -> Result<bool, LinuxError>
where
    J: FnMut(&RoutingPlan) -> Result<String, nftables::helper::NftablesError>,
    T: FnMut(&RoutingPlan) -> Result<String, LinuxError>,
{
    let json = match get_json(plan) {
        Ok(json) => json,
        Err(error) if is_missing_table_error(&error) => return Ok(false),
        Err(error) => return Err(map_nftables_error(error)),
    };

    if table_is_owned(&json, &plan.nft_family, &plan.nft_table) {
        return Ok(true);
    }

    // nftables 1.0.2 (Ubuntu 22.04) accepts table comments but does not expose
    // them in JSON. Require the exact table header and a top-level comment
    // before considering the table daemon-owned.
    let textual = get_text(plan)?;
    if table_is_owned_text(&textual, &plan.nft_family, &plan.nft_table) {
        Ok(true)
    } else {
        Err(LinuxError::Conflict {
            resource: format!("nft table {} {}", plan.nft_family, plan.nft_table),
            details: "table exists but its table-level ownership marker is absent or invalid"
                .into(),
        })
    }
}

fn inspect_nft_table(plan: &RoutingPlan) -> Result<bool, LinuxError> {
    inspect_nft_table_with(plan, &mut get_current_ruleset_json, &mut get_nft_table_text)
}

/// Runtime-facing abstraction for applying and removing firewall policies.
///
/// Implementations preserve ownership checks and atomic batch semantics. The
/// trait is synchronous because firewall operations participate in ordered
/// startup, reload, rollback, and shutdown transactions.
pub(crate) trait NftApplier {
    fn apply(&self, plan: &RoutingPlan) -> Result<(), LinuxError>;
    fn remove(&self, plan: &RoutingPlan) -> Result<(), LinuxError>;
}

/// Production implementation backed by the existing nft command/script adapter.
#[derive(Default)]
pub(crate) struct SystemNftApplier;

impl NftApplier for SystemNftApplier {
    fn apply(&self, plan: &RoutingPlan) -> Result<(), LinuxError> {
        apply_nft_with(plan, &mut inspect_nft_table, &mut run_nft_script)
    }

    fn remove(&self, plan: &RoutingPlan) -> Result<(), LinuxError> {
        remove_nft_with(plan, &mut inspect_nft_table, &mut run)
    }
}

/// Replace only a table whose table-level metadata proves ownership.
pub fn apply_nft(plan: &RoutingPlan) -> Result<(), LinuxError> {
    SystemNftApplier.apply(plan)
}

pub(super) fn apply_nft_with<I, R>(
    plan: &RoutingPlan,
    inspect_table: &mut I,
    run_script: &mut R,
) -> Result<(), LinuxError>
where
    I: FnMut(&RoutingPlan) -> Result<bool, LinuxError>,
    R: FnMut(&str) -> Result<(), LinuxError>,
{
    let mut script = String::new();
    if inspect_table(plan)? {
        script.push_str(&format!(
            "delete table {} {}\n",
            plan.nft_family, plan.nft_table
        ));
    }
    script.push_str(&plan.nft_script());
    run_script(&script)
}

/// Submit one complete nftables batch. nft applies a batch transactionally:
/// a rejected batch leaves the previous table intact.
fn run_nft_script(script: &str) -> Result<(), LinuxError> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
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
        .write_all(script.as_bytes());
    if let Err(source) = write_result {
        // Closing stdin lets nft observe EOF. Always reap the child even when
        // the pipe breaks, otherwise a failed policy update can leave an
        // unreaped subprocess behind.
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
        program: "nft -f -".into(),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().into(),
    })
}

pub fn remove_nft(plan: &RoutingPlan) -> Result<(), LinuxError> {
    SystemNftApplier.remove(plan)
}

pub(super) fn remove_nft_with<I, R>(
    plan: &RoutingPlan,
    inspect_table: &mut I,
    run_command: &mut R,
) -> Result<(), LinuxError>
where
    I: FnMut(&RoutingPlan) -> Result<bool, LinuxError>,
    R: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    if !inspect_table(plan)? {
        return Ok(());
    }
    run_command(
        "nft",
        &[
            "delete".into(),
            "table".into(),
            plan.nft_family.clone(),
            plan.nft_table.clone(),
        ],
    )
}
