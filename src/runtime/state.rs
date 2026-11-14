//! Durable conntrack routing-decision state.

use super::RuntimeError;
use crate::routing::RoutingPlan;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConntrackMarkStateFile {
    version: u32,
    decisions: Vec<crate::routing::RoutingDecision>,
}

fn validate_private_state_file(path: &Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(RuntimeError::ConntrackMarkState(format!(
            "refusing to use non-private state file {}",
            path.display()
        )));
    }
    Ok(())
}

fn load_conntrack_mark_history(
    path: &Path,
) -> Result<Vec<crate::routing::RoutingDecision>, RuntimeError> {
    // Open the inode we validate and read. A separate symlink_metadata()+read()
    // sequence permits a path swap between the security check and the read.
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(RuntimeError::ConntrackMarkState(error.to_string())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(RuntimeError::ConntrackMarkState(format!(
            "refusing to use non-private state file {}",
            path.display()
        )));
    }
    const MAX_STATE_FILE_SIZE: u64 = 4 * 1024 * 1024;
    if metadata.len() > MAX_STATE_FILE_SIZE {
        return Err(RuntimeError::ConntrackMarkState(
            "state file exceeds 4 MiB".to_owned(),
        ));
    }

    // Bound the read as well: the file may grow after fstat().
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_STATE_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    if bytes.len() as u64 > MAX_STATE_FILE_SIZE {
        return Err(RuntimeError::ConntrackMarkState(
            "state file exceeds 4 MiB".to_owned(),
        ));
    }
    let state: ConntrackMarkStateFile = serde_json::from_slice(&bytes)
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    if state.version != 1 {
        return Err(RuntimeError::ConntrackMarkState(format!(
            "unsupported state file version {}",
            state.version
        )));
    }
    RoutingPlan::validate_conntrack_mark_history(&state.decisions)
        .map_err(RuntimeError::ConntrackMarkState)?;
    Ok(state.decisions)
}

fn persist_conntrack_mark_history(
    path: &Path,
    decisions: &[crate::routing::RoutingDecision],
) -> Result<(), RuntimeError> {
    RoutingPlan::validate_conntrack_mark_history(decisions)
        .map_err(RuntimeError::ConntrackMarkState)?;

    if path.exists() {
        validate_private_state_file(path)?;
    }

    let temporary_path = path.with_extension(format!("marks.tmp-{}", std::process::id()));
    if let Ok(metadata) = fs::symlink_metadata(&temporary_path) {
        if !metadata.file_type().is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(RuntimeError::ConntrackMarkState(format!(
                "refusing to replace unsafe temporary state file {}",
                temporary_path.display()
            )));
        }
        fs::remove_file(&temporary_path)
            .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary_path)
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    let state = ConntrackMarkStateFile {
        version: 1,
        decisions: decisions.to_vec(),
    };
    let write_result = serde_json::to_writer(&mut file, &state)
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))
        .and_then(|()| {
            file.sync_all()
                .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))
        });
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }

    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(RuntimeError::ConntrackMarkState(error.to_string()));
    }
    let parent = path.parent().ok_or_else(|| {
        RuntimeError::ConntrackMarkState("state file path has no parent directory".to_owned())
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    Ok(())
}

