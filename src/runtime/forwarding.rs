//! Durable forwarding state and sysctl recovery for the Linux runtime.

use super::{ForwardingState, ForwardingStateFile, InterfaceForwardingState, RuntimeError};
use crate::linux;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub(super) fn read_sysctl(key: &str) -> Result<String, RuntimeError> {
    let output = std::process::Command::new("sysctl")
        .args(["-n", key])
        .output()
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    if !output.status.success() {
        return Err(RuntimeError::Forwarding(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub(super) fn write_sysctl(key: &str, value: &str) -> Result<(), RuntimeError> {
    let output = std::process::Command::new("sysctl")
        .args(["-w", &format!("{key}={value}")])
        .output()
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    if !output.status.success() {
        return Err(RuntimeError::Forwarding(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn enable_forwarding_state_with(
    mut state: ForwardingState,
    mut write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
) -> Result<ForwardingState, RuntimeError> {
    if state.ipv4 != "1" {
        state.ipv4_changed = true;
        if let Err(enable_error) = write("net.ipv4.ip_forward", "1") {
            if let Err(restore_error) = restore_forwarding_with(&state, &mut write) {
                return Err(RuntimeError::FatalTransition(format!(
                    "IPv4 forwarding enable failed ({enable_error}); restoring original forwarding state also failed ({restore_error}); fail-closed nftables policy must remain installed"
                )));
            }
            return Err(enable_error);
        }
    }
    Ok(state)
}

pub(super) fn validate_forwarding_state(state: &ForwardingState) -> Result<(), RuntimeError> {
    if !matches!(state.ipv4.as_str(), "0" | "1") {
        return Err(RuntimeError::Forwarding(
            "forwarding state contains an invalid IPv4 sysctl value".to_owned(),
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    let mut indices = std::collections::BTreeSet::new();
    for entry in &state.interfaces {
        if entry.name.is_empty()
            || entry.name.len() > 15
            || !entry.name.is_ascii()
            || !entry
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || entry.ifindex == 0
        {
            return Err(RuntimeError::Forwarding(
                "forwarding journal contains an invalid interface identity".to_owned(),
            ));
        }
        if !matches!(entry.ipv4.as_str(), "0" | "1") {
            return Err(RuntimeError::Forwarding(format!(
                "forwarding journal contains an invalid IPv4 sysctl value for interface '{}'",
                entry.name
            )));
        }
        if !names.insert(entry.name.as_str()) || !indices.insert(entry.ifindex) {
            return Err(RuntimeError::Forwarding(format!(
                "forwarding journal contains a duplicate interface name or ifindex for '{}'/{}",
                entry.name, entry.ifindex
            )));
        }
    }
    Ok(())
}

pub(super) fn load_forwarding_state(
    path: &Path,
    namespace_inode: u64,
) -> Result<Option<ForwardingState>, RuntimeError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(RuntimeError::Forwarding(error.to_string())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(RuntimeError::Forwarding(format!(
            "refusing to use non-private forwarding state file {}",
            path.display()
        )));
    }
    const MAX_FORWARDING_STATE_SIZE: u64 = 64 * 1024;
    if metadata.len() > MAX_FORWARDING_STATE_SIZE {
        return Err(RuntimeError::Forwarding(
            "forwarding state file exceeds 64 KiB".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_FORWARDING_STATE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    if bytes.len() as u64 > MAX_FORWARDING_STATE_SIZE {
        return Err(RuntimeError::Forwarding(
            "forwarding state file exceeds 4 KiB".to_owned(),
        ));
    }
    let document: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    let version = document
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            RuntimeError::Forwarding("forwarding state has no valid version".to_owned())
        })?;
    if version != 1 {
        return Err(RuntimeError::Forwarding(format!(
            "unsupported forwarding state version {version}"
        )));
    }
    let saved: ForwardingStateFile = serde_json::from_value(document)
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    if saved.namespace_inode != namespace_inode {
        return Err(RuntimeError::Forwarding(format!(
            "forwarding state belongs to network namespace {}, current namespace is {}",
            saved.namespace_inode, namespace_inode
        )));
    }
    validate_forwarding_state(&saved.state)?;
    Ok(Some(saved.state))
}

pub(super) trait ForwardingJournalIo {
    fn create_new_file(&mut self, path: &Path) -> std::io::Result<File>;
    fn write_state(&mut self, file: &mut File, saved: &ForwardingStateFile) -> std::io::Result<()>;
    fn sync_file(&mut self, file: &File) -> std::io::Result<()>;
    fn rename(&mut self, source: &Path, destination: &Path) -> std::io::Result<()>;
    fn remove_file(&mut self, path: &Path) -> std::io::Result<()>;
    fn sync_directory(&mut self, path: &Path) -> std::io::Result<()>;
}

pub(super) struct StdForwardingJournalIo;

impl ForwardingJournalIo for StdForwardingJournalIo {
    fn create_new_file(&mut self, path: &Path) -> std::io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    fn write_state(&mut self, file: &mut File, saved: &ForwardingStateFile) -> std::io::Result<()> {
        serde_json::to_writer(file, saved).map_err(std::io::Error::other)
    }

    fn sync_file(&mut self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }

    fn rename(&mut self, source: &Path, destination: &Path) -> std::io::Result<()> {
        fs::rename(source, destination)
    }

    fn remove_file(&mut self, path: &Path) -> std::io::Result<()> {
        fs::remove_file(path)
    }

    fn sync_directory(&mut self, path: &Path) -> std::io::Result<()> {
        File::open(path).and_then(|directory| directory.sync_all())
    }
}

pub(super) fn persist_forwarding_state(
    path: &Path,
    namespace_inode: u64,
    state: &ForwardingState,
) -> Result<(), RuntimeError> {
    persist_forwarding_state_with(path, namespace_inode, state, &mut StdForwardingJournalIo)
}

pub(super) fn persist_forwarding_state_with(
    path: &Path,
    namespace_inode: u64,
    state: &ForwardingState,
    io: &mut impl ForwardingJournalIo,
) -> Result<(), RuntimeError> {
    validate_forwarding_state(state)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let _ = load_forwarding_state(path, namespace_inode)?.ok_or_else(|| {
                RuntimeError::Forwarding(
                    "forwarding state disappeared during validation".to_owned(),
                )
            })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(RuntimeError::Forwarding(error.to_string())),
    }
    let temporary_path = path.with_extension(format!("forwarding.tmp-{}", std::process::id()));
    let mut file = io
        .create_new_file(&temporary_path)
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    let saved = ForwardingStateFile {
        version: 1,
        namespace_inode,
        state: state.clone(),
    };
    let result = io
        .write_state(&mut file, &saved)
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))
        .and_then(|()| {
            io.sync_file(&file)
                .map_err(|error| RuntimeError::Forwarding(error.to_string()))
        });
    drop(file);
    if let Err(error) = result {
        let _ = io.remove_file(&temporary_path);
        return Err(error);
    }
    if let Err(error) = io.rename(&temporary_path, path) {
        let _ = io.remove_file(&temporary_path);
        return Err(RuntimeError::Forwarding(error.to_string()));
    }
    let parent = path.parent().ok_or_else(|| {
        RuntimeError::Forwarding("forwarding state path has no parent directory".to_owned())
    })?;
    io.sync_directory(parent)
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))
}

pub(super) fn remove_forwarding_state_file(path: &Path) -> Result<(), RuntimeError> {
    remove_forwarding_state_file_with(path, &mut StdForwardingJournalIo)
}

pub(super) fn remove_forwarding_state_file_with(
    path: &Path,
    io: &mut impl ForwardingJournalIo,
) -> Result<(), RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o777 == 0o600
                && metadata.nlink() == 1 =>
        {
            io.remove_file(path)
                .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
            let parent = path.parent().ok_or_else(|| {
                RuntimeError::Forwarding("forwarding state path has no parent directory".to_owned())
            })?;
            io.sync_directory(parent)
                .map_err(|error| RuntimeError::Forwarding(error.to_string()))
        }
        Ok(_) => Err(RuntimeError::Forwarding(format!(
            "refusing to remove non-private forwarding state file {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RuntimeError::Forwarding(error.to_string())),
    }
}

pub(super) fn interface_forwarding_sysctl_key(name: &str) -> Result<String, RuntimeError> {
    if name.is_empty()
        || name.len() > 15
        || !name.is_ascii()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || name == "."
        || name == ".."
    {
        return Err(RuntimeError::Forwarding(
            "refusing to construct a sysctl path from an invalid interface name".to_owned(),
        ));
    }
    Ok(format!("net.ipv4.conf.{name}.forwarding"))
}

pub(super) fn read_forwarding_state_value(
    state: &ForwardingState,
    key: &str,
) -> Result<String, RuntimeError> {
    for entry in &state.interfaces {
        if key == interface_forwarding_sysctl_key(&entry.name)? {
            let enabled = linux::ipv4_interface_forwarding(entry.ifindex)
                .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
            return Ok(if enabled { "1" } else { "0" }.to_owned());
        }
    }
    read_sysctl(key)
}

pub(super) fn write_forwarding_state_value(
    state: &ForwardingState,
    key: &str,
    value: &str,
) -> Result<(), RuntimeError> {
    for entry in &state.interfaces {
        if key == interface_forwarding_sysctl_key(&entry.name)? {
            let enabled = match value {
                "0" => false,
                "1" => true,
                _ => {
                    return Err(RuntimeError::Forwarding(
                        "IPv4 forwarding must be 0 or 1".to_owned(),
                    ))
                }
            };
            linux::set_ipv4_interface_forwarding(&entry.name, entry.ifindex, enabled)
                .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
            return Ok(());
        }
    }
    write_sysctl(key, value)
}

pub(super) fn restore_interface_forwarding_entry_with(
    entry: &InterfaceForwardingState,
    original: &str,
    changed: bool,
    mut read: impl FnMut(&str) -> Result<String, RuntimeError>,
    mut write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
    mut verify: impl FnMut(&str, u32) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    if !changed {
        return Ok(());
    }
    let key = interface_forwarding_sysctl_key(&entry.name)?;
    if let Err(error) = verify(&entry.name, entry.ifindex) {
        if entry.daemon_owned {
            return Ok(());
        }
        return Err(error);
    }
    let current = read(&key)?;
    if current == original || current != "1" {
        return Ok(());
    }
    verify(&entry.name, entry.ifindex)?;
    write(&key, original)
}

pub(super) fn verify_forwarding_interface(name: &str, index: u32) -> Result<(), RuntimeError> {
    linux::verify_interface_identity(name, index)
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))
}

pub(super) fn restore_interface_forwarding_entries_with(
    state: &ForwardingState,
    mut read: impl FnMut(&str) -> Result<String, RuntimeError>,
    mut write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
    mut verify: impl FnMut(&str, u32) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let mut failures = Vec::new();
    for entry in &state.interfaces {
        if entry.daemon_owned {
            continue;
        }
        if let Err(error) = restore_interface_forwarding_entry_with(
            entry,
            &entry.ipv4,
            entry.ipv4_changed,
            &mut read,
            &mut write,
            &mut verify,
        ) {
            failures.push(format!("{} IPv4: {error}", entry.name));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::FatalTransition(format!(
            "failed to recover per-interface forwarding state: {}",
            failures.join("; ")
        )))
    }
}

pub(super) fn verify_managed_forwarding_runtime(
    allowed_names: &[String],
    state: &ForwardingState,
) -> Result<(), RuntimeError> {
    if read_sysctl("net.ipv4.ip_forward")? != "1" {
        return Err(RuntimeError::Forwarding(
            "namespace-wide IPv4 forwarding prerequisite changed".to_owned(),
        ));
    }
    let allowed = allowed_names
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    validate_unmanaged_forwarding_with(
        &allowed,
        &interface_sysctl_names("/proc/sys/net/ipv4/conf")?,
        read_unmanaged_forwarding_sysctl,
    )?;
    for entry in &state.interfaces {
        verify_forwarding_interface(&entry.name, entry.ifindex)?;
        if !linux::ipv4_interface_forwarding(entry.ifindex)
            .map_err(|error| RuntimeError::Forwarding(error.to_string()))?
        {
            return Err(RuntimeError::Forwarding(format!(
                "managed interface '{}' lost its IPv4 forwarding enable value",
                entry.name
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_unmanaged_forwarding_with(
    allowed: &std::collections::BTreeSet<String>,
    ipv4_interfaces: &[String],
    mut read: impl FnMut(&str) -> Result<Option<String>, RuntimeError>,
) -> Result<(), RuntimeError> {
    for name in ipv4_interfaces {
        if allowed.contains(name) {
            continue;
        }
        let key = format!("net.ipv4.conf.{name}.forwarding");
        let Some(value) = read(&key)? else {
            return Err(RuntimeError::Forwarding(format!(
                "IPv4 forwarding sysctl is unavailable for unmanaged interface '{name}'"
            )));
        };
        if value.trim() != "0" {
            return Err(RuntimeError::Forwarding(format!(
                "unmanaged interface '{name}' has IPv4 forwarding enabled; disable it or add the interface to daemon.forwarding_interfaces"
            )));
        }
    }
    Ok(())
}

pub(super) fn read_unmanaged_forwarding_sysctl(key: &str) -> Result<Option<String>, RuntimeError> {
    read_sysctl(key).map(Some)
}

pub(super) fn interface_sysctl_names(directory: &str) -> Result<Vec<String>, RuntimeError> {
    let entries =
        fs::read_dir(directory).map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
        let name = entry.file_name().into_string().map_err(|_| {
            RuntimeError::Forwarding(format!("non-UTF-8 interface sysctl entry in {directory}"))
        })?;
        if name != "all" && name != "default" {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

pub(super) fn enable_interface_forwarding_durable(
    path: &Path,
    namespace_inode: u64,
    names: &[String],
    daemon_owned_names: &std::collections::BTreeSet<String>,
) -> Result<ForwardingState, RuntimeError> {
    if read_sysctl("net.ipv4.ip_forward")? != "1" {
        return Err(RuntimeError::Forwarding(
            "per-interface forwarding requires net.ipv4.ip_forward=1; configure this namespace-wide prerequisite externally".to_owned(),
        ));
    }
    let allowed = names
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    validate_unmanaged_forwarding_with(
        &allowed,
        &interface_sysctl_names("/proc/sys/net/ipv4/conf")?,
        read_unmanaged_forwarding_sysctl,
    )?;
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        let ifindex = linux::interface_index(name)
            .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
        verify_forwarding_interface(name, ifindex)?;
        let ipv4 = linux::ipv4_interface_forwarding(ifindex)
            .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
        verify_forwarding_interface(name, ifindex)?;
        entries.push(InterfaceForwardingState {
            name: name.clone(),
            ifindex,
            daemon_owned: daemon_owned_names.contains(name),
            ipv4: if ipv4 { "1" } else { "0" }.to_owned(),
            ipv4_changed: false,
        });
    }
    let mut state = ForwardingState {
        ipv4: "1".to_owned(),
        ipv4_changed: false,
        interfaces: entries,
    };
    for entry in &mut state.interfaces {
        entry.ipv4_changed = entry.ipv4 != "1";
    }
    validate_forwarding_state(&state)?;
    if state.interfaces.iter().any(|entry| entry.ipv4_changed) {
        persist_forwarding_state(path, namespace_inode, &state)?;
    }
    if let Err(error) = enable_interface_forwarding_entries_with(
        &state,
        |key| read_forwarding_state_value(&state, key),
        |key, value| write_forwarding_state_value(&state, key, value),
        verify_forwarding_interface,
    ) {
        if matches!(error, RuntimeError::FatalTransition(_)) {
            return Err(error);
        }
        remove_forwarding_state_file(path)?;
        return Err(error);
    }
    Ok(state)
}

pub(super) fn enable_interface_forwarding_entries_with(
    state: &ForwardingState,
    mut read: impl FnMut(&str) -> Result<String, RuntimeError>,
    mut write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
    mut verify: impl FnMut(&str, u32) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let mut failures = Vec::new();
    for entry in &state.interfaces {
        if !entry.ipv4_changed {
            continue;
        }
        let key = interface_forwarding_sysctl_key(&entry.name)?;
        if let Err(error) = verify(&entry.name, entry.ifindex).and_then(|()| write(&key, "1")) {
            failures.push(format!("{} IPv4: {error}", entry.name));
        }
    }
    if failures.is_empty() {
        return Ok(());
    }
    if let Err(rollback_error) =
        restore_interface_forwarding_entries_with(state, &mut read, &mut write, &mut verify)
    {
        return Err(RuntimeError::FatalTransition(format!(
            "per-interface forwarding setup failed ({}); rollback failed ({rollback_error}); fail-closed nftables policy must remain installed",
            failures.join("; ")
        )));
    }
    Err(RuntimeError::Forwarding(format!(
        "per-interface forwarding setup failed: {}",
        failures.join("; ")
    )))
}

pub(super) fn restore_forwarding_state_with(
    state: &ForwardingState,
    read: impl FnMut(&str) -> Result<String, RuntimeError>,
    write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    restore_forwarding_state_with_mode(state, read, write)
}

pub(super) fn restore_forwarding_state_with_mode(
    state: &ForwardingState,
    read: impl FnMut(&str) -> Result<String, RuntimeError>,
    write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    restore_forwarding_state_with_mode_and_verify(state, read, write, verify_forwarding_interface)
}

pub(super) fn restore_forwarding_state_with_mode_and_verify(
    state: &ForwardingState,
    mut read: impl FnMut(&str) -> Result<String, RuntimeError>,
    mut write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
    mut verify: impl FnMut(&str, u32) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let mut failures = Vec::new();
    if state.ipv4_changed {
        match read("net.ipv4.ip_forward") {
            Ok(current) if current == state.ipv4 => {}
            Ok(_) => {
                if let Err(error) = write("net.ipv4.ip_forward", &state.ipv4) {
                    failures.push(format!("IPv4: {error}"));
                }
            }
            Err(error) => failures.push(format!("IPv4 read: {error}")),
        }
    }
    if let Err(error) =
        restore_interface_forwarding_entries_with(state, &mut read, &mut write, &mut verify)
    {
        failures.push(error.to_string());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::FatalTransition(format!(
            "failed to recover IPv4 forwarding state: {}",
            failures.join("; ")
        )))
    }
}

pub(super) fn recover_forwarding_state(
    path: &Path,
    namespace_inode: u64,
) -> Result<(), RuntimeError> {
    let Some(state) = load_forwarding_state(path, namespace_inode)? else {
        return Ok(());
    };
    restore_forwarding_state_with_mode(
        &state,
        |key| read_forwarding_state_value(&state, key),
        |key, value| write_forwarding_state_value(&state, key, value),
    )?;
    remove_forwarding_state_file(path)
}

pub(super) fn enable_forwarding_durable(
    path: &Path,
    namespace_inode: u64,
    forwarding_interfaces: &[String],
    daemon_owned_names: &std::collections::BTreeSet<String>,
) -> Result<ForwardingState, RuntimeError> {
    if !forwarding_interfaces.is_empty() {
        return enable_interface_forwarding_durable(
            path,
            namespace_inode,
            forwarding_interfaces,
            daemon_owned_names,
        );
    }
    let mut state = ForwardingState {
        ipv4: read_sysctl("net.ipv4.ip_forward")?,
        ipv4_changed: false,
        interfaces: Vec::new(),
    };
    state.ipv4_changed = state.ipv4 != "1";
    validate_forwarding_state(&state)?;
    if state.ipv4_changed {
        persist_forwarding_state(path, namespace_inode, &state)?;
    }
    match enable_forwarding_state_with(state, write_sysctl) {
        Ok(state) => Ok(state),
        Err(error) => {
            if !matches!(error, RuntimeError::FatalTransition(_)) {
                remove_forwarding_state_file(path)?;
            }
            Err(error)
        }
    }
}

pub(super) fn restore_forwarding_with(
    state: &ForwardingState,
    mut write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    if state.ipv4_changed {
        write("net.ipv4.ip_forward", &state.ipv4).map_err(|error| {
            RuntimeError::FatalTransition(format!(
                "failed to restore IPv4 forwarding state: {error}"
            ))
        })?;
    }
    Ok(())
}

pub(super) fn restore_forwarding(state: &ForwardingState) -> Result<(), RuntimeError> {
    restore_forwarding_state_with(
        state,
        |key| read_forwarding_state_value(state, key),
        |key, value| write_forwarding_state_value(state, key, value),
    )
}
