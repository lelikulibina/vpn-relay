//! Linux network-link identity and interface configuration.
use super::exec::run;
use super::LinuxError;

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

pub(super) fn verify_interface_identity_with(
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
