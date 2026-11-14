//! rtnetlink wire protocol for per-interface IPv4 forwarding.
use super::link::verify_interface_identity;
use super::LinuxError;

pub(super) const NETLINK_ROUTE: libc::c_int = 0;
pub(super) const RTM_NEWLINK: u16 = 16;
pub(super) const RTM_GETLINK: u16 = 18;
pub(super) const NLM_F_REQUEST: u16 = 0x01;
pub(super) const NLM_F_ACK: u16 = 0x04;
pub(super) const NLMSG_ERROR: u16 = 2;
pub(super) const NLM_F_CAPPED: u16 = 0x100;
pub(super) const NLM_F_ACK_TLVS: u16 = 0x200;
pub(super) const NLMSGERR_ATTR_MSG: u16 = 1;
pub(super) const SOL_NETLINK: libc::c_int = 270;
pub(super) const NETLINK_EXT_ACK: libc::c_int = 11;
pub(super) const IFLA_AF_SPEC: u16 = 26;
pub(super) const IFLA_INET_CONF: u16 = 1;
pub(super) const IPV4_DEVCONF_FORWARDING: u16 = 1;
pub(super) const NLA_F_NESTED: u16 = 1 << 15;
pub(super) const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
pub(super) const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);
pub(super) const AF_INET_ATTR: u16 = libc::AF_INET as u16;
#[cfg(test)]
pub(super) const IPV4_DEVCONF_MAX: usize = 33;

#[repr(C)]
pub(super) struct NetlinkAddress {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

pub(super) fn align_netlink(length: usize) -> usize {
    (length + 3) & !3
}

pub(super) fn append_netlink_attribute(buffer: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let length = 4 + payload.len();
    buffer.extend_from_slice(&(length as u16).to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(payload);
    buffer.resize(align_netlink(buffer.len()), 0);
}

pub(super) fn build_link_message(
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

pub(super) fn netlink_extended_ack(response: &[u8], offset: usize, length: usize) -> Option<String> {
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

pub(super) fn netlink_request(
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

pub(super) fn parse_link_ipv4_forwarding(response: &[u8], expected_ifindex: u32) -> Result<bool, LinuxError> {
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

pub(super) fn set_ipv4_interface_forwarding_with(
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
