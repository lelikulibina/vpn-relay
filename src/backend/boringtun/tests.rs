use super::*;


#[test]
fn backend_passes_keepalive_ranges_and_preserves_fixed_interval_compatibility() {
    for (setting, expected) in [
        ("persistent_keepalive_range = [25, 35]", Some((25, 35))),
        ("persistent_keepalive_secs = 25", Some((25, 25))),
        ("persistent_keepalive_secs = \"25-35\"", Some((25, 35))),
    ] {
        let source = format!(
            r#"
                type = "wg"
                address = ["10.0.0.1/24"]
                private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                [[peers]]
                public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                allowed_ips = ["10.0.0.2/32"]
                {setting}
            "#
        );
        let interface: InterfaceConfig = toml::from_str(&source).unwrap();
        let prepared = PreparedInterface {
            peer_endpoints: vec![None],
        };
        let peers = build_peer_configs("wg-test", &interface, &prepared).unwrap();
        assert_eq!(peers[0].persistent_keepalive, expected);
    }
}

#[test]
fn dns_resolution_requests_only_ipv4_addresses() {
    let address = resolve_ipv4_domain("localhost", 51820).unwrap();
    assert!(address.is_ipv4());
    assert_eq!(address.port(), 51820);
}

#[test]
fn backend_preflight_resolves_peer_endpoints_before_runtime_setup() {
    let mut interface: InterfaceConfig = toml::from_str(
        r#"
            type = "wg"
            address = ["10.0.0.1/24"]
            private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            [[peers]]
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            endpoint = "vpn-relay-preflight.invalid:51820"
            allowed_ips = ["10.0.0.2/32"]
        "#,
    )
    .expect("valid interface shape");

    let error = BoringTunBackend
        .prepare("wg-preflight", &interface)
        .expect_err("reserved .invalid endpoint must not resolve");
    assert!(error.to_string().contains("peers[0].endpoint"));

    interface.peers[0].endpoint = Some("192.0.2.10:51820".to_owned());
    let prepared = BoringTunBackend
        .prepare("wg-preflight", &interface)
        .expect("literal endpoint should pass preflight");
    assert_eq!(
        prepared.peer_endpoints,
        vec![Some("192.0.2.10:51820".parse().unwrap())]
    );
}
}

fn resolve_ipv4_domain(host: &str, port: u16) -> Result<SocketAddr, String> {
let host = CString::new(host).map_err(|_| "DNS name contains a NUL byte".to_owned())?;
let service = CString::new(port.to_string()).expect("decimal port contains no NUL");
let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
hints.ai_family = libc::AF_INET;
hints.ai_socktype = libc::SOCK_DGRAM;
let mut result = ptr::null_mut();
let status = unsafe { libc::getaddrinfo(host.as_ptr(), service.as_ptr(), &hints, &mut result) };
if status != 0 {
    let message = unsafe { CStr::from_ptr(libc::gai_strerror(status)) }
        .to_string_lossy()
        .into_owned();
    return Err(message);
}

struct AddrInfoGuard(*mut libc::addrinfo);
impl Drop for AddrInfoGuard {
    fn drop(&mut self) {
        unsafe { libc::freeaddrinfo(self.0) };
    }
}
if result.is_null() {
    return Err("DNS returned no IPv4 A records".to_owned());
}
let _guard = AddrInfoGuard(result);
let mut current = result;
while !current.is_null() {
    let entry = unsafe { &*current };
    if entry.ai_family == libc::AF_INET && !entry.ai_addr.is_null() {
        let address = unsafe { &*(entry.ai_addr as *const libc::sockaddr_in) };
        let ip = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
        return Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }
    current = entry.ai_next;
}
Err("DNS returned no IPv4 A records".to_owned())
}

fn resolve_endpoint(value: &str) -> Result<SocketAddr, BackendError> {
let parsed = PeerEndpoint::parse(value)
    .map_err(|reason| BackendError::new(format!("invalid endpoint {value}: {reason}")))?;
match parsed.host {
    EndpointHost::Ip(ip) => Ok(SocketAddr::new(ip.into(), parsed.port)),
    EndpointHost::Dns(host) => resolve_ipv4_domain(&host, parsed.port).map_err(|error| {
        BackendError::new(format!("failed to resolve IPv4 endpoint {value}: {error}"))
    }),
}
