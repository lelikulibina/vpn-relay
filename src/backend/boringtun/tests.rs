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