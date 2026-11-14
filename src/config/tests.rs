use super::*;
use super::validation::validate_interface_name;

const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn valid_config() -> String {
    format!(
        r#"
[daemon]
log_level = "info"
stats_interval_secs = 10
nft_table = "vpn_relay"
manage_ip_forwarding = false

[interfaces.wg-server]
type = "wg"
address = ["10.10.0.1/24"]
mtu = 1380
listen_port = 51820
private_key = "{KEY}"
socket_fwmark = 4097

[[interfaces.wg-server.peers]]
public_key = "{KEY}"
allowed_ips = ["10.10.0.2/32"]

[interfaces.awg-uplink]
type = "awg"
address = ["10.20.0.2/32"]
mtu = 1380
listen_port = 51821
private_key = "{KEY}"
socket_fwmark = 4098
jc = 5
jmin = 50
jmax = 1000
s1 = 0
s2 = 0
s3 = 0
s4 = 0
h1 = "1-100"
h2 = "101-200"
h3 = "201-300"
h4 = "301-400"

[[interfaces.awg-uplink.peers]]
public_key = "{KEY}"
endpoint = "198.51.100.10:51820"
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive_secs = 25

[[routing.rules]]
priority = 100
ingress = "wg-server"
destination = "0.0.0.0/0"
egress = "awg-uplink"

[[routing.rules]]
priority = 110
ingress = "wg-server"
destination = "203.0.113.0/24"
egress = "awg-uplink"

"#
    )
}

#[test]
fn shipped_example_configuration_parses_and_uses_only_supported_fields() {
    let config = Config::parse_toml(include_str!("../vpn-relay.example.toml")).unwrap();
    assert_eq!(config.interfaces.len(), 3);
    assert_eq!(config.routing.rules.len(), 3);
    assert_eq!(config.routing.mark_base, 0x8000_0000);
    assert_eq!(config.firewall.input.rules.len(), 1);
    assert_eq!(config.firewall.output.rules.len(), 1);
    assert!(config.interfaces["awg-primary"].has_awg_parameters());
    assert!(!config.interfaces["wg-server"].has_awg_parameters());
}

#[test]
fn forwarding_interface_allowlist_requires_explicit_global_management() {
    let text = valid_config().replace(
        "manage_ip_forwarding = false",
        "manage_ip_forwarding = false\nforwarding_interfaces = [\"eth0\"]",
    );
    assert!(Config::parse_toml(&text).is_err());
}

#[test]
fn forwarding_interface_allowlist_accepts_unique_valid_names() {
    let text = valid_config().replace(
        "manage_ip_forwarding = false",
        "manage_ip_forwarding = true\nforwarding_interfaces = [\"eth0\", \"wg-server\"]",
    );
    let config = Config::parse_toml(&text).unwrap();
    assert_eq!(
        config.daemon.forwarding_interfaces,
        vec!["eth0".to_owned(), "wg-server".to_owned()]
    );
}

#[test]
fn forwarding_interface_allowlist_rejects_duplicates_and_invalid_names() {
    let duplicate = valid_config().replace(
        "manage_ip_forwarding = false",
        "manage_ip_forwarding = true\nforwarding_interfaces = [\"eth0\", \"eth0\"]",
    );
    assert!(Config::parse_toml(&duplicate).is_err());

    let invalid = valid_config().replace(
        "manage_ip_forwarding = false",
        "manage_ip_forwarding = true\nforwarding_interfaces = [\"../eth0\"]",
    );
    assert!(Config::parse_toml(&invalid).is_err());
}

#[test]
fn forwarding_interface_allowlist_is_immutable_during_reload() {
    let current = Config::parse_toml(&valid_config().replace(
        "manage_ip_forwarding = false",
        "manage_ip_forwarding = true\nforwarding_interfaces = [\"eth0\"]",
    ))
    .unwrap();
    let next = Config::parse_toml(&valid_config().replace(
        "manage_ip_forwarding = false",
        "manage_ip_forwarding = true\nforwarding_interfaces = [\"eth1\"]",
    ))
    .unwrap();
    assert!(current.validate_reload_compatibility(&next).is_err());
}

#[test]
fn numeric_interface_names_are_rejected_as_inherited_file_descriptors() {
    assert!(validate_interface_name("123").is_err());
    assert!(validate_interface_name("-1").is_err());
    assert!(validate_interface_name("wg123").is_ok());
    assert!(validate_interface_name(".").is_err());
    assert!(validate_interface_name("..").is_err());
}

#[test]
fn reload_compatibility_allows_peer_routing_and_firewall_changes() {
    let current = Config::parse_toml(&valid_config()).unwrap();
    let mut candidate_text = valid_config()
        .replace("10.10.0.2/32", "10.10.0.3/32")
        .replace(
            "destination = \"0.0.0.0/0\"",
            "destination = \"10.0.0.0/8\"",
        );
    candidate_text.push_str(
        "\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nsource = \"10.10.0.3/32\"\n",
    );
    let candidate = Config::parse_toml(&candidate_text).unwrap();
    current.validate_reload_compatibility(&candidate).unwrap();
}

#[test]
fn reload_compatibility_allows_disjoint_policy_route_resource_changes() {
    let current = Config::parse_toml(&valid_config()).unwrap();

    let changed_mark_base = Config::parse_toml(&valid_config().replacen(
        "[[routing.rules]]",
        "[routing]\nmark_base = 0x90000000\n\n[[routing.rules]]",
        1,
    ))
    .unwrap();
    current
        .validate_reload_compatibility(&changed_mark_base)
        .unwrap();

    let mut changed_egress = current.clone();
    changed_egress.routing.rules.truncate(1);
    changed_egress.routing.rules[0].ingress = "awg-uplink".to_owned();
    changed_egress.routing.rules[0].egress = "wg-server".to_owned();
    changed_egress.routing.mark_base = 0x9000_0000;
    changed_egress.validate().unwrap();
    current
        .validate_reload_compatibility(&changed_egress)
        .unwrap();

    let mut no_egress = current.clone();
    no_egress.routing.rules.clear();
    no_egress.validate().unwrap();
    current.validate_reload_compatibility(&no_egress).unwrap();
}

#[test]
fn reload_compatibility_rejects_overlapping_policy_route_mark_ranges() {
    let current = Config::parse_toml(&valid_config()).unwrap();
    let mut changed_egress = current.clone();
    changed_egress.routing.rules.truncate(1);
    changed_egress.routing.rules[0].ingress = "awg-uplink".to_owned();
    changed_egress.routing.rules[0].egress = "wg-server".to_owned();
    // Keep the old mark base: the same numeric mark would select a
    // different egress while both old and new policy rules are installed.
    changed_egress.validate().unwrap();
    assert!(current
        .validate_reload_compatibility(&changed_egress)
        .unwrap_err()
        .to_string()
        .contains("mark ranges to be disjoint"));
}

#[test]
fn reload_compatibility_ignores_legacy_stats_interval() {
    let current = Config::parse_toml(&valid_config()).unwrap();

    let mut changed_table = current.clone();
    changed_table.daemon.nft_table = "other_table".to_owned();
    assert!(current
        .validate_reload_compatibility(&changed_table)
        .unwrap_err()
        .to_string()
        .contains("daemon.nft_table"));

    let mut changed_forwarding = current.clone();
    changed_forwarding.daemon.manage_ip_forwarding = !current.daemon.manage_ip_forwarding;
    assert!(current
        .validate_reload_compatibility(&changed_forwarding)
        .unwrap_err()
        .to_string()
        .contains("manage_ip_forwarding"));

    let mut changed_log_level = current.clone();
    changed_log_level.daemon.log_level = "debug".to_owned();
    assert!(current
        .validate_reload_compatibility(&changed_log_level)
        .unwrap_err()
        .to_string()
        .contains("daemon.log_level"));

    let mut changed_stats_interval = current.clone();
    changed_stats_interval.daemon.stats_interval_secs = 0;
    changed_stats_interval.validate().unwrap();
    current
        .validate_reload_compatibility(&changed_stats_interval)
        .unwrap();
}

#[test]
fn reload_compatibility_rejects_tunnel_identity_and_lifecycle_changes() {
    let current = Config::parse_toml(&valid_config()).unwrap();

    let changed_key = valid_config().replace(
        "private_key = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"",
        "private_key = \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"",
    );
    let changed_key = Config::parse_toml(&changed_key).unwrap();
    assert!(current
        .validate_reload_compatibility(&changed_key)
        .unwrap_err()
        .to_string()
        .contains("immutable tunnel parameters"));

    let changed_awg = Config::parse_toml(&valid_config().replace("jc = 5", "jc = 6")).unwrap();
    assert!(current
        .validate_reload_compatibility(&changed_awg)
        .unwrap_err()
        .to_string()
        .contains("immutable tunnel parameters"));

    let changed_socket_mark =
        Config::parse_toml(&valid_config().replace("socket_fwmark = 4098", "socket_fwmark = 4099"))
            .unwrap();
    assert!(current
        .validate_reload_compatibility(&changed_socket_mark)
        .unwrap_err()
        .to_string()
        .contains("immutable tunnel parameters"));

    let added_interface = Config::parse_toml(&format!(
        "{}\n[interfaces.extra]\ntype = \"wg\"\naddress = [\"10.30.0.1/24\"]\nprivate_key = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\n",
        valid_config()
    )).unwrap();
    assert!(current
        .validate_reload_compatibility(&added_interface)
        .unwrap_err()
        .to_string()
        .contains("add or remove interfaces"));
}

#[test]
fn reload_compatibility_rejects_interface_address_mtu_and_listen_port_changes() {
    let current = Config::parse_toml(&valid_config()).unwrap();

    let mut changed_address = current.clone();
    changed_address
        .interfaces
        .get_mut("wg-server")
        .unwrap()
        .address = vec!["10.10.0.9/24".to_owned()];
    changed_address.validate().unwrap();
    assert!(current
        .validate_reload_compatibility(&changed_address)
        .unwrap_err()
        .to_string()
        .contains("immutable tunnel parameters"));

    let mut changed_mtu = current.clone();
    changed_mtu.interfaces.get_mut("wg-server").unwrap().mtu = 1400;
    changed_mtu.validate().unwrap();
    assert!(current
        .validate_reload_compatibility(&changed_mtu)
        .unwrap_err()
        .to_string()
        .contains("immutable tunnel parameters"));

    let mut changed_listen_port = current.clone();
    changed_listen_port
        .interfaces
        .get_mut("wg-server")
        .unwrap()
        .listen_port = Some(51822);
    changed_listen_port.validate().unwrap();
    assert!(current
        .validate_reload_compatibility(&changed_listen_port)
        .unwrap_err()
        .to_string()
        .contains("immutable tunnel parameters"));

    let mut changed_tunnel_type = current.clone();
    let awg_uplink = changed_tunnel_type
        .interfaces
        .get_mut("awg-uplink")
        .unwrap();
    awg_uplink.tunnel_type = TunnelType::WireGuard;
    awg_uplink.awg = AmneziaWgConfig::default();
    changed_tunnel_type.validate().unwrap();
    assert!(current
        .validate_reload_compatibility(&changed_tunnel_type)
        .unwrap_err()
        .to_string()
        .contains("immutable tunnel parameters"));

    let mut removed_interface = current.clone();
    removed_interface.interfaces.remove("awg-uplink");
    removed_interface.routing.rules.clear();
    removed_interface.validate().unwrap();
    assert!(current
        .validate_reload_compatibility(&removed_interface)
        .unwrap_err()
        .to_string()
        .contains("add or remove interfaces"));
}

#[test]
fn firewall_allow_rules_parse_and_validate() {
    let input = format!(
        "{}\n[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nsource = [\"10.10.0.2/32\"]\nprotocol = \"tcp\"\nports = [22, 443]\n[firewall.output]\n[[firewall.output.rules]]\ninterface = \"awg-uplink\"\ndestination = \"0.0.0.0/0\"\nprotocol = \"udp\"\nports = [53]\n",
        valid_config()
    );
    let config = Config::parse_toml(&input).unwrap();
    assert_eq!(config.firewall.input.rules.len(), 1);
    assert_eq!(config.firewall.output.rules.len(), 1);
    assert_eq!(
        config.firewall.input.rules[0].protocol,
        Some(FirewallProtocol::Tcp)
    );
    assert_eq!(
        config.firewall.output.rules[0].ports.as_deref(),
        Some(&[53][..])
    );
}

#[test]
fn firewall_rules_reject_unknown_interfaces_and_wrong_direction_selectors() {
    let unknown = format!(
        "{}\n[[firewall.input.rules]]\ninterface = \"missing\"\n",
        valid_config()
    );
    assert!(Config::parse_toml(&unknown).is_err());

    let wrong_direction = format!(
        "{}\n[[firewall.input.rules]]\ninterface = \"wg-server\"\ndestination = \"10.0.0.0/24\"\n",
        valid_config()
    );
    assert!(Config::parse_toml(&wrong_direction).is_err());
}

#[test]
fn routing_rule_resolves_nat_fields_into_a_typed_action() {
    let mut rule: RoutingRule = toml::from_str(
        r#"
            priority = 1
            ingress = "wg-server"
            egress = "awg-uplink"
        "#,
    )
    .unwrap();
    assert_eq!(rule.nat_action(), NatAction::None);

    rule.nat = NatMode::Masquerade;
    assert_eq!(rule.nat_action(), NatAction::Masquerade);

    rule.nat = NatMode::Snat;
    rule.nat_to = Some("203.0.113.9".parse().unwrap());
    assert_eq!(
        rule.nat_action(),
        NatAction::Snat("203.0.113.9".parse().unwrap())
    );
}

#[test]
fn static_snat_requires_an_ipv4_address() {
    let missing_address = valid_config().replacen(
        "egress = \"awg-uplink\"",
        "egress = \"awg-uplink\"\nnat = \"snat\"",
        1,
    );
    assert!(Config::parse_toml(&missing_address).is_err());

    let valid_snat = valid_config().replacen(
        "egress = \"awg-uplink\"",
        "egress = \"awg-uplink\"\nnat = \"snat\"\nnat_to = \"203.0.113.9\"",
        1,
    );
    let parsed = Config::parse_toml(&valid_snat).unwrap();
    assert_eq!(parsed.routing.rules[0].nat, NatMode::Snat);
    assert_eq!(
        parsed.routing.rules[0].nat_to,
        Some("203.0.113.9".parse().unwrap())
    );
}

#[test]
fn routing_rule_nat_defaults_to_none_and_supports_source_selector() {
    let input = valid_config().replace(
        "destination = \"0.0.0.0/0\"",
        "source = \"10.10.0.0/24\"\ndestination = \"0.0.0.0/0\"\nnat = \"masquerade\"",
    );
    let config = Config::parse_toml(&input).unwrap();
    assert_eq!(
        config.routing.rules[0].source.as_deref(),
        Some(&["10.10.0.0/24".to_owned()][..])
    );
    assert_eq!(config.routing.rules[0].nat, NatMode::Masquerade);
    let default_config = Config::parse_toml(&valid_config()).unwrap();
    assert_eq!(default_config.routing.rules[0].nat, NatMode::None);
}

#[test]
fn routing_rule_allows_both_ip_selectors_to_be_omitted() {
    let input = valid_config().replace("destination = \"0.0.0.0/0\"\n", "");
    let config = Config::parse_toml(&input).unwrap();
    assert!(config.routing.rules[0].source.is_none());
    assert!(config.routing.rules[0].destination.is_none());
}

#[test]
fn routing_rule_accepts_multiple_source_and_destination_cidrs() {
    let input = valid_config().replace(
        "destination = \"0.0.0.0/0\"",
        "source = [\"10.10.0.0/24\", \"10.10.1.0/24\"]\ndestination = [\"0.0.0.0/0\", \"203.0.113.0/24\"]",
    );
    let config = Config::parse_toml(&input).unwrap();
    assert_eq!(config.routing.rules[0].source.as_ref().unwrap().len(), 2);
    assert_eq!(
        config.routing.rules[0].destination.as_ref().unwrap().len(),
        2
    );
}

#[test]
fn persistent_keepalive_range_is_validated_and_mutually_exclusive() {
    let ranged = valid_config().replace(
        "persistent_keepalive_secs = 25",
        "persistent_keepalive_secs = \"25-35\"",
    );
    let config = Config::parse_toml(&ranged).unwrap();
    assert_eq!(
        config.interfaces["awg-uplink"].peers[0].persistent_keepalive_secs,
        Some(PersistentKeepaliveConfig::Range("25-35".to_owned()))
    );

    for range in ["35-25", "0-25", "25-0", "1-2-3", "4294967296-4294967297"] {
        let input = valid_config().replace(
            "persistent_keepalive_secs = 25",
            &format!("persistent_keepalive_secs = \"{range}\""),
        );
        assert!(
            Config::parse_toml(&input).is_err(),
            "accepted range {range}"
        );
    }

    let fixed = Config::parse_toml(&valid_config()).unwrap();
    assert_eq!(
        fixed.interfaces["awg-uplink"].peers[0].persistent_keepalive_secs,
        Some(PersistentKeepaliveConfig::Seconds(25))
    );

    let both = valid_config().replace(
        "persistent_keepalive_secs = 25",
        "persistent_keepalive_secs = 25\npersistent_keepalive_range = [25, 35]",
    );
    assert!(Config::parse_toml(&both)
        .unwrap_err()
        .to_string()
        .contains("must not set both"));
}

#[test]
fn configuration_uses_only_the_canonical_singular_address_key() {
    let input = valid_config().replace("address =", "addresses =");
    assert!(Config::parse_toml(&input).is_err());
}

#[test]
fn awg_parameters_are_flattened_and_legacy_nested_table_is_rejected() {
    let config = Config::parse_toml(&valid_config()).unwrap();
    let awg = &config.interfaces["awg-uplink"];
    assert_eq!(awg.awg.jc, Some(5));

    let serialized = toml::to_string(awg).unwrap();
    assert!(serialized.contains("jc = 5"));
    assert!(!serialized.contains("[awg]"));

    let legacy = valid_config().replace("jc = 5\n", "") + "\n[interfaces.awg-uplink.awg]\njc = 5\n";
    let error = Config::parse_toml(&legacy).unwrap_err().to_string();
    assert!(error.contains("move AWG parameters directly into [interfaces.awg-uplink]"));
}

#[test]
fn unknown_flattened_interface_keys_are_rejected() {
    let input = valid_config().replace("mtu = 1380", "mtu = 1380\nmtuu = 1400");
    let error = Config::parse_toml(&input).unwrap_err().to_string();
    assert!(error.contains(".mtuu"));
}

#[test]
fn config_selects_tunnel_family_without_exposing_awg_generation() {
    let config = Config::parse_toml(&valid_config()).unwrap();
    assert_eq!(
        config.interfaces["wg-server"].tunnel_type,
        TunnelType::WireGuard
    );
    assert_eq!(
        config.interfaces["awg-uplink"].tunnel_type,
        TunnelType::AmneziaWg
    );
}

#[test]
fn parses_awg_30_and_31_extension_parameters() {
    let input = valid_config()
        .replace("s1 = 0", "s1 = 12")
        .replace("s2 = 0", "s2 = 12")
        .replace("s3 = 0", "s3 = 12")
        .replace("s4 = 0", "s4 = 12")
        .replace(
            "h4 = \"301-400\"",
            concat!(
                "h4 = \"301-400\"\n",
                "i1 = \"<b 0x4142><r 8>\"\n",
                "i2 = \"<t>\"\n",
                "i3 = \"<rc 4>\"\n",
                "i4 = \"<rd 4>\"\n",
                "i5 = \"<dz 2>\"\n",
                "header_protection_key = \"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=\"\n",
                "content_padding_addition = \"10-100\"\n",
                "rekey_after_time = \"100-120\"\n",
                "rekey_timeout = \"3-8\"\n",
                "reject_after_time = \"150-180\"\n",
                "keepalive_timeout = \"7-13\"\n",
                "max_handshake_attempts = \"15-20\""
            ),
        );
    let config = Config::parse_toml(&input).unwrap();
    crate::backend::BackendRegistry::default()
        .validate_config(&config)
        .unwrap();
}

#[test]
fn rejects_invalid_awg_extension_values() {
    for (field, value) in [
        ("header_protection_key", "\"abcd\""),
        (
            "header_protection_key",
            "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"",
        ),
        ("content_padding_addition", "\"100-10\""),
        ("rekey_timeout", "\"8-3\""),
        ("i1", "\"<unknown 2>\""),
    ] {
        let input = valid_config().replace(
            "h4 = \"301-400\"",
            &format!("h4 = \"301-400\"\n{} = {}", field, value),
        );
        let config = Config::parse_toml(&input).unwrap();
        assert!(
            crate::backend::BackendRegistry::default()
                .validate_config(&config)
                .is_err(),
            "{}",
            field
        );
    }
}

#[test]
fn parses_and_validates_a_complete_multi_tunnel_config() {
    let config = Config::parse_toml(&valid_config()).unwrap();
    assert_eq!(config.interfaces.len(), 2);
    assert_eq!(config.routing.rules.len(), 2);
    assert_eq!(
        config.interfaces["awg-uplink"].tunnel_type,
        TunnelType::AmneziaWg
    );
    assert!(config.interfaces.contains_key("wg-server"));
    assert_eq!(config.interfaces["wg-server"].peers.len(), 1);
    assert_eq!(config.interfaces["awg-uplink"].peers.len(), 1);
    assert_eq!(config.resolved_socket_fwmarks().unwrap(), vec![4098, 4097]);
}

#[test]
fn shipped_example_configuration_parses_with_named_sections() {
    let config = Config::parse_toml(include_str!("../vpn-relay.example.toml")).unwrap();
    assert!(config.interfaces.contains_key("wg-server"));
    assert_eq!(config.interfaces["wg-server"].peers.len(), 1);
    assert_eq!(config.interfaces["awg-primary"].peers.len(), 1);
    assert_eq!(config.interfaces["awg-secondary"].peers.len(), 1);
}

#[test]
fn named_interfaces_and_unnamed_peer_arrays_parse() {
    let config = Config::parse_toml(&valid_config()).unwrap();
    assert_eq!(
        config
            .interfaces
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["awg-uplink", "wg-server"]
    );
    assert_eq!(config.interfaces["wg-server"].peers.len(), 1);
    assert_eq!(config.interfaces["awg-uplink"].peers.len(), 1);
}

#[test]
fn interfaces_without_peers_are_valid() {
    let input = valid_config()
        .replace(
            &format!(
                "[[interfaces.wg-server.peers]]\npublic_key = \"{KEY}\"\nallowed_ips = [\"10.10.0.2/32\"]\n\n"
            ),
            "",
        )
        .replace(
            &format!(
                "[[interfaces.awg-uplink.peers]]\npublic_key = \"{KEY}\"\nendpoint = \"198.51.100.10:51820\"\nallowed_ips = [\"0.0.0.0/0\"]\npersistent_keepalive_secs = 25\n\n"
            ),
            "",
        );
    let config = Config::parse_toml(&input).unwrap();
    assert!(config
        .interfaces
        .values()
        .all(|interface| interface.peers.is_empty()));
}

#[test]
fn rejects_duplicate_peer_public_keys_in_unnamed_peer_array() {
    let input = valid_config().replace(
        "[interfaces.awg-uplink]",
        &format!(
            "[[interfaces.wg-server.peers]]\npublic_key = \"{}\"\nallowed_ips = [\"10.10.0.3/32\"]\n\n[interfaces.awg-uplink]",
            KEY
        ),
    );
    let error = Config::parse_toml(&input).unwrap_err();
    assert!(error.to_string().contains("duplicate peer public keys"));
}

#[test]
fn parses_dns_peer_endpoints_without_resolving_them() {
    let endpoint = PeerEndpoint::parse("VPN.Example.COM:51820").unwrap();
    assert_eq!(
        endpoint,
        PeerEndpoint {
            host: EndpointHost::Dns("vpn.example.com".to_owned()),
            port: 51820,
        }
    );
    assert_eq!(
        PeerEndpoint::parse("xn--bcher-kva.example:443")
            .unwrap()
            .port,
        443
    );
}

#[test]
fn parses_ipv4_peer_endpoints() {
    assert_eq!(PeerEndpoint::parse("192.0.2.1:51820").unwrap().port, 51820);
}

#[test]
fn rejects_malformed_dns_endpoints_and_zero_ports() {
    for value in [
        "bad..example:51820",
        "-bad.example:51820",
        "bad-.example:51820",
        "bad_name.example:51820",
        "münich.example:51820",
        "example.com:0",
        "example.com:not-a-port",
    ] {
        assert!(
            PeerEndpoint::parse(value).is_err(),
            "endpoint should be rejected: {value}"
        );
    }
}

#[test]
fn rejects_invalid_key_lengths() {
    let input = valid_config().replace(KEY, "AQID");
    let error = Config::parse_toml(&input).unwrap_err();
    assert!(error.to_string().contains("exactly 32 bytes"));
}

#[test]
fn socket_fwmarks_are_automatically_assigned_when_omitted() {
    let input = valid_config()
        .replace("socket_fwmark = 4097\n", "")
        .replace("socket_fwmark = 4098\n", "");
    let config = Config::parse_toml(&input).unwrap();
    assert_eq!(
        config.resolved_socket_fwmarks().unwrap(),
        vec![0x1000, 0x1001]
    );
}

#[test]
fn automatic_socket_marks_skip_explicit_values_regardless_of_interface_order() {
    let input = valid_config()
        .replace("socket_fwmark = 4097\n", "")
        .replace("socket_fwmark = 4098", "socket_fwmark = 4096");
    let config = Config::parse_toml(&input).unwrap();
    assert_eq!(config.resolved_socket_fwmarks().unwrap(), vec![4096, 4097]);
}

#[test]
fn automatic_socket_marks_skip_the_inner_routing_mark_range() {
    let input = valid_config()
        .replace("socket_fwmark = 4097\n", "")
        .replace("socket_fwmark = 4098\n", "")
        .replacen(
            "[[routing.rules]]",
            "[routing]\nmark_base = 4096\n\n[[routing.rules]]",
            1,
        );
    let config = Config::parse_toml(&input).unwrap();
    assert_eq!(config.resolved_socket_fwmarks().unwrap(), vec![4097, 4098]);
}

#[test]
fn explicit_socket_fwmarks_are_preserved_when_mixed_with_automatic_marks() {
    let input = valid_config().replace("socket_fwmark = 4097\n", "");
    let config = Config::parse_toml(&input).unwrap();
    assert_eq!(config.resolved_socket_fwmarks().unwrap(), vec![4098, 4096]);
}

#[test]
fn rejects_explicit_socket_mark_inside_packet_mark_range() {
    let input = valid_config().replace("socket_fwmark = 4097", "socket_fwmark = 2147483648");
    let error = Config::parse_toml(&input).unwrap_err();
    assert!(error.to_string().contains("mark_base range overlaps"));
}

#[test]
fn rejects_duplicate_socket_fwmarks() {
    let input = valid_config().replace("socket_fwmark = 4098", "socket_fwmark = 4097");
    let error = Config::parse_toml(&input).unwrap_err();
    assert!(error.to_string().contains("socket fwmark"));
}

#[test]
fn rejects_overlapping_awg_header_ranges() {
    let input = valid_config().replace("h2 = \"101-200\"", "h2 = \"50-200\"");
    let config = Config::parse_toml(&input).unwrap();
    let error = crate::backend::BackendRegistry::default()
        .validate_config(&config)
        .unwrap_err();
    assert!(
        error.to_string().contains("H1-H4 ranges"),
        "unexpected validation error: {error}"
    );
}

#[test]
fn rejects_more_routing_decisions_than_conntrack_mark_space_supports() {
    let mut config = Config::parse_toml(&valid_config()).unwrap();
    let template = config.routing.rules[0].clone();
    config
        .routing
        .rules
        .resize(MAX_ROUTING_DECISIONS + 1, template);

    let error = config.validate().unwrap_err();
    assert!(error
        .to_string()
        .contains("at most 4095 entries because conntrack decision marks"));
}

#[test]
fn rejects_unknown_fields_instead_of_ignoring_typos() {
    let input = valid_config().replace("mtu = 1380", "mtu = 1380\nmtuu = 1400");
    let error = Config::parse_toml(&input).unwrap_err();
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn rejects_duplicate_priorities_for_the_same_ingress() {
    let input = valid_config().replace("priority = 110", "priority = 100");
    let error = Config::parse_toml(&input).unwrap_err();
    assert!(error.to_string().contains("duplicate priority"));
}

#[test]
fn allows_the_same_priority_on_different_ingresses() {
    let input = valid_config().replace("priority = 110", "priority = 100");
    // Duplicate priorities are scoped to an ingress. The validation
    // fixture has one ingress, so move the second rule to another valid
    // server interface before parsing.
    let input = input.replace(
        "[interfaces.awg-uplink]",
        "[interfaces.wg-backup]\ntype = \"wg\"\naddress = [\"10.11.0.1/24\"]\nlisten_port = 51823\nprivate_key = \"{KEY}\"\nsocket_fwmark = 4100\n\n[interfaces.awg-uplink]",
    ).replace("priority = 100\ningress = \"wg-server\"\ndestination = \"0.0.0.0/0\"", "priority = 100\ningress = \"wg-backup\"\ndestination = \"0.0.0.0/0\" ")
    .replace("{KEY}", KEY);
    assert!(Config::parse_toml(&input).is_ok());
}

#[test]
fn rejects_unknown_routing_ingress_and_egress() {
    let unknown_ingress =
        valid_config().replace("ingress = \"wg-server\"", "ingress = \"wg-missing\"");
    assert!(Config::parse_toml(&unknown_ingress)
        .unwrap_err()
        .to_string()
        .contains("unknown ingress"));

    let unknown_egress =
        valid_config().replace("egress = \"awg-uplink\"", "egress = \"awg-missing\"");
    assert!(Config::parse_toml(&unknown_egress)
        .unwrap_err()
        .to_string()
        .contains("unknown egress"));
}

#[test]
fn rejects_same_interface_as_ingress_and_egress() {
    let input = valid_config().replace("egress = \"awg-uplink\"", "egress = \"wg-server\"");
    assert!(Config::parse_toml(&input)
        .unwrap_err()
        .to_string()
        .contains("both ingress and egress"));
}

#[test]
fn interfaces_can_be_used_in_both_routing_directions() {
    let input = valid_config().replace(
        "priority = 110\ningress = \"wg-server\"\ndestination = \"203.0.113.0/24\"\negress = \"awg-uplink\"",
        "priority = 110\ningress = \"awg-uplink\"\ndestination = \"10.0.0.0/24\"\negress = \"wg-server\""
    );
    let config = Config::parse_toml(&input).unwrap();
    assert_eq!(config.resolved_routing_fwmarks().unwrap().len(), 2);
}

#[test]
fn routing_marks_are_allocated_only_for_distinct_configured_egresses() {
    let mut config = Config::parse_toml(&valid_config()).unwrap();
    config.routing.rules.truncate(1);
    assert_eq!(
        config.resolved_routing_fwmarks().unwrap(),
        vec![config.routing.mark_base]
    );
}

#[test]
fn rejects_empty_or_invalid_routing_cidr_selectors() {
    let empty_source = valid_config().replace(
        "destination = \"0.0.0.0/0\"",
        "source = []\ndestination = \"0.0.0.0/0\"",
    );
    assert!(Config::parse_toml(&empty_source)
        .unwrap_err()
        .to_string()
        .contains("source must not be an empty list"));

    let invalid_destination = valid_config().replace(
        "destination = \"0.0.0.0/0\"",
        "destination = \"not-a-cidr\"",
    );
    assert!(Config::parse_toml(&invalid_destination)
        .unwrap_err()
        .to_string()
        .contains("invalid CIDR"));
}

#[test]
fn rejects_unknown_nat_modes() {
    let input = valid_config().replace(
        "destination = \"0.0.0.0/0\"",
        "destination = \"0.0.0.0/0\"\nnat = \"snat\"",
    );
    assert!(Config::parse_toml(&input).is_err());
}

#[test]
fn rejects_duplicate_routing_cidr_selectors() {
    let duplicate_source = valid_config().replace(
        "destination = \"0.0.0.0/0\"",
        "source = [\"10.10.0.0/24\", \"10.10.0.0/24\"]\ndestination = \"0.0.0.0/0\"",
    );
    assert!(Config::parse_toml(&duplicate_source)
        .unwrap_err()
        .to_string()
        .contains("source must not contain duplicate CIDR selectors"));

    let duplicate_destination = valid_config().replace(
        "destination = \"0.0.0.0/0\"",
        "destination = [\"0.0.0.0/0\", \"0.0.0.0/0\"]",
    );
    assert!(Config::parse_toml(&duplicate_destination)
        .unwrap_err()
        .to_string()
        .contains("destination must not contain duplicate CIDR selectors"));
}

#[test]
fn rejects_equivalent_cidr_networks_with_different_host_bits() {
    let source = valid_config().replace(
        "destination = \"0.0.0.0/0\"",
        "source = [\"10.10.0.0/24\", \"10.10.0.99/24\"]\ndestination = \"0.0.0.0/0\"",
    );
    assert!(Config::parse_toml(&source)
        .unwrap_err()
        .to_string()
        .contains("equivalent CIDR networks"));

    let destination = valid_config().replace(
        "destination = \"0.0.0.0/0\"",
        "destination = [\"10.10.0.0/24\", \"10.10.0.99/24\"]",
    );
    assert!(Config::parse_toml(&destination)
        .unwrap_err()
        .to_string()
        .contains("equivalent CIDR networks"));
}

#[test]
fn rejects_empty_firewall_selectors_and_unknown_interfaces() {
    let empty_input = format!(
        "{}\n[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nsource = []\n",
        valid_config()
    );
    assert!(Config::parse_toml(&empty_input)
        .unwrap_err()
        .to_string()
        .contains("firewall.input.rules[0].source must not be an empty list"));

    let empty_output = format!(
        "{}\n[firewall.output]\n[[firewall.output.rules]]\ninterface = \"awg-uplink\"\ndestination = []\n",
        valid_config()
    );
    assert!(Config::parse_toml(&empty_output)
        .unwrap_err()
        .to_string()
        .contains("firewall.output.rules[0].destination must not be an empty list"));

    let unknown_interface = format!(
        "{}\n[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-missing\"\n",
        valid_config()
    );
    assert!(Config::parse_toml(&unknown_interface)
        .unwrap_err()
        .to_string()
        .contains("firewall.input.rules[0] references unknown interface"));
}

#[test]
fn rejects_empty_zero_and_non_transport_firewall_ports() {
    let empty_ports = format!(
        "{}\n[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nprotocol = \"tcp\"\nports = []\n",
        valid_config()
    );
    assert!(Config::parse_toml(&empty_ports)
        .unwrap_err()
        .to_string()
        .contains("ports must contain one or more ports"));

    let zero_port = format!(
        "{}\n[firewall.output]\n[[firewall.output.rules]]\ninterface = \"awg-uplink\"\nprotocol = \"udp\"\nports = [0]\n",
        valid_config()
    );
    assert!(Config::parse_toml(&zero_port)
        .unwrap_err()
        .to_string()
        .contains("ports must contain one or more ports"));

    let icmp_ports = format!(
        "{}\n[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nprotocol = \"icmp\"\nports = [53]\n",
        valid_config()
    );
    assert!(Config::parse_toml(&icmp_ports)
        .unwrap_err()
        .to_string()
        .contains("ports requires protocol"));
}

#[test]
fn rejects_empty_routing_destination_list() {
    let input = valid_config().replace("destination = \"0.0.0.0/0\"", "destination = []");
    assert!(Config::parse_toml(&input)
        .unwrap_err()
        .to_string()
        .contains("routing.rules[0].destination must not be an empty list"));
}

#[test]
fn rejects_duplicate_firewall_cidr_selectors() {
    let input = format!(
        "{}\n[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nsource = [\"10.10.0.0/24\", \"10.10.0.0/24\"]\n",
        valid_config()
    );
    assert!(Config::parse_toml(&input)
        .unwrap_err()
        .to_string()
        .contains("firewall.input.rules[0].source must not contain duplicate CIDR selectors"));
}

#[test]
fn rejects_unknown_firewall_and_nat_rule_fields() {
    let unknown_nat = valid_config().replace(
        "destination = \"0.0.0.0/0\"",
        "destination = \"0.0.0.0/0\"\nnat = \"snat\"\nnat_to = \"203.0.113.9\"\nnat_target = \"203.0.113.10\"",
    );
    assert!(Config::parse_toml(&unknown_nat)
        .unwrap_err()
        .to_string()
        .contains("unknown field"));

    let unknown_firewall = valid_config().replacen(
        "[[routing.rules]]",
        "[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nprotocol = \"tcp\"\nports = [22]\nallow_all = true\n\n[[routing.rules]]",
        1,
    );
    assert!(Config::parse_toml(&unknown_firewall)
        .unwrap_err()
        .to_string()
        .contains("unknown field"));
}
