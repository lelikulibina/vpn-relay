//! WireGuard and AmneziaWG profile parsing and conversion.

use super::ImportError;
use crate::config::{
    InterfaceConfig, PeerConfig, PeerEndpoint, PersistentKeepaliveConfig, TunnelType,
};
use boringtun::noise::amnezia::AmneziaWgConfig;
use std::collections::HashMap;

#[derive(Clone, Copy)]
enum Section {
    Interface,
    Peer(usize),
}

pub(super) fn parse_interface(source: &str) -> Result<(InterfaceConfig, Vec<String>), ImportError> {
    let mut section = None;
    let mut interface = HashMap::<String, String>::new();
    let mut peers = Vec::<HashMap<String, String>>::new();
    for (line_index, raw) in source.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            match line[1..line.len() - 1].trim().to_ascii_lowercase().as_str() {
                "interface" => {
                    if section.is_some() {
                        return Err(parse_error(line_index, "duplicate [Interface] section"));
                    }
                    section = Some(Section::Interface);
                }
                "peer" => {
                    peers.push(HashMap::new());
                    section = Some(Section::Peer(peers.len() - 1));
                }
                other => {
                    return Err(parse_error(
                        line_index,
                        &format!("unsupported section [{other}]"),
                    ))
                }
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(parse_error(line_index, "expected Key = Value"));
        };
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(parse_error(line_index, "empty key"));
        }
        let value = unquote(value.trim());
        let target = match section {
            Some(Section::Interface) => &mut interface,
            Some(Section::Peer(index)) => &mut peers[index],
            None => return Err(parse_error(line_index, "key appears before a section")),
        };
        if target.insert(key.clone(), value).is_some() {
            return Err(parse_error(line_index, &format!("duplicate key '{key}'")));
        }
    }
    if !interface.contains_key("privatekey") {
        return Err(ImportError::Parse("[Interface] requires PrivateKey".into()));
    }
    let address = list_required(&interface, "address", "[Interface] Address")?;
    let private_key = required(&interface, "privatekey", "[Interface] PrivateKey")?.to_owned();
    let listen_port = interface
        .get("listenport")
        .map(|v| parse_number::<u16>(v, "ListenPort"))
        .transpose()?;
    let mtu = interface
        .get("mtu")
        .map(|v| parse_number::<u16>(v, "MTU"))
        .transpose()?
        .unwrap_or(1380);
    let socket_fwmark = interface
        .get("fwmark")
        .map(|v| parse_fwmark(v))
        .transpose()?;
    let mut warnings = Vec::new();
    for key in interface.keys() {
        if !matches!(
            key.as_str(),
            "privatekey"
                | "address"
                | "listenport"
                | "mtu"
                | "fwmark"
                | "dns"
                | "table"
                | "preup"
                | "postup"
                | "predown"
                | "postdown"
                | "saveconfig"
                | "jc"
                | "jmin"
                | "jmax"
                | "s1"
                | "s2"
                | "s3"
                | "s4"
                | "h1"
                | "h2"
                | "h3"
                | "h4"
                | "i1"
                | "i2"
                | "i3"
                | "i4"
                | "i5"
                | "headerprotectionkey"
                | "contentpaddingaddition"
                | "rekeyaftertime"
                | "rekeytimeout"
                | "rejectaftertime"
                | "keepalivetimeout"
                | "maxhandshakeattempts"
                | "randomtrailers"
                | "disablecookies"
        ) {
            warnings.push(format!(
                "[Interface] {key} is not supported and was not imported"
            ));
        }
    }
    for key in [
        "dns",
        "table",
        "preup",
        "postup",
        "predown",
        "postdown",
        "saveconfig",
    ] {
        if interface.contains_key(key) {
            warnings.push(format!(
                "[Interface] {} is not applied by vpn-relay",
                display_key(key)
            ));
        }
    }

    let mut parsed_peers = Vec::new();
    if address.iter().any(|a| a.contains(':')) {
        return Err(ImportError::Parse(
            "IPv6 interface addresses are not supported by vpn-relay".into(),
        ));
    }
    for (index, values) in peers.iter().enumerate() {
        let public_key = required(
            values,
            "publickey",
            &format!("[Peer {}] PublicKey", index + 1),
        )?
        .to_owned();
        let allowed_ips = list_optional(values, "allowedips");
        if allowed_ips.iter().any(|a| a.contains(':')) {
            return Err(ImportError::Parse(format!(
                "[Peer {}] IPv6 AllowedIPs are not supported by vpn-relay",
                index + 1
            )));
        }
        let endpoint = values.get("endpoint").cloned();
        if let Some(endpoint) = &endpoint {
            PeerEndpoint::parse(endpoint).map_err(|error| {
                ImportError::Parse(format!("[Peer {}] invalid Endpoint: {error}", index + 1))
            })?;
        }
        let persistent_keepalive_secs = values
            .get("persistentkeepalive")
            .map(|value| parse_persistent_keepalive(value))
            .transpose()?
            .flatten();
        parsed_peers.push(PeerConfig {
            public_key,
            preshared_key: values.get("presharedkey").cloned(),
            endpoint,
            allowed_ips,
            persistent_keepalive_secs,
            persistent_keepalive_range: None,
        });
        for key in values.keys() {
            if !matches!(
                key.as_str(),
                "publickey" | "presharedkey" | "endpoint" | "allowedips" | "persistentkeepalive"
            ) {
                warnings.push(format!(
                    "[Peer {}] {key} is not supported and was not imported",
                    index + 1
                ));
            }
        }
    }
    let awg = parse_awg(&interface)?;
    let tunnel_type = if awg.is_some() {
        TunnelType::AmneziaWg
    } else {
        TunnelType::WireGuard
    };
    let config = InterfaceConfig {
        tunnel_type,
        address,
        mtu,
        listen_port,
        private_key,
        socket_fwmark,
        peers: parsed_peers,
        awg: awg.unwrap_or_default(),
    };
    Ok((config, warnings))
}

fn parse_awg(values: &HashMap<String, String>) -> Result<Option<AmneziaWgConfig>, ImportError> {
    let mut a = AmneziaWgConfig::default();
    macro_rules! num {
        ($key:literal,$field:ident) => {
            if let Some(v) = values.get($key) {
                a.$field = Some(parse_number::<u16>(v, $key)?);
            }
        };
    }
    macro_rules! string {
        ($key:literal,$field:ident) => {
            if let Some(v) = values.get($key) {
                a.$field = Some(v.clone());
            }
        };
    }
    macro_rules! boolean {
        ($key:literal,$field:ident) => {
            if let Some(v) = values.get($key) {
                a.$field = Some(parse_bool(v, $key)?);
            }
        };
    }
    num!("jc", jc);
    num!("jmin", jmin);
    num!("jmax", jmax);
    num!("s1", s1);
    num!("s2", s2);
    num!("s3", s3);
    num!("s4", s4);
    string!("h1", h1);
    string!("h2", h2);
    string!("h3", h3);
    string!("h4", h4);
    string!("i1", i1);
    string!("i2", i2);
    string!("i3", i3);
    string!("i4", i4);
    string!("i5", i5);
    string!("headerprotectionkey", header_protection_key);
    string!("contentpaddingaddition", content_padding_addition);
    string!("rekeyaftertime", rekey_after_time);
    string!("rekeytimeout", rekey_timeout);
    string!("rejectaftertime", reject_after_time);
    string!("keepalivetimeout", keepalive_timeout);
    string!("maxhandshakeattempts", max_handshake_attempts);
    boolean!("randomtrailers", random_trailers);
    boolean!("disablecookies", disable_cookies);
    let any = [
        "jc",
        "jmin",
        "jmax",
        "s1",
        "s2",
        "s3",
        "s4",
        "h1",
        "h2",
        "h3",
        "h4",
        "i1",
        "i2",
        "i3",
        "i4",
        "i5",
        "headerprotectionkey",
        "contentpaddingaddition",
        "rekeyaftertime",
        "rekeytimeout",
        "rejectaftertime",
        "keepalivetimeout",
        "maxhandshakeattempts",
        "randomtrailers",
        "disablecookies",
    ]
    .iter()
    .any(|k| values.contains_key(*k));
    Ok(any.then_some(a))
}

fn required<'a>(
    v: &'a HashMap<String, String>,
    key: &str,
    label: &str,
) -> Result<&'a str, ImportError> {
    v.get(key)
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ImportError::Parse(format!("{label} is required")))
}
fn list_required(
    v: &HashMap<String, String>,
    key: &str,
    label: &str,
) -> Result<Vec<String>, ImportError> {
    let raw = required(v, key, label)?;
    let items: Vec<_> = raw
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    if items.is_empty() {
        return Err(ImportError::Parse(format!("{label} must not be empty")));
    }
    Ok(items)
}
fn list_optional(v: &HashMap<String, String>, key: &str) -> Vec<String> {
    v.get(key)
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}
fn parse_persistent_keepalive(
    value: &str,
) -> Result<Option<PersistentKeepaliveConfig>, ImportError> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("off") || value == "0" || value == "0-0" {
        return Ok(None);
    }
    if let Some((min, max)) = value.split_once('-') {
        if max.contains('-') {
            return Err(ImportError::Parse(format!(
                "invalid PersistentKeepalive range '{value}'"
            )));
        }
        let min = parse_number::<u32>(min, "PersistentKeepalive range minimum")?;
        let max = parse_number::<u32>(max, "PersistentKeepalive range maximum")?;
        if min == 0 || max == 0 || min > max {
            return Err(ImportError::Parse(format!(
                "invalid PersistentKeepalive range '{value}': expected 1 <= min <= max"
            )));
        }
        return Ok(Some(PersistentKeepaliveConfig::Range(format!(
            "{min}-{max}"
        ))));
    }
    let seconds = parse_number::<u16>(value, "PersistentKeepalive")?;
    if seconds == 0 {
        Ok(None)
    } else {
        Ok(Some(PersistentKeepaliveConfig::Seconds(seconds)))
    }
}

fn parse_number<T: std::str::FromStr>(v: &str, key: &str) -> Result<T, ImportError> {
    v.parse()
        .map_err(|_| ImportError::Parse(format!("invalid {key} value '{v}'")))
}
fn parse_fwmark(v: &str) -> Result<u32, ImportError> {
    if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
            .map_err(|_| ImportError::Parse(format!("invalid FwMark '{v}'")))
    } else {
        parse_number(v, "FwMark")
    }
}
fn parse_bool(v: &str, key: &str) -> Result<bool, ImportError> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(ImportError::Parse(format!("invalid {key} boolean '{v}'"))),
    }
}
fn unquote(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        v[1..v.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
        v[1..v.len() - 1].to_owned()
    } else {
        v.to_owned()
    }
}
fn strip_comment(v: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in v.char_indices() {
        if c == '"' && !escaped {
            quoted = !quoted;
        }
        if !quoted && (c == '#' || c == ';') {
            return &v[..i];
        }
        escaped = c == '\\' && !escaped;
        if c != '\\' {
            escaped = false;
        }
    }
    v
}
fn parse_error(line: usize, message: &str) -> ImportError {
    ImportError::Parse(format!("line {}: {message}", line + 1))
}
fn display_key(key: &str) -> &str {
    match key {
        "dns" => "DNS",
        "table" => "Table",
        "preup" => "PreUp",
        "postup" => "PostUp",
        "predown" => "PreDown",
        "postdown" => "PostDown",
        "saveconfig" => "SaveConfig",
        _ => key,
    }
}
