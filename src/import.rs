//! Import standard WireGuard and AmneziaWG INI configurations.
use crate::config::{Config, TunnelType};
#[cfg(test)]
use crate::config::PersistentKeepaliveConfig;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

mod parser;
use parser::parse_interface;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("failed to read source configuration: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid source configuration: {0}")]
    Parse(String),
    #[error("interface '{0}' already exists; pass --yes to replace it")]
    Exists(String),
    #[error("invalid resulting daemon configuration: {0}")]
    Config(String),
    #[error("cannot update daemon configuration: {0}")]
    Write(String),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ImportReport {
    pub tunnel_type: TunnelType,
    pub warnings: Vec<String>,
    pub replaced: bool,
}


pub fn interface_exists(config_path: &Path, name: &str) -> Result<bool, ImportError> {
    if !config_path.exists() {
        return Ok(false);
    }
    let source = fs::read_to_string(config_path)?;
    let value: toml::Value = source
        .parse()
        .map_err(|e: toml::de::Error| ImportError::Config(e.to_string()))?;
    Ok(value.get("interfaces").and_then(|v| v.get(name)).is_some())
}

/// Parse an imported WireGuard/AmneziaWG document and merge it into an
/// in-memory configuration. This is shared by the offline file importer and
/// the daemon Control API so both paths use identical parsing and validation.
pub fn import_into_config(
    current: &Config,
    source: &str,
    name: &str,
    replace: bool,
) -> Result<(Config, ImportReport), ImportError> {
    let (interface, warnings) = parse_interface(source)?;
    let replaced = current.interfaces.contains_key(name);
    if replaced && !replace {
        return Err(ImportError::Exists(name.to_owned()));
    }
    let mut candidate = current.clone();
    candidate
        .interfaces
        .insert(name.to_owned(), interface.clone());
    candidate
        .validate()
        .map_err(|error| ImportError::Config(error.to_string()))?;
    #[cfg(target_os = "linux")]
    crate::backend::BackendRegistry::default()
        .validate_config(&candidate)
        .map_err(|error| ImportError::Config(error.to_string()))?;
    Ok((
        candidate,
        ImportReport {
            tunnel_type: interface.tunnel_type,
            warnings,
            replaced,
        },
    ))
}

pub fn import_file(
    source_path: &Path,
    config_path: &Path,
    name: &str,
    replace: bool,
) -> Result<ImportReport, ImportError> {
    let source = fs::read_to_string(source_path)?;
    let (interface, warnings) = parse_interface(&source)?;
    if config_path.exists() {
        let current = fs::read_to_string(config_path)?;
        let mut root: toml::Value = current
            .parse()
            .map_err(|e: toml::de::Error| ImportError::Config(e.to_string()))?;
        let interfaces = root
            .as_table_mut()
            .and_then(|t| t.get_mut("interfaces"))
            .and_then(toml::Value::as_table_mut)
            .ok_or_else(|| {
                ImportError::Config("existing configuration has no [interfaces] table".into())
            })?;
        let replaced = interfaces.contains_key(name);
        if replaced && !replace {
            return Err(ImportError::Exists(name.into()));
        }
        let value =
            toml::Value::try_from(&interface).map_err(|e| ImportError::Config(e.to_string()))?;
        interfaces.insert(name.to_owned(), value);
        let rendered =
            toml::to_string_pretty(&root).map_err(|e| ImportError::Config(e.to_string()))?;
        validate_rendered_config(&rendered)?;
        atomic_write(config_path, rendered.as_bytes())?;
        Ok(ImportReport {
            tunnel_type: interface.tunnel_type,
            warnings,
            replaced,
        })
    } else {
        let mut root = toml::map::Map::new();
        root.insert(
            "interfaces".into(),
            toml::Value::Table(toml::map::Map::new()),
        );
        let mut value = toml::Value::Table(root);
        let interfaces = value
            .get_mut("interfaces")
            .and_then(toml::Value::as_table_mut)
            .unwrap();
        interfaces.insert(
            name.to_owned(),
            toml::Value::try_from(&interface).map_err(|e| ImportError::Config(e.to_string()))?,
        );
        let rendered =
            toml::to_string_pretty(&value).map_err(|e| ImportError::Config(e.to_string()))?;
        validate_rendered_config(&rendered)?;
        atomic_write(config_path, rendered.as_bytes())?;
        Ok(ImportReport {
            tunnel_type: interface.tunnel_type,
            warnings,
            replaced: false,
        })
    }
}

fn validate_rendered_config(rendered: &str) -> Result<(), ImportError> {
    let config =
        Config::parse_toml(rendered).map_err(|error| ImportError::Config(error.to_string()))?;
    #[cfg(target_os = "linux")]
    crate::backend::BackendRegistry::default()
        .validate_config(&config)
        .map_err(|error| ImportError::Config(error.to_string()))?;
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), ImportError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("toml.tmp.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(ImportError::Write(error.to_string()));
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = r#"[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
DNS = 1.1.1.1
MTU = 1380

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = localhost:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"#;

    #[test]
    fn imports_ipv4_wireguard_profiles_without_inferring_router_roles() {
        let (cfg, warnings) = parse_interface(CLIENT).unwrap();
        assert_eq!(cfg.tunnel_type, TunnelType::WireGuard);
        assert_eq!(cfg.address, vec!["10.0.0.2/32"]);
        assert_eq!(cfg.listen_port, None);
        assert_eq!(
            cfg.peers[0].persistent_keepalive_secs,
            Some(PersistentKeepaliveConfig::Seconds(25))
        );
        assert_eq!(cfg.peers[0].persistent_keepalive_range, None);
        assert!(warnings.iter().any(|w| w.contains("DNS")));
    }

    #[test]
    fn imports_ipv4_amnezia_persistent_keepalive_ranges_and_disable_values() {
        let range = CLIENT.replace("PersistentKeepalive = 25", "PersistentKeepalive = 25-35");
        let (cfg, _) = parse_interface(&range).unwrap();
        assert_eq!(
            cfg.peers[0].persistent_keepalive_secs,
            Some(PersistentKeepaliveConfig::Range("25-35".to_owned()))
        );
        assert_eq!(cfg.peers[0].persistent_keepalive_range, None);

        for value in ["off", "0", "0-0"] {
            let input = CLIENT.replace(
                "PersistentKeepalive = 25",
                &format!("PersistentKeepalive = {value}"),
            );
            let (cfg, _) = parse_interface(&input).unwrap();
            assert_eq!(cfg.peers[0].persistent_keepalive_secs, None);
            assert_eq!(cfg.peers[0].persistent_keepalive_range, None);
        }
    }

    #[test]
    fn rejects_invalid_persistent_keepalive_ranges() {
        for value in ["35-25", "0-25", "25-0", "1-2-3", "4294967296-4294967297"] {
            let input = CLIENT.replace(
                "PersistentKeepalive = 25",
                &format!("PersistentKeepalive = {value}"),
            );
            assert!(
                parse_interface(&input).is_err(),
                "accepted invalid range {value}"
            );
        }
    }

    #[test]
    fn importing_and_replacing_an_interface_preserves_other_interfaces() {
        let directory =
            std::env::temp_dir().join(format!("vpn-relay-import-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let source_path = directory.join("wg.conf");
        let config_path = directory.join("config.toml");
        fs::write(&source_path, CLIENT).unwrap();

        import_file(&source_path, &config_path, "wg-client", false).unwrap();
        import_file(&source_path, &config_path, "wg-backup", false).unwrap();

        let before_declined_replace = fs::read_to_string(&config_path).unwrap();
        assert!(matches!(
            import_file(&source_path, &config_path, "wg-client", false),
            Err(ImportError::Exists(_))
        ));
        assert_eq!(
            fs::read_to_string(&config_path).unwrap(),
            before_declined_replace
        );

        let report = import_file(&source_path, &config_path, "wg-client", true).unwrap();
        assert!(report.replaced);
        let config = Config::load(&config_path).unwrap();
        assert_eq!(config.interfaces.len(), 2);
        assert_eq!(config.interfaces["wg-client"].address, vec!["10.0.0.2/32"]);
        assert_eq!(config.interfaces["wg-client"].listen_port, None);
        assert_eq!(config.interfaces["wg-backup"].listen_port, None);

        let rendered = fs::read_to_string(&config_path).unwrap();
        assert!(rendered.contains("address ="));
        assert!(!rendered.contains("addresses ="));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn in_memory_import_builds_a_candidate_without_writing_the_source_config() {
        let directory =
            std::env::temp_dir().join(format!("vpn-relay-import-api-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let source_path = directory.join("wg.conf");
        let config_path = directory.join("config.toml");
        fs::write(&source_path, CLIENT).unwrap();
        import_file(&source_path, &config_path, "wg0", false).unwrap();

        let original_text = fs::read_to_string(&config_path).unwrap();
        let current = Config::load(&config_path).unwrap();
        let (candidate, report) = import_into_config(&current, CLIENT, "wg1", false).unwrap();

        assert_eq!(current.interfaces.len(), 1);
        assert_eq!(candidate.interfaces.len(), 2);
        assert!(!report.replaced);
        assert_eq!(fs::read_to_string(&config_path).unwrap(), original_text);
        assert!(matches!(
            import_into_config(&current, CLIENT, "wg0", false),
            Err(ImportError::Exists(_))
        ));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn imports_awg_parameter_profiles_as_awg_tunnel() {
        let base = CLIENT.replace("DNS = 1.1.1.1\n", "");
        let profiles = [
            ("Jc = 4\nS1 = 16", TunnelType::AmneziaWg),
            ("I1 = <t>", TunnelType::AmneziaWg),
            ("S3 = 16\nH1 = 1-100", TunnelType::AmneziaWg),
            ("S3 = 0\nS4 = 0\nI1 = <t>", TunnelType::AmneziaWg),
            (
                "HeaderProtectionKey = 0000000000000000000000000000000000000000000000000000000000000000",
                TunnelType::AmneziaWg,
            ),
            ("RandomTrailers = true", TunnelType::AmneziaWg),
        ];

        for (parameters, expected) in profiles {
            let input = base.replace("MTU = 1380", &format!("MTU = 1380\n{parameters}"));
            assert_eq!(parse_interface(&input).unwrap().0.tunnel_type, expected);
        }
    }

    #[test]
    fn imports_mixed_peer_endpoint_configuration_without_guessing_a_role() {
        let input = format!(
            "{}\n[Peer]\nPublicKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\nAllowedIPs = 10.0.0.3/32\n",
            CLIENT
        );
        assert!(parse_interface(&input).is_ok());
    }
}
