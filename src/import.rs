//! Import standard WireGuard and AmneziaWG INI configurations.
#[cfg(test)]
use crate::config::PersistentKeepaliveConfig;
use crate::config::{Config, TunnelType};
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
mod tests;
