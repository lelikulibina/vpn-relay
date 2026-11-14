//! Runtime implementation of the transport-independent Control API.

use super::Runtime;
use crate::config::Config;
use crate::control::{
    ControlApi, ControlError, ImportConfigRequest, InterfaceStats, ReloadConfigMode,
    ReloadConfigRequest,
};

impl ControlApi for Runtime {
    fn reload_config(&mut self, request: ReloadConfigRequest) -> Result<(), ControlError> {
        let parsed = Config::parse_toml(&request.toml)
            .map_err(|error| ControlError::new(error.to_string()))?;
        let candidate = match request.mode {
            ReloadConfigMode::Full => parsed,
            ReloadConfigMode::ReplacePeers { interface } => {
                let imported = parsed.interfaces.get(&interface).ok_or_else(|| {
                    ControlError::new(format!(
                        "interface '{interface}' is missing from supplied configuration"
                    ))
                })?;
                let mut candidate = self.config.clone();
                let target = candidate
                    .interfaces
                    .get_mut(&interface)
                    .ok_or_else(|| ControlError::new(format!("unknown interface '{interface}'")))?;
                target.peers = imported.peers.clone();
                candidate
            }
        };
        Runtime::reload_config(self, candidate)
            .map_err(|error| ControlError::new(error.to_string()))
    }

    fn get_stats(&self) -> Result<Vec<InterfaceStats>, ControlError> {
        self.collect_stats()
            .map_err(|error| ControlError::new(error.to_string()))
    }

    fn import_config(
        &mut self,
        request: ImportConfigRequest,
    ) -> Result<crate::import::ImportReport, ControlError> {
        let (candidate, report) = crate::import::import_into_config(
            &self.config,
            &request.source,
            &request.interface,
            request.replace,
        )
        .map_err(|error| ControlError::new(error.to_string()))?;
        Runtime::reload_config(self, candidate)
            .map_err(|error| ControlError::new(error.to_string()))?;
        Ok(report)
    }
}
