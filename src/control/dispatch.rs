use super::api::{ControlApi, ControlError, ControlErrorKind, ControlRequest, ControlResponse};

/// Dispatch a decoded request through the transport-independent daemon API.
pub fn handle(api: &mut dyn ControlApi, request: ControlRequest) -> ControlResponse {
    let result = match request {
        ControlRequest::GetStats => api.get_stats().map(Some),
        ControlRequest::ReplacePeers { interface, peers } => {
            api.replace_peers(&interface, peers).map(|()| None)
        }
        ControlRequest::ReloadConfig { toml } => api.reload_config(&toml).map(|()| None),
    };

    match result {
        Ok(stats) => ControlResponse::success(stats),
        Err(error) => ControlResponse::failure(error),
    }
}

pub(crate) fn invalid_request(message: impl Into<String>) -> ControlResponse {
    ControlResponse::failure(ControlError::new(ControlErrorKind::InvalidRequest, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerConfig;
    use crate::control::api::{ControlErrorKind, InterfaceStats};

    #[derive(Default)]
    struct MockApi {
        stats: Vec<InterfaceStats>,
        replaced: Option<(String, Vec<PeerConfig>)>,
        reloaded: Option<String>,
        fatal: bool,
        fail: bool,
    }

    impl ControlApi for MockApi {
        fn get_stats(&self) -> Result<Vec<InterfaceStats>, ControlError> {
            if self.fail {
                Err(ControlError::new(
                    ControlErrorKind::Unavailable,
                    "stats unavailable",
                ))
            } else {
                Ok(self.stats.clone())
            }
        }

        fn replace_peers(
            &mut self,
            interface: &str,
            peers: Vec<PeerConfig>,
        ) -> Result<(), ControlError> {
            if self.fail {
                return Err(ControlError::new(
                    ControlErrorKind::Conflict,
                    "replacement rejected",
                ));
            }
            self.replaced = Some((interface.to_owned(), peers));
            Ok(())
        }

        fn reload_config(&mut self, toml: &str) -> Result<(), ControlError> {
            if self.fail {
                return Err(ControlError::new(
                    ControlErrorKind::Configuration,
                    "invalid config",
                ));
            }
            self.reloaded = Some(toml.to_owned());
            Ok(())
        }

        fn is_fatal(&self) -> bool {
            self.fatal
        }
    }

    #[test]
    fn dispatches_stats_and_preserves_result() {
        let mut api = MockApi {
            stats: vec![InterfaceStats {
                name: "wg0".into(),
                peers: Vec::new(),
            }],
            ..MockApi::default()
        };
        let response = handle(&mut api, ControlRequest::GetStats);
        assert!(response.ok);
        assert_eq!(response.stats.unwrap()[0].name, "wg0");
    }

    #[test]
    fn dispatches_peer_replacement_and_config_reload() {
        let mut api = MockApi::default();
        let response = handle(
            &mut api,
            ControlRequest::ReplacePeers {
                interface: "wg0".into(),
                peers: Vec::new(),
            },
        );
        assert!(response.ok);
        assert_eq!(api.replaced.as_ref().unwrap().0, "wg0");

        let response = handle(
            &mut api,
            ControlRequest::ReloadConfig {
                toml: "[daemon]".into(),
            },
        );
        assert!(response.ok);
        assert_eq!(api.reloaded.as_deref(), Some("[daemon]"));
    }

    #[test]
    fn dispatch_preserves_typed_api_errors() {
        let mut api = MockApi {
            fail: true,
            ..MockApi::default()
        };
        let response = handle(&mut api, ControlRequest::GetStats);
        assert!(!response.ok);
        assert_eq!(response.error_kind, Some(ControlErrorKind::Unavailable));
        assert_eq!(response.error.as_deref(), Some("stats unavailable"));
    }

    #[test]
    fn dispatch_serializes_typed_error_categories() {
        let mut api = MockApi {
            fail: true,
            ..MockApi::default()
        };

        let response = handle(&mut api, ControlRequest::GetStats);
        let encoded = serde_json::to_value(&response).unwrap();
        assert_eq!(encoded["error_kind"], "unavailable");

        let decoded: ControlResponse = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.error_kind, Some(ControlErrorKind::Unavailable));

        let response = handle(
            &mut api,
            ControlRequest::ReplacePeers {
                interface: "wg0".to_owned(),
                peers: Vec::new(),
            },
        );
        assert_eq!(response.error_kind, Some(ControlErrorKind::Conflict));

        let response = handle(
            &mut api,
            ControlRequest::ReloadConfig {
                toml: "invalid".to_owned(),
            },
        );
        assert_eq!(response.error_kind, Some(ControlErrorKind::Configuration));
    }

    #[test]
    fn response_remains_compatible_with_legacy_json() {
        let legacy = br#"{"ok":false,"error":"rejected","stats":null}"#;
        let response: ControlResponse = serde_json::from_slice(legacy).unwrap();
        assert_eq!(response.error_kind, None);

        let encoded = serde_json::to_value(ControlResponse::success(None)).unwrap();
        assert!(encoded.get("error_kind").is_none());
    }
}
