//! Unix Domain Socket transport for the transport-independent Control API.
//!
//! This module owns only wire DTOs, JSON framing and socket I/O. Application
//! behavior is delegated to the parent module's ControlApi trait.

use super::{
    ControlApi, ImportConfigRequest, ImportReport, InterfaceStats, ReloadConfigMode,
    ReloadConfigRequest,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Request DTO used by the current Unix Domain Socket transport.
#[derive(serde::Serialize, serde::Deserialize, Debug, Eq, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum ControlRequest {
    GetStats,
    ReloadConfig {
        toml: String,
        #[serde(default)]
        mode: ReloadConfigMode,
    },
    ImportConfig {
        source: String,
        interface: String,
        replace: bool,
    },
}

#[cfg(target_os = "linux")]
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct ControlResponse {
    pub(crate) ok: bool,
    pub(crate) error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) stats: Option<Vec<InterfaceStats>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) import_report: Option<ImportReport>,
}

/// Serve one already-accepted Unix socket connection through the application
/// API. Framing, limits, JSON decoding and response encoding live in this
/// transport adapter; application operations remain on \`ControlApi\`.
pub(crate) fn handle_unix_connection(api: &mut impl ControlApi, mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut payload = Vec::new();
    let read_result = (&mut stream)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut payload);
    let response = match read_result {
        Ok(_) if payload.len() > 1024 * 1024 => ControlResponse {
            ok: false,
            error: Some("request exceeds 1 MiB limit".to_owned()),
            stats: None,
            import_report: None,
        },
        Ok(_) => match serde_json::from_slice::<ControlRequest>(&payload) {
            Ok(request) => {
                let mut stats = None;
                let mut import_report = None;
                let result = match request {
                    ControlRequest::GetStats => match api.get_stats() {
                        Ok(value) => {
                            stats = Some(value);
                            Ok(())
                        }
                        Err(error) => Err(error),
                    },
                    ControlRequest::ReloadConfig { toml, mode } => {
                        api.reload_config(ReloadConfigRequest { toml, mode })
                    }
                    ControlRequest::ImportConfig {
                        source,
                        interface,
                        replace,
                    } => match api.import_config(ImportConfigRequest {
                        source,
                        interface,
                        replace,
                    }) {
                        Ok(report) => {
                            import_report = Some(report);
                            Ok(())
                        }
                        Err(error) => Err(error),
                    },
                };
                match result {
                    Ok(()) => ControlResponse {
                        ok: true,
                        error: None,
                        stats,
                        import_report,
                    },
                    Err(error) => ControlResponse {
                        ok: false,
                        error: Some(error.to_string()),
                        stats: None,
                        import_report: None,
                    },
                }
            }
            Err(error) => ControlResponse {
                ok: false,
                error: Some(format!("invalid control request: {error}")),
                stats: None,
                import_report: None,
            },
        },
        Err(error) => ControlResponse {
            ok: false,
            error: Some(format!("failed to read control request: {error}")),
            stats: None,
            import_report: None,
        },
    };
    if let Err(error) = serde_json::to_vec(&response)
        .map_err(|error| error.to_string())
        .and_then(|payload| {
            stream
                .write_all(&payload)
                .map_err(|error| error.to_string())
        })
    {
        tracing::warn!(%error, "failed to send control response");
    }
}

/// Unix socket client transport. The caller supplies the namespace-scoped
/// socket path; this module does not discover runtime or filesystem state.
#[cfg(target_os = "linux")]
pub(crate) fn send_unix_request(
    path: &Path,
    request: ControlRequest,
) -> Result<ControlResponse, String> {
    let mut stream = UnixStream::connect(path).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .map_err(|error| error.to_string())?;
    serde_json::to_writer(&mut stream, &request).map_err(|error| error.to_string())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    (&mut stream)
        .take(4 * 1024 * 1024)
        .read_to_end(&mut response)
        .map_err(|error| error.to_string())?;
    let response: ControlResponse =
        serde_json::from_slice(&response).map_err(|error| error.to_string())?;
    if response.ok {
        Ok(response)
    } else {
        Err(response
            .error
            .unwrap_or_else(|| "daemon rejected request".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TunnelType;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::thread;

    #[derive(Default)]
    struct RecordingApi {
        calls: Vec<&'static str>,
    }

    impl ControlApi for RecordingApi {
        fn reload_config(&mut self, _request: ReloadConfigRequest) -> Result<(), super::super::ControlError> {
            self.calls.push("reload_config");
            Ok(())
        }

        fn get_stats(&self) -> Result<Vec<InterfaceStats>, super::super::ControlError> {
            Ok(Vec::new())
        }

        fn import_config(&mut self, request: ImportConfigRequest) -> Result<ImportReport, super::super::ControlError> {
            self.calls.push("import_config");
            Ok(ImportReport {
                tunnel_type: TunnelType::WireGuard,
                warnings: Vec::new(),
                replaced: request.replace,
            })
        }
    }

    fn exchange(request: ControlRequest) -> (ControlResponse, Vec<&'static str>) {
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            let mut api = RecordingApi::default();
            handle_unix_connection(&mut api, server);
            api.calls
        });
        serde_json::to_writer(&mut client, &request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        let response = serde_json::from_slice(&response).unwrap();
        (response, worker.join().unwrap())
    }

    #[test]
    fn unix_adapter_delegates_each_application_operation_to_control_api() {
        let (stats, calls) = exchange(ControlRequest::GetStats);
        assert!(stats.ok);
        assert!(stats.stats.unwrap().is_empty());
        assert!(calls.is_empty());

        let (reload, calls) = exchange(ControlRequest::ReloadConfig {
            toml: "[interfaces.wg0]".to_owned(),
            mode: ReloadConfigMode::Full,
        });
        assert!(reload.ok);
        assert_eq!(calls, vec!["reload_config"]);

        let (import, calls) = exchange(ControlRequest::ImportConfig {
            source: "[Interface]".to_owned(),
            interface: "wg0".to_owned(),
            replace: true,
        });
        assert!(import.ok);
        assert!(import.import_report.unwrap().replaced);
        assert_eq!(calls, vec!["import_config"]);
    }

    #[test]
    fn unix_adapter_rejects_oversized_requests_before_dispatch() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            let mut api = RecordingApi::default();
            handle_unix_connection(&mut api, server);
            api.calls
        });
        client.write_all(&vec![b'x'; 1024 * 1024 + 1]).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        let response: ControlResponse = serde_json::from_slice(&response).unwrap();
        assert!(!response.ok);
        assert!(response.error.unwrap().contains("1 MiB"));
        assert!(worker.join().unwrap().is_empty());
    }
}
