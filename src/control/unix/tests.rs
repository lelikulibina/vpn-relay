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
    fn reload_config(
        &mut self,
        _request: ReloadConfigRequest,
    ) -> Result<(), super::super::ControlError> {
        self.calls.push("reload_config");
        Ok(())
    }

    fn get_stats(&self) -> Result<Vec<InterfaceStats>, super::super::ControlError> {
        Ok(Vec::new())
    }

    fn import_config(
        &mut self,
        request: ImportConfigRequest,
    ) -> Result<ImportReport, super::super::ControlError> {
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
