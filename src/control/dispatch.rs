use super::api::{ControlApi, ControlError, ControlErrorKind, ControlRequest, ControlResponse};

/// Dispatch a decoded request through the transport-independent daemon API.
pub fn handle(api: &mut dyn ControlApi, request: ControlRequest) -> ControlResponse {
    let result = match request {
        ControlRequest::GetStats => api
            .get_stats()
            .map(|stats| Some(stats)),
        ControlRequest::ReplacePeers { interface, peers } => api
            .replace_peers(&interface, peers)
            .map(|()| None),
        ControlRequest::ReloadConfig { toml } => api
            .reload_config(&toml)
            .map(|()| None),
    };

    match result {
        Ok(stats) => ControlResponse::success(stats),
        Err(error) => ControlResponse::failure(error),
    }
}

pub(crate) fn invalid_request(message: impl Into<String>) -> ControlResponse {
    ControlResponse::failure(ControlError::new(
        ControlErrorKind::InvalidRequest,
        message,
    ))
}
