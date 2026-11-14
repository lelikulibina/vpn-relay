mod api;
pub mod dispatch;
#[cfg(target_os = "linux")]
pub mod unix;

pub use api::{
    ControlApi, ControlError, ControlErrorKind, ControlRequest, ControlResponse, InterfaceStats,
    PeerStats,
};

/// A transport polls its listener and dispatches all ready requests to the API.
pub trait ControlTransport {
    fn poll(&mut self, api: &mut dyn ControlApi);
}
