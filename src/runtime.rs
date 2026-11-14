//! Linux runtime: dispatch tunnel backends and install shared routing.
use crate::backend::{
    BackendError, BackendRegistry, PreparedInterface, TunnelHandle, TunnelSnapshot,
};
use crate::config::{Config, PeerConfig};
use crate::control::{ControlRequest, ControlResponse, ReloadConfigMode};
pub use crate::control::{InterfaceStats, PeerStats};
use crate::linux::{self, LinuxError};
use crate::routing::RoutingPlan;
mod control_api;
mod control_socket;
mod forwarding;
mod lifecycle;
mod reload;
mod peers;
mod state;
use control_socket::*;
use forwarding::*;
use peers::*;
use state::*;
#[cfg(test)]
use std::fs::{File, OpenOptions};
#[cfg(test)]
use std::io::Write;
#[cfg(test)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(test)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_shutdown(_: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Linux(#[from] LinuxError),
    #[error("tunnel backend error: {0}")]
    Backend(#[from] BackendError),
    #[error("invalid runtime configuration: {0}")]
    Configuration(String),
    #[error("failed to enable IP forwarding: {0}")]
    Forwarding(String),
    #[error("another vpn-relay instance is already running (lock: {0})")]
    AlreadyRunning(String),
    #[error("failed to acquire daemon instance lock: {0}")]
    InstanceLock(String),
    #[error("failed to install signal handler: {0}")]
    Signal(String),
    #[error("control socket error: {0}")]
    Control(String),
    #[error("conntrack decision-mark state error: {0}")]
    ConntrackMarkState(String),
    #[error("runtime transaction rollback or cleanup failed; daemon must stop: {0}")]
    FatalTransition(String),
}

pub struct Runtime {
    devices: Vec<Box<dyn TunnelHandle>>,
    config: Config,
    prepared_interfaces: std::collections::BTreeMap<String, PreparedInterface>,
    backends: BackendRegistry,
    routing: RoutingPlan,
    retired_routing: Vec<RoutingPlan>,
    conntrack_mark_state_path: PathBuf,
    conntrack_mark_history: Vec<crate::routing::RoutingDecision>,
    forwarding_state: Option<ForwardingState>,
    forwarding_state_path: PathBuf,
    control_socket: ControlSocket,
    fatal_error: Option<String>,
    /// Preserve the name-mismatch guards if the original TUN descriptor is lost.
    retain_firewall: bool,
    _instance_lock: InstanceLock,
}

impl Runtime {
    /// Start all interfaces through their registered backend, then install
    /// shared routing only after every tunnel has been configured.
    pub fn start(config: Config) -> Result<Self, RuntimeError> {
        install_signal_handlers()?;
        config
            .validate()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let lock_path = InstanceLock::current_netns_path()?;
        let instance_lock = InstanceLock::acquire(&lock_path)?;
        let forwarding_state_path = InstanceLock::current_forwarding_state_path()?;
        let namespace_inode = InstanceLock::current_netns_inode()?;
        recover_forwarding_state(&forwarding_state_path, namespace_inode)?;
        let control_socket = ControlSocket::bind(InstanceLock::current_control_path()?)?;
        let conntrack_mark_state_path = InstanceLock::current_conntrack_mark_state_path()?;
        let mut conntrack_mark_history = load_conntrack_mark_history(&conntrack_mark_state_path)?;
        let socket_fwmarks = config
            .resolved_socket_fwmarks()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let mut routing = RoutingPlan::from_config(&config);
        routing
            .assign_stable_conntrack_marks(&mut conntrack_mark_history)
            .map_err(RuntimeError::ConntrackMarkState)?;
        persist_conntrack_mark_history(&conntrack_mark_state_path, &conntrack_mark_history)?;
        let backends = BackendRegistry::default();
        let prepared_interfaces = backends.prepare_config(&config)?;

        // Install a drop-only bootstrap policy before creating any TUN.
        // It scopes drops by the configured names but contains no allow rules;
        // after descriptor verification it is atomically replaced by the
        // numeric-ifindex policy. This prevents traffic from slipping through
        // during link creation/configuration even if forwarding is pre-enabled.
        let bootstrap_routing = routing.fail_closed_bootstrap();
        linux::apply_nft(&bootstrap_routing)?;

        let mut devices = Vec::with_capacity(config.interfaces.len());
        let setup_result = (|| -> Result<(), RuntimeError> {
            for ((interface_name, interface), socket_fwmark) in
                config.interfaces.iter().zip(socket_fwmarks)
            {
                let handle = backends.create(
                    interface.tunnel_type,
                    interface_name,
                    interface,
                    socket_fwmark,
                    prepared_interfaces.get(interface_name).ok_or_else(|| {
                        BackendError::new(format!(
                            "interface '{interface_name}' is missing its prepared backend configuration"
                        ))
                    })?,
                )?;
                devices.push(handle);
                devices
                    .last()
                    .expect("just-pushed tunnel handle")
                    .verify_identity()
                    .map_err(|error| {
                        RuntimeError::FatalTransition(format!(
                            "new tunnel interface '{interface_name}' failed its identity check: {error}"
                        ))
                    })?;
                linux::configure_interface(interface_name, interface.mtu, &interface.address)?;
            }
            // Recheck the complete set after address/MTU configuration and
            // before installing any policy routes that refer to interface names.
            for (index, device) in devices.iter().enumerate() {
                device.verify_identity().map_err(|error| {
                    RuntimeError::FatalTransition(format!(
                        "tunnel device at runtime index {index} lost its identity during startup: {error}"
                    ))
                })?;
            }
            Ok(())
        })();
        if let Err(error) = setup_result {
            // Dropping the handles stops and joins any workers created before
            // the failing interface; the firewall is removed only afterwards.
            drop(devices);
            if let Err(cleanup) = linux::remove_nft(&routing) {
                return Err(RuntimeError::FatalTransition(format!(
                    "interface setup failed ({error}); nftables cleanup failed ({cleanup})"
                )));
            }
            return Err(error);
        }

        // Replace bootstrap name selectors with indices resolved only after
        // checking each original TUN descriptor. This switch is atomic in nft.
        let interface_indices_result = (|| -> Result<_, RuntimeError> {
            let mut indices = std::collections::BTreeMap::new();
            for (index, (name, _)) in config.interfaces.iter().enumerate() {
                devices[index].verify_identity()?;
                indices.insert(name.clone(), linux::interface_index(name)?);
                devices[index].verify_identity()?;
            }
            Ok(indices)
        })();
        let interface_indices = match interface_indices_result {
            Ok(indices) => indices,
            Err(error) => {
                drop(devices);
                if let Err(cleanup) = linux::remove_nft(&routing) {
                    return Err(RuntimeError::FatalTransition(format!(
                        "interface identity resolution failed ({error}); bootstrap firewall cleanup failed ({cleanup})"
                    )));
                }
                return Err(error);
            }
        };
        if let Err(error) = routing.bind_interface_indices(interface_indices) {
            drop(devices);
            if let Err(cleanup) = linux::remove_nft(&routing) {
                return Err(RuntimeError::FatalTransition(format!(
                    "interface index binding failed ({error}); bootstrap firewall cleanup failed ({cleanup})"
                )));
            }
            return Err(RuntimeError::Configuration(error));
        }
        if let Err(error) = linux::apply_nft(&routing) {
            drop(devices);
            if let Err(cleanup) = linux::remove_nft(&routing) {
                return Err(RuntimeError::FatalTransition(format!(
                    "numeric firewall install failed ({error}); cleanup failed ({cleanup})"
                )));
            }
            return Err(error.into());
        }

        // Close the lookup-to-activation race as far as userspace can:
        // every descriptor must still identify its original link after the
        // numeric nftables policy has been installed.
        let identity_error = devices
            .iter()
            .enumerate()
            .find_map(|(index, device)| device.verify_identity().err().map(|error| (index, error)));
        if let Some((index, error)) = identity_error {
            drop(devices);
            return Err(RuntimeError::FatalTransition(format!(
                "tunnel identity changed while activating numeric firewall (device {index}): {error}; retaining fail-closed nftables policy"
            )));
        }

        if let Err(error) = linux::apply_policy_routing(&routing) {
            drop(devices);
            if matches!(&error, LinuxError::Rollback { .. } | LinuxError::Cleanup(_)) {
                tracing::error!(%error, "startup policy-routing rollback failed; retaining nftables policy");
                return Err(RuntimeError::FatalTransition(error.to_string()));
            }
            if let Err(cleanup) = linux::remove_nft(&routing) {
                return Err(RuntimeError::FatalTransition(format!(
                    "policy-routing setup failed ({error}); nftables cleanup failed ({cleanup})"
                )));
            }
            return Err(error.into());
        }

        let forwarding_state = if config.daemon.manage_ip_forwarding {
            match enable_forwarding_durable(
                &forwarding_state_path,
                namespace_inode,
                &config.daemon.forwarding_interfaces,
                &config.interfaces.keys().cloned().collect(),
            ) {
                Ok(state) => Some(state),
                Err(error) => {
                    let route_cleanup = linux::remove_policy_routing(&routing);
                    drop(devices);
                    if let Err(cleanup) = route_cleanup {
                        tracing::error!(
                            %cleanup,
                            "startup policy-routing cleanup failed; retaining nftables policy"
                        );
                        return Err(RuntimeError::FatalTransition(format!(
                            "forwarding setup failed ({error}); policy-routing cleanup failed ({cleanup})"
                        )));
                    }
                    // If restoring the original forwarding value failed, the
                    // firewall is the remaining fail-closed protection.
                    if matches!(&error, RuntimeError::FatalTransition(_)) {
                        tracing::error!(
                            %error,
                            "startup aborted with forwarding state uncertain; retaining nftables policy"
                        );
                        return Err(error);
                    }
                    if let Err(cleanup) = linux::remove_nft(&routing) {
                        return Err(RuntimeError::FatalTransition(format!(
                            "forwarding setup failed ({error}); nftables cleanup failed ({cleanup})"
                        )));
                    }
                    return Err(error);
                }
            }
        } else {
            None
        };

        tracing::info!(interfaces = devices.len(), "vpn-relay runtime started");
        Ok(Self {
            devices,
            config,
            prepared_interfaces,
            backends,
            routing,
            retired_routing: Vec::new(),
            conntrack_mark_state_path,
            conntrack_mark_history,
            forwarding_state,
            forwarding_state_path,
            control_socket,
            fatal_error: None,
            retain_firewall: false,
            _instance_lock: instance_lock,
        })
    }

    pub fn routing_plan(&self) -> &RoutingPlan {
        &self.routing
    }

    fn accept_control_connections(&mut self) {
        // A failed rollback or post-commit cleanup makes the datapath state
        // unsuitable for further management operations. Do not drain queued
        // requests after the transition to fatal state: run() will return and
        // Runtime::drop will perform the ordered shutdown.
        if self.fatal_error.is_some() {
            return;
        }

        loop {
            match self.control_socket.listener.accept() {
                Ok((stream, _)) => {
                    crate::control::handle_unix_connection(self, stream);
                    // A request may itself trigger a fatal transition. Stop
                    // immediately rather than accepting another queued reload
                    // or peer replacement in the partially committed state.
                    if self.fatal_error.is_some() {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    tracing::warn!(%error, "failed to accept control connection");
                    break;
                }
            }
        }
    }

    /// Request live peer and interface statistics from the daemon.
    pub fn request_stats() -> Result<Vec<InterfaceStats>, RuntimeError> {
        Self::send_control_request(ControlRequest::GetStats)?
            .stats
            .ok_or_else(|| RuntimeError::Control("daemon returned no statistics".to_owned()))
    }

    /// Send a complete TOML configuration to the running daemon for validation
    /// and transactional application.
    pub fn request_config_reload(toml: String) -> Result<(), RuntimeError> {
        Self::send_control_request(ControlRequest::ReloadConfig {
            toml,
            mode: ReloadConfigMode::Full,
        })
        .map(|_| ())
    }

    /// Replace only the peer set of one interface, preserving the legacy
    /// semantics while using the reload_config application operation.
    pub fn request_peer_replacement(interface: String, toml: String) -> Result<(), RuntimeError> {
        Self::send_control_request(ControlRequest::ReloadConfig {
            toml,
            mode: ReloadConfigMode::ReplacePeers { interface },
        })
        .map(|_| ())
    }

    /// Ask the daemon to import an interface into its active configuration.
    pub fn request_config_import(
        source: String,
        interface: String,
        replace: bool,
    ) -> Result<crate::import::ImportReport, RuntimeError> {
        Self::send_control_request(ControlRequest::ImportConfig {
            source,
            interface,
            replace,
        })?
        .import_report
        .ok_or_else(|| RuntimeError::Control("daemon returned no import report".to_owned()))
    }

    fn send_control_request(request: ControlRequest) -> Result<ControlResponse, RuntimeError> {
        let path = InstanceLock::current_control_path()?;
        crate::control::send_unix_request(&path, request).map_err(RuntimeError::Control)
    }

    /// Return consistent live counters without depending on a backend UAPI.
    pub fn snapshots(&self) -> Result<Vec<TunnelSnapshot>, RuntimeError> {
        self.devices
            .iter()
            .map(|device| device.snapshot().map_err(RuntimeError::from))
            .collect()
    }

    fn collect_stats(&self) -> Result<Vec<InterfaceStats>, RuntimeError> {
        self.snapshots().map(|interfaces| {
            interfaces
                .into_iter()
                .map(|interface| InterfaceStats {
                    name: interface.name,
                    peers: interface
                        .peers
                        .into_iter()
                        .map(|peer| PeerStats {
                            public_key: hex_key(&peer.public_key),
                            client_ips: peer.allowed_ips,
                            endpoint: peer.endpoint,
                            tx_bytes: peer.tx_bytes,
                            rx_bytes: peer.rx_bytes,
                            handshake_age_secs: peer
                                .time_since_last_handshake
                                .map(|age| age.as_secs()),
                        })
                        .collect(),
                })
                .collect()
        })
    }

}

fn install_signal_handlers() -> Result<(), RuntimeError> {
    SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    unsafe {
        if libc::signal(
            libc::SIGINT,
            request_shutdown as *const () as libc::sighandler_t,
        ) == libc::SIG_ERR
        {
            return Err(RuntimeError::Signal("SIGINT".into()));
        }
        if libc::signal(
            libc::SIGTERM,
            request_shutdown as *const () as libc::sighandler_t,
        ) == libc::SIG_ERR
        {
            return Err(RuntimeError::Signal("SIGTERM".into()));
        }
    }
    Ok(())
}

fn hex_key(key: &[u8; 32]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Forwarding journal and sysctl recovery live in the dedicated submodule.
#[cfg(test)]
mod tests;

