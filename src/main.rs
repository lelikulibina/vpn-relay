#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use vpn_relay::{Config, InterfaceStats, Runtime};

#[cfg(target_os = "linux")]
const DEFAULT_CONFIG: &str = "/etc/vpn-relay/config.toml";
#[cfg(target_os = "linux")]
const DEFAULT_LOG: &str = "/var/log/vpn-relay.log";

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = run() {
        eprintln!("vpn-relay: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("vpn-relay is supported only on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1).peekable();
    let mut config_path = PathBuf::from(DEFAULT_CONFIG);
    let mut check_only = false;
    let mut stats_requested = false;
    let mut background = false;
    let mut log_path: Option<PathBuf> = None;
    let mut log_enabled = false;
    let mut replace_peers_interface: Option<String> = None;
    let mut reload_config_requested = false;
    let mut import_args: Option<(PathBuf, String)> = None;
    let mut yes = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                config_path = args.next().ok_or("--config requires a path")?.into()
            }
            "--check" => check_only = true,
            "--stats" => stats_requested = true,
            "--background" | "-b" => background = true,
            "--log" => {
                log_enabled = true;
                log_path = match args.next_if(|next| !next.starts_with('-')) {
                    Some(path) => Some(path.into()),
                    None => Some(PathBuf::from(DEFAULT_LOG)),
                };
            }
            value if value.starts_with("--log=") => {
                log_enabled = true;
                let path = &value["--log=".len()..];
                if path.is_empty() {
                    return Err(
                        "--log= requires a non-empty path; use --log for the default".into(),
                    );
                }
                log_path = Some(path.into());
            }
            "--replace-peers" => {
                replace_peers_interface = Some(
                    args.next()
                        .ok_or("--replace-peers requires an interface name")?,
                )
            }
            "--reload" => reload_config_requested = true,
            "--yes" | "-y" => yes = true,
            "--import" => {
                let source = args.next().ok_or("--import requires a source .conf path")?;
                let name = args.next().ok_or("--import requires an interface name")?;
                import_args = Some((source.into(), name));
            }
            "-h" | "--help" => {
                println!("Usage:\n  vpn-relay [--config PATH] [--check]\n  vpn-relay [--config PATH] --stats\n  vpn-relay [--config PATH] --replace-peers INTERFACE\n  vpn-relay [--config PATH] --reload\n  vpn-relay [--config PATH] --import WG.conf INTERFACE [--yes]\n  vpn-relay [--config PATH] [--background] [--log [PATH]]\n\nOptions:\n  -c, --config PATH  Configuration file (default: {DEFAULT_CONFIG})\n      --check        Validate configuration and exit\n      --stats        Print detailed live peer statistics\n      --background, -b  Run daemon in the background\n      --log [PATH]   Enable logging (default: {DEFAULT_LOG})\n      --replace-peers INTERFACE  Replace this interface peer set in a running daemon\n      --reload       Apply the complete config file to a running daemon\n      --import       Import WireGuard/AmneziaWG configuration\n  -y, --yes          Replace an existing interface without prompting");
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let control_operations = check_only as usize
        + stats_requested as usize
        + reload_config_requested as usize
        + replace_peers_interface.is_some() as usize
        + import_args.is_some() as usize;
    if control_operations > 1 {
        return Err(
            "--check, --stats, --reload, --replace-peers and --import are mutually exclusive"
                .into(),
        );
    }
    if background && control_operations != 0 {
        return Err("--background can only be used when starting the daemon".into());
    }
    if log_enabled && control_operations != 0 {
        return Err("--log can only be used when starting the daemon".into());
    }
    if yes && import_args.is_none() {
        return Err("--yes can only be used with --import".into());
    }

    if stats_requested {
        let stats = Runtime::request_stats()?;
        print_stats(&stats);
        return Ok(());
    }

    if let Some((source, name)) = import_args {
        let exists = vpn_relay::import::interface_exists(&config_path, &name)?;
        if exists && !yes {
            eprintln!("Интерфейс '{name}' уже существует. Заменить его? [y/N]");
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !matches!(
                answer.trim().to_ascii_lowercase().as_str(),
                "y" | "yes" | "д" | "да"
            ) {
                println!("Импорт отменён; конфигурация не изменена.");
                return Ok(());
            }
        }
        let report = vpn_relay::import::import_file(&source, &config_path, &name, exists)?;
        println!("Импортирован интерфейс '{name}': {:?}.", report.tunnel_type);
        if report.replaced {
            println!(
                "Существующий интерфейс заменён; остальные интерфейсы и routing rules сохранены."
            );
        }
        if report.warnings.is_empty() {
            println!("Все распознанные параметры перенесены.");
        } else {
            println!("Параметры, которые не применяются и не были импортированы:");
            for warning in report.warnings {
                println!("  - {warning}");
            }
        }
        println!("Конфигурация сохранена: {}", config_path.display());
        return Ok(());
    }

    if reload_config_requested {
        let toml = std::fs::read_to_string(&config_path)?;
        Runtime::request_config_reload(toml)?;
        println!("Runtime configuration reloaded successfully.");
        return Ok(());
    }

    let config = Config::load(&config_path)?;
    if let Some(interface_name) = replace_peers_interface {
        let interface = config.interfaces.get(&interface_name).ok_or_else(|| {
            format!(
                "interface '{interface_name}' is missing from {}",
                config_path.display()
            )
        })?;
        Runtime::request_peer_replacement(interface_name.clone(), interface.peers.clone())?;
        println!("Peer set for interface '{interface_name}' replaced successfully.");
        return Ok(());
    }
    if check_only {
        vpn_relay::backend::BackendRegistry::default().validate_config(&config)?;
        println!("configuration is valid: {}", config_path.display());
        return Ok(());
    }

    if background {
        daemonize(config, log_path)?;
    } else {
        let log_level = config.daemon.log_level.clone();
        init_logging(log_path, &log_level)?;
        tracing::info!(path = %config_path.display(), "starting vpn-relay");
        Runtime::start(config)?.run()?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn init_logging(
    path: Option<PathBuf>,
    configured_level: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = path {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| format!("cannot open log file {}: {error}", path.display()))?;
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(configured_level));
        tracing_subscriber::fmt()
            .with_writer(file)
            .with_ansi(false)
            .with_env_filter(filter)
            .try_init()
            .map_err(|error| format!("cannot initialize logging: {error}"))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn daemonize(config: Config, log_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let log_path = match log_path {
        Some(path) if !path.is_absolute() => Some(std::env::current_dir()?.join(path)),
        other => other,
    };
    let mut pipe_fds = [0; 2];
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    for index in 0..pipe_fds.len() {
        let fd = pipe_fds[index];
        if fd <= 2 {
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate < 0 {
                let error = std::io::Error::last_os_error();
                unsafe {
                    libc::close(pipe_fds[0]);
                    libc::close(pipe_fds[1]);
                }
                return Err(error.into());
            }
            unsafe {
                libc::close(fd);
            }
            pipe_fds[index] = duplicate;
        }
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
        return Err(error.into());
    }

    if pid > 0 {
        unsafe {
            libc::close(pipe_fds[1]);
        }
        let mut message = String::new();
        let mut reader = unsafe { std::fs::File::from_raw_fd(pipe_fds[0]) };
        reader.read_to_string(&mut message)?;
        if let Some(error) = message.strip_prefix("ERR ") {
            return Err(error.trim().to_owned().into());
        }
        if message.trim() != "OK" {
            return Err(format!(
                "background daemon exited before startup confirmation: {}",
                message.trim()
            )
            .into());
        }
        println!("vpn-relay started in background (pid {pid})");
        return Ok(());
    }

    unsafe {
        libc::close(pipe_fds[0]);
    }
    let startup_fd = pipe_fds[1];
    let log_level = config.daemon.log_level.clone();
    let startup_result = (|| -> Result<Runtime, Box<dyn std::error::Error>> {
        if unsafe { libc::setsid() } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let root_path = std::ffi::CString::new("/")?;
        if unsafe { libc::chdir(root_path.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        unsafe {
            libc::umask(0o027);
        }
        let null_path = std::ffi::CString::new("/dev/null")?;
        let null_fd = unsafe { libc::open(null_path.as_ptr(), libc::O_RDWR) };
        if null_fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        for target in 0..=2 {
            if unsafe { libc::dup2(null_fd, target) } < 0 {
                let error = std::io::Error::last_os_error();
                unsafe {
                    libc::close(null_fd);
                }
                return Err(error.into());
            }
        }
        if null_fd > 2 {
            unsafe {
                libc::close(null_fd);
            }
        }
        close_extra_fds(startup_fd);
        init_logging(log_path, &log_level)?;
        tracing::info!(pid = std::process::id(), "vpn-relay background daemon starting");
        Runtime::start(config).map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
    })();

    match startup_result {
        Ok(runtime) => {
            let _ = unsafe { libc::write(startup_fd, b"OK".as_ptr().cast(), 2) };
            unsafe {
                libc::close(startup_fd);
            }
            let exit_code = match runtime.run() {
                Ok(()) => 0,
                Err(error) => {
                    tracing::error!(%error, "background daemon stopped after startup");
                    1
                }
            };
            unsafe {
                libc::_exit(exit_code);
            }
        }
        Err(error) => {
            let message = format!("ERR {error}");
            let _ = unsafe { libc::write(startup_fd, message.as_ptr().cast(), message.len()) };
            unsafe {
                libc::close(startup_fd);
                libc::_exit(1);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn close_extra_fds(keep_fd: libc::c_int) {
    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let max_fd = if max_fd < 0 { 1024 } else { max_fd.min(65_536) };
    for fd in 3..max_fd as libc::c_int {
        if fd != keep_fd {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn print_stats(interfaces: &[InterfaceStats]) {
    if interfaces.is_empty() {
        println!("Нет настроенных туннельных интерфейсов.");
        return;
    }

    let mut total_peers = 0usize;
    let mut total_rx = 0u64;
    let mut total_tx = 0u64;

    for interface in interfaces {
        println!("\nИнтерфейс: {}", interface.name);
        println!(
            "{:<64}  {:<39}  {:<21}  {:>12}  {:>12}  {:>12}",
            "Публичный ключ", "IP клиента", "Endpoint", "Получено", "Отправлено", "Handshake"
        );
        println!("{}", "-".repeat(180));

        if interface.peers.is_empty() {
            println!("(нет пиров)");
            continue;
        }

        for peer in &interface.peers {
            let ips = if peer.client_ips.is_empty() {
                "-".to_owned()
            } else {
                peer.client_ips.join(", ")
            };
            let endpoint = peer
                .endpoint
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned());
            println!(
                "{:<64}  {:<39}  {:<21}  {:>12}  {:>12}  {:>12}",
                peer.public_key,
                ips,
                endpoint,
                format_bytes(peer.rx_bytes),
                format_bytes(peer.tx_bytes),
                format_handshake(peer.handshake_age_secs)
            );
            total_peers += 1;
            total_rx = total_rx.saturating_add(peer.rx_bytes);
            total_tx = total_tx.saturating_add(peer.tx_bytes);
        }
    }

    println!("\nВсего пиров: {total_peers}");
    println!("Получено от клиентов: {}", format_bytes(total_rx));
    println!("Отправлено клиентам: {}", format_bytes(total_tx));
}

#[cfg(target_os = "linux")]
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

#[cfg(target_os = "linux")]
fn format_handshake(age: Option<u64>) -> String {
    match age {
        None => "никогда".to_owned(),
        Some(seconds) if seconds < 60 => format!("{seconds}с назад"),
        Some(seconds) if seconds < 3600 => format!("{}м назад", seconds / 60),
        Some(seconds) if seconds < 86_400 => format!("{}ч назад", seconds / 3600),
        Some(seconds) => format!("{}д назад", seconds / 86_400),
    }
}

#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn byte_counts_use_readable_decimal_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1_000), "1.00 KB");
        assert_eq!(format_bytes(1_500_000), "1.50 MB");
        assert_eq!(format_bytes(1_000_000_000), "1.00 GB");
    }

    #[test]
    fn handshake_age_is_human_readable() {
        assert_eq!(format_handshake(None), "никогда");
        assert_eq!(format_handshake(Some(42)), "42с назад");
        assert_eq!(format_handshake(Some(120)), "2м назад");
        assert_eq!(format_handshake(Some(7_200)), "2ч назад");
        assert_eq!(format_handshake(Some(172_800)), "2д назад");
    }
}
