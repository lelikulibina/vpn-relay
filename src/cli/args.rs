use std::path::PathBuf;

pub(super) const DEFAULT_CONFIG: &str = "/etc/vpn-relay/config.toml";
pub(super) const DEFAULT_LOG: &str = "/var/log/vpn-relay.log";

pub(super) struct Args {
    pub(super) config_path: PathBuf,
    pub(super) check_only: bool,
    pub(super) stats_requested: bool,
    pub(super) background: bool,
    pub(super) log_path: Option<PathBuf>,
    pub(super) replace_peers_interface: Option<String>,
    pub(super) reload_config_requested: bool,
    pub(super) import_args: Option<(PathBuf, String)>,
    pub(super) yes: bool,
}

impl Args {
    pub(super) fn parse() -> Result<Option<Self>, Box<dyn std::error::Error>> {
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
                    return Ok(None);
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
        Ok(Some(Self {
            config_path,
            check_only,
            stats_requested,
            background,
            log_path,
            replace_peers_interface,
            reload_config_requested,
            import_args,
            yes,
        }))
    }
}
