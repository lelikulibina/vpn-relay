mod args;
mod daemon;
mod output;

use vpn_relay::{Config, Runtime};

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let Some(parsed) = args::Args::parse()? else {
        return Ok(());
    };
    let args::Args {
        config_path, check_only, stats_requested, background, log_path, log_enabled,
        replace_peers_interface, reload_config_requested, import_args, yes,
    } = parsed;

    if stats_requested {
        let stats = Runtime::request_stats()?;
        output::print_stats(&stats);
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
        daemon::daemonize(config, log_path)?;
    } else {
        let log_level = config.daemon.log_level.clone();
        daemon::init_logging(log_path, &log_level)?;
        tracing::info!(path = %config_path.display(), "starting vpn-relay");
        Runtime::start(config)?.run()?;
    }
    Ok(())
}
