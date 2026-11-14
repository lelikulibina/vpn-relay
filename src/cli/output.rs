#[cfg(target_os = "linux")]
use vpn_relay::InterfaceStats;

#[cfg(target_os = "linux")]
pub(super) fn print_stats(interfaces: &[InterfaceStats]) {
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
