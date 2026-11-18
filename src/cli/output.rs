#[cfg(target_os = "linux")]
use crate::InterfaceStats;

#[cfg(target_os = "linux")]
const RECENT_HANDSHAKE_SECS: u64 = 180;

#[cfg(target_os = "linux")]
pub(super) fn print_stats(interfaces: &[InterfaceStats]) {
    if interfaces.is_empty() {
        println!("Нет настроенных туннельных интерфейсов.");
        return;
    }

    let mut total_peers = 0usize;
    let mut total_recent = 0usize;
    let mut total_rx = 0u64;
    let mut total_tx = 0u64;

    println!("Статистика VPN-relay");
    println!("Интерфейсов: {}", interfaces.len());

    for interface in interfaces {
        let peer_count = interface.peers.len();
        let recent = interface
            .peers
            .iter()
            .filter(|peer| is_recent_handshake(peer.handshake_age_secs))
            .count();
        let rx = interface
            .peers
            .iter()
            .fold(0u64, |sum, peer| sum.saturating_add(peer.rx_bytes));
        let tx = interface
            .peers
            .iter()
            .fold(0u64, |sum, peer| sum.saturating_add(peer.tx_bytes));

        println!(
            "\nИнтерфейс: {}  |  Пиров: {}  |  Handshake ≤ 3 мин: {}  |  RX: {}  |  TX: {}",
            interface.name, peer_count, recent, format_bytes(rx), format_bytes(tx)
        );

        if interface.peers.is_empty() {
            println!("  Пиры не настроены или отсутствуют.");
            continue;
        }

        println!(
            "  {:<22}  {:<25}  {:<21}  {:>10}  {:>10}  {:>14}  {:<9}",
            "Публичный ключ (Base64)",
            "IP клиента",
            "Endpoint",
            "RX",
            "TX",
            "Handshake",
            "Состояние"
        );
        println!("  {}", "-".repeat(125));

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
                "  {:<22}  {:<25}  {:<21}  {:>10}  {:>10}  {:>14}  {:<9}",
                format_peer_key(&peer.public_key),
                truncate(&ips, 25),
                endpoint,
                format_bytes(peer.rx_bytes),
                format_bytes(peer.tx_bytes),
                format_handshake(peer.handshake_age_secs),
                handshake_status(peer.handshake_age_secs)
            );
        }

        total_peers += peer_count;
        total_recent += recent;
        total_rx = total_rx.saturating_add(rx);
        total_tx = total_tx.saturating_add(tx);
    }

    println!("\nИтого");
    println!("  Пиров: {total_peers}");
    println!("  Handshake за последние 3 минуты: {total_recent}");
    println!("  Получено от пиров (RX): {}", format_bytes(total_rx));
    println!("  Отправлено пирам (TX): {}", format_bytes(total_tx));
}

#[cfg(target_os = "linux")]
fn format_peer_key(key: &str) -> String {
    const PREFIX: usize = 10;
    const SUFFIX: usize = 8;
    let chars: Vec<char> = key.chars().collect();
    if chars.len() <= PREFIX + SUFFIX + 1 {
        return key.to_owned();
    }
    format!(
        "{}…{}",
        chars[..PREFIX].iter().collect::<String>(),
        chars[chars.len() - SUFFIX..].iter().collect::<String>()
    )
}

#[cfg(target_os = "linux")]
fn truncate(value: &str, max_chars: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= max_chars {
        return value.to_owned();
    }
    format!(
        "{}…",
        chars[..max_chars.saturating_sub(1)]
            .iter()
            .collect::<String>()
    )
}

#[cfg(target_os = "linux")]
fn is_recent_handshake(age: Option<u64>) -> bool {
    age.is_some_and(|seconds| seconds <= RECENT_HANDSHAKE_SECS)
}

#[cfg(target_os = "linux")]
fn handshake_status(age: Option<u64>) -> &'static str {
    match age {
        None => "нет",
        Some(seconds) if seconds <= RECENT_HANDSHAKE_SECS => "свежий",
        Some(_) => "давний",
    }
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

    #[test]
    fn peer_key_is_shortened_in_the_middle_without_changing_base64_edges() {
        let key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr==";
        assert_eq!(format_peer_key(key), "ABCDEFGHIJ…klmnopqr");
        assert_eq!(format_peer_key("short-key"), "short-key");
    }

    #[test]
    fn handshake_freshness_is_explicit_and_bounded_to_three_minutes() {
        assert!(is_recent_handshake(Some(180)));
        assert!(!is_recent_handshake(Some(181)));
        assert!(!is_recent_handshake(None));
        assert_eq!(handshake_status(Some(10)), "свежий");
        assert_eq!(handshake_status(Some(181)), "давний");
        assert_eq!(handshake_status(None), "нет");
    }
}
