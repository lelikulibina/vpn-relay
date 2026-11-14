#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = vpn_relay::cli::run() {
        eprintln!("vpn-relay: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("vpn-relay is supported only on Linux");
    std::process::exit(1);
}
