//! `more-ledgerd --socket PATH --domain HEX --identity FILE [--allow-uid UID]...
//! [--socket-group GID] [--tx-timeout-ms N] [--handshake-timeout-ms N]`

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = more_ledgerd::Config::from_args(&args).and_then(|cfg| more_ledgerd::run(&cfg));
    if let Err(e) = outcome {
        eprintln!("more-ledgerd: {e}");
        std::process::exit(2);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("more-ledgerd checks which user is at the other end of its socket, which this build does on Linux only");
    std::process::exit(2);
}
