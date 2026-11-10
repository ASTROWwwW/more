//! `more-ledgerd --socket PATH --domain HEX --identity FILE [--tx-timeout-ms N]`

#[cfg(unix)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = more_ledgerd::Config::from_args(&args).and_then(|cfg| more_ledgerd::run(&cfg));
    if let Err(e) = outcome {
        eprintln!("more-ledgerd: {e}");
        std::process::exit(2);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("more-ledgerd needs Unix sockets");
    std::process::exit(2);
}
