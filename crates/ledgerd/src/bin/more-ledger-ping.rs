//! `more-ledger-ping --socket PATH --domain HEX --identity FILE [--timeout-ms N]`
//!
//! Connects to the ledger as the service whose identity is in `FILE` and prints what the ledger
//! says of itself. Exit status 0 if it answered, 1 otherwise.

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match more_ledgerd::ping(&args) {
        Ok(answer) => println!("{answer}"),
        Err(e) => {
            eprintln!("more-ledger-ping: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("more-ledger-ping: Linux only");
    std::process::exit(1);
}
