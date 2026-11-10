//! The ledger in a process of its own (LEDGER-021 to LEDGER-024).
//!
//! `more-ledgerd` holds the journal, the job records and the directory of account keys. Other
//! services reach it through a Unix socket and the ledger link, each with its own key. The
//! daemon holds one secret, its own identity key, and the authority's public key.
//!
//! What this is not: a network service. The socket is local, payloads are not encrypted, and
//! the state lives in memory: a restart loses it. Persistence and a secure channel for remote
//! peers come before any deployment.

#![cfg(unix)]

use std::fs;
use std::io::{self, BufRead};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use gpu_ledger::link::{
    read_frame, write_frame, HostEnv, HostLimits, LedgerClient, LedgerHost, LinkError,
    StreamTransport,
};
use gpu_ledger::{LedgerLimits, LedgerService};
use more_identity::{CredentialVerifier, Domain, KeyDirectory, ServiceCredential};

/// Most connections served at once. Past it, new ones are closed at once.
pub const MAX_CONNECTIONS: usize = 64;

/// What the daemon is started with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Where to listen. The file is created with mode 0600.
    pub socket: PathBuf,
    /// The deployment: the public key of its identity authority.
    pub domain: Domain,
    /// File holding the daemon's own identity (role `Ledger`), readable by its owner only.
    pub identity: PathBuf,
    pub limits: HostLimits,
}

fn hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Lowercase hexadecimal, for identity files and the domain on the command line.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Config {
    /// `--socket PATH --domain HEX --identity FILE [--tx-timeout-ms N]`
    pub fn from_args(args: &[String]) -> Result<Config, String> {
        let mut socket = None;
        let mut domain = None;
        let mut identity = None;
        let mut limits = HostLimits::default();
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            let value = it.next().ok_or(format!("{flag} needs a value"))?;
            match flag.as_str() {
                "--socket" => socket = Some(PathBuf::from(value)),
                "--identity" => identity = Some(PathBuf::from(value)),
                "--domain" => {
                    let bytes: [u8; 32] = hex(value)
                        .and_then(|b| b.try_into().ok())
                        .ok_or("--domain is 64 hexadecimal digits")?;
                    domain = Some(Domain::from_bytes(bytes));
                }
                "--tx-timeout-ms" => {
                    limits.tx_timeout_ms =
                        value.parse().map_err(|_| "--tx-timeout-ms: a number")?;
                }
                other => return Err(format!("unknown option {other}")),
            }
        }
        Ok(Config {
            socket: socket.ok_or("--socket is required")?,
            domain: domain.ok_or("--domain is required")?,
            identity: identity.ok_or("--identity is required")?,
            limits,
        })
    }
}

/// Reads a service identity from a file of hexadecimal digits. The file holds a private key:
/// it is refused if anyone but its owner can read it.
pub fn read_identity(path: &Path) -> Result<ServiceCredential, String> {
    let mode = fs::metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "{}: readable by others (mode {:o}); a key file must be 0600",
            path.display(),
            mode & 0o777
        ));
    }
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    hex(&text)
        .and_then(|b| ServiceCredential::from_bytes(&b))
        .ok_or(format!("{}: not a service identity", path.display()))
}

/// Writes a service identity where only its owner can read it.
pub fn write_identity(path: &Path, me: &ServiceCredential) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(to_hex(&me.to_bytes()).as_bytes())
}

struct OsEnv {
    start: Instant,
}

impl HostEnv for OsEnv {
    fn now_ms(&mut self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
    fn nonce(&mut self) -> [u8; 32] {
        let mut n = [0u8; 32];
        // Without the system's random source there is no handshake worth having.
        if getrandom::getrandom(&mut n).is_err() {
            eprintln!("more-ledgerd: no random source, stopping");
            std::process::exit(3);
        }
        n
    }
}

/// A fresh nonce from the operating system, for a client's side of the handshake.
pub fn os_nonce() -> io::Result<[u8; 32]> {
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(n)
}

/// Other processes of the same user can normally read a process's memory (`/proc/PID/mem`,
/// `ptrace`). Marking the process as not dumpable closes that: the kernel then requires
/// `CAP_SYS_PTRACE`. Running the daemon under a user of its own remains the stronger boundary.
#[cfg(target_os = "linux")]
fn seal_memory() -> io::Result<()> {
    use rustix::process::{set_dumpable_behavior, DumpableBehavior};
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(io::Error::from)
}

#[cfg(not(target_os = "linux"))]
fn seal_memory() -> io::Result<()> {
    Ok(())
}

fn serve(host: &Mutex<LedgerHost>, stream: UnixStream, start: Instant) {
    let mut env = OsEnv { start };
    let mut conn = host.lock().unwrap_or_else(|e| e.into_inner()).open();
    let mut stream = stream;
    // A frame that cannot be read (too long, cut short, peer gone) ends the connection.
    while let Ok(frame) = read_frame(&mut stream) {
        let reply = {
            let mut host = host.lock().unwrap_or_else(|e| e.into_inner());
            host.handle(&mut conn, &frame, &mut env)
        };
        if write_frame(&mut stream, &reply.frame).is_err() || reply.close {
            break;
        }
    }
    // Whatever the connection left uncommitted goes with it.
    host.lock()
        .unwrap_or_else(|e| e.into_inner())
        .close(&mut conn);
}

/// Runs the daemon until the process is stopped. Prints `listening` on standard output once
/// the socket accepts connections.
pub fn run(cfg: &Config) -> Result<(), String> {
    seal_memory().map_err(|e| format!("cannot seal the process memory: {e}"))?;
    let identity = read_identity(&cfg.identity)?;
    let verifier =
        CredentialVerifier::for_domain(cfg.domain).ok_or("--domain is not a public key")?;
    let keys = KeyDirectory::new();
    let service = LedgerService::new(verifier.clone(), keys.clone(), LedgerLimits::default());
    let host = LedgerHost::new(service, keys, verifier, identity, cfg.limits)?;
    let host = Arc::new(Mutex::new(host));
    let listener =
        UnixListener::bind(&cfg.socket).map_err(|e| format!("{}: {e}", cfg.socket.display()))?;
    fs::set_permissions(&cfg.socket, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", cfg.socket.display()))?;
    println!("listening");
    let start = Instant::now();
    let open = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            open.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (host, open) = (Arc::clone(&host), Arc::clone(&open));
        std::thread::spawn(move || {
            serve(&host, stream, start);
            open.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// A connection to the daemon over its socket.
pub type SocketClient = LedgerClient<StreamTransport<UnixStream>>;

/// Connects to the daemon at `socket` as `me`, checking that it is this deployment's ledger.
pub fn connect(
    socket: &Path,
    me: &ServiceCredential,
    verifier: &CredentialVerifier,
) -> Result<SocketClient, LinkError> {
    let stream = UnixStream::connect(socket).map_err(|e| LinkError::Io(e.to_string()))?;
    let nonce = os_nonce().map_err(|e| LinkError::Io(e.to_string()))?;
    LedgerClient::connect(StreamTransport(stream), me, verifier, nonce)
}

/// Waits for the daemon's `listening` line on its standard output.
pub fn wait_until_listening(out: impl io::Read) -> bool {
    let mut line = String::new();
    io::BufReader::new(out)
        .read_line(&mut line)
        .is_ok_and(|_| line.trim() == "listening")
}
