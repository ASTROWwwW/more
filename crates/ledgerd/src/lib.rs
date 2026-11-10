//! The ledger in a process of its own (LEDGER-021 to LEDGER-027).
//!
//! `more-ledgerd` holds the journal, the job records and the directory of account keys. Other
//! services reach it through a Unix socket and the ledger link, each with its own key. The
//! daemon holds one secret, its own identity key, and the authority's public key.
//!
//! Who may connect is decided twice: by the socket file (its owner, or one group), and by the
//! user the kernel reports for each connection, checked against a list before a byte is read.
//! A connection then still has to authenticate as a service.
//!
//! What this is not: a network service, and not a ledger for credits that are worth anything.
//! The socket is local, payloads are not encrypted, and the state lives in memory: a restart
//! loses it. Each start draws a new incarnation number so that clients notice.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, BufRead, Read};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gpu_ledger::link::{
    read_frame, write_frame, HostEnv, HostLimits, LedgerClient, LedgerHost, LinkError,
    StreamTransport,
};
use gpu_ledger::{LedgerLimits, LedgerService};
use more_identity::{CredentialVerifier, Domain, KeyDirectory, ServiceCredential};

/// Most connections served at once. Past it, new ones are closed at once.
pub const MAX_CONNECTIONS: usize = 64;

/// How long a new connection has to authenticate, unless the command line says otherwise.
pub const HANDSHAKE_MS: u64 = 2_000;

/// How long a client waits for an answer, unless it asks for another delay.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Said on standard error at every start.
pub const WARNING: &str = "experimental. The ledger's state is in memory only and is lost when \
this process stops. Do not use it for credits that are worth anything.";

/// Said on standard error when the daemon's own timer ends a transaction.
pub const SWEPT: &str = "a transaction outlived its deadline and was rolled back by the timer";

/// The local users whose connections are accepted at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Access {
    users: BTreeSet<u32>,
}

impl Access {
    /// The listed users and nobody else. With no list, the daemon's own user. Root is a user
    /// like the others here: not listed, not admitted.
    pub fn new(own: u32, listed: &[u32]) -> Access {
        let users = if listed.is_empty() {
            BTreeSet::from([own])
        } else {
            listed.iter().copied().collect()
        };
        Access { users }
    }

    pub fn admits(&self, user: u32) -> bool {
        self.users.contains(&user)
    }
}

/// What the daemon is started with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Where to listen.
    pub socket: PathBuf,
    /// The deployment: the public key of its identity authority.
    pub domain: Domain,
    /// File holding the daemon's own identity (role `Ledger`), readable by its owner only.
    pub identity: PathBuf,
    pub limits: HostLimits,
    /// Users admitted on the socket. Empty: the daemon's own user only.
    pub allow: Vec<u32>,
    /// Group the socket file is opened to (mode 0660). Without one it is the owner's alone
    /// (0600). It is never opened to every local user.
    pub socket_group: Option<u32>,
    /// How long a connection has to authenticate.
    pub handshake_ms: u64,
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

/// `--flag value` pairs. A flag outside `known` is an error; a flag may come several times.
fn flags<'a>(
    args: &'a [String],
    known: &[&str],
) -> Result<BTreeMap<&'a str, Vec<&'a str>>, String> {
    let mut found: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if !known.contains(&flag.as_str()) {
            return Err(format!("unknown option {flag}"));
        }
        let value = it.next().ok_or(format!("{flag} needs a value"))?;
        found.entry(flag).or_default().push(value);
    }
    Ok(found)
}

fn one<'a>(found: &BTreeMap<&str, Vec<&'a str>>, flag: &str) -> Result<Option<&'a str>, String> {
    match found.get(flag).map(Vec::as_slice) {
        None => Ok(None),
        Some([value]) => Ok(Some(value)),
        Some(_) => Err(format!("{flag} given more than once")),
    }
}

fn required<'a>(found: &BTreeMap<&str, Vec<&'a str>>, flag: &str) -> Result<&'a str, String> {
    one(found, flag)?.ok_or(format!("{flag} is required"))
}

fn number<N: std::str::FromStr>(flag: &str, value: &str) -> Result<N, String> {
    value.parse().map_err(|_| format!("{flag}: a number"))
}

fn domain_of(value: &str) -> Result<Domain, String> {
    let bytes: [u8; 32] = hex(value)
        .and_then(|b| b.try_into().ok())
        .ok_or("--domain is 64 hexadecimal digits")?;
    Ok(Domain::from_bytes(bytes))
}

impl Config {
    /// `--socket PATH --domain HEX --identity FILE [--allow-uid UID]... [--socket-group GID]
    /// [--tx-timeout-ms N] [--handshake-timeout-ms N]`
    pub fn from_args(args: &[String]) -> Result<Config, String> {
        let known = [
            "--socket",
            "--domain",
            "--identity",
            "--allow-uid",
            "--socket-group",
            "--tx-timeout-ms",
            "--handshake-timeout-ms",
        ];
        let found = flags(args, &known)?;
        let mut limits = HostLimits::default();
        if let Some(v) = one(&found, "--tx-timeout-ms")? {
            limits.tx_timeout_ms = number("--tx-timeout-ms", v)?;
        }
        let handshake_ms = match one(&found, "--handshake-timeout-ms")? {
            Some(v) => number("--handshake-timeout-ms", v)?,
            None => HANDSHAKE_MS,
        };
        // A delay of zero would refuse everyone, or let nothing ever expire.
        if limits.tx_timeout_ms == 0 || handshake_ms == 0 {
            return Err("a timeout of zero is not a timeout".into());
        }
        let allow = found
            .get("--allow-uid")
            .into_iter()
            .flatten()
            .map(|v| number("--allow-uid", v))
            .collect::<Result<Vec<u32>, String>>()?;
        let socket_group = one(&found, "--socket-group")?
            .map(|v| number("--socket-group", v))
            .transpose()?;
        Ok(Config {
            socket: PathBuf::from(required(&found, "--socket")?),
            domain: domain_of(required(&found, "--domain")?)?,
            identity: PathBuf::from(required(&found, "--identity")?),
            limits,
            allow,
            socket_group,
            handshake_ms,
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

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

struct OsEnv {
    start: Instant,
}

impl HostEnv for OsEnv {
    fn now_ms(&mut self) -> u64 {
        elapsed_ms(self.start)
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
fn seal_memory() -> io::Result<()> {
    use rustix::process::{set_dumpable_behavior, DumpableBehavior};
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(io::Error::from)
}

/// The user at the other end of a local socket, as the kernel recorded it when the connection
/// was made. Nothing the peer sends can change it.
fn peer_user(stream: &UnixStream) -> Option<u32> {
    rustix::net::sockopt::socket_peercred(stream)
        .ok()
        .map(|peer| peer.uid.as_raw())
}

/// Creates the socket for its owner, or for its owner and one group, never for every local
/// user. Between `bind` and the change of mode the file has whatever the process's file mask
/// gives it: a connection made in that instant is checked against the list of users like any
/// other.
fn listen(cfg: &Config) -> Result<UnixListener, String> {
    let at = |e: io::Error| format!("{}: {e}", cfg.socket.display());
    let listener = UnixListener::bind(&cfg.socket).map_err(at)?;
    let mode = match cfg.socket_group {
        Some(group) => {
            std::os::unix::fs::chown(&cfg.socket, None, Some(group)).map_err(at)?;
            0o660
        }
        None => 0o600,
    };
    fs::set_permissions(&cfg.socket, fs::Permissions::from_mode(mode)).map_err(at)?;
    Ok(listener)
}

/// Reads from a connection, within a deadline while one is set. The deadline is for the whole
/// handshake: sending a byte now and then does not move it.
struct Timed<'a> {
    stream: &'a UnixStream,
    until: Option<Instant>,
}

impl Read for Timed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(until) = self.until {
            let left = until
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or(io::ErrorKind::TimedOut)?;
            self.stream.set_read_timeout(Some(left))?;
        }
        let mut stream = self.stream;
        stream.read(buf)
    }
}

fn serve(host: &Mutex<LedgerHost>, stream: UnixStream, start: Instant, handshake: Duration) {
    let mut env = OsEnv { start };
    let mut conn = host.lock().unwrap_or_else(|e| e.into_inner()).open();
    let mut from = Timed {
        stream: &stream,
        until: Some(Instant::now() + handshake),
    };
    // A frame that cannot be read (too long, cut short, late, peer gone) ends the connection.
    while let Ok(frame) = read_frame(&mut from) {
        let reply = {
            let mut host = host.lock().unwrap_or_else(|e| e.into_inner());
            host.handle(&mut conn, &frame, &mut env)
        };
        let mut to = &stream;
        if write_frame(&mut to, &reply.frame).is_err() || reply.close {
            break;
        }
        // An authenticated service may stay connected and silent as long as it likes.
        if from.until.is_some() && conn.peer().is_some() {
            from.until = None;
            if stream.set_read_timeout(None).is_err() {
                break;
            }
        }
    }
    // Whatever the connection left uncommitted goes with it.
    host.lock()
        .unwrap_or_else(|e| e.into_inner())
        .close(&mut conn);
}

/// How often expired transactions are looked for: a transaction outlives its deadline by this
/// much at most, whether or not anyone talks to the ledger.
fn sweep_period(limits: &HostLimits) -> Duration {
    Duration::from_millis((limits.tx_timeout_ms / 4).clamp(1, 250))
}

/// Runs the daemon until the process is stopped. Prints `listening` on standard output once
/// the socket accepts connections.
pub fn run(cfg: &Config) -> Result<(), String> {
    eprintln!("more-ledgerd: {WARNING}");
    seal_memory().map_err(|e| format!("cannot seal the process memory: {e}"))?;
    let identity = read_identity(&cfg.identity)?;
    let verifier =
        CredentialVerifier::for_domain(cfg.domain).ok_or("--domain is not a public key")?;
    let keys = KeyDirectory::new();
    let service = LedgerService::new(verifier.clone(), keys.clone(), LedgerLimits::default());
    // A number no earlier run of this ledger had: a client that reconnects sees that the
    // ledger it knew is gone, and its state with it.
    let nonce = os_nonce().map_err(|e| format!("no random source: {e}"))?;
    let mut incarnation = [0u8; 8];
    incarnation.copy_from_slice(&nonce[..8]);
    let incarnation = u64::from_le_bytes(incarnation);
    let host = LedgerHost::new(service, keys, verifier, identity, cfg.limits, incarnation)?;
    let host = Arc::new(Mutex::new(host));
    let access = Access::new(rustix::process::getuid().as_raw(), &cfg.allow);
    let listener = listen(cfg)?;
    eprintln!(
        "more-ledgerd: incarnation {incarnation:016x}, users admitted: {:?}",
        access.users
    );
    let start = Instant::now();
    {
        let host = Arc::clone(&host);
        let period = sweep_period(&cfg.limits);
        std::thread::spawn(move || loop {
            std::thread::sleep(period);
            let ended = host
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .sweep(elapsed_ms(start));
            if ended {
                eprintln!("more-ledgerd: {SWEPT}");
            }
        });
    }
    println!("listening");
    let handshake = Duration::from_millis(cfg.handshake_ms);
    let open = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        // Before a byte is read: a user that is not on the list has no connection.
        if !peer_user(&stream).is_some_and(|user| access.admits(user)) {
            continue;
        }
        if open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            open.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (host, open) = (Arc::clone(&host), Arc::clone(&open));
        std::thread::spawn(move || {
            serve(&host, stream, start, handshake);
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
    connect_within(socket, me, verifier, CALL_TIMEOUT)
}

/// As `connect`, waiting at most `wait` for each answer. An answer that does not come in time
/// is a failure of the link: the connection is then dead, and what became of a commit sent on
/// it has to be asked on another one.
pub fn connect_within(
    socket: &Path,
    me: &ServiceCredential,
    verifier: &CredentialVerifier,
    wait: Duration,
) -> Result<SocketClient, LinkError> {
    let io = |e: io::Error| LinkError::Io(e.to_string());
    let stream = UnixStream::connect(socket).map_err(io)?;
    stream.set_read_timeout(Some(wait)).map_err(io)?;
    stream.set_write_timeout(Some(wait)).map_err(io)?;
    let nonce = os_nonce().map_err(io)?;
    LedgerClient::connect(StreamTransport(stream), me, verifier, nonce)
}

/// `more-ledger-ping --socket PATH --domain HEX --identity FILE [--timeout-ms N]`: connects
/// as the service in `FILE` and asks the ledger who it is. Says what the ledger answered, or
/// why there is no answer.
pub fn ping(args: &[String]) -> Result<String, String> {
    let found = flags(
        args,
        &["--socket", "--domain", "--identity", "--timeout-ms"],
    )?;
    let wait = match one(&found, "--timeout-ms")? {
        Some(v) => Duration::from_millis(number("--timeout-ms", v)?),
        None => CALL_TIMEOUT,
    };
    let me = read_identity(Path::new(required(&found, "--identity")?))?;
    let verifier = CredentialVerifier::for_domain(domain_of(required(&found, "--domain")?)?)
        .ok_or("--domain is not a public key")?;
    let socket = Path::new(required(&found, "--socket")?);
    let mut client = connect_within(socket, &me, &verifier, wait)
        .map_err(|e| format!("no connection: {e:?}"))?;
    let info = client.info().map_err(|e| format!("no answer: {e:?}"))?;
    Ok(format!(
        "ok incarnation={:016x} seq={} now={}",
        info.incarnation, info.seq, info.now
    ))
}

/// Waits for the daemon's `listening` line on its standard output.
pub fn wait_until_listening(out: impl io::Read) -> bool {
    let mut line = String::new();
    io::BufReader::new(out)
        .read_line(&mut line)
        .is_ok_and(|_| line.trim() == "listening")
}
