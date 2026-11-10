//! The ledger as a real process (LEDGER-024): every test starts `more-ledgerd`, talks to it over
//! its socket and stops it. The attacker of these tests is a whole process: it has the
//! orchestrator's key, the socket and nothing else.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../../ledger/tests/common/mod.rs"]
mod common;

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use common::hostile::*;
use common::*;
use gpu_ledger::link::{Fault, LinkError, Message, Refusal, StreamTransport, MAX_FRAME};
use gpu_ledger::*;
use gpu_simulation::{op_strategy, RemoteRig, Sim};
use more_identity::{Domain, IdentityAuthority, ServiceCredential, ServiceRole};
use more_ledgerd::{connect, to_hex, wait_until_listening, write_identity};
use proptest::prelude::*;

const NOBODY: u32 = 65534;

struct Daemon {
    child: Child,
    dir: PathBuf,
    socket: PathBuf,
}

fn scratch_dir() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("more-ledgerd-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn command(dir: &Path, domain: Domain, identity: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_more-ledgerd"));
    c.arg("--socket")
        .arg(dir.join("ledger.sock"))
        .arg("--domain")
        .arg(to_hex(domain.as_bytes()))
        .arg("--identity")
        .arg(identity)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

impl Daemon {
    /// Starts the daemon as `user` (the current one if `None`) and waits until it listens.
    fn start(identity: &ServiceCredential, domain: Domain, user: Option<u32>) -> Daemon {
        let dir = scratch_dir();
        let key_file = dir.join("ledger.identity");
        write_identity(&key_file, identity).unwrap();
        let mut cmd = command(&dir, domain, &key_file);
        if let Some(uid) = user {
            for p in [&dir, &key_file] {
                std::os::unix::fs::chown(p, Some(uid), Some(uid)).unwrap();
            }
            cmd.uid(uid).gid(uid);
        }
        let mut child = cmd.spawn().unwrap();
        let listening = wait_until_listening(child.stdout.take().unwrap());
        assert!(listening, "the daemon did not start");
        Daemon {
            child,
            socket: dir.join("ledger.sock"),
            dir,
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The test world with its second ledger in a daemon: account keys registered by the identity
/// service, one socket connection per service.
fn process_world() -> (World, Daemon) {
    let mut w = bare_world();
    let daemon = Daemon::start(&w.ledger_id, dom(), None);
    let verifier = w.auth.verifier();
    let dial = |me: &ServiceCredential| connect(&daemon.socket, me, &verifier).unwrap();
    let mut registrar = dial(&w.identity);
    for a in [ALICE, BOB, L1, L2, WIT, MALLORY, ADMIN] {
        registrar
            .register_key(a, key(a).public().to_bytes())
            .unwrap()
            .unwrap();
    }
    w.mirror = Some(Mirror {
        orch: Box::new(dial(&w.orch)),
        treasury: Box::new(dial(&w.treasury)),
        clock: Box::new(dial(&w.clock)),
        platform: Box::new(dial(&w.platform)),
        auditor: Box::new(dial(&w.auditor)),
        host: None,
        in_tx: false,
    });
    w.setup();
    (w, daemon)
}

fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .map_or(default, |n| (n / 16).max(default))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(16), failure_persistence: None, ..ProptestConfig::default() })]

    /// TEST-P35 against the real process: a hostile orchestrator's calls go to the in-process
    /// ledger and, over the socket, to the daemon. Same answers, same balances, same journal,
    /// call after call.
    #[test]
    fn p35_the_daemon_is_the_same_ledger(seq in prop::collection::vec(calls(), 1..120)) {
        let (mut w, _daemon) = process_world();
        w.open(JOB, 500).unwrap();
        for c in &seq {
            let _ = apply(&mut w, c);
            check(&w, c)?;
        }
    }

    /// TEST-P37 against the real process: a coordinator that holds the orchestrator's key and a
    /// socket, driven by random traces, next to the coordinator of the model.
    #[test]
    fn p37_a_coordinator_drives_a_ledger_in_another_process(
        ops in prop::collection::vec(op_strategy(), 1..120)
    ) {
        let mut daemon = None;
        let mut sim = Sim::shadowed(|ids| {
            let d = Daemon::start(&ids.ledger, ids.verifier().domain(), None);
            let mut registrar = connect(&d.socket, &ids.registrar, &ids.verifier()).unwrap();
            use gpu_simulation::{BORROWERS, LENDERS, POOL_ADMIN, STRANGER, WITNESS};
            let accounts = BORROWERS
                .iter()
                .chain(&LENDERS)
                .chain(&[WITNESS, POOL_ADMIN, STRANGER]);
            for a in accounts {
                let public = gpu_simulation::user_key(*a).public().to_bytes();
                registrar.register_key(a.0, public).unwrap().unwrap();
            }
            let socket = d.socket.clone();
            daemon = Some(d);
            RemoteRig::new(ids, move || {
                StreamTransport(UnixStream::connect(&socket).unwrap())
            })
        });
        for op in &ops {
            sim.run_op(op);
        }
        sim.drain();
        prop_assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
        prop_assert!(sim.shadow.as_ref().is_some_and(|s| s.followed > 20));
        drop(daemon);
    }
}

/// The orchestrator's process is killed in the middle of a transaction: the kernel closes its
/// socket, and the ledger rolls back what was not committed.
#[test]
fn a_killed_orchestrator_leaves_nothing_half_done() {
    let (mut w, daemon) = process_world();
    w.open(JOB, 500).unwrap();
    let verifier = w.auth.verifier();
    let mut auditor = connect(&daemon.socket, &w.auditor, &verifier).unwrap();
    let before = (
        auditor.audit_balances().unwrap().unwrap(),
        auditor.audit_summary().unwrap().unwrap(),
    );
    let reserve = |n: u32| LedgerOp::Reserve {
        job: JOB,
        bucket: EscrowBucket::Work,
        key: format!("dying/{n}"),
        amount: 10,
    };
    let mut dying = connect(&daemon.socket, &w.orch, &verifier).unwrap();
    dying.begin().unwrap().unwrap();
    dying.execute(reserve(1)).unwrap().unwrap();
    dying.execute(reserve(2)).unwrap().unwrap();
    // While it holds its transaction the others are told to wait.
    assert_eq!(
        auditor.audit_balances(),
        Err(LinkError::Refused(Refusal::Busy))
    );
    drop(dying);
    // The daemon notices the closed socket on its own thread: give it a moment.
    let mut after = None;
    for _ in 0..200 {
        match auditor.audit_balances() {
            Err(LinkError::Refused(Refusal::Busy)) => {
                std::thread::sleep(std::time::Duration::from_millis(5))
            }
            other => {
                after = Some(other.unwrap().unwrap());
                break;
            }
        }
    }
    assert_eq!(after.as_ref(), Some(&before.0), "rolled back");
    assert_eq!(auditor.audit_summary().unwrap().unwrap(), before.1);
    // And the ledger is free for the next orchestrator.
    let mut next = connect(&daemon.socket, &w.orch, &verifier).unwrap();
    next.execute(reserve(1)).unwrap().unwrap();
}

/// Whatever arrives on the socket, the daemon keeps serving the others.
#[test]
fn garbage_on_the_socket_does_not_stop_the_daemon() {
    let (w, daemon) = process_world();
    let verifier = w.auth.verifier();
    let raw = || {
        let s = UnixStream::connect(&daemon.socket).unwrap();
        // A daemon that kept waiting for more bytes would show as a timeout, not as a close.
        s.set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        s
    };
    // A length far above the limit: the connection is closed without reading further.
    let mut s = raw();
    s.write_all(&u32::MAX.to_le_bytes()).unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(s.read(&mut buf).ok(), Some(0), "closed");
    let mut s = raw();
    s.write_all(&((MAX_FRAME as u32) + 1).to_le_bytes())
        .unwrap();
    assert_eq!(s.read(&mut buf).ok(), Some(0), "closed");
    // A frame cut short, then the peer goes away.
    let mut s = raw();
    s.write_all(&100u32.to_le_bytes()).unwrap();
    s.write_all(&[1, 2, 3]).unwrap();
    drop(s);
    // A well-framed payload that means nothing: a fault, then closed.
    let mut s = raw();
    s.write_all(&3u32.to_le_bytes()).unwrap();
    s.write_all(&[0xee, 0xee, 0xee]).unwrap();
    let mut len = [0u8; 4];
    s.read_exact(&mut len).unwrap();
    let mut payload = vec![0u8; u32::from_le_bytes(len) as usize];
    s.read_exact(&mut payload).unwrap();
    assert_eq!(
        Message::decode(&payload),
        Ok(Message::Fault(Fault::Malformed))
    );
    assert_eq!(s.read(&mut buf).ok(), Some(0), "closed");
    // Many silent connections, more than the daemon serves at once.
    let idle: Vec<UnixStream> = (0..more_ledgerd::MAX_CONNECTIONS + 16)
        .map(|_| raw())
        .collect();
    drop(idle);
    // The daemon is still there for a real service.
    let mut ok = None;
    for _ in 0..200 {
        match connect(&daemon.socket, &w.auditor, &verifier) {
            Ok(c) => {
                ok = Some(c);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
        }
    }
    let mut auditor = ok.expect("the daemon still serves");
    let summary = auditor.audit_summary().unwrap().unwrap();
    assert_eq!(
        summary.entries, 3,
        "the three issuances of the setup, nothing else"
    );
}

/// The socket and the key file belong to the daemon's user alone, and the daemon refuses to
/// start on a key file others can read, on an identity that is not a ledger's, or on one from
/// another deployment.
#[test]
fn the_socket_and_the_key_file_are_private() {
    let w = bare_world();
    let daemon = Daemon::start(&w.ledger_id, dom(), None);
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&daemon.socket), 0o600);
    assert_eq!(mode(&daemon.dir.join("ledger.identity")), 0o600);
    let refuses = |identity: &ServiceCredential, domain: Domain, loose: bool, why: &str| {
        let dir = scratch_dir();
        let key_file = dir.join("ledger.identity");
        write_identity(&key_file, identity).unwrap();
        if loose {
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let out = command(&dir, domain, &key_file).output().unwrap();
        let said = String::from_utf8_lossy(&out.stderr).to_string();
        assert_eq!(out.status.code(), Some(2), "{why}: {said}");
        assert!(said.contains(why), "{said}");
        assert!(!dir.join("ledger.sock").exists(), "no socket was opened");
        let _ = std::fs::remove_dir_all(&dir);
    };
    refuses(&w.ledger_id, dom(), true, "0600");
    refuses(&w.orch, dom(), false, "role Ledger");
    let mut elsewhere = IdentityAuthority::new([4; 32]);
    let foreign = elsewhere.issue(ServiceRole::Ledger);
    refuses(&foreign, dom(), false, "role Ledger");
    // A key file that is not an identity at all.
    let dir = scratch_dir();
    let junk = dir.join("ledger.identity");
    std::fs::write(&junk, "not hex").unwrap();
    std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = command(&dir, dom(), &junk).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The daemon's memory is not readable by another process of the same user. Linux marks the
/// files under `/proc/PID` of such a process as root's, and refuses to open its memory.
#[cfg(target_os = "linux")]
#[test]
fn another_process_of_the_same_user_cannot_read_the_ledgers_memory() {
    let w = bare_world();
    let me = std::fs::metadata("/proc/self").unwrap().uid();
    // As root nothing is refused to us: the daemon and the prying process then both run as an
    // unprivileged user.
    let user = (me == 0).then_some(NOBODY);
    let daemon = Daemon::start(&w.ledger_id, dom(), user);
    let runs_as = user.unwrap_or(me);
    let mem = format!("/proc/{}/mem", daemon.pid());
    let status = std::fs::read_to_string(format!("/proc/{}/status", daemon.pid())).unwrap();
    let uid_line = status.lines().find(|l| l.starts_with("Uid:")).unwrap();
    assert!(
        uid_line
            .split_whitespace()
            .skip(1)
            .all(|u| u == runs_as.to_string()),
        "the daemon runs as {runs_as}: {uid_line}"
    );
    assert_eq!(
        std::fs::metadata(&mem).unwrap().uid(),
        0,
        "a sealed process's memory file belongs to root, not to its user"
    );
    // An ordinary process of that user, for comparison: its memory file is its user's.
    let mut plain = Command::new("sleep");
    plain.arg("30");
    if let Some(uid) = user {
        plain.uid(uid).gid(uid);
    }
    let mut plain = plain.spawn().unwrap();
    let plain_mem = format!("/proc/{}/mem", plain.id());
    assert_eq!(std::fs::metadata(&plain_mem).unwrap().uid(), runs_as);
    // Opening the daemon's memory as that user fails.
    let open = |path: &str| {
        let mut probe = Command::new("sh");
        probe.arg("-c").arg(format!("exec 3<{path}"));
        probe.stderr(Stdio::null());
        if let Some(uid) = user {
            probe.uid(uid).gid(uid);
        }
        probe.status().unwrap().success()
    };
    assert!(
        !open(&mem),
        "the daemon's memory was opened by its own user"
    );
    if user.is_none() {
        // Without root in the way, the same open works on our own ordinary child.
        assert!(std::fs::File::open(&plain_mem).is_ok());
        let denied = std::fs::File::open(&mem).map_err(|e| e.kind());
        assert_eq!(denied.err(), Some(std::io::ErrorKind::PermissionDenied));
    }
    let _ = plain.kill();
    let _ = plain.wait();
}
