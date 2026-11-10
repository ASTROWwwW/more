//! The ledger as a real process (LEDGER-024 to LEDGER-027): every test starts `more-ledgerd`,
//! talks to it over its socket and stops it. The attacker of these tests is a whole process:
//! it has the orchestrator's key, the socket and nothing else.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../ledger/tests/common/mod.rs"]
mod common;

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::hostile::*;
use common::*;
use gpu_domain::{Command as Cmd, DomainError, Outcome};
use gpu_ledger::link::{
    Fault, LinkError, Message, Refusal, Request, Rollback, StreamTransport, Transport, TxState,
    MAX_FRAME,
};
use gpu_ledger::*;
use gpu_simulation::{op_strategy, Cut, Faults, Flaky, RemoteRig, Sim, SimIdentity};
use more_identity::{Domain, IdentityAuthority, ServiceCredential, ServiceRole};
use more_ledgerd::{connect, connect_within, to_hex, wait_until_listening, write_identity};
use proptest::prelude::*;
use proptest::test_runner::{TestCaseError, TestRunner};

const NOBODY: u32 = 65534;

fn me() -> u32 {
    std::fs::metadata("/proc/self").unwrap().uid()
}

struct Daemon {
    child: Child,
    dir: PathBuf,
    socket: PathBuf,
    start: Box<dyn Fn() -> Command>,
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
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

/// Runs a command that must end by itself. One that is still there after ten seconds is killed
/// and fails the test: a daemon that should have refused to start, and started.
fn finish(mut cmd: Command) -> Output {
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("still running after ten seconds");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

/// Tries `f` every few milliseconds until it gives something, for five seconds at most.
fn eventually<V>(mut f: impl FnMut() -> Option<V>) -> Option<V> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match f() {
            Some(v) => return Some(v),
            None if Instant::now() > deadline => return None,
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}

impl Daemon {
    /// Starts the daemon as `user` (the current one if `None`) and waits until it listens.
    fn start(identity: &ServiceCredential, domain: Domain, user: Option<u32>) -> Daemon {
        Self::start_with(identity, domain, user, &[])
    }

    fn start_with(
        identity: &ServiceCredential,
        domain: Domain,
        user: Option<u32>,
        options: &[&str],
    ) -> Daemon {
        let dir = scratch_dir();
        let key_file = dir.join("ledger.identity");
        write_identity(&key_file, identity).unwrap();
        if let Some(uid) = user {
            for p in [&dir, &key_file] {
                std::os::unix::fs::chown(p, Some(uid), Some(uid)).unwrap();
            }
        }
        let mut options: Vec<String> = options.iter().map(|o| o.to_string()).collect();
        // A daemon under another user admits its own user only, unless told: tell it who we are.
        if user.is_some() && !options.iter().any(|o| o == "--allow-uid") {
            options.extend(["--allow-uid".to_string(), me().to_string()]);
        }
        let at = dir.clone();
        let start = Box::new(move || {
            let mut cmd = command(&at, domain, &key_file);
            cmd.args(&options);
            if let Some(uid) = user {
                cmd.uid(uid).gid(uid);
            }
            cmd
        });
        let child = Self::spawn(&start);
        Daemon {
            child,
            socket: dir.join("ledger.sock"),
            dir,
            start,
        }
    }

    fn spawn(start: &dyn Fn() -> Command) -> Child {
        let mut child = start().spawn().unwrap();
        let listening = wait_until_listening(child.stdout.take().unwrap());
        assert!(listening, "the daemon did not start");
        child
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Stops the process and returns what it said on standard error.
    fn stop(&mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut said = String::new();
        if let Some(mut err) = self.child.stderr.take() {
            let _ = err.read_to_string(&mut said);
        }
        said
    }

    /// The same daemon started again: same socket, same identity, an empty ledger.
    fn restart(&mut self) {
        self.stop();
        std::fs::remove_file(&self.socket).unwrap();
        self.child = Self::spawn(&self.start);
    }

    fn signal(&self, name: &str) {
        let done = Command::new("kill")
            .arg(format!("-{name}"))
            .arg(self.pid().to_string())
            .status()
            .unwrap();
        assert!(done.success());
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
fn process_world_with(options: &[&str]) -> (World, Daemon) {
    let daemon = Daemon::start_with(&bare_world().ledger_id, dom(), None, options);
    (world_at(&daemon.socket), daemon)
}

/// The test world, mirrored by the ledger that listens at `socket`.
fn world_at(socket: &Path) -> World {
    let mut w = bare_world();
    let verifier = w.auth.verifier();
    let dial = |me: &ServiceCredential| connect(socket, me, &verifier).unwrap();
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
    w
}

fn process_world() -> (World, Daemon) {
    process_world_with(&[])
}

/// A simulation whose shadow coordinator drives a ledger in a daemon. The orchestrator's
/// connection goes through `faults`.
fn process_sim(faults: &Faults) -> (Sim, Daemon) {
    let mut daemon = None;
    let sim = Sim::shadowed(|ids| {
        let d = Daemon::start(&ids.ledger, ids.verifier().domain(), None);
        register_sim_keys(ids, &d.socket);
        let socket = d.socket.clone();
        daemon = Some(d);
        let faults = faults.clone();
        let mut n = 0;
        RemoteRig::new(ids, move || -> Box<dyn Transport + Send> {
            n += 1;
            let link = StreamTransport(UnixStream::connect(&socket).unwrap());
            // The first connection asked for is the orchestrator's.
            if n == 1 {
                Box::new(Flaky::new(link, &faults))
            } else {
                Box::new(link)
            }
        })
    });
    (sim, daemon.unwrap())
}

fn register_sim_keys(ids: &SimIdentity, socket: &Path) {
    use gpu_simulation::{BORROWERS, LENDERS, POOL_ADMIN, STRANGER, WITNESS};
    let mut registrar = connect(socket, &ids.registrar, &ids.verifier()).unwrap();
    let accounts = BORROWERS
        .iter()
        .chain(&LENDERS)
        .chain(&[WITNESS, POOL_ADMIN, STRANGER]);
    for a in accounts {
        let public = gpu_simulation::user_key(*a).public().to_bytes();
        registrar.register_key(a.0, public).unwrap().unwrap();
    }
}

fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .map_or(default, |n| (n / 16).max(default))
}

fn runner() -> TestRunner {
    TestRunner::new(ProptestConfig {
        cases: cases(16),
        failure_persistence: None,
        ..ProptestConfig::default()
    })
}

/// TEST-P35 against the real process: a hostile orchestrator's calls go to the in-process
/// ledger and, over the socket, to the daemon. Same answers, same balances, same journal,
/// call after call.
#[test]
fn p35_the_daemon_is_the_same_ledger() {
    let compared = AtomicU64::new(0);
    let result = runner().run(&prop::collection::vec(calls(), 1..120), |seq| {
        let (mut w, _daemon) = process_world();
        w.open(JOB, 500).unwrap();
        for c in &seq {
            let _ = apply(&mut w, c);
            check(&w, c)?;
        }
        compared.fetch_add(seq.len() as u64, Ordering::Relaxed);
        Ok(())
    });
    if let Err(e) = result {
        panic!("against the daemon: {e}");
    }
    let compared = compared.into_inner();
    println!(
        "TEST-P35 against the process: {} daemons started, {compared} hostile calls compared",
        cases(16)
    );
}

/// TEST-P36 against the real process: groups of hostile calls inside transactions of the
/// daemon, committed or aborted, against a plain copy-and-restore of the ledger in this
/// process. After every group the daemon's auditor sees the same balances and journal.
#[test]
fn p36_transactions_in_the_daemon_match_copy_and_restore() {
    let ended = AtomicU64::new(0);
    let group = (prop::collection::vec(calls(), 1..8), any::<bool>());
    let result = runner().run(&prop::collection::vec(group, 1..24), |groups| {
        let (mut w, _daemon) = process_world();
        w.open(JOB, 500).unwrap();
        for (n, (group, commit)) in groups.iter().enumerate() {
            let copy = w.ledger.clone();
            let m = w.mirror.as_mut().unwrap();
            m.orch.tx(Request::Begin {
                id: tx(n as u64 + 1),
            });
            m.in_tx = true;
            // Only the orchestrator's own calls belong in its transaction: the clock waits.
            for c in group.iter().filter(|c| !matches!(c, Call::Tick(_))) {
                let _ = apply(&mut w, c);
            }
            let m = w.mirror.as_mut().unwrap();
            m.orch.tx(if *commit {
                Request::Commit
            } else {
                Request::Abort
            });
            m.in_tx = false;
            if !*commit {
                w.ledger = copy;
            }
            w.same_as_mirror(commit);
            check(&w, &Call::Settle(255))?;
        }
        ended.fetch_add(groups.len() as u64, Ordering::Relaxed);
        Ok(())
    });
    if let Err(e) = result {
        panic!("against the daemon: {e}");
    }
    let ended = ended.into_inner();
    println!(
        "TEST-P36 against the process: {} daemons started, {ended} transactions committed or aborted and compared",
        cases(16)
    );
}

/// TEST-P37 against the real process: a coordinator that holds the orchestrator's key and a
/// socket, driven by random traces, next to the coordinator of the model.
#[test]
fn p37_a_coordinator_drives_a_ledger_in_another_process() {
    let followed = AtomicU64::new(0);
    let result = runner().run(&prop::collection::vec(op_strategy(), 1..120), |ops| {
        let (mut sim, daemon) = process_sim(&Faults::default());
        for op in &ops {
            sim.run_op(op);
        }
        sim.drain();
        if !sim.violations.is_empty() {
            return Err(TestCaseError::fail(format!("{:#?}", sim.violations)));
        }
        let n = sim.shadow.as_ref().map_or(0, |s| s.followed);
        prop_assert!(n > 20);
        followed.fetch_add(n, Ordering::Relaxed);
        drop(daemon);
        Ok(())
    });
    if let Err(e) = result {
        panic!("against the daemon: {e}");
    }
    let followed = followed.into_inner();
    println!(
        "TEST-P37 against the process: {} daemons started, {followed} commands followed",
        cases(16)
    );
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
    dying.begin(tx(1)).unwrap().unwrap();
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
    // And the ledger is free for the next orchestrator, which can ask what happened.
    let mut next = connect(&daemon.socket, &w.orch, &verifier).unwrap();
    let (state, _) = next.tx_status(tx(1)).unwrap().unwrap();
    assert_eq!(state, TxState::RolledBack(Rollback::Disconnected));
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
        let out = finish(command(&dir, domain, &key_file));
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
    let out = finish(command(&dir, dom(), &junk));
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

fn reserve_op(n: u32) -> LedgerOp {
    LedgerOp::Reserve {
        job: JOB,
        bucket: EscrowBucket::Work,
        key: format!("late/{n}"),
        amount: 1,
    }
}

/// Third review of the isolation, timeouts, against the real process. Nobody but the owner
/// talks to the daemon: its own timer ends a transaction that outlived its deadline, whether
/// the owner went silent or keeps working, and the owner is told at its next request.
#[test]
fn r5_the_daemon_ends_a_transaction_past_its_deadline_by_itself() {
    let (mut w, daemon) = process_world_with(&["--tx-timeout-ms", "300"]);
    w.open(JOB, 500).unwrap();
    let verifier = w.auth.verifier();
    let dial = |me: &ServiceCredential| connect(&daemon.socket, me, &verifier).unwrap();
    let mut auditor = dial(&w.auditor);
    let mut asking = dial(&w.orch);
    let state = |c: &mut more_ledgerd::SocketClient| {
        (
            c.audit_balances().unwrap().unwrap(),
            c.audit_summary().unwrap().unwrap(),
        )
    };
    let before = state(&mut auditor);
    let expired = TxState::RolledBack(Rollback::Expired);
    let late = Err(LinkError::Refused(Refusal::TransactionExpired));

    // 1. Idle: one reserve, then silence, from everyone. Any request would make the daemon
    // look at its transactions; with none, only its timer can end this one. The timer says so
    // on standard error, which is read at the end.
    let mut owner = dial(&w.orch);
    owner.begin(tx(1)).unwrap().unwrap();
    owner.execute(reserve_op(1)).unwrap().unwrap();
    assert_eq!(asking.tx_status(tx(1)).unwrap().unwrap().0, TxState::Open);
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(asking.tx_status(tx(1)).unwrap().unwrap().0, expired);
    assert!(state(&mut auditor) == before, "rolled back");
    // The owner comes back and goes on with what it believes is its transaction.
    assert_eq!(owner.execute(reserve_op(2)), late);
    assert!(
        state(&mut auditor) == before,
        "the late reserve did not land alone"
    );
    assert_eq!(
        owner.commit(),
        Err(LinkError::Refused(Refusal::NoTransaction))
    );

    // 2. Active: the owner never stops, and no one else asks anything.
    owner.begin(tx(2)).unwrap().unwrap();
    let mut accepted = 0u32;
    let stopped = eventually(|| match owner.execute(reserve_op(100 + accepted)) {
        Ok(Ok(_)) => {
            accepted += 1;
            std::thread::sleep(Duration::from_millis(10));
            None
        }
        other => Some(other),
    });
    assert_eq!(stopped, Some(late.clone()));
    assert!(
        accepted > 1,
        "{accepted} reserves accepted before the deadline"
    );
    assert_eq!(asking.tx_status(tx(2)).unwrap().unwrap().0, expired);
    assert!(state(&mut auditor) == before);

    // 3. Nested: a savepoint late in the transaction does not buy time.
    let begun = Instant::now();
    owner.begin(tx(3)).unwrap().unwrap();
    std::thread::sleep(Duration::from_millis(200));
    owner.savepoint().unwrap().unwrap();
    owner.execute(reserve_op(3)).unwrap().unwrap();
    while begun.elapsed() < Duration::from_millis(450) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(asking.tx_status(tx(3)).unwrap().unwrap().0, expired);
    assert_eq!(
        owner.commit(),
        Err(LinkError::Refused(Refusal::TransactionExpired))
    );
    assert!(state(&mut auditor) == before);

    // The connection is as good as new, and a transaction within its time commits.
    owner.begin(tx(4)).unwrap().unwrap();
    owner.execute(reserve_op(4)).unwrap().unwrap();
    owner.commit().unwrap().unwrap();
    assert!(matches!(
        asking.tx_status(tx(4)).unwrap().unwrap().0,
        TxState::Committed { .. }
    ));
    assert!(state(&mut auditor) != before);
    let mut daemon = daemon;
    let said = daemon.stop();
    assert!(
        said.contains(more_ledgerd::SWEPT),
        "the timer ended nothing: {said}"
    );
}

/// Third review of the isolation, unknown outcomes, against the real process. The daemon
/// applies a commit and the answer never reaches the coordinator. The coordinator stops,
/// reconnects, asks, and takes the state that goes with the commit. Nothing is sent twice.
#[test]
fn r5_a_commit_applied_by_the_daemon_whose_answer_was_lost_is_found_again() {
    let faults = Faults::default();
    let (mut sim, daemon) = process_sim(&faults);
    let socket = daemon.socket.clone();
    let link = || {
        Flaky::new(
            StreamTransport(UnixStream::connect(&socket).unwrap()),
            &faults,
        )
    };
    let job = gpu_simulation::JOBS[0];
    let cmd = Cmd::Reserve { job };
    let ctx = sim.actor(&cmd);
    let cmd = sim.signed(&ctx, cmd);

    faults.at_outer_commit(Cut::After);
    let mut rig = sim.shadow.take().unwrap();
    assert_eq!(sim.exec(cmd.clone()), Ok(Outcome::Applied));
    let answer = rig.coord.execute(&ctx, &cmd);
    assert_eq!(answer, Err(DomainError::LedgerOutcomeUnknown));
    assert_eq!(answer.map_err(|e| e.code()), Err("LEDGER_OUTCOME_UNKNOWN"));
    let name = rig
        .coord
        .unknown_commit()
        .expect("stopped on a transaction");
    // Stopped: the same command again is refused before anything is sent.
    assert_eq!(
        rig.coord.execute(&ctx, &cmd),
        Err(DomainError::LedgerOutcomeUnknown)
    );
    rig.reconnect(link()).unwrap();
    // The daemon may still be reading the commit from the old connection.
    let state = eventually(|| match rig.coord.resolve_commit() {
        Ok(TxState::Open) => None,
        other => Some(other),
    });
    assert!(
        matches!(state, Some(Ok(TxState::Committed { .. }))),
        "{name:?}: {state:?}"
    );
    assert_eq!(rig.coord.unknown_commit(), None);
    // Same state on both sides, same journal in both ledgers: applied once.
    rig.check(&sim.coord, sim.ledger());
    sim.shadow = Some(rig);
    for op in [
        Cmd::Tick { dt: 3 },
        Cmd::Reserve { job },
        Cmd::Reserve {
            job: gpu_simulation::JOBS[1],
        },
        Cmd::Reconcile,
    ] {
        let _ = sim.exec(op);
    }
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);

    // The other way round: the commit never reaches the daemon.
    let mut rig = sim.shadow.take().unwrap();
    faults.at_outer_commit(Cut::Before);
    let cmd = Cmd::Cancel {
        job,
        expected_version: None,
    };
    let ctx = sim.actor(&cmd);
    let cmd = sim.signed(&ctx, cmd);
    assert_eq!(
        rig.coord.execute(&ctx, &cmd),
        Err(DomainError::LedgerOutcomeUnknown)
    );
    rig.reconnect(link()).unwrap();
    let state = eventually(|| match rig.coord.resolve_commit() {
        Ok(TxState::Open) => None,
        other => Some(other),
    });
    assert_eq!(state, Some(Ok(TxState::RolledBack(Rollback::Disconnected))));
    rig.check(&sim.coord, sim.ledger());
    // Sent again by its sender, the command is applied on both sides.
    sim.shadow = Some(rig);
    assert_eq!(sim.exec(cmd), Ok(Outcome::Applied));
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
}

/// The daemon keeps its ledger in memory. Killed and started again, it is another ledger: it
/// says so with a new incarnation number, and a coordinator that reconnects stops for good
/// instead of working against an empty ledger.
#[test]
fn r5_a_restarted_daemon_is_another_ledger_and_says_so() {
    let (mut sim, mut daemon) = process_sim(&Faults::default());
    let socket = daemon.socket.clone();
    let job = gpu_simulation::JOBS[0];
    assert_eq!(sim.exec(Cmd::Reserve { job }), Ok(Outcome::Applied));
    let verifier = sim.ids.verifier();
    let info = |socket: &Path| {
        connect(socket, &sim.ids.auditor, &verifier)
            .unwrap()
            .info()
            .unwrap()
    };
    let first = info(&socket);
    assert!(first.seq > 0);
    let said = daemon.stop();
    assert!(said.contains(more_ledgerd::WARNING), "{said}");
    assert!(
        said.contains(&format!("incarnation {:016x}", first.incarnation)),
        "{said}"
    );
    daemon.restart();
    let second = info(&socket);
    assert_ne!(second.incarnation, first.incarnation);
    assert_eq!((second.seq, second.now), (0, 0), "an empty ledger");

    let mut rig = sim.shadow.take().unwrap();
    let cmd = Cmd::Tick { dt: 1 };
    let ctx = sim.actor(&cmd);
    // The old connection died with the old process.
    let dead = rig.coord.execute(&ctx, &Cmd::Reserve { job });
    assert!(dead.is_err(), "{dead:?}");
    let link = StreamTransport(UnixStream::connect(&socket).unwrap());
    assert_eq!(rig.reconnect(link), Err(DomainError::LedgerStateLost));
    for _ in 0..2 {
        let answer = rig.coord.execute(&ctx, &cmd);
        assert_eq!(answer.map_err(|e| e.code()), Err("LEDGER_STATE_LOST"));
    }
    assert_eq!(info(&socket).seq, 0, "nothing was sent to the new ledger");
}

/// An answer that does not come in time kills the connection for good: when the daemon wakes
/// up, its late answer is never read as the answer to something else.
#[test]
fn r5_a_connection_that_timed_out_is_not_used_again() {
    let w = bare_world();
    let daemon = Daemon::start(&w.ledger_id, dom(), None);
    let verifier = w.auth.verifier();
    let wait = Duration::from_millis(200);
    let mut orch = connect_within(&daemon.socket, &w.orch, &verifier, wait).unwrap();
    let first = orch.info().unwrap();
    daemon.signal("STOP");
    let asked = Instant::now();
    // Asked from another thread: a client that waited for ever would hang the test instead of
    // failing it.
    let (tell, told) = std::sync::mpsc::channel();
    let asking = std::thread::spawn(move || {
        let answer = orch.info();
        let _ = tell.send(answer.clone());
        (orch, answer)
    });
    let answer = told.recv_timeout(Duration::from_secs(5));
    daemon.signal("CONT");
    assert!(matches!(answer, Ok(Err(LinkError::Io(_)))), "{answer:?}");
    assert!(asked.elapsed() >= wait);
    let (mut orch, _) = asking.join().unwrap();
    // The daemon now answers the request it had received. Nobody reads that answer.
    std::thread::sleep(Duration::from_millis(100));
    for _ in 0..3 {
        let asked = Instant::now();
        assert!(matches!(orch.tx_status(tx(1)), Err(LinkError::Io(_))));
        assert!(asked.elapsed() < wait, "refused without waiting");
    }
    assert!(matches!(orch.begin(tx(1)), Err(LinkError::Io(_))));
    let mut again = connect_within(&daemon.socket, &w.orch, &verifier, wait).unwrap();
    assert_eq!(again.info().unwrap().incarnation, first.incarnation);
    assert_eq!(
        again.tx_status(tx(1)).unwrap().unwrap().0,
        TxState::Unknown,
        "the dead connection sent nothing"
    );
}

/// A connection has a fixed time to authenticate, whatever it sends meanwhile. Once
/// authenticated it may stay silent.
#[test]
fn r5_a_connection_that_does_not_authenticate_in_time_is_closed() {
    let w = bare_world();
    let daemon = Daemon::start_with(
        &w.ledger_id,
        dom(),
        None,
        &["--handshake-timeout-ms", "300"],
    );
    let verifier = w.auth.verifier();
    let raw = || {
        let s = UnixStream::connect(&daemon.socket).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s
    };
    let mut buf = [0u8; 256];
    // Silent.
    let opened = Instant::now();
    let mut silent = raw();
    assert_eq!(silent.read(&mut buf).ok(), Some(0), "closed by the daemon");
    let took = opened.elapsed();
    assert!(took >= Duration::from_millis(300), "{took:?}");
    assert!(took < Duration::from_secs(3), "{took:?}");
    // A byte now and then: the frame announced never completes, the deadline does not move.
    let opened = Instant::now();
    let mut slow = raw();
    slow.write_all(&64u32.to_le_bytes()).unwrap();
    slow.set_nonblocking(true).unwrap();
    let closed = eventually(|| {
        let _ = slow.write_all(&[0]);
        std::thread::sleep(Duration::from_millis(50));
        matches!(slow.read(&mut buf), Ok(0)).then_some(())
    });
    assert!(
        closed.is_some(),
        "still open after five seconds of dripping"
    );
    assert!(opened.elapsed() < Duration::from_secs(3));
    // Half a handshake, then nothing.
    let mut half = raw();
    let hello = Message::Hello {
        version: gpu_ledger::link::LINK_VERSION,
        domain: dom(),
        cert: w.orch.certificate(),
        nonce: [7; 32],
    };
    let mut frames = StreamTransport(&mut half);
    frames.send(&hello.encode()).unwrap();
    let challenge = Message::decode(&frames.recv().unwrap());
    assert!(matches!(challenge, Ok(Message::Challenge { .. })));
    assert_eq!(half.read(&mut buf).ok(), Some(0), "closed by the daemon");
    // Authenticated, a service may wait far longer than that between two requests.
    let mut auditor = connect(&daemon.socket, &w.auditor, &verifier).unwrap();
    std::thread::sleep(Duration::from_millis(700));
    auditor.info().unwrap();
}

/// Who may connect: the users on the daemon's list, and no other, whatever the socket file
/// lets through. The file itself is opened to its owner, or to one group, never to everyone.
#[test]
fn r5_the_socket_admits_listed_users_only() {
    let w = bare_world();
    let verifier = w.auth.verifier();
    let mine = me();
    let other = (mine + 1).to_string();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    // By default the daemon's own user, and the socket is the owner's alone.
    let daemon = Daemon::start(&w.ledger_id, dom(), None);
    assert_eq!(mode(&daemon.socket), 0o600);
    connect(&daemon.socket, &w.orch, &verifier).unwrap();
    drop(daemon);
    // A list that does not name us: no connection, though the file would let us in and our
    // credential is good.
    let daemon = Daemon::start_with(&w.ledger_id, dom(), None, &["--allow-uid", &other]);
    assert!(matches!(
        connect(&daemon.socket, &w.orch, &verifier),
        Err(LinkError::Io(_))
    ));
    let mut s = UnixStream::connect(&daemon.socket).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 8];
    let closed = matches!(s.read(&mut buf), Ok(0) | Err(_));
    assert!(closed, "closed before anything is read or said");
    drop(daemon);
    // A list that names us among others.
    let us = mine.to_string();
    let listed = ["--allow-uid", other.as_str(), "--allow-uid", us.as_str()];
    let daemon = Daemon::start_with(&w.ledger_id, dom(), None, &listed);
    connect(&daemon.socket, &w.orch, &verifier).unwrap();
    drop(daemon);
    // Opened to a group: that group and the owner, never the rest.
    let group = std::fs::metadata("/proc/self").unwrap().gid();
    let options = ["--socket-group", &group.to_string(), "--allow-uid", &us];
    let daemon = Daemon::start_with(&w.ledger_id, dom(), None, &options);
    assert_eq!(mode(&daemon.socket), 0o660);
    assert_eq!(std::fs::metadata(&daemon.socket).unwrap().gid(), group);
    connect(&daemon.socket, &w.orch, &verifier).unwrap();
}

/// What the command line accepts, and who a list of users admits.
#[test]
fn r5_the_daemon_checks_its_own_options() {
    use more_ledgerd::{Access, Config};
    let args = |extra: &[&str]| -> Vec<String> {
        let d = to_hex(dom().as_bytes());
        let base = [
            "--socket",
            "/tmp/s",
            "--domain",
            d.as_str(),
            "--identity",
            "/tmp/i",
        ];
        base.iter().chain(extra).map(|a| a.to_string()).collect()
    };
    let plain = Config::from_args(&args(&[])).unwrap();
    assert_eq!((plain.allow.len(), plain.socket_group), (0, None));
    assert_eq!(plain.handshake_ms, more_ledgerd::HANDSHAKE_MS);
    let full = Config::from_args(&args(&[
        "--allow-uid",
        "1001",
        "--allow-uid",
        "1002",
        "--socket-group",
        "77",
        "--tx-timeout-ms",
        "250",
        "--handshake-timeout-ms",
        "900",
    ]))
    .unwrap();
    assert_eq!(full.allow, vec![1001, 1002]);
    assert_eq!(full.socket_group, Some(77));
    assert_eq!((full.limits.tx_timeout_ms, full.handshake_ms), (250, 900));
    for bad in [
        &["--tx-timeout-ms", "0"][..],
        &["--handshake-timeout-ms", "0"],
        &["--allow-uid", "root"],
        &["--allow-uid", "-1"],
        &["--socket-group", "wheel"],
        &["--socket", "/tmp/other"],
        &["--socket-group", "1", "--socket-group", "2"],
        &["--allow-everyone", "yes"],
        &["--allow-uid"],
    ] {
        assert!(Config::from_args(&args(bad)).is_err(), "{bad:?}");
    }
    assert!(Config::from_args(&args(&[])[2..]).is_err(), "no socket");
    // Nobody listed: the daemon's own user, and nobody else. Not even root.
    let own = Access::new(1000, &[]);
    assert!(own.admits(1000));
    assert!(!own.admits(0) && !own.admits(1001));
    // Users listed: exactly those. The daemon's own user is not implied, nor is root.
    let listed = Access::new(1000, &[1001, 1002]);
    assert!(listed.admits(1001) && listed.admits(1002));
    assert!(!listed.admits(1000) && !listed.admits(0) && !listed.admits(1003));
}

/// `more-ledger-ping` says whether a service gets an answer from the ledger.
#[test]
fn r5_ping_answers_for_a_service_and_for_no_one_else() {
    let w = bare_world();
    let daemon = Daemon::start(&w.ledger_id, dom(), None);
    let ping = |identity: &Path| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_more-ledger-ping"));
        c.arg("--socket")
            .arg(&daemon.socket)
            .arg("--domain")
            .arg(to_hex(dom().as_bytes()))
            .arg("--identity")
            .arg(identity)
            .args(["--timeout-ms", "3000"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        finish(c)
    };
    let good = daemon.dir.join("auditor.identity");
    write_identity(&good, &w.auditor).unwrap();
    let out = ping(&good);
    let said = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(out.status.code(), Some(0), "{said}");
    assert!(said.starts_with("ok incarnation="), "{said}");
    // A service of another deployment gets no connection.
    let foreign = daemon.dir.join("foreign.identity");
    let stranger = IdentityAuthority::new([4; 32]).issue(ServiceRole::Auditor);
    write_identity(&foreign, &stranger).unwrap();
    let out = ping(&foreign);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no connection"));
    // A key file others can read is not used.
    std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(ping(&good).status.code(), Some(1));
}

/// Users of the two-users test. None of them needs an entry in the system's user list.
const LEDGER_USER: u32 = 61001;
const ORCH_USER: u32 = 61002;
const THIRD_USER: u32 = 61003;
/// The group the ledger's sockets are opened to.
const LEDGER_GROUP: u32 = 61500;

struct Tree(PathBuf);

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Third review of the isolation, Unix users. The ledger runs under one user, the orchestrator
/// under another, and a third user stands by. The orchestrator's user reaches the ledger
/// through its socket and through nothing else: not its key file, not its memory. The third
/// user does not reach it at all, with or without the socket's group, with or without a valid
/// credential. Root is not on the list either.
///
/// As the orchestrator's user, the differential tests then run against these daemons.
#[test]
#[ignore = "needs root: it starts processes under three users (CI job `isolation`)"]
fn r5_two_users_the_orchestrator_reaches_the_ledger_through_its_socket_only() {
    assert_eq!(me(), 0, "this test changes user: start it as root");
    let base = Tree(PathBuf::from(format!(
        "/tmp/more-users-{}",
        std::process::id()
    )));
    let _ = std::fs::remove_dir_all(&base.0);
    let dir = |name: &str, user: u32, group: u32, mode: u32| {
        let d = base.0.join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::os::unix::fs::chown(&d, Some(user), Some(group)).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();
        d
    };
    std::fs::create_dir_all(&base.0).unwrap();
    std::fs::set_permissions(&base.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    // The binaries, where every user can run them.
    let bin = dir("bin", 0, 0, 0o755);
    let install = |from: &Path, name: &str| {
        let to = bin.join(name);
        std::fs::copy(from, &to).unwrap();
        std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o755)).unwrap();
        to
    };
    let ledgerd = install(
        Path::new(env!("CARGO_BIN_EXE_more-ledgerd")),
        "more-ledgerd",
    );
    let ping_bin = install(
        Path::new(env!("CARGO_BIN_EXE_more-ledger-ping")),
        "more-ledger-ping",
    );
    let tests = install(&std::env::current_exe().unwrap(), "tests");
    // The ledger's directory: its user, and the socket's group may pass through.
    let ledger_dir = dir("ledger", LEDGER_USER, LEDGER_GROUP, 0o750);
    let orch_dir = dir("orch", ORCH_USER, ORCH_USER, 0o700);
    let third_dir = dir("third", THIRD_USER, THIRD_USER, 0o700);
    let key_file = |d: &Path, name: &str, me: &ServiceCredential, user: u32| {
        let f = d.join(name);
        write_identity(&f, me).unwrap();
        std::os::unix::fs::chown(&f, Some(user), Some(user)).unwrap();
        f
    };
    // Two deployments, two daemons: the world of the hostile calls and the simulation's.
    let w = bare_world();
    let sim_ids = Sim::default().ids;
    let start = |name: &str, identity: &ServiceCredential, domain: Domain| {
        let key = key_file(
            &ledger_dir,
            &format!("{name}.identity"),
            identity,
            LEDGER_USER,
        );
        let mut c = Command::new(&ledgerd);
        c.arg("--socket")
            .arg(ledger_dir.join(format!("{name}.sock")))
            .arg("--domain")
            .arg(to_hex(domain.as_bytes()))
            .arg("--identity")
            .arg(key)
            .args(["--socket-group", &LEDGER_GROUP.to_string()])
            .args(["--allow-uid", &ORCH_USER.to_string()])
            .uid(LEDGER_USER)
            .gid(LEDGER_GROUP)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = c.spawn().unwrap();
        assert!(wait_until_listening(child.stdout.take().unwrap()));
        Killed(child)
    };
    let a = start("a", &w.ledger_id, dom());
    let b = start("b", &sim_ids.ledger, sim_ids.verifier().domain());
    let socket = ledger_dir.join("a.sock");
    let meta = std::fs::metadata(&socket).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o660);
    assert_eq!((meta.uid(), meta.gid()), (LEDGER_USER, LEDGER_GROUP));
    for pid in [a.0.id(), b.0.id()] {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let uid = status.lines().find(|l| l.starts_with("Uid:")).unwrap();
        let ledger = LEDGER_USER.to_string();
        assert!(uid.split_whitespace().skip(1).all(|u| u == ledger), "{uid}");
    }

    let orch_key = key_file(&orch_dir, "orchestrator.identity", &w.orch, ORCH_USER);
    // The bystander even holds a credential the ledger would accept.
    let third_key = key_file(&third_dir, "auditor.identity", &w.auditor, THIRD_USER);
    let ping = |user: u32, group: u32, identity: &Path| {
        let mut c = Command::new(&ping_bin);
        c.arg("--socket")
            .arg(&socket)
            .arg("--domain")
            .arg(to_hex(dom().as_bytes()))
            .arg("--identity")
            .arg(identity)
            .args(["--timeout-ms", "3000"])
            .uid(user)
            .gid(group)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = finish(c);
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code(), said)
    };
    // The orchestrator's user, in the socket's group, with its own key: answered.
    let (code, said) = ping(ORCH_USER, LEDGER_GROUP, &orch_key);
    assert_eq!(code, Some(0), "{said}");
    println!("orchestrator's user: {}", said.trim());
    // Without the group it does not get as far as the socket.
    let (code, said) = ping(ORCH_USER, ORCH_USER, &orch_key);
    assert_eq!(code, Some(1), "{said}");
    assert!(said.contains("ermission denied"), "{said}");
    // A third user: the file system stops it.
    let (code, said) = ping(THIRD_USER, THIRD_USER, &third_key);
    assert_eq!(code, Some(1), "{said}");
    assert!(said.contains("ermission denied"), "{said}");
    println!("third user: {}", said.trim());
    // A third user that got into the group: the file system lets it through, the daemon does
    // not, valid credential or not.
    let (code, said) = ping(THIRD_USER, LEDGER_GROUP, &third_key);
    assert_eq!(code, Some(1), "{said}");
    assert!(
        said.contains("no connection") && !said.contains("ermission"),
        "{said}"
    );
    println!("third user in the group: {}", said.trim());
    // Root passes every file permission, and is not on the list.
    assert!(matches!(
        connect(&socket, &w.auditor, &w.auth.verifier()),
        Err(LinkError::Io(_))
    ));
    // The ledger's key is not the orchestrator's to read.
    let (code, said) = ping(ORCH_USER, LEDGER_GROUP, &ledger_dir.join("a.identity"));
    assert_eq!(code, Some(1), "{said}");
    assert!(said.contains("ermission denied"), "{said}");

    // The rest runs as the orchestrator's user: this same test binary, started again.
    let mut child = Command::new(&tests);
    child
        .args(["--ignored", "--exact", "--nocapture", "--test-threads", "1"])
        .arg("helper_run_as_the_orchestrators_user")
        .env("MORE_TWO_USERS", &base.0)
        .env("MORE_LEDGER_PID", a.0.id().to_string())
        .current_dir(&orch_dir)
        .uid(ORCH_USER)
        .gid(LEDGER_GROUP)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = child.output().unwrap();
    let said = String::from_utf8_lossy(&out.stdout).to_string();
    let errors = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "{said}\n{errors}");
    let report = said
        .lines()
        .find_map(|l| l.find("two users:").map(|at| &l[at..]))
        .unwrap_or_else(|| panic!("no report from the orchestrator's user: {said}\n{errors}"));
    println!("{report}");
}

/// The part of the two-users test that runs as the orchestrator's user. Started by that test
/// only: on its own it does nothing.
#[test]
#[ignore = "run by the two-users test, under the orchestrator's user"]
fn helper_run_as_the_orchestrators_user() {
    use proptest::strategy::ValueTree;
    let Ok(base) = std::env::var("MORE_TWO_USERS") else {
        return;
    };
    assert_eq!(me(), ORCH_USER, "started under the wrong user");
    let ledger_dir = Path::new(&base).join("ledger");
    let pid = std::env::var("MORE_LEDGER_PID").unwrap();
    // What is the ledger's is out of reach from here: key file, memory, open files.
    let denied = Some(std::io::ErrorKind::PermissionDenied);
    let open = |p: PathBuf| {
        std::fs::File::open(p)
            .map(|_| ())
            .map_err(|e| e.kind())
            .err()
    };
    assert_eq!(open(ledger_dir.join("a.identity")), denied);
    assert_eq!(open(format!("/proc/{pid}/mem").into()), denied);
    assert_eq!(
        std::fs::read_dir(format!("/proc/{pid}/fd"))
            .map(|_| ())
            .map_err(|e| e.kind())
            .err(),
        denied
    );
    let can_write = std::fs::write(ledger_dir.join("planted"), b"x").is_ok();
    assert!(!can_write, "the ledger's directory is not ours to write");

    // TEST-P35: one long hostile trace against daemon `a`, mirrored in this process.
    let mut runner = TestRunner::deterministic();
    let calls = prop::collection::vec(calls(), 20_000)
        .new_tree(&mut runner)
        .unwrap()
        .current();
    let mut w = world_at(&ledger_dir.join("a.sock"));
    w.open(JOB, 500).unwrap();
    // TEST-P36 first, on the same daemon: transactions committed or aborted.
    let group = (prop::collection::vec(hostile::calls(), 1..8), any::<bool>());
    let groups = prop::collection::vec(group, 1_000)
        .new_tree(&mut runner)
        .unwrap()
        .current();
    for (n, (group, commit)) in groups.iter().enumerate() {
        let copy = w.ledger.clone();
        let m = w.mirror.as_mut().unwrap();
        m.orch.tx(Request::Begin {
            id: tx(n as u64 + 1),
        });
        m.in_tx = true;
        for c in group.iter().filter(|c| !matches!(c, Call::Tick(_))) {
            let _ = apply(&mut w, c);
        }
        let m = w.mirror.as_mut().unwrap();
        m.orch.tx(if *commit {
            Request::Commit
        } else {
            Request::Abort
        });
        m.in_tx = false;
        if !*commit {
            w.ledger = copy;
        }
        w.same_as_mirror(commit);
        check(&w, &Call::Settle(255)).unwrap();
    }
    for c in &calls {
        let _ = apply(&mut w, c);
        check(&w, c).unwrap();
    }
    // TEST-P37: a coordinator with the orchestrator's key drives daemon `b`.
    let socket = ledger_dir.join("b.sock");
    let ops = prop::collection::vec(op_strategy(), 8_000)
        .new_tree(&mut runner)
        .unwrap()
        .current();
    let mut sim = Sim::shadowed(|ids| {
        register_sim_keys(ids, &socket);
        RemoteRig::new(ids, || {
            StreamTransport(UnixStream::connect(&socket).unwrap())
        })
    });
    for op in &ops {
        sim.run_op(op);
    }
    sim.drain();
    assert!(sim.violations.is_empty(), "{:#?}", sim.violations);
    let followed = sim.shadow.as_ref().map_or(0, |s| s.followed);
    println!(
        "two users: ledger under user {LEDGER_USER}, this process under user {}: \
         {} transactions and {} hostile calls compared, {followed} commands followed",
        me(),
        groups.len(),
        calls.len()
    );
}
