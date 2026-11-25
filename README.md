# More

![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)
![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange)

Share GPU power. Lend your idle GPU and earn credits. Spend them to run models too big for your own machine.

## The idea

A large model does not fit on one consumer card. More cuts it into layer slices and runs each slice on a different lender's GPU. The lenders pass the intermediate results to each other directly, so the computation never goes through a central server.

A coordinator keeps the accounts and organizes each run. Credits cannot be bought or transferred: you earn them by lending and spend them by borrowing, inside a pool. A pool can stay private, federate with other pools, or open to the public. Anyone can host their own coordinator.

```
borrower ──job──▶ coordinator ──slices──▶ lender A ──▶ lender B ──▶ lender C
                      │                                                │
                   ledger                                  results go back to the borrower
```

## Status

Early stage. The repository holds the system specification and an executable Rust model of its rules. There is no network layer or GPU engine yet, and nothing here is ready to deploy. The next step is a network prototype over QUIC.

The model exists to check the rules before the real coordinator is written:

- An interrupted job resumes without losing or re-billing a result that was already delivered.
- Each output is billed once, and each lender contribution is paid at most once.
- No credit is created or lost along the way.
- Nobody can act on what is not theirs.

The ledger can also run as a separate process, so that taking over the coordinator does not give access to the accounts. That process keeps its state in memory only, so it is not for real credits yet.

## How it is tested

The tests generate random sequences of commands: nodes going down, duplicated messages, clients that never acknowledge, lenders lying about delivery, expiring clocks. The invariants are checked after every command. A mutation campaign puts known bugs back in to make sure the tests catch them. The ledger is also tested against an orchestrator that turned hostile: it only pays on what lenders, recipients, borrowers and pool admins signed. The same hostile tests run against the separate ledger process over its socket.

`TEST_REPORT.md` lists the runs and their results.

## Repository

| Path | Purpose |
| --- | --- |
| `crates/identity` | Signatures, one key and certificate per service, authenticated caller context |
| `crates/ledger` | Append-only double-entry ledger behind a typed, authenticated API |
| `crates/ledgerd` | `more-ledgerd`: the ledger as a process of its own, behind a local socket |
| `crates/domain` | Coordinator: authorization, jobs, attempts, leases, pools, delivery, settlement |
| `crates/protocol` | Signed messages, size checks, error codes, replay protection |
| `crates/simulation` | Invariant checker and random scenario generators |
| `tests/` | Property tests, failure and security scenarios, regressions |
| `scripts/mutation.py` | Mutation campaign |
| `docs/specification.md` | Full specification |
| `docs/SECURITY_ARCHITECTURE.md` | Trust domains and permission matrix |
| `docs/AUDIT_CODE.md`, `docs/VALIDATION.md` | The code audits and how their fixes were checked |
| `STYLE_GUIDE.md`, `CONTRIBUTING.md` | Rules for every change |

## Run the tests

```sh
cargo test --release --workspace
PROPTEST_CASES=5000 cargo test --release --workspace   # more random traces
python3 scripts/mutation.py                            # several hours; --check only verifies the anchors,
                                                       # --shard=K/N splits the table over N machines
```

Requires Rust 1.88 or newer.

## Feedback

Comments on the design are welcome. Open an issue, and read `CONTRIBUTING.md` before sending a change.

## License

AGPL-3.0.
