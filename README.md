# More

More lets people share GPU power. When your card sits idle, you lend it to the network and earn credits. When you want to run a model too large for your machine, you spend those credits: the model is cut into layer slices, and each slice runs on a lender's GPU.

A coordinator keeps the accounts and organizes the run, but the computation flows directly between machines. Credits cannot be bought or transferred: you earn them by lending and spend them by borrowing, inside a pool. A pool can stay private, federate with other pools or open to the public, and anyone can host their own coordinator.

## What is in the repository

For now the repository holds the system specification and an executable Rust model of its rules. There is no network layer or GPU engine yet, and nothing here is ready to be deployed. The model checks, before the real coordinator is written, that the rules hold up against failures and cheating. An interrupted job has to resume without losing or re-billing a result that was already delivered. Each output is billed once, each lender contribution is paid at most once, and no credit is created or lost along the way.

The tests generate random command sequences: nodes going down, duplicated messages, clients that never acknowledge, lenders lying about delivery, expiring clocks. Invariants are checked after every command, and a mutation campaign puts known bugs back in to make sure the tests catch them. The generators also send every kind of command from every kind of participant, to check that nobody can act on what is not theirs. The ledger is also tested on its own against an orchestrator that turned hostile: it only pays on what lenders, recipients, borrowers and pool admins signed. It can run as a separate process, so that taking over the coordinator does not give access to the accounts; the same hostile tests then run against that process over its socket.

| Path | Purpose |
| --- | --- |
| `crates/identity` | Signatures, one key and certificate per service, authenticated caller context, signed statements |
| `crates/ledger` | Append-only double-entry ledger behind a typed, authenticated API; keeps the signed terms, leases and receipts it pays on. Its `link` module is the protocol other processes use to reach it |
| `crates/ledgerd` | `more-ledgerd`: the ledger as a process of its own, under its own user, behind a local socket. Experimental: its state is in memory only and a restart loses it, so it is not for real credits. `more-ledger-ping` checks that a service reaches it |
| `crates/domain` | Coordinator: authorization, jobs, attempts and per-node leases, pools and catalog, output delivery, settlement |
| `crates/protocol` | Signed messages, size checks, error codes, replay protection |
| `crates/simulation` | Invariant checker and random scenario generators |
| `tests/` | Property tests, failure and security scenarios, counterexamples found so far |
| `scripts/mutation.py` | Mutation campaign |
| `docs/specification.md` | Full specification |
| `docs/SECURITY_ARCHITECTURE.md` | Trust domains, permission matrix, what each boundary is made of |
| `docs/AUDIT_CODE.md`, `docs/VALIDATION.md` | The two code audits and how their fixes were checked |
| `TEST_REPORT.md` | Tests run and results for the v2.5 model |
| `STYLE_GUIDE.md`, `CONTRIBUTING.md` | Rules for every change |

## Running the tests

```sh
cargo test --release --workspace
PROPTEST_CASES=5000 cargo test --release --workspace   # more random traces
python3 scripts/mutation.py                            # several hours; --check only verifies the anchors,
                                                       # --shard=K/N splits the table over N machines
```

Requires Rust 1.88 or newer.

## License

AGPL-3.0.
