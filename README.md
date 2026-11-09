# More

More lets people share GPU power. When your card sits idle, you lend it to the network and earn credits. When you want to run a model too large for your machine, you spend those credits: the model is cut into layer slices, and each slice runs on a lender's GPU.

A coordinator keeps the accounts and organizes the run, but the computation flows directly between machines. Credits cannot be bought or transferred: you earn them by lending and spend them by borrowing, inside a pool. A pool can stay private, federate with other pools or open to the public, and anyone can host their own coordinator.

## What is in the repository

For now the repository holds the system specification and an executable Rust model of its rules. There is no network layer or GPU engine yet. The model checks, before the real coordinator is written, that the rules hold up against failures and cheating. An interrupted job has to resume without losing or re-billing a result that was already delivered. Each output is billed once, each lender contribution is paid at most once, and no credit is created or lost along the way.

The tests generate random command sequences: nodes going down, duplicated messages, clients that never acknowledge, lenders lying about delivery, expiring clocks. Invariants are checked after every command, and a mutation campaign puts known bugs back in to make sure the tests catch them.

| Path | Purpose |
| --- | --- |
| `crates/ledger` | Append-only double-entry ledger |
| `crates/domain` | Coordinator: jobs, attempts, billing slices, output delivery, settlement |
| `crates/protocol` | Message contract: envelope, size check, error codes, anti-replay |
| `crates/simulation` | Invariant checker and random scenario generators |
| `tests/` | Property tests, failure scenarios and counterexamples found so far |
| `scripts/mutation.py` | Mutation campaign |
| `docs/specification.md` | Full specification |
| `TEST_REPORT.md` | Tests run and results |

## Running the tests

```sh
cargo test --release --workspace
PROPTEST_CASES=5000 cargo test --release --workspace   # more random traces
python3 scripts/mutation.py                            # about 30 min
```

Requires Rust 1.75 or newer.

## License

AGPL-3.0.
