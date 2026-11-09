# Contributing

## Before you start

Read `docs/specification.md` (what the system must do), `docs/SECURITY_ARCHITECTURE.md` (who may do what) and `STYLE_GUIDE.md`. A change to the state machine, the accounting or the permissions starts with the spec or the permission matrix, then the code, then the tests.

## Workflow

1. Branch from `main`. Never push to `main` directly.
2. Keep each pull request to one subject.
3. Run the checks below locally.
4. Describe in the pull request what changed, why, which requirements are affected (`JOB-*`, `LEDGER-*`, `PROTO-*`, `TEST-*`), what you ran and what is still open.

## Commands

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                                   # debug: overflow checks on
cargo test --release --workspace                         # 512 traces per generator
PROPTEST_CASES=5000 cargo test --release --workspace     # reference run
python3 scripts/mutation.py                              # mutation campaign, about an hour
```

During a change, run a few mutations instead of the whole campaign:

```sh
python3 -c "import sys; sys.path.insert(0, 'scripts'); import mutation as m; \
m.MUTATIONS = [x for x in m.MUTATIONS if x[0] in {'M51', 'M52'}]; m.main()"
```

The script exits with an error if a mutation is not caught.

## Rules that are not negotiable

- Never weaken an invariant, an authorization rule or a test to make a change pass. If a rule is wrong, document the inconsistency, write the test that shows it, and fix the spec and the code together.
- Never delete a regression test or a seed without a written technical reason.
- Never reuse or renumber a requirement or property id.
- Never commit secrets, keys or build output.
- Never present a symbolic mechanism (FNV digests, in-process boundaries) as real security.

## CI

Every push and pull request runs format, lints, the minimum Rust version, debug tests and release tests. The heavy job (5,000 traces per generator and the mutation campaign) runs on demand from the Actions tab.
