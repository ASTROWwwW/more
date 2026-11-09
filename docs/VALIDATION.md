# Validation

How the changes of branch `hardening/security-architecture` were checked, with the real results. Environment: Linux, Rust 1.97.0, one machine, November 9, 2026. Baseline: `8e020bd`. Code validated: `752b864`.

## Commands and results

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | Clean, with the new workspace lints (no `unsafe`, `unwrap`, `expect`, `panic!` in production crates) |
| `cargo test --workspace` (test profile: overflow checks on, 512 traces per generator) | 100 tests passed, 0 failed |
| `cargo test --release --workspace` | 100 passed, 0 failed |
| `cargo clean && PROPTEST_CASES=5000 cargo test --release --workspace` | 97 passed, 0 failed, on `752b864` (before the three tests kept by name were added); 69 s including build, property tests 27.9 s |
| `python3 scripts/mutation.py` | {{MUTATION_SUMMARY}} |

Not run here: the CI workflow itself (it runs on the first push), and the build with the declared minimum Rust version 1.87 (only 1.97 is installed; the `msrv` CI job checks it).

### Tests, before and after

| Suite | Baseline | Now | Added |
| --- | --- | --- | --- |
| `more-identity` (unit) | — | 4 | credential forgery, other authority, revocation, signatures |
| `gpu-ledger` (unit) | 5 | 5 | |
| `gpu-ledger` (API, from outside the crate) | — | 9 | role matrix, forged and revoked credentials, issuance limits near `u64::MAX`, mandates, compromised scheduler and delivery service, atomic rollback, read scopes |
| `gpu-ledger` (doc test) | — | 1 | the generic transfer does not compile from outside the crate |
| `gpu-protocol` (unit) | 4 | 4 | signature coverage, replay policy, bounded retransmission window; three older tests now run on signed envelopes in `tests/security/`, under their original names |
| `tests/properties` | 5 | 5 | TEST-P29 and impersonation in every generator |
| `tests/scenarios` | 46 | 46 | JOB-F41 strengthened (M50) |
| `tests/regressions` | 7 | 8 | CE-07 |
| `tests/security` | — | 18 | the ten attacks of the audit, three simulated compromises, unsigned or altered messages, distinct lenders, and the three protocol tests kept by name |
| **Total** | **67** | **100** | |

No test was deleted. The two counterexample seeds found during this work are in `tests/properties/proptest-regressions.txt` (11 seeds in total).

### The ten required security cases

| # | Case | Test | Checked |
| --- | --- | --- | --- |
| 1 | Account A cancels account B's job | `borrower_cannot_cancel_another_borrowers_job` | `UNAUTHORIZED`, state unchanged |
| 2 | Account A confirms B's tokens | `borrower_cannot_ack_or_confirm_another_borrowers_tokens` | same |
| 3 | A lender passes itself off as the witness | `lender_cannot_act_as_witness` | `INADMISSIBLE_PROOF` as itself, `BAD_SIGNATURE` in the witness's name, `UNAUTHORIZED` for the witness's buffer |
| 4 | A lender renews another's lease | `only_lenders_of_the_attempt_renew_its_lease` | `UNAUTHORIZED` |
| 5 | Receipt commitment in another lender's name | `receipt_commitments_come_from_the_recipient_only` | producer and wrong recipient refused, wrong digest `INADMISSIBLE_PROOF`, right recipient accepted |
| 6 | Expired attempt still sending work | `expired_or_revoked_attempt_cannot_send_work` | `LEASE_EXPIRED`, then `STALE_ATTEMPT` |
| 7 | Price fraudulently set to zero | `the_client_never_sets_the_price` | no price field; tariff from the catalog; budget below cost refused; only admins set tariffs; no tariff in free pools |
| 8 | Non-member in a private pool | `non_member_cannot_use_a_private_pool` | `UNAUTHORIZED`; self-join refused in a private pool, allowed in an open one without the witness right |
| 9 | Amounts near `u64::MAX` | `extreme_values_are_refused_without_panic`, `issuance_limits_hold_near_u64_max` | `LIMIT_EXCEEDED`, `INVALID_INPUT`, `ARITHMETIC_OVERFLOW`; no panic in debug or release; balances unchanged |
| 10 | Refused answer, then retransmission with the same business key | `retransmission_gets_the_first_answer_and_runs_nothing` | same answer, nothing run twice; new number: domain idempotency (`AlreadyApplied`); same number, other content: `REPLAY` |

Every refusal test compares the whole coordinator state before and after.

### Coverage of the reference run

Written by the tests themselves in `target/coverage/` during the 5,000-trace run.

{{COVERAGE}}

Impersonation operations send a realistic command from a random account or service. 36,768 of them were refused as unauthorized; the ones that happened to come from the right sender were accepted, and TEST-P29 checked every accepted command against the independent oracle.

## Mutation campaign

62 mutants: the 52 of v2.5, 15 of them with anchors moved to the new code with the same bug, and 10 new ones on the trust boundaries (M51 to M60). The suite run for each mutant is now the whole workspace (unit, ledger API, security, properties at 300 traces, scenarios, regressions), not only the conformance tests.

{{MUTATIONS}}

### Defects found in the campaign script

- A mutant that does not compile used to be reported as "missed" (its test list was empty). Compile errors are now reported as such. Earlier campaigns were not inflated by this: a compile error could only lower their score.
- M57 did not compile as first written (type inference on an unused set); rewritten.
- M58 survived its first run: the security test checked all catalog bounds with one input that broke all of them, so removing one bound was invisible. The test now checks each bound separately; M58 is caught.

## Benchmark

Same machine, same command (`PROPTEST_CASES=5000 cargo test --release --workspace`), property tests only:

| | Commands checked | Time | Commands per second |
| --- | --- | --- | --- |
| Baseline `8e020bd` | 1,998,359 | 18.8 s | 106,000 |
| `752b864` | 2,293,620 | 27.9 s | 82,000 |

About 22 % slower per command: authorization before every command, a credential check (HMAC-SHA256) on every ledger operation, checked arithmetic and the extra checker work (TEST-P29). Each command also clones a slightly larger state. These figures describe the in-memory model and its checker, not a PostgreSQL coordinator.

## Limits of this validation

- Boundaries between trust domains are in-process (compiler, private types, checks on every call). Process, OS and database isolation are specified in `docs/SECURITY_ARCHITECTURE.md` but not built.
- Envelope signatures are real Ed25519; frame, receipt and ledger-chain digests are still FNV-1a. Delivery on a real network is not shown.
- The simulation authenticates accounts through the `test-support` feature; signatures themselves are tested at the protocol edge and in `tests/security/`.
- Properties are checked on finite random traces; they are not proven for all traces.
- A green test count is not the claim. The claims are the specific checks listed above, the mutants they catch, and the open issues of `docs/AUDIT_CODE.md`.
