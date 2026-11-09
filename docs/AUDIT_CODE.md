# Code audit

Audit of the executable model of More, branch `hardening/security-architecture`. Baseline: commit `8e020bd` on `main`, 67 tests passing (ledger 5, protocol 4, properties 5, scenarios 46, regressions 7), clippy clean, mutation campaign 51 of 52 then 52 of 52 (`TEST_REPORT.md`).

Each finding was reproduced on the baseline before any change. The reproduction file is `docs/audit/baseline_repro.rs` and its output, in debug and release builds, is `docs/audit/baseline_repro_output.txt`. Line numbers below refer to the baseline.

Severity scale: **critical** (credits or another user's job at the mercy of any account), **high** (a participant can bypass an economic rule or crash the coordinator), **medium** (a rule holds only by convention), **low** (robustness or hygiene).

## Summary

| ID | Finding | Severity | Status |
| --- | --- | --- | --- |
| SEC-001 | Commands translated without checking who sends them | Critical | Confirmed, fixed |
| SEC-002 | Client sets the price and the layout | Critical | Confirmed, fixed |
| SEC-003 | No pool membership or rights | High | Confirmed, fixed |
| SEC-004 | Receipt commitments made by anyone, including the producer itself | High | Confirmed, fixed |
| SEC-005 | Replay guard: no sessions, no answer for a retransmission | Medium | Confirmed, fixed |
| SEC-006 | Signatures not verified (any non-zero value accepted) | Critical | Confirmed, fixed for envelopes; frame and receipt digests remain symbolic (open) |
| SAFE-001 | Unchecked arithmetic on prices, time and counters | High | Confirmed, fixed |
| SAFE-002 | One lender may hold several ranges of an attempt | Medium | Confirmed, fixed |
| A-01 | Any holder of the coordinator can write any balance | Critical | Confirmed, fixed (ledger API) |
| A-02 | A refused reconciliation still checked by the post-reconciliation properties; reconciliation callable by the scheduler | Medium | Found by `proptest` (CE-07), fixed |
| A-03 | Digest recomputation is linear in the number of positions | Low | Open |
| A-04 | `test-support` feature could be enabled in a production build | Low | Open |
| A-05 | All trust domains run in one process | Medium | Open, by design of the model |
| A-06 to A-08, A-10 | See open issues below | Low to medium | Open |
| A-09 | Declared minimum Rust version wrong (1.75, while the code needed 1.87 and `proptest` 1.88) | Low | Fixed: 1.88, checked by CI |

## Findings

### SEC-001: commands translated without checking the sender

- **Where**: `crates/protocol/src/lib.rs`, `to_command` (l. 235 to 352). `Message::CancelJob` (l. 252), `ResumeJob`, `AssignAck`, `AssignReject`, `Produced`, `TokenAck`, `ReceiptCommit` (l. 118 and 299), `Heartbeat`, `ClientHeartbeat`, `DeliveryConfirm` ignore `env.sender`. `crates/domain/src/coordinator.rs` had no notion of a caller: `Coordinator::apply(&Command)`.
- **Cause**: the domain trusted the command's fields; the protocol layer only filled the actor fields of `Submit`, `Claim`, `Deliver` and `WitnessCommit`.
- **Preconditions**: any account able to send a message (the signature was not checked either, SEC-006).
- **Impact**: any account could cancel or pause another user's job, acknowledge its tokens (charging the borrower and validating positions), renew leases, report production for an attempt it does not belong to.
- **Reproduction**: `sec001_cancel_other_users_job` → `Ok(Applied), exec now Cancelled`; `sec001_ack_other_users_tokens` → `validated [0, 2, 0]`; `sec001_heartbeat_and_produce_by_anyone` → produce `Ok(Applied)`.
- **Fix**: `more-identity` builds an `AuthContext` only from a verified signature or a service credential. `Coordinator::execute(ctx, cmd)` calls `authorization::authorize` before cloning the state; the matrix (`docs/SECURITY_ARCHITECTURE.md`, section 3) checks the sender against the resource: borrower of the job, lender of the attempt, output node, recipient of a producer, assigned witness, pool admin, or service role. `to_command` fills every actor field from the authenticated sender (PROTO-009). New rule JOB-R36.
- **Tests**: `tests/security/` cases 1 to 4 and `compromise_gpu_agent_cannot_cancel_other_jobs`; property TEST-P29 with impersonation operations in every generator (each command sent by a random account or service; refusal counts in `docs/VALIDATION.md`); mutation M51.

### SEC-002: client-chosen price and layout

- **Where**: `coordinator.rs`, `submit` (l. 732 to 810): `price`, `layout` and `max_outputs` came from the request; free pools zeroed the price, credit pools accepted anything.
- **Cause**: no catalog, no tariff.
- **Preconditions**: any account submitting to a credit pool.
- **Impact**: a borrower could set the price to 0 and make lenders work for nothing, or set a layout that pays one stage almost everything.
- **Reproduction**: `sec002_zero_price_and_any_pool` → `Ok(Applied), est_cost 0`.
- **Fix**: `Registry` (Model Registry domain) holds, per pool, a catalog of models with their layers, tariff and output limits, set by the pool's admins and bounded (`MAX_PRICE`, `MAX_OUTPUTS`, `MAX_LAYERS`); a free-sharing pool cannot have a tariff. `Submit` names a model and the outputs wanted, plus the most the borrower agrees to lock, signed for the ledger (mandate). The scheduler chooses the layout in `Place`; it must cover the model's layers exactly. New rule JOB-R37. Free-sharing pools keep working (price 0, quota).
- **Tests**: `the_client_never_sets_the_price`, `extreme_values_are_refused_without_panic`, `f01_*`; mutation M58.

### SEC-003: no pool membership

- **Where**: `crates/domain/src/model.rs`, `Pool { id, mode }`; `submit` and `place` only checked that the pool exists.
- **Impact**: any existing id could borrow in any pool, lend or witness anywhere.
- **Reproduction**: `sec002_zero_price_and_any_pool`, account 55 in pool 7: `Ok(Applied)`.
- **Fix**: pools have an access mode (private or open), admins and per-account rights (borrow, lend, witness). `Submit` needs the borrow right; `Place` needs the lend right for every lender and the witness right for the witness. Open pools let an account join by itself with borrow and lend rights only. Rights are never implied by an account existing.
- **Tests**: `non_member_cannot_use_a_private_pool`; TEST-P29 (oracle checks the borrow right).

### SEC-004: receipt commitments

- **Where**: `coordinator.rs`, `commit_receipts` (l. 1779 to 1812) checked that the producer is in the attempt, not who commits. The protocol took `producer` from the message.
- **Impact**: a lender could commit its own receipts and get paid on "committed" evidence, which bypasses the anti-collusion cap (JOB-R19).
- **Reproduction**: `sec003_sec004_self_commit_bypasses_cap` → `Ok(Applied)`.
- **Fix**: only the recipient of the producer's output commits: the next stage's lender, or the witness for the output node (`Attempt::recipient_of`). The commitment carries a digest bound to job, stream, attempt, producer, type and covered positions (`receipt_digest`). Precedence rules of v2.5 are unchanged (`committed_before`). Slice binding stays through the log order (JOB-R12), not a field.
- **Tests**: `receipt_commitments_come_from_the_recipient_only`; mutation M55.
- **Limit**: the digest is FNV-1a over public data, like the frame digest. It binds the commitment to its context; it does not prove possession of the receipts. That needs the signed receipts themselves (network prototype).

### SEC-005: replay guard

- **Where**: `crates/protocol/src/lib.rs`, `ReplayGuard::admit` (l. 218 to 230): one counter per sender, consumed before the domain runs, no session.
- **Impact**: a sender that restarts can never talk again (`restarted sender (seq 1): Err(Replay)`); a response lost on the way back cannot be recovered under the same number. No security hole: the domain's business keys already made retries harmless.
- **Fix and policy**, documented in `crates/protocol/src/replay_guard.rs` and PROTO-005:
  - the guard runs after signature verification, so forged messages cannot burn numbers;
  - numbers are per sender and session, strictly increasing, consumed on admission whatever the domain answers;
  - an exact retransmission of one of the last 16 messages gets the stored answer and runs nothing; the same number with other content is a replay;
  - a higher session closes the older one;
  - out-of-order messages are refused (one ordered stream per sender);
  - business idempotency stays in the domain (job ids, cumulative acks, ledger keys), never on transport numbers.
- **Tests**: protocol unit tests `replay_policy`, `retransmission_window_is_bounded`; `retransmission_gets_the_first_answer_and_runs_nothing`; mutation M56.

### SEC-006: signatures

- **Where**: `ReplayGuard::admit` rejected only `signature == 0` (l. 222).
- **Impact**: anyone could send any message as anyone.
- **Reproduction**: `sec006_signature_is_not_checked` → `Ok(Applied)`.
- **Fix**: Ed25519 (`ed25519-dalek`) over a fixed binary encoding of the envelope (`Envelope::signing_bytes`, PROTO-003); keys registered in `KeyDirectory`; a key is never replaced silently. Service credentials are signed by `IdentityAuthority` (Ed25519 over id and role); the ledger and the coordinator hold only the authority's public key, so they can check a credential but not mint one, and they check the revocation list on every call. A first version used an HMAC, which would have given every verifier the minting secret; replaced before review. A `VerifiedAccount` can only come out of a successful verification.
- **Tests**: `unsigned_or_altered_messages_are_refused`, `lender_cannot_act_as_witness`, `revoked_service_credential_is_refused_by_the_coordinator`, identity unit tests; mutations M60, M61.
- **Still symbolic**: frame digests (JOB-R34), receipt digests and the ledger chain use FNV-1a. Delivery is not proven on a network. Nothing in this repository claims otherwise.

### SAFE-001: arithmetic

- **Where**: `submit` `est_cost` (l. 765), `Tick` (l. 457), window computation in `produce`, line counters (`+=`, `-=`), `release_reward` commission (l. 2487), pool relay counters.
- **Impact**: in debug builds a panic (the coordinator stops); in release builds silent wrapping. Observed: a price of `u64::MAX / 2` for 4 outputs wraps to `18446744073709551612`; `Tick { dt: u64::MAX }` moves the clock back to 1 in release, which breaks every deadline.
- **Fix**: bounded inputs (`MAX_TIME`, `MAX_DURATION` with `Config::validate`, `MAX_PRICE`, `MAX_OUTPUTS`, `MAX_LAYERS`; ledger `max_amount`, `max_issue`, `supply_cap`); `checked_*` everywhere a value can come from outside, `DomainError::Overflow` (`ARITHMETIC_OVERFLOW`); internal counters use checked subtraction that reports `Internal` instead of wrapping; commission computed in `u128` by the ledger. No `unwrap`, `expect` or `panic!` left in production crates, enforced by workspace lints.
- **Tests**: `extreme_values_are_refused_without_panic` in debug and release; `issuance_limits_hold_near_u64_max`; mutation M59.

### SAFE-002: billing and finalization

Reviewed invariants: single charge per output, single payment per contribution, contributions ≤ price, funded refunds and contests, no double release, recovery within budget, no orphan escrow, no involuntary pool funding, no negative amount. They were already properties (TEST-P03, P12, P13, P14, P15, P17) and stay so. One rule was not enforced:

- **Where**: `place` (l. 856 to 930) checked `lenders.len() == layout.len()`, not that lenders are distinct, although JOB-T04 says "one layer range per lender".
- **Impact**: one account on every stage could commit its own receipts (it is its own recipient) and collect every share.
- **Reproduction**: `safe002_duplicate_lenders` → `Ok(Applied)`.
- **Fix**: distinct lenders, rights checked, layout covering the model.
- **Tests**: `one_lender_holds_one_range`; mutation M57.

### A-01: any holder of the coordinator could write balances

- **Where**: `Coordinator.ledger` was a public field (l. 170) and `Ledger::transfer` public (`crates/ledger/src/lib.rs`, l. 160).
- **Impact**: any code holding the coordinator could move or mint credits.
- **Reproduction**: `ledger_is_writable_by_anyone_holding_the_coordinator` → user 99 credited 1,000,100.
- **Fix**: the journal's `transfer` is private to `gpu-ledger` (a `compile_fail` doc test proves it is unreachable from outside). The only entry point is `LedgerService::execute(credential, LedgerOp)`: typed operations with fixed account flows inside one job, its owner, its pool and its lenders; Treasury only for issuance; escrow opened only with the owner's Ed25519 mandate and capped by it; amount limits; atomic multi-entry operations with rollback; refusals logged. Reads are scoped (orchestrator: job accounts; full view: Auditor only). LEDGER-011, LEDGER-012.
- **Tests**: `crates/ledger/tests/service.rs` (9 tests, including `compromise_scheduler_cannot_move_arbitrary_balances` and `compromise_delivery_cannot_issue_or_move_credits`); mutations M52 to M54.

### A-02: reconciliation identity (CE-07)

Found by `proptest` once impersonation entered the generators (seed `59d2ec9c…` kept). A `Reconcile` sent by the auditor was correctly refused, but the checker still applied its post-reconciliation checks (TEST-P24, P27) to the unchanged state. Fixing the checker's scope was not enough: the scheduler was allowed to reconcile, and some due transitions (silent-client pause, default rulings, releases) are reserved to the reconciler, so a scheduler-run reconciliation would have skipped them. Now only the reconciler reconciles, and a refusal inside reconciliation is an internal error. Test `ce07_only_the_reconciler_reconciles`.

## Open issues

| ID | Issue | Severity | Next step |
| --- | --- | --- | --- |
| A-03 | `frame_digest` and `receipt_digest` recompute over all positions: up to `MAX_OUTPUTS` hash steps per message | Low | Store the chained digest incrementally, before the network prototype |
| A-04 | `more-identity`'s `test-support` feature builds an account context without a signature; the simulation needs it | Low | CI check that production binaries do not enable it |
| A-05 | All domains share one process; in-process boundaries stop bugs and API misuse, not an attacker who controls the process | Medium | Separate processes, per-service credentials over mTLS, per-service database roles (`docs/SECURITY_ARCHITECTURE.md`, sections 9 and 10) |
| A-06 | A compromised orchestrator can still pay lenders of its choice from a job's escrow, up to the borrower's mandate | Medium | Ledger checks lenders' signed lease acceptance |
| A-07 | Exposure is bounded per job and type (`K`), not per account or pool across jobs | Medium | Aggregated exposure cap before opening to the public |
| A-08 | Refused commands are not logged at the coordinator edge (the ledger logs its own refusals) | Low | Security log at the network edge |
| A-10 | `Coordinator::execute` clones the whole state per command, so cost grows with history | Low (model) | Not a concern for the model; the real coordinator uses database transactions |

## Rejected hypotheses

- **Lender attesting its own delivery** (SEC-001, "a lender passes itself off as a witness"): already refused at baseline. The attester was the envelope signer and had to be the assigned witness (`INADMISSIBLE_PROOF`). Kept and extended: a forged envelope in the witness's name now fails the signature check.
- **Expired attempt still producing** (security case 6): already refused at baseline (`LEASE_EXPIRED`, then `STALE_ATTEMPT`, JOB-R31). Kept as a regression test.
- **Double payment of a contribution or double release of a reward**: not reachable; held by TEST-P03, P12 and the ledger's idempotency keys, and confirmed again by the mutation campaign.
