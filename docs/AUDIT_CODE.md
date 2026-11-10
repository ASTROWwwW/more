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
| A-06 | A compromised orchestrator can still pay lenders of its choice from a job's escrow, up to the borrower's mandate | Medium | Closed by R2-03 (part 2): signed leases and recipients' receipts checked by the Ledger. What remains is R2-09 and R2-10 |
| A-07 | Exposure is bounded per job and type (`K`), not per account or pool across jobs | Medium | Aggregated exposure cap before opening to the public |
| A-08 | Refused commands are not logged at the coordinator edge (the ledger logs its own refusals) | Low | Security log at the network edge |
| A-10 | `Coordinator::execute` clones the whole state per command, so cost grows with history | Low (model) | Not a concern for the model; the real coordinator uses database transactions |

## Rejected hypotheses

- **Lender attesting its own delivery** (SEC-001, "a lender passes itself off as a witness"): already refused at baseline. The attester was the envelope signer and had to be the assigned witness (`INADMISSIBLE_PROOF`). Kept and extended: a forged envelope in the witness's name now fails the signature check.
- **Expired attempt still producing** (security case 6): already refused at baseline (`LEASE_EXPIRED`, then `STALE_ATTEMPT`, JOB-R31). Kept as a regression test.
- **Double payment of a contribution or double release of a reward**: not reachable; held by TEST-P03, P12 and the ledger's idempotency keys, and confirmed again by the mutation campaign.

# Part 2: second audit (November 10, 2026)

An external review of `main` at `e398159` reported six problems. Each was checked against the code and, where it is a code defect, reproduced on `e398159` before any change: `docs/audit/round2_repro.rs`, output in `docs/audit/round2_repro_output.txt`. Fixes are on branch `hardening/ledger-authority`.

The review's common thread is right: after part 1, the Ledger checked who called and which accounts an operation touched, but still believed the orchestrator about who had worked, what a share was worth and where a refund should go. A service that is allowed to call can chain allowed calls into a forbidden result.

## Summary

| ID | Finding | Reported as | Verdict | Status |
| --- | --- | --- | --- | --- |
| R2-01 | A reserve taken from the recovery budget can be refunded to the output hold, which settlement returns to the borrower | Critical | Confirmed | Fixed |
| R2-01b | `SettleJob` took the pool's share from the caller: `pool_unspent = 0` sends the whole relay to the borrower | Not reported | Found while reproducing R2-01; shorter path to the same loss | Fixed |
| R2-02 | `SettleJob` accepted with an open line; a later refund then strands credits in the output hold of a closed job | Critical | Confirmed | Fixed |
| R2-03 | The Ledger pays whichever account the orchestrator names as lender | Critical | Confirmed (an account that was never in any attempt was paid 90 of 100 credits) | Fixed for the stated threat; two collusion cases remain (R2-09, R2-10) |
| R2-04 | One `AttemptReady` from any lender starts the whole cluster | High | Confirmed | Fixed |
| R2-05 | One lease expiry per attempt: a live lender's heartbeat keeps silent lenders alive | High | Confirmed (two lenders silent for three lease lifetimes, job still `running`) | Fixed |
| R2-06 | Ledger, coordinator and the other domains share one process | Architecture | Correct, and already stated in `SECURITY_ARCHITECTURE.md` section 7 | Not done in this branch; plan in section 11 |
| R2-07 | The orchestrator could relay any amount of a pool's treasury into a job | Not reported | Found by TEST-P30 while testing R2-01 | Fixed |
| R2-08 | Uncommitted receipts were a label on the claim: nothing checked that the recipient had signed anything | Not reported | Found while designing R2-03 | Fixed |
| R2-09 | Recovery can be paid to a colluding lender of a started attempt, within the agreed budget | Not reported | Found by TEST-P30 | Fixed by decision (JOB-R18): the recipient must corroborate the restoration |
| R2-10 | Orchestrator colluding with every recipient of a stage | Not reported | By construction of receipts and corroborations | **Open**, bounded by contests and JOB-R19 |
| R2-12 | Reconciliation skipped, without a word, a transition the ledger failed to write (CE-08) | Not reported | Found by the fault-and-restart test asked before the merge | Fixed |

The review's table also lists "symbolic frame proofs": unchanged, already open as SEC-006, due with the QUIC prototype.

## Findings

### R2-01, R2-01b: provenance of reserves and the pool's share

- **Where** (at `e398159`): `crates/ledger/src/service.rs`, `ReserveLine { source }` l. 543, `RefundLine { to }` l. 575, `SettleJob { pool_unspent }` l. 655.
- **Reproduction**: `finding1_pool_credits_reach_the_owner` (pool 1,000 → 950, owner 1,000 → 1,050) and `finding1b_settle_with_a_chosen_pool_share` (same result with one call).
- **Fix** (LEDGER-013): a line item is named by what it pays for, and the Ledger records it. `RefundLine` has no destination: a contribution goes back to the output hold, recovery to the recovery escrow. The Ledger tracks what the owner and the pool each put into recovery, splits each recovery payment itself (owner first), and computes the pool's share at contest and at settlement. The coordinator still computes the same figures for its own state; any difference is an internal error.
- **Tests**: `r2_recovery_reserve_goes_back_where_it_came_from`, `r2_settlement_computes_the_pool_share`, `r2_recovery_split_and_contest_follow_the_ledgers_records`; TEST-P30 (the owner never ends with more than it had); mutations M12, M63, M75.

### R2-02: closure

- **Where**: `SettleJob`, l. 655 to 688: only `settled` was checked. `PayLine` and `RefundLine` used `escrow()`, not `live_escrow()`.
- **Reproduction**: `finding2_settle_with_an_open_line_then_orphan_funds`: settlement accepted with 40 credits in a line, refund accepted afterwards, second settlement refused, 40 credits left in `OutputHold` of a closed job.
- **Fix** (LEDGER-014): the Ledger refuses to settle while any item is reserved, and every operation that writes to the job's escrow, hold or lines requires a job that is not settled. Held rewards can still be released or contested after settlement; they end in a user, pool or commission account.
- **Tests**: `r2_settlement_waits_for_every_item_and_is_final`; TEST-P30 (settled ⇒ escrow, hold and lines at zero, after every later call); mutations M64, M65.

### R2-03: payments bound to signed assignments and receipts

- **Where**: `ReserveLine`, `PayLine`, `ReleaseReward` took the lender from the request.
- **Reproduction**: `finding3_pay_an_account_that_never_worked`: account 66, in no attempt, receives 90 credits.
- **Fix** (LEDGER-015, LEDGER-016, JOB-R37):
  - The borrower's mandate now covers the job's terms (model, layers, prices, outputs, budget). Shares are computed by the Ledger from them.
  - Placement registers the attempt at the Ledger. Each lender signs the assignment (cluster, layout, witness, earmark); the Ledger verifies it. A line is reserved only for the lender that signed the stage it claims, on an output charged to that attempt.
  - A contribution is paid only if the Ledger holds a receipt covering the output, signed by the stage's recipient as the assignment names it (next stage, or the witness).
  - Recovery is reserved only once every lender of the attempt signed ready (JOB-R18's own rule), within the attempt's earmark, and earmarks stay within the budget.
  - Charges carry the output and its billing generation; the price comes from the signed terms.
- **What this achieves**: an orchestrator acting alone cannot credit an account of its choice. It needs the signature of the lender, and of an honest third party for contributions.
- **Tests**: `r2_only_a_lender_that_signed_its_lease_gets_a_line`, `r2_no_payment_without_the_recipients_receipt`, `r2_recovery_needs_readiness_and_stays_within_the_earmark`, `r2_attempts_are_checked_against_the_signed_terms`, `r2_charges_and_voids_follow_the_ledgers_records`; TEST-P30; mutations M66 to M73, M76, M85.

### R2-04: per-node readiness

- **Where**: `crates/domain/src/coordinator/placement.rs`, `attempt_ready`, l. 128 to 173: `a.ready = true` on the first call. Authorization only required "a lender of the attempt".
- **Reproduction**: `finding4_one_lender_starts_the_cluster`.
- **Fix** (JOB-R38): one lease per stage, `assigned → accepted → loaded → ready`. `AcceptLease` carries the lender's signature over the assignment, `LeaseLoaded` the configuration digest of its stage, `AttemptReady` its signature over the restored positions. Each command names its lender, who must be the sender. The attempt starts on the last ready lease.
- **Tests**: `r2_one_ready_lender_does_not_start_the_cluster`, `r2_lease_steps_are_ordered_personal_and_signed`; TEST-P31; mutations M77 to M79, M83.

### R2-05: per-node leases

- **Where**: `Attempt.lease_expires_at` (`model.rs` l. 102), renewed by any lender in `heartbeat` (`placement.rs` l. 193).
- **Reproduction**: `finding5_one_heartbeat_keeps_every_lease`.
- **Fix** (JOB-R39): each lease has its own expiry; the witness has its own lease and its own `WitnessHeartbeat`. A heartbeat renews the sender's lease. Any expired lease stops the attempt at once and reconciliation revokes it, recording the silent nodes (`LeasesExpired`).
- **Tests**: `r2_a_heartbeat_renews_only_its_own_lease`, `r2_the_witness_lease_is_its_own`; TEST-P24 (per node), TEST-P31; mutations M25 to M27, M80 to M82.

### R2-06: one process

Correct, and not fixed here. The order of priorities in the review puts it after the financial boundaries and before the QUIC prototype; `SECURITY_ARCHITECTURE.md` section 11 lists the steps and what the first one (the Ledger in its own process) needs. What this branch contributes: the Ledger's safety no longer depends on the coordinator being honest, which is the property a separate process is supposed to protect. TEST-P30 calls the Ledger's public API directly, as a hostile caller would over a socket.

### R2-07: pool relay without the pool's consent

Found by TEST-P30: `FundRecovery` only needed the Orchestrator credential, so a compromised orchestrator could move a pool's whole treasury into the recovery escrow of a job, then try to pay it out. Fix (LEDGER-017): the platform admin registers each pool's admin at the Ledger with its own credential; a relay carries that admin's signature over the new running total for the job. Tests: `r2_pool_relay_needs_the_admins_consent`, `r2_pool_relay_needs_its_admins_signature`; mutations M74, M86.

### R2-09: recovery on the lender's word (decision of November 10, 2026)

TEST-P30 showed that an orchestrator and one lender account could collect recovery: the lender signs ready, the honest lenders of the cluster sign ready for themselves, and JOB-R18 took the start of the attempt as proof. The decision: keep the three steps apart.

- **Reservation.** The earmark is registered with the attempt, at the Ledger, before any work; a claim is reserved within it on a started attempt.
- **Execution.** The lender signs its restored positions. The account that receives its output signs that it received that restored state (`CorroborateRestore`, `restore_message`). The producer cannot send it for itself (authorization), and a corroboration signed by anyone else is refused by the Ledger. No new output is required.
- **Settlement.** The Ledger pays a recovery item only if the corroboration is on file. Without it, the coordinator waits until the evaluation deadline, then holds the amount as disputed; a ruling cannot pay it (`INADMISSIBLE_PROOF`) unless the corroboration arrived; the default ruling refunds it.

What it guarantees and what it does not is written in JOB-R18 and in `SECURITY_ARCHITECTURE.md` section 5: a third account must sign; a colluding recipient still can (R2-10).

Tests: `r2_recovery_is_settled_only_on_a_corroborated_restoration` (ledger), `r2_an_accomplice_cannot_collect_recovery_without_corroboration`, `r2_an_honest_restoration_is_paid_even_if_no_output_follows`, `r2_a_late_corroboration_lets_a_ruling_pay`; TEST-P30 again asserts that the attacker's account never receives a credit; TEST-P32; mutations M72, M88 to M93.

### R2-12: reconciliation and ledger failures (CE-08)

The test "a fault in the middle of a settlement, then a restart and a reconciliation" injects a journal failure after N entries (`fault-injection` feature, tests only). The command that hit the fault was rolled back correctly. Reconciliation was not: it propagated internal and authorization errors of the transitions it runs, but dropped ledger errors, so a due evaluation whose payment failed was skipped and the reconciliation reported success. Fix: a ledger error inside reconciliation is reported as internal and the whole reconciliation rolled back (JOB-R20). Tests: `ce08_reconciliation_reports_a_ledger_failure`, `r2_a_fault_during_a_partial_settlement_then_restart_and_reconciliation`; mutation M87.

### R2-08: uncommitted receipts were not checked

`Evidence::Uncommitted` meant "I hold a receipt countersigned by the recipient", and nothing looked at it. With the Ledger now requiring a receipt to pay, the claim must be backed: the producer presents the receipt (`PresentReceipt`), the Ledger verifies the recipient's signature, and an uncommitted item with no receipt on file at the evaluation deadline is refunded as unproven (JOB-R12, JOB-R35). The fairness property TEST-P23 was narrowed accordingly: an uncommitted item may be refunded by arbitration or for want of a receipt, and a step check verifies the receipt was really missing. Test: `r2_an_uncommitted_claim_needs_the_recipients_receipt`; mutation M84.

## Still open after part 2

| ID | Issue | Bound today | What would close it |
| --- | --- | --- | --- |
| R2-10 | Orchestrator plus every recipient of a stage (next lender, or the witness for the last stage): receipts and corroborations are attestations between two accounts, not proofs of computation | What was charged to the borrower and the recovery earmark; contest windows; JOB-R19 for uncommitted receipts | Verification of the work itself; witness assignment the orchestrator cannot choose alone |
| A-04 (extended) | Two test-only features now exist: `more-identity/test-support` and `gpu-ledger/fault-injection` (forwarded by `gpu-domain`). Only the conformance tests enable them | A production build that enabled one would accept unsigned accounts or injected faults | CI check on the features of release binaries, once there is a binary |
| R2-11 | The Ledger does not check the delivery proof behind a charge | An unproven charge pays nobody without receipts and returns at settlement | Witness attestation or client ack verified by the Ledger; contest filed with the Ledger |
| R2-06 | One process | — | `SECURITY_ARCHITECTURE.md` section 11 |
| SEC-006 | Frame and receipt digests are symbolic (FNV-1a) | — | QUIC prototype |

## Claims checked and qualified

- "The Ledger does not keep enough information" (R2-01): exact. It kept the escrow's owner, pool and budget, nothing about lines.
- "Tests exercise the intended paths, not a hostile orchestrator" (review, section on tests): exact for the Ledger. Part 1 had two compromise tests that tried single forbidden calls; none chained allowed calls. TEST-P30 does, and found R2-07 and R2-09 on its first deep runs.
- The 101 tests and 64 mutants of part 1 were not contradicted by this review, and did not cover these sequences.

## Tests asked before the merge

| Asked | Test | What it shows |
| --- | --- | --- |
| Compromised orchestrator and colluding lender share the recovery budget with no verifiable progress | `r2_recovery_is_settled_only_on_a_corroborated_restoration` (Ledger API), `r2_an_accomplice_cannot_collect_recovery_without_corroboration` (coordinator), TEST-P30 | Reserved, never paid; self-corroboration and corroboration by the wrong account refused; held at the deadline; a pay ruling refused; refunded by the default ruling; accomplice's balance 0 |
| A node falls after an honest restoration, before any new output | `r2_an_honest_restoration_is_paid_even_if_no_output_follows` | Corroborated restoration paid in full although attempt 2 produced nothing |
| A lease stays ready while another node of the cluster expires | `r2_a_ready_lease_does_not_outlive_another_nodes_expiry` (while placing), `r2_a_heartbeat_renews_only_its_own_lease` (while running) | The ready lease is valid and changes nothing: placement fails or the attempt is revoked, the silent nodes are named, nothing is paid |
| A valid receipt replayed for a second payment | `r2_a_replayed_receipt_never_pays_twice` (Ledger API), `r2_a_replayed_receipt_pays_once` (coordinator) | Second presentation is a no-op; the item is unique per output, charge and stage; the signature does not verify on another attempt or job |
| A fault during a partial settlement, then restart and reconciliation | `r2_a_fault_during_a_partial_settlement_then_restart_and_reconciliation`, `ce08_reconciliation_reports_a_ledger_failure`, `failed_multi_entry_operation_writes_nothing` | State identical before and after each failed transition; reconciliation reports the fault; after the restart it completes; final balances equal those of a run without fault. Found CE-08 |

## Test changes that need a justification

- `failed_multi_entry_operation_writes_nothing` moved from `crates/ledger/tests/service.rs` to a unit test inside the crate (`service/mod.rs`). It forced a key collision through caller-chosen keys; keys are now derived by the Ledger, so the collision can only be planted from inside. Same property, same name.
- Regression lists that contained one `AttemptReady` for the cluster now expand it into every lender's three steps (`start_cluster`); `Uncommitted` claims in scenarios JOB-F17 and JOB-F40 are preceded by the receipt they rely on. No assertion was changed.
- The coverage thresholds of `generator_reaches_interesting_paths` are unchanged. Its traces went from 150 to 180 operations, because starting a cluster now takes three steps per lender and a corroboration per stage, and three generator weights were raised. Four thresholds were added (attempts revoked for an expired lease, for one silent node, restorations corroborated, recovery held).
- Scenario and regression harnesses now have each stage's recipient corroborate the restoration when a cluster starts (a healthy cluster); `r2_recovery_split_and_contest…` and `r2_recovery_needs_readiness…` do it explicitly. No assertion on amounts was changed.

