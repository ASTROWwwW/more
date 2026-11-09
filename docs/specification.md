# More — Implementation specification v2.5

November 9, 2026 · @Astrxw

This specification describes **how** the system works, based on the decisions of the architecture document v1.1. It starts with the job state machine, from which the protocol, the accounting and the orchestration follow. Every requirement has a stable identifier linked to at least one test.

**Acceptance criterion**: no sequence of failures, retries, cancellations or disconnections may produce a double payment for the same output or the same contribution, a negative balance, a resume on the wrong attempt, a silent loss of validated positions, an escrow that is never settled, or a transfer of credits from one payer to another (borrower, pool). Since v2.4, also: no billing without admissible proof of delivery, no delivered position regenerated, each party's exposure bounded by the flow budget, and no honest, proven and funded contribution left unpaid without an explicit decision. Since v2.5: no contested output made definitive without a signed client ack covering it, no proof reusable in another stream, and no replay buffer released while a contest may still need it.

**Status of v2.5**: checked against the executable model More 0.3.0 (Rust, `proptest`). Last documentation iteration before the network prototype of the witness (QUIC), unless the tests reveal a critical inconsistency. Sections 2, 3 and 4 are implemented in the `gpu-domain` crate and covered by the tests of section 9. Sections 5 to 8 are still to be completed. Any significant change to the state machine or the accounting MUST come with a model test showing that it preserves the invariants. The delivery protocol (section 2.4) went through the model before entering this specification; its guarantees still have to be confirmed on real network exchanges.

## Changelog v2.4 → v2.5

### Decisions taken after the v2.4 audit

| Point | Decision | Requirements | Tests |
| --- | --- | --- | --- |
| Witness trust | Witnesses have their own reputation from the MVP on; selection by phase (pool, then operators recognized by both pools, then public with exposure limits and random checks); bond postponed | JOB-R26 | — (outside the model) |
| Delivery window | 24 h to contest (instead of 10 min); buffer kept at least 24 h **and** until open contests are resolved; rewards held 48 h | JOB-R28, R29 | TEST-P26, JOB-F39 |
| Closing a contest | **Only a signed cumulative application ack, bound to the stream and covering the position**, makes it definitive. A replay, an attested replay or a plain liveness signal is not enough. No ack by the deadline: refund | JOB-R33 | TEST-P27, JOB-F33, F34 |
| Cryptographic binding | Chained digest signed by the output node covering job, client stream, model, type, position and billing generation; a substituted frame or one from another session is rejected | JOB-R34 | TEST-P20, JOB-F35, F36 |
| Late attestations | New deliveries rejected after revocation; a full attestation is admissible while draining **if** a short witness commitment was recorded before the revocation | JOB-R32 | TEST-P20, JOB-F37, F38 |
| Contributions without proof | Supplementary proof allowed until the evaluation deadline; refund final only at the deadline; after closure, no change (a correction is a new funded entry) | JOB-R35, JOB-S04 | TEST-P28, JOB-F41 |
| Anti-collusion cap | 24 h sliding window on the **gross amounts** admitted; a refund does not restore the quota | JOB-R19 | TEST-P08, JOB-F40 |

### Found during implementation

| Ref. | How | Problem | Fix |
| --- | --- | --- | --- |
| CE-06 | `proptest` counterexample (TEST-P12), general and partial-reserve generators, on the first run | A slice finished its evaluation before the deadline while a contribution was waiting for its output to be delivered. Once the output became definitive, the contribution without proof went back to "awaiting proof" (JOB-R35) in a slice already evaluated: a final slice with a pending amount | JOB-S04: before the deadline, evaluation does not finish while a contribution is waiting for its output. Test `ce06_*` |
| I-17 | JOB-F39 | Window expiry cannot make definitive the positions that **follow** a contested position: they depend on it, and a refund of the contested position will void them | JOB-R29: expiry stops at the first contested or not-yet-due position |
| I-18 | JOB-R33 | v2.4 made an output definitive as soon as it was replayed, before any proof of receipt (raised by the audit) | JOB-R33; `ChargeBasis::Replayed` removed from the model |
| I-19 | JOB-R14 with JOB-R35 | "Single evaluation" can no longer mean "in one command": proven payments are immediate, refunds for missing proof wait for the deadline | JOB-R14 reworded: each item is decided once, and the slice finishes once |
| I-20 | Buffer cost | For a few tokens, retention is negligible; for large outputs or thousands of sessions it will have to be measured | Decided after v2.5 (section 10) |

## Changelog v2.3 → v2.4

### Decision I-03: proven delivery and replay

v2.3 made the client ack mandatory for billing: a borrower could receive an answer and then always refuse to confirm. v2.4 adopts the variant with proof of delivery and replay, with three situations.

| Situation | Behavior | Rules |
| --- | --- | --- |
| Token received and acked by the client | Definitive billing of the output | JOB-R23 |
| Token delivered with a witness attestation, ack lost | Provisional billing, token kept for replay; definitive on client confirmation, on replay or when the delivery window expires | JOB-R26 to JOB-R30 |
| Token produced without proof of delivery | No billing; unconfirmed work, lender loss ≤ `K` | JOB-R06, JOB-R13 |

A proof of sending is not a proof of receipt: only the attestation of a **delivery witness** independent of the lenders and the borrower (the relay the encrypted stream to the client goes through) is admissible, and only the client's signature is definitive on its own. A hash signed by the lender proves nothing (JOB-R26).

| Requirement | Change | Tests |
| --- | --- | --- |
| JOB-R26 *(new)* | Delivery witness assigned to each attempt, independent; the only one allowed to attest | TEST-P20, JOB-F25, `delivery_attested_by_a_lender_is_inadmissible` |
| JOB-R27 *(new)* | Provisional billing on attestation; delivered positions ≥ validated positions | TEST-P05, TEST-P19, TEST-P21, JOB-F24 |
| JOB-R28 *(new)* | Replay buffer; signed client declaration on resume; replay without re-billing | TEST-P25, JOB-F26, JOB-F30 |
| JOB-R29 *(new)* | Delivery window, single contest, rewind if the buffer is lost | TEST-P20, JOB-F27, JOB-F31, JOB-F32 |
| JOB-R30 *(new)* | A contribution is never paid while its output is provisional | TEST-P22, JOB-F27 |
| JOB-R31 *(new)* | Timed leases, renewed by heartbeat; expiry = immediate rejection, then revocation | TEST-P24, JOB-F28, JOB-F29 |
| JOB-R06, R13, R23, R25 | Ack not mandatory; flow budget measured from the client signature; validated ≠ delivered; window measured from delivered positions | TEST-P09, TEST-P18, TEST-P21 |
| JOB-T05, T08, T13 | Resume at **delivered** positions; T08 also triggered by lease expiry and by a rewind; T13 requires everything produced to be delivered | TEST-P07, TEST-P25 |
| JOB-S04, S06, S12 | Contributions of provisional outputs put on hold, never arbitrated on their own; settlement after deliveries are resolved | TEST-P22, TEST-P06 |

### Requests from the v2.3 audit

| Request | Answer | Tests |
| --- | --- | --- |
| Fairness property | TEST-P23: at the end of the drain, every contribution claimed by the right lender on an output that stayed billed is reserved; every contribution proven by a prior commitment and funded is paid and its reward released or contested; an uncommitted receipt is refunded only by arbitration | TEST-P23 |
| Held rewards and arbitration rarely exercised | Automatic release at the end of the window (JOB-R22, JOB-R20). Dedicated operations in the generator (disputes, explicit arbitration). The coverage check now requires a **minimum number** of passes per path, not just one | `generator_reaches_interesting_paths` |
| Clock and lease expiry | JOB-R31; heartbeat; immediate rejection under an expired lease; revocation by reconciliation | TEST-P24, JOB-F28, JOB-F29 |
| Adversarial tests on I-03 | New `delivery` generator: client that never acks, lender attesting its own delivery, lost ack, lost buffer, client lying on resume, simultaneous failures. Scenarios JOB-F24 to JOB-F32 | Section 9 |
| Inconsistent command total (1.3 million announced, 1.6 million in the table) | The two figures came from two different runs: the coverage table had been measured separately, with 5,000 traces for the partial reserve, while the reference run used 2,500. Figures are now written by the tests themselves during the reference run (`target/coverage/`): a single source | `TEST_REPORT.md` |

### Found during implementation

| Ref. | How | Problem | Fix |
| --- | --- | --- | --- |
| CE-04 | `proptest` counterexample (TEST-P06), `delivery` generator | Slice closed, contribution reserved but not yet evaluated, then output voided by a rewind: evaluation subtracted the item already refunded, failed, and reconciliation swallowed the error. Job stuck in `finalizing` | JOB-S04: only items still `pending_evaluation` are evaluated. JOB-R20: an internal error is never swallowed by reconciliation. Test `ce04_*` |
| CE-05 | `proptest` counterexample (TEST-P23, new property), found by all four generators | In open sharing, a paid contribution is worth 0: nothing is held, so nothing is ever released, and the reward stayed "neither released nor contested" forever | JOB-R22: a zero reward is complete as soon as it is paid. Test `ce05_*` |
| D-01 | TEST-P22, while writing JOB-F27 | Implementation defect (not in the spec): an awaiting contribution refunded by a void kept its "awaiting" flag | Flag cleared on any payment or refund |
| I-11 | Design of JOB-R28 | Contesting an output of the **live** attempt makes no sense: the witness is online, a retransmission is enough. Allowing the contest there would cause a useless rewind | JOB-R28: only outputs of revoked attempts can be declared missing |
| I-12 | TEST-P21 | Exposure is not bounded "per interruption" but **for the whole job**: since the flow budget is measured from the client's last signature, at most `K` positions per type are delivered without a signature, whatever the number of resumes | JOB-R27; JOB-F15 and JOB-F24 reworded |
| I-13 | JOB-F32 | A rewind invalidates all work built on the voided outputs, including that of a resume attempt already started | JOB-R29: the live attempt is revoked (JOB-T08 or JOB-T06) |
| I-14 | JOB-F27 | An output voided then produced again is a new billing: its contributions cannot carry the same identifier as the old ones | `contribution_id` includes the output's billing generation |
| I-15 | JOB-R08 applied to JOB-R22 | "Release possible after the window" was not an automatic transition: a reward could stay held forever, contrary to JOB-R08 | JOB-R22: reconciliation releases rewards at the end of the window |
| I-16 | JOB-F32 | With a flow budget measured from the client signature, a resume after a provisional end of stream starts with a reduced window: it produces only `K − (delivered − validated)` units before the first ack | Intended behavior (exposure bound). Documented in JOB-R27 |

## Changelog v2.2 → v2.3

### Fixes requested (v2.2 audit)

| Requirement | Problem fixed | New rule | Tests |
| --- | --- | --- | --- |
| JOB-R17, JOB-R21 | A "logical unit" `(job, type, position)` did not distinguish layer ranges: 4 GPUs producing the same token looked like the same work | Split into `output_id = (job, type, position)` (billed once to the borrower) and `contribution_id = (output_id, layer range, role)` (each contribution paid once). Sum of an output's contributions ≤ output price | `r21_every_stage_paid_once_and_sum_le_price`, `r21_rounding_never_exceeds_price`, TEST-P03, TEST-P15 |
| JOB-R24, JOB-S03 | `paid + refunded + disputed = claimed` false between closure and evaluation | Added `pending_evaluation`: `claimed = pending + paid + refunded + disputed`. All lines reserved atomically at closure, capped by the outputs actually billed | `r24_pending_evaluation_balances_line_between_close_and_evaluate`, TEST-P12 |
| JOB-R22, JOB-S12 | Source of refunds after job closure undefined | Single contest window: rewards stay held, a contest refunds from them, a release is final. No contest creates credits | `r22_contest_after_job_closed_refunds_from_held_rewards`, TEST-P12 |
| Section 9 | Deterministic tests limited to JOB-F01 to F14 | One test per scenario JOB-F01 to JOB-F23 | Section 9.2 |

### Found during implementation

| Ref. | How | Problem | Fix |
| --- | --- | --- | --- |
| CE-01 | `proptest` counterexample (TEST-P13), shrunk to one command | The pool could fund the recovery of a job still `queued`; rejecting the job (JOB-S13, "no entry") left those credits with no owner | JOB-R18: pool relay only if `settlement_status = active` |
| CE-02 | While writing the CE-01 test; no property watched it | JOB-S12 returned the whole unused recovery budget to the borrower, including the part advanced by the pool | JOB-R18: borrower budget used first, then pool relay. JOB-S12 and JOB-R22 return each payer its share. New property TEST-P17 |
| CE-03 | `proptest` counterexample (TEST-P08), shrunk to 8 operations, once the checker was made independent of the domain | A commitment recorded after a slice closed (but before its evaluation) was accepted as proof. Also, precedence was judged by time: a commitment and a revocation in the same second could not be told apart | JOB-R09, JOB-R12, JOB-R15: precedence is judged by the coordinator log sequence number, before the earlier of the revocation and the slice closure |
| I-03 | Implementing JOB-F15 with JOB-R17 | Contradiction: JOB-F15 paid unacked units covered by commitments, while the resume restarts from the last validated position and regenerates them. The same position could be billed twice, or a contribution of the next attempt never paid | JOB-R23: an output is billed only when validated, bound to the attempt that validated it. JOB-R06 reworded. JOB-F15 rewritten: the unacked window is never billed, the loss is bounded by the flow budget. **Decision to confirm** (see section 10) |
| I-04 | Definition of "validated position" | "Recorded by the client" left two possible authorities (client and coordinator) | JOB-R23: the position is validated when the coordinator accepts the client ack for the current attempt |
| I-05 | JOB-F10 unreachable | With an escrow equal to the full cost, the unvalidated window is always covered: JOB-F10 could not happen | JOB-T02: initial reserve can be capped, top-ups through JOB-T12. New rule JOB-R25 (window coverage) |
| I-06 | Proof of recovery work | A recomputation has no position to commit: "receipt commitment" proof does not apply | JOB-R18: recovery work is attested by the attempt being accepted (JOB-T05), as seen by the coordinator |
| I-07 | Receipt commitments | Keeping only the last commitment erased the precedence proof of older ones | JOB-R15: the full history of timestamped commitments is kept |
| I-08 | Recovery earmark | An earmark given to a failed attempt stayed lost for the following resumes | JOB-R18: unused earmark returned to the budget when the attempt is revoked and its slices are final |
| I-09 | Commission | Taken at evaluation, it made the contest incomplete | LEDGER-008: commission taken when the reward is released |
| I-10 | JOB-T13 | "Last unit delivered" was ambiguous | JOB-T13 requires every produced unit to be validated; otherwise, silent client path (JOB-T11) |

## Changelog v2.1 → v2.2

| Requirement | Problem fixed | New rule | Tests |
| --- | --- | --- | --- |
| JOB-T04, JOB-T05, JOB-T06, JOB-T12 | `recovery_mode` reset to `false` by JOB-T04 after a pause | Replaced by `execution_intent` (`initial` / `resume`), monotonic. JOB-T06 goes back to the placement's original state | TEST-P07, JOB-F19 |
| JOB-R14, JOB-R17 | Two attempts could be paid for the same positions | Billing per logical unit, at most once; resume recomputation billed separately | TEST-P03, JOB-F20 |
| JOB-S01 to JOB-S07 | Partial settlement and dispute ambiguous | Explicit amounts per slice and per lender; single atomic evaluation | TEST-P12, JOB-F21 |
| JOB-T14 to JOB-T17, section 2.3 | Terminal job with unsettled escrow | Separate `execution_status` and `settlement_status` | TEST-P13, JOB-F22 |
| JOB-T02, JOB-T09, JOB-R18 | Resume recomputation not funded | Recovery budget of 10 % of the estimated cost, provisioned at reservation | TEST-P14, JOB-F23 |
| JOB-R12, JOB-R19 | Two accounts ≠ two independent participants | Receipts = proofs of transmission; cap on uncommitted receipts | TEST-P10 |
| JOB-R08, JOB-R20 | An alert is not a recovery | Automatic reconciliation with deadlines | TEST-P06 |
| JOB-R13, JOB-R16 | K only covered generation | Three flow budgets | TEST-P09 |

## Changelog v2.0 → v2.1

| Requirement | Problem fixed | New rule |
| --- | --- | --- |
| JOB-T09 | Resume into `running` without the new cluster accepting | `recovering → placing`, `running` only after JOB-T05 |
| JOB-T08, JOB-T11, JOB-T13 | Open slices not settled on interruption | Slice draining |
| JOB-T15, JOB-T16 | Contradiction with JOB-F09 on `settling` | `settling` can neither be cancelled nor failed |
| JOB-T03, JOB-T12 | Insufficient balance = cancellation; resume impossible in open sharing | Wait in `queued`; credits or quota depending on the pool |
| JOB-R05, JOB-R06, JOB-R08 | Rejection too broad, client veto, incomplete timeouts | Earlier receipts admissible, admissible proofs, full deadline table |

## 1. Conventions

Requirements are numbered per domain and never renumbered: a withdrawn requirement keeps its number with the status "withdrawn".

| Prefix | Domain |
| --- | --- |
| `JOB-T` | State machine transitions |
| `JOB-S` | Slice lifecycle (S01 to S07) and job settlement status (S10 to S13) |
| `JOB-R` | Global rules |
| `JOB-F` | Failure scenarios |
| `PROTO` | Messages and protocol |
| `ENGINE` | Engine interface |
| `LEDGER` | Accounting |
| `ORCH` | Orchestration |
| `TEST` | Conformance tests |

**Keywords**: MUST (mandatory), MUST NOT (forbidden), SHOULD (recommended, deviations justified).

**Versions**: architecture v1.1 = what the system does; specification v2.x = how. In case of contradiction, the specification wins and the architecture is corrected. v2.0 adds `settling`; v2.1 the slice lifecycle and flow control; v2.2 separates execution and settlement; v2.3 separates output and contribution and is checked by the executable model; v2.4 adds proven delivery, replay and timed leases; v2.5 adds contests closed by signed ack, binding of proofs to the stream, committed late attestations, supplementary proofs and the sliding cap.

**Mapping to the code**: every identifier cited here appears in the `gpu-domain` code where it is implemented.

### Vocabulary

| Term | Definition |
| --- | --- |
| Job | A request by a borrower to run a model |
| `execution_status` | Execution state of the job (section 2.1) |
| `settlement_status` | Financial state of the job (section 2.3), independent of execution |
| `execution_intent` | `initial` or `resume`. Becomes `resume` as soon as a position is validated or a checkpoint exists; never goes back to `initial` |
| Attempt (`attempt`) | One run of the job on a given cluster, numbered from 1; only one active attempt at a time |
| Lease (`lease`) | Signed, timed right given to a node for a role on an attempt. Expires without heartbeat (JOB-R31) |
| Billing slice (`slice`) | Settlement unit, global identifier `(job, attempt, slice_no)` |
| Output (`output_id`) | `(job, type, position)`: a result delivered to the borrower. Stable logical identity, independent of the attempt. Billed at most once at a time (net billing ≤ 1), bound to the attempt that produced it |
| Contribution (`contribution_id`) | `(output_id, billing generation, layer range, role)`: a lender's share in an output. Each contribution is paid at most once; several contributions of the same output are each paid |
| Billing generation | Number of an output's billing: 0 the first time, incremented if a voided provisional output is produced again (JOB-R29) |
| Delivery witness | Relay the encrypted stream to the client goes through, assigned to each attempt, independent of the lenders and the borrower (JOB-R26) |
| Delivery attestation | Signed statement by the witness: positions sent **and acknowledged at transport level** by the client's authenticated endpoint, with the frame digest. Proves neither application-level receipt nor processing by the client |
| Witness commitment | Short witness message, timestamped and numbered by the coordinator, announcing the attested positions; makes a full attestation arriving while draining admissible (JOB-R32) |
| Client stream | The borrower's session for a job; its identifier is covered by the digest of every frame and every declaration (JOB-R34) |
| Frame digest | Chained digest signed by the output node: job, stream, model, type, position, billing generation (JOB-R34) |
| Contest | Declaration that a provisional output was not received, made during the window; one per output; closed by a signed cumulative ack covering the position, otherwise refunded at the deadline (JOB-R33) |
| Supplementary proof | Stronger proof added to a reserved item before the evaluation deadline (JOB-R35) |
| Delivered position | Position billed, definitively or provisionally. `validated ≤ delivered` (JOB-R27) |
| Provisional billing | Billing on a witness attestation, waiting for the client signature, a replay or the expiry of the delivery window |
| Replay buffer | Encrypted frames of attested outputs, kept by the witness to resend them to the client without recomputation, at least 24 h and until contests are resolved (JOB-R28) |
| Delivery window | 24 h period opened when the producing attempt is revoked, during which the client can contest a provisional output (JOB-R29) |
| Rewind | Voiding of provisional outputs from a lost position on, with their price refunded to the escrow (JOB-R29) |
| Recovery work (`recovery_work_id`) | `(job, attempt, segment)`: recomputation needed to rebuild a lost state, paid from the recovery budget |
| Wasted work | Computation of an interrupted attempt that was never delivered (neither acked nor attested), or a voided provisional output. Never billed, never paid |
| Validated position | Position covered by a client signature: ack accepted for the current attempt, or resume declaration (JOB-R23, JOB-R28). Never goes back |
| Recovery budget | 10 % of the estimated cost, accepted at submission, put into escrow at reservation |
| Pool relay | Credits the pool treasury puts into the recovery escrow when the borrower's budget is exhausted |
| Recovery earmark | Share of the recovery budget given to a resume attempt when it is placed |
| Work types | `prefill` (input tokens), `generate` (output tokens), `batch` (delivered items) |
| Receipt (`receipt`) | Ack signed by the recipient of a unit. Proves transmission, not that the computation is valid |
| Receipt commitment | Digest of a batch of receipts sent to the coordinator and timestamped by it. The full history is kept |
| Draining | Period after revocation where no new unit is accepted, but receipts for earlier work remain admissible |
| Flow budget (`K_prefill`, `K_generate`, `K_batch`) | Maximum number of units produced and not validated (not signed by the client), per type |
| Initial reserve | "Work" share put into escrow at reservation, can be capped; the rest comes through top-ups |
| Escrow | Credits locked for the job: work + recovery budget (+ pool relay) |
| Held reward | Paid share of a line, kept in a holding account during the contest window |
| Outbox | Table of events to send, written in the same transaction as the state change |

## 2. Job state machine

A job has two independent statuses: `execution_status` (10 states, 3 of them terminal: `completed`, `failed`, `cancelled`) and `settlement_status` (section 2.3). A job is closed only when both are final. Any transition not listed here is forbidden and MUST be rejected.

The nominal path goes from `queued` to `completed`. A failure goes through `recovering` and back through `placing` (a placement failure during resume goes back to `recovering`); missing credits or replacements go through `paused`, from which the job returns to `reserved`. `settling` can be neither cancelled nor failed.

### 2.1 Job transitions

| ID | Transition | Trigger | Preconditions | Atomic effects | Events | Recovery |
| --- | --- | --- | --- | --- | --- | --- |
| JOB-T01 | ∅ → `queued` | `SubmitJob` | Active account; pool allowed; model allowed; budget ≤ trust-level cap; recovery budget accepted; unknown idempotency key | Job created (`attempt = 0`, `execution_intent = initial`, `settlement_status = none`) | `JobQueued` | Same key and same parameters: the existing job is returned; same key, other parameters: rejected |
| JOB-T02 | `queued` → `reserved` | Automatic, as soon as resources allow | Credits mode: balance ≥ initial reserve + recovery budget. Open sharing: quota available. Otherwise, wait in `queued` | Entry balance → work escrow (initial reserve = min(estimated cost, cap)) and balance → recovery escrow, or quota reservation; `settlement_status = active` | `CreditsReserved` | Key `(job, reserve)` |
| JOB-T03 | `queued` → `cancelled` | Final rejection: wait exceeded, model withdrawn, impossible budget | None | `settlement_status = closed` (JOB-S13), no entry | `JobRejected(reason)` | Idempotent |
| JOB-T04 | `reserved` → `placing` | The scheduler found an eligible cluster | Eligible cluster (ORCH); one layer range per lender; attempts < maximum; **witness independent** of the lenders and the borrower (JOB-R26). If `execution_intent = resume`: recovery earmark ≤ unallocated budget (JOB-R18) | `attempt += 1`; timed leases (JOB-R31); witness assigned; `placing_from = reserved`; attempt production initialized to the **delivered positions** *(v2.4)*. **`execution_intent` is not changed** | `AssignmentsIssued` | `Assign` resent from the outbox (idempotent per `lease_id`) |
| JOB-T05 | `placing` → `running` | All nodes accepted and loaded their slice | Leases not expired (JOB-R31). State restored **exactly** up to the **delivered** positions *(v2.4)* (0 on first launch); sampler restored. Positions delivered but not received by the client are replayed to it (JOB-R28), never recomputed | `running`; a slice is opened; the attempt is recorded as started (proof of recovery work, JOB-R18) | `JobStarted` or `JobResumed` | A late `AssignAck`, or one from another attempt, is rejected |
| JOB-T06 | `placing` → `placing_from` (`reserved` or `recovering`) | Placement timeout or a node refused | Failed placements < maximum | Attempt revoked; its recovery earmark is returned | `PlacementFailed` | At the maximum: JOB-T16 |
| JOB-T07 | `running` → `running` | A slice is closed | `open` slice of the current attempt | Slice → `closed` (JOB-S03); new slice opened | `SliceClosed` | See JOB-S04 |
| JOB-T08 | `running` → `recovering` | Node lost, engine error, **lease expired** (JOB-R31) or **rewind** under the attempt (JOB-R29) *(v2.4)* | Current attempt active | Execution revoked; `open` slices → `draining`; `execution_intent = resume`; delivery window opened for the attempt's provisional outputs | `NodeLost`, `RecoveryStarted` | Any unit from the old attempt rejected (JOB-R11) |
| JOB-T09 | `recovering` → `placing` | Replacements found | Resume timeout not exceeded; earmark ≤ unallocated budget (JOB-R18) | `attempt += 1`; new leases; `placing_from = recovering` | `AssignmentsIssued` | As JOB-T04 |
| JOB-T10 | `recovering` → `paused` | No replacement by the deadline, or recovery budget exhausted | None | Persistent checkpoint if possible; cluster released | `JobPaused(no_capacity` or `recovery_budget)` | Resume through JOB-T12 |
| JOB-T11 | `running` → `paused` | Escrow insufficient; pause requested; preemption; silent client | None | Execution revoked; `open` slices → `draining`; checkpoint | `JobPaused(reason)` | Resume through JOB-T12 |
| JOB-T12 | `paused` → `reserved` | Resume | Credits mode: work escrow after top-up ≥ price of the cheapest remaining output. Open sharing: no credits accepted. Pause not expired | Entry balance → work escrow (top-up). `execution_intent` kept | `JobResumeRequested` | Key `(job, topup, version)` |
| JOB-T13 | `running` → `settling` | Generation finished | **All produced units are delivered** (acked or attested) *(v2.4)* | Execution revoked; `open` slices → `draining`; delivery window opened for provisional outputs | `JobFinished` | Undelivered units: JOB-T11 (silent client) |
| JOB-T14 | `settling` → `completed` | No `open` or `draining` slice left | None | `settlement_status = finalizing` | `JobCompleted` | Idempotent |
| JOB-T15 | Any active state **except `settling`** → `cancelled` | Cancellation, or maximum wait in `reserved` exceeded | Not in `settling` (otherwise rejected with `JOB_SETTLING`) | Revocation; slices → `draining`; `settlement_status = finalizing` (or `closed` if never reserved) | `JobCancelled` | Idempotent |
| JOB-T16 | Any active state **except `settling`** → `failed` | Maximum attempts or placements, invalid model, violation | Not in `settling` | As JOB-T15; proven work is still paid | `JobFailed(reason)` | Idempotent |
| JOB-T17 | `paused` → `cancelled` | Pause expired | Pause duration ≥ maximum | Checkpoint deleted; `settlement_status = finalizing` | `JobExpired` | Idempotent |

A terminal execution state never releases the escrow directly: the settlement status (section 2.3) does that, once all slices are final.

### 2.2 Slice lifecycle

Draining is a state of the **slice**, not of the job: a slice of the old attempt can be settled while the new attempt runs.

`open` → `draining` → `closed` → `final`, with `closed` → `disputed` → `final` when a line is disputed. Evaluating a closed slice is **a single atomic transition** (JOB-S04).

| ID | Transition | Trigger | Effects |
| --- | --- | --- | --- |
| JOB-S01 | ∅ → `open` | JOB-T05 or JOB-T07 | Claims and commitments accepted |
| JOB-S02 | `open` → `draining` | Execution revoked | No new unit; `receipt_deadline` = now + drain window; at most "flow budget" uncommitted items per lender and per type (JOB-R12 b) |
| JOB-S03 | `open` or `draining` → `closed` | Normal closure, or `receipt_deadline` reached (never before) | **Atomic reservation** of all lines (JOB-R24): each structurally valid item is reserved, the others are rejected. A contribution is valid if its output is bound to the slice's attempt, if the lender is the one assigned to that range in that attempt, and if the contribution is not already taken. A recovery item is valid if it fits in the attempt's earmark and the attempt has started |
| JOB-S04 | `closed` → `final` or `disputed` | Evaluation, from closure on and at the latest at the deadline | For each item **still** in `pending_evaluation` (CE-04): contribution of a **provisional** output → awaiting delivery (JOB-R30); committed proof checked → paid; uncommitted receipt under the JOB-R19 sliding cap → paid, beyond → disputed; proof missing or not found → **refunded at the deadline only**, the item stays awaiting proof before that (JOB-R35). The slice goes to `final` or `disputed` when no item awaits proof anymore and, before the deadline, when no contribution awaits its output (CE-06). `final` if no line is disputed |
| JOB-S05 | *(withdrawn in v2.2, merged into JOB-S04)* | — | — |
| JOB-S06 | `disputed` → `final` | Arbitration of each disputed line, or deadline; or resolution of pending deliveries (JOB-R30) | Per line: paid or refunded. Default rule at the deadline: not proven = refunded. Items awaiting delivery are **never arbitrated on their own**: they are evaluated by the JOB-S04 rules when their output becomes definitive, or refunded if it is voided |
| JOB-S07 | `closed` → (evaluation) | Evaluation deadline | Reconciliation runs JOB-S04 |

### Slice amounts

Amounts are tracked **per line** `(slice, lender)` and per item: a dispute involving several lenders is settled line by line.

| Amount | Definition |
| --- | --- |
| `claimed` | Total reserved at closure for the line |
| `pending_evaluation` | Reserved share, not evaluated yet |
| `paid` | Paid share (into held rewards) |
| `refunded` | Share returned to the job escrow |
| `disputed` | Disputed share, blocked until arbitration or, for a contribution awaiting delivery, until its output's fate is known |
| `held` | Held reward, neither released nor contested |
| `released` / `contested` | Reward released to the lender / returned by a contest |

**Line invariants** (JOB-R24): `claimed = pending_evaluation + paid + refunded + disputed` at all times; `paid = held + released + contested`; a `final` slice has `pending_evaluation = disputed = 0`; the line account balance = `pending_evaluation + disputed`; the held reward account balance = `held`.

Each partial operation has its key: `(slice, lender, operation type, item)` with type ∈ {`claim`, `pay`, `refund`, `release`, `commission`, `contest`}. Each refund carries its reason: missing proof, proof not found, attempt not started, arbitration, voided output.

Recovery work follows the same cycle, on `recovery_work_id` items paid from the recovery escrow.

### 2.3 Job settlement status

`none` → `active` → `finalizing` → `closed`.

| ID | Transition | Trigger | Effects |
| --- | --- | --- | --- |
| JOB-S10 | `none` → `active` | JOB-T02 | Escrow set up |
| JOB-S11 | `active` → `finalizing` | `execution_status` becomes terminal | Reconciliation takes charge of the job |
| JOB-S12 | `finalizing` → `closed` | All slices `final` **and no provisional output** *(v2.4)* | Work escrow and undistributed billed outputs → borrower. Recovery escrow: unused pool relay share → pool, rest → borrower (JOB-R18). Escrow = 0 |
| JOB-S13 | `none` → `closed` | JOB-T03, or JOB-T15 before reservation | No entry (no credit can have moved, JOB-R18) |

A job is **closed** when `execution_status` is terminal and `settlement_status = closed`. Held rewards then keep their contest window (JOB-R22), which does not reopen the job.

### 2.4 Output delivery *(new in v2.4)*

An output has its own life, independent of the attempt that produced it:

`unbilled` → `provisional` (witness attestation) → `definitive` (client signature covering the position, or window expired without contest); `provisional` → `contested` (declared not received, replay requested) → `definitive` (signed cumulative ack covering the position) or `voided` (deadline without ack, or buffer lost); `voided` → `unbilled`, then possibly billed again by another attempt, with a new generation. A `definitive` output never becomes provisional or voided again. *(v2.5: a replay no longer makes an output definitive.)*

| Event | Before | After | Rule | Entries |
| --- | --- | --- | --- | --- |
| Client ack up to `p` | unbilled | definitive | JOB-R23 | work escrow → billed outputs |
| Client ack up to `p` | provisional | definitive | JOB-R23 | none |
| Witness attestation up to `p` | unbilled | provisional | JOB-R26, R27 | work escrow → billed outputs |
| Late attestation while draining, covered by a commitment prior to the revocation | unbilled | provisional | JOB-R32 | work escrow → billed outputs |
| Signed client declaration (stream digest): position `< confirmed` | provisional or contested | definitive | JOB-R28, R33 | none |
| Declaration: position missing, window open, buffer available | provisional | **contested** (replay, 1 h deadline) | JOB-R33 | none |
| Declaration: position missing, already contested or definitive, buffer available | unchanged | unchanged (retransmission only) | JOB-R28, R33 | none |
| Declaration: position missing, buffer lost | provisional or contested | voided, together with every later position of the same type | JOB-R29 | reserved contributions → billed outputs; billed outputs → work escrow |
| Declaration: position missing, buffer lost | definitive | declaration rejected | JOB-R29 | none |
| Client liveness signal | any | unchanged | JOB-R33 | none |
| Contest deadline without a covering ack | contested | voided, together with every later position of the same type | JOB-R33 | as above |
| Delivery window expired, position not contested and before any contested position | provisional | definitive | JOB-R29 | none |

**Delivery invariants**: billed positions = exactly `[0, delivered)` per type; `validated ≤ delivered`; definitive prefix then provisional suffix; every validated position is definitive; `delivered − validated ≤ K` per type (TEST-P05, P19, P21).

**Admissible proofs** (JOB-R26):

| Level | Proof | Effect |
| --- | --- | --- |
| P0 | The lender says it produced | None |
| P1 | Send log signed by the lender, token hash | None: a proof of sending is not a proof of receipt. Only used to ask for a retransmission |
| P2 | Attestation by the assigned witness, with the frame digest signed by the output node (JOB-R34): frames sent and acknowledged at transport level by the client's authenticated endpoint | **Provisional** billing. Does not prove application-level receipt: not enough to close a contest |
| P3 | Client signature bound to the stream: cumulative ack, or declaration "I hold `0..n`" with the prefix digest | **Definitive** billing of the covered positions, the only way to close a contest |

## 3. Global rules

- **JOB-R01 — Single transaction**: a transition MUST run in a single transaction containing the state change, the accounting entries and the insertion of events into the outbox. Either everything is written, or nothing.
- **JOB-R02 — Outbox**: outgoing messages MUST be sent only after commit, from the outbox. Recipients MUST tolerate duplicates.
- **JOB-R03 — Optimistic lock**: every job, slice and line carries a `version`; a transition MUST be conditioned on the version read.
- **JOB-R04 — Idempotency**: every external command and every accounting entry MUST carry an idempotency key. A command already applied changes nothing, not even the sequence number.
- **JOB-R05 — Current attempt**: every message from a node, the witness or the client MUST carry `(job, attempt, lease_id, seq)`. A new unit, an attestation or an ack under a revoked or expired lease, or from a non-current attempt, MUST be rejected. Receipts for earlier work fall under JOB-R12.
- **JOB-R06 — Billing and payment** *(changed in v2.4)*: an **output** is billed to the borrower only on admissible proof of delivery: client signature (definitive, JOB-R23) or witness attestation (provisional, JOB-R27). The client ack is therefore **not** mandatory. A **contribution** is paid only if its output is billed **definitively** (JOB-R30) and admissible proofs cover it. No proof is considered infallible on its own, and a payment MUST NOT rest only on the statement of a single participant. Without attestation or ack, a lender's loss is bounded by the flow budget (JOB-R13).
- **JOB-R07 — No negative balance**: a transition MUST NOT make a balance, an escrow, a line or a held reward negative.
- **JOB-R08 — Timeouts**: every non-final state of the job, its settlement, a slice, a disputed line, a provisional output and a held reward has a deadline **and an automatic transition**.
- **JOB-R09 — Clock and order** *(changed in v2.3)*: only coordinator timestamps count for deadlines. The **order** of events is judged by the coordinator log sequence number, never by time: two events can share the same second (CE-03).
- **JOB-R10 — Log**: every transition is logged, without borrower data.
- **JOB-R11 — Revocation**: after `execution_revoked`, the coordinator MUST NOT accept any new unit or ack from the attempt.
- **JOB-R12 — Receipts while draining**: a receipt proves a transmission, not a computation. An item is admissible if (a) its position is covered by a commitment recorded, in log order, **before the earlier of the attempt revocation and the slice closure** (CE-03), or (b) it belongs to the last uncommitted interval (at most the flow budget per type) and is countersigned. A commitment recorded after the revocation or after the closure proves nothing. Signer independence is never assumed: items (b) are subject to JOB-R19.
- **JOB-R13 — Flow control** *(changed in v2.4)*: for each work type, the number of units produced and not **validated** (not signed by the client) MUST never exceed its budget, across all attempts. A witness attestation does not free room in the window: this is what bounds the exposure of both parties (JOB-R27). Acks are asynchronous and only block a full window.
- **JOB-R14 — Single evaluation** *(clarified in v2.5)*: each item of a slice is decided once, and the slice finishes its evaluation once (key `(job, attempt, slice_no)`), at the latest at the evaluation deadline (I-19).
- **JOB-R15 — Receipt commitments** *(changed in v2.3)*: each recipient sends a commitment at most every "flow budget" units, without blocking the stream. A commitment can only cover produced units. The coordinator MUST keep the full history of commitments, each with its time and sequence number, not just the last one.
- **JOB-R16 — Flow budgets**: each budget covers at least the units produced during one ack round trip. MVP values: `K_generate = 4`, `K_prefill = 1` block, `K_batch = 1`.
- **JOB-R17 — Single output** *(changed in v2.3)*: an output `(job, type, position)` MUST be billed to the borrower only once, across all attempts. It is bound to the attempt that validated it; the unvalidated positions of an interrupted attempt are wasted work.
- **JOB-R18 — Recovery budget** *(changed in v2.3)*: resume recomputation is paid to the node that does it, from a cumulative budget of 10 % of the estimated cost, provisioned at reservation. Each resume gets an earmark when placed; a resume MUST NOT start if its earmark is not funded. The unused earmark of a revoked attempt goes back to the budget once its slices are final. The pool can relay the budget **only if `settlement_status = active`** (CE-01), by putting in its credits before the resume. Order of use: **borrower budget first, then pool relay**; at closure or on a contest, each payer gets its own share back (CE-02). Recovery work is attested by the attempt being accepted (JOB-T05).
- **JOB-R19 — Anti-collusion cap** *(changed in v2.5)*: over any 24 h sliding window, the sum of the **gross** amounts admitted on uncommitted receipts for one account MUST NOT exceed the cap (initial value: 50 credits). Beyond that: dispute. A refund or a contest does not restore the quota during the window. The check runs on the payment log, not on a counter. A sliding window has no calendar boundary: a burst at 23:59 and another at 00:01 fall in the same window.
- **JOB-R20 — Reconciliation** *(changed in v2.4)*: an automatic, restartable and idempotent process applies every transition that is due (jobs, leases, slices, disputed lines, delivery windows, held rewards, settlements). A human only steps in on disputes the rules do not decide, with the same deadline. An internal error met during reconciliation MUST NOT be ignored: it is reported and blocks any new issuance (LEDGER-007) (CE-04).
- **JOB-R21 — Single contribution** *(new in v2.3)*: a contribution `(output_id, layer range, role)` MUST be paid only once. It is payable only if its output is bound to the slice's attempt and the lender is the one assigned to that range in that attempt. A contribution's share is proportional to the number of layers in its range, rounded down: the sum of an output's contributions never exceeds its price, the remainder goes back to the borrower.
- **JOB-R22 — Held rewards** *(changed in v2.4)*: a payment first goes into a held reward. During a single contest window (48 h after the slice is finalized), a contest refunds each payer its share **from the held reward**. At the end of the window, reconciliation **releases** the reward (I-15); a release is final, nothing is ever taken back from a lender's balance. No contest creates credits. A zero reward (open sharing) is complete as soon as it is paid (CE-05).
- **JOB-R23 — Validation** *(changed in v2.4)*: a position is validated when the coordinator accepts a client signature covering it: cumulative ack for the current attempt, or resume declaration (JOB-R28). Validation makes the output definitive; if it was not billed yet, it bills it (work escrow → billed outputs) in the same transaction and binds it to the current attempt. Validated positions never go back. A resume restarts from the **delivered** positions (JOB-R27), not the validated ones.
- **JOB-R24 — Atomic reservation** *(new in v2.3)*: at closure, all lines of the slice are reserved in the same transaction, from billed outputs (contributions) or from the recovery escrow (recovery). A reserved contribution can no longer be reserved by another slice.
- **JOB-R25 — Window coverage** *(changed in v2.4)*: a unit can only be produced if the work escrow covers the price of every unit produced and not yet billed (beyond the delivered positions). A validation or an attestation can therefore never lack funds.
- **JOB-R26 — Delivery witness** *(new in v2.4)*: each attempt has a witness assigned at placement, through which the end-to-end encrypted stream to the client goes. It MUST be neither one of the attempt's lenders nor the borrower. Only its attestation is an admissible proof of delivery; an attestation signed by anyone else (in particular the output node) is rejected with `INADMISSIBLE_PROOF`. An attestation is accepted only while the attempt is live and under a valid lease, and only for produced units. A witness that lost its buffer no longer attests. *(v2.5)* Each witness has a **reputation separate** from the lenders', fed by its attestations later refunded and by random checks. Selection by phase: private MVP, witness of the pool or its coordinator; federation, operators recognized by both pools; public, reputation, per-witness exposure limits and random checks, a bond possibly later.
- **JOB-R27 — Provisional billing** *(new in v2.4)*: an attestation bills provisionally the positions it covers (work escrow → billed outputs) and binds them to the producing attempt; they become **delivered** positions. A provisional output becomes definitive by client signature, by replay (JOB-R28) or when the delivery window expires (JOB-R29). Since the flow budget is measured from the client signature (JOB-R13), at most `K` positions per type are delivered without signature at any time, for the whole job: this bounds what a colluding witness can wrongly bill, and what a dishonest client can withhold (I-12). Consequence: a resume after a provisional end of stream produces only `K − (delivered − validated)` units before the first ack (I-16).
- **JOB-R28 — Replay** *(changed in v2.5)*: the witness keeps the encrypted frames of each attested output **at least 24 h after the producing attempt is revoked, and as long as an output of that attempt is provisional or contested**; it MUST NOT purge before. On resume or after the end, the client signs a declaration "I hold exactly `0..confirmed`", bound to the stream by the prefix digest (JOB-R34), with `validated ≤ confirmed ≤ delivered` (otherwise rejected). Positions `< confirmed` become validated and definitive; the missing positions are **replayed** to it from the buffer, without recomputation or re-billing, **without becoming definitive** (JOB-R33). An output of the live attempt cannot be declared missing: it is retransmitted (I-11). Buffer storage is paid from the pool's infrastructure fees (section 10).
- **JOB-R29 — Delivery window and rewind** *(changed in v2.5)*: the delivery window (**24 h**) opens when the producing attempt is revoked. If a provisional output is declared missing while the buffer is lost, it is **voided together with every later output of the same type** (they depend on it): reserved contributions returned, price returned to the escrow, delivered positions brought back to the lost position (never below the validated ones). A live attempt built on those outputs is revoked (JOB-T08, or JOB-T06 while placing) (I-13). Without a contest during the window, provisional outputs become definitive, **in position order, up to the first contested position**: the later ones depend on it and wait for its resolution (I-17). After the window, a definitive output whose buffer is lost can no longer be declared missing: the client's loss is bounded by `K`.
- **JOB-R30 — Contributions of provisional outputs** *(new in v2.4)*: a contribution is NEVER paid while its output is provisional. At evaluation, it is put on hold (disputed, never arbitrated on its own). When the output becomes definitive, the contribution is evaluated with the ordinary JOB-S04 rules; when it is voided, the contribution is refunded. An output produced again is a new billing generation, with distinct contributions (I-14).
- **JOB-R32 — Late attestations** *(new in v2.5)*: after an attempt is revoked, no new delivery is accepted. A full attestation arriving **while draining** is admissible only if a short witness commitment covering those positions was recorded by the coordinator **before the revocation, in log order** (JOB-R09), and no newer attempt has been placed. A commitment is only accepted from the live attempt: a commitment created afterwards cannot pass for an old one.
- **JOB-R33 — Contest** *(new in v2.5)*: a provisional output declared missing during the window is **contested**, once; the witness replays it; a deadline is set (1 h). It becomes definitive only through a **signed cumulative application ack, bound to the same stream, covering its position** (an ack of a later position in the same ordered stream covers all earlier ones). A replay, a replay attested at transport level, a liveness signal or any other signed client activity is not enough. At the deadline without such an ack, or if the witness cannot present the buffer or the required proofs: refund, through a rewind (JOB-R29).
- **JOB-R34 — Binding proofs to the stream** *(new in v2.5)*: the output node signs the chained digest of each frame, covering job, client stream identifier, model, type, position and billing generation. An attestation whose digest differs from that of the signed frames (substituted frame, or valid frame from another session) is rejected with `INADMISSIBLE_PROOF`; likewise for a client declaration whose prefix digest is not this stream's. The signature and the digest prove the integrity and origin of a frame, not its receipt: that is why JOB-R33 requires the client ack.
- **JOB-R35 — Supplementary proofs** *(new in v2.5)*: until a slice's evaluation deadline, a lender can replace the proof of an undecided item with a stronger one (missing < uncommitted receipt < commitment). A refund for missing proof only takes effect at the deadline. At the deadline, final settlement according to the available proofs and the arbitration rules. After closure, the ledger is never modified: any exceptional correction is a new, explicitly funded accounting operation.
- **JOB-R31 — Timed leases** *(new in v2.4)*: each lease has a deadline (45 s), renewed by heartbeat as long as it has not expired. An expired lease is never renewed. The coordinator immediately rejects, by its own clock (JOB-R09), any unit, attestation, acceptance or ack received under an expired lease, even before revocation; reconciliation then revokes the attempt (JOB-T08, or JOB-T06 while placing). A node MUST stop producing before the deadline by its local clock, with a margin covering drift.

### Deadlines and limits (initial values, to be calibrated)

| State | Initial deadline | On expiry |
| --- | --- | --- |
| `queued` (waiting for resources) | 15 min | JOB-T03 |
| `reserved` (waiting for placement) | 15 min | JOB-T15 (reason: timeout) |
| `placing` | 60 s | JOB-T06 |
| `running`, silent client | 60 s without ack, with an unvalidated window | JOB-T11 |
| Lease without heartbeat | 45 s | Immediate rejection, then JOB-T08 or JOB-T06 by reconciliation |
| Uncontested provisional output | 24 h after the producing attempt is revoked | Definitive, up to the first contested position (JOB-R29) |
| Contested output | 1 h after the contest | Voided without a covering ack (JOB-R33) |
| Item without proof | Evaluation deadline (10 min after closure) | Refunded (JOB-R35) |
| `recovering` | 2 min | JOB-T10 |
| `paused` | 30 days | JOB-T17 |
| `settling` | Drain window | Slices closed (JOB-S03), then JOB-T14 |
| `draining` slice | 2 min | JOB-S03 |
| `closed` slice not evaluated | 10 min | JOB-S07 |
| `disputed` line | 48 h | JOB-S06, default rule |
| `finalizing` settlement | As soon as all slices are `final` | JOB-S12 |
| Held reward | 48 h after the slice is finalized | Automatic release (JOB-R22) |

| Limit | Initial value |
| --- | --- |
| Failed placements before `failed` | 5 |
| Maximum attempts per job | 8 |
| `K_generate` / `K_prefill` / `K_batch` | 4 / 1 / 1 |
| Recovery budget | 10 % of the estimated cost, cumulative |
| Cap on uncommitted receipts | 50 credits per account over any 24 h sliding window, gross amounts |
| Commission | 10 %, taken on release |
| Initial reserve | Full estimated cost (cap configurable per pool) |
| Replay buffer retention | At least 24 h after revocation, and until every open contest is resolved |
| Contests per output | 1 (closed by a signed cumulative ack, or refunded at the deadline) |
| Short witness commitment | On every attestation, or at most every `K` units |

## 4. Failure scenarios

Each scenario has a deterministic test (`tests/scenarios/`), which also checks every invariant at each step and liveness at the end of the test.

| ID | Scenario | Required behavior | Test |
| --- | --- | --- | --- |
| JOB-F01 | The coordinator stops in the middle of a transition with several writes | Nothing is written (JOB-R01). The outbox resends undelivered events | `f01_partial_transition_leaves_no_trace` |
| JOB-F02 | Restart after JOB-T04 or JOB-T09, before the `Assign` messages are sent | `Assign` resent; duplicates have no effect; placement timeout: JOB-T06 | `f02_redelivered_assignments_are_harmless` |
| JOB-F03 | A unit produced after revocation or expiry | Rejected, never paid. Receipts for earlier work stay admissible while draining | `f03_work_after_revocation_rejected_prior_receipts_paid` |
| JOB-F04 | Settlement done, ack lost | Report resent: contribution already taken, no second payment | `f04_duplicate_report_after_settlement_pays_once` |
| JOB-F05 | The failed node comes back after being replaced | Its units and acks are rejected; its earlier receipts are settled through draining | `f05_returning_node_is_ignored_but_keeps_prior_pay` |
| JOB-F06 | An ack arrives twice | No effect, output billed once | `f06_duplicate_ack_charges_once` |
| JOB-F07 | The client disconnects | Production stopped by the flow budget; after 60 s, JOB-T11. Without attestation, the unvalidated window is not billed; the resume restarts from the last delivered position | `f07_client_disconnect_stops_after_k_then_pauses` |
| JOB-F08 | The coordinator loses contact with the cluster | Leases expire, nodes stop; nothing later is billed or paid | `f08_lost_contact_revocation_stops_payment`, and JOB-F29 for actual expiry |
| JOB-F09 | Cancellation and end of generation at the same time | Optimistic lock: the first one wins; in `settling`, cancellation and failure are rejected | `f09_cancel_and_finish_race` |
| JOB-F10 | The escrow no longer covers the window | Production rejected (JOB-R25), pause, resume with a top-up | `f10_low_escrow_blocks_window_then_pause_and_topup` |
| JOB-F11 | Two identical reports | The second item is rejected at closure | `f11_identical_reports_counted_once` |
| JOB-F12 | Malformed or oversized message | Rejected before decoding, stable code | `f12_oversized_frame_rejected_before_decoding` |
| JOB-F13 | The scheduler restarts during a placement | Replaying its decisions has no effect | `f13_scheduler_restart_replays_nothing` |
| JOB-F14 | Preemption of a deferred job | JOB-T11; slice drained and settled; resume | `f14_preemption_settles_slice_then_resumes` |
| JOB-F15 *(clarified in v2.4)* | The client refuses to ack **and the witness attested nothing** | The undelivered window is never billed or paid; production stops at `K` units; JOB-T11 after 60 s; repeated refusals: borrower reputation lowered. A lender loses ≤ `K` units. With attestation: JOB-F24 | `f15_withheld_acks_bound_loss_to_k` |
| JOB-F16 | One GPU fails, another had valid work | Draining; the survivor is paid, line by line | `f16_survivor_paid_after_other_gpu_fails` |
| JOB-F17 | Receipts fabricated afterwards | Commitment after the revocation or the slice closure: nothing is proven, refunded; uncommitted receipts limited to `K` per type then the JOB-R19 cap, beyond that dispute | `f17_receipts_fabricated_after_revocation` |
| JOB-F18 | New attempt while the old one drains | Each slice follows its own cycle; each output belongs to a single attempt. Also works in open sharing | `f18_new_attempt_runs_while_old_slice_drains`, `f18b_free_pool_resume_uses_quota_not_credits` |
| JOB-F19 | Pause, then resume through `reserved` → `placing` | `execution_intent` stays `resume`; JOB-T05 rejects a state not restored | `f19_resume_after_pause_keeps_intent` |
| JOB-F20 | Attempt 1: positions 0-1 validated, 2-4 produced, failure. Attempt 2 | Positions 0-1: attempt 1. Positions 2-4 of attempt 1: wasted. Rebuild: recovery. Positions 2-4: attempt 2 | `f20_unvalidated_positions_are_wasted_not_billed` |
| JOB-F21 | Dispute on a slice with several lenders | Only the line concerned is disputed; the others are paid at evaluation | `f21_dispute_isolated_to_one_lender_line` |
| JOB-F22 | Cancellation while draining | `cancelled` + `finalizing`; reconciliation finishes the slices then settles the escrow | `f22_cancel_while_draining_settles_everything` |
| JOB-F23 | Recovery budget exhausted | Resume rejected until funded; pool relay possible; otherwise pause | `f23_recovery_budget_exhausted_then_pool_relay` |
| JOB-F24 *(v2.4)* | The client receives tokens attested by the witness and never acks | Provisional billing; JOB-T11; at the end of the window (24 h), definitive; contributions paid to lenders. Late contest: free retransmission, no refund | `f24_withheld_acks_with_witness_bill_provisionally_and_pay_lenders` |
| JOB-F25 *(v2.4)* | The lender lies about delivery | Attestation signed by the output node rejected (`INADMISSIBLE_PROOF`); a lender cannot be assigned as witness; nothing is billed | `f25_lender_cannot_attest_its_own_delivery` |
| JOB-F26 *(v2.4)* | Ack lost, failure, resume | The client declares what it received; the rest is contested and replayed; the resume starts at the delivered positions; the next cumulative ack covers the replay; each position billed once | `f26_lost_ack_then_resume_replays_without_double_billing` |
| JOB-F27 *(v2.4)* | Witness buffer lost, the client declares tokens not received | Rewind: missing and later outputs voided, price returned, awaiting contributions refunded; produced again by the next attempt, new generation | `f27_lost_replay_buffer_contest_refunds_and_rewinds` |
| JOB-F28 *(v2.4)* | Simultaneous disconnection: silent client and lease expired at the same deadline; then node and witness lost in the same second | A single transition wins, a single revocation; attested outputs stay due but can no longer be replayed | `f28_simultaneous_client_silence_and_lease_expiry` |
| JOB-F29 *(v2.4)* | Silent cluster past the lease deadline | Production and heartbeat rejected (`LEASE_EXPIRED`) before any revocation; reconciliation revokes | `f29_expired_lease_rejects_work_until_reconciliation_revokes` |
| JOB-F30 *(v2.4)* | The client lies on resume | Declaring more than delivered or less than validated: rejected; contesting an output of the live attempt: rejected (retransmission) | `f30_client_cannot_overstate_or_unconfirm_or_contest_live_output` |
| JOB-F31 *(v2.4)* | Contest after the delivery window (24 h) | Retransmission if the buffer exists, with no contest and no accounting entry; buffer lost: rejected, the output stays due | `f31_contest_after_window_replays_but_never_refunds` |
| JOB-F32 *(v2.4)* | Rewind while a resume is already running | The resume, built on voided outputs, is revoked and restarts from the lost position; reduced flow budget until the client has signed | `f32_rewind_revokes_live_attempt_built_on_voided_outputs` |
| JOB-F33 *(v2.5)* | Signed client liveness signal without receipt of the replay | No resolution; at the deadline, contested and later outputs refunded | `f33_signed_heartbeat_without_replay_receipt_is_refunded` |
| JOB-F34 *(v2.5)* | Signed cumulative ack covering the replay | Definitive billing; nothing refunded at the deadline | `f34_cumulative_ack_covering_the_replay_bills_definitively` |
| JOB-F35 *(v2.5)* | Attestation or declaration from another session | Rejected `INADMISSIBLE_PROOF`, state unchanged | `f35_declaration_or_attestation_from_another_session_is_rejected` |
| JOB-F36 *(v2.5)* | Witness presenting a frame different from the signed digest | Rejected `INADMISSIBLE_PROOF`, nothing billed | `f36_frame_different_from_the_signed_digest_is_rejected` |
| JOB-F37 *(v2.5)* | Commitment before revocation, full attestation while draining | Admissible: provisional billing | `f37_commitment_before_revocation_makes_late_attestation_admissible` |
| JOB-F38 *(v2.5)* | Commitment created after revocation, or attestation after draining | Rejected | `f38_commitment_after_revocation_or_attestation_after_drain_proves_nothing` |
| JOB-F39 *(v2.5)* | Contest at 23:59 | Buffer kept past 24 h; later positions wait; purge possible only after resolution | `f39_contest_just_before_window_end_keeps_the_buffer` |
| JOB-F40 *(v2.5)* | Cap at calendar boundaries and after refunds | 23:55 then 00:01: same window, dispute; a contest does not restore the quota; 24 h later, quota available | `f40_sliding_cap_holds_across_midnight_and_after_refunds` |
| JOB-F41 *(v2.5)* | Supplementary proof | Added before the deadline: paid; without a supplement: refunded at the deadline; after the deadline: rejected | `f41_supplementary_proof_before_deadline_is_paid_after_is_refused` |

## 5. Protocol

Status: **to be completed**. Messages follow from the transitions of section 2. The `gpu-protocol` crate already fixes the envelope, the size check, the error codes and anti-replay.

### Messages per transition

| Message | Direction | Transition | Minimal fields |
| --- | --- | --- | --- |
| `SubmitJob` | Client → coordinator | JOB-T01 | idempotency key, pool, model, class, max budget |
| `CancelJob` / `ResumeJob` | Client → coordinator | JOB-T15, JOB-T12 | job, idempotency key, top-up |
| `Assign` | Coordinator → node, witness | JOB-T04, JOB-T09 | job, attempt, lease\_id, role, layer range, neighbors, witness, flow budgets, expiry, `execution_intent`, signature |
| `AssignAck` / `AssignReject` | Node → coordinator | JOB-T05, JOB-T06 | lease\_id, restored positions per type, reason |
| `Heartbeat` | Node → coordinator | JOB-R31, JOB-T08 | node\_id, job, attempt, active leases, GPU state, seq |
| `LeaseRenew` / `Revoke` / `Release` | Coordinator → node | JOB-R05, JOB-R11, JOB-F05 | lease\_id, expiry or reason, `receipt_deadline` |
| `ActivationFrame` | Peer → peer | Execution | job, attempt, lease\_id, slice, seq, tensor (fixed binary format) |
| `Produced` | Output node → coordinator | JOB-R13, JOB-R25 | job, attempt, type, up to |
| `TokenAck` | Client → coordinator | JOB-R23 | job, attempt, type, positions validated up to, client signature |
| `DeliveryAttestation` | Witness → coordinator | JOB-R26, R27, R32 | job, attempt, type, delivered up to, chained digest of the frames signed by the output node (job, stream, model, type, position, generation), offset acknowledged at transport level, witness signature |
| `WitnessCommitment` | Witness → coordinator | JOB-R32 | job, attempt, type, attested up to; timestamped and numbered by the coordinator |
| `DeliveryConfirm` | Client → coordinator | JOB-R28, R33, R34 | job, type, confirmed position ("I hold exactly `0..confirmed`"), digest of the held prefix, client signature |
| `ClientHeartbeat` | Client → coordinator | JOB-R33 | job, client signature; covers no position |
| `EvidenceSupplement` | Lender → coordinator | JOB-R35 | slice, output, new proof |
| `Replay` | Witness → client | JOB-R28 | job, type, positions, original encrypted frames (byte for byte identical) |
| `Receipt` | Recipient → producer | JOB-R12 | slice, attempt, seq, content hash, signature |
| `ReceiptCommit` | Recipient → coordinator | JOB-R15 | attempt, producer, type, covered up to, digest; timestamped by the coordinator |
| `UsageReport` / `UsageAck` | Node ↔ coordinator | JOB-S03, JOB-F04 | slice, items (`contribution_id` or `recovery_work_id`) with proof, signature |
| `DisputeOpened` / `DisputeResolved` | Coordinator → parties | JOB-S04, JOB-S06 | slice, line, disputed amount, decision |
| `Checkpoint` | Cluster controller → storage | JOB-T10, JOB-T11 | job, attempt, positions, sampler state, caches if exportable |

### Fixed requirements

- **PROTO-001**: every message MUST carry a protocol version, a sender identifier, a sequence number and a signature. *(implemented: `Envelope`, `ReplayGuard`)*
- **PROTO-002**: a frame's size MUST be checked before any decoding. *(implemented: `check_frame`)*
- **PROTO-003**: a dynamic serialization format MUST NOT be used.
- **PROTO-004**: every rejection MUST have a stable code: `UNKNOWN_JOB`, `INVALID_TRANSITION`, `VERSION_CONFLICT`, `STALE_ATTEMPT`, `JOB_SETTLING`, `FLOW_BUDGET_EXCEEDED`, `WINDOW_NOT_COVERED`, `RECOVERY_BUDGET`, `INADMISSIBLE_PROOF` *(v2.4)*, `LEASE_EXPIRED` *(v2.4)*, `PRECONDITION_FAILED`, `LEDGER_REJECTED`, `FRAME_TOO_LARGE`, `REPLAY`, `MISSING_SIGNATURE`, `UNSUPPORTED_VERSION`. *(implemented: `domain_code`, `ProtoError::code`)*
- **PROTO-005**: a sequence number MUST be strictly increasing per sender; a replayed message is rejected before reaching the domain.
- **PROTO-006** *(new in v2.4)*: the attester of a `DeliveryAttestation` is the envelope signer, never a field of the message. *(implemented: `to_command`, test `delivery_attested_by_a_lender_is_inadmissible`)*
- **PROTO-007** *(v2.4)*: the stream to the client is end-to-end encrypted; the witness sees encrypted frames, not tokens. A replay resends the original frames: the client checks their digest against the attestation. *(not modeled: symbolic cryptography)*
- **PROTO-008** *(new in v2.5)*: the frame digest covers job, client stream identifier, model, type, position and billing generation; it is signed by the output node. A valid frame or declaration cannot be reused in another stream. *(modeled by an FNV-1a digest, checked by the domain and recomputed independently by the checker)*

**To decide**: Protobuf or a custom binary format; final size limits; tensor encoding.

## 6. Engine interface

Status: **to be completed**, unchanged since v2.2. The contract is defined as a Rust trait; Petals implements it through an IPC adapter.

```rust
trait Engine {
    fn describe(&self) -> EngineInfo;            // version, architectures, capabilities
    fn load_slice(&mut self, s: SliceSpec) -> Result<SliceHandle, EngineError>;
    fn execute(&mut self, h: SliceHandle, input: Activations, pos: Position) -> Result<Activations, EngineError>;
    fn cancel(&mut self, h: SliceHandle) -> Result<(), EngineError>;
    fn metrics(&self) -> EngineMetrics;
    fn unload(&mut self, h: SliceHandle) -> Result<(), EngineError>;
    // Optional, declared in EngineInfo.capabilities
    fn snapshot_session(&self, h: SliceHandle) -> Result<SessionState, EngineError>;
    fn restore_session(&mut self, s: SessionState) -> Result<SliceHandle, EngineError>;
    fn set_sampler_state(&mut self, st: SamplerState) -> Result<(), EngineError>;
}
```

- **ENGINE-001**: capabilities declared in `describe`; an undeclared optional method returns `Unsupported`, never a simulation.
- **ENGINE-002**: `load_slice` checks the slice hash against the signed manifest.
- **ENGINE-003**: a `SessionState` is restored only on an identical engine, version, quantization and hash.
- **ENGINE-004**: the engine has no network access.
- **ENGINE-005**: without session export, resume by recomputation; without sampler control, sampling on the client or cluster controller side.
- **ENGINE-006** *(new)*: `AssignAck` MUST declare the restored positions per type; JOB-T05 compares them exactly with the validated positions.

## 7. Accounting

Status: **implemented in the model** (`gpu-ledger`); PostgreSQL persistence is still to be written.

### Accounts

| Account | Role |
| --- | --- |
| `Issuance` | The only account that creates credits; the only account allowed to be negative |
| `Burn` | Destroyed credits |
| `User(account)` | Available balance |
| `PoolReserve(pool)` | Pool treasury (bootstrap, recovery relay) |
| `EscrowWork(job)` | "Work" escrow |
| `EscrowRecovery(job)` | "Recovery" escrow (borrower budget + pool relay) |
| `OutputHold(job)` | Price of billed outputs (definitive and provisional), waiting to be split between contributions |
| `SliceLine(job, attempt, slice, lender)` | Reserve of a line (`pending_evaluation + disputed`) |
| `PendingReward(job, attempt, slice, lender)` | Held reward (`held`) |
| `Commission` | Commissions |

### Requirements

- **LEDGER-001**: every entry has a source account, a destination account, an amount, a unique idempotency key and a reason.
- **LEDGER-002**: append only; a correction is a reverse entry.
- **LEDGER-003**: only `Issuance` creates credits.
- **LEDGER-004**: the sum of all accounts is zero (negative `Issuance` = total issued).
- **LEDGER-005**: no account other than `Issuance` is negative; otherwise the entry is rejected (in the database: a constraint, not just code).
- **LEDGER-006**: each entry is chained by digest to the previous one (the model uses FNV-1a; production MUST use SHA-256 or BLAKE3).
- **LEDGER-007**: an invariant check runs continuously and blocks any new issuance on a discrepancy.
- **LEDGER-008** *(new)*: the commission is taken when a reward is released, never before.
- **LEDGER-009**: amounts are integers in the smallest unit; never floats.
- **LEDGER-010** *(new in v2.4)*: voiding a provisional output is a reverse entry (billed outputs → work escrow), never a deletion. Billing and void keys include the generation: `charge/{job}/{type}/{position}/{generation}`, `void/…/{generation}`.

## 8. Orchestration

Status: **to be completed**, unchanged since v2.2 (ORCH-001 to ORCH-006). The model has no scheduler: placements are commands.

## 9. Conformance tests

### 9.1 Properties (generated by `proptest`)

Checked after **every** command on random sequences of commands, failures, duplicates, concurrent versions, stale messages, fabricated receipts, clock jumps and adversarial delivery behavior, then at the end of the sequence after a drain phase. Four generators: general random, failure-heavy, partial reserve, and `delivery` (I-03).

| ID | Property | Requirements |
| --- | --- | --- |
| TEST-P01 | No transition outside the table, for jobs or slices | Section 2 |
| TEST-P02 | Ledger: zero sum, no negative, recomputable balances, chain intact, append only | LEDGER-001 to 006 |
| TEST-P03 | Net billing of an output ∈ {0, 1} at all times; a contribution reserved and paid once | JOB-R14, R17, R21 |
| TEST-P04 | No unit or ack accepted outside the live attempt; no contribution paid on an attempt other than its output's | JOB-R05, R11, R21 |
| TEST-P05 | Billed positions = exactly `[0, delivered)`; `validated ≤ delivered`; validated positions never go back | JOB-R23, R27 |
| TEST-P06 | Once activity stops, every job ends terminal and settled, every slice final, without human intervention | JOB-R08, R20 |
| TEST-P07 | Every (re)start begins exactly at the **delivered** positions; `execution_intent` never goes back to `initial` | JOB-T04, T05, T12 |
| TEST-P08 | A "committed" payment is covered by a commitment prior (in log order) to the revocation and the closure, recomputed independently of the domain code; *(v2.5)* over any 24 h interval, the gross sum of payments on uncommitted receipts, recomputed from the log, does not exceed the cap | JOB-R12, R15, R19 |
| TEST-P09 | Unvalidated window ≤ flow budget, per type; live production is never behind the delivered positions | JOB-R13 |
| TEST-P10 | No payment without proof, except by arbitration | JOB-R06 |
| TEST-P11 | `settling` only leads to `completed` | JOB-T14 to T16 |
| TEST-P12 | Line invariants and consistency with the `SliceLine` and `PendingReward` accounts | JOB-R22, R24 |
| TEST-P13 | Settlement closed ⇒ escrows and billed outputs at zero, slices final, execution terminal | JOB-S12 |
| TEST-P14 | Reserved recovery ≤ earmark; paid recovery ≤ credits put into the recovery escrow | JOB-R18 |
| TEST-P15 *(new)* | Sum of an output's paid contributions ≤ output price | JOB-R21 |
| TEST-P16 *(new)* | A rejection does not change the state; an idempotent command changes nothing; no internal error | JOB-R01, R04 |
| TEST-P17 *(new, CE-02)* | Borrower budget used before the pool relay; at closure, each gets back exactly its unused share | JOB-R18 |
| TEST-P18 | Units produced and not billed by the live attempt are always covered by the work escrow | JOB-R25 |
| TEST-P19 *(v2.4)* | Output registry consistent with the log; definitive prefix then provisional suffix; every validated position is definitive | JOB-R17, R27, R29 |
| TEST-P20 *(v2.4, extended in v2.5)* | Basis of every billing, recomputed independently: provisional only on an attestation by the assigned, independent witness, with the exact digest of the stream's frames and, if late, covered by a commitment prior to the revocation while draining; definitive only on a client signature covering the position and bound to the stream, or a window that really expired; void only of a provisional output, on a client declaration or at a contest deadline | JOB-R26 to R29, R32, R34 |
| TEST-P21 *(v2.4)* | Bounded exposure: `delivered − validated ≤ K` per type, for the whole job | JOB-R13, R27 |
| TEST-P22 *(v2.4)* | No contribution paid while its output is provisional; a contribution of a voided billing is refunded; an awaiting contribution concerns an output that is still provisional | JOB-R30 |
| TEST-P23 *(v2.4)* | **Fairness**, at the end of the drain: no valid claim lost at closure; every contribution proven by a prior commitment and funded is paid, and its reward released or contested; an uncommitted receipt is refunded only by arbitration | JOB-R06, R12, R19, R22 |
| TEST-P24 *(v2.4)* | Nothing is accepted under an expired lease; after a reconciliation, no live attempt has an expired lease; a lease is never extended beyond one TTL | JOB-R31 |
| TEST-P25 *(v2.4)* | A billed position is never recomputed: delivered positions are replayed, not regenerated; a live attempt is never built beyond the delivered positions | JOB-R28 |
| TEST-P26 *(v2.5)* | Replay buffer never purged before 24 h after the revocation, nor while an output of the attempt is provisional or contested | JOB-R28 |
| TEST-P27 *(v2.5)* | A contest opens once, on a signed declaration, during the window; a contested output becomes definitive only through a client signature covering its position; the window never confirms a contested output; no due contest survives reconciliation | JOB-R33 |
| TEST-P28 *(v2.5)* | No refund for missing proof before the evaluation deadline; no supplementary proof after it | JOB-R35 |

**Results**: see `TEST_REPORT.md` for the reference run, the counterexample search and the full mutation campaign.

### 9.2 Deterministic scenarios

JOB-F01 to JOB-F41: one test each (table in section 4; JOB-F18 has two), plus the targeted tests of the v2.3 fixes (`r21_*`, `r22_*`, `r24_*`). Each scenario goes through the full checker and ends with the drain phase, which also checks fairness (TEST-P23).

### 9.3 Non-regression

Every counterexample found is kept twice: the raw seed in `tests/properties/proptest-regressions.txt` (replayed first on every run) and a shrunk, commented version in `tests/regressions/` (CE-01 to CE-06). These tests are never deleted. In v2.5, two of them were adapted to the new JOB-R35 rule without changing what they show: CE-03 now checks that the item is never paid, then that it is refunded at the deadline.

### 9.4 Tests on a real cluster (to come)

- **TEST-G01**: unplug one GPU out of 4 while a 70B model generates; resume without losing any validated position.
- **TEST-G02**: replay the same slices on various GPUs and quantizations to calibrate numerical tolerances.
- **TEST-G03**: simulated RTT from 2 to 50 ms and packet loss.
- **TEST-G04**: simulated cheating node; detection measured.

## 10. Decisions and model limits

### Decisions taken

- **I-03** (v2.4): proof of delivery and replay.
- **v2.5**: the decisions in the changelog (witness reputation, 24 h window, closure by a cumulative ack bound to the stream, frame digest, committed late attestations, supplementary proofs until the deadline, sliding cap on gross amounts).
- **After the v2.5 audit**:
  1. **Contest resolution deadline**: 1 h, to be calibrated with the network prototype.
  2. **Replay buffer (I-20)**: kept at least 24 h after revocation and as long as a contest is open; its storage is paid from the pool's infrastructure fees. A witness that disappears for good is treated as a lost buffer.
  3. **Witness reputation**: a score built from availability, integrity (attestations later refunded, random checks) and confirmed disputes; per-witness exposure limits in the public phase.
  4. **Contribution refunded for missing proof**: final after the evaluation deadline; it stays taken and can no longer be claimed.

### Open points

- **Aggregated exposure cap**: the `K` bound holds per job and per type. Before opening to the public, add a cap on total exposure per account and per pool across concurrent jobs.
- Delivery guarantees still have to be measured on the network prototype: witness latency, buffer storage cost, resumes after reconnection, forged attestation attempts.

### Limits of the executable model

- No outbox or persistence: atomicity (JOB-R01) is shown in memory, not event delivery (JOB-R02).
- Leases: deadline and heartbeat are modeled on the coordinator clock; node clock drift (the JOB-R31 margin) is not.
- Witness: attestation, commitment, buffer and replay are commands. Transport acks, end-to-end encryption, signatures and byte-for-byte equality of replayed frames are symbolic; the digest is FNV-1a, not a cryptographic hash. **Delivery guarantees still have to be confirmed on real network exchanges (QUIC prototype, next step).**
- No scheduler, no network, no engine: placements, productions and acks are commands.
- Liveness and fairness are checked by a drain phase on finite traces, not proven for all traces (which TLA+ would do).
- The anti-collusion cap is lowered to 4 credits in the simulation so that disputes get exercised.
