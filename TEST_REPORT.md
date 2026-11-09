# Test report — executable model v2.5

November 9, 2026 · More 0.3.0 · implementation specification v2.5

## Summary

All **67 tests** of the suite pass. The four property tests ran on 5,009, 5,009, 2,509 and 5,009 random traces (the 9 extra traces are the regression seeds, replayed first). That is **1,998,359 commands**, each followed by the full check of the 28 properties. The total and every coverage figure come from that run: the tests write them themselves to `target/coverage/`.

v2.5 integrates the six decisions taken after the v2.4 audit. In particular, a delivery contest closes **only** through a signed cumulative ack, bound to the stream and covering the position; otherwise it is refunded at the deadline. The eight requested cases each have a deterministic scenario (JOB-F33 to F41), and they are also exercised by the random generators and checked by properties (TEST-P08 extended, P20 extended, P26 to P28).

The model found **1 real counterexample** in the v2.5 design (CE-06), fixed in the spec and the code and turned into a permanent test. The mutation campaign, rerun in full with the final generator, caught **51 of 52 injected bugs**; the one it missed (M50) is now caught after a scenario was strengthened (section 2).

What this does not show: delivery guarantees on a real network. The witness, transport acks, signatures and digests are still symbolic, hence the QUIC prototype. Neither the outbox, nor clock drift, nor liveness on every trace (TLA+) are covered.

## 1. Reference run

```
cargo clean
PROPTEST_CASES=5000 cargo test --release --workspace
python3 scripts/mutation.py
```

Rust 1.97.0, Linux, `release` profile. Suite duration including compilation: 48 s (properties: 18.8 s). Mutation campaign: about 40 min.

| Suite | Tests | Result |
| --- | --- | --- |
| `gpu-ledger` (unit) | 5 | 5 passed |
| `gpu-protocol` (unit) | 4 | 4 passed |
| `tests/properties` | 5 | 5 passed |
| `tests/scenarios` | 46 | 46 passed |
| `tests/regressions` | 7 | 7 passed |
| **Total** | **67** | **67 passed, 0 failed** |

During v2.5 development, a counterexample search with 20,000 traces per generator (more than 7 million commands) found none. It was not rerun for this report.

### Volume and coverage measured during the reference run

| Measure | General | Failures | Partial reserve | Delivery | Total |
| --- | --- | --- | --- | --- | --- |
| Traces | 5,009 | 5,009 | 2,509 | 5,009 | 17,536 |
| **Commands run and checked** | 457,580 | 626,066 | 293,877 | 620,836 | **1,998,359** |
| accepted | 296,321 | 429,922 | 206,402 | 465,682 | 1,398,327 |
| Resumes (`running → recovering`) | 2,852 | 8,530 | 3,938 | 13,156 | 28,476 |
| Outputs charged on ack | 460 | 1,768 | 734 | 669 | 3,631 |
| Outputs charged provisionally (witness) | 428 | 2,114 | 891 | 2,447 | 5,880 |
| Late attestations admitted (JOB-R32) | 39 | 290 | 126 | 256 | 711 |
| Delivery contests opened, with replay (JOB-R33) | 9 | 189 | 62 | 261 | 521 |
| Provisional confirmed by the client | 198 | 1,371 | 492 | 1,211 | 3,272 |
| Provisional confirmed by window expiry | 226 | 681 | 372 | 506 | 1,785 |
| Rewinds (buffer lost or contest due) | 4 | 39 | 22 | 437 | 502 |
| Outputs voided | 4 | 62 | 27 | 730 | 823 |
| Buffers purged after retention (JOB-R28) | 90 | 206 | 65 | 448 | 809 |
| Supplementary proofs (JOB-R35) | 13 | 245 | 84 | 83 | 425 |
| Contributions awaiting delivery | 546 | 2,541 | 1,092 | 2,764 | 6,943 |
| Contributions voided with their output | 4 | 36 | 38 | 394 | 472 |
| Contribution payments | 689 | 3,537 | 1,437 | 2,745 | 8,408 |
| Recovery payments | 89 | 764 | 297 | 633 | 1,783 |
| Items refunded for missing proof (at the deadline) | 249 | 1,633 | 604 | 737 | 3,223 |
| Items disputed (sliding cap exceeded) | 18 | 292 | 117 | 104 | 531 |
| Payments by arbitration | 4 | 90 | 33 | 13 | 140 |
| Refunds by arbitration | 14 | 202 | 84 | 91 | 391 |
| Reward contests | 13 | 235 | 85 | 120 | 453 |
| Rewards released | 331 | 2,037 | 825 | 1,691 | 4,884 |
| `INADMISSIBLE_PROOF` rejections (witness, digest, other session, uncommitted late) | 1,933 | 1,949 | 846 | 11,540 | 16,268 |
| `LEASE_EXPIRED` rejections | 5,977 | 28,718 | 12,851 | 18,387 | 65,933 |

**Reading**: every new v2.5 mechanism is exercised hundreds of times, except payments by arbitration (140). The coverage check requires at least 5 passes for that path and for supplementary proofs, over its 600 traces. These two floors were lowered from 10 to 5, and the one for refunds by arbitration from 20 to 10, because the new operations with large time jumps (24 h) dilute those paths. The real counts are in the table.

### The eight requested cases

| Case | Scenario | Exercised by the generator | Property |
| --- | --- | --- | --- |
| Signed liveness signal without receipt of the replay: refund | JOB-F33 | `ClientHeartbeat`, `ContestReplay` | TEST-P27: only a signature covering the position confirms a contested output; no due contest survives reconciliation |
| Signed cumulative ack covering the replay: definitive | JOB-F34 | `ContestReplay` then a full declaration | TEST-P20, TEST-P27 |
| Ack from another session: rejected | JOB-F35 | digests of another job on `Deliver` and `Confirm` | TEST-P20 (digest recomputed independently) |
| Frame different from the signed digest: rejected | JOB-F36 | altered digest on `Deliver` | TEST-P20 |
| Commitment before revocation, attestation while draining: admissible | JOB-F37 | `LateDeliver` with commitment | TEST-P20 (log order recomputed) |
| Commitment after revocation: rejected | JOB-F38 | `LateDeliver` without commitment or with a late one | TEST-P20 |
| Contest just before 24 h: buffer kept | JOB-F39 | `ContestAtWindowEnd` (contest at 23:59 then purge) | TEST-P26 |
| Cap at calendar boundaries and after refunds | JOB-F40 | `BoundaryBurst` (receipts before midnight, contest, receipts after) | TEST-P08 (gross sum over any 24 h window, recomputed from the log) |

### Non-regression (7)

| Test | Origin |
| --- | --- |
| `ce01_*` to `ce05_*` (6 tests) | v2.3 and v2.4. `ce03_*` adapted to JOB-R35 without changing what it shows: the item is never paid, then it is refunded at the deadline |
| `ce06_awaiting_contribution_reverting_to_pending_keeps_slice_open` | CE-06, found on the first v2.5 run by two generators |

The seed file holds 9 real counterexamples: 7 earlier ones and 2 from CE-06. The mutation script restores it after each mutant.

## 2. Mutation campaign

52 bugs put back one at a time: the 38 of v2.4, with two anchors adjusted to the v2.5 code (M20, M28), and 14 new ones, M37 to M50. The coverage check does not count as a detection. Campaign rerun in full on the final code and generator; the log is reproduced below.

| Mutation | Injected bug | Caught by |
| --- | --- | --- |
| M01 | v2.1 bug: JOB-T04 resets execution_intent to initial | TEST-P07 |
| M02 | v2.1 bug: contribution payable on another attempt | scenario only: `f20_*` |
| M03 | v2.2 bug: contribution id without layer range | TEST-P23 |
| M04 | v2.2 bug: no pending_evaluation at closure | TEST-P12 |
| M05 | Contest that creates credits | TEST-P12 |
| M06 | Cancel allowed while settling | scenario only: `f09_*` |
| M06b | Cancel allowed while settling (transition table too) | TEST-P11 |
| M07 | Flow control disabled | TEST-P09 |
| M08 | Anti-collusion cap ignored | TEST-P08 |
| M09 | Late commitment accepted as prior | TEST-P08 |
| M09b | CE-03 back: bound = revocation, not slice closure | TEST-P08 |
| M10 | Settlement forgets OutputHold | TEST-P13 |
| M11 | CE-01 back: pool relay without active escrow | TEST-P13, TEST-P17 |
| M12 | CE-02 back: pool share returned to the borrower | TEST-P17 |
| M13 | Resume without state restore | TEST-P07, TEST-P25 |
| M14 | Work accepted on a revoked attempt | TEST-P04 |
| M15 | Reconciliation without default dispute arbitration | TEST-P06, TEST-P23 |
| M16 | Unvalidated window coverage disabled (JOB-R25) | TEST-P18 |
| M17 | Pool relay used before the borrower budget | TEST-P17 |
| M18 | Recovery not capped by the earmark | TEST-P06, TEST-P14, TEST-P16 |
| M19 | Flow budget measured from delivered positions (colluding witness unbounded) | TEST-P09 |
| M20 | Attestation from someone other than the assigned witness accepted | TEST-P20 |
| M21 | Non-independent witness accepted at placement | TEST-P20 |
| M22 | Contribution evaluated while its output is provisional | TEST-P22 |
| M23 | Rewind without cascade: only the lost position is voided | TEST-P05 |
| M24 | Rewind without revoking the live attempt | TEST-P25 |
| M25 | Work accepted under an expired lease | TEST-P24 |
| M26 | Reconciliation does not revoke expired leases | TEST-P24 |
| M27 | Heartbeat renews an expired lease | TEST-P24 |
| M28 | Delivery window closed without waiting for revocation | TEST-P20 |
| M29 | Client may confirm beyond delivered | TEST-P16 |
| M30 | Resume from validated positions: delivered ones are regenerated | TEST-P09 |
| M31 | CE-04 back: already decided item evaluated twice | TEST-P06, TEST-P16, TEST-P23 |
| M32 | CE-05 back: zero reward never closed | TEST-P23 |
| M33 | Closure loses claims (fairness) | TEST-P23 |
| M34 | Proven contribution refunded when its output becomes definitive (fairness) | TEST-P23 |
| M35 | Automatic reward release disabled | TEST-P06, TEST-P23 |
| M36 | Attestation beyond produced accepted | TEST-P09, TEST-P21 |
| M37 | Contest closed by the replay alone | TEST-P20, TEST-P22 |
| M38 | Client liveness signal resolves contests | TEST-P20, TEST-P22 |
| M39 | Frame digest not checked on attestation | TEST-P20 |
| M40 | Client declaration not bound to the stream | scenario only: `f35_*` |
| M41 | Late attestation without prior commitment | TEST-P20 |
| M42 | Commitment accepted after revocation and counted as prior | TEST-P20 |
| M43 | Buffer purged despite an open contest | TEST-P26 |
| M44 | Per-calendar-day cap instead of a sliding window | TEST-P08 |
| M45 | Refund restores the quota (net amounts) | scenario only: `f40_*` |
| M46 | Refund for missing proof before the deadline | TEST-P28 |
| M47 | Expired window ignores contests | TEST-P20, TEST-P27 |
| M48 | Contest deadline never enforced | TEST-P06, TEST-P27 |
| M49 | CE-06 back: slice finished before the deadline with an awaiting contribution | TEST-P12 |
| M50 | Supplementary proof accepted after the deadline | **missed** in the full campaign; caught after the fix below |

**51 of 52 caught in the full campaign, 47 of them by properties. With the fix to JOB-F41 described below, 52 of 52.**

The mutants not caught by a property:

- **M50 was missed.** In the v2.5 campaign it had been caught by TEST-P28, but only by chance: the deadline check it removes is reachable only between the evaluation deadline and the next reconciliation, a window the generator rarely hits, and JOB-F41 tested the late proof only after reconciliation had already finalized the slice. JOB-F41 now sends a proof right at the deadline, before reconciliation, and expects a rejection. Rerun of M50 alone after that change: caught by `f41_*`.
- **M06** only changes an error code without breaking an invariant: only a scenario can see it, as expected.
- **M02, M40 and M45** were caught by properties in earlier runs (M02 by TEST-P04, M40 by TEST-P20, M45 by TEST-P08), but not in this one at 300 traces per mutant. Their scenarios caught them. These three, like M50, show that a property seeing a bug in some runs is not a guarantee; each has a deterministic scenario for that reason.


## 3. Invariants

### Checked

TEST-P01 to TEST-P25 as in v2.4 (details in the spec, section 9.1), with these changes:

| ID | v2.5 change |
| --- | --- |
| TEST-P08 | **Sliding** cap: over any 24 h interval, **gross** sum of payments on uncommitted receipts ≤ cap, recomputed from the payment log (not from the domain counter) |
| TEST-P20 | An attestation must carry the exact digest of the stream's frames, recomputed independently; a late attestation must be covered by a commitment prior to the revocation, while draining; a client confirmation must cover the position and be bound to the stream |
| TEST-P26 *(new)* | Buffer never purged before 24 h after the revocation, nor while an output of the attempt is provisional or contested |
| TEST-P27 *(new)* | Contest opened once, on a signed declaration, during the window; contested output confirmed only by a signature covering its position; the window never confirms a contested output; no due contest after reconciliation |
| TEST-P28 *(new)* | No refund for missing proof before the evaluation deadline; no supplementary proof after it |

### Still to show

| Point | Why | How |
| --- | --- | --- |
| Delivery guarantees on a real network | Witness, transport ack, signatures, digests and replay are symbolic | Three-process QUIC prototype (next step) |
| Replay buffer cost | Not measured | Prototype: large outputs, batch, thousands of sessions |
| Event delivery (outbox) | No persistence | PostgreSQL + outbox |
| Node clock drift | A single clock | TLA+ or bounded local clocks |
| Liveness and fairness on every trace | Checked on finite traces | TLA+ |
| Fairness of recovery | TEST-P23 only covers contributions | Extend P23 |
| Aggregated exposure | `K` bounds each job; nothing bounds the total over concurrent jobs of one account or pool | Cap per account and per pool, before opening to the public |

## 4. Inconsistencies found (v2.5)

| Ref. | Found by | Problem | Fix |
| --- | --- | --- | --- |
| CE-06 | proptest, TEST-P12, on the first run | A slice finished its evaluation before the deadline with a contribution waiting for its output. Once the output became definitive, the contribution without proof went back to "awaiting proof" in a slice already evaluated | JOB-S04: before the deadline, the slice does not finish while a contribution waits for its output |
| I-17 | JOB-F39 | Positions following a contested position depend on it: the window cannot confirm them | JOB-R29: expiry stops at the first contested position |
| I-18 | v2.4 audit | A replay made the output definitive without proof of receipt | JOB-R33 |
| I-19 | JOB-R14 and JOB-R35 | "Single evaluation" can no longer mean "in one command" | Each item decided once; the slice finishes once, at the latest at the deadline |
| I-20 | Buffer cost | Not negligible for large outputs | Decided: paid from pool infrastructure fees (spec, section 10) |

No invariant was weakened to make a test pass. Several older tests had to follow the new rules, without their intent changing:
- CE-03 and JOB-F17: refund at the deadline, no longer at evaluation;
- JOB-F24 and F31: 24 h window;
- JOB-F26: a replay stays contested until the ack;
- JOB-F27: the slice stays closed before the deadline, a consequence of CE-06;
- JOB-F17 and F21: now explicitly configured with the 8-credit cap they were written for, the simulation moving to 4.

## 5. Decisions taken after the v2.5 audit

Detailed in section 10 of the spec: contest resolution in 1 h, replay buffer kept at least 24 h and while a contest is open and paid from pool infrastructure fees, a witness reputation score (availability, integrity, confirmed disputes), and a contribution refunded for missing proof that becomes final after the deadline.

## 6. Next steps (agreed order)

1. Real witness prototype: three processes (output node, witness, client) over QUIC, authenticated frames, verified signatures, application acks, exact replay, simulated network loss, then the same adversarial cases as JOB-F33 to F41.
2. TLA+: safety and liveness, with explicit assumptions on permanent failures and malicious participants.
3. PostgreSQL + outbox: same transitions, atomicity, idempotency and restarts on a real database.
