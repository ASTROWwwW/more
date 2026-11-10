# Security architecture

This document sets the trust boundaries of More, who may do what, and what each boundary is made of. It is written against a precise threat model: **any component can be compromised on its own**, and the damage it can do must stay bounded by its own permissions.

The repository today is a single Rust process: an executable model of the coordinator, with no network, no database and no GPU engine. The boundaries below therefore exist at two levels, and this document always says which one applies:

- **Enforced now**: checked by the compiler (private types and fields, capability values that cannot be built outside their crate) or by code on every call (authentication of the caller, per-operation and per-resource authorization, input validation), and covered by tests, including simulated compromise tests.
- **Deployment target**: process, OS and database isolation. It is specified here so the future services are built to it, but nothing in this repository runs it yet. A target is never presented as a protection that exists.

Section 7 lists both, boundary by boundary.

## 1. Trust domains

```text
                         ┌──────────────────────────────┐
  borrowers, lenders,    │  Identity / Auth             │  keys of users and services,
  witnesses (signed) ───►│  verifies signatures,        │  service credentials,
                         │  mints AuthContext           │  revocation
                         └──────────────┬───────────────┘
                                        │ AuthContext (verified principal)
                                        ▼
 ┌────────────────┐  catalog,  ┌──────────────────────────────┐  typed ledger ops,  ┌───────────────────┐
 │ Model Registry │  tariffs   │  Job Orchestrator            │  own credential     │  Ledger           │
 │ pools, members,├───────────►│  authorizes each command per │────────────────────►│  only writer of   │
 │ models, prices │  (read)    │  resource, runs transitions, │  (no generic        │  balances; checks │
 └────────────────┘            │  scheduler, reconciliation   │   transfer)         │  caller, op, flow,│
                               └───────┬──────────────▲───────┘                     │  mandate, limits  │
                                       │ leases       │ attestations,               └───────────────────┘
                                       ▼              │ commitments                          ▲
                               ┌──────────────┐  ┌────┴─────────────┐                        │ issuance only
                               │  GPU Agent   │  │ Delivery/Witness │               ┌────────┴────────┐
                               │  (lender     │  │ relays encrypted │               │ Treasury        │
                               │  machine,    │  │ frames, attests, │               │ (issuance)      │
                               │  sandboxed)  │  │ keeps buffer     │               └─────────────────┘
                               └──────────────┘  └──────────────────┘
```

| Domain | Responsibility | Holds | Never holds |
| --- | --- | --- | --- |
| Identity / Auth | Registers principals (users, services), verifies signatures, mints `AuthContext` and service credentials, revokes them | Public keys of users; the authority key that mints service credentials | Balances, jobs, deliveries |
| Job Orchestrator | Job state machine, placement (scheduler), slices, settlement decisions, reconciliation. Authorizes every command against the resource it touches | Its own ledger credential (Orchestrator role) | Issuance rights; user private keys; a generic transfer |
| Ledger | The only code that changes balances. Accepts typed operations only, checks the calling service, the operation, the accounts, the borrower's signed mandate, amount limits; logs every decision | Balances, journal, escrow ownership and mandates, the users' public keys it needs to verify mandates | Job logic; any way to move credits outside the allowed flows |
| Delivery / Witness | Witness nodes relay the encrypted stream, attest transport delivery, keep the replay buffer. The delivery rules (attestation, contest, rewind) only decide output states | Its own signing key; encrypted frames | Ledger access; coordinator secrets; plaintext tokens |
| Model Registry | Pools, membership and rights, model catalog, tariffs set by the pool | Pool admin decisions | Balances; job state |
| GPU Agent | Runs a layer range in a sandbox, sends heartbeats, production counters, receipts | Its node key, model weights it was assigned | Ledger access, coordinator secrets, database credentials, other users' data |

## 2. Principals and credentials

| Principal | How it is authenticated now | Target |
| --- | --- | --- |
| User account (borrower, lender, witness, pool admin) | Ed25519 signature on every protocol envelope, verified against the key registered in Identity (`gpu-protocol`, `more-identity`) | Same, over QUIC with mutual authentication of the transport |
| Service (Orchestrator, Reconciler, Scheduler, Treasury, Clock, Platform admin, Auditor, Delivery) | `ServiceCredential`: a value only `more-identity` can mint, carrying a service id and a role, signed by the identity authority (Ed25519). Verifiers hold the authority's public key only, so checking a credential never gives the power to mint one. Each service has its own credential; there is no shared global secret. Tag and revocation are checked on every ledger call and every coordinator command | Separate processes, mTLS client certificates per service, short-lived tokens |

A user role is never a property of the account alone. It comes from the resource: a borrower is the borrower **of this job**, a lender is a lender **of this attempt**, a witness is the witness **assigned to this attempt**, and pool rights (borrow, lend, witness, admin) are granted per pool by its admin.

## 3. Permission matrix

Commands of the coordinator (`gpu-domain::Command`). A cell lists who may send the command and the resource condition checked before any mutation. Anything not listed is denied (fail closed).

| Command | Allowed principal | Resource check |
| --- | --- | --- |
| `Tick` | Clock service | — |
| `Issue` | Treasury service | Credential forwarded to the Ledger, which checks the Treasury role itself |
| `CreatePool` | Platform admin | — |
| `SetRights` (grant or remove rights) | Pool admin, Platform admin | Admin of that pool |
| `JoinPool` | The joining account itself | Open pools only; grants borrow and lend, never witness |
| `RegisterModel` (catalog, tariff) | Pool admin | Admin of that pool |
| `Submit` | User | `borrower` = caller; caller has the borrow right in the pool; model in the pool's catalog; price taken from the tariff, never from the request; estimated cost ≤ the budget the borrower signed |
| `Reserve`, `RejectQueued`, `CloseSlice`, `Evaluate`, `NodeLost`, `RecoveryTimeout`, `CompleteSettling`, `Settle`, `ExpirePause`, `ExpireDeliveryWindow`, `ResolveContests`, `Fail` | Scheduler or Reconciler service | — |
| `Reconcile` | Reconciler service only | A due transition refused inside reconciliation is an internal error, not skipped (CE-07) |
| `Place` | Scheduler service | Lenders distinct, each with the lend right in the job's pool; witness with the witness right, independent of lenders and borrower; layout covers exactly the model's layers |
| `AcceptLease`, `LeaseLoaded`, `AttemptReady`, `Heartbeat` | User | Caller is the lender the command names, and a lender of that attempt: a node speaks for its own lease only (JOB-R38, JOB-R39) |
| `WitnessHeartbeat` | User | Caller is the witness the command names, assigned to that attempt |
| `CorroborateRestore` | User | Caller is the recipient of the producer's stage; the producer never vouches for itself (JOB-R18) |
| `PresentReceipt` | User | Caller is the producer the receipt is about; the recipient's signature inside is checked by the Ledger |
| `PlacementFailed` | Lender of the attempt, Scheduler, Reconciler | — |
| `Produce`, `Finish` | Output node (last-stage lender) of the current attempt; `Finish` also Scheduler | — |
| `Ack`, `ConfirmDelivery`, `ClientHeartbeat`, `Resume` | User | Caller is the job's borrower |
| `Cancel` | Borrower of the job, Reconciler | — |
| `Pause` | Borrower (reason `Requested` only), Scheduler (`Preempted`, `LowEscrow`), Reconciler (`ClientSilent`) | — |
| `Deliver`, `WitnessCommit` | User | Caller is the witness assigned to the attempt (and equals the `witness` field) |
| `WitnessLost`, `PurgeBuffer` | Witness of the attempt, Reconciler | — |
| `CommitReceipts` | User | Caller is the recipient of the producer's stage: next-stage lender, or the witness for the output node. Commitment digest must match |
| `Claim`, `SupplementEvidence` | User | `lender` = caller, and caller is a lender of the slice's attempt |
| `Arbitrate` | Pool admin of the job's pool (pay or refund); Reconciler (default ruling, refund only) | — |
| `FundRecovery` | Pool admin of the job's pool | The admin's signature over the relay's new total, checked by the Ledger |
| `ReleaseReward` | Reconciler; the lender itself after the window | — |
| `ContestReward` | Borrower of the job; pool admin of the job's pool | — |

### Ledger API

The Ledger exposes no generic transfer. Each operation has fixed source and destination account kinds, and every account involved must belong to the same job, its owner, its pool or the lenders that signed its attempts. The Ledger does not rely on the orchestrator for who worked, what anything costs or where a refund goes: it keeps the terms the owner signed, the attempts their lenders signed, the receipts their recipients signed and the provenance of every reserve.

| Operation | Allowed service | Signed by | Checks done by the Ledger |
| --- | --- | --- | --- |
| `Issue` | Treasury | — | Amount within the per-issuance limit and the supply cap |
| `RegisterPool` | Platform admin | — | Once per pool: who administers its treasury |
| `OpenEscrow` | Orchestrator | Borrower | Mandate over (job, pool, model, layers, prices, outputs, max budget); one escrow per job |
| `Reserve` (work, recovery, top-up) | Orchestrator | — (covered by the mandate) | Source is the escrow owner's account; cumulative amount ≤ signed budget |
| `FundRecovery` | Orchestrator | Pool admin | Signature over the new running total of the relay for this job; the job's own pool only |
| `RegisterAttempt` | Orchestrator | — | Layout covers the signed model; lenders distinct; witness neither a lender nor the owner; earmark within the recovery budget not yet promised; attempts in increasing order |
| `AcceptLease` | Orchestrator | Lender of the stage | Signature over the registered assignment; attempt not revoked |
| `LeaseReady` | Orchestrator | Lender of the stage | Signature over the job, attempt, lender, restored positions, state commitment and one commitment per recovery segment (at most 64); lease accepted first; attempt not revoked |
| `Advance` | Clock | — | Time never goes back. The orchestrator cannot move it |
| `RecordRestore` | Orchestrator | Recipient of the producer | Signature over the job, attempt, producer, layer range, positions, state commitment and each segment received with the commitment the producer signed for it; segments named once, in order; lease ready first; attempt not revoked; written once, with its position in the Ledger's records |
| `RevokeAttempt` | Orchestrator | — | Once per attempt. Records the position of the revocation: no lease step and no corroboration is added to the attempt afterwards |
| `RecordReceipt` | Orchestrator | Recipient of the producer (next stage, or witness) | Signature by the account the assignment names; the same coverage with another digest is refused |
| `ChargeOutput`, `VoidOutput` | Orchestrator | — | Price from the signed terms; position within the signed maximum; one charge in force per output, billing generations in order; no void while a share is reserved or paid |
| `ReserveContribution` | Orchestrator | — | The lender signed that stage of that attempt; the output is charged to that attempt at that generation; once per output, charge and stage; share computed by the Ledger |
| `ReserveRecovery` | Orchestrator | — | Every lender of the attempt signed ready; within the attempt's earmark |
| `PayLine` | Orchestrator | — | Item reserved on that line; for a contribution, charge still in force and a receipt from the recipient covering the output; for recovery, the restoration corroborated by the lender's recipient for that segment; split borrower first, then pool, computed by the Ledger. Starts the item's contest window |
| `RefundLine` | Orchestrator | — | Back to where the Ledger recorded the reserve came from; no destination in the request |
| `ReleaseReward` | Orchestrator | — | Held reward → its own lender + commission; commission rate set by the Ledger; only the payments of the line that are at least 48 h old, by the Ledger's clock; the others stay held |
| `ContestReward` | Orchestrator | — | Held reward → the job's owner and pool; the pool's share is what the Ledger recorded; only the payments of the line that are less than 7 days old; the others stay held |
| `ReturnEarmark` | Orchestrator | — | No undecided recovery item on the attempt; closes its recovery budget |
| `SettleJob` | Orchestrator | — | No undecided item; pool share computed by the Ledger; afterwards nothing is written to the job's escrow, hold or lines |
| Read balances | Orchestrator (job accounts), Auditor (everything) | — | — |

## 4. Allowed flows of credits

```text
Issuance ──Treasury──► User / PoolReserve
User(owner) ──mandate──► EscrowWork(job), EscrowRecovery(job)
PoolReserve(pool of job) ──► EscrowRecovery(job)
EscrowWork(job) ◄──► OutputHold(job)
OutputHold(job), EscrowRecovery(job) ◄──► SliceLine(job, attempt, slice, lender)
SliceLine ──► PendingReward(same ids)
PendingReward ──► User(that lender) + Commission      (release)
PendingReward ──► User(owner) + PoolReserve(pool)     (contest)
EscrowWork, EscrowRecovery, OutputHold ──► User(owner), PoolReserve(pool)   (settlement)
```

There is no edge from a user account to another user account, from one job to another job, or into `Issuance`.

## 5. Compromise scenarios

| Compromised component | What it can still do | What stops the rest | Test |
| --- | --- | --- | --- |
| Delivery service or witness | Attest outputs that were produced but not received: provisional billing, at most `K` per type per job (JOB-R27) | Its credential has no ledger right and no coordinator command; issuance needs the Treasury role; contests and rewinds refund unproven outputs | `compromise_delivery_cannot_issue_or_move_credits` (ledger), `compromise_delivery_service_has_no_command` |
| GPU agent | Lie about its own work, stop, produce garbage | Every command is authorized per resource: it cannot cancel, ack or confirm someone else's job, renew another node's lease, or commit receipts for itself; it has no ledger access | `compromise_gpu_agent_cannot_cancel_other_jobs`, security scenarios |
| Scheduler | Make bad placements | Its credential cannot issue, pay a dispute, fund from a pool, contest for a borrower, submit for one, or take a lease step for a lender | `compromise_scheduler_cannot_move_balances`, `r2_lease_steps_are_ordered_personal_and_signed` |
| Orchestrator (holds the credential the Ledger accepts) | Charge outputs at the signed price (returned at settlement unless receipts exist); delay or refuse operations | The Ledger needs the borrower's signed terms to open and fill an escrow, the lender's signature to give it a line, the recipient's signature to pay a contribution, every lender's readiness and the recipient's corroboration to pay recovery, the pool admin's signature to touch the pool's treasury. It computes shares, splits and settlement itself, sends refunds back to their source, and refuses to settle with an open item | `crates/ledger/tests/authority.rs`, TEST-P30 (`crates/ledger/tests/hostile.rs`) |
| Treasury | Issue credits | Per-issuance limit and supply cap in the Ledger; every issuance is a journal entry | `issuance_limits_hold_near_u64_max`, `extreme_values_are_refused_without_panic` |
| A user account | Act as itself | Per-resource checks; a signature for one session or job cannot be reused (JOB-R34, replay guard); the generators send every kind of command from every principal (TEST-P29) | `tests/security/`, TEST-P29 |

Residual risks, stated plainly:

- **Orchestrator plus every recipient of a stage.** A receipt or a corroboration is what one account says it received from another. An attacker that also holds the next lender's key, or the witness's for the last stage, can have that stage's contributions paid, within what was charged to the borrower, and its recovery within the earmark. These signatures raise the number of accounts a fraud needs from one to two per stage; they do not prove that the computation happened. That takes a verification of the work itself, which More does not have yet. The borrower's contest and the anti-collusion cap bound it; the Ledger cannot.
- **Revocation as seen by the Ledger.** The Ledger closes an attempt's proofs when the orchestrator records the revocation. It does not see lease deadlines or pool rights: refusing a corroboration on an expired lease, or after a right was withdrawn, is done by the coordinator on its own log. A compromised orchestrator can skip that and delay the revocation record. It gains nothing without the recipient's signature, which is the case above.
- **Charges.** The Ledger does not see the delivery proof behind a charge. Without receipts an unproven charge pays nobody and goes back to the borrower at settlement, but it stays locked until then.
- **Liveness.** A compromised orchestrator can refuse to settle or to release. Nothing here prevents that; it is visible in the audit view.

## 6. Data separation

| Data | Owner | Who can read it now |
| --- | --- | --- |
| Balances and journal | Ledger | Orchestrator for job accounts it needs; Auditor read-only view |
| Signed terms, attempts and their signatures, receipts, items and their provenance, pool admins | Ledger | Ledger only; Auditor read-only view |
| User public keys | Identity | Identity, Ledger (mandate verification) |
| Service credentials | Identity mints, each service keeps its own | The service it was minted for |
| Jobs, attempts, slices | Orchestrator | Read accessors on `Coordinator`; every field private |
| Charges, contests, witness commitments | Delivery (`DeliveryBook`) | Read accessors; written only through `DeliveryBook` methods, which have no ledger access |
| Pools, members, catalog | Model Registry (`Registry`) | Read accessors; written only through `Registry` methods, which validate every input |
| Encrypted frames, replay buffer | Witness | Witness only (never decrypted by More) |

## 7. Boundary status

What each boundary is made of today. "In-process" means it holds against bugs and against misuse of the API by other code, not against an attacker who controls the process's memory.

| Boundary | Mechanism | Status |
| --- | --- | --- |
| Only the Ledger writes balances | `Ledger::transfer` is private to the ledger crate; the public API is `LedgerService::execute` with typed operations; a doc test proves the generic transfer does not compile from outside | Enforced now (compiler + tests) |
| Caller authentication on the Ledger API and the coordinator | `ServiceCredential` cannot be built outside `more-identity`; the Ledger and the coordinator check its tag and revocation on each call | Enforced now (in-process); mTLS between processes is the target |
| Issuance only by Treasury | Ledger permission matrix | Enforced now |
| Borrower consent to spending and to the job's terms | Ed25519 mandate verified by the Ledger | Enforced now |
| Lender, recipient and pool admin consent | Ed25519 statements verified by the Ledger (lease, readiness, receipt, relay) | Enforced now |
| Statements bound to one deployment | Every signed statement and every envelope carries the public key of the deployment's identity authority; the Ledger and the protocol edge compare it with their own verifier's | Enforced now |
| Proofs recorded before the revocation | The Ledger numbers its records and takes no lease step or corroboration once `RevokeAttempt` is recorded | Enforced now for attempt revocation; lease expiry and pool rights are checked by the coordinator only |
| Provenance of reserves, closure with no open item | Ledger records and checks, independent of the coordinator's | Enforced now (tests, TEST-P30 under a hostile orchestrator) |
| Final proofs, bounded contest cycle | Write-once records in the Ledger; its own clock, moved by the Clock credential only | Enforced now (TEST-P33, TEST-P30) |
| One lease per node | Per-stage state and expiry, authorized per sender | Enforced now (TEST-P24, TEST-P31) |
| Per-resource authorization of commands | `authorize` runs before any mutation; TEST-P29 checks every accepted command against an independent restatement of the matrix, on traces where any principal sends any command | Enforced now |
| Delivery and registry data owned by their module | Private fields in `DeliveryBook` and `Registry`, sibling modules of the coordinator; the delivery module never sees the ledger | Enforced now (compiler) |
| Pricing by the pool, not the client | Catalog and tariff in the Model Registry | Enforced now |
| User authentication | Ed25519 envelope signatures; replay guard per sender and session | Enforced now in `gpu-protocol`; transport security is the target |
| Separate processes per domain | — | Target. Today all domains run in one process: a memory-level compromise of that process bypasses every logical boundary above |
| GPU engine sandbox | — | Target (section 9) |
| Per-service database roles | — | Target (section 10) |

## 8. Open points

- Verification of the work itself (recomputation by a third party, sampling, or proofs): the only way past "two accounts agree".
- Delivery proof checked by the Ledger before a charge (witness attestation or client ack), and a contest the borrower can file with the Ledger directly.
- Witness assignment that the orchestrator cannot choose alone.
- Aggregated exposure cap per account and per pool across concurrent jobs.
- Real digests (SHA-256 or BLAKE3) for frames and the ledger chain; the model uses FNV-1a.
- Rate limiting per principal at the network edge; the model only bounds amounts and request sizes.
- Logging of refused commands at the coordinator edge. A refused command leaves no trace in the coordinator state by design (JOB-R01); the ledger logs its own refusals.
- Frame and receipt digests are recomputed over all positions on each call (O(n), n ≤ `MAX_OUTPUTS`): a sender can make each message cost up to a million hash steps. A stored chained digest removes this before the network prototype.
- The `test-support` feature of `more-identity` builds an account context without a signature, for the simulation only. A production build must not enable it; a CI check for that is still to add.

## 9. GPU agent sandbox (target)

The GPU agent runs third-party model code on a lender's machine. Target profile:

- separate process under a dedicated unprivileged user, no login shell, no sudo;
- read-only root file system, a private writable directory for the assigned weights and scratch, nothing else mounted;
- CPU, memory and pids limits (cgroups v2), no new privileges, seccomp filter;
- network limited to the coordinator, the witness and the neighbor nodes of the attempt;
- no access to the lender's credits: the agent holds a node key, not the account key that controls the balance.

Real limits that this does not remove: the GPU driver runs in the kernel and is a large attack surface; device files (`/dev/nvidia*`, `/dev/dri`) must be exposed to the sandbox; GPU memory is not always cleared between processes; a container is not a security boundary against a kernel or driver exploit. Strong isolation needs a VM with GPU passthrough (or confidential computing where available), which costs performance and is not available on most consumer machines.

## 10. Database separation (target)

One PostgreSQL schema per domain, each owned by a role that only that service uses: `ledger` (journal, balances, mandates), `orchestrator` (jobs, attempts, slices), `registry` (pools, members, catalog), `identity` (keys, credentials). Services get `USAGE` on their own schema only; the ledger tables are writable only by the ledger role, with balance constraints in the database (LEDGER-005) and an append-only journal enforced by revoking `UPDATE` and `DELETE`. GPU agents and witnesses never get database credentials.

## 11. Process separation (next step)

Nothing in this section is built, and it is deliberately kept out of the change that fixed the Ledger's economic invariants: one change for the rules, another for the isolation. The boundaries above are compiler-level and API-level; the second audit is right that one process is one enclosure. The order below follows what a compromise costs.

| Step | What moves out | Interface | Credentials | What it removes |
| --- | --- | --- | --- | --- |
| 1 | Ledger, with its journal, job records and the public key directory | `LedgerOp` → `LedgerOutcome` as framed messages over a local socket, then mTLS. Every operation and outcome is already an owned value with no reference into ledger memory; the two read accessors that return references (`audit_view`, `audit_escrows`) become queries | Orchestrator, Treasury, Platform admin and Auditor each hold their own; the Ledger holds none but its verifier's public key | A memory compromise of the coordinator no longer reaches balances: it is the "hostile orchestrator" of TEST-P30 |
| 2 | Identity authority (credential minting and revocation) | Offline minting, online revocation list | Authority key leaves every online process | A compromised service cannot mint roles |
| 3 | Protocol edge (envelope checks, replay guard) | Verified commands to the coordinator | No signing key at the edge | Parsing of untrusted input leaves the coordinator's process |
| 4 | GPU engine and witness | Section 9 | Lender and witness keys stay on their machines | Untrusted model code |

What step 1 needs before it can be called done: a wire encoding for `LedgerOp` with the same care as the envelope (fixed, versioned, length-prefixed); the coordinator's `execute` no longer cloning the ledger for its all-or-nothing step, so a two-phase call or compensating operations (the typed operations already have inverses for everything but release, contest and settlement, which are final by design); a restart story (the journal is the source of truth, job records are rebuilt from it or persisted with it); and TEST-P30 run against the socket instead of the in-process service. The QUIC witness prototype comes after step 1.

