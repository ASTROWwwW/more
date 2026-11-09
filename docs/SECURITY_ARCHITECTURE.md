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
| Service (Orchestrator, Reconciler, Scheduler, Treasury, Clock, Platform admin, Auditor, Delivery) | `ServiceCredential`: a value only `more-identity` can mint, carrying a service id and a role, tagged by the authority. Each service has its own credential; there is no shared global secret. Revocation is checked on each ledger call | Separate processes, mTLS client certificates per service, short-lived tokens |

A user role is never a property of the account alone. It comes from the resource: a borrower is the borrower **of this job**, a lender is a lender **of this attempt**, a witness is the witness **assigned to this attempt**, and pool rights (borrow, lend, witness, admin) are granted per pool by its admin.

## 3. Permission matrix

Commands of the coordinator (`gpu-domain::Command`). A cell lists who may send the command and the resource condition checked before any mutation. Anything not listed is denied (fail closed).

| Command | Allowed principal | Resource check |
| --- | --- | --- |
| `Tick` | Clock service | — |
| `Issue` | Treasury service | Credential forwarded to the Ledger, which checks the Treasury role itself |
| `CreatePool` | Platform admin | — |
| `GrantMembership`, `RevokeMembership` | Pool admin, Platform admin | Admin of that pool |
| `RegisterModel` (catalog, tariff) | Pool admin | Admin of that pool |
| `Submit` | User | `borrower` = caller; caller has the borrow right in the pool; model in the pool's catalog; price taken from the tariff, never from the request; estimated cost ≤ the budget the borrower signed |
| `Reserve`, `RejectQueued`, `CloseSlice`, `Evaluate`, `NodeLost`, `RecoveryTimeout`, `CompleteSettling`, `Settle`, `ExpirePause`, `ExpireDeliveryWindow`, `ResolveContests`, `Reconcile`, `Fail` | Scheduler or Reconciler service | — |
| `Place` | Scheduler service | Lenders distinct, each with the lend right in the job's pool; witness with the witness right, independent of lenders and borrower; layout covers exactly the model's layers |
| `Heartbeat`, `AttemptReady` | User | Caller is a lender of that attempt |
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
| `FundRecovery` | Pool admin of the job's pool | — |
| `ReleaseReward` | Reconciler; the lender itself after the window | — |
| `ContestReward` | Borrower of the job; pool admin of the job's pool | — |

### Ledger API

The Ledger exposes no generic transfer. Each operation has fixed source and destination account kinds, and every account involved must belong to the same job, its owner, its pool or its assigned lenders.

| Operation | Allowed service | Checks done by the Ledger |
| --- | --- | --- |
| `Issue` | Treasury | Amount within the per-issuance limit and the supply cap |
| `OpenEscrow` | Orchestrator | Borrower's Ed25519 mandate signature over (job, pool, max budget); one escrow per job |
| `Reserve` (work, recovery, top-up) | Orchestrator | Source is the escrow owner's account; cumulative amount ≤ signed mandate |
| `ChargeOutput`, `VoidOutput` | Orchestrator | Same job's work escrow ↔ output hold |
| `ReserveLine`, `PayLine`, `RefundLine` | Orchestrator | Same job's output hold or recovery escrow ↔ that job's line accounts |
| `ReleaseReward` | Orchestrator | Pending reward → its own lender + commission; commission rate set by the Ledger |
| `ContestReward` | Orchestrator | Pending reward → the job's owner and the job's pool only |
| `FundRecovery` | Orchestrator | Pool reserve of the job's own pool → that job's recovery escrow |
| `SettleJob` | Orchestrator | Escrows of the job → its owner, unspent pool share → its pool; destinations computed by the Ledger |
| Read balances | Orchestrator (job accounts), Auditor (everything) | — |

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
| Delivery service or witness | Attest outputs that were produced but not received: provisional billing, at most `K` per type per job (JOB-R27) | No ledger credential with any write right; issuance needs the Treasury role; contests and rewinds refund unproven outputs | `compromise_delivery_cannot_issue_or_move_credits` |
| GPU agent | Lie about its own work, stop, produce garbage | Every command is authorized per resource: it cannot cancel, ack or confirm someone else's job, renew another node's lease, or commit receipts for itself; it has no ledger access | `compromise_gpu_agent_cannot_cancel_other_jobs`, security scenarios |
| Scheduler / Orchestrator | Make bad placements; route a job's escrow to lenders it picked | The Ledger only accepts typed operations within one job; a reservation needs the borrower's signed mandate and stays under it; no transfer between users; cannot issue | `compromise_scheduler_cannot_move_arbitrary_balances` |
| Treasury | Issue credits | Per-issuance limit and supply cap in the Ledger; every issuance logged | `ledger_issue_limits` |
| A user account | Act as itself | Per-resource checks; a signature for one session or job cannot be reused (JOB-R34, replay guard) | security scenarios 1 to 10 |

Residual risk, stated plainly: a compromised orchestrator can still pay a lender it chose with credits a borrower committed to that job, up to the signed mandate. Removing that would require lenders' signed lease acceptance to be checked by the Ledger too (listed in section 8).

## 6. Data separation

| Data | Owner | Who can read it now |
| --- | --- | --- |
| Balances and journal | Ledger | Orchestrator for job accounts it needs; Auditor read-only view |
| Mandates, escrow owners | Ledger | Ledger only |
| User public keys | Identity | Identity, Ledger (mandate verification) |
| Service credentials | Identity mints, each service keeps its own | The service it was minted for |
| Jobs, attempts, slices, outputs | Orchestrator | Read accessors; no public mutable field |
| Pools, members, catalog | Model Registry | Read accessors |
| Encrypted frames, replay buffer | Witness | Witness only (never decrypted by More) |

## 7. Boundary status

| Boundary | Mechanism | Status |
| --- | --- | --- |
| Only the Ledger writes balances | `Ledger::transfer` is private to the ledger crate; the public API is `LedgerService::execute` with typed operations; a doc test proves the generic transfer does not compile from outside | Enforced now (compiler + tests) |
| Caller authentication on the Ledger API | `ServiceCredential` cannot be built outside `more-identity`; the Ledger checks role and revocation on each call | Enforced now (in-process); mTLS between processes is the target |
| Issuance only by Treasury | Ledger permission matrix | Enforced now |
| Borrower consent to spending | Ed25519 mandate verified by the Ledger | Enforced now |
| Per-resource authorization of commands | `authorize` runs before any mutation; TEST-P29 checks that an unauthorized command never changes state | Enforced now |
| Pricing by the pool, not the client | Catalog and tariff in the Model Registry | Enforced now |
| User authentication | Ed25519 envelope signatures; replay guard per sender and session | Enforced now in `gpu-protocol`; transport security is the target |
| Separate processes per domain | — | Target. Today all domains run in one process: a memory-level compromise of that process bypasses every logical boundary above |
| GPU engine sandbox | — | Target (section 9) |
| Per-service database roles | — | Target (section 10) |

## 8. Open points

- Lenders' signed lease acceptance checked by the Ledger, to bound what a compromised orchestrator can redirect.
- Aggregated exposure cap per account and per pool across concurrent jobs.
- Real digests (SHA-256 or BLAKE3) for frames and the ledger chain; the model uses FNV-1a.
- Rate limiting per principal at the network edge; the model only bounds amounts and request sizes.

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
