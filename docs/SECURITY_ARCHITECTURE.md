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
| Caller authentication on the Ledger API and the coordinator | `ServiceCredential` cannot be built outside `more-identity`; the Ledger and the coordinator check its certificate and revocation on each call | Enforced now: in process by the type, between processes by the link's handshake. A secure channel for remote peers is the target |
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
| Ledger in its own process | `more-ledgerd` behind a Unix socket (mode 0600), not dumpable; typed requests only | Enforced now for the Ledger (section 11). State in memory only; a user of its own is recommended, not enforced |
| Service identity bound to a key | Certificate over the service's public key; mutual proof of possession over fresh nonces on every connection; revocation checked on every request | Enforced now on the ledger link. Inside one process a credential is still an object that code could pass around |
| A command is atomic across the two processes | One ledger transaction per command, rolled back with the coordinator's copy, on abort, timeout or a lost connection | Enforced now. A lost answer to `Commit` needs an operator |
| Other domains in their own process | — | Target: identity authority, protocol edge, registry and delivery still share the coordinator's process |
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

## 11. Process separation

The order follows what a compromise costs. Step 1 is built; the others are not.

| Step | What moves out | Interface | Credentials | What it removes | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Ledger, with its journal, job records and the directory of account keys | Typed requests over a local socket (the ledger link) | Each service holds its own key; the Ledger holds its own and the authority's public key | A memory compromise of the coordinator no longer reaches balances: it is the hostile orchestrator of TEST-P30, over a socket | **Built** (`more-ledgerd`), without persistence |
| 2 | Identity authority (certification and revocation) | Offline certification of keys the services generate; revocations as signed statements | Authority key leaves every online process | A compromised service cannot mint roles | Revocation statements and `certify` exist; the authority still runs with the model |
| 3 | Protocol edge (envelope checks, replay guard) | Verified commands to the coordinator | No signing key at the edge | Parsing of untrusted input leaves the coordinator's process | Not built |
| 4 | GPU engine and witness | Section 9 | Lender and witness keys stay on their machines | Untrusted model code | Not built |

### What step 1 is

- **A process, under a user of its own.** `more-ledgerd` owns the ledger's memory. It marks itself not dumpable, so another process of the same user cannot open `/proc/PID/mem` or attach to it. The boundary the operating system enforces best is a separate user, and the socket is made for that: see "Two users" below.
- **Identities with keys.** A service identity used to be a value signed by the authority: in one process the type system kept it from being copied, between processes it would have been a bearer token. It is now a certificate over the service's own public key. Connecting takes a signature over nonces chosen by both sides, so a copied certificate, or a recorded handshake, opens nothing. The service checks the ledger the same way.
- **No borrowed identity.** In one process the coordinator passed the treasury's, the clock's and the platform admin's credentials on to the ledger. Between processes it cannot: it does not hold their keys. Those services connect to the ledger themselves.
- **One transaction per command.** The coordinator's all-or-nothing step was a copy of the whole state, ledger included. With the ledger elsewhere it is a transaction there, committed or rolled back with the coordinator's copy. Transactions nest (reconciliation applies its transitions one by one), are bounded, and die with their connection. Each has a name and a deadline that binds its owner; what became of it can be asked afterwards.
- **The same ledger.** Three differential properties hold the split to that: TEST-P35 (hostile calls, in process and over the link), TEST-P36 (transactions against copy-and-restore), TEST-P37 (the whole simulation next to a coordinator behind the link). Each also runs against the real daemon.

### What a fully compromised orchestrator process can still do

It holds the orchestrator's key and the socket. Everything below is an operation the Ledger accepts from the orchestrator by design; none moves credits to an account of the attacker's choosing without a signature it does not have.

| It can | Bound | Who loses, and what |
| --- | --- | --- |
| Lock a borrower's credits in the escrow of a job the borrower signed, and charge outputs that were never delivered | The budget and prices the borrower signed, per job | The borrower's credits are held until settlement, then returned: nothing is paid without the recipients' receipts |
| Register an attempt on a cluster of its choice, including accounts it controls | The layout must cover the signed model; a lender counts only once it signed | Nobody, unless the recipient of a stage also colludes (section 5, residual risks) |
| Refund a line instead of paying it, or void an output with no share left | Reserved items only; a paid item is final | A lender is not paid for that work; the credits go back to the borrower |
| Contest a held reward | Only within 7 days of the payment and before release; funds go to the job's owner and pool | A lender loses a reward it had earned; nothing is created or kept by the attacker |
| Revoke an attempt early | Once per attempt | A lender whose restoration was not yet corroborated is not paid for it |
| Hold the Ledger with a transaction | 5 s from its first `Begin`, 4,096 operations, 4 levels; rolled back at the deadline whoever is asking, and if its connection ends | Others wait at most that long, each time. It can open the next one at once: a per-service share of the ledger's time is not built |
| Open connections | 64 at once for everyone; an unauthenticated one is closed after 2 s | With its own key it can hold all 64: other services cannot connect until it lets go. A cap per service is not built |
| Ask what became of any transaction | The last 1,024 outcomes | Nothing: names and outcomes of the orchestrator's own transactions |
| Refuse to pay, release or settle | None on its side | Liveness: credits stay held; visible to the auditor |
| Read its jobs' escrow, hold and line balances | Job accounts only | Nothing beyond what the orchestrator already knows |

It cannot issue credits, move the Ledger's clock, register a pool's admin or an account's key, read the journal or another user's balance, act as another service, open a contest window early, pay without the signatures of section 3, or read the Ledger's memory.

The contest and the refund are the two that hurt honest lenders, and the Ledger cannot tell them from honest ones today: neither carries a statement from the borrower. A contest signed by the borrower, checked by the Ledger, is the next rule to add.

### Two users

`more-ledgerd --allow-uid UID` lists the local users whose connections it accepts; the kernel says who is at the other end of each connection, and the peer cannot change that. `--socket-group GID` opens the socket file to one group (mode 0660) instead of its owner alone (0600). Nothing opens it to every local user.

| | Ledger's user | Orchestrator's user | Any other user |
| --- | --- | --- | --- |
| Socket file | Owner | In its group | No access |
| On the daemon's list | Only if listed | Listed | Not listed: closed before a byte is read, even if it got into the group, even with a valid credential, even root |
| Ledger's key file (0600) | Reads | Cannot | Cannot |
| Ledger's memory | Its own | Cannot (another user, and not dumpable) | Cannot |

The test `r5_two_users_…` starts the daemon under one user, an orchestrator under a second and a bystander under a third, checks each cell of this table, and then runs the differential tests as the orchestrator's user. It needs root to change user, so it runs in its own CI job.

In that test every service on the test's side runs under the orchestrator's user. A deployment gives each service its own user and lists them all; the list does not yet tie a user to a role, so a listed user holding another service's key could use it. The credential, not the user, still decides what a connection may do.

The clients do not trust the socket's path: whatever answers there has to prove it is this deployment's ledger (LEDGER-022). A directory others can write to lets them replace the socket, which stops the service and nothing more.

### When the link fails around a commit

A commit that gets no answer may or may not have been applied. The coordinator cannot tell, so it does not guess.

| What the coordinator sees | What it does |
| --- | --- |
| The ledger answers "done" | Keeps the command's state |
| The ledger refuses, or ends the connection itself | Keeps nothing of the command; reports the error |
| No answer to the commit | Stops. Every command is refused with `LEDGER_OUTCOME_UNKNOWN`. Keeps both states: the one it had, and the one that goes with the commit |
| Then, asked on a new connection: committed | Takes the state that goes with the commit, goes on |
| … rolled back | Keeps the state it had, goes on. The sender may send the command again; it runs under a new name |
| … still open | Stays stopped. The ledger's deadline rolls the transaction back within 5 s |
| … unknown to the ledger | Stays stopped. More than 1,024 transactions went by, or something is wrong: a person compares the two sides |
| The ledger at the other end has another incarnation | Stops for good with `LEDGER_STATE_LOST`: that ledger restarted and is empty |

The coordinator never sends a command again by itself. The connection on which an answer was lost is dropped, so a late answer is never read as the answer to something else.

**Recovery by hand, while nothing is persisted.** A coordinator stopped on `LEDGER_STATE_LOST`, or on an outcome the ledger forgot, is not restarted against that ledger: both are started again from nothing. There is no tool that rebuilds one side from the other, because neither side keeps anything on disk.

### What step 1 is not

- **A ledger for real credits.** The daemon says so on standard error at every start.
- **Persistence.** The daemon keeps everything in memory. When it stops, the journal, the balances, the held payments, the signed terms, leases and receipts on record, the registered account keys, the revocations it was told of and the outcomes of transactions are lost. The coordinator notices by the incarnation number and stops; the other services do not check it yet. The coordinator's state is in memory too: one that restarts has lost its jobs while the ledger still holds their escrow. The journal on disk, and both sides rebuilt from it, come before any deployment; the transaction names, the outcome log and the incarnation number are there for that.
- **Atomic commitment across both processes.** What holds: a command is never applied twice, never applied in part at the ledger, and the coordinator never continues on a guess. What does not: if the coordinator's process dies while a commit is in doubt, the state that went with it is gone, and the ledger may hold a commit no coordinator knows of. Closing that takes persistence on both sides.
- **A network service.** The link has no encryption and no per-message authentication. It relies on the socket being local. Remote peers need a secure channel underneath (mutual TLS, or QUIC with the same certificates).
- **Efficient transactions.** `Begin` copies the ledger's state. Fine for a model; a real store uses a write-ahead log.
- **A second boundary.** The identity authority, the protocol edge and the registry are still in the coordinator's process.
