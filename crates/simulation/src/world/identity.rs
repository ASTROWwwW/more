//! Who sends each command: one credential per service, one key per account, and the honest sender of every command.

use super::*;

/// Identities of the simulated world: one credential per service, one key per account.
pub struct SimIdentity {
    pub keys: KeyDirectory,
    pub clock: ServiceCredential,
    pub treasury: ServiceCredential,
    pub platform: ServiceCredential,
    pub scheduler: ServiceCredential,
    pub reconciler: ServiceCredential,
    pub auditor: ServiceCredential,
    /// Valid credential with no right in the domain, for compromise tests.
    pub delivery: ServiceCredential,
    authority: IdentityAuthority,
}

impl SimIdentity {
    pub(super) fn new() -> (Self, ServiceCredential) {
        let mut authority = IdentityAuthority::new(AUTHORITY_SEED);
        let keys = KeyDirectory::new();
        for a in BORROWERS
            .iter()
            .chain(&LENDERS)
            .chain(&[WITNESS, POOL_ADMIN, STRANGER])
        {
            // Accounts are distinct constants: registration cannot collide.
            let _ = keys.register(a.0, user_key(*a).public());
        }
        let orchestrator = authority.issue(ServiceRole::Orchestrator);
        let ids = SimIdentity {
            keys,
            clock: authority.issue(ServiceRole::Clock),
            treasury: authority.issue(ServiceRole::Treasury),
            platform: authority.issue(ServiceRole::PlatformAdmin),
            scheduler: authority.issue(ServiceRole::Scheduler),
            reconciler: authority.issue(ServiceRole::Reconciler),
            auditor: authority.issue(ServiceRole::Auditor),
            delivery: authority.issue(ServiceRole::Delivery),
            authority,
        };
        (ids, orchestrator)
    }

    /// Credential checker of this world's authority.
    pub fn verifier(&self) -> more_identity::CredentialVerifier {
        self.authority.verifier()
    }

    /// Revokes a service credential (compromise tests).
    pub fn revoke(&self, cred: &ServiceCredential) {
        self.authority.revoke(cred.id());
    }

    /// Ledger service bound to this world's identities.
    pub fn verifier_ledger(&self) -> LedgerService {
        LedgerService::new(
            self.authority.verifier(),
            self.keys.clone(),
            LedgerLimits::default(),
        )
    }
}

impl Sim {
    /// Service context.
    pub fn as_service(&self, role: ServiceRole) -> AuthContext {
        let ids = &self.ids;
        let cred = match role {
            ServiceRole::Clock => &ids.clock,
            ServiceRole::Treasury => &ids.treasury,
            ServiceRole::PlatformAdmin => &ids.platform,
            ServiceRole::Scheduler => &ids.scheduler,
            ServiceRole::Reconciler => &ids.reconciler,
            ServiceRole::Auditor => &ids.auditor,
            ServiceRole::Delivery | ServiceRole::Orchestrator => &ids.delivery,
        };
        AuthContext::service(cred.clone())
    }

    /// The honest sender of `cmd` in the current state: the borrower of the job, the lender of the
    /// attempt, the assigned witness, the right service. Adversarial operations pick other
    /// senders explicitly.
    pub fn actor(&self, cmd: &Command) -> AuthContext {
        use Command::*;
        let c = &self.coord;
        let svc = |r| self.as_service(r);
        let acct = |a: AccountId| assume_account(a.0);
        let borrower = |job: &JobId| c.jobs().get(job).map(|j| j.borrower);
        let attempt = |job: &JobId, n: u32| c.jobs().get(job).and_then(|j| j.attempts.get(&n));
        match cmd {
            Tick { .. } => svc(ServiceRole::Clock),
            Issue { .. } => svc(ServiceRole::Treasury),
            CreatePool { .. } => svc(ServiceRole::PlatformAdmin),
            SetRights { .. } | RegisterModel { .. } | FundRecovery { .. } => acct(POOL_ADMIN),
            Arbitrate { pay: true, .. } => acct(POOL_ADMIN),
            JoinPool { account, .. } => acct(*account),
            Submit { borrower: b, .. } => acct(*b),
            Place { .. } | Finish { .. } | PlacementFailed { .. } => svc(ServiceRole::Scheduler),
            Pause { reason, job, .. } => match reason {
                PauseReason::Requested => borrower(job).map_or(svc(ServiceRole::Scheduler), acct),
                PauseReason::ClientSilent => svc(ServiceRole::Reconciler),
                _ => svc(ServiceRole::Scheduler),
            },
            AcceptLease { lender, .. }
            | LeaseLoaded { lender, .. }
            | AttemptReady { lender, .. }
            | Heartbeat { lender, .. }
            | PresentReceipt { lender, .. } => acct(*lender),
            WitnessHeartbeat { witness, .. } => acct(*witness),
            Produce {
                job, attempt: n, ..
            } => match attempt(job, *n).and_then(|a| a.output_node()) {
                Some(l) => acct(l),
                None => svc(ServiceRole::Scheduler),
            },
            Ack { job, .. }
            | ConfirmDelivery { job, .. }
            | ClientHeartbeat { job }
            | Resume { job, .. }
            | Cancel { job, .. } => borrower(job).map_or(svc(ServiceRole::Scheduler), acct),
            ContestReward { slice, .. } => {
                borrower(&slice.job).map_or(svc(ServiceRole::Scheduler), acct)
            }
            Deliver { witness, .. } | WitnessCommit { witness, .. } => acct(*witness),
            WitnessLost { job, attempt: n } | PurgeBuffer { job, attempt: n } => {
                match attempt(job, *n) {
                    Some(a) => acct(a.witness),
                    None => svc(ServiceRole::Reconciler),
                }
            }
            CommitReceipts {
                job,
                attempt: n,
                lender,
                ..
            }
            | CorroborateRestore {
                job,
                attempt: n,
                lender,
                ..
            } => match attempt(job, *n)
                .and_then(|a| a.stage_of(*lender).and_then(|st| a.recipient_of(st)))
            {
                Some(r) => acct(r),
                None => acct(*lender),
            },
            Claim { lender, .. } | SupplementEvidence { lender, .. } => acct(*lender),
            Arbitrate { .. } | ReleaseReward { .. } | Reconcile => svc(ServiceRole::Reconciler),
            Reserve { .. }
            | RejectQueued { .. }
            | CloseSlice { .. }
            | Evaluate { .. }
            | NodeLost { .. }
            | RecoveryTimeout { .. }
            | CompleteSettling { .. }
            | Settle { .. }
            | ExpirePause { .. }
            | ExpireDeliveryWindow { .. }
            | ResolveContests { .. }
            | Fail { .. } => svc(ServiceRole::Scheduler),
        }
    }

    /// Any principal of the simulated world.
    pub fn principal(&self, sel: u8) -> AuthContext {
        const SERVICES: [ServiceRole; 7] = [
            ServiceRole::Clock,
            ServiceRole::Treasury,
            ServiceRole::PlatformAdmin,
            ServiceRole::Scheduler,
            ServiceRole::Reconciler,
            ServiceRole::Auditor,
            ServiceRole::Delivery,
        ];
        let accounts = [
            BORROWERS[0],
            BORROWERS[1],
            LENDERS[0],
            LENDERS[1],
            LENDERS[2],
            LENDERS[3],
            WITNESS,
            POOL_ADMIN,
            STRANGER,
        ];
        let k = usize::from(sel) % (accounts.len() + SERVICES.len());
        match accounts.get(k) {
            Some(a) => assume_account(a.0),
            None => self.as_service(SERVICES[k - accounts.len()]),
        }
    }
}

/// Seed of the simulated deployment's identity authority.
const AUTHORITY_SEED: [u8; 32] = [0x42; 32];

/// The simulated deployment, as named in every statement its accounts sign (LEDGER-019).
pub fn sim_domain() -> Domain {
    static DOMAIN: std::sync::OnceLock<Domain> = std::sync::OnceLock::new();
    *DOMAIN.get_or_init(|| IdentityAuthority::new(AUTHORITY_SEED).domain())
}

/// Signature left for the sending client to fill in (see [`Sim::signed`]).
pub const UNSIGNED: [u8; 64] = [0; 64];

/// Configuration digest left for the loading lender to fill in (see [`Sim::signed`]).
pub const UNSET_CONFIG: u64 = 0;

/// State commitment left for the restoring lender to fill in (see [`Sim::signed`]).
pub const UNSET_STATE: u64 = 0;

/// Recovery segments an honest lender commits to, and an honest recipient attests by default.
pub const SEGMENTS: u32 = 4;

/// Every simulated segment, named.
pub fn all_segments() -> Vec<u32> {
    (0..SEGMENTS).collect()
}

/// What an honest lender commits to for each recovery segment, given its state commitment
/// (symbolic).
pub fn segment_commitments(state: u64) -> Vec<u64> {
    (0..u64::from(SEGMENTS))
        .map(|k| (state ^ (k + 1)).wrapping_mul(0x0100_0000_01b3))
        .collect()
}

/// The readiness an honest lender signs for `restored`.
pub fn readiness_of(
    job: JobId,
    attempt: u32,
    lender: AccountId,
    restored: PerType<u32>,
) -> Readiness {
    let state = state_commitment(job, attempt, lender, restored);
    Readiness {
        job: job.0,
        attempt,
        lender: lender.0,
        restored,
        state,
        segments: segment_commitments(state),
    }
}

/// What an honest lender commits to after restoring its state (symbolic, never 0).
pub fn state_commitment(
    job: JobId,
    attempt: u32,
    lender: AccountId,
    restored: PerType<u32>,
) -> u64 {
    let mut h: u64 = 0x5245_5354_4f52_4544;
    for w in [
        job.0,
        attempt,
        lender.0,
        restored[0],
        restored[1],
        restored[2],
    ] {
        h = (h ^ u64::from(w)).wrapping_mul(0x0100_0000_01b3);
    }
    h | 1
}

/// The statement a recipient signs about `lender`'s restoration on `a` for the segments it
/// names, as the ledger rebuilds it: `None` until the lender reported ready.
pub fn restoration_of(
    job: JobId,
    a: &Attempt,
    lender: AccountId,
    segments: &[u32],
) -> Option<Restoration> {
    let stage = a.stage_of(lender)?;
    let r = a.leases[stage].restored.as_ref()?;
    let commitment = |k: &u32| r.segments.get(*k as usize).copied().unwrap_or(0);
    Some(Restoration {
        job: job.0,
        attempt: a.no,
        producer: lender.0,
        layers: a.layer_range(stage)?,
        restored: r.positions,
        state: r.state,
        segments: segments.iter().map(|k| (*k, commitment(k))).collect(),
    })
}

impl Sim {
    /// The simulated clients complete and sign their own statements when they send them: a lender
    /// its lease, the configuration it loaded and its readiness, a recipient its receipt
    /// commitments. A producer presenting a receipt
    /// carries its recipient's co-signature, which an honest recipient gives only for what it
    /// received. A signature that is not [`UNSIGNED`] is sent as is (forgery tests).
    pub fn signed(&self, ctx: &AuthContext, mut cmd: Command) -> Command {
        use Command::*;
        let Some(me) = ctx.account_no().map(AccountId) else {
            return cmd;
        };
        let c = &self.coord;
        let d = &sim_domain();
        let att = |job: JobId, n: u32| c.jobs().get(&job).and_then(|j| j.attempts.get(&n));
        match &mut cmd {
            AcceptLease {
                job,
                attempt,
                signature,
                ..
            } if *signature == UNSIGNED => {
                if let Some(a) = att(*job, *attempt) {
                    *signature = user_key(me).sign(&lease_message(d, &assignment_of(*job, a)));
                }
            }
            CorroborateRestore {
                job,
                attempt,
                lender,
                segments,
                signature,
            } if *signature == UNSIGNED => {
                // An honest recipient attests the restored state it received from the producer.
                let r =
                    att(*job, *attempt).and_then(|a| restoration_of(*job, a, *lender, segments));
                if let Some(r) = r {
                    *signature = user_key(me).sign(&restore_message(d, &r));
                }
            }
            FundRecovery {
                job,
                amount,
                signature,
            } if *signature == UNSIGNED => {
                if let Some(j) = c.jobs().get(job) {
                    let total = j.pool_recovery_funded.saturating_add(*amount);
                    *signature = user_key(me).sign(&relay_message(d, job.0, j.pool.0, total));
                }
            }
            LeaseLoaded {
                job,
                attempt,
                lender,
                config,
            } if *config == UNSET_CONFIG => {
                let stage = att(*job, *attempt).and_then(|a| a.stage_of(*lender));
                if let Some(d) = stage.and_then(|s| c.config_digest(*job, *attempt, s)) {
                    *config = d;
                }
            }
            AttemptReady {
                job,
                attempt,
                lender,
                restored,
                state,
                segments,
                signature,
            } if *signature == UNSIGNED => {
                // An honest lender commits to the state it really restored, and to each segment
                // it recomputed.
                if *state == UNSET_STATE {
                    *state = state_commitment(*job, *attempt, *lender, *restored);
                    if segments.is_empty() {
                        *segments = segment_commitments(*state);
                    }
                }
                let r = Readiness {
                    job: job.0,
                    attempt: *attempt,
                    lender: lender.0,
                    restored: *restored,
                    state: *state,
                    segments: segments.clone(),
                };
                *signature = user_key(me).sign(&ready_message(d, &r));
            }
            CommitReceipts {
                job,
                attempt,
                lender,
                wt,
                upto,
                digest,
                signature,
            } if *signature == UNSIGNED => {
                let m =
                    receipt_message(d, job.0, *attempt, lender.0, wt.idx() as u8, *upto, *digest);
                *signature = user_key(me).sign(&m);
            }
            PresentReceipt {
                job,
                attempt,
                lender,
                wt,
                upto,
                digest,
                signature,
            } if *signature == UNSIGNED => {
                let recipient = att(*job, *attempt).and_then(|a| {
                    let received = *upto <= a.produced[wt.idx()];
                    let r = a.stage_of(*lender).and_then(|s| a.recipient_of(s));
                    r.filter(|_| received)
                });
                if let Some(r) = recipient {
                    let m = receipt_message(
                        d,
                        job.0,
                        *attempt,
                        lender.0,
                        wt.idx() as u8,
                        *upto,
                        *digest,
                    );
                    *signature = user_key(r).sign(&m);
                }
            }
            _ => {}
        }
        cmd
    }
}

/// The assignment the ledger registered for `a`, rebuilt from the coordinator's view.
pub fn assignment_of(job: JobId, a: &Attempt) -> Assignment {
    Assignment {
        job: job.0,
        attempt: a.no,
        lenders: a.lenders.iter().map(|l| l.0).collect(),
        layout: a.layout.clone(),
        witness: a.witness.0,
        recovery_earmark: a.recovery_earmark,
    }
}
