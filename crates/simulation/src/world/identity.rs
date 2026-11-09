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
        let mut authority = IdentityAuthority::new([0x42; 32]);
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
            Heartbeat { job, attempt: n }
            | AttemptReady {
                job, attempt: n, ..
            } => match attempt(job, *n).and_then(|a| a.lenders.first()) {
                Some(l) => acct(*l),
                None => svc(ServiceRole::Scheduler),
            },
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
