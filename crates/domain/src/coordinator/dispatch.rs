//! Command dispatch: one transition function per command. Authorization already ran
//! (`Coordinator::execute`).

use super::*;

impl Coordinator {
    pub(super) fn step(&mut self, ctx: &AuthContext, cmd: &Command) -> R<Outcome> {
        use Command::*;
        // Rejected commands roll back with the rest of the state, so sequence numbers have no gaps.
        self.seq += 1;
        match cmd {
            Tick { dt } => self.tick(ctx, *dt),
            Issue { id, to, amount } => self.issue(ctx, *id, *to, *amount),
            CreatePool {
                pool,
                mode,
                access,
                admin,
            } => self.create_pool(ctx, *pool, *mode, *access, *admin),
            SetRights {
                pool,
                account,
                rights,
            } => {
                let seq = self.seq;
                self.registry.set_rights(*pool, *account, *rights, seq)
            }
            JoinPool { pool, account } => self.registry.join(*pool, *account),
            RegisterModel { pool, model, spec } => {
                self.registry.register_model(*pool, *model, *spec)
            }
            Submit {
                job,
                borrower,
                pool,
                model,
                outputs,
                max_budget,
                mandate,
            } => self.submit(
                *job,
                *borrower,
                *pool,
                *model,
                *outputs,
                *max_budget,
                mandate,
            ),
            Reserve { job } => self.reserve(*job),
            RejectQueued { job } => self.reject_queued(*job),
            Place {
                job,
                lenders,
                layout,
                recovery_estimate,
                witness,
                expected_version,
            } => {
                self.check_version(*job, *expected_version)?;
                self.place(*job, lenders, layout, *recovery_estimate, *witness)
            }
            AcceptLease {
                job,
                attempt,
                lender,
                signature,
            } => self.accept_lease(*job, *attempt, *lender, signature),
            CorroborateRestore {
                job,
                attempt,
                lender,
                segments,
                signature,
            } => self.corroborate_restore(*job, *attempt, *lender, segments, signature),
            LeaseLoaded {
                job,
                attempt,
                lender,
                config,
            } => self.lease_loaded(*job, *attempt, *lender, *config),
            Heartbeat {
                job,
                attempt,
                lender,
            } => self.heartbeat(*job, *attempt, *lender),
            WitnessHeartbeat {
                job,
                attempt,
                witness,
            } => self.witness_heartbeat(*job, *attempt, *witness),
            Deliver {
                job,
                attempt,
                witness,
                wt,
                upto,
                digest,
            } => self.deliver(*job, *attempt, *witness, *wt, *upto, *digest),
            WitnessCommit {
                job,
                attempt,
                witness,
                wt,
                upto,
            } => self.witness_commit(*job, *attempt, *witness, *wt, *upto),
            ConfirmDelivery {
                job,
                wt,
                confirmed,
                digest,
            } => self.confirm_delivery(*job, *wt, *confirmed, *digest),
            ClientHeartbeat { job } => {
                // JOB-R33: a keepalive covers no position, so it resolves nothing.
                self.job(*job)?;
                Ok(Outcome::AlreadyApplied)
            }
            ResolveContests { job } => self.resolve_contests(*job),
            PurgeBuffer { job, attempt } => self.purge_buffer(*job, *attempt),
            SupplementEvidence {
                slice,
                lender,
                output,
                evidence,
            } => self.supplement_evidence(*slice, *lender, *output, *evidence),
            WitnessLost { job, attempt } => self.witness_lost(*job, *attempt),
            ExpireDeliveryWindow { job } => self.expire_delivery_window(*job),
            PlacementFailed { job } => self.placement_failed(*job),
            AttemptReady {
                job,
                attempt,
                lender,
                restored,
                state,
                segments,
                signature,
            } => self.attempt_ready(
                *job,
                *attempt,
                *lender,
                (*restored, *state, segments),
                signature,
            ),
            Produce {
                job,
                attempt,
                wt,
                upto,
            } => self.produce(*job, *attempt, *wt, *upto),
            Ack {
                job,
                attempt,
                wt,
                upto,
            } => self.ack(*job, *attempt, *wt, *upto),
            CommitReceipts {
                job,
                attempt,
                lender,
                wt,
                upto,
                digest,
                signature,
            } => self.commit_receipts(*job, *attempt, *lender, (*wt, *upto, *digest), signature),
            PresentReceipt {
                job,
                attempt,
                lender,
                wt,
                upto,
                digest,
                signature,
            } => self.present_receipt(*job, *attempt, *lender, (*wt, *upto, *digest), signature),
            Claim {
                slice,
                lender,
                items,
            } => self.claim(*slice, *lender, items),
            CloseSlice { slice } => self.close_slice(*slice),
            Evaluate { slice } => self.evaluate(*slice),
            Arbitrate { slice, lender, pay } => self.arbitrate(*slice, *lender, *pay),
            NodeLost {
                job,
                expected_version,
            } => {
                self.check_version(*job, *expected_version)?;
                self.node_lost(*job)
            }
            Pause {
                job,
                reason,
                expected_version,
            } => {
                self.check_version(*job, *expected_version)?;
                self.pause(*job, *reason)
            }
            Resume { job, topup } => self.resume(*job, *topup),
            RecoveryTimeout { job } => self.recovery_timeout(*job),
            FundRecovery {
                job,
                amount,
                signature,
            } => self.fund_recovery(*job, *amount, signature),
            Finish {
                job,
                expected_version,
            } => {
                self.check_version(*job, *expected_version)?;
                self.finish(*job)
            }
            CompleteSettling { job } => self.complete_settling(*job),
            Cancel {
                job,
                expected_version,
            } => {
                self.check_version(*job, *expected_version)?;
                self.terminate(*job, ExecStatus::Cancelled, "JOB-T15")
            }
            Fail { job } => self.terminate(*job, ExecStatus::Failed, "JOB-T16"),
            ExpirePause { job } => self.expire_pause(*job),
            Settle { job } => self.settle(*job),
            ReleaseReward { slice, lender } => self.release_reward(*slice, *lender),
            ContestReward { slice, lender } => self.contest_reward(*slice, *lender),
            Reconcile => self.reconcile(ctx),
        }
    }
}
