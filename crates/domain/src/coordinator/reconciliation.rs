//! Reconciliation: every due transition, automatically (JOB-R20).

use super::*;

impl Coordinator {
    /// JOB-R20: applies every automatic transition that is due. Each stays atomic; reconciliation
    /// is idempotent.
    pub(super) fn reconcile(&mut self, ctx: &AuthContext) -> R<Outcome> {
        let mut changed = false;
        for _ in 0..64 {
            let mut todo: Vec<Command> = Vec::new();
            let now = self.now;
            let c = &self.cfg;
            for j in self.jobs.values() {
                let since = now.saturating_sub(j.exec_since);
                match j.exec {
                    ExecStatus::Queued if since >= c.queued_wait => {
                        todo.push(Command::RejectQueued { job: j.id })
                    }
                    ExecStatus::Reserved if since >= c.reserved_wait => {
                        todo.push(Command::Cancel {
                            job: j.id,
                            expected_version: None,
                        })
                    }
                    ExecStatus::Placing
                        if since >= c.placing_timeout
                            || j.current().is_some_and(|a| a.any_expired(now)) =>
                    {
                        todo.push(Command::PlacementFailed { job: j.id })
                    }
                    ExecStatus::Recovering if since >= c.recovery_timeout => {
                        todo.push(Command::RecoveryTimeout { job: j.id })
                    }
                    ExecStatus::Paused if since >= c.pause_max => {
                        todo.push(Command::ExpirePause { job: j.id })
                    }
                    ExecStatus::Running => {
                        // JOB-R31, JOB-R39: any node's expired lease means a lost node.
                        if j.current().is_some_and(|a| a.any_expired(now)) {
                            todo.push(Command::NodeLost {
                                job: j.id,
                                expected_version: None,
                            });
                        }
                        let window = j.current().is_some_and(|a| a.produced != j.validated);
                        if window && now.saturating_sub(j.last_ack_at) >= c.client_silence {
                            todo.push(Command::Pause {
                                job: j.id,
                                reason: PauseReason::ClientSilent,
                                expected_version: None,
                            });
                        }
                    }
                    ExecStatus::Settling => todo.push(Command::CompleteSettling { job: j.id }),
                    _ => {}
                }
                if j.settle == SettleStatus::Finalizing {
                    todo.push(Command::Settle { job: j.id });
                }
                if !self.window_due(j.id).is_empty() {
                    todo.push(Command::ExpireDeliveryWindow { job: j.id });
                }
                let contest_due = self.delivery.charges().iter().any(|(o, ch)| {
                    o.job == j.id && !ch.definitive && ch.contest.is_some_and(|k| now >= k.deadline)
                });
                if contest_due {
                    todo.push(Command::ResolveContests { job: j.id });
                }
            }
            for s in self.slices.values() {
                match s.status {
                    SliceStatus::Draining if now >= s.receipt_deadline.unwrap_or(0) => {
                        todo.push(Command::CloseSlice { slice: s.id })
                    }
                    SliceStatus::Closed
                        if now >= s.closed_at.unwrap_or(0) + c.evaluation_deadline =>
                    {
                        todo.push(Command::Evaluate { slice: s.id })
                    }
                    SliceStatus::Disputed
                        if now >= s.closed_at.unwrap_or(0) + c.dispute_deadline =>
                    {
                        for (lender, l) in &s.lines {
                            let arbitrable = l
                                .items
                                .iter()
                                .any(|i| i.status == ItemStatus::Disputed && !i.awaiting_delivery);
                            if arbitrable {
                                todo.push(Command::Arbitrate {
                                    slice: s.id,
                                    lender: *lender,
                                    pay: false,
                                });
                            }
                        }
                    }
                    // JOB-R22: automatic release at the end of the window.
                    SliceStatus::Final
                        if s.final_at.is_some_and(|f| now >= f + c.reward_window) =>
                    {
                        for (lender, l) in &s.lines {
                            if l.held > 0 {
                                todo.push(Command::ReleaseReward {
                                    slice: s.id,
                                    lender: *lender,
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
            let mut progressed = false;
            for cmd in todo {
                match self.execute(ctx, &cmd) {
                    Ok(Outcome::Applied) => progressed = true,
                    // Reconciliation never swallows an internal error; it would silently block the
                    // job (CE-04).
                    Err(DomainError::Internal(m)) => {
                        return Err(DomainError::Internal(format!("reconcile {cmd:?}: {m}")))
                    }
                    // A due transition the ledger refuses or cannot write is never skipped in
                    // silence either: the job would look settled-in-progress forever while credits
                    // sit in its accounts.
                    Err(DomainError::Ledger(e)) => {
                        return Err(DomainError::Internal(format!(
                            "reconcile {cmd:?}: ledger {e:?}"
                        )))
                    }
                    // A due transition the reconciler may not run is a permission matrix bug: it
                    // would stay due forever.
                    Err(DomainError::Unauthorized(m)) => {
                        return Err(DomainError::Internal(format!("reconcile {cmd:?}: {m}")))
                    }
                    _ => {}
                }
            }
            if !progressed {
                break;
            }
            changed = true;
        }
        Ok(if changed {
            Outcome::Applied
        } else {
            Outcome::AlreadyApplied
        })
    }
}
