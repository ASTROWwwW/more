//! Contests, buffers, delivery window and rewinds (JOB-R28, JOB-R29, JOB-R33).

use super::*;

impl Coordinator {
    /// JOB-R33: at the deadline, a contested output with no covering ack is refunded along with
    /// everything after it.
    pub(super) fn resolve_contests(&mut self, job: JobId) -> R<Outcome> {
        let first = self.delivery.contests_due(job, self.now);
        if first.is_empty() {
            return Err(DomainError::Precondition("JOB-R33: no contest due"));
        }
        for (wt, p) in first {
            self.rewind(job, wt, p)?;
        }
        Ok(Outcome::Applied)
    }

    /// JOB-R28: the witness keeps its buffer until the delivery window has passed AND no output of
    /// the attempt is provisional or contested.
    pub(super) fn purge_buffer(&mut self, job: JobId, attempt: u32) -> R<Outcome> {
        let now = self.now;
        let w = self.cfg.delivery_window;
        let j = self.job(job)?;
        let a = j.attempts.get(&attempt).ok_or(DomainError::StaleAttempt)?;
        if a.buffer_purged {
            return Ok(Outcome::AlreadyApplied);
        }
        let Some(r) = a.revoked_at else {
            return Err(DomainError::Precondition("JOB-R28: attempt still live"));
        };
        if now < r + w {
            return Err(DomainError::Precondition("JOB-R28: retention not over"));
        }
        if self.delivery.has_provisional(job, Some(attempt)) {
            return Err(DomainError::Precondition(
                "JOB-R28: provisional or contested outputs pending",
            ));
        }
        self.attempt_mut(job, attempt)?.buffer_purged = true;
        self.delivery.stop_replay(job, attempt);
        self.audit.push(AuditEvent::BufferPurged { job, attempt });
        Ok(Outcome::Applied)
    }

    pub(super) fn witness_lost(&mut self, job: JobId, attempt: u32) -> R<Outcome> {
        let j = self.job_mut(job)?;
        let a = j
            .attempts
            .get_mut(&attempt)
            .ok_or(DomainError::StaleAttempt)?;
        if a.witness_lost {
            return Ok(Outcome::AlreadyApplied);
        }
        a.witness_lost = true;
        self.delivery.stop_replay(job, attempt);
        Ok(Outcome::Applied)
    }

    /// Uncontested provisional outputs whose window expired, in position order. Stops at the first
    /// contested or not yet due one, since later outputs depend on it (JOB-R29, JOB-R33).
    pub(super) fn window_due(&self, job: JobId) -> Vec<OutputId> {
        let now = self.now;
        let w = self.cfg.delivery_window;
        let Ok(j) = self.job(job) else { return vec![] };
        let mut due = Vec::new();
        for wt in WorkType::ALL {
            let t = wt.idx();
            for pos in j.validated[t]..j.delivered[t] {
                let o = OutputId { job, wt, pos };
                let Some(ch) = self.delivery.charge(o) else {
                    break;
                };
                if ch.definitive {
                    continue;
                }
                let expired = j.attempts[&ch.attempt]
                    .revoked_at
                    .is_some_and(|r| now >= r + w);
                if ch.contest.is_some() || !expired {
                    break;
                }
                due.push(o);
            }
        }
        due
    }

    /// JOB-R29: an attested delivery with no contest during the window becomes definitive.
    pub(super) fn expire_delivery_window(&mut self, job: JobId) -> R<Outcome> {
        let due = self.window_due(job);
        if due.is_empty() {
            return Err(DomainError::Precondition(
                "JOB-R29: no delivery window expired",
            ));
        }
        for o in &due {
            self.make_definitive(*o, ChargeBasis::WindowExpired)?;
        }
        for o in due {
            self.resolve_awaiting(o)?;
        }
        Ok(Outcome::Applied)
    }

    /// JOB-R29: rewinds to `to`. Every charged output of this type from `to` on is provisional and
    /// voided; a live attempt built on them is revoked.
    pub(super) fn rewind(&mut self, job: JobId, wt: WorkType, to: u32) -> R {
        let t = wt.idx();
        let from = self.job(job)?.delivered[t];
        for pos in (to..from).rev() {
            self.void_output(OutputId { job, wt, pos })?;
        }
        {
            let j = self.job_mut(job)?;
            j.delivered[t] = to;
            j.version += 1;
        }
        self.audit.push(AuditEvent::Rewound { job, wt, from, to });
        let j = self.job(job)?;
        let live = j
            .current()
            .is_some_and(|a| a.revoked_at.is_none() && a.produced[t] > to);
        if live {
            match j.exec {
                ExecStatus::Running => {
                    self.revoke_current(job)?;
                    self.job_mut(job)?.intent = Intent::Resume;
                    self.set_exec(job, ExecStatus::Recovering, "JOB-T08")?;
                }
                ExecStatus::Placing => {
                    self.revoke_current(job)?;
                    let back = self
                        .job(job)?
                        .placing_from
                        .ok_or_else(|| DomainError::Internal("placing_from".into()))?;
                    self.set_exec(job, back, "JOB-T06")?;
                }
                other => return Err(DomainError::Internal(format!("live attempt in {other:?}"))),
            }
        }
        Ok(())
    }

    /// Voids a provisional output: its reserved contributions are returned, then its price goes
    /// back to work escrow (JOB-R29, JOB-R30).
    pub(super) fn void_output(&mut self, output: OutputId) -> R {
        let ch = *self
            .delivery
            .charge(output)
            .ok_or_else(|| DomainError::Internal(format!("void uncharged {output:?}")))?;
        if ch.definitive {
            return Err(DomainError::Internal(format!(
                "voiding a definitive output {output:?}"
            )));
        }
        let mut touched = Vec::new();
        let targets = self.items_of(output, ch.gen);
        for (slice, lender, idx) in targets {
            let st = self.slices[&slice].lines[&lender].items[idx].status;
            match st {
                ItemStatus::PendingEvaluation | ItemStatus::Disputed => {
                    self.refund_item(slice, lender, idx, RefundReason::OutputVoided)?;
                    touched.push(slice);
                }
                ItemStatus::Refunded => {}
                ItemStatus::Paid => {
                    return Err(DomainError::Internal(format!(
                        "contribution of provisional {output:?} was paid"
                    )))
                }
            }
        }
        let price = self.job(output.job)?.price[output.wt.idx()];
        self.ledger_op(LedgerOp::VoidOutput {
            job: job_acct(output.job),
            key: format!(
                "void/{}/{:?}/{}/{}",
                output.job.0, output.wt, output.pos, ch.gen
            ),
            amount: price,
        })?;
        self.delivery.void(output)?;
        self.audit.push(AuditEvent::OutputVoided {
            output,
            gen: ch.gen,
            amount: price,
        });
        for s in touched {
            self.maybe_finalize_disputed(s)?;
        }
        Ok(())
    }
}
