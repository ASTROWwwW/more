//! Output delivery: charges, witness attestations, client acks and statements (section 2.4, JOB-R23, JOB-R26 to JOB-R28, JOB-R32, JOB-R34).

use super::*;

impl Coordinator {
    /// Charges an output (work escrow to output hold), provisionally or definitively, and binds it
    /// to its attempt (JOB-R17).
    pub(super) fn charge_output(
        &mut self,
        output: OutputId,
        attempt: u32,
        definitive: bool,
        basis: ChargeBasis,
    ) -> R {
        if self.delivery.charge(output).is_some() {
            return Err(DomainError::Internal(format!(
                "output charged twice: {output:?}"
            )));
        }
        let (price, replayable) = {
            let j = self.job(output.job)?;
            let a = j
                .attempts
                .get(&attempt)
                .ok_or_else(|| DomainError::Internal("attempt".into()))?;
            (
                j.price[output.wt.idx()],
                !a.witness_lost && !a.buffer_purged,
            )
        };
        let gen = self.delivery.generation(output);
        let moved = self.ledger_op(LedgerOp::ChargeOutput {
            job: job_acct(output.job),
            attempt,
            output: output_ref(output),
            gen,
        })?;
        if moved != LedgerOutcome::Moved(price) {
            return Err(DomainError::Internal(format!(
                "charge of {output:?}: ledger {moved:?}, price {price}"
            )));
        }
        self.delivery
            .record_charge(output, attempt, definitive, basis, replayable)?;
        self.audit.push(AuditEvent::OutputCharged {
            output,
            attempt,
            amount: price,
            gen,
            provisional: !definitive,
        });
        Ok(())
    }

    /// Makes a provisional output definitive. Returns true if it was provisional.
    pub(super) fn make_definitive(&mut self, output: OutputId, basis: ChargeBasis) -> R<bool> {
        if !self.delivery.make_definitive(output, basis)? {
            return Ok(false);
        }
        self.audit
            .push(AuditEvent::OutputConfirmed { output, basis });
        Ok(true)
    }

    /// JOB-R26, JOB-R27: delivery attestation by the assigned witness.
    pub(super) fn deliver(
        &mut self,
        job: JobId,
        attempt: u32,
        witness: AccountId,
        wt: WorkType,
        upto: u32,
        digest: u64,
    ) -> R<Outcome> {
        let now = self.now;
        let drain = self.cfg.drain_window;
        let j = self.job(job)?;
        let a = j
            .attempts
            .get(&attempt)
            .ok_or(DomainError::StaleAttempt)?
            .clone();
        let late = match a.revoked_at {
            None => {
                self.current_live_attempt(job, attempt)?;
                false
            }
            Some(r) => {
                // JOB-R32: late attestations only while draining, and only if no newer attempt was
                // placed.
                if attempt != j.attempt || now > r + drain {
                    return Err(DomainError::StaleAttempt);
                }
                true
            }
        };
        // Only the assigned witness can attest; a lender attesting its own delivery proves nothing
        // (JOB-R26).
        if witness != a.witness || a.witness_lost || a.buffer_purged {
            return Err(DomainError::InadmissibleProof);
        }
        let t = wt.idx();
        let from = j.delivered[t];
        if upto <= from {
            return Ok(Outcome::AlreadyApplied);
        }
        if upto > a.produced[t] {
            return Err(DomainError::Precondition(
                "JOB-R27: attestation beyond produced",
            ));
        }
        // JOB-R34: the digest must match the frames signed by the output node for this stream;
        // substituted or foreign frames are rejected.
        if digest != self.frame_digest(job, wt, upto) {
            return Err(DomainError::InadmissibleProof);
        }
        if late {
            let cutoff = a.revoked_seq.unwrap_or(0);
            if !self
                .delivery
                .witness_committed_before((job, attempt, wt), upto, cutoff)
            {
                return Err(DomainError::InadmissibleProof);
            }
        }
        for pos in from..upto {
            self.charge_output(
                OutputId { job, wt, pos },
                attempt,
                false,
                ChargeBasis::Witnessed,
            )?;
        }
        let j = self.job_mut(job)?;
        j.delivered[t] = upto;
        j.intent = Intent::Resume;
        j.version += 1;
        self.audit.push(if late {
            AuditEvent::LateDelivery {
                job,
                attempt,
                wt,
                to: upto,
            }
        } else {
            AuditEvent::Delivered {
                job,
                attempt,
                wt,
                from,
                to: upto,
            }
        });
        Ok(Outcome::Applied)
    }

    /// Chained digest of a stream's frames `0..upto` (JOB-R34): job, client stream, model, type,
    /// and each position with its billing generation. FNV-1a in the model.
    pub fn frame_digest(&self, job: JobId, wt: WorkType, upto: u32) -> u64 {
        let Ok(j) = self.job(job) else { return 0 };
        let mut h = fnv(&[
            u64::from(job.0),
            j.stream,
            u64::from(j.model.0),
            wt.idx() as u64,
        ]);
        for pos in 0..upto {
            let gen = self.delivery.generation(OutputId { job, wt, pos });
            h = fnv(&[h, u64::from(pos), u64::from(gen)]);
        }
        h
    }

    /// JOB-R32: short witness commitment, live attempt only.
    pub(super) fn witness_commit(
        &mut self,
        job: JobId,
        attempt: u32,
        witness: AccountId,
        wt: WorkType,
        upto: u32,
    ) -> R<Outcome> {
        let a = self.current_live_attempt(job, attempt)?;
        if witness != a.witness || a.witness_lost {
            return Err(DomainError::InadmissibleProof);
        }
        if upto > a.produced[wt.idx()] {
            return Err(DomainError::Precondition(
                "JOB-R32: commitment beyond produced",
            ));
        }
        let seq = self.seq;
        Ok(
            if self
                .delivery
                .record_witness_commit((job, attempt, wt), upto, seq)
            {
                Outcome::Applied
            } else {
                Outcome::AlreadyApplied
            },
        )
    }

    pub(super) fn ack(&mut self, job: JobId, attempt: u32, wt: WorkType, upto: u32) -> R<Outcome> {
        let a = self.current_live_attempt(job, attempt)?;
        let t = wt.idx();
        let produced = a.produced[t];
        let j = self.job(job)?;
        let from = j.validated[t];
        let delivered = j.delivered[t];
        if upto <= from {
            return Ok(Outcome::AlreadyApplied);
        }
        if upto > produced {
            return Err(DomainError::Precondition("ack beyond produced"));
        }
        // JOB-R23: client acks are cumulative. Delivered (provisional) positions become definitive;
        // later ones are charged now, once (JOB-R17).
        let mut resolved = Vec::new();
        for pos in from..upto {
            let output = OutputId { job, wt, pos };
            if pos < delivered {
                if self.make_definitive(output, ChargeBasis::ClientSigned)? {
                    resolved.push(output);
                }
            } else {
                self.charge_output(output, attempt, true, ChargeBasis::ClientSigned)?;
            }
        }
        let now = self.now;
        let j = self.job_mut(job)?;
        j.validated[t] = upto;
        j.delivered[t] = j.delivered[t].max(upto);
        j.last_ack_at = now;
        j.intent = Intent::Resume;
        j.version += 1;
        self.audit.push(AuditEvent::Validated {
            job,
            attempt,
            wt,
            from,
            to: upto,
        });
        for o in resolved {
            self.resolve_awaiting(o)?;
        }
        Ok(Outcome::Applied)
    }

    /// JOB-R28, JOB-R29: signed client statement "I hold exactly `0..confirmed`". Earlier positions
    /// become definitive; missing ones are replayed, or voided with everything after them if the
    /// buffer is lost.
    pub(super) fn confirm_delivery(
        &mut self,
        job: JobId,
        wt: WorkType,
        confirmed: u32,
        digest: u64,
    ) -> R<Outcome> {
        let now = self.now;
        let w = self.cfg.delivery_window;
        let resolution = self.cfg.contest_resolution;
        let j = self.job(job)?;
        if j.settle == SettleStatus::Closed {
            return Err(DomainError::Precondition("JOB-R28: job closed"));
        }
        let t = wt.idx();
        let (validated, delivered) = (j.validated[t], j.delivered[t]);
        if confirmed < validated {
            return Err(DomainError::Precondition(
                "JOB-R28: a validated position cannot be unconfirmed",
            ));
        }
        if confirmed > delivered {
            return Err(DomainError::Precondition(
                "JOB-R28: confirmed beyond delivered",
            ));
        }
        // JOB-R34: the statement is bound to the stream by the prefix digest; one from another
        // session is rejected.
        if digest != self.frame_digest(job, wt, confirmed) {
            return Err(DomainError::InadmissibleProof);
        }
        // Missing outputs: contest them (window open), or just retransmit (already definitive or
        // contested).
        let mut to_contest = Vec::new();
        let mut first_lost = None;
        for pos in confirmed..delivered {
            let output = OutputId { job, wt, pos };
            let ch = self.delivery.charge(output).ok_or_else(|| {
                DomainError::Internal(format!("delivered but uncharged {output:?}"))
            })?;
            let producer = j
                .attempts
                .get(&ch.attempt)
                .ok_or_else(|| DomainError::Internal("attempt".into()))?;
            // An output of the live attempt is retransmitted, not contested.
            let Some(revoked) = producer.revoked_at else {
                return Err(DomainError::Precondition(
                    "JOB-R28: missing output of the live attempt (retransmit)",
                ));
            };
            let window_open = now < revoked + w;
            let provisional = !ch.definitive && (ch.contest.is_some() || window_open);
            if !ch.replayable {
                if !provisional {
                    return Err(DomainError::Precondition(
                        "JOB-R29: definitive output can no longer be replayed",
                    ));
                }
                // Witness cannot produce the buffer: refund (JOB-R33).
                first_lost = Some(pos);
                break;
            }
            if provisional && ch.contest.is_none() {
                to_contest.push(output);
            }
        }
        if confirmed == validated && to_contest.is_empty() && first_lost.is_none() {
            return Ok(Outcome::AlreadyApplied);
        }
        let mut resolved = Vec::new();
        for pos in validated..confirmed {
            let output = OutputId { job, wt, pos };
            if self.make_definitive(output, ChargeBasis::ClientSigned)? {
                resolved.push(output);
            }
        }
        {
            let j = self.job_mut(job)?;
            j.validated[t] = confirmed;
            j.version += 1;
        }
        // One contest per output: replay requested, deadline set. Only a signed cumulative ack
        // covering it makes it definitive.
        for output in to_contest {
            let deadline = now + resolution;
            self.delivery.open_contest(
                output,
                Contest {
                    opened_at: now,
                    deadline,
                },
            )?;
            self.audit
                .push(AuditEvent::ContestOpened { output, deadline });
            self.audit.push(AuditEvent::Replayed { output });
        }
        if let Some(p) = first_lost {
            self.rewind(job, wt, p)?;
        }
        for o in resolved {
            self.resolve_awaiting(o)?;
        }
        Ok(Outcome::Applied)
    }
}
