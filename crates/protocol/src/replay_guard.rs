//! Replay protection (PROTO-005, SEC-005).
//!
//! Policy:
//! - The guard runs after the signature check, so a forged message cannot consume a sequence
//!   number.
//! - Sequence numbers are per (sender, session) and strictly increasing. A number is consumed when
//!   the message is admitted, whatever the domain answers: a refused command is not retried under
//!   the same number.
//! - An exact retransmission (same session, same number, same signed bytes) of one of the last
//!   [`RECENT`] messages gets the original answer again, without running the command twice. This
//!   covers a response lost on the way back. The same number with different content is a replay.
//! - A higher session closes the previous one: its messages are refused from then on.
//! - Business idempotency does not rely on these numbers: it comes from the domain's own keys (job
//!   id, ledger keys, cumulative acks).
//! - Out-of-order messages within a session are refused; the transport (one ordered stream per
//!   sender) keeps them in order, and a sender resends under a new number.

use std::collections::{BTreeMap, VecDeque};

use gpu_domain::{AccountId, Outcome};

use crate::envelope::Envelope;
use crate::errors::ProtoError;

/// Answers kept per sender for retransmissions.
pub const RECENT: usize = 16;

pub type Answer = Result<Outcome, ProtoError>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SenderState {
    session: u64,
    last_seq: u64,
    recent: VecDeque<(u64, [u8; 32], Answer)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// New message: run it, then [`ReplayGuard::record`] the answer.
    Fresh,
    /// Exact retransmission: answer again with this, run nothing.
    Retransmission(Answer),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayGuard {
    senders: BTreeMap<AccountId, SenderState>,
}

impl ReplayGuard {
    /// Admits an authenticated envelope.
    pub fn admit(&mut self, env: &Envelope) -> Result<Admission, ProtoError> {
        let st = self.senders.entry(env.sender).or_default();
        if env.session < st.session {
            return Err(ProtoError::StaleSession);
        }
        if env.session > st.session {
            *st = SenderState {
                session: env.session,
                ..SenderState::default()
            };
        }
        if env.seq <= st.last_seq {
            let hash = env.content_hash();
            return match st.recent.iter().find(|(s, _, _)| *s == env.seq) {
                Some((_, h, answer)) if *h == hash => Ok(Admission::Retransmission(answer.clone())),
                _ => Err(ProtoError::Replay),
            };
        }
        st.last_seq = env.seq;
        Ok(Admission::Fresh)
    }

    /// Keeps the answer to an admitted message for retransmissions.
    pub fn record(&mut self, env: &Envelope, answer: &Answer) {
        let Some(st) = self.senders.get_mut(&env.sender) else {
            return;
        };
        if st.session != env.session {
            return;
        }
        if st.recent.len() == RECENT {
            st.recent.pop_front();
        }
        st.recent
            .push_back((env.seq, env.content_hash(), answer.clone()));
    }
}
