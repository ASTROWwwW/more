//! Protocol edge (spec section 5). Authenticates each message (Ed25519, `more-identity`), guards
//! against replays, turns it into a domain command whose actor is the authenticated sender, and
//! hands it to the coordinator with an [`more_identity::AuthContext`]. The wire transport (QUIC)
//! is not here yet; the fixed binary encoding of what is signed is.

mod dispatch;
mod envelope;
mod errors;
mod limits;
mod messages;
mod replay_guard;

pub use dispatch::{handle, to_command};
pub use envelope::{Envelope, PROTOCOL_VERSION};
pub use errors::{domain_code, ProtoError};
pub use limits::check_frame;
pub use messages::{Message, MessageKind};
pub use replay_guard::{Admission, Answer, ReplayGuard, RECENT};

#[cfg(test)]
mod tests {
    use super::*;
    use gpu_domain::{AccountId, JobId, Outcome};
    use more_identity::UserKey;

    fn env(session: u64, seq: u64, body: Message) -> Envelope {
        Envelope::signed(
            AccountId(9),
            session,
            seq,
            body,
            &UserKey::from_seed([9; 32]),
        )
    }

    #[test]
    fn oversized_frame_rejected_before_decoding() {
        assert_eq!(
            check_frame(MessageKind::TokenAck, 513),
            Err(ProtoError::FrameTooLarge)
        );
        assert!(check_frame(MessageKind::TokenAck, 512).is_ok());
    }

    #[test]
    fn signature_covers_every_field() {
        let a = env(1, 5, Message::CancelJob { job: JobId(1) });
        let mut b = a.clone();
        b.body = Message::CancelJob { job: JobId(2) };
        assert_ne!(a.signing_bytes(), b.signing_bytes());
        let mut c = a.clone();
        c.session = 2;
        assert_ne!(a.signing_bytes(), c.signing_bytes());
    }

    #[test]
    fn replay_policy() {
        let mut g = ReplayGuard::default();
        let m = Message::CancelJob { job: JobId(1) };
        let first = env(1, 5, m.clone());
        assert_eq!(g.admit(&first), Ok(Admission::Fresh));
        let answer = Err(ProtoError::Rejected("STALE_ATTEMPT"));
        g.record(&first, &answer);
        // Exact retransmission: same answer, nothing run again.
        assert_eq!(g.admit(&first), Ok(Admission::Retransmission(answer)));
        // Same number, other content: replay.
        assert_eq!(
            g.admit(&env(1, 5, Message::CancelJob { job: JobId(2) })),
            Err(ProtoError::Replay)
        );
        // Older number never seen: replay.
        assert_eq!(g.admit(&env(1, 4, m.clone())), Err(ProtoError::Replay));
        // Restarted sender opens session 2 and starts again at 1.
        assert_eq!(g.admit(&env(2, 1, m.clone())), Ok(Admission::Fresh));
        // Session 1 is closed for good.
        assert_eq!(g.admit(&env(1, 6, m)), Err(ProtoError::StaleSession));
    }

    #[test]
    fn retransmission_window_is_bounded() {
        let mut g = ReplayGuard::default();
        let m = |j| Message::CancelJob { job: JobId(j) };
        for seq in 1..=(RECENT as u64 + 1) {
            let e = env(1, seq, m(seq as u32));
            assert_eq!(g.admit(&e), Ok(Admission::Fresh));
            g.record(&e, &Ok(Outcome::Applied));
        }
        // The oldest answer was dropped: its retransmission is now refused, not run again.
        assert_eq!(g.admit(&env(1, 1, m(1))), Err(ProtoError::Replay));
        assert_eq!(
            g.admit(&env(1, 2, m(2))),
            Ok(Admission::Retransmission(Ok(Outcome::Applied)))
        );
    }
}
