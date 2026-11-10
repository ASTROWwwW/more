//! Envelope shared by every message (PROTO-001): version, sender, session, sequence, body and an
//! Ed25519 signature over all of them.

use gpu_domain::AccountId;
use more_identity::{Domain, UserKey};
use sha2::{Digest, Sha256};

use crate::messages::Message;

pub const PROTOCOL_VERSION: u16 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub version: u16,
    /// The deployment the message is meant for (LEDGER-019). Signed with the rest, so a message
    /// captured in one deployment is void in another.
    pub domain: Domain,
    pub sender: AccountId,
    /// Sender session. A sender that restarts opens a new, higher session; sequence numbers start
    /// again in it, and messages of older sessions are refused (SEC-005).
    pub session: u64,
    /// Strictly increasing within a session.
    pub seq: u64,
    pub body: Message,
    /// Ed25519 signature of [`Envelope::signing_bytes`] by the sender's registered key.
    pub signature: [u8; 64],
}

impl Envelope {
    /// The exact bytes the sender signs.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(b"more/envelope/v3");
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(self.domain.as_bytes());
        out.extend_from_slice(&self.sender.0.to_le_bytes());
        out.extend_from_slice(&self.session.to_le_bytes());
        out.extend_from_slice(&self.seq.to_le_bytes());
        self.body.encode(&mut out);
        out
    }

    /// Builds and signs an envelope.
    pub fn signed(
        domain: Domain,
        sender: AccountId,
        session: u64,
        seq: u64,
        body: Message,
        key: &UserKey,
    ) -> Self {
        let mut env = Envelope {
            version: PROTOCOL_VERSION,
            domain,
            sender,
            session,
            seq,
            body,
            signature: [0; 64],
        };
        env.signature = key.sign(&env.signing_bytes());
        env
    }

    /// Digest of the signed content, used to recognize an exact retransmission.
    pub(crate) fn content_hash(&self) -> [u8; 32] {
        Sha256::digest(self.signing_bytes()).into()
    }
}
