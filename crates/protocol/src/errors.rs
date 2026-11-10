//! Stable error codes (PROTO-004).

use gpu_domain::DomainError;
use more_identity::AuthError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtoError {
    UnsupportedVersion,
    /// Message signed for another deployment.
    WrongDeployment,
    FrameTooLarge,
    /// Signature missing, malformed or not made by the sender's registered key.
    Unauthenticated(AuthError),
    /// Sequence number already used in this session, with different content.
    Replay,
    /// Message from a session older than the sender's current one.
    StaleSession,
    /// Domain error, by its stable code.
    Rejected(&'static str),
}

impl ProtoError {
    pub fn code(&self) -> &'static str {
        match self {
            ProtoError::UnsupportedVersion => "UNSUPPORTED_VERSION",
            ProtoError::WrongDeployment => "WRONG_DEPLOYMENT",
            ProtoError::FrameTooLarge => "FRAME_TOO_LARGE",
            ProtoError::Unauthenticated(e) => e.code(),
            ProtoError::Replay => "REPLAY",
            ProtoError::StaleSession => "STALE_SESSION",
            ProtoError::Rejected(c) => c,
        }
    }
}

/// Stable code of a domain rejection (PROTO-004).
pub fn domain_code(e: &DomainError) -> &'static str {
    e.code()
}
