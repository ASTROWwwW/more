//! Size limits checked before any decoding (PROTO-002). Provisional values.

use crate::errors::ProtoError;
use crate::messages::MessageKind;

impl MessageKind {
    pub fn max_frame_bytes(self) -> usize {
        match self {
            MessageKind::SubmitJob | MessageKind::RegisterModel => 4 * 1024,
            MessageKind::UsageReport => 64 * 1024,
            _ => 512,
        }
    }
}

/// Checks a frame's declared size BEFORE decoding it (PROTO-002).
pub fn check_frame(kind: MessageKind, declared_len: usize) -> Result<(), ProtoError> {
    if declared_len > kind.max_frame_bytes() {
        return Err(ProtoError::FrameTooLarge);
    }
    Ok(())
}
