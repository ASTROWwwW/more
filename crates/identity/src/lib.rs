//! Identity / Auth trust domain.
//!
//! Turns a signature or a service credential into an [`AuthContext`], the only proof of identity
//! the other domains accept. Nothing outside this crate can build an `AuthContext`, a
//! [`VerifiedAccount`] or a [`ServiceCredential`]: their fields are private and the only
//! constructors check a signature or are reserved to the [`IdentityAuthority`].
//!
//! What this crate does not do: transport security, key storage, key rotation policy. The model
//! keeps keys in memory.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, RwLock};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

mod statements;

pub use statements::{
    lease_message, mandate_message, ready_message, receipt_message, relay_message, Assignment,
    JobTerms,
};

/// Account number, as used by the ledger and the domain (`AccountId.0`).
pub type AccountNo = u32;

/// Role of a service. Each service gets its own credential; no credential carries more than one
/// role, and no role grants everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServiceRole {
    /// Advances the coordinator clock.
    Clock,
    /// The only role allowed to issue credits (LEDGER-003).
    Treasury,
    /// Creates pools and appoints their admins.
    PlatformAdmin,
    /// Places jobs and drives their lifecycle.
    Scheduler,
    /// Applies due transitions (JOB-R20).
    Reconciler,
    /// The job orchestrator's own identity towards the ledger.
    Orchestrator,
    /// Delivery verification service (future separate process). Has no ledger write right.
    Delivery,
    /// Read-only access to every domain, for invariant checks and audits.
    Auditor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceId(pub u32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    UnknownAccount,
    BadSignature,
    KeyAlreadyRegistered,
    InvalidCredential,
    RevokedCredential,
}

impl AuthError {
    pub fn code(&self) -> &'static str {
        match self {
            AuthError::UnknownAccount => "UNKNOWN_ACCOUNT",
            AuthError::BadSignature => "BAD_SIGNATURE",
            AuthError::KeyAlreadyRegistered => "KEY_ALREADY_REGISTERED",
            AuthError::InvalidCredential => "INVALID_CREDENTIAL",
            AuthError::RevokedCredential => "REVOKED_CREDENTIAL",
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for AuthError {}

/// Credential of one service, minted by the [`IdentityAuthority`]. The tag is the authority's
/// Ed25519 signature of the id and the role: a credential cannot be altered or made up, and the
/// services that check it hold only the authority's public key, so they cannot mint one either.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceCredential {
    id: ServiceId,
    role: ServiceRole,
    tag: [u8; 64],
}

impl ServiceCredential {
    pub fn id(&self) -> ServiceId {
        self.id
    }

    pub fn role(&self) -> ServiceRole {
        self.role
    }
}

impl fmt::Debug for ServiceCredential {
    // The tag is a secret-derived value: never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceCredential({:?}, {:?})", self.id, self.role)
    }
}

fn credential_message(id: ServiceId, role: ServiceRole) -> Vec<u8> {
    let mut msg = Vec::with_capacity(16);
    msg.extend_from_slice(b"more/svc/v1");
    msg.extend_from_slice(&id.0.to_le_bytes());
    msg.push(role as u8);
    msg
}

/// Mints and revokes service credentials. Held by the Identity domain only: its signing key is
/// the one secret that can create a service identity.
pub struct IdentityAuthority {
    key: SigningKey,
    next_id: u32,
    revoked: Arc<RwLock<BTreeSet<ServiceId>>>,
}

impl IdentityAuthority {
    /// `seed` must come from a secure random source in a real deployment.
    pub fn new(seed: [u8; 32]) -> Self {
        IdentityAuthority {
            key: SigningKey::from_bytes(&seed),
            next_id: 1,
            revoked: Arc::default(),
        }
    }

    pub fn issue(&mut self, role: ServiceRole) -> ServiceCredential {
        let id = ServiceId(self.next_id);
        self.next_id += 1;
        ServiceCredential {
            id,
            role,
            tag: self.key.sign(&credential_message(id, role)).to_bytes(),
        }
    }

    pub fn revoke(&self, id: ServiceId) {
        // A poisoned lock means a panic while revoking: keep the revocation anyway.
        let mut set = self.revoked.write().unwrap_or_else(|e| e.into_inner());
        set.insert(id);
    }

    /// Verifier handed to the services that must check credentials (Ledger, coordinator). It holds
    /// the authority's public key only, so it cannot mint.
    pub fn verifier(&self) -> CredentialVerifier {
        CredentialVerifier {
            authority: self.key.verifying_key(),
            revoked: Arc::clone(&self.revoked),
            seen: Arc::default(),
        }
    }
}

/// (service id, role, tag) of a credential whose signature was checked.
type CredentialKey = (u32, u8, [u8; 64]);

/// Checks that a credential was minted by the authority and is not revoked.
#[derive(Clone)]
pub struct CredentialVerifier {
    authority: VerifyingKey,
    revoked: Arc<RwLock<BTreeSet<ServiceId>>>,
    /// Credentials whose signature already verified. Revocation is still checked every time.
    seen: Arc<RwLock<BTreeSet<CredentialKey>>>,
}

impl CredentialVerifier {
    pub fn verify(&self, cred: &ServiceCredential) -> Result<ServiceRole, AuthError> {
        let key = (cred.id.0, cred.role as u8, cred.tag);
        let known = self
            .seen
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&key);
        if !known {
            self.authority
                .verify(
                    &credential_message(cred.id, cred.role),
                    &Signature::from_bytes(&cred.tag),
                )
                .map_err(|_| AuthError::InvalidCredential)?;
            self.seen
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key);
        }
        let revoked = self.revoked.read().unwrap_or_else(|e| e.into_inner());
        if revoked.contains(&cred.id) {
            return Err(AuthError::RevokedCredential);
        }
        Ok(cred.role)
    }
}

impl fmt::Debug for CredentialVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialVerifier")
    }
}

impl PartialEq for CredentialVerifier {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.revoked, &other.revoked)
    }
}

impl Eq for CredentialVerifier {}

/// Public keys of user accounts. Shared between the protocol edge (envelope signatures) and the
/// Ledger (borrower mandates); only the Identity domain registers keys.
#[derive(Clone, Default)]
pub struct KeyDirectory {
    keys: Arc<RwLock<BTreeMap<AccountNo, VerifyingKey>>>,
}

impl KeyDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the key of a new account. An existing key is never replaced silently: rotation
    /// needs its own, signed, procedure.
    pub fn register(&self, account: AccountNo, key: VerifyingKey) -> Result<(), AuthError> {
        let mut keys = self.keys.write().unwrap_or_else(|e| e.into_inner());
        if keys.contains_key(&account) {
            return Err(AuthError::KeyAlreadyRegistered);
        }
        keys.insert(account, key);
        Ok(())
    }

    pub fn contains(&self, account: AccountNo) -> bool {
        let keys = self.keys.read().unwrap_or_else(|e| e.into_inner());
        keys.contains_key(&account)
    }

    /// Verifies `signature` by `account` over `message`.
    pub fn verify(
        &self,
        account: AccountNo,
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<VerifiedAccount, AuthError> {
        let key = {
            let keys = self.keys.read().unwrap_or_else(|e| e.into_inner());
            *keys.get(&account).ok_or(AuthError::UnknownAccount)?
        };
        key.verify(message, &Signature::from_bytes(signature))
            .map_err(|_| AuthError::BadSignature)?;
        Ok(VerifiedAccount(account))
    }
}

impl fmt::Debug for KeyDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyDirectory")
    }
}

impl PartialEq for KeyDirectory {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.keys, &other.keys)
    }
}

impl Eq for KeyDirectory {}

/// Signing key of a user account. Lives on the user's machine, never in a service.
pub struct UserKey {
    key: SigningKey,
}

impl UserKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        UserKey {
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn public(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }
}

/// An account whose signature was checked. Only [`KeyDirectory::verify`] creates one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedAccount(AccountNo);

impl VerifiedAccount {
    pub fn account(self) -> AccountNo {
        self.0
    }
}

/// Who is calling, as established by this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Principal {
    Account(AccountNo),
    Service(ServiceCredential),
}

/// Verified caller identity handed to the domains. Built only from a [`VerifiedAccount`] or a
/// [`ServiceCredential`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthContext {
    principal: Principal,
}

impl AuthContext {
    pub fn account(v: VerifiedAccount) -> Self {
        AuthContext {
            principal: Principal::Account(v.0),
        }
    }

    pub fn service(cred: ServiceCredential) -> Self {
        AuthContext {
            principal: Principal::Service(cred),
        }
    }

    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    pub fn account_no(&self) -> Option<AccountNo> {
        match &self.principal {
            Principal::Account(a) => Some(*a),
            Principal::Service(_) => None,
        }
    }

    pub fn service_role(&self) -> Option<ServiceRole> {
        match &self.principal {
            Principal::Service(c) => Some(c.role),
            Principal::Account(_) => None,
        }
    }

    pub fn credential(&self) -> Option<&ServiceCredential> {
        match &self.principal {
            Principal::Service(c) => Some(c),
            Principal::Account(_) => None,
        }
    }
}

/// Test support: builds an authenticated account context without a signature. Compiled only with
/// the `test-support` feature, which production builds must not enable. The simulation uses it to
/// test authorization rules on millions of commands; signatures are tested at the protocol edge.
#[cfg(feature = "test-support")]
pub fn assume_account(account: AccountNo) -> AuthContext {
    AuthContext {
        principal: Principal::Account(account),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_cannot_be_altered() {
        let mut auth = IdentityAuthority::new([7; 32]);
        let v = auth.verifier();
        let cred = auth.issue(ServiceRole::Delivery);
        assert_eq!(v.verify(&cred), Ok(ServiceRole::Delivery));
        let mut forged = cred.clone();
        forged.role = ServiceRole::Treasury;
        assert_eq!(v.verify(&forged), Err(AuthError::InvalidCredential));
    }

    #[test]
    fn credential_from_another_authority_is_rejected() {
        let mut other = IdentityAuthority::new([8; 32]);
        let auth = IdentityAuthority::new([7; 32]);
        let cred = other.issue(ServiceRole::Treasury);
        assert_eq!(
            auth.verifier().verify(&cred),
            Err(AuthError::InvalidCredential)
        );
    }

    #[test]
    fn revoked_credential_is_rejected() {
        let mut auth = IdentityAuthority::new([7; 32]);
        let v = auth.verifier();
        let cred = auth.issue(ServiceRole::Scheduler);
        auth.revoke(cred.id());
        assert_eq!(v.verify(&cred), Err(AuthError::RevokedCredential));
    }

    #[test]
    fn signature_checked_against_registered_key() {
        let dir = KeyDirectory::new();
        let alice = UserKey::from_seed([1; 32]);
        let mallory = UserKey::from_seed([2; 32]);
        dir.register(1, alice.public()).unwrap();
        let sig = alice.sign(b"hello");
        assert_eq!(dir.verify(1, b"hello", &sig).map(|v| v.account()), Ok(1));
        assert_eq!(dir.verify(1, b"hello!", &sig), Err(AuthError::BadSignature));
        assert_eq!(
            dir.verify(1, b"hello", &mallory.sign(b"hello")),
            Err(AuthError::BadSignature)
        );
        assert_eq!(
            dir.verify(2, b"hello", &sig),
            Err(AuthError::UnknownAccount)
        );
        assert_eq!(
            dir.register(1, mallory.public()),
            Err(AuthError::KeyAlreadyRegistered)
        );
    }
}
