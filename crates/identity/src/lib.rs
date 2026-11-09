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
use sha2::{Digest, Sha256};

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

/// Credential of one service, minted by the [`IdentityAuthority`]. The tag binds the id and the
/// role to the authority's secret, so a credential cannot be altered or made up, even by code that
/// can see one.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceCredential {
    id: ServiceId,
    role: ServiceRole,
    tag: [u8; 32],
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

fn credential_tag(secret: &[u8; 32], id: ServiceId, role: ServiceRole) -> [u8; 32] {
    // HMAC-SHA256 (RFC 2104) over (id, role).
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, b) in secret.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let mut msg = Vec::with_capacity(16);
    msg.extend_from_slice(b"more/svc/v1");
    msg.extend_from_slice(&id.0.to_le_bytes());
    msg.push(role as u8);
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(&msg)
        .finalize();
    Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize()
        .into()
}

/// Mints and revokes service credentials. Held by the Identity domain only.
pub struct IdentityAuthority {
    secret: [u8; 32],
    next_id: u32,
    revoked: Arc<RwLock<BTreeSet<ServiceId>>>,
}

impl IdentityAuthority {
    /// `secret` must come from a secure random source in a real deployment.
    pub fn new(secret: [u8; 32]) -> Self {
        IdentityAuthority {
            secret,
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
            tag: credential_tag(&self.secret, id, role),
        }
    }

    pub fn revoke(&self, id: ServiceId) {
        // A poisoned lock means a panic while revoking: keep the revocation anyway.
        let mut set = self.revoked.write().unwrap_or_else(|e| e.into_inner());
        set.insert(id);
    }

    /// Verifier handed to the services that must check credentials (the Ledger). It cannot mint.
    pub fn verifier(&self) -> CredentialVerifier {
        CredentialVerifier {
            secret: self.secret,
            revoked: Arc::clone(&self.revoked),
        }
    }
}

/// Checks that a credential was minted by the authority and is not revoked.
#[derive(Clone)]
pub struct CredentialVerifier {
    secret: [u8; 32],
    revoked: Arc<RwLock<BTreeSet<ServiceId>>>,
}

impl CredentialVerifier {
    pub fn verify(&self, cred: &ServiceCredential) -> Result<ServiceRole, AuthError> {
        if credential_tag(&self.secret, cred.id, cred.role) != cred.tag {
            return Err(AuthError::InvalidCredential);
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

/// Bytes a borrower signs to let the Ledger lock up to `max_budget` credits for one job. Binding
/// the job, the pool and the borrower keeps a mandate from being reused elsewhere.
pub fn mandate_message(job: u32, pool: u32, borrower: AccountNo, max_budget: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(36);
    m.extend_from_slice(b"more/mandate/v1");
    m.extend_from_slice(&job.to_le_bytes());
    m.extend_from_slice(&pool.to_le_bytes());
    m.extend_from_slice(&borrower.to_le_bytes());
    m.extend_from_slice(&max_budget.to_le_bytes());
    m
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
