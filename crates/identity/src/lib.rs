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
    lease_message, mandate_message, ready_message, receipt_message, relay_message, restore_message,
    Assignment, Domain, JobTerms, Readiness, Restoration,
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
    /// The ledger's own identity, shown to the services that connect to it.
    Ledger,
    /// Registers account keys with the ledger. No right on credits.
    Identity,
}

impl ServiceRole {
    /// Inverse of `role as u8`, for certificates read from the wire.
    pub fn from_u8(b: u8) -> Option<Self> {
        use ServiceRole::*;
        [
            Clock,
            Treasury,
            PlatformAdmin,
            Scheduler,
            Reconciler,
            Orchestrator,
            Delivery,
            Auditor,
            Ledger,
            Identity,
        ]
        .into_iter()
        .find(|r| *r as u8 == b)
    }
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

/// Public half of a service's identity: its id, its role and its own public key, signed by the
/// [`IdentityAuthority`]. It can be shown to anyone and proves nothing alone: the service also
/// has to sign with the matching key (see [`ServiceCredential::sign`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ServiceCertificate {
    id: ServiceId,
    role: ServiceRole,
    key: [u8; 32],
    tag: [u8; 64],
}

impl ServiceCertificate {
    /// Encoded size: id, role, key, tag.
    pub const LEN: usize = 4 + 1 + 32 + 64;

    pub fn id(&self) -> ServiceId {
        self.id
    }

    pub fn role(&self) -> ServiceRole {
        self.role
    }

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..4].copy_from_slice(&self.id.0.to_le_bytes());
        out[4] = self.role as u8;
        out[5..37].copy_from_slice(&self.key);
        out[37..].copy_from_slice(&self.tag);
        out
    }

    /// `None` unless `bytes` is exactly one certificate with a known role.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; Self::LEN] = bytes.try_into().ok()?;
        Some(ServiceCertificate {
            id: ServiceId(u32::from_le_bytes(bytes[..4].try_into().ok()?)),
            role: ServiceRole::from_u8(bytes[4])?,
            key: bytes[5..37].try_into().ok()?,
            tag: bytes[37..].try_into().ok()?,
        })
    }

    /// Checks a signature made with the service's own key. It says nothing about who certified
    /// that key: check the certificate with [`CredentialVerifier::verify_certificate`] first.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), AuthError> {
        let key = VerifyingKey::from_bytes(&self.key).map_err(|_| AuthError::InvalidCredential)?;
        key.verify(message, &Signature::from_bytes(signature))
            .map_err(|_| AuthError::BadSignature)
    }
}

impl fmt::Debug for ServiceCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceCertificate({:?}, {:?})", self.id, self.role)
    }
}

/// Identity of one service: its certificate and the private key that goes with it. The key
/// never leaves the service; what travels is the certificate and signatures made with the key,
/// so a copied certificate is useless to whoever copied it.
#[derive(Clone)]
pub struct ServiceCredential {
    cert: ServiceCertificate,
    key: SigningKey,
}

impl ServiceCredential {
    /// Encoded size: the key's seed, then the certificate.
    pub const LEN: usize = 32 + ServiceCertificate::LEN;

    pub fn id(&self) -> ServiceId {
        self.cert.id
    }

    pub fn role(&self) -> ServiceRole {
        self.cert.role
    }

    pub fn certificate(&self) -> ServiceCertificate {
        self.cert
    }

    /// Signs with the service's own key (proof of possession).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }

    /// Secret material, for provisioning a service from a file readable by that service only.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..32].copy_from_slice(&self.key.to_bytes());
        out[32..].copy_from_slice(&self.cert.to_bytes());
        out
    }

    /// `None` unless the key is the one the certificate names.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let seed: [u8; 32] = bytes.get(..32)?.try_into().ok()?;
        let cert = ServiceCertificate::from_bytes(bytes.get(32..)?)?;
        let key = SigningKey::from_bytes(&seed);
        (key.verifying_key().to_bytes() == cert.key).then_some(ServiceCredential { cert, key })
    }
}

impl PartialEq for ServiceCredential {
    fn eq(&self, other: &Self) -> bool {
        self.cert == other.cert
    }
}

impl Eq for ServiceCredential {}

impl fmt::Debug for ServiceCredential {
    // Never prints the key or the tag.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ServiceCredential({:?}, {:?})",
            self.cert.id, self.cert.role
        )
    }
}

fn credential_message(id: ServiceId, role: ServiceRole, key: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(48);
    msg.extend_from_slice(b"more/svc/v2");
    msg.extend_from_slice(&id.0.to_le_bytes());
    msg.push(role as u8);
    msg.extend_from_slice(key);
    msg
}

fn revocation_message(id: ServiceId) -> Vec<u8> {
    let mut msg = Vec::with_capacity(24);
    msg.extend_from_slice(b"more/svc-revoke/v1");
    msg.extend_from_slice(&id.0.to_le_bytes());
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

    /// Certifies a key the service generated itself: the authority never sees the private half.
    pub fn certify(&mut self, role: ServiceRole, service_key: [u8; 32]) -> ServiceCertificate {
        let id = ServiceId(self.next_id);
        self.next_id += 1;
        let tag = self.key.sign(&credential_message(id, role, &service_key));
        ServiceCertificate {
            id,
            role,
            key: service_key,
            tag: tag.to_bytes(),
        }
    }

    /// Mints a whole identity, key included. For the model and its tests: the key is derived
    /// from the authority's, so runs are reproducible. A deployed service generates its own key
    /// and asks for [`IdentityAuthority::certify`].
    pub fn issue(&mut self, role: ServiceRole) -> ServiceCredential {
        let mut label = b"more/svc-key/v1".to_vec();
        label.extend_from_slice(&self.next_id.to_le_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.key.sign(&label).to_bytes()[..32]);
        let key = SigningKey::from_bytes(&seed);
        let cert = self.certify(role, key.verifying_key().to_bytes());
        ServiceCredential { cert, key }
    }

    pub fn revoke(&self, id: ServiceId) {
        // A poisoned lock means a panic while revoking: keep the revocation anyway.
        let mut set = self.revoked.write().unwrap_or_else(|e| e.into_inner());
        set.insert(id);
    }

    /// A revocation any verifier of this authority accepts, wherever it runs
    /// ([`CredentialVerifier::apply_revocation`]).
    pub fn revocation(&self, id: ServiceId) -> [u8; 64] {
        self.key.sign(&revocation_message(id)).to_bytes()
    }

    /// This deployment's identifier in signed statements (LEDGER-019).
    pub fn domain(&self) -> Domain {
        Domain(self.key.verifying_key().to_bytes())
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

/// (service id, role, service key, tag) of a certificate whose signature was checked. The key is
/// part of it: a checked tag must not vouch for another key.
type CredentialKey = (u32, u8, [u8; 32], [u8; 64]);

/// Checks that a credential was minted by the authority and is not revoked.
#[derive(Clone)]
pub struct CredentialVerifier {
    authority: VerifyingKey,
    revoked: Arc<RwLock<BTreeSet<ServiceId>>>,
    /// Credentials whose signature already verified. Revocation is still checked every time.
    seen: Arc<RwLock<BTreeSet<CredentialKey>>>,
}

impl CredentialVerifier {
    /// A verifier for a process that only knows the authority's public key (its domain). It
    /// starts with no revocation; those arrive signed ([`CredentialVerifier::apply_revocation`]).
    pub fn for_domain(domain: Domain) -> Option<Self> {
        Some(CredentialVerifier {
            authority: VerifyingKey::from_bytes(domain.as_bytes()).ok()?,
            revoked: Arc::default(),
            seen: Arc::default(),
        })
    }

    /// The deployment this verifier belongs to: statements signed for another one are void here.
    pub fn domain(&self) -> Domain {
        Domain(self.authority.to_bytes())
    }

    /// Records a revocation signed by the authority. Anyone may deliver it: only the authority
    /// can have signed it.
    pub fn apply_revocation(&self, id: ServiceId, signature: &[u8; 64]) -> Result<(), AuthError> {
        self.authority
            .verify(&revocation_message(id), &Signature::from_bytes(signature))
            .map_err(|_| AuthError::BadSignature)?;
        let mut set = self.revoked.write().unwrap_or_else(|e| e.into_inner());
        set.insert(id);
        Ok(())
    }

    pub fn verify(&self, cred: &ServiceCredential) -> Result<ServiceRole, AuthError> {
        self.verify_certificate(&cred.cert)
    }

    /// The certificate was signed by the authority and is not revoked. The caller still has to
    /// check that its peer holds the certified key.
    pub fn verify_certificate(&self, cred: &ServiceCertificate) -> Result<ServiceRole, AuthError> {
        let key = (cred.id.0, cred.role as u8, cred.key, cred.tag);
        let known = self
            .seen
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&key);
        if !known {
            self.authority
                .verify(
                    &credential_message(cred.id, cred.role, &cred.key),
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
    /// Signature checks done through this directory (cost accounting).
    checks: Arc<std::sync::atomic::AtomicU64>,
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

    /// Same, for a key received as bytes. Bytes that are not a public key are refused.
    pub fn register_bytes(&self, account: AccountNo, key: &[u8; 32]) -> Result<(), AuthError> {
        let key = VerifyingKey::from_bytes(key).map_err(|_| AuthError::InvalidCredential)?;
        self.register(account, key)
    }

    /// Number of signature checks done through this directory and its clones.
    pub fn signature_checks(&self) -> u64 {
        self.checks.load(std::sync::atomic::Ordering::Relaxed)
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
        self.checks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
    Service(Box<ServiceCredential>),
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
            principal: Principal::Service(Box::new(cred)),
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
            Principal::Service(c) => Some(c.role()),
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
        forged.cert.role = ServiceRole::Treasury;
        assert_eq!(v.verify(&forged), Err(AuthError::InvalidCredential));
        // Nor can the certified key be swapped for another one.
        let mut rekeyed = cred.certificate();
        rekeyed.key = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes();
        assert_eq!(
            v.verify_certificate(&rekeyed),
            Err(AuthError::InvalidCredential)
        );
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
    fn domain_is_the_authority_and_nothing_else() {
        let (a, b) = (
            IdentityAuthority::new([7; 32]),
            IdentityAuthority::new([8; 32]),
        );
        assert_eq!(a.domain(), a.verifier().domain());
        assert_eq!(a.domain(), IdentityAuthority::new([7; 32]).domain());
        assert_ne!(a.domain(), b.domain());
    }

    /// A certificate is public: showing it proves nothing. Only the holder of the certified key
    /// can sign for the service, and a credential read back from bytes must match its key.
    #[test]
    fn a_certificate_without_its_key_proves_nothing() {
        let mut auth = IdentityAuthority::new([7; 32]);
        let v = auth.verifier();
        let (orch, treasury) = (
            auth.issue(ServiceRole::Orchestrator),
            auth.issue(ServiceRole::Treasury),
        );
        let cert = treasury.certificate();
        assert_eq!(v.verify_certificate(&cert), Ok(ServiceRole::Treasury));
        assert_eq!(cert.verify(b"nonce", &treasury.sign(b"nonce")), Ok(()));
        assert_eq!(
            cert.verify(b"nonce", &orch.sign(b"nonce")),
            Err(AuthError::BadSignature)
        );
        assert_eq!(
            cert.verify(b"other", &treasury.sign(b"nonce")),
            Err(AuthError::BadSignature)
        );
        // Round trips, and a key grafted onto someone else's certificate is refused.
        let bytes = treasury.to_bytes();
        assert_eq!(
            ServiceCredential::from_bytes(&bytes),
            Some(treasury.clone())
        );
        assert_eq!(ServiceCertificate::from_bytes(&cert.to_bytes()), Some(cert));
        let mut grafted = bytes;
        grafted[..32].copy_from_slice(&orch.to_bytes()[..32]);
        assert_eq!(ServiceCredential::from_bytes(&grafted), None);
        assert_eq!(ServiceCredential::from_bytes(&bytes[1..]), None);
        let mut unknown_role = cert.to_bytes();
        unknown_role[4] = 200;
        assert_eq!(ServiceCertificate::from_bytes(&unknown_role), None);
        // A service that made its own key is certified without the authority seeing it.
        let own = SigningKey::from_bytes(&[9; 32]);
        let cert = auth.certify(ServiceRole::Ledger, own.verifying_key().to_bytes());
        assert_eq!(v.verify_certificate(&cert), Ok(ServiceRole::Ledger));
        for r in 0..=255u8 {
            if let Some(role) = ServiceRole::from_u8(r) {
                assert_eq!(role as u8, r);
            }
        }
    }

    /// A process that only knows the authority's public key learns of a revocation through a
    /// statement the authority signed. Nobody else can revoke.
    #[test]
    fn revocations_travel_signed() {
        let mut auth = IdentityAuthority::new([7; 32]);
        let other = IdentityAuthority::new([8; 32]);
        let (a, b) = (
            auth.issue(ServiceRole::Scheduler),
            auth.issue(ServiceRole::Clock),
        );
        let remote = CredentialVerifier::for_domain(auth.domain()).unwrap();
        assert_eq!(remote.domain(), auth.domain());
        assert_eq!(remote.verify(&a), Ok(ServiceRole::Scheduler));
        assert_eq!(
            remote.apply_revocation(a.id(), &other.revocation(a.id())),
            Err(AuthError::BadSignature)
        );
        assert_eq!(
            remote.apply_revocation(a.id(), &auth.revocation(b.id())),
            Err(AuthError::BadSignature)
        );
        assert_eq!(remote.verify(&a), Ok(ServiceRole::Scheduler));
        assert_eq!(
            remote.apply_revocation(a.id(), &auth.revocation(a.id())),
            Ok(())
        );
        assert_eq!(remote.verify(&a), Err(AuthError::RevokedCredential));
        assert_eq!(remote.verify(&b), Ok(ServiceRole::Clock));
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
