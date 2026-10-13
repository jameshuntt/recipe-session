//! Generic recipe-backed session contract primitives.
//!
//! `recipe-session` is intentionally a contract layer only. It does not parse
//! bytes, generate Rust code, open sockets, encrypt payloads, or know about any
//! planner/runtime crate. Later layers can use these validated contracts to
//! negotiate and lock recipe-backed ingress/egress sessions.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use sha2::{Digest, Sha256};

/// Result type for recipe session contract operations.
pub type RecipeSessionResult<T> = Result<T, RecipeSessionError>;

/// Validation failures for recipe-backed session contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipeSessionError {
    EmptyField(&'static str),
    InvalidField {
        field: &'static str,
        value: String,
    },
    DuplicateParticipant(String),
    DuplicatePathPermission {
        direction: RecipeSessionDirection,
        path: String,
    },
    MissingParticipant,
    NotEnoughParticipants,
    MissingPathPermission,
    InvalidLimits(String),
    PathPermissionLimitExceeded {
        actual: usize,
        max: usize,
    },
    InvalidSecurityPolicy(String),
    UnknownParticipant {
        participant_id: String,
    },
    AcceptanceContractIdMismatch {
        expected: String,
        actual: String,
    },
    AcceptanceRecipeRefMismatch {
        expected: String,
        actual: String,
    },
    AcceptanceRecipeManifestHashMismatch {
        expected: String,
        actual: String,
    },
    AcceptancePathManifestHashMismatch {
        expected: String,
        actual: String,
    },
    AcceptanceParticipantMismatch,
    AcceptanceSecurityPolicyMismatch,
    AcceptanceReceiptPolicyMismatch,
    AcceptanceLimitExpansion {
        field: &'static str,
        proposed: usize,
        accepted: usize,
    },
    AcceptancePathPermissionExpansion {
        direction: RecipeSessionDirection,
        path: String,
    },
    AcceptanceProposalIdMismatch {
        expected: String,
        actual: String,
    },
    PathAccessDenied {
        direction: RecipeSessionDirection,
        path: String,
    },
    ReceiptLiveTransportClaimRejected,
    ReceiptByteMovementClaimRejected {
        bytes_sent: usize,
        bytes_received: usize,
    },
}

impl fmt::Display for RecipeSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "empty recipe session field: {field}"),
            Self::InvalidField { field, value } => {
                write!(f, "invalid recipe session field {field}: {value}")
            }
            Self::DuplicateParticipant(id) => write!(f, "duplicate participant id: {id}"),
            Self::DuplicatePathPermission { direction, path } => {
                write!(f, "duplicate {direction} path permission: {path}")
            }
            Self::MissingParticipant => write!(f, "recipe session requires participants"),
            Self::NotEnoughParticipants => {
                write!(f, "recipe session requires at least two participants")
            }
            Self::MissingPathPermission => write!(f, "recipe session requires path permissions"),
            Self::InvalidLimits(reason) => write!(f, "invalid recipe session limits: {reason}"),
            Self::PathPermissionLimitExceeded { actual, max } => write!(
                f,
                "recipe session path permission count {actual} exceeds configured max {max}"
            ),
            Self::InvalidSecurityPolicy(reason) => {
                write!(f, "invalid recipe session security policy: {reason}")
            }
            Self::UnknownParticipant { participant_id } => {
                write!(f, "unknown recipe session participant: {participant_id}")
            }
            Self::AcceptanceContractIdMismatch { expected, actual } => write!(
                f,
                "acceptance contract id mismatch: expected {expected}, got {actual}"
            ),
            Self::AcceptanceRecipeRefMismatch { expected, actual } => write!(
                f,
                "acceptance recipe ref mismatch: expected {expected}, got {actual}"
            ),
            Self::AcceptanceRecipeManifestHashMismatch { expected, actual } => write!(
                f,
                "acceptance recipe manifest hash mismatch: expected {expected}, got {actual}"
            ),
            Self::AcceptancePathManifestHashMismatch { expected, actual } => write!(
                f,
                "acceptance path manifest hash mismatch: expected {expected}, got {actual}"
            ),
            Self::AcceptanceParticipantMismatch => {
                write!(
                    f,
                    "acceptance participants do not match proposal participants"
                )
            }
            Self::AcceptanceSecurityPolicyMismatch => {
                write!(
                    f,
                    "acceptance security policy does not match proposal policy"
                )
            }
            Self::AcceptanceReceiptPolicyMismatch => {
                write!(
                    f,
                    "acceptance receipt policy does not match proposal policy"
                )
            }
            Self::AcceptanceLimitExpansion {
                field,
                proposed,
                accepted,
            } => write!(
                f,
                "acceptance limit {field} expands proposal: proposed {proposed}, accepted {accepted}"
            ),
            Self::AcceptancePathPermissionExpansion { direction, path } => write!(
                f,
                "acceptance expands {direction} path permission outside proposal: {path}"
            ),
            Self::AcceptanceProposalIdMismatch { expected, actual } => write!(
                f,
                "acceptance proposal id mismatch: expected {expected}, got {actual}"
            ),
            Self::PathAccessDenied { direction, path } => write!(
                f,
                "recipe session {direction} path access is not allowed by contract: {path}"
            ),
            Self::ReceiptLiveTransportClaimRejected => {
                write!(
                    f,
                    "recipe session receipt cannot claim live transport usage"
                )
            }
            Self::ReceiptByteMovementClaimRejected {
                bytes_sent,
                bytes_received,
            } => write!(
                f,
                "recipe session receipt cannot claim byte movement: sent {bytes_sent}, received {bytes_received}"
            ),
        }
    }
}

impl Error for RecipeSessionError {}

/// A generic role in a recipe-backed session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecipeSessionRole {
    Initiator,
    Responder,
    Producer,
    Consumer,
    Peer,
    Observer,
}

impl fmt::Display for RecipeSessionRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
            Self::Producer => "producer",
            Self::Consumer => "consumer",
            Self::Peer => "peer",
            Self::Observer => "observer",
        })
    }
}

/// Which side of a contract path is being granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecipeSessionDirection {
    Ingress,
    Egress,
}

impl fmt::Display for RecipeSessionDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        })
    }
}

/// A participant that can be referenced by a future proposal/acceptance layer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecipeSessionParticipant {
    id: String,
    role: RecipeSessionRole,
}

impl RecipeSessionParticipant {
    pub fn new(id: impl Into<String>, role: RecipeSessionRole) -> RecipeSessionResult<Self> {
        let id = id.into();
        validate_identifier("participant.id", &id)?;
        Ok(Self { id, role })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn role(&self) -> RecipeSessionRole {
        self.role
    }
}

/// The recipe identity a session contract agrees to use.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecipeSessionRecipeRef {
    namespace: String,
    name: String,
    version: String,
}

impl RecipeSessionRecipeRef {
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> RecipeSessionResult<Self> {
        let namespace = namespace.into();
        let name = name.into();
        let version = version.into();
        validate_identifier("recipe.namespace", &namespace)?;
        validate_identifier("recipe.name", &name)?;
        validate_identifier("recipe.version", &version)?;
        Ok(Self {
            namespace,
            name,
            version,
        })
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn canonical_name(&self) -> String {
        format!("{}.{}@{}", self.namespace, self.name, self.version)
    }
}

/// A stable manifest hash reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecipeSessionHash(String);

impl RecipeSessionHash {
    pub fn new(value: impl Into<String>) -> RecipeSessionResult<Self> {
        let value = value.into();
        validate_hash("manifest_hash", &value)?;
        Ok(Self(value))
    }

    /// Build a stable manifest hash reference from deterministic fixture material.
    ///
    /// This is evidence metadata only. It does not sign, encrypt, fetch, or
    /// execute the referenced recipe/path manifest material.
    pub fn from_material(namespace: &str, material: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(namespace.as_bytes());
        hasher.update(b"\n");
        hasher.update(material.as_bytes());
        let digest = hasher.finalize();
        Self(format!("sha256:{}", to_lower_hex(&digest)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecipeSessionHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Deterministic digest for contract evidence produced by this crate.
///
/// This is used to address proposal, acceptance, rejection, lock, and receipt
/// material. It is evidence metadata only; it does not imply encryption, key
/// custody, signing, or live transport.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecipeSessionDigest(String);

impl RecipeSessionDigest {
    pub fn from_material(namespace: &str, material: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(namespace.as_bytes());
        hasher.update(b"\n");
        hasher.update(material.as_bytes());
        let digest = hasher.finalize();
        Self(format!("sha256:{}", to_lower_hex(&digest)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecipeSessionDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validated path string used by recipe-backed contracts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecipeSessionPath(String);

impl RecipeSessionPath {
    pub fn new(path: impl Into<String>) -> RecipeSessionResult<Self> {
        let path = path.into();
        validate_recipe_path(&path)?;
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_wildcard_pattern(&self) -> bool {
        self.0.contains("[*]")
    }

    pub fn is_concrete_indexed(&self) -> bool {
        self.0
            .split('.')
            .any(|segment| path_segment_index(segment).is_some_and(|index| index != "*"))
    }

    pub fn wildcard_path(&self) -> RecipeSessionResult<Self> {
        RecipeSessionPath::new(wildcardize_path(self.as_str()))
    }

    pub fn is_allowed_by(&self, permission: &RecipeSessionPath) -> bool {
        path_pattern_allows(permission.as_str(), self.as_str())
    }
}

impl fmt::Display for RecipeSessionPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Directional permission for a recipe/pathgen-compatible path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecipeSessionPathPermission {
    direction: RecipeSessionDirection,
    path: RecipeSessionPath,
}

impl RecipeSessionPathPermission {
    pub fn new(
        direction: RecipeSessionDirection,
        path: impl Into<String>,
    ) -> RecipeSessionResult<Self> {
        Ok(Self {
            direction,
            path: RecipeSessionPath::new(path)?,
        })
    }

    pub fn ingress(path: impl Into<String>) -> RecipeSessionResult<Self> {
        Self::new(RecipeSessionDirection::Ingress, path)
    }

    pub fn egress(path: impl Into<String>) -> RecipeSessionResult<Self> {
        Self::new(RecipeSessionDirection::Egress, path)
    }

    pub fn direction(&self) -> RecipeSessionDirection {
        self.direction
    }

    pub fn path(&self) -> &RecipeSessionPath {
        &self.path
    }

    pub fn allows(&self, direction: RecipeSessionDirection, path: &RecipeSessionPath) -> bool {
        self.direction == direction && path.is_allowed_by(&self.path)
    }
}

/// A requested path access before any runtime stream execution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecipeSessionPathAccess {
    direction: RecipeSessionDirection,
    path: RecipeSessionPath,
}

impl RecipeSessionPathAccess {
    pub fn new(
        direction: RecipeSessionDirection,
        path: impl Into<String>,
    ) -> RecipeSessionResult<Self> {
        Ok(Self {
            direction,
            path: RecipeSessionPath::new(path)?,
        })
    }

    pub fn ingress(path: impl Into<String>) -> RecipeSessionResult<Self> {
        Self::new(RecipeSessionDirection::Ingress, path)
    }

    pub fn egress(path: impl Into<String>) -> RecipeSessionResult<Self> {
        Self::new(RecipeSessionDirection::Egress, path)
    }

    pub fn direction(&self) -> RecipeSessionDirection {
        self.direction
    }

    pub fn path(&self) -> &RecipeSessionPath {
        &self.path
    }
}

/// Evidence that a requested path access was allowed by a contract permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeSessionPathBinding {
    access: RecipeSessionPathAccess,
    matched_permission: RecipeSessionPathPermission,
}

impl RecipeSessionPathBinding {
    pub fn new(
        access: RecipeSessionPathAccess,
        matched_permission: RecipeSessionPathPermission,
    ) -> RecipeSessionResult<Self> {
        if !matched_permission.allows(access.direction(), access.path()) {
            return Err(RecipeSessionError::PathAccessDenied {
                direction: access.direction(),
                path: access.path().as_str().to_string(),
            });
        }
        Ok(Self {
            access,
            matched_permission,
        })
    }

    pub fn access(&self) -> &RecipeSessionPathAccess {
        &self.access
    }

    pub fn matched_permission(&self) -> &RecipeSessionPathPermission {
        &self.matched_permission
    }

    pub fn canonical_binding_material(&self) -> String {
        format!(
            "direction={};path={};matched={}:{}",
            self.access.direction(),
            self.access.path(),
            self.matched_permission.direction(),
            self.matched_permission.path()
        )
    }
}

/// Bounded session limits. These are constraints only; they do not execute IO.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecipeSessionLimits {
    pub max_payload_len: usize,
    pub max_frame_count: usize,
    pub max_sequence_len: usize,
    pub max_path_permissions: usize,
}

impl RecipeSessionLimits {
    pub fn new(
        max_payload_len: usize,
        max_frame_count: usize,
        max_sequence_len: usize,
        max_path_permissions: usize,
    ) -> RecipeSessionResult<Self> {
        let limits = Self {
            max_payload_len,
            max_frame_count,
            max_sequence_len,
            max_path_permissions,
        };
        limits.validate()?;
        Ok(limits)
    }

    pub fn validate(&self) -> RecipeSessionResult<()> {
        if self.max_payload_len == 0 {
            return Err(RecipeSessionError::InvalidLimits(
                "max_payload_len must be greater than zero".to_string(),
            ));
        }
        if self.max_frame_count == 0 {
            return Err(RecipeSessionError::InvalidLimits(
                "max_frame_count must be greater than zero".to_string(),
            ));
        }
        if self.max_sequence_len == 0 {
            return Err(RecipeSessionError::InvalidLimits(
                "max_sequence_len must be greater than zero".to_string(),
            ));
        }
        if self.max_path_permissions == 0 {
            return Err(RecipeSessionError::InvalidLimits(
                "max_path_permissions must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for RecipeSessionLimits {
    fn default() -> Self {
        Self {
            max_payload_len: 64 * 1024,
            max_frame_count: 1024,
            max_sequence_len: 4096,
            max_path_permissions: 256,
        }
    }
}

/// Contract-level receipt requirements. Execution receipts are later-layer work.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecipeSessionReceiptPolicy {
    pub contract_receipt_required: bool,
    pub lock_receipt_required: bool,
    pub ingress_receipts_required: bool,
    pub egress_receipts_required: bool,
}

impl RecipeSessionReceiptPolicy {
    pub fn contract_only() -> Self {
        Self {
            contract_receipt_required: true,
            lock_receipt_required: true,
            ingress_receipts_required: false,
            egress_receipts_required: false,
        }
    }

    pub fn ingress_and_egress() -> Self {
        Self {
            contract_receipt_required: true,
            lock_receipt_required: true,
            ingress_receipts_required: true,
            egress_receipts_required: true,
        }
    }
}

impl Default for RecipeSessionReceiptPolicy {
    fn default() -> Self {
        Self::contract_only()
    }
}

/// Security policy placeholder for a future envelope/signing layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecipeSessionSecurityPolicy {
    pub envelope: RecipeSessionSecurityEnvelope,
    pub signing_required: bool,
    pub encryption_required: bool,
}

impl RecipeSessionSecurityPolicy {
    pub fn none() -> Self {
        Self {
            envelope: RecipeSessionSecurityEnvelope::None,
            signing_required: false,
            encryption_required: false,
        }
    }

    pub fn external_envelope_required() -> Self {
        Self {
            envelope: RecipeSessionSecurityEnvelope::ExternalEnvelopeRequired,
            signing_required: true,
            encryption_required: true,
        }
    }

    pub fn validate(&self) -> RecipeSessionResult<()> {
        if self.envelope == RecipeSessionSecurityEnvelope::None
            && (self.signing_required || self.encryption_required)
        {
            return Err(RecipeSessionError::InvalidSecurityPolicy(
                "none envelope cannot require signing or encryption".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for RecipeSessionSecurityPolicy {
    fn default() -> Self {
        Self::none()
    }
}

/// The type of security envelope a contract requires. This is declarative only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecipeSessionSecurityEnvelope {
    None,
    ExternalEnvelopeRequired,
    Deferred,
}

impl fmt::Display for RecipeSessionSecurityEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::ExternalEnvelopeRequired => "external_envelope_required",
            Self::Deferred => "deferred",
        })
    }
}

/// Generic recipe-backed ingress/egress session contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeSessionContract {
    contract_id: String,
    participants: Vec<RecipeSessionParticipant>,
    recipe_ref: RecipeSessionRecipeRef,
    recipe_manifest_hash: RecipeSessionHash,
    path_manifest_hash: RecipeSessionHash,
    path_permissions: Vec<RecipeSessionPathPermission>,
    limits: RecipeSessionLimits,
    receipt_policy: RecipeSessionReceiptPolicy,
    security_policy: RecipeSessionSecurityPolicy,
}

impl RecipeSessionContract {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        participants: Vec<RecipeSessionParticipant>,
        recipe_ref: RecipeSessionRecipeRef,
        recipe_manifest_hash: RecipeSessionHash,
        path_manifest_hash: RecipeSessionHash,
        path_permissions: Vec<RecipeSessionPathPermission>,
        limits: RecipeSessionLimits,
        receipt_policy: RecipeSessionReceiptPolicy,
        security_policy: RecipeSessionSecurityPolicy,
    ) -> RecipeSessionResult<Self> {
        let contract = Self {
            contract_id: contract_id.into(),
            participants,
            recipe_ref,
            recipe_manifest_hash,
            path_manifest_hash,
            path_permissions,
            limits,
            receipt_policy,
            security_policy,
        };
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> RecipeSessionResult<()> {
        validate_identifier("contract_id", &self.contract_id)?;
        validate_participants(&self.participants)?;
        validate_path_permissions(&self.path_permissions)?;
        self.limits.validate()?;
        self.security_policy.validate()?;
        if self.path_permissions.len() > self.limits.max_path_permissions {
            return Err(RecipeSessionError::PathPermissionLimitExceeded {
                actual: self.path_permissions.len(),
                max: self.limits.max_path_permissions,
            });
        }
        Ok(())
    }

    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    pub fn participants(&self) -> &[RecipeSessionParticipant] {
        &self.participants
    }

    pub fn recipe_ref(&self) -> &RecipeSessionRecipeRef {
        &self.recipe_ref
    }

    pub fn recipe_manifest_hash(&self) -> &RecipeSessionHash {
        &self.recipe_manifest_hash
    }

    pub fn path_manifest_hash(&self) -> &RecipeSessionHash {
        &self.path_manifest_hash
    }

    pub fn path_permissions(&self) -> &[RecipeSessionPathPermission] {
        &self.path_permissions
    }

    pub fn limits(&self) -> &RecipeSessionLimits {
        &self.limits
    }

    pub fn receipt_policy(&self) -> &RecipeSessionReceiptPolicy {
        &self.receipt_policy
    }

    pub fn security_policy(&self) -> &RecipeSessionSecurityPolicy {
        &self.security_policy
    }

    pub fn contains_exact_path(
        &self,
        direction: RecipeSessionDirection,
        path: &RecipeSessionPath,
    ) -> bool {
        self.path_permissions
            .iter()
            .any(|permission| permission.direction == direction && &permission.path == path)
    }

    pub fn allows_path(&self, direction: RecipeSessionDirection, path: &RecipeSessionPath) -> bool {
        self.path_permissions
            .iter()
            .any(|permission| permission.allows(direction, path))
    }

    pub fn bind_path_access(
        &self,
        direction: RecipeSessionDirection,
        path: impl Into<String>,
    ) -> RecipeSessionResult<RecipeSessionPathBinding> {
        let access = RecipeSessionPathAccess::new(direction, path)?;
        let matched_permission = self
            .path_permissions
            .iter()
            .find(|permission| permission.allows(direction, access.path()))
            .cloned()
            .ok_or_else(|| RecipeSessionError::PathAccessDenied {
                direction,
                path: access.path().as_str().to_string(),
            })?;
        RecipeSessionPathBinding::new(access, matched_permission)
    }

    pub fn bind_ingress_path(
        &self,
        path: impl Into<String>,
    ) -> RecipeSessionResult<RecipeSessionPathBinding> {
        self.bind_path_access(RecipeSessionDirection::Ingress, path)
    }

    pub fn bind_egress_path(
        &self,
        path: impl Into<String>,
    ) -> RecipeSessionResult<RecipeSessionPathBinding> {
        self.bind_path_access(RecipeSessionDirection::Egress, path)
    }

    pub fn allowed_paths_for(&self, direction: RecipeSessionDirection) -> Vec<&RecipeSessionPath> {
        self.path_permissions
            .iter()
            .filter(|permission| permission.direction == direction)
            .map(|permission| &permission.path)
            .collect()
    }

    /// Deterministic text material suitable for a future hash/receipt pass.
    pub fn canonical_contract_material(&self) -> String {
        let mut participants: Vec<String> = self
            .participants
            .iter()
            .map(|participant| format!("{}:{}", participant.role, participant.id))
            .collect();
        participants.sort();

        let mut permissions: Vec<String> = self
            .path_permissions
            .iter()
            .map(|permission| format!("{}:{}", permission.direction, permission.path))
            .collect();
        permissions.sort();

        format!(
            "contract_id={};recipe={};recipe_manifest_hash={};path_manifest_hash={};participants={};paths={};limits={},{},{},{};receipts={},{},{},{};security={},{},{}",
            self.contract_id,
            self.recipe_ref.canonical_name(),
            self.recipe_manifest_hash,
            self.path_manifest_hash,
            participants.join(","),
            permissions.join(","),
            self.limits.max_payload_len,
            self.limits.max_frame_count,
            self.limits.max_sequence_len,
            self.limits.max_path_permissions,
            self.receipt_policy.contract_receipt_required,
            self.receipt_policy.lock_receipt_required,
            self.receipt_policy.ingress_receipts_required,
            self.receipt_policy.egress_receipts_required,
            self.security_policy.envelope,
            self.security_policy.signing_required,
            self.security_policy.encryption_required,
        )
    }

    pub fn contract_digest(&self) -> RecipeSessionDigest {
        RecipeSessionDigest::from_material(
            "recipe_session.contract.v1",
            &self.canonical_contract_material(),
        )
    }
}

/// A proposal to use a generic recipe-backed session contract.
///
/// This is still contract-only metadata. Creating a proposal does not open a
/// transport, send bytes, or imply that a counterparty accepted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeSessionProposal {
    proposal_id: String,
    proposed_by: String,
    contract: RecipeSessionContract,
}

impl RecipeSessionProposal {
    pub fn new(
        proposal_id: impl Into<String>,
        proposed_by: impl Into<String>,
        contract: RecipeSessionContract,
    ) -> RecipeSessionResult<Self> {
        let proposal = Self {
            proposal_id: proposal_id.into(),
            proposed_by: proposed_by.into(),
            contract,
        };
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn validate(&self) -> RecipeSessionResult<()> {
        validate_identifier("proposal_id", &self.proposal_id)?;
        validate_identifier("proposed_by", &self.proposed_by)?;
        self.contract.validate()?;
        ensure_participant_known(self.contract.participants(), &self.proposed_by)
    }

    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }

    pub fn proposed_by(&self) -> &str {
        &self.proposed_by
    }

    pub fn contract(&self) -> &RecipeSessionContract {
        &self.contract
    }

    pub fn accept(
        &self,
        acceptance_id: impl Into<String>,
        accepted_by: impl Into<String>,
        accepted_contract: RecipeSessionContract,
    ) -> RecipeSessionResult<RecipeSessionAcceptance> {
        validate_acceptance_contract(&self.contract, &accepted_contract)?;
        RecipeSessionAcceptance::new(
            acceptance_id,
            self.proposal_id.clone(),
            accepted_by,
            accepted_contract,
        )
    }

    pub fn reject(
        &self,
        rejection_id: impl Into<String>,
        rejected_by: impl Into<String>,
        reason: RecipeSessionRejectionReason,
    ) -> RecipeSessionResult<RecipeSessionRejection> {
        let rejected_by = rejected_by.into();
        ensure_participant_known(self.contract.participants(), &rejected_by)?;
        RecipeSessionRejection::new(rejection_id, self.proposal_id.clone(), rejected_by, reason)
    }

    /// Deterministic text material suitable for a later hash/receipt pass.
    pub fn canonical_proposal_material(&self) -> String {
        format!(
            "proposal_id={};proposed_by={};contract={}",
            self.proposal_id,
            self.proposed_by,
            self.contract.canonical_contract_material()
        )
    }

    pub fn proposal_digest(&self) -> RecipeSessionDigest {
        RecipeSessionDigest::from_material(
            "recipe_session.proposal.v1",
            &self.canonical_proposal_material(),
        )
    }

    pub fn receipt(
        &self,
        receipt_id: impl Into<String>,
    ) -> RecipeSessionResult<RecipeSessionProposalReceipt> {
        RecipeSessionProposalReceipt::new(receipt_id, self)
    }

    pub fn lock(
        &self,
        lock_id: impl Into<String>,
        acceptance: &RecipeSessionAcceptance,
    ) -> RecipeSessionResult<LockedRecipeSessionContract> {
        LockedRecipeSessionContract::new(lock_id, self, acceptance)
    }
}

/// A compatible response that narrows or confirms a proposed contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeSessionAcceptance {
    acceptance_id: String,
    proposal_id: String,
    accepted_by: String,
    accepted_contract: RecipeSessionContract,
}

impl RecipeSessionAcceptance {
    pub fn new(
        acceptance_id: impl Into<String>,
        proposal_id: impl Into<String>,
        accepted_by: impl Into<String>,
        accepted_contract: RecipeSessionContract,
    ) -> RecipeSessionResult<Self> {
        let acceptance = Self {
            acceptance_id: acceptance_id.into(),
            proposal_id: proposal_id.into(),
            accepted_by: accepted_by.into(),
            accepted_contract,
        };
        acceptance.validate()?;
        Ok(acceptance)
    }

    pub fn validate(&self) -> RecipeSessionResult<()> {
        validate_identifier("acceptance_id", &self.acceptance_id)?;
        validate_identifier("proposal_id", &self.proposal_id)?;
        validate_identifier("accepted_by", &self.accepted_by)?;
        self.accepted_contract.validate()?;
        ensure_participant_known(self.accepted_contract.participants(), &self.accepted_by)
    }

    pub fn acceptance_id(&self) -> &str {
        &self.acceptance_id
    }

    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }

    pub fn accepted_by(&self) -> &str {
        &self.accepted_by
    }

    pub fn accepted_contract(&self) -> &RecipeSessionContract {
        &self.accepted_contract
    }

    /// Deterministic text material suitable for a later hash/receipt pass.
    pub fn canonical_acceptance_material(&self) -> String {
        format!(
            "acceptance_id={};proposal_id={};accepted_by={};contract={}",
            self.acceptance_id,
            self.proposal_id,
            self.accepted_by,
            self.accepted_contract.canonical_contract_material()
        )
    }

    pub fn acceptance_digest(&self) -> RecipeSessionDigest {
        RecipeSessionDigest::from_material(
            "recipe_session.acceptance.v1",
            &self.canonical_acceptance_material(),
        )
    }

    pub fn receipt(
        &self,
        receipt_id: impl Into<String>,
    ) -> RecipeSessionResult<RecipeSessionAcceptanceReceipt> {
        RecipeSessionAcceptanceReceipt::new(receipt_id, self)
    }
}

/// Structured reason for refusing a proposal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecipeSessionRejectionReason {
    UnsupportedRecipe,
    ManifestMismatch,
    PathPermissionDenied,
    LimitIncompatible,
    DirectionIncompatible,
    SecurityPolicyIncompatible,
    ReceiptPolicyIncompatible,
    Other(String),
}

impl RecipeSessionRejectionReason {
    pub fn other(value: impl Into<String>) -> RecipeSessionResult<Self> {
        let value = value.into();
        validate_reason_text(&value)?;
        Ok(Self::Other(value))
    }

    pub fn canonical_label(&self) -> String {
        match self {
            Self::UnsupportedRecipe => "unsupported_recipe".to_string(),
            Self::ManifestMismatch => "manifest_mismatch".to_string(),
            Self::PathPermissionDenied => "path_permission_denied".to_string(),
            Self::LimitIncompatible => "limit_incompatible".to_string(),
            Self::DirectionIncompatible => "direction_incompatible".to_string(),
            Self::SecurityPolicyIncompatible => "security_policy_incompatible".to_string(),
            Self::ReceiptPolicyIncompatible => "receipt_policy_incompatible".to_string(),
            Self::Other(value) => format!("other:{value}"),
        }
    }
}

/// A structured refusal of a proposal. This records no live transport effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeSessionRejection {
    rejection_id: String,
    proposal_id: String,
    rejected_by: String,
    reason: RecipeSessionRejectionReason,
}

impl RecipeSessionRejection {
    pub fn new(
        rejection_id: impl Into<String>,
        proposal_id: impl Into<String>,
        rejected_by: impl Into<String>,
        reason: RecipeSessionRejectionReason,
    ) -> RecipeSessionResult<Self> {
        let rejection = Self {
            rejection_id: rejection_id.into(),
            proposal_id: proposal_id.into(),
            rejected_by: rejected_by.into(),
            reason,
        };
        rejection.validate()?;
        Ok(rejection)
    }

    pub fn validate(&self) -> RecipeSessionResult<()> {
        validate_identifier("rejection_id", &self.rejection_id)?;
        validate_identifier("proposal_id", &self.proposal_id)?;
        validate_identifier("rejected_by", &self.rejected_by)?;
        if let RecipeSessionRejectionReason::Other(value) = &self.reason {
            validate_reason_text(value)?;
        }
        Ok(())
    }

    pub fn rejection_id(&self) -> &str {
        &self.rejection_id
    }

    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }

    pub fn rejected_by(&self) -> &str {
        &self.rejected_by
    }

    pub fn reason(&self) -> &RecipeSessionRejectionReason {
        &self.reason
    }

    /// Deterministic text material suitable for a later hash/receipt pass.
    pub fn canonical_rejection_material(&self) -> String {
        format!(
            "rejection_id={};proposal_id={};rejected_by={};reason={}",
            self.rejection_id,
            self.proposal_id,
            self.rejected_by,
            self.reason.canonical_label()
        )
    }

    pub fn rejection_digest(&self) -> RecipeSessionDigest {
        RecipeSessionDigest::from_material(
            "recipe_session.rejection.v1",
            &self.canonical_rejection_material(),
        )
    }

    pub fn receipt(
        &self,
        receipt_id: impl Into<String>,
    ) -> RecipeSessionResult<RecipeSessionRejectionReceipt> {
        RecipeSessionRejectionReceipt::new(receipt_id, self)
    }
}

/// Evidence that a contract-layer receipt did not perform transport IO.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecipeSessionNoLiveEvidence {
    live_transport_used: bool,
    bytes_sent: usize,
    bytes_received: usize,
}

impl RecipeSessionNoLiveEvidence {
    pub fn no_live() -> Self {
        Self {
            live_transport_used: false,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    pub fn new(
        live_transport_used: bool,
        bytes_sent: usize,
        bytes_received: usize,
    ) -> RecipeSessionResult<Self> {
        let evidence = Self {
            live_transport_used,
            bytes_sent,
            bytes_received,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> RecipeSessionResult<()> {
        if self.live_transport_used {
            return Err(RecipeSessionError::ReceiptLiveTransportClaimRejected);
        }
        if self.bytes_sent != 0 || self.bytes_received != 0 {
            return Err(RecipeSessionError::ReceiptByteMovementClaimRejected {
                bytes_sent: self.bytes_sent,
                bytes_received: self.bytes_received,
            });
        }
        Ok(())
    }

    pub fn live_transport_used(&self) -> bool {
        self.live_transport_used
    }

    pub fn bytes_sent(&self) -> usize {
        self.bytes_sent
    }

    pub fn bytes_received(&self) -> usize {
        self.bytes_received
    }

    fn canonical_material(&self) -> String {
        format!(
            "live_transport_used={};bytes_sent={};bytes_received={}",
            self.live_transport_used, self.bytes_sent, self.bytes_received
        )
    }
}

/// Receipt recording that a proposal was prepared as contract metadata only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeSessionProposalReceipt {
    receipt_id: String,
    proposal_id: String,
    proposal_digest: RecipeSessionDigest,
    proposed_by: String,
    no_live_evidence: RecipeSessionNoLiveEvidence,
}

impl RecipeSessionProposalReceipt {
    pub fn new(
        receipt_id: impl Into<String>,
        proposal: &RecipeSessionProposal,
    ) -> RecipeSessionResult<Self> {
        Self::new_with_evidence(receipt_id, proposal, RecipeSessionNoLiveEvidence::no_live())
    }

    pub fn new_with_evidence(
        receipt_id: impl Into<String>,
        proposal: &RecipeSessionProposal,
        no_live_evidence: RecipeSessionNoLiveEvidence,
    ) -> RecipeSessionResult<Self> {
        no_live_evidence.validate()?;
        let receipt = Self {
            receipt_id: receipt_id.into(),
            proposal_id: proposal.proposal_id().to_string(),
            proposal_digest: proposal.proposal_digest(),
            proposed_by: proposal.proposed_by().to_string(),
            no_live_evidence,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> RecipeSessionResult<()> {
        validate_identifier("proposal_receipt_id", &self.receipt_id)?;
        validate_identifier("proposal_id", &self.proposal_id)?;
        validate_identifier("proposed_by", &self.proposed_by)?;
        self.no_live_evidence.validate()
    }

    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }
    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }
    pub fn proposal_digest(&self) -> &RecipeSessionDigest {
        &self.proposal_digest
    }
    pub fn proposed_by(&self) -> &str {
        &self.proposed_by
    }
    pub fn no_live_evidence(&self) -> &RecipeSessionNoLiveEvidence {
        &self.no_live_evidence
    }

    pub fn canonical_receipt_material(&self) -> String {
        format!(
            "receipt_id={};proposal_id={};proposal_digest={};proposed_by={};evidence={}",
            self.receipt_id,
            self.proposal_id,
            self.proposal_digest,
            self.proposed_by,
            self.no_live_evidence.canonical_material()
        )
    }

    pub fn receipt_digest(&self) -> RecipeSessionDigest {
        RecipeSessionDigest::from_material(
            "recipe_session.proposal_receipt.v1",
            &self.canonical_receipt_material(),
        )
    }
}

/// Receipt recording that an acceptance was prepared as contract metadata only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeSessionAcceptanceReceipt {
    receipt_id: String,
    acceptance_id: String,
    proposal_id: String,
    acceptance_digest: RecipeSessionDigest,
    accepted_by: String,
    no_live_evidence: RecipeSessionNoLiveEvidence,
}

impl RecipeSessionAcceptanceReceipt {
    pub fn new(
        receipt_id: impl Into<String>,
        acceptance: &RecipeSessionAcceptance,
    ) -> RecipeSessionResult<Self> {
        Self::new_with_evidence(
            receipt_id,
            acceptance,
            RecipeSessionNoLiveEvidence::no_live(),
        )
    }

    pub fn new_with_evidence(
        receipt_id: impl Into<String>,
        acceptance: &RecipeSessionAcceptance,
        no_live_evidence: RecipeSessionNoLiveEvidence,
    ) -> RecipeSessionResult<Self> {
        no_live_evidence.validate()?;
        let receipt = Self {
            receipt_id: receipt_id.into(),
            acceptance_id: acceptance.acceptance_id().to_string(),
            proposal_id: acceptance.proposal_id().to_string(),
            acceptance_digest: acceptance.acceptance_digest(),
            accepted_by: acceptance.accepted_by().to_string(),
            no_live_evidence,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> RecipeSessionResult<()> {
        validate_identifier("acceptance_receipt_id", &self.receipt_id)?;
        validate_identifier("acceptance_id", &self.acceptance_id)?;
        validate_identifier("proposal_id", &self.proposal_id)?;
        validate_identifier("accepted_by", &self.accepted_by)?;
        self.no_live_evidence.validate()
    }

    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }
    pub fn acceptance_id(&self) -> &str {
        &self.acceptance_id
    }
    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }
    pub fn acceptance_digest(&self) -> &RecipeSessionDigest {
        &self.acceptance_digest
    }
    pub fn accepted_by(&self) -> &str {
        &self.accepted_by
    }
    pub fn no_live_evidence(&self) -> &RecipeSessionNoLiveEvidence {
        &self.no_live_evidence
    }

    pub fn canonical_receipt_material(&self) -> String {
        format!(
            "receipt_id={};acceptance_id={};proposal_id={};acceptance_digest={};accepted_by={};evidence={}",
            self.receipt_id,
            self.acceptance_id,
            self.proposal_id,
            self.acceptance_digest,
            self.accepted_by,
            self.no_live_evidence.canonical_material()
        )
    }

    pub fn receipt_digest(&self) -> RecipeSessionDigest {
        RecipeSessionDigest::from_material(
            "recipe_session.acceptance_receipt.v1",
            &self.canonical_receipt_material(),
        )
    }
}

/// Receipt recording that a rejection was prepared as contract metadata only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeSessionRejectionReceipt {
    receipt_id: String,
    rejection_id: String,
    proposal_id: String,
    rejection_digest: RecipeSessionDigest,
    rejected_by: String,
    no_live_evidence: RecipeSessionNoLiveEvidence,
}

impl RecipeSessionRejectionReceipt {
    pub fn new(
        receipt_id: impl Into<String>,
        rejection: &RecipeSessionRejection,
    ) -> RecipeSessionResult<Self> {
        Self::new_with_evidence(
            receipt_id,
            rejection,
            RecipeSessionNoLiveEvidence::no_live(),
        )
    }

    pub fn new_with_evidence(
        receipt_id: impl Into<String>,
        rejection: &RecipeSessionRejection,
        no_live_evidence: RecipeSessionNoLiveEvidence,
    ) -> RecipeSessionResult<Self> {
        no_live_evidence.validate()?;
        let receipt = Self {
            receipt_id: receipt_id.into(),
            rejection_id: rejection.rejection_id().to_string(),
            proposal_id: rejection.proposal_id().to_string(),
            rejection_digest: rejection.rejection_digest(),
            rejected_by: rejection.rejected_by().to_string(),
            no_live_evidence,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> RecipeSessionResult<()> {
        validate_identifier("rejection_receipt_id", &self.receipt_id)?;
        validate_identifier("rejection_id", &self.rejection_id)?;
        validate_identifier("proposal_id", &self.proposal_id)?;
        validate_identifier("rejected_by", &self.rejected_by)?;
        self.no_live_evidence.validate()
    }

    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }
    pub fn rejection_id(&self) -> &str {
        &self.rejection_id
    }
    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }
    pub fn rejection_digest(&self) -> &RecipeSessionDigest {
        &self.rejection_digest
    }
    pub fn rejected_by(&self) -> &str {
        &self.rejected_by
    }
    pub fn no_live_evidence(&self) -> &RecipeSessionNoLiveEvidence {
        &self.no_live_evidence
    }

    pub fn canonical_receipt_material(&self) -> String {
        format!(
            "receipt_id={};rejection_id={};proposal_id={};rejection_digest={};rejected_by={};evidence={}",
            self.receipt_id,
            self.rejection_id,
            self.proposal_id,
            self.rejection_digest,
            self.rejected_by,
            self.no_live_evidence.canonical_material()
        )
    }

    pub fn receipt_digest(&self) -> RecipeSessionDigest {
        RecipeSessionDigest::from_material(
            "recipe_session.rejection_receipt.v1",
            &self.canonical_receipt_material(),
        )
    }
}

/// Immutable contract lock produced after a compatible proposal and acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedRecipeSessionContract {
    lock_id: String,
    proposal_id: String,
    acceptance_id: String,
    proposal_digest: RecipeSessionDigest,
    acceptance_digest: RecipeSessionDigest,
    locked_contract_digest: RecipeSessionDigest,
    lock_digest: RecipeSessionDigest,
    locked_contract: RecipeSessionContract,
}

impl LockedRecipeSessionContract {
    pub fn new(
        lock_id: impl Into<String>,
        proposal: &RecipeSessionProposal,
        acceptance: &RecipeSessionAcceptance,
    ) -> RecipeSessionResult<Self> {
        if acceptance.proposal_id() != proposal.proposal_id() {
            return Err(RecipeSessionError::AcceptanceProposalIdMismatch {
                expected: proposal.proposal_id().to_string(),
                actual: acceptance.proposal_id().to_string(),
            });
        }
        validate_acceptance_contract(proposal.contract(), acceptance.accepted_contract())?;

        let proposal_digest = proposal.proposal_digest();
        let acceptance_digest = acceptance.acceptance_digest();
        let locked_contract_digest = acceptance.accepted_contract().contract_digest();
        let lock_material = format!(
            "proposal_digest={};acceptance_digest={};locked_contract_digest={}",
            proposal_digest, acceptance_digest, locked_contract_digest
        );
        let lock = Self {
            lock_id: lock_id.into(),
            proposal_id: proposal.proposal_id().to_string(),
            acceptance_id: acceptance.acceptance_id().to_string(),
            proposal_digest,
            acceptance_digest,
            locked_contract_digest,
            lock_digest: RecipeSessionDigest::from_material(
                "recipe_session.locked_contract.v1",
                &lock_material,
            ),
            locked_contract: acceptance.accepted_contract().clone(),
        };
        lock.validate()?;
        Ok(lock)
    }

    pub fn validate(&self) -> RecipeSessionResult<()> {
        validate_identifier("lock_id", &self.lock_id)?;
        validate_identifier("proposal_id", &self.proposal_id)?;
        validate_identifier("acceptance_id", &self.acceptance_id)?;
        self.locked_contract.validate()
    }

    pub fn lock_id(&self) -> &str {
        &self.lock_id
    }
    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }
    pub fn acceptance_id(&self) -> &str {
        &self.acceptance_id
    }
    pub fn proposal_digest(&self) -> &RecipeSessionDigest {
        &self.proposal_digest
    }
    pub fn acceptance_digest(&self) -> &RecipeSessionDigest {
        &self.acceptance_digest
    }
    pub fn locked_contract_digest(&self) -> &RecipeSessionDigest {
        &self.locked_contract_digest
    }
    pub fn lock_digest(&self) -> &RecipeSessionDigest {
        &self.lock_digest
    }
    pub fn locked_contract(&self) -> &RecipeSessionContract {
        &self.locked_contract
    }

    pub fn canonical_lock_material(&self) -> String {
        format!(
            "proposal_digest={};acceptance_digest={};locked_contract_digest={}",
            self.proposal_digest, self.acceptance_digest, self.locked_contract_digest
        )
    }

    pub fn receipt(
        &self,
        receipt_id: impl Into<String>,
    ) -> RecipeSessionResult<RecipeSessionLockReceipt> {
        RecipeSessionLockReceipt::new(receipt_id, self)
    }
}

/// Receipt recording that a compatible proposal/acceptance pair was locked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeSessionLockReceipt {
    receipt_id: String,
    lock_id: String,
    proposal_id: String,
    acceptance_id: String,
    lock_digest: RecipeSessionDigest,
    locked_contract_digest: RecipeSessionDigest,
    no_live_evidence: RecipeSessionNoLiveEvidence,
}

impl RecipeSessionLockReceipt {
    pub fn new(
        receipt_id: impl Into<String>,
        locked: &LockedRecipeSessionContract,
    ) -> RecipeSessionResult<Self> {
        Self::new_with_evidence(receipt_id, locked, RecipeSessionNoLiveEvidence::no_live())
    }

    pub fn new_with_evidence(
        receipt_id: impl Into<String>,
        locked: &LockedRecipeSessionContract,
        no_live_evidence: RecipeSessionNoLiveEvidence,
    ) -> RecipeSessionResult<Self> {
        no_live_evidence.validate()?;
        let receipt = Self {
            receipt_id: receipt_id.into(),
            lock_id: locked.lock_id().to_string(),
            proposal_id: locked.proposal_id().to_string(),
            acceptance_id: locked.acceptance_id().to_string(),
            lock_digest: locked.lock_digest().clone(),
            locked_contract_digest: locked.locked_contract_digest().clone(),
            no_live_evidence,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> RecipeSessionResult<()> {
        validate_identifier("lock_receipt_id", &self.receipt_id)?;
        validate_identifier("lock_id", &self.lock_id)?;
        validate_identifier("proposal_id", &self.proposal_id)?;
        validate_identifier("acceptance_id", &self.acceptance_id)?;
        self.no_live_evidence.validate()
    }

    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }
    pub fn lock_id(&self) -> &str {
        &self.lock_id
    }
    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }
    pub fn acceptance_id(&self) -> &str {
        &self.acceptance_id
    }
    pub fn lock_digest(&self) -> &RecipeSessionDigest {
        &self.lock_digest
    }
    pub fn locked_contract_digest(&self) -> &RecipeSessionDigest {
        &self.locked_contract_digest
    }
    pub fn no_live_evidence(&self) -> &RecipeSessionNoLiveEvidence {
        &self.no_live_evidence
    }

    pub fn canonical_receipt_material(&self) -> String {
        format!(
            "receipt_id={};lock_id={};proposal_id={};acceptance_id={};lock_digest={};locked_contract_digest={};evidence={}",
            self.receipt_id,
            self.lock_id,
            self.proposal_id,
            self.acceptance_id,
            self.lock_digest,
            self.locked_contract_digest,
            self.no_live_evidence.canonical_material()
        )
    }

    pub fn receipt_digest(&self) -> RecipeSessionDigest {
        RecipeSessionDigest::from_material(
            "recipe_session.lock_receipt.v1",
            &self.canonical_receipt_material(),
        )
    }
}
/// Full path root used by the reusable file-transfer recipe catalog fixture.
pub const ARTIFACT_TRANSFER_PATH_ROOT: &str = "file_transfer.multi_file_then_instruction";
const ARTIFACT_TRANSFER_VALUE_PREFIX: &str = "file_transfer.multi_file_then_instruction.";

/// File-transfer item path constants exported by the existing recipe catalog shape.
pub const ARTIFACT_TRANSFER_ITEMS_NAME_PATH: &str =
    "file_transfer.multi_file_then_instruction.items[*].name";
pub const ARTIFACT_TRANSFER_ITEMS_DECLARED_LEN_PATH: &str =
    "file_transfer.multi_file_then_instruction.items[*].declared_len";
pub const ARTIFACT_TRANSFER_ITEMS_CHUNK_RECIPE_NAME_PATH: &str =
    "file_transfer.multi_file_then_instruction.items[*].chunk_recipe_name";
pub const ARTIFACT_TRANSFER_ITEMS_START_SEQ_PATH: &str =
    "file_transfer.multi_file_then_instruction.items[*].start_seq";
pub const ARTIFACT_TRANSFER_ITEMS_PACKET_START_PATH: &str =
    "file_transfer.multi_file_then_instruction.items[*].packet_start";
pub const ARTIFACT_TRANSFER_ITEMS_PACKET_END_EXCLUSIVE_PATH: &str =
    "file_transfer.multi_file_then_instruction.items[*].packet_end_exclusive";
pub const ARTIFACT_TRANSFER_ITEMS_END_SEQ_PATH: &str =
    "file_transfer.multi_file_then_instruction.items[*].end_seq";
pub const ARTIFACT_TRANSFER_ITEMS_PACKET_COUNT_PATH: &str =
    "file_transfer.multi_file_then_instruction.items[*].packet_count";

/// File-transfer packet path constants exported by the existing recipe catalog shape.
pub const ARTIFACT_TRANSFER_PACKETS_ITEM_NAME_PATH: &str =
    "file_transfer.multi_file_then_instruction.packets[*].item_name";
pub const ARTIFACT_TRANSFER_PACKETS_CHUNK_RECIPE_NAME_PATH: &str =
    "file_transfer.multi_file_then_instruction.packets[*].chunk_recipe_name";
pub const ARTIFACT_TRANSFER_PACKETS_SEQ_PATH: &str =
    "file_transfer.multi_file_then_instruction.packets[*].seq";
pub const ARTIFACT_TRANSFER_PACKETS_ITEM_BYTE_START_PATH: &str =
    "file_transfer.multi_file_then_instruction.packets[*].item_byte_start";
pub const ARTIFACT_TRANSFER_PACKETS_ITEM_BYTE_END_PATH: &str =
    "file_transfer.multi_file_then_instruction.packets[*].item_byte_end";
pub const ARTIFACT_TRANSFER_PACKETS_PAYLOAD_LEN_PATH: &str =
    "file_transfer.multi_file_then_instruction.packets[*].payload_len";
pub const ARTIFACT_TRANSFER_PACKETS_IS_FINAL_FOR_ITEM_PATH: &str =
    "file_transfer.multi_file_then_instruction.packets[*].is_final_for_item";
pub const ARTIFACT_TRANSFER_NEXT_INSTRUCTION_SEQ_PATH: &str =
    "file_transfer.multi_file_then_instruction.next_instruction_seq";

/// Receipt ingress paths for later file-transfer acknowledgement material.
///
/// These paths are session receipt metadata only. They are not part of the
/// egress file-transfer recipe manifest and they do not perform IO.
pub const ARTIFACT_TRANSFER_RECEIPT_PACKET_SEQ_PATH: &str = "receipts[*].packet_seq";
pub const ARTIFACT_TRANSFER_RECEIPT_STATUS_PATH: &str = "receipts[*].status";
pub const ARTIFACT_TRANSFER_RECEIPT_DIGEST_PATH: &str = "receipts[*].digest";

/// Contract fixture for the reusable artifact/file-transfer recipe catalog shape.
///
/// The fixture binds the existing `recipes::file_transfer`/`recipe_writer`
/// pathgen surface into a generic `recipe-session` proposal. It remains a
/// metadata-only contract builder: no stream is opened, no bytes are moved, no
/// cryptographic envelope is implemented, and no planner/runtime authority is
/// assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecipeSessionArtifactTransferFixture;

impl RecipeSessionArtifactTransferFixture {
    pub fn recipe_ref() -> RecipeSessionResult<RecipeSessionRecipeRef> {
        RecipeSessionRecipeRef::new("file_transfer", "multi_file_then_instruction", "v1")
    }

    pub fn egress_manifest_paths() -> &'static [&'static str] {
        &[
            ARTIFACT_TRANSFER_ITEMS_NAME_PATH,
            ARTIFACT_TRANSFER_ITEMS_DECLARED_LEN_PATH,
            ARTIFACT_TRANSFER_ITEMS_CHUNK_RECIPE_NAME_PATH,
            ARTIFACT_TRANSFER_ITEMS_START_SEQ_PATH,
            ARTIFACT_TRANSFER_ITEMS_PACKET_START_PATH,
            ARTIFACT_TRANSFER_ITEMS_PACKET_END_EXCLUSIVE_PATH,
            ARTIFACT_TRANSFER_ITEMS_END_SEQ_PATH,
            ARTIFACT_TRANSFER_ITEMS_PACKET_COUNT_PATH,
            ARTIFACT_TRANSFER_PACKETS_ITEM_NAME_PATH,
            ARTIFACT_TRANSFER_PACKETS_CHUNK_RECIPE_NAME_PATH,
            ARTIFACT_TRANSFER_PACKETS_SEQ_PATH,
            ARTIFACT_TRANSFER_PACKETS_ITEM_BYTE_START_PATH,
            ARTIFACT_TRANSFER_PACKETS_ITEM_BYTE_END_PATH,
            ARTIFACT_TRANSFER_PACKETS_PAYLOAD_LEN_PATH,
            ARTIFACT_TRANSFER_PACKETS_IS_FINAL_FOR_ITEM_PATH,
            ARTIFACT_TRANSFER_NEXT_INSTRUCTION_SEQ_PATH,
        ]
    }

    pub fn ingress_receipt_paths() -> &'static [&'static str] {
        &[
            ARTIFACT_TRANSFER_RECEIPT_PACKET_SEQ_PATH,
            ARTIFACT_TRANSFER_RECEIPT_STATUS_PATH,
            ARTIFACT_TRANSFER_RECEIPT_DIGEST_PATH,
        ]
    }

    pub fn path_permissions() -> RecipeSessionResult<Vec<RecipeSessionPathPermission>> {
        let mut permissions = Vec::new();
        for path in Self::egress_manifest_paths() {
            permissions.push(RecipeSessionPathPermission::egress(*path)?);
        }
        for path in Self::ingress_receipt_paths() {
            permissions.push(RecipeSessionPathPermission::ingress(*path)?);
        }
        Ok(permissions)
    }

    pub fn relative_value_path(full_path: &str) -> Option<&str> {
        full_path.strip_prefix(ARTIFACT_TRANSFER_VALUE_PREFIX)
    }

    pub fn contract(
        contract_id: impl Into<String>,
        producer_id: impl Into<String>,
        consumer_id: impl Into<String>,
        recipe_manifest_hash: RecipeSessionHash,
        path_manifest_hash: RecipeSessionHash,
    ) -> RecipeSessionResult<RecipeSessionContract> {
        let producer_id = producer_id.into();
        let consumer_id = consumer_id.into();
        RecipeSessionContract::new(
            contract_id,
            vec![
                RecipeSessionParticipant::new(producer_id, RecipeSessionRole::Producer)?,
                RecipeSessionParticipant::new(consumer_id, RecipeSessionRole::Consumer)?,
            ],
            Self::recipe_ref()?,
            recipe_manifest_hash,
            path_manifest_hash,
            Self::path_permissions()?,
            RecipeSessionLimits::new(64 * 1024 * 1024, 1_000_000, 1_000_000, 64)?,
            RecipeSessionReceiptPolicy::ingress_and_egress(),
            RecipeSessionSecurityPolicy::none(),
        )
    }

    pub fn proposal(
        proposal_id: impl Into<String>,
        contract_id: impl Into<String>,
        producer_id: impl Into<String>,
        consumer_id: impl Into<String>,
        recipe_manifest_hash: RecipeSessionHash,
        path_manifest_hash: RecipeSessionHash,
    ) -> RecipeSessionResult<RecipeSessionProposal> {
        let producer_id = producer_id.into();
        let contract = Self::contract(
            contract_id,
            producer_id.clone(),
            consumer_id,
            recipe_manifest_hash,
            path_manifest_hash,
        )?;
        RecipeSessionProposal::new(proposal_id, producer_id, contract)
    }

    /// Build, accept, and lock the artifact-transfer fixture contract in one call.
    ///
    /// This is the final closeout convenience for the metadata-only recipe
    /// session flow. It performs the same deterministic contract/proposal/
    /// acceptance/lock sequence as the manual API, but it does not open sockets,
    /// move bytes, invoke a runtime, encrypt data, or assume NodePlan authority.
    pub fn locked_contract(
        proposal_id: impl Into<String>,
        acceptance_id: impl Into<String>,
        lock_id: impl Into<String>,
        contract_id: impl Into<String>,
        producer_id: impl Into<String>,
        consumer_id: impl Into<String>,
        recipe_manifest_hash: RecipeSessionHash,
        path_manifest_hash: RecipeSessionHash,
    ) -> RecipeSessionResult<LockedRecipeSessionContract> {
        let producer_id = producer_id.into();
        let consumer_id = consumer_id.into();
        let proposal = Self::proposal(
            proposal_id,
            contract_id,
            producer_id,
            consumer_id.clone(),
            recipe_manifest_hash,
            path_manifest_hash,
        )?;
        let acceptance =
            proposal.accept(acceptance_id, consumer_id, proposal.contract().clone())?;
        proposal.lock(lock_id, &acceptance)
    }

    /// Stable recipe manifest material used by the artifact-transfer fixture.
    pub fn recipe_manifest_material() -> &'static str {
        "file_transfer.multi_file_then_instruction@v1"
    }

    /// Build the stable recipe manifest hash for the artifact-transfer fixture.
    pub fn recipe_manifest_hash() -> RecipeSessionHash {
        RecipeSessionHash::from_material(
            "recipe_session.fixture.recipe_manifest.v1",
            Self::recipe_manifest_material(),
        )
    }

    /// Build the stable path manifest hash for caller-provided path manifest material.
    ///
    /// The caller supplies the path manifest material so this crate does not need
    /// a runtime dependency on the recipe catalog crate.
    pub fn path_manifest_hash(path_manifest_material: &str) -> RecipeSessionHash {
        RecipeSessionHash::from_material(
            "recipe_session.fixture.path_manifest.v1",
            path_manifest_material,
        )
    }

    /// Build the pair of hashes needed to lock an artifact-transfer fixture session.
    pub fn manifest_hashes(path_manifest_material: &str) -> (RecipeSessionHash, RecipeSessionHash) {
        (
            Self::recipe_manifest_hash(),
            Self::path_manifest_hash(path_manifest_material),
        )
    }

    /// Return true when a path is one of the declared artifact-transfer egress
    /// permission patterns.
    pub fn is_declared_egress_permission_path(path: &str) -> bool {
        Self::egress_manifest_paths().contains(&path)
    }

    /// Return true when a path is one of the declared artifact-transfer ingress
    /// receipt permission patterns.
    pub fn is_declared_ingress_receipt_path(path: &str) -> bool {
        Self::ingress_receipt_paths().contains(&path)
    }

    /// Classify an exact declared fixture permission path by direction.
    ///
    /// This only classifies the declared wildcard/exact permission inventory,
    /// not arbitrary concrete indexed runtime paths.
    pub fn declared_permission_direction(path: &str) -> Option<RecipeSessionDirection> {
        if Self::is_declared_egress_permission_path(path) {
            Some(RecipeSessionDirection::Egress)
        } else if Self::is_declared_ingress_receipt_path(path) {
            Some(RecipeSessionDirection::Ingress)
        } else {
            None
        }
    }

    /// Return true when this locked session can emit the concrete egress path.
    ///
    /// This is a small preflight/helper surface over `bind_egress_path`; it does
    /// not read values, move bytes, open a transport, or create runtime effects.
    pub fn can_emit_path(locked: &LockedRecipeSessionContract, path: &str) -> bool {
        locked.locked_contract().bind_egress_path(path).is_ok()
    }

    /// Return true when this locked session can receive the concrete ingress
    /// receipt path.
    ///
    /// This is a small preflight/helper surface over `bind_ingress_path`; it
    /// remains metadata-only.
    pub fn can_receive_receipt_path(locked: &LockedRecipeSessionContract, path: &str) -> bool {
        locked.locked_contract().bind_ingress_path(path).is_ok()
    }
}
fn to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn validate_acceptance_contract(
    proposed: &RecipeSessionContract,
    accepted: &RecipeSessionContract,
) -> RecipeSessionResult<()> {
    if proposed.contract_id() != accepted.contract_id() {
        return Err(RecipeSessionError::AcceptanceContractIdMismatch {
            expected: proposed.contract_id().to_string(),
            actual: accepted.contract_id().to_string(),
        });
    }

    if proposed.recipe_ref() != accepted.recipe_ref() {
        return Err(RecipeSessionError::AcceptanceRecipeRefMismatch {
            expected: proposed.recipe_ref().canonical_name(),
            actual: accepted.recipe_ref().canonical_name(),
        });
    }

    if proposed.recipe_manifest_hash() != accepted.recipe_manifest_hash() {
        return Err(RecipeSessionError::AcceptanceRecipeManifestHashMismatch {
            expected: proposed.recipe_manifest_hash().as_str().to_string(),
            actual: accepted.recipe_manifest_hash().as_str().to_string(),
        });
    }

    if proposed.path_manifest_hash() != accepted.path_manifest_hash() {
        return Err(RecipeSessionError::AcceptancePathManifestHashMismatch {
            expected: proposed.path_manifest_hash().as_str().to_string(),
            actual: accepted.path_manifest_hash().as_str().to_string(),
        });
    }

    if participant_set(proposed.participants()) != participant_set(accepted.participants()) {
        return Err(RecipeSessionError::AcceptanceParticipantMismatch);
    }

    if proposed.security_policy() != accepted.security_policy() {
        return Err(RecipeSessionError::AcceptanceSecurityPolicyMismatch);
    }

    if proposed.receipt_policy() != accepted.receipt_policy() {
        return Err(RecipeSessionError::AcceptanceReceiptPolicyMismatch);
    }

    ensure_limit_not_expanded(
        "max_payload_len",
        proposed.limits().max_payload_len,
        accepted.limits().max_payload_len,
    )?;
    ensure_limit_not_expanded(
        "max_frame_count",
        proposed.limits().max_frame_count,
        accepted.limits().max_frame_count,
    )?;
    ensure_limit_not_expanded(
        "max_sequence_len",
        proposed.limits().max_sequence_len,
        accepted.limits().max_sequence_len,
    )?;
    ensure_limit_not_expanded(
        "max_path_permissions",
        proposed.limits().max_path_permissions,
        accepted.limits().max_path_permissions,
    )?;

    let proposed_paths: BTreeSet<_> = proposed
        .path_permissions()
        .iter()
        .map(|permission| {
            (
                permission.direction(),
                permission.path().as_str().to_string(),
            )
        })
        .collect();
    for permission in accepted.path_permissions() {
        let accepted_key = (
            permission.direction(),
            permission.path().as_str().to_string(),
        );
        if !proposed_paths.contains(&accepted_key) {
            return Err(RecipeSessionError::AcceptancePathPermissionExpansion {
                direction: permission.direction(),
                path: permission.path().as_str().to_string(),
            });
        }
    }

    Ok(())
}

fn participant_set(participants: &[RecipeSessionParticipant]) -> BTreeSet<String> {
    participants
        .iter()
        .map(|participant| format!("{}:{}", participant.role(), participant.id()))
        .collect()
}

fn ensure_participant_known(
    participants: &[RecipeSessionParticipant],
    participant_id: &str,
) -> RecipeSessionResult<()> {
    if participants
        .iter()
        .any(|participant| participant.id() == participant_id)
    {
        Ok(())
    } else {
        Err(RecipeSessionError::UnknownParticipant {
            participant_id: participant_id.to_string(),
        })
    }
}

fn ensure_limit_not_expanded(
    field: &'static str,
    proposed: usize,
    accepted: usize,
) -> RecipeSessionResult<()> {
    if accepted > proposed {
        return Err(RecipeSessionError::AcceptanceLimitExpansion {
            field,
            proposed,
            accepted,
        });
    }
    Ok(())
}

fn validate_participants(participants: &[RecipeSessionParticipant]) -> RecipeSessionResult<()> {
    if participants.is_empty() {
        return Err(RecipeSessionError::MissingParticipant);
    }
    if participants.len() < 2 {
        return Err(RecipeSessionError::NotEnoughParticipants);
    }
    let mut ids = BTreeSet::new();
    for participant in participants {
        if !ids.insert(participant.id.clone()) {
            return Err(RecipeSessionError::DuplicateParticipant(
                participant.id.clone(),
            ));
        }
    }
    Ok(())
}

fn validate_path_permissions(
    permissions: &[RecipeSessionPathPermission],
) -> RecipeSessionResult<()> {
    if permissions.is_empty() {
        return Err(RecipeSessionError::MissingPathPermission);
    }
    let mut seen = BTreeSet::new();
    for permission in permissions {
        let key = (permission.direction, permission.path.as_str().to_string());
        if !seen.insert(key) {
            return Err(RecipeSessionError::DuplicatePathPermission {
                direction: permission.direction,
                path: permission.path.as_str().to_string(),
            });
        }
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> RecipeSessionResult<()> {
    if value.trim().is_empty() {
        return Err(RecipeSessionError::EmptyField(field));
    }
    if value.len() > 128
        || value.chars().any(|ch| {
            ch.is_control()
                || ch.is_whitespace()
                || matches!(ch, '/' | '\\' | '?' | '#' | '[' | ']')
        })
    {
        return Err(RecipeSessionError::InvalidField {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_hash(field: &'static str, value: &str) -> RecipeSessionResult<()> {
    if value.trim().is_empty() {
        return Err(RecipeSessionError::EmptyField(field));
    }
    if value.len() > 256
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        || value.contains("..")
    {
        return Err(RecipeSessionError::InvalidField {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_reason_text(value: &str) -> RecipeSessionResult<()> {
    if value.trim().is_empty() {
        return Err(RecipeSessionError::EmptyField("rejection.reason"));
    }
    if value.len() > 256 || value.chars().any(|ch| ch.is_control()) {
        return Err(RecipeSessionError::InvalidField {
            field: "rejection.reason",
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_recipe_path(path: &str) -> RecipeSessionResult<()> {
    if path.trim().is_empty() {
        return Err(RecipeSessionError::EmptyField("path"));
    }
    if path.len() > 512
        || path.starts_with('.')
        || path.ends_with('.')
        || path.contains("..")
        || path
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '/' | '\\'))
    {
        return Err(RecipeSessionError::InvalidField {
            field: "path",
            value: path.to_string(),
        });
    }

    for segment in path.split('.') {
        validate_path_segment(segment, path)?;
    }
    Ok(())
}

fn validate_path_segment(segment: &str, full_path: &str) -> RecipeSessionResult<()> {
    if segment.is_empty() {
        return Err(RecipeSessionError::InvalidField {
            field: "path",
            value: full_path.to_string(),
        });
    }

    if let Some(open_index) = segment.find('[') {
        if !segment.ends_with(']') || segment[open_index + 1..segment.len() - 1].is_empty() {
            return Err(RecipeSessionError::InvalidField {
                field: "path",
                value: full_path.to_string(),
            });
        }
        let base = &segment[..open_index];
        let index = &segment[open_index + 1..segment.len() - 1];
        if segment[open_index + 1..segment.len() - 1].contains('[') || base.is_empty() {
            return Err(RecipeSessionError::InvalidField {
                field: "path",
                value: full_path.to_string(),
            });
        }
        validate_path_atom(base, full_path)?;
        if index != "*" && !index.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(RecipeSessionError::InvalidField {
                field: "path",
                value: full_path.to_string(),
            });
        }
        return Ok(());
    }

    if segment.contains(']') {
        return Err(RecipeSessionError::InvalidField {
            field: "path",
            value: full_path.to_string(),
        });
    }

    validate_path_atom(segment, full_path)
}

fn validate_path_atom(atom: &str, full_path: &str) -> RecipeSessionResult<()> {
    if atom.is_empty()
        || !atom
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        return Err(RecipeSessionError::InvalidField {
            field: "path",
            value: full_path.to_string(),
        });
    }
    Ok(())
}

fn path_pattern_allows(permission_pattern: &str, requested_path: &str) -> bool {
    if permission_pattern == requested_path {
        return true;
    }

    let permission_segments: Vec<_> = permission_pattern.split('.').collect();
    let requested_segments: Vec<_> = requested_path.split('.').collect();
    if permission_segments.len() != requested_segments.len() {
        return false;
    }

    permission_segments
        .iter()
        .zip(requested_segments.iter())
        .all(|(permission, requested)| path_segment_pattern_allows(permission, requested))
}

fn path_segment_pattern_allows(permission: &str, requested: &str) -> bool {
    if permission == requested {
        return true;
    }

    let Some(permission_open) = permission.find('[') else {
        return false;
    };
    let Some(requested_open) = requested.find('[') else {
        return false;
    };

    if !permission.ends_with(']') || !requested.ends_with(']') {
        return false;
    }

    let permission_base = &permission[..permission_open];
    let requested_base = &requested[..requested_open];
    let permission_index = &permission[permission_open + 1..permission.len() - 1];
    let requested_index = &requested[requested_open + 1..requested.len() - 1];

    permission_base == requested_base
        && permission_index == "*"
        && !requested_index.is_empty()
        && requested_index.chars().all(|ch| ch.is_ascii_digit())
}

fn wildcardize_path(path: &str) -> String {
    path.split('.')
        .map(wildcardize_path_segment)
        .collect::<Vec<_>>()
        .join(".")
}

fn wildcardize_path_segment(segment: &str) -> String {
    let Some(open_index) = segment.find('[') else {
        return segment.to_string();
    };
    if !segment.ends_with(']') {
        return segment.to_string();
    }
    let base = &segment[..open_index];
    let index = &segment[open_index + 1..segment.len() - 1];
    if index.chars().all(|ch| ch.is_ascii_digit()) {
        format!("{base}[*]")
    } else {
        segment.to_string()
    }
}

fn path_segment_index(segment: &str) -> Option<&str> {
    let open_index = segment.find('[')?;
    if !segment.ends_with(']') {
        return None;
    }
    Some(&segment[open_index + 1..segment.len() - 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn participant_a() -> RecipeSessionParticipant {
        RecipeSessionParticipant::new("peer-a", RecipeSessionRole::Initiator).unwrap()
    }

    fn participant_b() -> RecipeSessionParticipant {
        RecipeSessionParticipant::new("peer-b", RecipeSessionRole::Responder).unwrap()
    }

    fn recipe_ref() -> RecipeSessionRecipeRef {
        RecipeSessionRecipeRef::new("file_transfer", "artifact_bundle", "v1").unwrap()
    }

    fn hash(label: &str) -> RecipeSessionHash {
        RecipeSessionHash::new(format!("sha256:{label}")).unwrap()
    }

    fn permissions() -> Vec<RecipeSessionPathPermission> {
        vec![
            RecipeSessionPathPermission::egress("items[*].packets[*].payload_len").unwrap(),
            RecipeSessionPathPermission::ingress("receipts[*].status").unwrap(),
        ]
    }

    fn valid_contract() -> RecipeSessionContract {
        RecipeSessionContract::new(
            "contract-1",
            vec![participant_a(), participant_b()],
            recipe_ref(),
            hash("recipe"),
            hash("path"),
            permissions(),
            RecipeSessionLimits::default(),
            RecipeSessionReceiptPolicy::ingress_and_egress(),
            RecipeSessionSecurityPolicy::none(),
        )
        .unwrap()
    }

    #[test]
    fn valid_minimal_contract_is_accepted() {
        let contract = valid_contract();
        assert_eq!(contract.contract_id(), "contract-1");
        assert_eq!(contract.participants().len(), 2);
        assert_eq!(
            contract.recipe_ref().canonical_name(),
            "file_transfer.artifact_bundle@v1"
        );
        assert_eq!(contract.recipe_manifest_hash().as_str(), "sha256:recipe");
        assert_eq!(contract.path_manifest_hash().as_str(), "sha256:path");
    }

    #[test]
    fn participant_ids_reject_empty_or_unsafe_values() {
        assert!(matches!(
            RecipeSessionParticipant::new("", RecipeSessionRole::Peer),
            Err(RecipeSessionError::EmptyField("participant.id"))
        ));
        assert!(RecipeSessionParticipant::new("peer a", RecipeSessionRole::Peer).is_err());
        assert!(RecipeSessionParticipant::new("../peer", RecipeSessionRole::Peer).is_err());
    }

    #[test]
    fn duplicate_participants_are_rejected() {
        let result = RecipeSessionContract::new(
            "contract-1",
            vec![participant_a(), participant_a()],
            recipe_ref(),
            hash("recipe"),
            hash("path"),
            permissions(),
            RecipeSessionLimits::default(),
            RecipeSessionReceiptPolicy::default(),
            RecipeSessionSecurityPolicy::default(),
        );
        assert!(matches!(
            result,
            Err(RecipeSessionError::DuplicateParticipant(id)) if id == "peer-a"
        ));
    }

    #[test]
    fn at_least_two_participants_are_required() {
        let result = RecipeSessionContract::new(
            "contract-1",
            vec![participant_a()],
            recipe_ref(),
            hash("recipe"),
            hash("path"),
            permissions(),
            RecipeSessionLimits::default(),
            RecipeSessionReceiptPolicy::default(),
            RecipeSessionSecurityPolicy::default(),
        );
        assert!(matches!(
            result,
            Err(RecipeSessionError::NotEnoughParticipants)
        ));
    }

    #[test]
    fn recipe_ref_rejects_empty_or_unsafe_parts() {
        assert!(RecipeSessionRecipeRef::new("", "name", "v1").is_err());
        assert!(RecipeSessionRecipeRef::new("namespace", "bad name", "v1").is_err());
        assert!(RecipeSessionRecipeRef::new("namespace", "name", "v[1]").is_err());
    }

    #[test]
    fn manifest_hashes_reject_empty_whitespace_or_traversal() {
        assert!(RecipeSessionHash::new("").is_err());
        assert!(RecipeSessionHash::new("sha256:bad hash").is_err());
        assert!(RecipeSessionHash::new("sha256:../bad").is_err());
        assert!(RecipeSessionHash::new("sha256:abc123").is_ok());
    }

    #[test]
    fn path_permissions_accept_wildcard_and_indexed_path_shapes() {
        assert!(RecipeSessionPathPermission::egress("items[*].packets[*].payload_len").is_ok());
        assert!(RecipeSessionPathPermission::ingress("items[0].packets[2].status").is_ok());
        assert!(
            RecipeSessionPathPermission::ingress(
                "quic.payload.frames[*].active_schema.crypto_data"
            )
            .is_ok()
        );
    }

    #[test]
    fn path_permissions_reject_malformed_paths() {
        assert!(RecipeSessionPathPermission::egress("").is_err());
        assert!(RecipeSessionPathPermission::egress("items..payload").is_err());
        assert!(RecipeSessionPathPermission::egress("items[*").is_err());
        assert!(RecipeSessionPathPermission::egress("items[abc].payload").is_err());
        assert!(RecipeSessionPathPermission::egress("items/payload").is_err());
    }

    #[test]
    fn duplicate_path_permissions_are_rejected_per_direction() {
        let duplicate = "items[*].packets[*].payload_len";
        let result = RecipeSessionContract::new(
            "contract-1",
            vec![participant_a(), participant_b()],
            recipe_ref(),
            hash("recipe"),
            hash("path"),
            vec![
                RecipeSessionPathPermission::egress(duplicate).unwrap(),
                RecipeSessionPathPermission::egress(duplicate).unwrap(),
            ],
            RecipeSessionLimits::default(),
            RecipeSessionReceiptPolicy::default(),
            RecipeSessionSecurityPolicy::default(),
        );
        assert!(matches!(
            result,
            Err(RecipeSessionError::DuplicatePathPermission { direction, path })
                if direction == RecipeSessionDirection::Egress && path == duplicate
        ));
    }

    #[test]
    fn same_path_can_be_allowed_for_different_directions() {
        let path = "items[*].packets[*].payload_len";
        let contract = RecipeSessionContract::new(
            "contract-1",
            vec![participant_a(), participant_b()],
            recipe_ref(),
            hash("recipe"),
            hash("path"),
            vec![
                RecipeSessionPathPermission::egress(path).unwrap(),
                RecipeSessionPathPermission::ingress(path).unwrap(),
            ],
            RecipeSessionLimits::default(),
            RecipeSessionReceiptPolicy::default(),
            RecipeSessionSecurityPolicy::default(),
        )
        .unwrap();
        let path = RecipeSessionPath::new(path).unwrap();
        assert!(contract.contains_exact_path(RecipeSessionDirection::Egress, &path));
        assert!(contract.contains_exact_path(RecipeSessionDirection::Ingress, &path));
    }

    #[test]
    fn limits_reject_zero_values() {
        assert!(RecipeSessionLimits::new(0, 1, 1, 1).is_err());
        assert!(RecipeSessionLimits::new(1, 0, 1, 1).is_err());
        assert!(RecipeSessionLimits::new(1, 1, 0, 1).is_err());
        assert!(RecipeSessionLimits::new(1, 1, 1, 0).is_err());
    }

    #[test]
    fn path_permission_count_must_fit_limits() {
        let result = RecipeSessionContract::new(
            "contract-1",
            vec![participant_a(), participant_b()],
            recipe_ref(),
            hash("recipe"),
            hash("path"),
            permissions(),
            RecipeSessionLimits::new(1024, 16, 16, 1).unwrap(),
            RecipeSessionReceiptPolicy::default(),
            RecipeSessionSecurityPolicy::default(),
        );
        assert!(matches!(
            result,
            Err(RecipeSessionError::PathPermissionLimitExceeded { actual: 2, max: 1 })
        ));
    }

    #[test]
    fn receipt_policy_can_require_contract_only_or_full_path_receipts() {
        let contract_only = RecipeSessionReceiptPolicy::contract_only();
        assert!(contract_only.contract_receipt_required);
        assert!(contract_only.lock_receipt_required);
        assert!(!contract_only.ingress_receipts_required);
        assert!(!contract_only.egress_receipts_required);

        let full = RecipeSessionReceiptPolicy::ingress_and_egress();
        assert!(full.ingress_receipts_required);
        assert!(full.egress_receipts_required);
    }

    #[test]
    fn security_policy_is_declarative_and_rejects_impossible_none_profile() {
        assert!(RecipeSessionSecurityPolicy::none().validate().is_ok());
        assert!(
            RecipeSessionSecurityPolicy::external_envelope_required()
                .validate()
                .is_ok()
        );
        let impossible = RecipeSessionSecurityPolicy {
            envelope: RecipeSessionSecurityEnvelope::None,
            signing_required: true,
            encryption_required: false,
        };
        assert!(matches!(
            impossible.validate(),
            Err(RecipeSessionError::InvalidSecurityPolicy(_))
        ));
    }

    #[test]
    fn allowed_paths_are_filtered_by_direction() {
        let contract = valid_contract();
        let egress_paths = contract.allowed_paths_for(RecipeSessionDirection::Egress);
        let ingress_paths = contract.allowed_paths_for(RecipeSessionDirection::Ingress);
        assert_eq!(egress_paths.len(), 1);
        assert_eq!(egress_paths[0].as_str(), "items[*].packets[*].payload_len");
        assert_eq!(ingress_paths.len(), 1);
        assert_eq!(ingress_paths[0].as_str(), "receipts[*].status");
    }

    #[test]
    fn path_binding_allows_exact_paths() {
        let contract = valid_contract();
        let binding = contract.bind_ingress_path("receipts[*].status").unwrap();
        assert_eq!(
            binding.access().direction(),
            RecipeSessionDirection::Ingress
        );
        assert_eq!(binding.access().path().as_str(), "receipts[*].status");
        assert_eq!(
            binding.matched_permission().path().as_str(),
            "receipts[*].status"
        );
        assert!(
            binding
                .canonical_binding_material()
                .contains("matched=ingress:receipts[*].status")
        );
    }

    #[test]
    fn wildcard_permission_allows_concrete_indexed_paths() {
        let contract = valid_contract();
        let binding = contract
            .bind_egress_path("items[0].packets[2].payload_len")
            .unwrap();
        assert_eq!(
            binding.access().path().as_str(),
            "items[0].packets[2].payload_len"
        );
        assert_eq!(
            binding.matched_permission().path().as_str(),
            "items[*].packets[*].payload_len"
        );
    }

    #[test]
    fn concrete_indexed_path_can_be_wildcardized() {
        let path = RecipeSessionPath::new("items[10].packets[2].payload_len").unwrap();
        assert!(path.is_concrete_indexed());
        assert!(!path.is_wildcard_pattern());
        assert_eq!(
            path.wildcard_path().unwrap().as_str(),
            "items[*].packets[*].payload_len"
        );
    }

    #[test]
    fn indexed_path_does_not_allow_sibling_path() {
        let contract = valid_contract();
        let result = contract.bind_egress_path("items[0].packets[2].payload_digest");
        assert!(matches!(
            result,
            Err(RecipeSessionError::PathAccessDenied { direction, path })
                if direction == RecipeSessionDirection::Egress
                    && path == "items[0].packets[2].payload_digest"
        ));
    }

    #[test]
    fn ingress_path_cannot_be_used_as_egress_path() {
        let contract = valid_contract();
        let result = contract.bind_egress_path("receipts[0].status");
        assert!(matches!(
            result,
            Err(RecipeSessionError::PathAccessDenied { direction, path })
                if direction == RecipeSessionDirection::Egress && path == "receipts[0].status"
        ));
    }

    #[test]
    fn malformed_path_access_is_rejected_before_permission_lookup() {
        let contract = valid_contract();
        assert!(matches!(
            contract.bind_ingress_path("receipts[abc].status"),
            Err(RecipeSessionError::InvalidField { field: "path", .. })
        ));
    }

    #[test]
    fn locked_contract_can_bind_path_access_without_execution() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let acceptance = proposal
            .accept("acceptance-1", "peer-b", valid_contract())
            .unwrap();
        let locked = proposal.lock("lock-1", &acceptance).unwrap();

        let binding = locked
            .locked_contract()
            .bind_egress_path("items[1].packets[0].payload_len")
            .unwrap();
        assert_eq!(
            binding.access().path().as_str(),
            "items[1].packets[0].payload_len"
        );
        assert_eq!(
            binding.matched_permission().path().as_str(),
            "items[*].packets[*].payload_len"
        );
    }

    #[test]
    fn canonical_contract_material_is_deterministic() {
        let first = valid_contract().canonical_contract_material();
        let second = valid_contract().canonical_contract_material();
        assert_eq!(first, second);
        assert!(first.contains("contract_id=contract-1"));
        assert!(first.contains("recipe=file_transfer.artifact_bundle@v1"));
        assert!(first.contains("egress:items[*].packets[*].payload_len"));
        assert!(first.contains("ingress:receipts[*].status"));
    }

    fn contract_with(
        contract_id: &str,
        recipe_ref: RecipeSessionRecipeRef,
        recipe_hash: RecipeSessionHash,
        path_hash: RecipeSessionHash,
        path_permissions: Vec<RecipeSessionPathPermission>,
        limits: RecipeSessionLimits,
    ) -> RecipeSessionContract {
        RecipeSessionContract::new(
            contract_id,
            vec![participant_a(), participant_b()],
            recipe_ref,
            recipe_hash,
            path_hash,
            path_permissions,
            limits,
            RecipeSessionReceiptPolicy::ingress_and_egress(),
            RecipeSessionSecurityPolicy::none(),
        )
        .unwrap()
    }

    #[test]
    fn proposal_requires_known_proposer() {
        let result = RecipeSessionProposal::new("proposal-1", "ghost-peer", valid_contract());
        assert!(matches!(
            result,
            Err(RecipeSessionError::UnknownParticipant { participant_id })
                if participant_id == "ghost-peer"
        ));
    }

    #[test]
    fn compatible_acceptance_can_narrow_limits_and_paths() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let accepted = contract_with(
            "contract-1",
            recipe_ref(),
            hash("recipe"),
            hash("path"),
            vec![RecipeSessionPathPermission::egress("items[*].packets[*].payload_len").unwrap()],
            RecipeSessionLimits::new(1024, 16, 16, 1).unwrap(),
        );

        let acceptance = proposal.accept("acceptance-1", "peer-b", accepted).unwrap();

        assert_eq!(acceptance.proposal_id(), "proposal-1");
        assert_eq!(acceptance.accepted_by(), "peer-b");
        assert_eq!(acceptance.accepted_contract().path_permissions().len(), 1);
        assert_eq!(
            acceptance.accepted_contract().limits().max_payload_len,
            1024
        );
    }

    #[test]
    fn acceptance_rejects_contract_id_mismatch() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let accepted = contract_with(
            "different-contract",
            recipe_ref(),
            hash("recipe"),
            hash("path"),
            permissions(),
            RecipeSessionLimits::default(),
        );

        let result = proposal.accept("acceptance-1", "peer-b", accepted);
        assert!(matches!(
            result,
            Err(RecipeSessionError::AcceptanceContractIdMismatch { expected, actual })
                if expected == "contract-1" && actual == "different-contract"
        ));
    }

    #[test]
    fn acceptance_rejects_recipe_manifest_hash_mismatch() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let accepted = contract_with(
            "contract-1",
            recipe_ref(),
            hash("other-recipe"),
            hash("path"),
            permissions(),
            RecipeSessionLimits::default(),
        );

        let result = proposal.accept("acceptance-1", "peer-b", accepted);
        assert!(matches!(
            result,
            Err(RecipeSessionError::AcceptanceRecipeManifestHashMismatch { expected, actual })
                if expected == "sha256:recipe" && actual == "sha256:other-recipe"
        ));
    }

    #[test]
    fn acceptance_rejects_path_manifest_hash_mismatch() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let accepted = contract_with(
            "contract-1",
            recipe_ref(),
            hash("recipe"),
            hash("other-path"),
            permissions(),
            RecipeSessionLimits::default(),
        );

        let result = proposal.accept("acceptance-1", "peer-b", accepted);
        assert!(matches!(
            result,
            Err(RecipeSessionError::AcceptancePathManifestHashMismatch { expected, actual })
                if expected == "sha256:path" && actual == "sha256:other-path"
        ));
    }

    #[test]
    fn acceptance_rejects_limit_expansion() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let accepted = contract_with(
            "contract-1",
            recipe_ref(),
            hash("recipe"),
            hash("path"),
            permissions(),
            RecipeSessionLimits::new(128 * 1024, 1024, 4096, 256).unwrap(),
        );

        let result = proposal.accept("acceptance-1", "peer-b", accepted);
        assert!(matches!(
            result,
            Err(RecipeSessionError::AcceptanceLimitExpansion { field, proposed, accepted })
                if field == "max_payload_len" && proposed == 64 * 1024 && accepted == 128 * 1024
        ));
    }

    #[test]
    fn acceptance_rejects_path_permission_expansion() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let mut expanded_permissions = permissions();
        expanded_permissions.push(
            RecipeSessionPathPermission::egress("items[*].packets[*].secret_key_hint").unwrap(),
        );
        let accepted = contract_with(
            "contract-1",
            recipe_ref(),
            hash("recipe"),
            hash("path"),
            expanded_permissions,
            RecipeSessionLimits::default(),
        );

        let result = proposal.accept("acceptance-1", "peer-b", accepted);
        assert!(matches!(
            result,
            Err(RecipeSessionError::AcceptancePathPermissionExpansion { direction, path })
                if direction == RecipeSessionDirection::Egress
                    && path == "items[*].packets[*].secret_key_hint"
        ));
    }

    #[test]
    fn acceptance_rejects_unknown_acceptor() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let result = proposal.accept("acceptance-1", "ghost-peer", valid_contract());
        assert!(matches!(
            result,
            Err(RecipeSessionError::UnknownParticipant { participant_id })
                if participant_id == "ghost-peer"
        ));
    }

    #[test]
    fn proposal_rejection_is_structured_and_deterministic() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let rejection = proposal
            .reject(
                "rejection-1",
                "peer-b",
                RecipeSessionRejectionReason::ManifestMismatch,
            )
            .unwrap();

        assert_eq!(rejection.proposal_id(), "proposal-1");
        assert_eq!(rejection.rejected_by(), "peer-b");
        assert_eq!(
            rejection.canonical_rejection_material(),
            "rejection_id=rejection-1;proposal_id=proposal-1;rejected_by=peer-b;reason=manifest_mismatch"
        );
    }

    #[test]
    fn freeform_rejection_reason_rejects_empty_or_control_text() {
        assert!(RecipeSessionRejectionReason::other("").is_err());
        assert!(RecipeSessionRejectionReason::other("bad\nreason").is_err());
        assert_eq!(
            RecipeSessionRejectionReason::other("counterparty requires smaller payload")
                .unwrap()
                .canonical_label(),
            "other:counterparty requires smaller payload"
        );
    }

    #[test]
    fn proposal_acceptance_rejection_digests_are_deterministic() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let acceptance = proposal
            .accept("acceptance-1", "peer-b", valid_contract())
            .unwrap();
        let rejection = proposal
            .reject(
                "rejection-1",
                "peer-b",
                RecipeSessionRejectionReason::ManifestMismatch,
            )
            .unwrap();

        assert_eq!(proposal.proposal_digest(), proposal.proposal_digest());
        assert_eq!(
            acceptance.acceptance_digest(),
            acceptance.acceptance_digest()
        );
        assert_eq!(rejection.rejection_digest(), rejection.rejection_digest());
        assert!(proposal.proposal_digest().as_str().starts_with("sha256:"));
        assert_ne!(proposal.proposal_digest(), acceptance.acceptance_digest());
        assert_ne!(proposal.proposal_digest(), rejection.rejection_digest());
    }

    #[test]
    fn proposal_and_acceptance_create_deterministic_locked_contract() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let acceptance = proposal
            .accept("acceptance-1", "peer-b", valid_contract())
            .unwrap();

        let first = proposal.lock("lock-1", &acceptance).unwrap();
        let second = proposal.lock("lock-2", &acceptance).unwrap();

        assert_eq!(first.proposal_id(), "proposal-1");
        assert_eq!(first.acceptance_id(), "acceptance-1");
        assert_eq!(first.lock_digest(), second.lock_digest());
        assert_eq!(
            first.locked_contract_digest(),
            &valid_contract().contract_digest()
        );
        assert_eq!(first.locked_contract().contract_id(), "contract-1");
    }

    #[test]
    fn lock_digest_changes_when_accepted_limits_change() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let narrow_a = contract_with(
            "contract-1",
            recipe_ref(),
            hash("recipe"),
            hash("path"),
            permissions(),
            RecipeSessionLimits::new(4096, 16, 16, 16).unwrap(),
        );
        let narrow_b = contract_with(
            "contract-1",
            recipe_ref(),
            hash("recipe"),
            hash("path"),
            permissions(),
            RecipeSessionLimits::new(2048, 16, 16, 16).unwrap(),
        );

        let acceptance_a = proposal.accept("acceptance-1", "peer-b", narrow_a).unwrap();
        let acceptance_b = proposal.accept("acceptance-2", "peer-b", narrow_b).unwrap();
        let lock_a = proposal.lock("lock-1", &acceptance_a).unwrap();
        let lock_b = proposal.lock("lock-2", &acceptance_b).unwrap();

        assert_ne!(lock_a.lock_digest(), lock_b.lock_digest());
        assert_ne!(
            lock_a.locked_contract_digest(),
            lock_b.locked_contract_digest()
        );
    }

    #[test]
    fn lock_digest_changes_when_accepted_path_permissions_change() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let accepted_all = valid_contract();
        let accepted_narrow = contract_with(
            "contract-1",
            recipe_ref(),
            hash("recipe"),
            hash("path"),
            vec![RecipeSessionPathPermission::egress("items[*].packets[*].payload_len").unwrap()],
            RecipeSessionLimits::new(64 * 1024, 1024, 4096, 1).unwrap(),
        );

        let acceptance_all = proposal
            .accept("acceptance-1", "peer-b", accepted_all)
            .unwrap();
        let acceptance_narrow = proposal
            .accept("acceptance-2", "peer-b", accepted_narrow)
            .unwrap();
        let lock_all = proposal.lock("lock-1", &acceptance_all).unwrap();
        let lock_narrow = proposal.lock("lock-2", &acceptance_narrow).unwrap();

        assert_ne!(lock_all.lock_digest(), lock_narrow.lock_digest());
        assert_ne!(
            lock_all.locked_contract_digest(),
            lock_narrow.locked_contract_digest()
        );
    }

    #[test]
    fn lock_rejects_acceptance_bound_to_different_proposal_id() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let acceptance = RecipeSessionAcceptance::new(
            "acceptance-1",
            "proposal-other",
            "peer-b",
            valid_contract(),
        )
        .unwrap();

        let result = proposal.lock("lock-1", &acceptance);
        assert!(matches!(
            result,
            Err(RecipeSessionError::AcceptanceProposalIdMismatch { expected, actual })
                if expected == "proposal-1" && actual == "proposal-other"
        ));
    }

    #[test]
    fn proposal_acceptance_rejection_and_lock_receipts_are_non_live_metadata() {
        let proposal =
            RecipeSessionProposal::new("proposal-1", "peer-a", valid_contract()).unwrap();
        let acceptance = proposal
            .accept("acceptance-1", "peer-b", valid_contract())
            .unwrap();
        let rejection = proposal
            .reject(
                "rejection-1",
                "peer-b",
                RecipeSessionRejectionReason::LimitIncompatible,
            )
            .unwrap();
        let lock = proposal.lock("lock-1", &acceptance).unwrap();

        let proposal_receipt = proposal.receipt("proposal-receipt-1").unwrap();
        let acceptance_receipt = acceptance.receipt("acceptance-receipt-1").unwrap();
        let rejection_receipt = rejection.receipt("rejection-receipt-1").unwrap();
        let lock_receipt = lock.receipt("lock-receipt-1").unwrap();

        assert_eq!(
            proposal_receipt.proposal_digest(),
            &proposal.proposal_digest()
        );
        assert_eq!(
            acceptance_receipt.acceptance_digest(),
            &acceptance.acceptance_digest()
        );
        assert_eq!(
            rejection_receipt.rejection_digest(),
            &rejection.rejection_digest()
        );
        assert_eq!(lock_receipt.lock_digest(), lock.lock_digest());
        assert!(!proposal_receipt.no_live_evidence().live_transport_used());
        assert_eq!(lock_receipt.no_live_evidence().bytes_sent(), 0);
        assert_ne!(
            proposal_receipt.receipt_digest(),
            lock_receipt.receipt_digest()
        );
    }

    #[test]
    fn receipts_reject_live_transport_claims() {
        let result = RecipeSessionNoLiveEvidence::new(true, 0, 0);
        assert!(matches!(
            result,
            Err(RecipeSessionError::ReceiptLiveTransportClaimRejected)
        ));
    }

    #[test]
    fn receipts_reject_byte_movement_claims() {
        let result = RecipeSessionNoLiveEvidence::new(false, 1, 0);
        assert!(matches!(
            result,
            Err(RecipeSessionError::ReceiptByteMovementClaimRejected {
                bytes_sent: 1,
                bytes_received: 0
            })
        ));

        let result = RecipeSessionNoLiveEvidence::new(false, 0, 1);
        assert!(matches!(
            result,
            Err(RecipeSessionError::ReceiptByteMovementClaimRejected {
                bytes_sent: 0,
                bytes_received: 1
            })
        ));
    }
    fn artifact_fixture_hashes() -> (RecipeSessionHash, RecipeSessionHash) {
        let export = recipes::file_transfer::uneven_multi_file_pathgen_export();
        let path_manifest_material = export.to_manifest_lines();
        let recipe_manifest_material = format!(
            "recipe=file_transfer.multi_file_then_instruction@v1\n{}",
            path_manifest_material
        );
        (
            RecipeSessionHash::from_material(
                "recipes.file_transfer.multi_file_then_instruction.v1",
                &recipe_manifest_material,
            ),
            RecipeSessionHash::from_material(
                "pathgen_manifest_v1.file_transfer.multi_file_then_instruction",
                &path_manifest_material,
            ),
        )
    }

    fn artifact_fixture_contract() -> RecipeSessionContract {
        let (recipe_hash, path_hash) = artifact_fixture_hashes();
        RecipeSessionArtifactTransferFixture::contract(
            "artifact-contract-1",
            "producer-a",
            "consumer-b",
            recipe_hash,
            path_hash,
        )
        .unwrap()
    }

    fn artifact_fixture_locked() -> LockedRecipeSessionContract {
        let (recipe_hash, path_hash) = artifact_fixture_hashes();
        let proposal = RecipeSessionArtifactTransferFixture::proposal(
            "artifact-proposal-1",
            "artifact-contract-1",
            "producer-a",
            "consumer-b",
            recipe_hash,
            path_hash,
        )
        .unwrap();
        let acceptance = proposal
            .accept(
                "artifact-acceptance-1",
                "consumer-b",
                proposal.contract().clone(),
            )
            .unwrap();
        proposal.lock("artifact-lock-1", &acceptance).unwrap()
    }

    #[test]
    fn artifact_fixture_can_build_a_valid_session_contract() {
        let contract = artifact_fixture_contract();

        assert_eq!(contract.contract_id(), "artifact-contract-1");
        assert_eq!(
            contract.recipe_ref().canonical_name(),
            "file_transfer.multi_file_then_instruction@v1"
        );
        assert_eq!(contract.participants().len(), 2);
        assert!(contract.participants().iter().any(|participant| {
            participant.id() == "producer-a" && participant.role() == RecipeSessionRole::Producer
        }));
        assert!(contract.participants().iter().any(|participant| {
            participant.id() == "consumer-b" && participant.role() == RecipeSessionRole::Consumer
        }));
        assert_eq!(
            contract.path_permissions().len(),
            RecipeSessionArtifactTransferFixture::egress_manifest_paths().len()
                + RecipeSessionArtifactTransferFixture::ingress_receipt_paths().len()
        );
        assert!(contract.contains_exact_path(
            RecipeSessionDirection::Egress,
            &RecipeSessionPath::new(ARTIFACT_TRANSFER_ITEMS_DECLARED_LEN_PATH).unwrap()
        ));
        assert!(contract.contains_exact_path(
            RecipeSessionDirection::Ingress,
            &RecipeSessionPath::new(ARTIFACT_TRANSFER_RECEIPT_STATUS_PATH).unwrap()
        ));
    }

    #[test]
    fn artifact_fixture_can_build_proposal_acceptance_and_lock() {
        let (recipe_hash, path_hash) = artifact_fixture_hashes();
        let proposal = RecipeSessionArtifactTransferFixture::proposal(
            "artifact-proposal-1",
            "artifact-contract-1",
            "producer-a",
            "consumer-b",
            recipe_hash,
            path_hash,
        )
        .unwrap();

        let acceptance = proposal
            .accept(
                "artifact-acceptance-1",
                "consumer-b",
                proposal.contract().clone(),
            )
            .unwrap();
        let locked = proposal.lock("artifact-lock-1", &acceptance).unwrap();

        assert_eq!(proposal.proposed_by(), "producer-a");
        assert_eq!(acceptance.accepted_by(), "consumer-b");
        assert_eq!(locked.proposal_id(), "artifact-proposal-1");
        assert_eq!(locked.acceptance_id(), "artifact-acceptance-1");
        assert_eq!(
            locked.locked_contract().recipe_ref().canonical_name(),
            "file_transfer.multi_file_then_instruction@v1"
        );
    }

    #[test]
    fn locked_artifact_fixture_binds_file_transfer_egress_paths() {
        let locked = artifact_fixture_locked();

        let item_binding = locked
            .locked_contract()
            .bind_egress_path("file_transfer.multi_file_then_instruction.items[0].declared_len")
            .unwrap();
        assert_eq!(
            item_binding.matched_permission().path().as_str(),
            ARTIFACT_TRANSFER_ITEMS_DECLARED_LEN_PATH
        );

        let packet_binding = locked
            .locked_contract()
            .bind_egress_path("file_transfer.multi_file_then_instruction.packets[4].payload_len")
            .unwrap();
        assert_eq!(
            packet_binding.matched_permission().path().as_str(),
            ARTIFACT_TRANSFER_PACKETS_PAYLOAD_LEN_PATH
        );

        let boundary_binding = locked
            .locked_contract()
            .bind_egress_path(ARTIFACT_TRANSFER_NEXT_INSTRUCTION_SEQ_PATH)
            .unwrap();
        assert_eq!(
            boundary_binding.access().path().as_str(),
            ARTIFACT_TRANSFER_NEXT_INSTRUCTION_SEQ_PATH
        );
    }

    #[test]
    fn locked_artifact_fixture_binds_receipt_ingress_paths() {
        let locked = artifact_fixture_locked();

        let status_binding = locked
            .locked_contract()
            .bind_ingress_path("receipts[2].status")
            .unwrap();
        assert_eq!(
            status_binding.matched_permission().path().as_str(),
            ARTIFACT_TRANSFER_RECEIPT_STATUS_PATH
        );

        let digest_binding = locked
            .locked_contract()
            .bind_ingress_path("receipts[2].digest")
            .unwrap();
        assert_eq!(
            digest_binding.matched_permission().path().as_str(),
            ARTIFACT_TRANSFER_RECEIPT_DIGEST_PATH
        );
    }

    #[test]
    fn artifact_fixture_rejects_forbidden_file_transfer_paths() {
        let locked = artifact_fixture_locked();

        let forbidden_packet_digest = locked.locked_contract().bind_egress_path(
            "file_transfer.multi_file_then_instruction.packets[0].payload_digest",
        );
        assert!(matches!(
            forbidden_packet_digest,
            Err(RecipeSessionError::PathAccessDenied { direction, path })
                if direction == RecipeSessionDirection::Egress
                    && path == "file_transfer.multi_file_then_instruction.packets[0].payload_digest"
        ));

        let wrong_direction = locked
            .locked_contract()
            .bind_egress_path("receipts[0].status");
        assert!(matches!(
            wrong_direction,
            Err(RecipeSessionError::PathAccessDenied { direction, path })
                if direction == RecipeSessionDirection::Egress && path == "receipts[0].status"
        ));
    }

    #[test]
    fn artifact_fixture_hashes_are_deterministic() {
        let first = RecipeSessionHash::from_material(
            "recipes.file_transfer.fixture",
            "stable recipe manifest material",
        );
        let second = RecipeSessionHash::from_material(
            "recipes.file_transfer.fixture",
            "stable recipe manifest material",
        );
        let changed = RecipeSessionHash::from_material(
            "recipes.file_transfer.fixture",
            "changed recipe manifest material",
        );

        assert_eq!(first, second);
        assert_ne!(first, changed);
        assert!(first.as_str().starts_with("sha256:"));
        assert_eq!(first.as_str().len(), "sha256:".len() + 64);
    }

    #[test]
    fn artifact_fixture_path_bindings_remain_metadata_only() {
        let locked = artifact_fixture_locked();
        let binding = locked
            .locked_contract()
            .bind_egress_path("file_transfer.multi_file_then_instruction.packets[0].seq")
            .unwrap();
        let lock_receipt = locked.receipt("artifact-lock-receipt-1").unwrap();

        assert_eq!(
            binding.canonical_binding_material(),
            "direction=egress;path=file_transfer.multi_file_then_instruction.packets[0].seq;matched=egress:file_transfer.multi_file_then_instruction.packets[*].seq"
        );
        assert!(!lock_receipt.no_live_evidence().live_transport_used());
        assert_eq!(lock_receipt.no_live_evidence().bytes_sent(), 0);
        assert_eq!(lock_receipt.no_live_evidence().bytes_received(), 0);
    }

    #[test]
    fn artifact_fixture_paths_agree_with_real_file_transfer_manifest() {
        let export = recipes::file_transfer::uneven_multi_file_pathgen_export();

        assert_eq!(export.namespace, "file_transfer");
        assert_eq!(export.program_name, "multi_file_then_instruction");
        assert!(export.const_names_are_unique());
        for path in RecipeSessionArtifactTransferFixture::egress_manifest_paths() {
            assert!(
                export.contains_path(path),
                "missing egress manifest path {path}"
            );
        }
    }

    #[test]
    fn artifact_fixture_relative_paths_resolve_with_recipe_writer_lookup() {
        let schedule = recipes::file_transfer::uneven_multi_file_fixture();
        let export = schedule.to_pathgen_export("file_transfer");
        let value = schedule.to_value();

        for concrete in [
            "file_transfer.multi_file_then_instruction.items[0].declared_len",
            "file_transfer.multi_file_then_instruction.items[1].packet_count",
            "file_transfer.multi_file_then_instruction.packets[4].item_byte_end",
            "file_transfer.multi_file_then_instruction.packets[5].is_final_for_item",
            "file_transfer.multi_file_then_instruction.next_instruction_seq",
        ] {
            let wildcard = recipe_writer::path_lookup::wildcardize_indexes(concrete);
            assert!(
                export.contains_path(&wildcard),
                "missing wildcard {wildcard}"
            );
            let relative = RecipeSessionArtifactTransferFixture::relative_value_path(concrete)
                .expect("artifact path should strip to a recipe_writer value path");
            assert!(
                recipe_writer::path_lookup::lookup_value_path(&value, relative).is_ok(),
                "lookup failed for {relative}"
            );
        }

        let relative_payload_lens = RecipeSessionArtifactTransferFixture::relative_value_path(
            ARTIFACT_TRANSFER_PACKETS_PAYLOAD_LEN_PATH,
        )
        .unwrap();
        let payload_lens =
            recipe_writer::path_lookup::collect_value_path(&value, relative_payload_lens).unwrap();
        assert_eq!(payload_lens.len(), 6);

        assert!(
            RecipeSessionArtifactTransferFixture::relative_value_path(
                ARTIFACT_TRANSFER_RECEIPT_STATUS_PATH
            )
            .is_none(),
            "receipt ingress paths are session metadata, not file-transfer value paths"
        );
    }

    #[test]
    fn artifact_fixture_closeout_one_call_locks_and_binds_usage_paths() {
        let (recipe_hash, path_hash) = artifact_fixture_hashes();

        let locked = RecipeSessionArtifactTransferFixture::locked_contract(
            "artifact-proposal-closeout-1",
            "artifact-acceptance-closeout-1",
            "artifact-lock-closeout-1",
            "artifact-contract-closeout-1",
            "artifact-sender",
            "artifact-receiver",
            recipe_hash,
            path_hash,
        )
        .unwrap();

        assert_eq!(locked.proposal_id(), "artifact-proposal-closeout-1");
        assert_eq!(locked.acceptance_id(), "artifact-acceptance-closeout-1");
        assert_eq!(
            locked.locked_contract().recipe_ref().canonical_name(),
            "file_transfer.multi_file_then_instruction@v1"
        );

        let payload_len_binding = locked
            .locked_contract()
            .bind_egress_path("file_transfer.multi_file_then_instruction.packets[4].payload_len")
            .unwrap();

        assert_eq!(
            payload_len_binding.matched_permission().path().as_str(),
            ARTIFACT_TRANSFER_PACKETS_PAYLOAD_LEN_PATH
        );

        let receipt_status_binding = locked
            .locked_contract()
            .bind_ingress_path("receipts[0].status")
            .unwrap();

        assert_eq!(
            receipt_status_binding.matched_permission().path().as_str(),
            ARTIFACT_TRANSFER_RECEIPT_STATUS_PATH
        );
    }

    #[test]
    fn artifact_fixture_closeout_surface_has_complete_distinct_path_inventory() {
        let egress_paths = RecipeSessionArtifactTransferFixture::egress_manifest_paths();
        let ingress_paths = RecipeSessionArtifactTransferFixture::ingress_receipt_paths();

        assert_eq!(egress_paths.len(), 16);
        assert_eq!(ingress_paths.len(), 3);

        let mut all_paths = Vec::new();
        all_paths.extend_from_slice(egress_paths);
        all_paths.extend_from_slice(ingress_paths);

        for (left_index, left) in all_paths.iter().enumerate() {
            assert!(
                !left.trim().is_empty(),
                "fixture path at index {left_index} must not be empty"
            );

            for right in all_paths.iter().skip(left_index + 1) {
                assert_ne!(
                    left, right,
                    "artifact fixture closeout path inventory must not contain duplicates"
                );
            }
        }

        assert!(egress_paths.contains(&ARTIFACT_TRANSFER_ITEMS_DECLARED_LEN_PATH));
        assert!(egress_paths.contains(&ARTIFACT_TRANSFER_PACKETS_PAYLOAD_LEN_PATH));
        assert!(egress_paths.contains(&ARTIFACT_TRANSFER_NEXT_INSTRUCTION_SEQ_PATH));
        assert!(ingress_paths.contains(&ARTIFACT_TRANSFER_RECEIPT_PACKET_SEQ_PATH));
        assert!(ingress_paths.contains(&ARTIFACT_TRANSFER_RECEIPT_STATUS_PATH));
        assert!(ingress_paths.contains(&ARTIFACT_TRANSFER_RECEIPT_DIGEST_PATH));
    }

    #[test]
    fn artifact_fixture_closeout_one_call_receipt_remains_metadata_only() {
        let (recipe_hash, path_hash) = artifact_fixture_hashes();

        let locked = RecipeSessionArtifactTransferFixture::locked_contract(
            "artifact-proposal-closeout-2",
            "artifact-acceptance-closeout-2",
            "artifact-lock-closeout-2",
            "artifact-contract-closeout-2",
            "artifact-sender",
            "artifact-receiver",
            recipe_hash,
            path_hash,
        )
        .unwrap();

        let receipt = locked.receipt("artifact-closeout-lock-receipt-1").unwrap();

        assert!(!receipt.no_live_evidence().live_transport_used());
        assert_eq!(receipt.no_live_evidence().bytes_sent(), 0);
        assert_eq!(receipt.no_live_evidence().bytes_received(), 0);

        let binding = locked
            .locked_contract()
            .bind_egress_path("file_transfer.multi_file_then_instruction.items[1].packet_count")
            .unwrap();

        assert_eq!(
            binding.matched_permission().path().as_str(),
            ARTIFACT_TRANSFER_ITEMS_PACKET_COUNT_PATH
        );
    }

    fn artifact_fixture_locked_from_real_export() -> LockedRecipeSessionContract {
        let export = recipes::file_transfer::uneven_multi_file_pathgen_export();
        let (recipe_hash, path_hash) =
            RecipeSessionArtifactTransferFixture::manifest_hashes(&export.to_manifest_lines());

        RecipeSessionArtifactTransferFixture::locked_contract(
            "artifact-e2e-proposal-1",
            "artifact-e2e-acceptance-1",
            "artifact-e2e-lock-1",
            "artifact-e2e-contract-1",
            "artifact-sender",
            "artifact-receiver",
            recipe_hash,
            path_hash,
        )
        .unwrap()
    }

    #[test]
    fn artifact_fixture_e2e_helpers_build_hashes_and_lock_from_real_export() {
        let export = recipes::file_transfer::uneven_multi_file_pathgen_export();

        let (recipe_hash, path_hash) =
            RecipeSessionArtifactTransferFixture::manifest_hashes(&export.to_manifest_lines());

        assert_eq!(
            RecipeSessionArtifactTransferFixture::recipe_manifest_material(),
            "file_transfer.multi_file_then_instruction@v1"
        );
        assert!(recipe_hash.as_str().starts_with("sha256:"));
        assert!(path_hash.as_str().starts_with("sha256:"));
        assert_ne!(recipe_hash, path_hash);

        let locked = RecipeSessionArtifactTransferFixture::locked_contract(
            "artifact-e2e-proposal-2",
            "artifact-e2e-acceptance-2",
            "artifact-e2e-lock-2",
            "artifact-e2e-contract-2",
            "artifact-sender",
            "artifact-receiver",
            recipe_hash,
            path_hash,
        )
        .unwrap();

        assert_eq!(locked.proposal_id(), "artifact-e2e-proposal-2");
        assert_eq!(locked.acceptance_id(), "artifact-e2e-acceptance-2");
        assert_eq!(
            locked.locked_contract().recipe_ref().canonical_name(),
            "file_transfer.multi_file_then_instruction@v1"
        );
    }

    #[test]
    fn artifact_fixture_e2e_helpers_classify_declared_permission_inventory() {
        assert_eq!(
            RecipeSessionArtifactTransferFixture::declared_permission_direction(
                ARTIFACT_TRANSFER_PACKETS_PAYLOAD_LEN_PATH
            ),
            Some(RecipeSessionDirection::Egress)
        );
        assert_eq!(
            RecipeSessionArtifactTransferFixture::declared_permission_direction(
                ARTIFACT_TRANSFER_ITEMS_PACKET_COUNT_PATH
            ),
            Some(RecipeSessionDirection::Egress)
        );
        assert_eq!(
            RecipeSessionArtifactTransferFixture::declared_permission_direction(
                ARTIFACT_TRANSFER_RECEIPT_STATUS_PATH
            ),
            Some(RecipeSessionDirection::Ingress)
        );
        assert_eq!(
            RecipeSessionArtifactTransferFixture::declared_permission_direction(
                "file_transfer.multi_file_then_instruction.packets[*].payload_digest"
            ),
            None
        );
        assert_eq!(
            RecipeSessionArtifactTransferFixture::declared_permission_direction(
                "receipts[*].unknown"
            ),
            None
        );
    }

    #[test]
    fn artifact_fixture_e2e_can_emit_and_receive_probe_helpers_match_contract_binding() {
        let locked = artifact_fixture_locked_from_real_export();

        assert!(RecipeSessionArtifactTransferFixture::can_emit_path(
            &locked,
            "file_transfer.multi_file_then_instruction.items[0].declared_len"
        ));
        assert!(RecipeSessionArtifactTransferFixture::can_emit_path(
            &locked,
            "file_transfer.multi_file_then_instruction.items[1].packet_count"
        ));
        assert!(RecipeSessionArtifactTransferFixture::can_emit_path(
            &locked,
            "file_transfer.multi_file_then_instruction.packets[4].payload_len"
        ));
        assert!(RecipeSessionArtifactTransferFixture::can_emit_path(
            &locked,
            "file_transfer.multi_file_then_instruction.packets[5].is_final_for_item"
        ));
        assert!(RecipeSessionArtifactTransferFixture::can_emit_path(
            &locked,
            ARTIFACT_TRANSFER_NEXT_INSTRUCTION_SEQ_PATH
        ));

        assert!(
            RecipeSessionArtifactTransferFixture::can_receive_receipt_path(
                &locked,
                "receipts[0].packet_seq"
            )
        );
        assert!(
            RecipeSessionArtifactTransferFixture::can_receive_receipt_path(
                &locked,
                "receipts[0].status"
            )
        );
        assert!(
            RecipeSessionArtifactTransferFixture::can_receive_receipt_path(
                &locked,
                "receipts[0].digest"
            )
        );
    }

    #[test]
    fn artifact_fixture_e2e_probe_helpers_reject_wrong_direction_and_unknown_siblings() {
        let locked = artifact_fixture_locked_from_real_export();

        assert!(!RecipeSessionArtifactTransferFixture::can_emit_path(
            &locked,
            "receipts[0].status"
        ));
        assert!(!RecipeSessionArtifactTransferFixture::can_emit_path(
            &locked,
            "file_transfer.multi_file_then_instruction.packets[0].payload_digest"
        ));
        assert!(!RecipeSessionArtifactTransferFixture::can_emit_path(
            &locked,
            "file_transfer.multi_file_then_instruction.items[0].unknown"
        ));

        assert!(
            !RecipeSessionArtifactTransferFixture::can_receive_receipt_path(
                &locked,
                "file_transfer.multi_file_then_instruction.packets[0].payload_len"
            )
        );
        assert!(
            !RecipeSessionArtifactTransferFixture::can_receive_receipt_path(
                &locked,
                "receipts[0].unknown"
            )
        );
    }

    #[test]
    fn artifact_fixture_e2e_real_recipe_values_bind_through_session_permissions() {
        let locked = artifact_fixture_locked_from_real_export();
        let schedule = recipes::file_transfer::uneven_multi_file_fixture();
        let export = schedule.to_pathgen_export("file_transfer");
        let value = schedule.to_value();

        for concrete in [
            "file_transfer.multi_file_then_instruction.items[0].declared_len",
            "file_transfer.multi_file_then_instruction.items[1].packet_count",
            "file_transfer.multi_file_then_instruction.packets[4].payload_len",
            "file_transfer.multi_file_then_instruction.packets[5].is_final_for_item",
            "file_transfer.multi_file_then_instruction.next_instruction_seq",
        ] {
            assert!(
                RecipeSessionArtifactTransferFixture::can_emit_path(&locked, concrete),
                "locked contract should allow {concrete}"
            );

            let wildcard = recipe_writer::path_lookup::wildcardize_indexes(concrete);
            assert!(
                export.contains_path(&wildcard),
                "export should contain {wildcard}"
            );

            let relative = RecipeSessionArtifactTransferFixture::relative_value_path(concrete)
                .expect("artifact egress path should map to recipe_writer value path");

            assert!(
                recipe_writer::path_lookup::lookup_value_path(&value, relative).is_ok(),
                "recipe_writer lookup should resolve {relative}"
            );
        }
    }

    #[test]
    fn artifact_fixture_e2e_collects_packet_lengths_for_future_send_attempts() {
        let locked = artifact_fixture_locked_from_real_export();
        let schedule = recipes::file_transfer::uneven_multi_file_fixture();
        let value = schedule.to_value();

        assert!(RecipeSessionArtifactTransferFixture::can_emit_path(
            &locked,
            "file_transfer.multi_file_then_instruction.packets[0].payload_len"
        ));

        let relative_payload_lens = RecipeSessionArtifactTransferFixture::relative_value_path(
            ARTIFACT_TRANSFER_PACKETS_PAYLOAD_LEN_PATH,
        )
        .unwrap();

        let payload_lens =
            recipe_writer::path_lookup::collect_value_path(&value, relative_payload_lens).unwrap();

        assert_eq!(payload_lens.len(), 6);

        for concrete_packet_path in [
            "file_transfer.multi_file_then_instruction.packets[0].payload_len",
            "file_transfer.multi_file_then_instruction.packets[1].payload_len",
            "file_transfer.multi_file_then_instruction.packets[2].payload_len",
            "file_transfer.multi_file_then_instruction.packets[3].payload_len",
            "file_transfer.multi_file_then_instruction.packets[4].payload_len",
            "file_transfer.multi_file_then_instruction.packets[5].payload_len",
        ] {
            assert!(
                RecipeSessionArtifactTransferFixture::can_emit_path(&locked, concrete_packet_path),
                "locked contract should allow {concrete_packet_path}"
            );
        }
    }

    #[test]
    fn artifact_fixture_e2e_manual_and_one_call_flows_authorize_same_paths() {
        let export = recipes::file_transfer::uneven_multi_file_pathgen_export();
        let (recipe_hash, path_hash) =
            RecipeSessionArtifactTransferFixture::manifest_hashes(&export.to_manifest_lines());

        let manual_proposal = RecipeSessionArtifactTransferFixture::proposal(
            "artifact-e2e-manual-proposal-1",
            "artifact-e2e-manual-contract-1",
            "artifact-sender",
            "artifact-receiver",
            recipe_hash.clone(),
            path_hash.clone(),
        )
        .unwrap();
        let manual_acceptance = manual_proposal
            .accept(
                "artifact-e2e-manual-acceptance-1",
                "artifact-receiver",
                manual_proposal.contract().clone(),
            )
            .unwrap();
        let manual_locked = manual_proposal
            .lock("artifact-e2e-manual-lock-1", &manual_acceptance)
            .unwrap();

        let one_call_locked = RecipeSessionArtifactTransferFixture::locked_contract(
            "artifact-e2e-one-call-proposal-1",
            "artifact-e2e-one-call-acceptance-1",
            "artifact-e2e-one-call-lock-1",
            "artifact-e2e-one-call-contract-1",
            "artifact-sender",
            "artifact-receiver",
            recipe_hash,
            path_hash,
        )
        .unwrap();

        for egress_path in [
            "file_transfer.multi_file_then_instruction.items[0].declared_len",
            "file_transfer.multi_file_then_instruction.items[1].packet_count",
            "file_transfer.multi_file_then_instruction.packets[4].payload_len",
            "file_transfer.multi_file_then_instruction.next_instruction_seq",
        ] {
            assert_eq!(
                RecipeSessionArtifactTransferFixture::can_emit_path(&manual_locked, egress_path),
                RecipeSessionArtifactTransferFixture::can_emit_path(&one_call_locked, egress_path),
                "manual and one-call flows should agree for {egress_path}"
            );
        }

        for ingress_path in [
            "receipts[0].packet_seq",
            "receipts[0].status",
            "receipts[0].digest",
        ] {
            assert_eq!(
                RecipeSessionArtifactTransferFixture::can_receive_receipt_path(
                    &manual_locked,
                    ingress_path
                ),
                RecipeSessionArtifactTransferFixture::can_receive_receipt_path(
                    &one_call_locked,
                    ingress_path
                ),
                "manual and one-call flows should agree for {ingress_path}"
            );
        }
    }

    #[test]
    fn artifact_fixture_e2e_receipt_paths_stay_session_metadata_not_recipe_values() {
        let locked = artifact_fixture_locked_from_real_export();

        assert!(
            RecipeSessionArtifactTransferFixture::can_receive_receipt_path(
                &locked,
                "receipts[3].status"
            )
        );

        assert!(
            RecipeSessionArtifactTransferFixture::relative_value_path("receipts[3].status")
                .is_none()
        );
        assert!(
            RecipeSessionArtifactTransferFixture::relative_value_path("receipts[3].digest")
                .is_none()
        );

        let receipt = locked.receipt("artifact-e2e-lock-receipt-1").unwrap();

        assert!(!receipt.no_live_evidence().live_transport_used());
        assert_eq!(receipt.no_live_evidence().bytes_sent(), 0);
        assert_eq!(receipt.no_live_evidence().bytes_received(), 0);
    }
}
