//! Durable create-once identity claimants for exact D1 DML attempts.
//!
//! Three independent namespaces reserve the operation, execution-attempt, and
//! provider-request identities before any provider access. Because the private
//! store cannot atomically create three files, each claimant first binds the
//! exact caller intent and claimant set, then is sealed to the full attempt
//! binding after exact plan composition. Provider dispatch is authorized only
//! after all three sealed files have been reread exactly.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::d1_dml_attempt_custody::D1DmlAttemptIdentities;
use crate::d1_opaque_identity::valid_d1_opaque_identity;
use crate::d1_target::{D1TargetIdentity, normalize_d1_target};

pub(crate) const D1_DML_IDENTITY_CLAIMANT_OPERATION: &str = "d1_dml_identity_claimant";
pub(crate) const D1_DML_IDENTITY_CLAIMANT_BYTE_CAP: usize = 4_096;

const CLAIMANT_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlIdentityNamespace {
    Operation,
    ExecutionAttempt,
    ProviderRequest,
}

impl D1DmlIdentityNamespace {
    pub(crate) const ALL: [Self; 3] = [
        Self::Operation,
        Self::ExecutionAttempt,
        Self::ProviderRequest,
    ];

    pub(crate) fn filename_label(self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::ExecutionAttempt => "execution-attempt",
            Self::ProviderRequest => "provider-request",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlIdentityClaimantPhase {
    Pending,
    Bound,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct D1DmlIdentityClaimantReceipt {
    version: u8,
    operation: String,
    pub(crate) namespace: D1DmlIdentityNamespace,
    pub(crate) target_key_sha256: String,
    pub(crate) identity_sha256: String,
    claimant_set_sha256: String,
    execute_plan_sha256: String,
    intent_binding_sha256: String,
    pub(crate) phase: D1DmlIdentityClaimantPhase,
    pub(crate) attempt_binding_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1DmlIdentityClaimantProduct {
    receipt: D1DmlIdentityClaimantReceipt,
    state_bytes: Vec<u8>,
}

impl D1DmlIdentityClaimantProduct {
    pub(crate) fn receipt(&self) -> &D1DmlIdentityClaimantReceipt {
        &self.receipt
    }

    pub(crate) fn state_bytes(&self) -> &[u8] {
        &self.state_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1DmlIdentityClaimantSet {
    target_key_sha256: String,
    claimant_set_sha256: String,
    execute_plan_sha256: String,
    intent_binding_sha256: String,
    identities: [(D1DmlIdentityNamespace, String); 3],
}

impl D1DmlIdentityClaimantSet {
    pub(crate) fn identity_sha256(&self, namespace: D1DmlIdentityNamespace) -> &str {
        self.identities
            .iter()
            .find_map(|(candidate, digest)| (*candidate == namespace).then_some(digest.as_str()))
            .expect("closed claimant namespace is complete")
    }

    pub(crate) fn pending(
        &self,
        namespace: D1DmlIdentityNamespace,
    ) -> D1DmlIdentityClaimantProduct {
        self.product(namespace, D1DmlIdentityClaimantPhase::Pending, None)
    }

    pub(crate) fn bound(
        &self,
        namespace: D1DmlIdentityNamespace,
        attempt_binding_sha256: &str,
    ) -> Result<D1DmlIdentityClaimantProduct, D1DmlIdentityClaimantError> {
        if !valid_sha256(attempt_binding_sha256) {
            return Err(claimant_error(
                D1DmlIdentityClaimantClassification::AttemptBindingInvalid,
                "full attempt binding was not canonical SHA-256",
            ));
        }
        Ok(self.product(
            namespace,
            D1DmlIdentityClaimantPhase::Bound,
            Some(attempt_binding_sha256.to_string()),
        ))
    }

    pub(crate) fn restore_exact(
        &self,
        namespace: D1DmlIdentityNamespace,
        bytes: &[u8],
    ) -> Result<D1DmlIdentityClaimantProduct, D1DmlIdentityClaimantError> {
        let product = inspect_d1_dml_identity_claimant(bytes)?;
        let expected = self.product(
            namespace,
            product.receipt.phase,
            product.receipt.attempt_binding_sha256.clone(),
        );
        if product != expected {
            return Err(claimant_error(
                D1DmlIdentityClaimantClassification::RestoredClaimantContradictory,
                "physically present identity claimant contradicted the exact target, namespace, claimant set, or caller intent",
            ));
        }
        Ok(product)
    }

    fn product(
        &self,
        namespace: D1DmlIdentityNamespace,
        phase: D1DmlIdentityClaimantPhase,
        attempt_binding_sha256: Option<String>,
    ) -> D1DmlIdentityClaimantProduct {
        let receipt = D1DmlIdentityClaimantReceipt {
            version: CLAIMANT_VERSION,
            operation: D1_DML_IDENTITY_CLAIMANT_OPERATION.to_string(),
            namespace,
            target_key_sha256: self.target_key_sha256.clone(),
            identity_sha256: self.identity_sha256(namespace).to_string(),
            claimant_set_sha256: self.claimant_set_sha256.clone(),
            execute_plan_sha256: self.execute_plan_sha256.clone(),
            intent_binding_sha256: self.intent_binding_sha256.clone(),
            phase,
            attempt_binding_sha256,
        };
        let state_bytes = canonical_bytes(&receipt);
        D1DmlIdentityClaimantProduct {
            receipt,
            state_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlIdentityClaimantClassification {
    TargetIdentityInvalid,
    ExecutePlanDigestInvalid,
    OpaqueIdentityInvalid,
    OpaqueIdentityDuplicate,
    AttemptBindingInvalid,
    RestoredClaimantRequired,
    RestoredClaimantTooLarge,
    RestoredClaimantMalformed,
    RestoredClaimantNonCanonical,
    RestoredClaimantContradictory,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1DmlIdentityClaimantError {
    pub(crate) code: &'static str,
    pub(crate) classification: D1DmlIdentityClaimantClassification,
    pub(crate) message: &'static str,
}

pub(crate) fn derive_d1_dml_identity_claimant_set(
    target: &D1TargetIdentity,
    execute_plan_sha256: &str,
    identities: D1DmlAttemptIdentities<'_>,
) -> Result<D1DmlIdentityClaimantSet, D1DmlIdentityClaimantError> {
    let normalized =
        normalize_d1_target(&target.account_id, &target.database_id).map_err(|_| {
            claimant_error(
                D1DmlIdentityClaimantClassification::TargetIdentityInvalid,
                "D1 target identity was not exact canonical input",
            )
        })?;
    if &normalized != target {
        return Err(claimant_error(
            D1DmlIdentityClaimantClassification::TargetIdentityInvalid,
            "D1 target identity was not exact canonical input",
        ));
    }
    if !valid_sha256(execute_plan_sha256) {
        return Err(claimant_error(
            D1DmlIdentityClaimantClassification::ExecutePlanDigestInvalid,
            "execute-plan digest was not canonical SHA-256",
        ));
    }
    let opaque = [
        identities.operation_id,
        identities.execution_attempt_id,
        identities.provider_request_id,
    ];
    if opaque.iter().any(|value| !valid_d1_opaque_identity(value)) {
        return Err(claimant_error(
            D1DmlIdentityClaimantClassification::OpaqueIdentityInvalid,
            "preallocated attempt identities were not exact bounded opaque identifiers",
        ));
    }
    if opaque.into_iter().collect::<BTreeSet<_>>().len() != 3 {
        return Err(claimant_error(
            D1DmlIdentityClaimantClassification::OpaqueIdentityDuplicate,
            "preallocated attempt identities were not pairwise distinct",
        ));
    }
    let identities = [
        (
            D1DmlIdentityNamespace::Operation,
            hash_bytes(opaque[0].as_bytes()),
        ),
        (
            D1DmlIdentityNamespace::ExecutionAttempt,
            hash_bytes(opaque[1].as_bytes()),
        ),
        (
            D1DmlIdentityNamespace::ProviderRequest,
            hash_bytes(opaque[2].as_bytes()),
        ),
    ];
    let target_key_sha256 = target.target_key_sha256();
    let claimant_set_sha256 = hash_serialized(&(
        CLAIMANT_VERSION,
        D1_DML_IDENTITY_CLAIMANT_OPERATION,
        &identities,
    ));
    let intent_binding_sha256 = hash_serialized(&(
        CLAIMANT_VERSION,
        D1_DML_IDENTITY_CLAIMANT_OPERATION,
        target_key_sha256.as_str(),
        execute_plan_sha256,
        claimant_set_sha256.as_str(),
    ));
    Ok(D1DmlIdentityClaimantSet {
        target_key_sha256,
        claimant_set_sha256,
        execute_plan_sha256: execute_plan_sha256.to_string(),
        intent_binding_sha256,
        identities,
    })
}

pub(crate) fn inspect_d1_dml_identity_claimant(
    bytes: &[u8],
) -> Result<D1DmlIdentityClaimantProduct, D1DmlIdentityClaimantError> {
    if bytes.is_empty() {
        return Err(claimant_error(
            D1DmlIdentityClaimantClassification::RestoredClaimantRequired,
            "one physically present claimant artifact was required",
        ));
    }
    if bytes.len() > D1_DML_IDENTITY_CLAIMANT_BYTE_CAP {
        return Err(claimant_error(
            D1DmlIdentityClaimantClassification::RestoredClaimantTooLarge,
            "claimant artifact exceeded the exact byte cap",
        ));
    }
    let receipt = serde_json::from_slice::<D1DmlIdentityClaimantReceipt>(bytes).map_err(|_| {
        claimant_error(
            D1DmlIdentityClaimantClassification::RestoredClaimantMalformed,
            "claimant artifact was malformed or outside the closed schema",
        )
    })?;
    if canonical_bytes(&receipt) != bytes {
        return Err(claimant_error(
            D1DmlIdentityClaimantClassification::RestoredClaimantNonCanonical,
            "claimant artifact was not exact canonical JSON",
        ));
    }
    if receipt.version != CLAIMANT_VERSION
        || receipt.operation != D1_DML_IDENTITY_CLAIMANT_OPERATION
        || !valid_sha256(&receipt.target_key_sha256)
        || !valid_sha256(&receipt.identity_sha256)
        || !valid_sha256(&receipt.claimant_set_sha256)
        || !valid_sha256(&receipt.execute_plan_sha256)
        || !valid_sha256(&receipt.intent_binding_sha256)
        || match receipt.phase {
            D1DmlIdentityClaimantPhase::Pending => receipt.attempt_binding_sha256.is_some(),
            D1DmlIdentityClaimantPhase::Bound => receipt
                .attempt_binding_sha256
                .as_deref()
                .is_none_or(|value| !valid_sha256(value)),
        }
    {
        return Err(claimant_error(
            D1DmlIdentityClaimantClassification::RestoredClaimantContradictory,
            "claimant artifact contradicted the closed claimant product",
        ));
    }
    Ok(D1DmlIdentityClaimantProduct {
        receipt,
        state_bytes: bytes.to_vec(),
    })
}

pub(crate) fn validate_d1_dml_identity_claimant_seal(
    expected: &[u8],
    successor: &[u8],
) -> Result<(), D1DmlIdentityClaimantError> {
    let pending = inspect_d1_dml_identity_claimant(expected)?;
    let bound = inspect_d1_dml_identity_claimant(successor)?;
    if pending.receipt.phase != D1DmlIdentityClaimantPhase::Pending
        || bound.receipt.phase != D1DmlIdentityClaimantPhase::Bound
    {
        return Err(claimant_error(
            D1DmlIdentityClaimantClassification::RestoredClaimantContradictory,
            "identity claimant seal must be the single Pending-to-Bound transition",
        ));
    }
    let expected_bound = D1DmlIdentityClaimantReceipt {
        phase: D1DmlIdentityClaimantPhase::Bound,
        attempt_binding_sha256: bound.receipt.attempt_binding_sha256.clone(),
        ..pending.receipt
    };
    if expected_bound != bound.receipt {
        return Err(claimant_error(
            D1DmlIdentityClaimantClassification::RestoredClaimantContradictory,
            "identity claimant seal changed authority outside the full attempt binding",
        ));
    }
    Ok(())
}

fn canonical_bytes(receipt: &D1DmlIdentityClaimantReceipt) -> Vec<u8> {
    serde_json::to_vec(receipt).expect("serializing claimant receipt cannot fail")
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'))
}

fn hash_serialized<T: Serialize>(value: &T) -> String {
    hash_bytes(&serde_json::to_vec(value).expect("serializing claimant binding cannot fail"))
}

fn hash_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn claimant_error(
    classification: D1DmlIdentityClaimantClassification,
    message: &'static str,
) -> D1DmlIdentityClaimantError {
    D1DmlIdentityClaimantError {
        code: "d1.execute_write_identity_claimant_conflict",
        classification,
        message,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::d1_target::normalize_d1_target;

    fn fixture() -> (D1TargetIdentity, D1DmlIdentityClaimantSet) {
        let target = normalize_d1_target(
            "0123456789abcdef0123456789abcdef",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("target");
        let set = derive_d1_dml_identity_claimant_set(
            &target,
            &"a".repeat(64),
            D1DmlAttemptIdentities {
                operation_id: "operation-fixture-0001",
                execution_attempt_id: "attempt-fixture-0001",
                provider_request_id: "provider-fixture-0001",
            },
        )
        .expect("claimant set");
        (target, set)
    }

    #[test]
    fn exact_pending_and_bound_claimants_round_trip_for_every_namespace() {
        let (_, set) = fixture();
        for namespace in D1DmlIdentityNamespace::ALL {
            let pending = set.pending(namespace);
            assert_eq!(
                set.restore_exact(namespace, pending.state_bytes())
                    .expect("pending replay")
                    .receipt()
                    .phase,
                D1DmlIdentityClaimantPhase::Pending
            );
            let bound = set.bound(namespace, &"b".repeat(64)).expect("bound");
            let replay = set
                .restore_exact(namespace, bound.state_bytes())
                .expect("bound replay");
            assert_eq!(replay.receipt().phase, D1DmlIdentityClaimantPhase::Bound);
            assert_eq!(
                replay.receipt().attempt_binding_sha256.as_deref(),
                Some("b".repeat(64).as_str())
            );
        }
    }

    #[test]
    fn physical_malformed_unknown_duplicate_and_contradictory_claimants_fail_closed() {
        let (_, set) = fixture();
        let namespace = D1DmlIdentityNamespace::ProviderRequest;
        let canonical = set.pending(namespace);
        for bytes in [
            b"null".as_slice(),
            b"[]".as_slice(),
            b"1".as_slice(),
            b"{".as_slice(),
        ] {
            assert!(inspect_d1_dml_identity_claimant(bytes).is_err());
        }

        let mut value: Value = serde_json::from_slice(canonical.state_bytes()).expect("json");
        value["version"] = json!(2);
        assert!(inspect_d1_dml_identity_claimant(&serde_json::to_vec(&value).unwrap()).is_err());

        let mut duplicate = canonical.state_bytes().to_vec();
        duplicate.pop();
        duplicate.extend_from_slice(b",\"namespace\":\"operation\"}");
        assert!(inspect_d1_dml_identity_claimant(&duplicate).is_err());

        let mut swapped: Value =
            serde_json::from_slice(canonical.state_bytes()).expect("claimant json");
        swapped["namespace"] = json!("operation");
        let swapped = serde_json::to_vec(&swapped).expect("swapped claimant");
        assert!(set.restore_exact(namespace, &swapped).is_err());

        let mut noncanonical = canonical.state_bytes().to_vec();
        noncanonical.push(b'\n');
        assert_eq!(
            inspect_d1_dml_identity_claimant(&noncanonical)
                .expect_err("noncanonical")
                .classification,
            D1DmlIdentityClaimantClassification::RestoredClaimantNonCanonical
        );
    }

    #[test]
    fn either_plan_order_conflicts_while_exact_plan_converges() {
        let (target, first) = fixture();
        let identities = D1DmlAttemptIdentities {
            operation_id: "operation-fixture-0001",
            execution_attempt_id: "attempt-fixture-0001",
            provider_request_id: "provider-fixture-0001",
        };
        let second = derive_d1_dml_identity_claimant_set(&target, &"b".repeat(64), identities)
            .expect("second set");
        for namespace in D1DmlIdentityNamespace::ALL {
            assert!(
                second
                    .restore_exact(namespace, first.pending(namespace).state_bytes())
                    .is_err()
            );
            assert!(
                first
                    .restore_exact(namespace, second.pending(namespace).state_bytes())
                    .is_err()
            );
            assert!(
                first
                    .restore_exact(namespace, first.pending(namespace).state_bytes())
                    .is_ok()
            );
        }
    }

    #[test]
    fn only_exact_pending_to_bound_transition_is_valid() {
        let (_, set) = fixture();
        let namespace = D1DmlIdentityNamespace::ProviderRequest;
        let pending = set.pending(namespace);
        let first = set.bound(namespace, &"b".repeat(64)).expect("first bound");
        let second = set.bound(namespace, &"c".repeat(64)).expect("second bound");
        assert!(
            validate_d1_dml_identity_claimant_seal(pending.state_bytes(), first.state_bytes())
                .is_ok()
        );
        assert!(
            validate_d1_dml_identity_claimant_seal(first.state_bytes(), second.state_bytes())
                .is_err(),
            "a Bound claimant must never be rebound"
        );
        assert!(
            validate_d1_dml_identity_claimant_seal(
                pending.state_bytes(),
                set.bound(D1DmlIdentityNamespace::Operation, &"b".repeat(64))
                    .expect("different namespace bound")
                    .state_bytes()
            )
            .is_err()
        );
    }
}
