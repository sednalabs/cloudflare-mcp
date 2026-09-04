//! Immutable, externally-authorized target genesis for D1 row-write custody.
//!
//! This pure boundary derives a canonical marker from an exact D1 target,
//! opaque custody generation, and an external authority pin. It does not
//! create files, read environment configuration, call providers, or authorize
//! a write. A later offline/provisioning boundary may install the returned
//! bytes, while online custody only opens and verifies them.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::d1_opaque_identity::valid_d1_opaque_identity;
use crate::d1_target::{D1TargetIdentity, normalize_d1_target};
use crate::tools::sha256_bytes_hex;

pub(crate) const D1_DML_CUSTODY_GENESIS_VERSION: u8 = 1;
pub(crate) const D1_DML_CUSTODY_GENESIS_CONTRACT: &str = "d1-row-write-custody-genesis-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum D1DmlCustodyGenesisError {
    TargetNotCanonical,
    GenerationNotCanonical,
    AuthorityPinNotCanonical,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GenesisMarker {
    version: u8,
    contract: String,
    target_key_sha256: String,
    custody_generation_sha256: String,
    authority_sha256: String,
}

/// Aggregate-safe projection of exact genesis bytes. Fields are private so a
/// caller cannot construct authority by deserializing an untrusted summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1DmlCustodyGenesisAuthority {
    target_key_sha256: String,
    custody_generation_sha256: String,
    authority_sha256: String,
    genesis_sha256: String,
}

impl D1DmlCustodyGenesisAuthority {
    pub(crate) fn target_key_sha256(&self) -> &str {
        &self.target_key_sha256
    }

    pub(crate) fn custody_generation_sha256(&self) -> &str {
        &self.custody_generation_sha256
    }

    pub(crate) fn authority_sha256(&self) -> &str {
        &self.authority_sha256
    }

    pub(crate) fn genesis_sha256(&self) -> &str {
        &self.genesis_sha256
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn canonical_marker_bytes(marker: &GenesisMarker) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(marker).expect("genesis marker serialization is infallible");
    bytes.push(b'\n');
    bytes
}

/// Derive a canonical target-bound genesis marker and its aggregate authority.
pub(crate) fn derive_d1_dml_custody_genesis(
    target: &D1TargetIdentity,
    custody_generation: &str,
    authority_sha256: &str,
) -> Result<(D1DmlCustodyGenesisAuthority, Vec<u8>), D1DmlCustodyGenesisError> {
    let normalized = normalize_d1_target(&target.account_id, &target.database_id)
        .map_err(|_| D1DmlCustodyGenesisError::TargetNotCanonical)?;
    if normalized != *target {
        return Err(D1DmlCustodyGenesisError::TargetNotCanonical);
    }
    if !valid_d1_opaque_identity(custody_generation) {
        return Err(D1DmlCustodyGenesisError::GenerationNotCanonical);
    }
    if !valid_sha256(authority_sha256) {
        return Err(D1DmlCustodyGenesisError::AuthorityPinNotCanonical);
    }
    let marker = GenesisMarker {
        version: D1_DML_CUSTODY_GENESIS_VERSION,
        contract: D1_DML_CUSTODY_GENESIS_CONTRACT.to_string(),
        target_key_sha256: target.target_key_sha256(),
        custody_generation_sha256: sha256_bytes_hex(custody_generation.as_bytes()),
        authority_sha256: authority_sha256.to_string(),
    };
    let bytes = canonical_marker_bytes(&marker);
    let authority = D1DmlCustodyGenesisAuthority {
        target_key_sha256: marker.target_key_sha256.clone(),
        custody_generation_sha256: marker.custody_generation_sha256.clone(),
        authority_sha256: marker.authority_sha256.clone(),
        genesis_sha256: sha256_hex(&bytes),
    };
    Ok((authority, bytes))
}

pub(crate) fn validate_d1_dml_custody_genesis(
    bytes: &[u8],
    expected: &D1DmlCustodyGenesisAuthority,
) -> bool {
    let Ok(marker) = serde_json::from_slice::<GenesisMarker>(bytes) else {
        return false;
    };
    marker.version == D1_DML_CUSTODY_GENESIS_VERSION
        && marker.contract == D1_DML_CUSTODY_GENESIS_CONTRACT
        && marker.target_key_sha256 == expected.target_key_sha256
        && marker.custody_generation_sha256 == expected.custody_generation_sha256
        && marker.authority_sha256 == expected.authority_sha256
        && canonical_marker_bytes(&marker) == bytes
        && sha256_hex(bytes) == expected.genesis_sha256
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::d1_target::normalize_d1_target;

    fn target() -> D1TargetIdentity {
        normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000")
            .expect("fixture target")
    }

    #[test]
    fn genesis_is_canonical_and_target_generation_bound() {
        let (authority, bytes) =
            derive_d1_dml_custody_genesis(&target(), "custody-generation-0001", &"a".repeat(64))
                .expect("canonical genesis");
        assert!(validate_d1_dml_custody_genesis(&bytes, &authority));
        assert!(!validate_d1_dml_custody_genesis(
            &bytes,
            &derive_d1_dml_custody_genesis(&target(), "custody-generation-0002", &"a".repeat(64))
                .expect("changed genesis")
                .0
        ));
    }

    #[test]
    fn genesis_rejects_forged_target_and_noncanonical_pins() {
        let forged = D1TargetIdentity {
            account_id: " acct-1".to_string(),
            database_id: "123e4567-e89b-42d3-a456-426614174000".to_string(),
        };
        assert_eq!(
            derive_d1_dml_custody_genesis(&forged, "custody-generation-0001", &"a".repeat(64)),
            Err(D1DmlCustodyGenesisError::TargetNotCanonical)
        );
        assert_eq!(
            derive_d1_dml_custody_genesis(&target(), "bad", &"a".repeat(64)),
            Err(D1DmlCustodyGenesisError::GenerationNotCanonical)
        );
        assert_eq!(
            derive_d1_dml_custody_genesis(&target(), "custody-generation-0001", &"A".repeat(64)),
            Err(D1DmlCustodyGenesisError::AuthorityPinNotCanonical)
        );
    }

    #[test]
    fn duplicate_or_noncanonical_genesis_bytes_fail_closed() {
        let (authority, bytes) =
            derive_d1_dml_custody_genesis(&target(), "custody-generation-0001", &"a".repeat(64))
                .expect("canonical genesis");
        let duplicate = br#"{"version":1,"contract":"d1-row-write-custody-genesis-v1","target_key_sha256":"x","target_key_sha256":"x","custody_generation_sha256":"x","authority_sha256":"x"}
"#;
        assert!(!validate_d1_dml_custody_genesis(duplicate, &authority));
        let mut changed = bytes.clone();
        changed.push(b' ');
        assert!(!validate_d1_dml_custody_genesis(&changed, &authority));
    }
}
