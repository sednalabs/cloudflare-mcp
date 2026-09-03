//! Immutable generation authority for the local D1 DML custody namespace.
//!
//! The genesis artifact lives in the target directory, outside the replaceable
//! `dml-custody-v1` tree.  Ordinary provider workflows may only open and prove
//! this product; the separately exposed no-provider provisioning boundary is
//! the only caller allowed to create it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::d1_dml_custody_layout::{D1_DML_CUSTODY_LAYOUT_SHA256, D1_DML_CUSTODY_LAYOUT_VERSION};
use crate::d1_opaque_identity::valid_d1_opaque_identity;

pub(crate) const D1_DML_CUSTODY_GENESIS_NAME: &str = "dml-custody-genesis-v1.json";
pub(crate) const D1_DML_CUSTODY_GENESIS_VERSION: u8 = 1;
pub(crate) const D1_DML_CUSTODY_GENERATION_ENV: &str = "CLOUDFLARE_MCP_D1_CUSTODY_GENERATION";
pub(crate) const D1_DML_CUSTODY_AUTHORITY_SHA256_ENV: &str =
    "CLOUDFLARE_MCP_D1_CUSTODY_AUTHORITY_SHA256";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct D1DmlCustodyGenesisMarker {
    version: u8,
    contract: String,
    target_key_sha256: String,
    layout_version: u8,
    layout_sha256: String,
    custody_generation_sha256: String,
    authority_sha256: String,
}

/// Aggregate-safe authority projected from exact canonical genesis bytes.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct D1DmlCustodyAuthority {
    pub(crate) version: u8,
    pub(crate) target_key_sha256: String,
    pub(crate) layout_version: u8,
    pub(crate) layout_sha256: String,
    pub(crate) custody_generation_sha256: String,
    pub(crate) authority_sha256: String,
    pub(crate) genesis_sha256: String,
}

pub(crate) fn configured_d1_dml_custody_authority_inputs() -> Result<(String, String), &'static str>
{
    let generation = std::env::var(D1_DML_CUSTODY_GENERATION_ENV)
        .ok()
        .filter(|value| valid_d1_opaque_identity(value))
        .ok_or("D1 custody generation is unconfigured or not one canonical opaque identity")?;
    let authority_sha256 = std::env::var(D1_DML_CUSTODY_AUTHORITY_SHA256_ENV)
        .ok()
        .filter(|value| valid_sha256(value))
        .ok_or("D1 custody authority pin is unconfigured or not canonical lowercase SHA-256")?;
    Ok((generation, authority_sha256))
}

pub(crate) fn derive_d1_dml_custody_authority(
    target_key_sha256: &str,
    custody_generation: &str,
    authority_sha256: &str,
) -> Result<(D1DmlCustodyAuthority, Vec<u8>), &'static str> {
    if !valid_sha256(target_key_sha256) {
        return Err("D1 custody target key was not canonical lowercase SHA-256");
    }
    if !valid_d1_opaque_identity(custody_generation) {
        return Err("D1 custody generation was not one canonical opaque identity");
    }
    if !valid_sha256(authority_sha256) {
        return Err("D1 custody authority pin was not canonical lowercase SHA-256");
    }
    let marker = D1DmlCustodyGenesisMarker {
        version: D1_DML_CUSTODY_GENESIS_VERSION,
        contract: "d1-dml-custody-genesis-v1".to_string(),
        target_key_sha256: target_key_sha256.to_string(),
        layout_version: D1_DML_CUSTODY_LAYOUT_VERSION,
        layout_sha256: D1_DML_CUSTODY_LAYOUT_SHA256.to_string(),
        custody_generation_sha256: sha256_hex(custody_generation.as_bytes()),
        authority_sha256: authority_sha256.to_string(),
    };
    let bytes = canonical_marker_bytes(&marker);
    let authority = D1DmlCustodyAuthority {
        version: marker.version,
        target_key_sha256: marker.target_key_sha256.clone(),
        layout_version: marker.layout_version,
        layout_sha256: marker.layout_sha256.clone(),
        custody_generation_sha256: marker.custody_generation_sha256.clone(),
        authority_sha256: marker.authority_sha256.clone(),
        genesis_sha256: sha256_hex(&bytes),
    };
    Ok((authority, bytes))
}

pub(crate) fn validate_d1_dml_custody_genesis(
    bytes: &[u8],
    expected: &D1DmlCustodyAuthority,
) -> bool {
    let Ok(marker) = serde_json::from_slice::<D1DmlCustodyGenesisMarker>(bytes) else {
        return false;
    };
    marker.version == D1_DML_CUSTODY_GENESIS_VERSION
        && marker.contract == "d1-dml-custody-genesis-v1"
        && marker.target_key_sha256 == expected.target_key_sha256
        && marker.layout_version == D1_DML_CUSTODY_LAYOUT_VERSION
        && marker.layout_sha256 == D1_DML_CUSTODY_LAYOUT_SHA256
        && marker.custody_generation_sha256 == expected.custody_generation_sha256
        && marker.authority_sha256 == expected.authority_sha256
        && canonical_marker_bytes(&marker) == bytes
        && sha256_hex(bytes) == expected.genesis_sha256
}

pub(crate) fn inspect_d1_dml_custody_genesis(
    bytes: &[u8],
) -> Result<D1DmlCustodyAuthority, &'static str> {
    let marker = serde_json::from_slice::<D1DmlCustodyGenesisMarker>(bytes)
        .map_err(|_| "D1 custody genesis was malformed or duplicate-keyed")?;
    if marker.version != D1_DML_CUSTODY_GENESIS_VERSION
        || marker.contract != "d1-dml-custody-genesis-v1"
        || !valid_sha256(&marker.target_key_sha256)
        || marker.layout_version != D1_DML_CUSTODY_LAYOUT_VERSION
        || marker.layout_sha256 != D1_DML_CUSTODY_LAYOUT_SHA256
        || !valid_sha256(&marker.custody_generation_sha256)
        || !valid_sha256(&marker.authority_sha256)
        || canonical_marker_bytes(&marker) != bytes
    {
        return Err("D1 custody genesis was non-canonical or contradictory");
    }
    Ok(D1DmlCustodyAuthority {
        version: marker.version,
        target_key_sha256: marker.target_key_sha256,
        layout_version: marker.layout_version,
        layout_sha256: marker.layout_sha256,
        custody_generation_sha256: marker.custody_generation_sha256,
        authority_sha256: marker.authority_sha256,
        genesis_sha256: sha256_hex(bytes),
    })
}

fn canonical_marker_bytes(marker: &D1DmlCustodyGenesisMarker) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(marker).expect("genesis marker serialization is infallible");
    bytes.push(b'\n');
    bytes
}

pub(crate) fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_canonical_and_binds_independent_authority() {
        let target = "a".repeat(64);
        let pin = "b".repeat(64);
        let (authority, bytes) =
            derive_d1_dml_custody_authority(&target, "custody-generation-0001", &pin)
                .expect("canonical genesis");
        assert!(validate_d1_dml_custody_genesis(&bytes, &authority));

        let (changed, _) =
            derive_d1_dml_custody_authority(&target, "custody-generation-0002", &pin)
                .expect("changed generation");
        assert!(!validate_d1_dml_custody_genesis(&bytes, &changed));
    }
}
