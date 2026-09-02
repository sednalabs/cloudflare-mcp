//! Fixed durable layout identity for D1 DML claimant and attempt custody.
//!
//! The Linux dirfd adapter owns placement, capacity, atomic installation, and
//! audits. Pure custody receipts bind this immutable identity so bytes restored
//! under another layout fail closed.

use serde::{Deserialize, Serialize};

pub(crate) const D1_DML_CUSTODY_LAYOUT_NAME: &str = "dml-custody-v1";
pub(crate) const D1_DML_CUSTODY_LAYOUT_MARKER_NAME: &str = "layout.json";
pub(crate) const D1_DML_CUSTODY_LAYOUT_VERSION: u8 = 1;
pub(crate) const D1_DML_CUSTODY_LAYOUT_SHA256: &str =
    "68da1f2248681d61a387f503b370a73ebc848b9c34bec6afd00b24a0bef36b48"; // DevSkim: ignore DS173237 -- public layout specification digest, not a credential
pub(crate) const D1_DML_CUSTODY_LEAF_ENTRY_LIMIT: usize = 4_096;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct D1DmlCustodyLayoutMarker {
    pub(crate) version: u8,
    pub(crate) layout: String,
    pub(crate) layout_sha256: String,
    pub(crate) target_key_sha256: String,
}

pub(crate) fn canonical_layout_marker_bytes(target_key_sha256: &str) -> Vec<u8> {
    let marker = D1DmlCustodyLayoutMarker {
        version: D1_DML_CUSTODY_LAYOUT_VERSION,
        layout: D1_DML_CUSTODY_LAYOUT_NAME.to_string(),
        layout_sha256: D1_DML_CUSTODY_LAYOUT_SHA256.to_string(),
        target_key_sha256: target_key_sha256.to_string(),
    };
    let mut bytes = serde_json::to_vec(&marker).expect("layout marker serialization is infallible");
    bytes.push(b'\n');
    bytes
}

pub(crate) fn validate_layout_marker(bytes: &[u8], target_key_sha256: &str) -> bool {
    let Ok(marker) = serde_json::from_slice::<D1DmlCustodyLayoutMarker>(bytes) else {
        return false;
    };
    marker.version == D1_DML_CUSTODY_LAYOUT_VERSION
        && marker.layout == D1_DML_CUSTODY_LAYOUT_NAME
        && marker.layout_sha256 == D1_DML_CUSTODY_LAYOUT_SHA256
        && marker.target_key_sha256 == target_key_sha256
        && canonical_layout_marker_bytes(target_key_sha256) == bytes
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[allow(dead_code)] // separately owned restore/activation audit; hot DML path audits affected leaves
pub(crate) struct D1DmlCustodyCompleteAuditReceipt {
    pub(crate) version: u8,
    pub(crate) layout_sha256: String,
    pub(crate) target_key_sha256: String,
    pub(crate) claimant_count: usize,
    pub(crate) attempt_count: usize,
    pub(crate) pending_claimant_count: usize,
    pub(crate) bound_claimant_count: usize,
    pub(crate) cas_scratch_count: usize,
    pub(crate) claimant_set_count: usize,
    pub(crate) complete_claimant_set_count: usize,
    pub(crate) matched_claimant_set_count: usize,
    pub(crate) unmatched_claimant_set_count: usize,
    pub(crate) unmatched_attempt_count: usize,
    pub(crate) orphan_claimant_set_count: usize,
    pub(crate) incomplete_claimant_set_count: usize,
    pub(crate) reconciliation_required: bool,
    pub(crate) provider_dispatch_authority: D1DmlCustodyAuditProviderAuthority,
    pub(crate) audit_sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlCustodyAuditProviderAuthority {
    None,
}
