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
pub(crate) const D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_VERSION: u8 = 1;
pub(crate) const D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_SHA256: &str =
    "97e3ea422008c9a0e6cbf3749e11d2b2bdbdedc49c29291fe62ea314453dcc49"; // DevSkim: ignore DS173237 -- public DML audit-budget specification digest, not a credential
pub(crate) const D1_DML_CUSTODY_COMPLETE_AUDIT_LEAF_LIMIT: usize = 16_384;
pub(crate) const D1_DML_CUSTODY_COMPLETE_AUDIT_ARTIFACT_LIMIT: usize = 65_536;
pub(crate) const D1_DML_CUSTODY_COMPLETE_AUDIT_PAYLOAD_BYTE_LIMIT: usize = 256 * 1024 * 1024;

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
pub(crate) struct D1DmlCustodyCompleteAuditReceipt {
    pub(crate) version: u8,
    pub(crate) layout_sha256: String,
    pub(crate) audit_budget_version: u8,
    pub(crate) audit_budget_sha256: String,
    pub(crate) audited_leaf_limit: usize,
    pub(crate) physical_artifact_limit: usize,
    pub(crate) artifact_payload_byte_limit: usize,
    pub(crate) audited_leaf_count: usize,
    pub(crate) physical_artifact_count: usize,
    pub(crate) artifact_payload_bytes: usize,
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

/// Exact clean complete-audit identity carried across target-wide authority
/// boundaries. The complete receipt remains aggregate diagnostic evidence;
/// only this closed projection may authorize a later local or provider step.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct D1DmlCustodyCompleteAuditAuthorization {
    pub(crate) version: u8,
    pub(crate) target_key_sha256: String,
    pub(crate) layout_sha256: String,
    pub(crate) audit_budget_version: u8,
    pub(crate) audit_budget_sha256: String,
    pub(crate) audit_sha256: String,
}

impl D1DmlCustodyCompleteAuditReceipt {
    pub(crate) fn authorize_target_wide_custody(
        &self,
        expected_target_key_sha256: &str,
    ) -> Result<D1DmlCustodyCompleteAuditAuthorization, &'static str> {
        let counts_are_clean = self.pending_claimant_count == 0
            && self.cas_scratch_count == 0
            && self.claimant_count == self.bound_claimant_count
            && self.claimant_count
                == self
                    .claimant_set_count
                    .checked_mul(3)
                    .ok_or("DML complete-audit claimant count overflowed")?
            && self.claimant_set_count == self.complete_claimant_set_count
            && self.claimant_set_count == self.matched_claimant_set_count
            && self.attempt_count == self.matched_claimant_set_count
            && self.unmatched_claimant_set_count == 0
            && self.unmatched_attempt_count == 0
            && self.orphan_claimant_set_count == 0
            && self.incomplete_claimant_set_count == 0;
        let fixed_identity_is_exact = self.version == D1_DML_CUSTODY_LAYOUT_VERSION
            && self.target_key_sha256 == expected_target_key_sha256
            && self.layout_sha256 == D1_DML_CUSTODY_LAYOUT_SHA256
            && self.audit_budget_version == D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_VERSION
            && self.audit_budget_sha256 == D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_SHA256
            && self.audited_leaf_limit == D1_DML_CUSTODY_COMPLETE_AUDIT_LEAF_LIMIT
            && self.physical_artifact_limit == D1_DML_CUSTODY_COMPLETE_AUDIT_ARTIFACT_LIMIT
            && self.artifact_payload_byte_limit == D1_DML_CUSTODY_COMPLETE_AUDIT_PAYLOAD_BYTE_LIMIT
            && self.audited_leaf_count <= self.audited_leaf_limit
            && self.physical_artifact_count <= self.physical_artifact_limit
            && self.artifact_payload_bytes <= self.artifact_payload_byte_limit
            && self.audit_sha256.len() == 64
            && self
                .audit_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
        if self.reconciliation_required
            || self.provider_dispatch_authority != D1DmlCustodyAuditProviderAuthority::None
            || !fixed_identity_is_exact
            || !counts_are_clean
        {
            return Err("DML complete custody is not clean target-wide authority");
        }
        Ok(D1DmlCustodyCompleteAuditAuthorization {
            version: self.version,
            target_key_sha256: self.target_key_sha256.clone(),
            layout_sha256: self.layout_sha256.clone(),
            audit_budget_version: self.audit_budget_version,
            audit_budget_sha256: self.audit_budget_sha256.clone(),
            audit_sha256: self.audit_sha256.clone(),
        })
    }
}
