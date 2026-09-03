//! Durable, cross-process custody for exact-byte D1 migration applies.
//!
//! A target directory and its guard are permanent. `active.lease.json` is
//! evidence, not garbage: later processes stop for reconciliation when it is
//! present. This module deliberately owns no MCP registration or provider I/O.

#[cfg(test)]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::{Mutex, OnceLock, mpsc};

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Write;

use mcp_toolkit_core::response_contract::MutationApplyStatus;
use rmcp::model::CallToolResult;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::d1_migration_terminal_semantics::valid_receipt_outcome_prefixes;
use crate::d1_target::{D1TargetIdentity, normalize_d1_target};
use crate::tools::{invalid_argument_result, sha256_bytes_hex};
use crate::verification::now_unix_ms;

pub(crate) const D1_MANIFEST_LEASE_ROOT_ENV: &str = "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT";
#[cfg(test)]
pub(crate) const TEST_D1_DML_CUSTODY_GENERATION: &str = "test-custody-generation-v1";
#[cfg(test)]
pub(crate) const TEST_D1_DML_CUSTODY_AUTHORITY_SHA256: &str =
    "73cc578c679ad9a10bba8ca71ef85a1efc39e8edfb46a38516fb61ab08c98548"; // DevSkim: ignore DS173237 -- synthetic test authority digest, not a credential
pub(crate) const D1_BOOTSTRAP_INITIALIZER_DISPATCH_PROTOCOL: &str =
    "bootstrap-initializer-attempt-marker-v1";
static D1_MANIFEST_LEASE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

// Kept test-only so production retirement has no injectable branch. Faults
// are keyed by the exact lease nonce so a parallel retirement cannot consume
// another test's single-use failure.
#[cfg(test)]
static TERMINAL_TEST_HOOK_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
struct TerminalRetirementTestFailure {
    registration_id: u64,
    local_namespace_mutations: usize,
}

#[cfg(test)]
static TERMINAL_RETIRE_TEST_FAILURES: OnceLock<
    Mutex<HashMap<String, TerminalRetirementTestFailure>>,
> = OnceLock::new();

#[cfg(test)]
struct TerminalReceiptPreCreatePauseHook {
    registration_id: u64,
    entered: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
}

#[cfg(test)]
static TERMINAL_RECEIPT_PRE_CREATE_PAUSE_HOOK: OnceLock<
    Mutex<HashMap<String, TerminalReceiptPreCreatePauseHook>>,
> = OnceLock::new();

#[cfg(test)]
struct TerminalReceiptReadbackPauseHook {
    registration_id: u64,
    entered: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
}

#[cfg(test)]
static TERMINAL_RECEIPT_READBACK_PAUSE_HOOK: OnceLock<
    Mutex<HashMap<String, TerminalReceiptReadbackPauseHook>>,
> = OnceLock::new();

#[cfg(test)]
struct TerminalLeaseNamespaceReadbackPauseHook {
    registration_id: u64,
    entered: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
}

#[cfg(test)]
static TERMINAL_LEASE_NAMESPACE_READBACK_PAUSE_HOOK: OnceLock<
    Mutex<HashMap<String, TerminalLeaseNamespaceReadbackPauseHook>>,
> = OnceLock::new();

#[cfg(test)]
#[derive(Clone, Copy)]
enum TerminalTestHookRegistry {
    ReceiptPreCreate,
    ReceiptReadback,
    LeaseNamespaceReadback,
    RetirementFailure,
}

#[cfg(test)]
struct TerminalTestHookGuard {
    registry: TerminalTestHookRegistry,
    lease_nonce: String,
    registration_id: u64,
}

#[cfg(target_os = "linux")]
const ACTIVE_LEASE_NAME: &str = "active.lease.json";
#[cfg(target_os = "linux")]
const RETIRING_LEASE_NAME: &str = "retiring.lease.json";
#[cfg(target_os = "linux")]
const GUARD_NAME: &str = "guard.lock";
const TARGET_IDENTITY_ACTIVATION_GUARD_NAME: &str = "target-identity-v2.guard.lock";
const TARGET_IDENTITY_ACTIVATION_MARKER_NAME: &str = "target-identity-v2.activation.json";
const TARGET_IDENTITY_ACTIVATION_MARKER_BYTES: &[u8] = br#"{"root_audit":"registered_namespaces_v2","target_identity_contract":"lowercase_hyphenated_uuid_v1","version":2}"#;
const TARGET_IDENTITY_REGISTRATION_PREFIX: &str = "target-identity-v2.";
const TARGET_IDENTITY_REGISTRATION_SUFFIX: &str = ".receipt.json";
const TARGET_IDENTITY_ROOT_ENTRY_LIMIT: usize = 4096;
#[cfg(target_os = "linux")]
const BOOTSTRAP_INITIALIZER_ATTEMPT_PREFIX: &str = "bootstrap-initializer-attempt.";

#[derive(Debug)]
pub(crate) struct D1MigrationLease {
    #[cfg(target_os = "linux")]
    root_path: PathBuf,
    #[cfg(target_os = "linux")]
    root: fs::File,
    #[cfg(target_os = "linux")]
    root_identity: D1LeaseFileIdentity,
    #[cfg(target_os = "linux")]
    target_name: String,
    #[cfg(target_os = "linux")]
    target: fs::File,
    #[cfg(target_os = "linux")]
    target_identity: D1LeaseFileIdentity,
    #[cfg(target_os = "linux")]
    guard: Option<fs::File>,
    #[cfg(target_os = "linux")]
    guard_identity: D1LeaseFileIdentity,
    #[cfg(target_os = "linux")]
    active: fs::File,
    #[cfg(target_os = "linux")]
    active_file_identity: D1LeaseFileIdentity,
    #[cfg(target_os = "linux")]
    released: bool,
    dml_custody_authorization: crate::d1_dml_custody_layout::D1DmlCustodyCompleteAuditAuthorization,
    bootstrap_initializer_dispatch_protocol: bool,
    pub(crate) identity: D1MigrationLeaseIdentity,
}

/// Process-local handle for the permanent account/database guard shared by
/// every existing-target D1 provider mutation. Unlike a migration lease this
/// handle creates no operation-specific retained evidence; its only contract
/// is atomic exclusion while the provider boundary is in flight.
#[derive(Debug)]
pub(crate) struct D1TargetMutationGuard {
    operation: &'static str,
    canonical_target: D1TargetIdentity,
    #[cfg(target_os = "linux")]
    root_path: PathBuf,
    #[cfg(target_os = "linux")]
    root: fs::File,
    #[cfg(target_os = "linux")]
    root_identity: D1LeaseFileIdentity,
    #[cfg(target_os = "linux")]
    target_name: String,
    #[cfg(target_os = "linux")]
    target: fs::File,
    #[cfg(target_os = "linux")]
    target_identity: D1LeaseFileIdentity,
    #[cfg(target_os = "linux")]
    guard: fs::File,
    #[cfg(target_os = "linux")]
    guard_identity: D1LeaseFileIdentity,
    pub(crate) target_key_sha256: String,
    dml_custody_authority: crate::d1_dml_custody_genesis::D1DmlCustodyAuthority,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1DmlCustodyProvisionReceipt {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) apply_status: MutationApplyStatus,
    pub(crate) target_key_sha256: String,
    pub(crate) layout_version: u8,
    pub(crate) layout_sha256: String,
    pub(crate) custody_generation_sha256: String,
    pub(crate) authority_sha256: String,
    pub(crate) genesis_sha256: String,
    pub(crate) provider_calls: u8,
    pub(crate) provider_mutations: u8,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct D1MigrationLeaseIdentity {
    pub(crate) target_key_sha256: String,
    pub(crate) nonce: String,
    pub(crate) payload_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct D1RetainedMigrationLeaseIdentity {
    pub(crate) target_key_sha256: String,
    pub(crate) namespace: String,
    pub(crate) nonce: String,
    pub(crate) payload_sha256: String,
    pub(crate) approved_plan_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct D1RetainedMigrationLeasePayload {
    approved_plan_sha256: String,
    created_at_unix_ms: u64,
    dml_custody_authorization: crate::d1_dml_custody_layout::D1DmlCustodyCompleteAuditAuthorization,
    migration_family: String,
    nonce: String,
    target_key_sha256: String,
    version: u8,
    #[serde(default)]
    initializer_dispatch_protocol: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct D1TerminalReconciliationReceipt {
    pub(crate) version: u8,
    pub(crate) operation: String,
    pub(crate) target_key_sha256: String,
    pub(crate) lease_nonce: String,
    pub(crate) lease_payload_sha256: String,
    pub(crate) approved_apply_plan_sha256: String,
    pub(crate) effect_assertion_id: String,
    pub(crate) reconciliation_plan_sha256: String,
    pub(crate) expectation_proof_sha256: String,
    pub(crate) query_sha256: String,
    pub(crate) canonical_snapshot_sha256: String,
    pub(crate) terminal_request_sha256: String,
    pub(crate) terminal_attempt_sha256: String,
    pub(crate) terminal_plan_sha256: String,
    pub(crate) outcome: String,
    pub(crate) original_prefix_length: usize,
    pub(crate) current_prefix_length: usize,
}

fn valid_terminal_receipt_authority(receipt: &D1TerminalReconciliationReceipt) -> bool {
    match receipt.operation.as_str() {
        "d1_finalize_migration_reconciliation" => matches!(
            receipt.effect_assertion_id.as_str(),
            "schema_create_only_v1"
                | "schema_create_tables_indexes_views_triggers_v1"
                | "schema_create_objects_additive_v1"
                | "schema_create_objects_additive_seed_rows_v1"
                | "schema_create_objects_additive_seed_rows_v2"
        ),
        "d1_finalize_bootstrap_migration_ledger" => {
            receipt.effect_assertion_id == "bootstrap_canonical_empty_ledger_v1"
                && receipt.outcome == "full_state_converged"
                && receipt.original_prefix_length == 0
                && receipt.current_prefix_length == 1
        }
        "d1_abort_bootstrap_migration_ledger" => {
            receipt.effect_assertion_id == "bootstrap_initializer_not_dispatched_v1"
                && receipt.outcome == "not_committed"
                && receipt.original_prefix_length == 0
                && receipt.current_prefix_length == 0
        }
        _ => false,
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct D1TerminalReconciliationReceiptV1 {
    pub(crate) version: u8,
    pub(crate) operation: String,
    pub(crate) target_key_sha256: String,
    pub(crate) lease_nonce: String,
    pub(crate) lease_payload_sha256: String,
    pub(crate) approved_apply_plan_sha256: String,
    pub(crate) reconciliation_plan_sha256: String,
    pub(crate) expectation_proof_sha256: String,
    pub(crate) query_sha256: String,
    pub(crate) canonical_snapshot_sha256: String,
    pub(crate) terminal_request_sha256: String,
    pub(crate) terminal_attempt_sha256: String,
    pub(crate) terminal_plan_sha256: String,
    pub(crate) outcome: String,
    pub(crate) original_prefix_length: usize,
    pub(crate) current_prefix_length: usize,
}

#[derive(Debug)]
pub(crate) struct D1TerminalReconciliationReceiptEvidence {
    #[cfg(target_os = "linux")]
    file: fs::File,
    #[cfg(target_os = "linux")]
    file_identity: D1LeaseFileIdentity,
    #[cfg(target_os = "linux")]
    name: String,
    pub(crate) payload_sha256: String,
    pub(crate) receipt_version: u8,
    pub(crate) effect_assertion_id: String,
    target_key_sha256: String,
    lease_nonce: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum D1TerminalCustodyNamespace {
    Active,
    Retiring,
    Retired,
    Unverified,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct D1TerminalEvidenceReadback {
    pub(crate) custody: D1TerminalCustodyNamespace,
    /// `None` means the descriptor-bound receipt readback was contradictory,
    /// malformed, or changed while being read and therefore proves neither
    /// presence nor absence.
    pub(crate) receipt_persisted: Option<bool>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct D1TerminalRetirement {
    pub(crate) local_namespace_mutations: usize,
}

#[derive(Debug)]
pub(crate) struct D1TerminalRetirementFailure {
    pub(crate) result: CallToolResult,
    pub(crate) local_namespace_mutations: usize,
}

#[derive(Debug)]
pub(crate) struct D1TerminalReceiptPersistenceFailure {
    pub(crate) result: CallToolResult,
    pub(crate) local_namespace_mutations: usize,
}

/// A guard-held, descriptor-bound view of retained migration evidence.
/// Dropping this value releases only the advisory guard. It never renames,
/// unlinks, rewrites, or otherwise mutates the retained namespace.
#[derive(Debug)]
pub(crate) struct D1RetainedMigrationLease {
    #[cfg(target_os = "linux")]
    root_path: PathBuf,
    #[cfg(target_os = "linux")]
    root: fs::File,
    #[cfg(target_os = "linux")]
    root_identity: D1LeaseFileIdentity,
    #[cfg(target_os = "linux")]
    target_name: String,
    #[cfg(target_os = "linux")]
    target: fs::File,
    #[cfg(target_os = "linux")]
    target_identity: D1LeaseFileIdentity,
    #[cfg(target_os = "linux")]
    guard: fs::File,
    #[cfg(target_os = "linux")]
    guard_identity: D1LeaseFileIdentity,
    #[cfg(target_os = "linux")]
    evidence: fs::File,
    #[cfg(target_os = "linux")]
    evidence_file_identity: D1LeaseFileIdentity,
    #[cfg(target_os = "linux")]
    evidence_name: String,
    dml_custody_authorization: crate::d1_dml_custody_layout::D1DmlCustodyCompleteAuditAuthorization,
    bootstrap_initializer_dispatch_protocol: bool,
    pub(crate) identity: D1RetainedMigrationLeaseIdentity,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct D1BootstrapInitializerAttemptReceipt {
    version: u8,
    operation: String,
    target_key_sha256: String,
    lease_nonce: String,
    lease_payload_sha256: String,
    approved_bootstrap_plan_sha256: String,
    migration_family: String,
    dispatch_protocol: String,
    state: String,
}

#[cfg(target_os = "linux")]
type D1LeaseFileIdentity = crate::private_file_custody::UnixFileIdentity;

impl D1MigrationLease {
    /// Record normal terminal completion without unlinking the active evidence.
    pub(crate) fn release(&mut self) -> Result<(), CallToolResult> {
        #[cfg(target_os = "linux")]
        {
            self.release_linux()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(d1_lease_platform_unsupported())
        }
    }

    /// Preserve active evidence on every uncertain outcome.
    pub(crate) fn retain(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.guard.take();
        }
    }

    /// Durably record initializer-attempt authority before the bootstrap
    /// coordinator is permitted to cross the provider dispatch boundary.
    pub(crate) fn record_bootstrap_initializer_attempt(&self) -> Result<(), CallToolResult> {
        #[cfg(target_os = "linux")]
        {
            self.revalidate()?;
            if !self.bootstrap_initializer_dispatch_protocol {
                return Err(self.revalidation_failure(
                    "bootstrap lease does not carry the initializer dispatch-marker protocol",
                ));
            }
            let receipt = D1BootstrapInitializerAttemptReceipt {
                version: 1,
                operation: "d1_bootstrap_migration_ledger".to_string(),
                target_key_sha256: self.identity.target_key_sha256.clone(),
                lease_nonce: self.identity.nonce.clone(),
                lease_payload_sha256: self.identity.payload_sha256.clone(),
                approved_bootstrap_plan_sha256: linux::approved_plan_from_owned_lease(&self.active)
                    .map_err(|message| self.revalidation_failure(message))?,
                migration_family: "migration-ledger-bootstrap-v1".to_string(),
                dispatch_protocol: D1_BOOTSTRAP_INITIALIZER_DISPATCH_PROTOCOL.to_string(),
                state: "attempt_authorized".to_string(),
            };
            linux::persist_bootstrap_initializer_attempt(&self.target, &receipt)
                .map_err(|message| self.revalidation_failure(message))?;
            self.revalidate()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(d1_lease_platform_unsupported())
        }
    }

    /// Re-check the held custody chain immediately before a provider boundary.
    pub(crate) fn revalidate(&self) -> Result<(), CallToolResult> {
        #[cfg(target_os = "linux")]
        {
            let guard = self.guard.as_ref().ok_or_else(|| {
                self.revalidation_failure(
                    "this invocation no longer holds the permanent target guard",
                )
            })?;
            validate_d1_lease_custody(
                &self.root_path,
                &self.root,
                &self.root_identity,
                &self.target_name,
                &self.target,
                &self.target_identity,
                guard,
                &self.guard_identity,
            )
            .map_err(|message| self.revalidation_failure(message))?;
            validate_owned_named_lease(
                &self.target,
                ACTIVE_LEASE_NAME,
                &self.active,
                &self.active_file_identity,
                &self.identity,
                true,
            )
            .map_err(|message| self.revalidation_failure(message))?;
            self.revalidate_dml_custody_authorization()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(d1_lease_platform_unsupported())
        }
    }

    #[cfg(test)]
    pub(crate) fn active_path_for_test(&self) -> Option<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            Some(
                self.root_path
                    .join(&self.target_name)
                    .join(ACTIVE_LEASE_NAME),
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn release_linux(&mut self) -> Result<(), CallToolResult> {
        if self.released {
            return Ok(());
        }
        let guard = self.guard.as_ref().ok_or_else(|| {
            self.release_failure("this invocation no longer holds the permanent target guard")
        })?;
        validate_d1_lease_custody(
            &self.root_path,
            &self.root,
            &self.root_identity,
            &self.target_name,
            &self.target,
            &self.target_identity,
            guard,
            &self.guard_identity,
        )
        .map_err(|message| self.release_failure(message))?;
        validate_owned_named_lease(
            &self.target,
            ACTIVE_LEASE_NAME,
            &self.active,
            &self.active_file_identity,
            &self.identity,
            true,
        )
        .map_err(|message| self.release_failure(message))?;
        self.revalidate_dml_custody_authorization().map_err(|_| {
            self.release_failure("complete DML custody changed before lease retirement")
        })?;

        rename_owned_lease_no_replace(
            &self.target,
            ACTIVE_LEASE_NAME,
            RETIRING_LEASE_NAME,
            &self.active,
            &self.active_file_identity,
            &self.identity,
        )
        .map_err(|_| {
            self.release_failure(
                "active lease could not enter the retiring namespace without replacement",
            )
        })?;
        if sync_d1_lease_directory(&self.target).is_err() {
            if self.revalidate_dml_custody_authorization().is_err() {
                return Err(self.release_failure(
                    "complete DML custody changed before active-lease restoration",
                ));
            }
            let restored = restore_active_or_leave_blocker(
                &self.target,
                RETIRING_LEASE_NAME,
                &self.active,
                &self.active_file_identity,
                &self.identity,
            );
            return Err(self.release_failure(if restored {
                "retiring lease directory could not be synchronized; exact active evidence was restored"
            } else {
                "retiring lease directory could not be synchronized; active or retiring evidence remains an explicit reconciliation blocker"
            }));
        }

        let retired_name = format!("retired.{}.lease.json", self.identity.nonce);
        self.revalidate_dml_custody_authorization().map_err(|_| {
            self.release_failure("complete DML custody changed before terminal retirement")
        })?;
        rename_owned_lease_no_replace(
            &self.target,
            RETIRING_LEASE_NAME,
            &retired_name,
            &self.active,
            &self.active_file_identity,
            &self.identity,
        )
        .map_err(|_| {
            self.release_failure(
                "retiring lease could not be recorded as terminal retirement without replacement",
            )
        })?;
        if sync_d1_lease_directory(&self.target).is_err() {
            if self.revalidate_dml_custody_authorization().is_err() {
                return Err(self.release_failure(
                    "complete DML custody changed before active-lease restoration",
                ));
            }
            let restored = restore_active_or_leave_blocker(
                &self.target,
                &retired_name,
                &self.active,
                &self.active_file_identity,
                &self.identity,
            );
            return Err(self.release_failure(if restored {
                "retired lease directory could not be synchronized; exact active evidence was restored"
            } else {
                "retired lease directory could not be synchronized; active or retiring evidence remains an explicit reconciliation blocker"
            }));
        }

        self.released = true;
        self.guard.take();
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn revalidate_dml_custody_authorization(&self) -> Result<(), CallToolResult> {
        let current = linux::authorize_target_wide_d1_dml_custody(
            &self.target,
            &self.dml_custody_authorization.custody_authority(),
        )
        .map_err(|message| self.revalidation_failure(message))?;
        if current != self.dml_custody_authorization {
            return Err(self.revalidation_failure(
                "complete DML custody changed after migration authority was bound",
            ));
        }
        Ok(())
    }

    fn release_failure(&self, message: &'static str) -> CallToolResult {
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest",
            "status": "reconciliation_required", "provider_calls": 0,
            "provider_mutations": 0, "lease_retained": true, "lease": self.identity,
            "error": {"code": "d1.migration_lease_release_failed", "message": message,
                "hint": "Inspect the permanent target custody directory and reconcile the named owner through the governed recovery path before another apply."}
        }))
    }

    fn revalidation_failure(&self, message: &'static str) -> CallToolResult {
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest",
            "status": "reconciliation_required", "provider_calls": 0,
            "provider_mutations": 0, "lease_retained": true, "lease": self.identity,
            "error": {"code": "d1.migration_lease_revalidation_failed", "message": message,
                "hint": "Do not issue provider SQL. Reconcile the permanent target custody evidence through the governed recovery path first."}
        }))
    }
}

impl D1TargetMutationGuard {
    pub(crate) fn dml_custody_authority(
        &self,
    ) -> &crate::d1_dml_custody_genesis::D1DmlCustodyAuthority {
        &self.dml_custody_authority
    }

    /// Prove that the caller's complete canonical account/database identity is
    /// exactly the target captured when this guard was acquired. This check is
    /// read-only and must precede every caller-selected custody namespace.
    pub(crate) fn assert_exact_target(
        &self,
        target: &D1TargetIdentity,
    ) -> Result<(), CallToolResult> {
        let canonical = normalize_d1_target(&target.account_id, &target.database_id).ok();
        if canonical.as_ref() != Some(target) || target != &self.canonical_target {
            return Err(d1_target_guard_target_mismatch_error(
                self.operation,
                &self.target_key_sha256,
                &target.target_key_sha256(),
            ));
        }
        Ok(())
    }

    /// Rebind the complete custody chain immediately before provider dispatch.
    pub(crate) fn revalidate(&self) -> Result<(), CallToolResult> {
        #[cfg(target_os = "linux")]
        {
            validate_d1_lease_custody(
                &self.root_path,
                &self.root,
                &self.root_identity,
                &self.target_name,
                &self.target,
                &self.target_identity,
                &self.guard,
                &self.guard_identity,
            )
            .map_err(|message| {
                d1_target_guard_error(
                    self.operation,
                    "d1.target_guard_custody_changed",
                    message,
                    &self.target_key_sha256,
                )
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(d1_target_guard_error(
                self.operation,
                "d1.target_guard_platform_unsupported",
                "permanent cross-process D1 mutation custody requires the Linux dirfd-bound guard implementation",
                &self.target_key_sha256,
            ))
        }
    }

    /// Open and prove the independently provisioned genesis and layout.
    /// Ordinary provider execution has no creation authority.
    pub(crate) fn open_existing_d1_dml_custody(&self) -> Result<(), CallToolResult> {
        self.revalidate()?;
        #[cfg(target_os = "linux")]
        {
            linux::open_existing_d1_dml_custody(&self.target, &self.dml_custody_authority)
                .map_err(|message| d1_dml_attempt_store_error(&self.target_key_sha256, message))?;
            self.revalidate()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "durable sharded DML custody requires Linux dirfd-bound storage",
            ))
        }
    }

    #[cfg(test)]
    pub(crate) fn ensure_d1_dml_custody_layout(&self) -> Result<(), CallToolResult> {
        self.revalidate()?;
        linux::ensure_d1_dml_custody_layout(&self.target, &self.dml_custody_authority)
            .map_err(|message| d1_dml_attempt_store_error(&self.target_key_sha256, message))?;
        self.revalidate()
    }

    /// Open the exact existing layout for a target-wide operation.
    /// Provisioning is a separate no-provider product.
    pub(crate) fn open_target_wide_d1_dml_custody_layout(
        &self,
    ) -> Result<crate::d1_dml_custody_layout::D1DmlCustodyLayoutEnsureOutcome, CallToolResult> {
        self.revalidate()?;
        #[cfg(target_os = "linux")]
        {
            linux::open_existing_d1_dml_custody(&self.target, &self.dml_custody_authority)
                .map_err(|message| {
                    d1_target_guard_error(
                        self.operation,
                        "d1.target_wide_dml_custody_layout_unavailable",
                        message,
                        &self.target_key_sha256,
                    )
                })?;
            self.revalidate()?;
            Ok(crate::d1_dml_custody_layout::D1DmlCustodyLayoutEnsureOutcome::AlreadyPresent)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(d1_target_guard_error(
                self.operation,
                "d1.target_guard_platform_unsupported",
                "target-wide DML custody layout requires Linux dirfd-bound storage",
                &self.target_key_sha256,
            ))
        }
    }

    #[cfg(test)]
    pub(crate) fn ensure_target_wide_d1_dml_custody_layout(
        &self,
    ) -> Result<crate::d1_dml_custody_layout::D1DmlCustodyLayoutEnsureOutcome, CallToolResult> {
        self.revalidate()?;
        let outcome =
            linux::ensure_d1_dml_custody_layout(&self.target, &self.dml_custody_authority)
                .map_err(|message| {
                    d1_target_guard_error(
                        self.operation,
                        "d1.target_wide_dml_custody_layout_unavailable",
                        message,
                        &self.target_key_sha256,
                    )
                })?;
        self.revalidate()?;
        Ok(outcome)
    }

    /// Separately owned target-wide audit for restore, activation, and other
    /// destructive-boundary workflows. The live path deliberately uses only
    /// affected-leaf audits.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn audit_d1_dml_custody_complete(
        &self,
    ) -> Result<crate::d1_dml_custody_layout::D1DmlCustodyCompleteAuditReceipt, CallToolResult>
    {
        self.revalidate()?;
        #[cfg(target_os = "linux")]
        {
            linux::audit_d1_dml_custody_complete(&self.target, &self.dml_custody_authority)
                .map_err(|message| d1_dml_attempt_store_error(&self.target_key_sha256, message))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "complete DML custody audit requires Linux dirfd-bound storage",
            ))
        }
    }

    /// Produce the only complete-audit projection accepted by a target-wide
    /// authority workflow. This does not authorize ordinary DML dispatch.
    #[allow(dead_code)]
    pub(crate) fn authorize_target_wide_d1_dml_custody(
        &self,
    ) -> Result<crate::d1_dml_custody_layout::D1DmlCustodyCompleteAuditAuthorization, CallToolResult>
    {
        self.revalidate()?;
        #[cfg(target_os = "linux")]
        {
            linux::authorize_target_wide_d1_dml_custody(&self.target, &self.dml_custody_authority)
                .map_err(|message| {
                    d1_target_wide_dml_custody_error(
                        self.operation,
                        message,
                        &self.target_key_sha256,
                    )
                })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(d1_target_guard_error(
                self.operation,
                "d1.target_guard_platform_unsupported",
                "complete DML custody authority requires Linux dirfd-bound storage",
                &self.target_key_sha256,
            ))
        }
    }

    /// Re-run the bounded complete audit at the last owned target-wide
    /// boundary and require the exact identity bound into the caller's plan.
    #[allow(dead_code)]
    pub(crate) fn revalidate_target_wide_d1_dml_custody(
        &self,
        expected: &crate::d1_dml_custody_layout::D1DmlCustodyCompleteAuditAuthorization,
    ) -> Result<(), CallToolResult> {
        let current = self.authorize_target_wide_d1_dml_custody()?;
        if current != *expected {
            return Err(d1_target_guard_error(
                self.operation,
                "d1.target_wide_dml_custody_changed",
                "complete DML custody changed after the target-wide plan was bound",
                &self.target_key_sha256,
            ));
        }
        self.revalidate()
    }

    /// Read one exact DML-attempt state through the held target directory.
    /// The opaque attempt binding is used only as a bounded filename digest.
    pub(crate) fn read_d1_dml_attempt_state(
        &self,
        attempt_binding_sha256: &str,
    ) -> Result<Option<Vec<u8>>, CallToolResult> {
        self.revalidate()?;
        #[cfg(target_os = "linux")]
        {
            linux::read_d1_dml_attempt_state(
                &self.target,
                attempt_binding_sha256,
                &self.target_key_sha256,
            )
            .map_err(|message| d1_dml_attempt_store_error(&self.target_key_sha256, message))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = attempt_binding_sha256;
            Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "durable DML attempt custody requires Linux dirfd-bound storage",
            ))
        }
    }

    /// Reserve the permanent entry and one CAS scratch slot before any other
    /// member of a new attempt claimant set is installed.
    pub(crate) fn preflight_d1_dml_attempt_capacity(
        &self,
        attempt_binding_sha256: &str,
    ) -> Result<(), CallToolResult> {
        self.revalidate()?;
        if attempt_binding_sha256.len() != 64
            || !attempt_binding_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "DML attempt capacity preflight received a non-canonical binding",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            linux::preflight_d1_dml_attempt_capacity(
                &self.target,
                attempt_binding_sha256,
                &self.target_key_sha256,
            )
            .map_err(|message| d1_dml_attempt_store_error(&self.target_key_sha256, message))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "durable DML attempt capacity proof requires Linux dirfd-bound storage",
            ))
        }
    }

    /// Install the first canonical Prepared state exactly once.
    pub(crate) fn create_d1_dml_attempt_state(
        &self,
        attempt_binding_sha256: &str,
        state: &[u8],
    ) -> Result<(), CallToolResult> {
        self.revalidate()?;
        self.validate_d1_dml_attempt_state(attempt_binding_sha256, state)?;
        #[cfg(target_os = "linux")]
        {
            linux::create_d1_dml_attempt_state(&self.target, attempt_binding_sha256, state)
                .map_err(|message| d1_dml_attempt_store_error(&self.target_key_sha256, message))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (attempt_binding_sha256, state);
            Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "durable DML attempt custody requires Linux dirfd-bound storage",
            ))
        }
    }

    /// Atomically replace exact incumbent bytes with one canonical successor.
    pub(crate) fn compare_exchange_d1_dml_attempt_state(
        &self,
        attempt_binding_sha256: &str,
        expected: &[u8],
        successor: &[u8],
    ) -> Result<(), CallToolResult> {
        self.revalidate()?;
        self.validate_d1_dml_attempt_state(attempt_binding_sha256, expected)?;
        self.validate_d1_dml_attempt_state(attempt_binding_sha256, successor)?;
        #[cfg(target_os = "linux")]
        {
            linux::compare_exchange_d1_dml_attempt_state(
                &self.target,
                attempt_binding_sha256,
                expected,
                successor,
            )
            .map_err(|message| d1_dml_attempt_store_error(&self.target_key_sha256, message))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (attempt_binding_sha256, expected, successor);
            Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "durable DML attempt custody requires Linux dirfd-bound storage",
            ))
        }
    }

    /// Read one create-once identity claimant through the held target directory.
    pub(crate) fn read_d1_dml_identity_claimant(
        &self,
        namespace: crate::d1_dml_identity_claimant::D1DmlIdentityNamespace,
        identity_sha256: &str,
    ) -> Result<Option<Vec<u8>>, CallToolResult> {
        self.revalidate()?;
        #[cfg(target_os = "linux")]
        {
            linux::read_d1_dml_identity_claimant(
                &self.target,
                namespace,
                identity_sha256,
                &self.target_key_sha256,
            )
            .map_err(|message| d1_dml_attempt_store_error(&self.target_key_sha256, message))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (namespace, identity_sha256);
            Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "durable DML identity claimants require Linux dirfd-bound storage",
            ))
        }
    }

    /// Reserve capacity for every missing member of one three-namespace
    /// claimant set before the first permanent claimant file is created.
    pub(crate) fn preflight_d1_dml_identity_claimant_set_capacity(
        &self,
        set: &crate::d1_dml_identity_claimant::D1DmlIdentityClaimantSet,
    ) -> Result<(), CallToolResult> {
        self.revalidate()?;
        let representative =
            set.pending(crate::d1_dml_identity_claimant::D1DmlIdentityNamespace::Operation);
        if representative.receipt().target_key_sha256 != self.target_key_sha256
            || representative.receipt().custody_generation_sha256
                != self.dml_custody_authority.custody_generation_sha256
        {
            return Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "DML claimant set contradicted target custody generation authority",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            linux::preflight_d1_dml_identity_claimant_set_capacity(
                &self.target,
                set,
                &self.target_key_sha256,
            )
            .map_err(|message| d1_dml_attempt_store_error(&self.target_key_sha256, message))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = set;
            Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "durable DML identity claimant capacity proof requires Linux dirfd-bound storage",
            ))
        }
    }

    /// Install one canonical Pending claimant exactly once.
    pub(crate) fn create_d1_dml_identity_claimant(
        &self,
        namespace: crate::d1_dml_identity_claimant::D1DmlIdentityNamespace,
        identity_sha256: &str,
        state: &[u8],
    ) -> Result<(), CallToolResult> {
        self.revalidate()?;
        self.validate_d1_dml_identity_claimant(namespace, identity_sha256, state)?;
        if crate::d1_dml_identity_claimant::inspect_d1_dml_identity_claimant(state)
            .map_err(|_| {
                d1_dml_attempt_store_error(
                    &self.target_key_sha256,
                    "DML identity claimant creation was not canonical",
                )
            })?
            .receipt()
            .phase
            != crate::d1_dml_identity_claimant::D1DmlIdentityClaimantPhase::Pending
        {
            return Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "DML identity claimant creation requires Pending state",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            linux::create_d1_dml_identity_claimant(&self.target, namespace, identity_sha256, state)
                .map_err(|message| d1_dml_attempt_store_error(&self.target_key_sha256, message))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (namespace, identity_sha256, state);
            Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "durable DML identity claimants require Linux dirfd-bound storage",
            ))
        }
    }

    /// Seal one exact Pending claimant to its full attempt binding.
    pub(crate) fn compare_exchange_d1_dml_identity_claimant(
        &self,
        namespace: crate::d1_dml_identity_claimant::D1DmlIdentityNamespace,
        identity_sha256: &str,
        expected: &[u8],
        successor: &[u8],
    ) -> Result<(), CallToolResult> {
        self.revalidate()?;
        self.validate_d1_dml_identity_claimant(namespace, identity_sha256, expected)?;
        self.validate_d1_dml_identity_claimant(namespace, identity_sha256, successor)?;
        crate::d1_dml_identity_claimant::validate_d1_dml_identity_claimant_seal(
            expected, successor,
        )
        .map_err(|_| {
            d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "DML identity claimant successor was not the exact Pending-to-Bound seal",
            )
        })?;
        #[cfg(target_os = "linux")]
        {
            linux::compare_exchange_d1_dml_identity_claimant(
                &self.target,
                namespace,
                identity_sha256,
                expected,
                successor,
            )
            .map_err(|message| d1_dml_attempt_store_error(&self.target_key_sha256, message))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (namespace, identity_sha256, expected, successor);
            Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "durable DML identity claimants require Linux dirfd-bound storage",
            ))
        }
    }

    fn validate_d1_dml_identity_claimant(
        &self,
        namespace: crate::d1_dml_identity_claimant::D1DmlIdentityNamespace,
        identity_sha256: &str,
        state: &[u8],
    ) -> Result<(), CallToolResult> {
        let product = crate::d1_dml_identity_claimant::inspect_d1_dml_identity_claimant(state)
            .map_err(|_| {
                d1_dml_attempt_store_error(
                    &self.target_key_sha256,
                    "DML identity claimant was malformed or contradicted the closed custody product",
                )
            })?;
        if product.receipt().target_key_sha256 != self.target_key_sha256
            || product.receipt().custody_generation_sha256
                != self.dml_custody_authority.custody_generation_sha256
            || product.receipt().namespace != namespace
            || product.receipt().identity_sha256 != identity_sha256
        {
            return Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "DML identity claimant contradicted its target or filename binding",
            ));
        }
        Ok(())
    }

    fn validate_d1_dml_attempt_state(
        &self,
        attempt_binding_sha256: &str,
        state: &[u8],
    ) -> Result<(), CallToolResult> {
        let receipt =
            crate::d1_attempt_artifact::inspect_d1_attempt_artifact(state).map_err(|_| {
                d1_dml_attempt_store_error(
                    &self.target_key_sha256,
                    "DML attempt state was malformed or contradicted the closed custody product",
                )
            })?;
        if receipt.target_key_sha256 != self.target_key_sha256
            || receipt.custody_generation_sha256
                != self.dml_custody_authority.custody_generation_sha256
            || receipt.attempt_binding_sha256 != attempt_binding_sha256
        {
            return Err(d1_dml_attempt_store_error(
                &self.target_key_sha256,
                "DML attempt state contradicted its target or filename binding",
            ));
        }
        Ok(())
    }
}

fn d1_dml_attempt_store_error(target_key_sha256: &str, message: &'static str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_execute_write",
        "status": "reconciliation_required",
        "provider_calls": 0,
        "provider_mutations": 0,
        "custody": {"target_key_sha256": target_key_sha256, "retained": true},
        "automatic_retry_permitted": false,
        "error": {
            "code": "d1.execute_write_custody_unproven",
            "message": message,
            "hint": "Do not issue or replay a provider write; inspect the durable target custody namespace."
        }
    }))
}

impl D1RetainedMigrationLease {
    /// Rebind every held descriptor and require the exact retained namespace
    /// and payload to remain unchanged before or after a provider read.
    pub(crate) fn revalidate(&self) -> Result<(), CallToolResult> {
        #[cfg(target_os = "linux")]
        {
            validate_d1_lease_custody(
                &self.root_path,
                &self.root,
                &self.root_identity,
                &self.target_name,
                &self.target,
                &self.target_identity,
                &self.guard,
                &self.guard_identity,
            )
            .map_err(d1_retained_lease_revalidation_error)?;
            let retired_name = format!("retired.{}.lease.json", self.identity.nonce);
            let active_present = retained_entry_present(&self.target, ACTIVE_LEASE_NAME)
                .map_err(d1_retained_lease_revalidation_error)?;
            let retiring_present = retained_entry_present(&self.target, RETIRING_LEASE_NAME)
                .map_err(d1_retained_lease_revalidation_error)?;
            let retired_present = retained_entry_present(&self.target, &retired_name)
                .map_err(d1_retained_lease_revalidation_error)?;
            let expected_namespace = match self.identity.namespace.as_str() {
                "active" => (true, false, false),
                "retiring" => (false, true, false),
                "retired" => (false, false, true),
                _ => {
                    return Err(d1_retained_lease_revalidation_error(
                        "retained lease namespace is not recognized",
                    ));
                }
            };
            if (active_present, retiring_present, retired_present) != expected_namespace {
                return Err(d1_retained_lease_revalidation_error(
                    "active, retiring, or exact terminal-retired migration evidence conflicts",
                ));
            }
            validate_retained_named_lease(
                &self.target,
                &self.evidence_name,
                &self.evidence,
                &self.evidence_file_identity,
                &self.identity,
            )
            .map_err(d1_retained_lease_revalidation_error)?;
            self.revalidate_dml_custody_authorization()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(d1_retained_lease_platform_unsupported())
        }
    }

    pub(crate) fn is_retired(&self) -> bool {
        self.identity.namespace == "retired"
    }

    #[cfg(target_os = "linux")]
    fn revalidate_dml_custody_authorization(&self) -> Result<(), CallToolResult> {
        let current = linux::authorize_target_wide_d1_dml_custody(
            &self.target,
            &self.dml_custody_authorization.custody_authority(),
        )
        .map_err(d1_retained_lease_revalidation_error)?;
        if current != self.dml_custody_authorization {
            return Err(d1_retained_lease_revalidation_error(
                "complete DML custody changed after retained migration authority was bound",
            ));
        }
        Ok(())
    }

    /// Prove that this lease was created under the marker-before-dispatch
    /// bootstrap protocol and that the exact initializer-attempt marker is
    /// stably absent. Legacy custody can never satisfy this proof.
    pub(crate) fn prove_bootstrap_initializer_not_dispatched(&self) -> Result<(), CallToolResult> {
        #[cfg(target_os = "linux")]
        {
            self.revalidate()?;
            if !self.bootstrap_initializer_dispatch_protocol {
                return Err(d1_retained_lease_error(
                    "d1.bootstrap_abort_dispatch_protocol_absent",
                    "retained bootstrap custody predates or contradicts the marker-before-dispatch protocol",
                ));
            }
            linux::prove_bootstrap_initializer_attempt_absent(&self.target, &self.identity)
                .map_err(|message| {
                    d1_retained_lease_error("d1.bootstrap_abort_dispatch_not_absent", message)
                })?;
            self.revalidate()?;
            linux::prove_bootstrap_initializer_attempt_absent(&self.target, &self.identity).map_err(
                |message| {
                    d1_retained_lease_error("d1.bootstrap_abort_dispatch_not_absent", message)
                },
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(d1_retained_lease_platform_unsupported())
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn terminal_receipt_state(
        &self,
        expected: &D1TerminalReconciliationReceipt,
    ) -> Result<Option<D1TerminalReconciliationReceiptEvidence>, CallToolResult> {
        #[cfg(target_os = "linux")]
        {
            self.revalidate()?;
            linux::terminal_receipt_state(&self.target, expected)
                .map_err(d1_terminal_reconciliation_error)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = expected;
            Err(d1_retained_lease_platform_unsupported())
        }
    }

    pub(crate) fn compatible_terminal_receipt_state(
        &self,
        expected: &D1TerminalReconciliationReceipt,
        legacy_expected: Option<&D1TerminalReconciliationReceiptV1>,
    ) -> Result<Option<D1TerminalReconciliationReceiptEvidence>, CallToolResult> {
        #[cfg(target_os = "linux")]
        {
            self.revalidate()?;
            linux::compatible_terminal_receipt_state(&self.target, expected, legacy_expected)
                .map_err(d1_terminal_reconciliation_error)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (expected, legacy_expected);
            Err(d1_retained_lease_platform_unsupported())
        }
    }

    /// Obtain a stable, descriptor-bound view of both the current lease
    /// namespace and the exact expected receipt. A malformed or changed
    /// receipt invalidates the whole evidence claim rather than leaving a
    /// retained namespace to stand in for receipt authority.
    pub(crate) fn terminal_evidence_readback(
        &self,
        expected: &D1TerminalReconciliationReceipt,
        legacy_expected: Option<&D1TerminalReconciliationReceiptV1>,
    ) -> D1TerminalEvidenceReadback {
        #[cfg(target_os = "linux")]
        {
            if self.revalidate().is_err() {
                return D1TerminalEvidenceReadback {
                    custody: D1TerminalCustodyNamespace::Unverified,
                    receipt_persisted: None,
                };
            }
            let first_receipt = match linux::compatible_terminal_receipt_state(
                &self.target,
                expected,
                legacy_expected,
            ) {
                Ok(receipt) => receipt,
                Err(_) => {
                    return D1TerminalEvidenceReadback {
                        custody: D1TerminalCustodyNamespace::Unverified,
                        receipt_persisted: None,
                    };
                }
            };
            if self.revalidate().is_err() {
                return D1TerminalEvidenceReadback {
                    custody: D1TerminalCustodyNamespace::Unverified,
                    receipt_persisted: None,
                };
            }
            let second_receipt = match linux::compatible_terminal_receipt_state(
                &self.target,
                expected,
                legacy_expected,
            ) {
                Ok(receipt) => receipt,
                Err(_) => {
                    return D1TerminalEvidenceReadback {
                        custody: D1TerminalCustodyNamespace::Unverified,
                        receipt_persisted: None,
                    };
                }
            };
            let preliminary_receipt_persisted = match (&first_receipt, &second_receipt) {
                (None, None) => Some(false),
                (Some(first), Some(second))
                    if linux::same_terminal_receipt_evidence(first, second)
                        && linux::validate_stable_terminal_receipt_evidence(
                            &self.target,
                            second,
                        )
                        .is_ok() =>
                {
                    Some(true)
                }
                _ => None,
            };
            if preliminary_receipt_persisted.is_none() {
                return D1TerminalEvidenceReadback {
                    custody: D1TerminalCustodyNamespace::Unverified,
                    receipt_persisted: None,
                };
            }
            maybe_pause_terminal_receipt_readback_for_test(&expected.lease_nonce);
            if self.revalidate().is_err() {
                return D1TerminalEvidenceReadback {
                    custody: D1TerminalCustodyNamespace::Unverified,
                    receipt_persisted: None,
                };
            }
            let final_receipt = match linux::compatible_terminal_receipt_state(
                &self.target,
                expected,
                legacy_expected,
            ) {
                Ok(receipt) => receipt,
                Err(_) => {
                    return D1TerminalEvidenceReadback {
                        custody: D1TerminalCustodyNamespace::Unverified,
                        receipt_persisted: None,
                    };
                }
            };
            let receipt_persisted = match (&second_receipt, &final_receipt) {
                (None, None) if preliminary_receipt_persisted == Some(false) => Some(false),
                (Some(second), Some(final_receipt))
                    if preliminary_receipt_persisted == Some(true)
                        && linux::same_terminal_receipt_evidence(second, final_receipt)
                        && linux::validate_stable_terminal_receipt_evidence(
                            &self.target,
                            final_receipt,
                        )
                        .is_ok() =>
                {
                    Some(true)
                }
                _ => None,
            };
            if receipt_persisted.is_none() {
                return D1TerminalEvidenceReadback {
                    custody: D1TerminalCustodyNamespace::Unverified,
                    receipt_persisted: None,
                };
            }
            maybe_pause_terminal_lease_namespace_readback_for_test(&expected.lease_nonce);
            if self.revalidate().is_err() {
                return D1TerminalEvidenceReadback {
                    custody: D1TerminalCustodyNamespace::Unverified,
                    receipt_persisted: None,
                };
            }
            // Linearization contract: the permanent target guard remains held
            // across the exact lease-namespace revalidation above and this one
            // final compatible receipt read. Controlled custody writers honor
            // that guard, so convergence here is the bounded joint decision.
            // Do not alternate back to another lease read: an endless sequence
            // cannot create stronger atomicity against an out-of-contract local
            // filesystem writer.
            let linearized_receipt = match linux::compatible_terminal_receipt_state(
                &self.target,
                expected,
                legacy_expected,
            ) {
                Ok(receipt) => receipt,
                Err(_) => {
                    return D1TerminalEvidenceReadback {
                        custody: D1TerminalCustodyNamespace::Unverified,
                        receipt_persisted: None,
                    };
                }
            };
            let receipt_persisted = match (&final_receipt, &linearized_receipt) {
                (None, None) if receipt_persisted == Some(false) => Some(false),
                (Some(final_receipt), Some(linearized_receipt))
                    if receipt_persisted == Some(true)
                        && linux::same_terminal_receipt_evidence(
                            final_receipt,
                            linearized_receipt,
                        )
                        && linux::validate_stable_terminal_receipt_evidence(
                            &self.target,
                            linearized_receipt,
                        )
                        .is_ok() =>
                {
                    Some(true)
                }
                _ => None,
            };
            if receipt_persisted.is_none() {
                return D1TerminalEvidenceReadback {
                    custody: D1TerminalCustodyNamespace::Unverified,
                    receipt_persisted: None,
                };
            }
            let custody = match self.identity.namespace.as_str() {
                "active" => D1TerminalCustodyNamespace::Active,
                "retiring" => D1TerminalCustodyNamespace::Retiring,
                "retired" => D1TerminalCustodyNamespace::Retired,
                _ => D1TerminalCustodyNamespace::Unverified,
            };
            D1TerminalEvidenceReadback {
                custody,
                receipt_persisted,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (expected, legacy_expected);
            D1TerminalEvidenceReadback {
                custody: D1TerminalCustodyNamespace::Unverified,
                receipt_persisted: None,
            }
        }
    }

    pub(crate) fn persist_terminal_receipt(
        &self,
        expected: &D1TerminalReconciliationReceipt,
    ) -> Result<(D1TerminalReconciliationReceiptEvidence, bool), D1TerminalReceiptPersistenceFailure>
    {
        #[cfg(target_os = "linux")]
        {
            self.revalidate()
                .map_err(|result| D1TerminalReceiptPersistenceFailure {
                    result,
                    local_namespace_mutations: 0,
                })?;
            if self.is_retired() {
                return Err(D1TerminalReceiptPersistenceFailure {
                    result: d1_terminal_reconciliation_error(
                        "terminal retirement exists without an exact durable terminal receipt",
                    ),
                    local_namespace_mutations: 0,
                });
            }
            linux::persist_terminal_receipt(&self.target, expected).map_err(|failure| {
                D1TerminalReceiptPersistenceFailure {
                    result: d1_terminal_reconciliation_error(failure.message),
                    local_namespace_mutations: failure.local_namespace_mutations,
                }
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = expected;
            Err(D1TerminalReceiptPersistenceFailure {
                result: d1_retained_lease_platform_unsupported(),
                local_namespace_mutations: 0,
            })
        }
    }

    pub(crate) fn retire_after_terminal_receipt(
        &mut self,
        receipt: &D1TerminalReconciliationReceiptEvidence,
    ) -> Result<D1TerminalRetirement, D1TerminalRetirementFailure> {
        #[cfg(target_os = "linux")]
        {
            let mut local_namespace_mutations = 0;
            if let Err(result) = self.revalidate() {
                return Err(D1TerminalRetirementFailure {
                    result,
                    local_namespace_mutations,
                });
            }
            if let Err(message) =
                linux::validate_stable_terminal_receipt_evidence(&self.target, receipt)
            {
                return Err(D1TerminalRetirementFailure {
                    result: d1_terminal_reconciliation_error(message),
                    local_namespace_mutations,
                });
            }
            if self.is_retired() {
                return Ok(D1TerminalRetirement {
                    local_namespace_mutations,
                });
            }
            let retired_name = format!("retired.{}.lease.json", self.identity.nonce);
            match retained_entry_present(&self.target, &retired_name) {
                Ok(true) => {
                    return Err(D1TerminalRetirementFailure {
                        result: d1_terminal_reconciliation_error(
                            "terminal retirement is already present beside retained evidence",
                        ),
                        local_namespace_mutations,
                    });
                }
                Ok(false) => {}
                Err(message) => {
                    return Err(D1TerminalRetirementFailure {
                        result: d1_terminal_reconciliation_error(message),
                        local_namespace_mutations,
                    });
                }
            }
            if self.identity.namespace == "active" {
                if let Err(message) = linux::rename_retained_lease_no_replace(
                    &self.target,
                    ACTIVE_LEASE_NAME,
                    RETIRING_LEASE_NAME,
                    &self.evidence,
                    &self.evidence_file_identity,
                    &self.identity,
                ) {
                    return Err(D1TerminalRetirementFailure {
                        result: d1_terminal_reconciliation_error(message),
                        local_namespace_mutations,
                    });
                }
                local_namespace_mutations += 1;
                self.evidence_name = RETIRING_LEASE_NAME.to_string();
                self.identity.namespace = "retiring".to_string();
                if sync_terminal_retirement_directory(
                    &self.target,
                    &self.identity.nonce,
                    local_namespace_mutations,
                )
                .is_err()
                {
                    return Err(D1TerminalRetirementFailure {
                        result: d1_terminal_reconciliation_error(
                            "retained lease entered retiring state but the directory sync failed",
                        ),
                        local_namespace_mutations,
                    });
                }
            }
            if let Err(result) = self.revalidate() {
                return Err(D1TerminalRetirementFailure {
                    result,
                    local_namespace_mutations,
                });
            }
            if let Err(message) = linux::rename_retained_lease_no_replace(
                &self.target,
                RETIRING_LEASE_NAME,
                &retired_name,
                &self.evidence,
                &self.evidence_file_identity,
                &self.identity,
            ) {
                return Err(D1TerminalRetirementFailure {
                    result: d1_terminal_reconciliation_error(message),
                    local_namespace_mutations,
                });
            }
            local_namespace_mutations += 1;
            self.evidence_name = retired_name;
            self.identity.namespace = "retired".to_string();
            if sync_terminal_retirement_directory(
                &self.target,
                &self.identity.nonce,
                local_namespace_mutations,
            )
            .is_err()
            {
                return Err(D1TerminalRetirementFailure {
                    result: d1_terminal_reconciliation_error(
                        "retained lease entered terminal retirement but the directory sync failed",
                    ),
                    local_namespace_mutations,
                });
            }
            if let Err(result) = self.revalidate() {
                return Err(D1TerminalRetirementFailure {
                    result,
                    local_namespace_mutations,
                });
            }
            if let Err(message) =
                linux::validate_stable_terminal_receipt_evidence(&self.target, receipt)
            {
                return Err(D1TerminalRetirementFailure {
                    result: d1_terminal_reconciliation_error(message),
                    local_namespace_mutations,
                });
            }
            Ok(D1TerminalRetirement {
                local_namespace_mutations,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = receipt;
            Err(D1TerminalRetirementFailure {
                result: d1_retained_lease_platform_unsupported(),
                local_namespace_mutations: 0,
            })
        }
    }
}

#[cfg(test)]
impl TerminalTestHookGuard {
    fn new(registry: TerminalTestHookRegistry, lease_nonce: String) -> Self {
        Self {
            registry,
            lease_nonce,
            registration_id: TERMINAL_TEST_HOOK_SEQUENCE.fetch_add(1, Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
impl Drop for TerminalTestHookGuard {
    fn drop(&mut self) {
        match self.registry {
            TerminalTestHookRegistry::ReceiptPreCreate => {
                let mut hooks = TERMINAL_RECEIPT_PRE_CREATE_PAUSE_HOOK
                    .get_or_init(|| Mutex::new(HashMap::new()))
                    .lock()
                    .expect("terminal receipt pre-create pause hook lock");
                if hooks
                    .get(&self.lease_nonce)
                    .is_some_and(|hook| hook.registration_id == self.registration_id)
                {
                    hooks.remove(&self.lease_nonce);
                }
            }
            TerminalTestHookRegistry::ReceiptReadback => {
                let mut hooks = TERMINAL_RECEIPT_READBACK_PAUSE_HOOK
                    .get_or_init(|| Mutex::new(HashMap::new()))
                    .lock()
                    .expect("terminal receipt readback pause hook lock");
                if hooks
                    .get(&self.lease_nonce)
                    .is_some_and(|hook| hook.registration_id == self.registration_id)
                {
                    hooks.remove(&self.lease_nonce);
                }
            }
            TerminalTestHookRegistry::LeaseNamespaceReadback => {
                let mut hooks = TERMINAL_LEASE_NAMESPACE_READBACK_PAUSE_HOOK
                    .get_or_init(|| Mutex::new(HashMap::new()))
                    .lock()
                    .expect("terminal lease namespace readback pause hook lock");
                if hooks
                    .get(&self.lease_nonce)
                    .is_some_and(|hook| hook.registration_id == self.registration_id)
                {
                    hooks.remove(&self.lease_nonce);
                }
            }
            TerminalTestHookRegistry::RetirementFailure => {
                let mut failures = TERMINAL_RETIRE_TEST_FAILURES
                    .get_or_init(|| Mutex::new(HashMap::new()))
                    .lock()
                    .expect("terminal retirement test failure lock");
                if failures
                    .get(&self.lease_nonce)
                    .is_some_and(|failure| failure.registration_id == self.registration_id)
                {
                    failures.remove(&self.lease_nonce);
                }
            }
        }
    }
}

#[cfg(test)]
fn install_terminal_receipt_readback_pause_hook(
    lease_nonce: String,
    entered: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
) -> Result<TerminalTestHookGuard, &'static str> {
    let mut hooks = TERMINAL_RECEIPT_READBACK_PAUSE_HOOK
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("terminal receipt readback pause hook lock");
    if hooks.contains_key(&lease_nonce) {
        return Err("terminal receipt readback pause hook nonce is already installed");
    }
    let guard = TerminalTestHookGuard::new(
        TerminalTestHookRegistry::ReceiptReadback,
        lease_nonce.clone(),
    );
    hooks.insert(
        lease_nonce,
        TerminalReceiptReadbackPauseHook {
            registration_id: guard.registration_id,
            entered,
            resume,
        },
    );
    Ok(guard)
}

#[cfg(test)]
fn maybe_pause_terminal_receipt_readback_for_test(lease_nonce: &str) {
    let hook = {
        let mut hooks = TERMINAL_RECEIPT_READBACK_PAUSE_HOOK
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .expect("terminal receipt readback pause hook lock");
        hooks.remove(lease_nonce)
    };
    if let Some(hook) = hook {
        hook.entered
            .send(())
            .expect("terminal receipt readback pause receiver");
        hook.resume
            .recv()
            .expect("terminal receipt readback resume signal");
    }
}

#[cfg(not(test))]
fn maybe_pause_terminal_receipt_readback_for_test(_lease_nonce: &str) {}

#[cfg(test)]
fn install_terminal_lease_namespace_readback_pause_hook(
    lease_nonce: String,
    entered: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
) -> Result<TerminalTestHookGuard, &'static str> {
    let mut hooks = TERMINAL_LEASE_NAMESPACE_READBACK_PAUSE_HOOK
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("terminal lease namespace readback pause hook lock");
    if hooks.contains_key(&lease_nonce) {
        return Err("terminal lease namespace readback pause hook nonce is already installed");
    }
    let guard = TerminalTestHookGuard::new(
        TerminalTestHookRegistry::LeaseNamespaceReadback,
        lease_nonce.clone(),
    );
    hooks.insert(
        lease_nonce,
        TerminalLeaseNamespaceReadbackPauseHook {
            registration_id: guard.registration_id,
            entered,
            resume,
        },
    );
    Ok(guard)
}

#[cfg(test)]
fn maybe_pause_terminal_lease_namespace_readback_for_test(lease_nonce: &str) {
    let hook = {
        let mut hooks = TERMINAL_LEASE_NAMESPACE_READBACK_PAUSE_HOOK
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .expect("terminal lease namespace readback pause hook lock");
        hooks.remove(lease_nonce)
    };
    if let Some(hook) = hook {
        hook.entered
            .send(())
            .expect("terminal lease namespace readback pause receiver");
        hook.resume
            .recv()
            .expect("terminal lease namespace readback resume signal");
    }
}

#[cfg(not(test))]
fn maybe_pause_terminal_lease_namespace_readback_for_test(_lease_nonce: &str) {}

#[cfg(test)]
fn install_terminal_receipt_pre_create_pause_hook(
    lease_nonce: String,
    entered: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
) -> Result<TerminalTestHookGuard, &'static str> {
    let mut hooks = TERMINAL_RECEIPT_PRE_CREATE_PAUSE_HOOK
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("terminal receipt pre-create pause hook lock");
    if hooks.contains_key(&lease_nonce) {
        return Err("terminal receipt pre-create pause hook nonce is already installed");
    }
    let guard = TerminalTestHookGuard::new(
        TerminalTestHookRegistry::ReceiptPreCreate,
        lease_nonce.clone(),
    );
    hooks.insert(
        lease_nonce,
        TerminalReceiptPreCreatePauseHook {
            registration_id: guard.registration_id,
            entered,
            resume,
        },
    );
    Ok(guard)
}

#[cfg(test)]
fn maybe_pause_terminal_receipt_pre_create_for_test(lease_nonce: &str) {
    let hook = {
        let mut hooks = TERMINAL_RECEIPT_PRE_CREATE_PAUSE_HOOK
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .expect("terminal receipt pre-create pause hook lock");
        hooks.remove(lease_nonce)
    };
    if let Some(hook) = hook {
        hook.entered
            .send(())
            .expect("terminal receipt pre-create pause receiver");
        hook.resume
            .recv()
            .expect("terminal receipt pre-create resume signal");
    }
}

#[cfg(not(test))]
fn maybe_pause_terminal_receipt_pre_create_for_test(_lease_nonce: &str) {}

#[cfg(test)]
fn install_terminal_retirement_failure_after(
    lease_nonce: String,
    local_namespace_mutations: usize,
) -> Result<TerminalTestHookGuard, &'static str> {
    if !(1..=2).contains(&local_namespace_mutations) {
        return Err("terminal retirement failure count must name a physical transition");
    }
    let mut failures = TERMINAL_RETIRE_TEST_FAILURES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("terminal retirement test failure lock");
    if failures.contains_key(&lease_nonce) {
        return Err("terminal retirement failure nonce is already installed");
    }
    let guard = TerminalTestHookGuard::new(
        TerminalTestHookRegistry::RetirementFailure,
        lease_nonce.clone(),
    );
    failures.insert(
        lease_nonce,
        TerminalRetirementTestFailure {
            registration_id: guard.registration_id,
            local_namespace_mutations,
        },
    );
    Ok(guard)
}

#[cfg(test)]
fn terminal_retirement_test_failure_after(
    lease_nonce: &str,
    local_namespace_mutations: usize,
) -> bool {
    let mut failures = TERMINAL_RETIRE_TEST_FAILURES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("terminal retirement test failure lock");
    if failures
        .get(lease_nonce)
        .is_some_and(|failure| failure.local_namespace_mutations == local_namespace_mutations)
    {
        failures.remove(lease_nonce);
        true
    } else {
        false
    }
}

#[cfg(target_os = "linux")]
fn sync_terminal_retirement_directory(
    directory: &fs::File,
    lease_nonce: &str,
    local_namespace_mutations: usize,
) -> std::io::Result<()> {
    #[cfg(test)]
    if terminal_retirement_test_failure_after(lease_nonce, local_namespace_mutations) {
        return Err(std::io::Error::other(
            "forced terminal retirement directory sync failure",
        ));
    }
    #[cfg(not(test))]
    let _ = (lease_nonce, local_namespace_mutations);
    sync_d1_lease_directory(directory)
}

fn d1_terminal_reconciliation_error(message: &'static str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_finalize_migration_reconciliation",
        "status": "reconciliation_required",
        "retry_decision": "do_not_retry_same_attempt",
        // A namespace rename can succeed before a later directory sync or
        // descriptor validation fails. This lower custody primitive cannot
        // honestly infer whether active evidence remains, retirement is now
        // terminal, or the namespace became uninspectable. The terminal
        // coordinator re-reads its held descriptors and supplies the precise
        // retained/retired/unverifiable state to the operator result.
        "lease_retained": Value::Null,
        "error": {
            "code": "d1.migration_terminal_evidence_invalid",
            "message": message,
            "hint": "Preserve the exact target custody directory and reconcile its receipt and lease namespaces before another terminal attempt."
        }
    }))
}

pub(crate) fn inspect_retained_d1_migration_lease(
    account_id: &str,
    database_id: &str,
    family: &str,
    approved_plan_sha256: &str,
    nonce: &str,
    payload_sha256: &str,
) -> Result<D1RetainedMigrationLease, CallToolResult> {
    let root = std::env::var(D1_MANIFEST_LEASE_ROOT_ENV)
        .ok()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| {
            d1_retained_lease_error(
                "d1.migration_reconciliation_lease_root_unconfigured",
                "read-only reconciliation requires the configured operator-owned migration lease root",
            )
        })?;
    inspect_retained_d1_migration_lease_at(
        root,
        account_id,
        database_id,
        family,
        approved_plan_sha256,
        nonce,
        payload_sha256,
    )
}

pub(crate) fn inspect_retained_d1_migration_lease_at(
    root: PathBuf,
    account_id: &str,
    database_id: &str,
    family: &str,
    approved_plan_sha256: &str,
    nonce: &str,
    payload_sha256: &str,
) -> Result<D1RetainedMigrationLease, CallToolResult> {
    #[cfg(target_os = "linux")]
    {
        inspect_retained_d1_migration_lease_at_linux(
            root,
            account_id,
            database_id,
            family,
            approved_plan_sha256,
            nonce,
            payload_sha256,
            false,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            root,
            account_id,
            database_id,
            family,
            approved_plan_sha256,
            nonce,
            payload_sha256,
        );
        Err(d1_retained_lease_platform_unsupported())
    }
}

pub(crate) fn inspect_terminal_d1_migration_lease(
    account_id: &str,
    database_id: &str,
    family: &str,
    approved_plan_sha256: &str,
    nonce: &str,
    payload_sha256: &str,
) -> Result<D1RetainedMigrationLease, CallToolResult> {
    let root = std::env::var(D1_MANIFEST_LEASE_ROOT_ENV)
        .ok()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| {
            d1_retained_lease_error(
                "d1.migration_reconciliation_lease_root_unconfigured",
                "terminal reconciliation requires the configured operator-owned migration lease root",
            )
        })?;
    inspect_terminal_d1_migration_lease_at(
        root,
        account_id,
        database_id,
        family,
        approved_plan_sha256,
        nonce,
        payload_sha256,
    )
}

pub(crate) fn inspect_terminal_d1_migration_lease_at(
    root: PathBuf,
    account_id: &str,
    database_id: &str,
    family: &str,
    approved_plan_sha256: &str,
    nonce: &str,
    payload_sha256: &str,
) -> Result<D1RetainedMigrationLease, CallToolResult> {
    #[cfg(target_os = "linux")]
    {
        inspect_retained_d1_migration_lease_at_linux(
            root,
            account_id,
            database_id,
            family,
            approved_plan_sha256,
            nonce,
            payload_sha256,
            true,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            root,
            account_id,
            database_id,
            family,
            approved_plan_sha256,
            nonce,
            payload_sha256,
        );
        Err(d1_retained_lease_platform_unsupported())
    }
}

#[allow(dead_code)]
fn d1_retained_lease_platform_unsupported() -> CallToolResult {
    d1_retained_lease_error(
        "d1.migration_reconciliation_platform_unsupported",
        "read-only retained-lease reconciliation requires the Linux dirfd-bound custody implementation",
    )
}

fn d1_retained_lease_revalidation_error(message: &'static str) -> CallToolResult {
    d1_retained_lease_error("d1.migration_reconciliation_lease_changed", message)
}

fn d1_retained_lease_error(code: &'static str, message: &'static str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_reconcile_migration_manifest",
        "dry_run": true,
        "read_only": true,
        "status": "reconciliation_required",
        "retry_decision": "do_not_retry_same_attempt",
        "lease_decision": "not_acquired",
        "lease_retained": null,
        "custody_status": "inspection_failed",
        "provider_calls": 0,
        "error": {
            "code": code,
            "message": message,
            "hint": "Retain the exact custody evidence and resolve this boundary before any provider read or migration retry."
        }
    }))
}

pub(crate) fn d1_migration_lease_requirements(
    account_id: &str,
    database_id: &str,
    family: &str,
) -> Value {
    json!({
        "required_for_live_apply": true,
        "environment": D1_MANIFEST_LEASE_ROOT_ENV,
        "target_key_sha256": sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes()),
        "migration_family": family,
        "scope": "one permanent directory and guard per account/database target; family is evidence only and cannot split target serialization",
        "active_evidence": "active.lease.json and transient retiring.lease.json are never auto-reclaimed; malformed, symlink, non-regular, or otherwise present active/retiring evidence stops the next apply for governed reconciliation",
        "cross_host_limitation": "Cross-process serialization covers only hosts sharing the same configured operator-owned lease root. It is not a Cloudflare/provider-distributed lease.",
        "platform_requirement": "Linux on a trusted filesystem supporting working renameat2 RENAME_NOREPLACE, directory fsync, and advisory file locks; unsupported platforms or filesystems fail closed before provider I/O. Cross-host or shared-filesystem semantics require separate proof; retained evidence requires the governed recovery path.",
        "complete_dml_custody_authority": {
            "required": true,
            "layout_sha256": crate::d1_dml_custody_layout::D1_DML_CUSTODY_LAYOUT_SHA256,
            "audit_budget_version": crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_VERSION,
            "audit_budget_sha256": crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_SHA256,
            "genesis": crate::d1_dml_custody_genesis::D1_DML_CUSTODY_GENESIS_NAME,
            "generation_environment": crate::d1_dml_custody_genesis::D1_DML_CUSTODY_GENERATION_ENV,
            "authority_environment": crate::d1_dml_custody_genesis::D1_DML_CUSTODY_AUTHORITY_SHA256_ENV,
            "provisioning": "explicit_d1_provision_dml_custody_only",
            "ordinary_execution_may_create": false,
            "provisioning_provider_dispatch_authority": "none",
            "retained_or_recovery_absence": "reconciliation_required_without_creation",
            "binding": "the exact clean complete-audit identity is persisted in the lease payload and therefore inherited by every terminal receipt through lease_payload_sha256",
            "last_boundary_revalidation": true,
            "provider_dispatch_authority_from_audit": false,
        },
        "target_identity_activation": {
            "contract_version": 2,
            "target_identity_contract": "lowercase_hyphenated_uuid_v1",
            "activation_marker": {
                "required": true,
                "filename": TARGET_IDENTITY_ACTIVATION_MARKER_NAME,
                "version": 2,
                "payload_sha256": sha256_bytes_hex(TARGET_IDENTITY_ACTIVATION_MARKER_BYTES),
            },
            "target_registration": {
                "required_for_every_target": true,
                "create_only": true,
                "version": 1,
                "filename_pattern": format!("{TARGET_IDENTITY_REGISTRATION_PREFIX}<target_key_sha256>{TARGET_IDENTITY_REGISTRATION_SUFFIX}"),
            },
            "first_activation": {
                "requires_fresh_empty_root": true,
                "bounded_root_entry_limit": TARGET_IDENTITY_ROOT_ENTRY_LIMIT,
                "legacy_in_place_upgrade_allowed": false,
            },
            "operator_cutover": {
                "predecessor_writer_drain_required": true,
                "preserve_predecessor_root": true,
                "predecessor_root_reuse_by_upgraded_writers_allowed": false,
                "older_binary_on_activated_root_allowed": false,
                "rollback": {
                    "upgraded_writer_drain_required": true,
                    "preserve_activated_root_without_manual_changes": true,
                    "return_all_writers_as_one_predecessor_generation": true,
                    "mixed_roots_or_binary_generations_allowed": false,
                },
            },
        },
    })
}

pub(crate) fn acquire_d1_migration_lease(
    account_id: &str,
    database_id: &str,
    family: &str,
    approved_plan_sha256: Option<&str>,
) -> Result<D1MigrationLease, CallToolResult> {
    let target = normalize_d1_target(account_id, database_id)?;
    let plan_sha256 = approved_plan_sha256
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| {
            invalid_argument_result(
                "d1.approved_plan_sha256_required",
                "approved_plan_sha256 is required for live apply and must be the exact lowercase SHA-256 digest returned by dry run",
                "Use the exact plan_sha256 from a successful manifest dry run.",
            )
        })?;
    let root = std::env::var(D1_MANIFEST_LEASE_ROOT_ENV)
        .ok()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest",
            "error": {"code": "d1.migration_lease_root_unconfigured", "message": "live migration apply requires a configured operator-owned shared lease root", "hint": format!("Set {D1_MANIFEST_LEASE_ROOT_ENV} to a pre-created private directory shared by all MCP processes that can target this D1 database.")}
        })))?;
    let (custody_generation, authority_sha256) =
        crate::d1_dml_custody_genesis::configured_d1_dml_custody_authority_inputs().map_err(
            |message| {
                d1_migration_dml_custody_error(
                    "d1.migration_dml_custody_authority_unconfigured",
                    message,
                )
            },
        )?;
    acquire_d1_migration_lease_at_expected(
        root,
        &target.account_id,
        &target.database_id,
        family,
        plan_sha256,
        &custody_generation,
        &authority_sha256,
    )
}

pub(crate) fn acquire_d1_target_mutation_guard(
    operation: &'static str,
    account_id: &str,
    database_id: &str,
) -> Result<D1TargetMutationGuard, CallToolResult> {
    let target = normalize_d1_target(account_id, database_id)?;
    let root = std::env::var(D1_MANIFEST_LEASE_ROOT_ENV)
        .ok()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_root_unconfigured",
                "live D1 mutation requires the configured shared target guard root",
                &target.target_key_sha256(),
            )
        })?;
    let (custody_generation, authority_sha256) =
        crate::d1_dml_custody_genesis::configured_d1_dml_custody_authority_inputs().map_err(
            |message| {
                d1_target_guard_error(
                    operation,
                    "d1.dml_custody_authority_unconfigured",
                    message,
                    &target.target_key_sha256(),
                )
            },
        )?;
    acquire_d1_target_mutation_guard_at_expected(
        root,
        operation,
        &target.account_id,
        &target.database_id,
        &custody_generation,
        &authority_sha256,
    )
}

#[cfg(test)]
pub(crate) fn acquire_d1_target_mutation_guard_at(
    root: PathBuf,
    operation: &'static str,
    account_id: &str,
    database_id: &str,
) -> Result<D1TargetMutationGuard, CallToolResult> {
    acquire_d1_target_mutation_guard_at_expected(
        root,
        operation,
        account_id,
        database_id,
        TEST_D1_DML_CUSTODY_GENERATION,
        TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
    )
}

pub(crate) fn acquire_d1_target_mutation_guard_at_expected(
    root: PathBuf,
    operation: &'static str,
    account_id: &str,
    database_id: &str,
    custody_generation: &str,
    authority_sha256: &str,
) -> Result<D1TargetMutationGuard, CallToolResult> {
    let target = normalize_d1_target(account_id, database_id)?;
    let (expected_authority, _) = crate::d1_dml_custody_genesis::derive_d1_dml_custody_authority(
        &target.target_key_sha256(),
        custody_generation,
        authority_sha256,
    )
    .map_err(|message| {
        d1_target_guard_error(
            operation,
            "d1.dml_custody_authority_invalid",
            message,
            &target.target_key_sha256(),
        )
    })?;
    #[cfg(target_os = "linux")]
    {
        linux::acquire_d1_target_mutation_guard_at_linux(
            root,
            operation,
            target,
            expected_authority,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, expected_authority);
        Err(d1_target_guard_error(
            operation,
            "d1.target_guard_platform_unsupported",
            "permanent cross-process D1 mutation custody requires the Linux dirfd-bound guard implementation",
            &target.target_key_sha256(),
        ))
    }
}

/// Explicit one-time local provisioning. This operation never constructs or
/// submits a Cloudflare request; its supplied authority must independently
/// match the process configuration before any local artifact is created.
pub(crate) fn provision_d1_dml_custody(
    account_id: &str,
    database_id: &str,
    custody_generation: &str,
    authority_sha256: &str,
) -> Result<D1DmlCustodyProvisionReceipt, CallToolResult> {
    let target = normalize_d1_target(account_id, database_id)?;
    let root = std::env::var(D1_MANIFEST_LEASE_ROOT_ENV)
        .ok()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| {
            d1_target_guard_error(
                "d1_provision_dml_custody",
                "d1.target_guard_root_unconfigured",
                "D1 custody provisioning requires the configured shared target guard root",
                &target.target_key_sha256(),
            )
        })?;
    let configured = crate::d1_dml_custody_genesis::configured_d1_dml_custody_authority_inputs()
        .map_err(|message| {
            d1_target_guard_error(
                "d1_provision_dml_custody",
                "d1.dml_custody_authority_unconfigured",
                message,
                &target.target_key_sha256(),
            )
        })?;
    if configured.0 != custody_generation || configured.1 != authority_sha256 {
        return Err(d1_target_guard_error(
            "d1_provision_dml_custody",
            "d1.dml_custody_authority_mismatch",
            "supplied custody generation or authority pin did not match independent process configuration",
            &target.target_key_sha256(),
        ));
    }
    provision_d1_dml_custody_at(
        root,
        &target.account_id,
        &target.database_id,
        custody_generation,
        authority_sha256,
    )
}

pub(crate) fn provision_d1_dml_custody_at(
    root: PathBuf,
    account_id: &str,
    database_id: &str,
    custody_generation: &str,
    authority_sha256: &str,
) -> Result<D1DmlCustodyProvisionReceipt, CallToolResult> {
    let target = normalize_d1_target(account_id, database_id)?;
    let (expected_authority, genesis_bytes) =
        crate::d1_dml_custody_genesis::derive_d1_dml_custody_authority(
            &target.target_key_sha256(),
            custody_generation,
            authority_sha256,
        )
        .map_err(|message| {
            d1_target_guard_error(
                "d1_provision_dml_custody",
                "d1.dml_custody_authority_invalid",
                message,
                &target.target_key_sha256(),
            )
        })?;
    #[cfg(target_os = "linux")]
    {
        linux::provision_d1_dml_custody_at_linux(root, target, expected_authority, &genesis_bytes)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, expected_authority, genesis_bytes);
        Err(d1_target_guard_error(
            "d1_provision_dml_custody",
            "d1.target_guard_platform_unsupported",
            "D1 custody provisioning requires Linux dirfd-bound storage",
            &target.target_key_sha256(),
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn acquire_d1_target_mutation_guard_for_test(
    label: &str,
    operation: &'static str,
) -> (PathBuf, D1TargetMutationGuard) {
    use std::os::unix::fs::PermissionsExt;

    let root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-d1-target-wide-{label}-{}-{}",
        std::process::id(),
        D1_MANIFEST_LEASE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("create private target-wide fixture root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("private target-wide fixture root");
    provision_d1_dml_custody_at(
        root.clone(),
        "acct-1",
        "123e4567-e89b-42d3-a456-426614174000",
        TEST_D1_DML_CUSTODY_GENERATION,
        TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
    )
    .expect("provision target-wide fixture custody");
    let guard = acquire_d1_target_mutation_guard_at(
        root.clone(),
        operation,
        "acct-1",
        "123e4567-e89b-42d3-a456-426614174000",
    )
    .expect("acquire target-wide fixture guard");
    (root, guard)
}

/// Read-only occupancy check for the permanent target namespace.  This runs
/// before remote authority preflight so retained custody continues to block a
/// fresh caller without any provider I/O.  It deliberately never creates the
/// target directory or its guard: an absent target is the only state in which
/// a later acquisition may create new local custody.
pub(crate) fn preflight_d1_migration_target_custody(
    account_id: &str,
    database_id: &str,
) -> Result<(), CallToolResult> {
    let target = normalize_d1_target(account_id, database_id)?;
    let root = std::env::var(D1_MANIFEST_LEASE_ROOT_ENV)
        .ok()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| {
            CallToolResult::structured_error(json!({
                "ok": false, "operation": "d1_apply_migration_manifest",
                "error": {"code": "d1.migration_lease_root_unconfigured", "message": "live migration apply requires a configured operator-owned shared lease root", "hint": format!("Set {D1_MANIFEST_LEASE_ROOT_ENV} to a pre-created private directory shared by all MCP processes that can target this D1 database.")}
            }))
        })?;
    preflight_d1_migration_target_custody_at(root, &target.account_id, &target.database_id)
}

pub(crate) fn preflight_d1_migration_target_custody_at(
    root: PathBuf,
    account_id: &str,
    database_id: &str,
) -> Result<(), CallToolResult> {
    let target = normalize_d1_target(account_id, database_id)?;
    #[cfg(target_os = "linux")]
    {
        preflight_d1_migration_target_custody_at_linux(
            root,
            &target.account_id,
            &target.database_id,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, account_id, database_id);
        Err(d1_lease_platform_unsupported())
    }
}

#[cfg(test)]
pub(crate) fn acquire_d1_migration_lease_at(
    root: PathBuf,
    account_id: &str,
    database_id: &str,
    family: &str,
    plan_sha256: &str,
) -> Result<D1MigrationLease, CallToolResult> {
    let root_is_empty = fs::read_dir(&root)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false);
    if root_is_empty {
        let _ = provision_d1_dml_custody_at(
            root.clone(),
            account_id,
            database_id,
            TEST_D1_DML_CUSTODY_GENERATION,
            TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
        )?;
    }
    acquire_d1_migration_lease_at_expected(
        root,
        account_id,
        database_id,
        family,
        plan_sha256,
        TEST_D1_DML_CUSTODY_GENERATION,
        TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
    )
}

pub(crate) fn acquire_d1_migration_lease_at_expected(
    root: PathBuf,
    account_id: &str,
    database_id: &str,
    family: &str,
    plan_sha256: &str,
    custody_generation: &str,
    authority_sha256: &str,
) -> Result<D1MigrationLease, CallToolResult> {
    let target = normalize_d1_target(account_id, database_id)?;
    let (expected_authority, _) = crate::d1_dml_custody_genesis::derive_d1_dml_custody_authority(
        &target.target_key_sha256(),
        custody_generation,
        authority_sha256,
    )
    .map_err(|message| {
        d1_migration_dml_custody_error("d1.migration_dml_custody_authority_invalid", message)
    })?;
    #[cfg(target_os = "linux")]
    {
        acquire_d1_migration_lease_at_linux(
            root,
            &target.account_id,
            &target.database_id,
            family,
            plan_sha256,
            expected_authority,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            root,
            account_id,
            database_id,
            family,
            plan_sha256,
            expected_authority,
        );
        Err(d1_lease_platform_unsupported())
    }
}

fn d1_target_guard_error(
    operation: &'static str,
    code: &'static str,
    message: &'static str,
    target_key_sha256: &str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": operation,
        "status": "blocked",
        "provider_calls": 0,
        "provider_mutations": 0,
        "target_key_sha256": target_key_sha256,
        "error": {
            "code": code,
            "message": message,
            "hint": "Use the canonical target identity and wait for or reconcile the current target owner before another provider mutation."
        }
    }))
}

fn d1_target_guard_target_mismatch_error(
    operation: &'static str,
    guard_target_key_sha256: &str,
    supplied_target_key_sha256: &str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": operation,
        "status": "blocked",
        "provider_calls": 0,
        "provider_mutations": 0,
        "local_mutations": 0,
        "target_key_sha256": guard_target_key_sha256,
        "supplied_target_key_sha256": supplied_target_key_sha256,
        "error": {
            "code": "d1.target_guard_target_mismatch",
            "message": "supplied D1 target did not exactly match the target owned by the held guard",
            "hint": "Do not inspect or mutate either custody namespace; acquire and use the guard for the exact canonical target."
        }
    }))
}

#[allow(dead_code)]
fn d1_target_wide_dml_custody_error(
    operation: &'static str,
    message: &'static str,
    target_key_sha256: &str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": operation,
        "status": "reconciliation_required",
        "provider_calls": 0,
        "provider_mutations": 0,
        "target_key_sha256": target_key_sha256,
        "error": {
            "code": "d1.target_wide_dml_custody_unproven",
            "message": message,
            "hint": "Do not issue a provider mutation. Reconcile every nonterminal or malformed DML attempt through its governed recovery path first."
        }
    }))
}

fn d1_target_identity_activation_error(
    operation: &'static str,
    message: &'static str,
    target_key_sha256: &str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": operation,
        "status": "blocked",
        "provider_calls": 0,
        "provider_mutations": 0,
        "target_key_sha256": target_key_sha256,
        "error": {
            "code": "d1.target_guard_upgrade_activation_required",
            "message": message,
            "hint": "Stop predecessor writers, preserve and reconcile the old root separately, then configure every upgraded writer to one new private empty lease root. Do not create the activation marker manually."
        }
    }))
}

fn d1_migration_target_identity_activation_error(message: &'static str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_apply_migration_manifest",
        "status": "blocked",
        "provider_calls": 0,
        "provider_mutations": 0,
        "lease_retained": null,
        "error": {
            "code": "d1.migration_lease_upgrade_activation_required",
            "message": message,
            "hint": "Stop predecessor writers, preserve and reconcile the old root separately, then configure every upgraded writer to one new private empty lease root. Do not create the activation marker manually."
        }
    }))
}

#[allow(dead_code)]
fn d1_lease_platform_unsupported() -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required", "lease_retained": false,
        "error": {"code": "d1.migration_lease_platform_unsupported", "message": "permanent cross-process migration custody requires the Linux dirfd-bound lease implementation", "hint": "Use a supported Linux MCP installation; do not issue provider migration writes from this platform."}
    }))
}

fn d1_lease_root_error(code: &'static str, message: &'static str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required", "lease_retained": false,
        "error": {"code": code, "message": message, "hint": "Use an absolute, operator-owned 0700 lease root with safe ancestors."}
    }))
}

fn d1_migration_dml_custody_error(code: &'static str, message: &'static str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_apply_migration_manifest",
        "status": "reconciliation_required",
        "provider_calls": 0,
        "provider_mutations": 0,
        "lease_retained": false,
        "error": {
            "code": code,
            "message": message,
            "hint": "Do not persist migration authority or issue provider SQL. Reconcile the complete target DML custody graph and run a fresh approved plan."
        }
    }))
}

fn d1_migration_lease_nonce(target_hash: &str, plan_sha256: &str) -> String {
    let sequence = D1_MANIFEST_LEASE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    blake3::hash(
        format!(
            "{target_hash}\0{plan_sha256}\0{}\0{sequence}",
            now_unix_ms()
        )
        .as_bytes(),
    )
    .to_hex()
    .to_string()
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::private_file_custody::{
        file_identity as identity, private_directory as private_dir,
        private_regular_file as private_file, safe_root_ancestor,
    };
    use libc::{
        AT_FDCWD, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_PATH, O_RDONLY, O_RDWR,
        O_WRONLY,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::{CStr, CString, c_char};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};

    const RENAME_NOREPLACE: u32 = 1;
    const MAX_LEASE_PAYLOAD_BYTES: u64 = 4096;
    pub(super) const MAX_TARGET_CUSTODY_DIRECTORY_ENTRIES: usize = TARGET_IDENTITY_ROOT_ENTRY_LIMIT;
    const TERMINAL_RECEIPT_PREFIX: &str = "terminal-reconciliation.";
    const TERMINAL_RECEIPT_SUFFIX: &str = ".receipt.json";

    #[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct TargetIdentityRegistrationReceipt {
        version: u8,
        target_identity_contract: String,
        target_key_sha256: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CustodyFileSnapshot {
        name: String,
        file_identity: D1LeaseFileIdentity,
        payload_sha256: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TargetDirectorySnapshot {
        target_key_sha256: String,
        directory_identity: D1LeaseFileIdentity,
        entries: Vec<CustodyFileSnapshot>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RootNamespaceSnapshot {
        activation_guard_identity: D1LeaseFileIdentity,
        activation_marker: Option<CustodyFileSnapshot>,
        registrations: Vec<CustodyFileSnapshot>,
        targets: Vec<TargetDirectorySnapshot>,
    }

    pub(super) struct TerminalReceiptPersistenceFailure {
        pub(super) message: &'static str,
        pub(super) local_namespace_mutations: usize,
    }

    impl TerminalReceiptPersistenceFailure {
        fn before_create(message: &'static str) -> Self {
            Self {
                message,
                local_namespace_mutations: 0,
            }
        }

        fn after_create(message: &'static str) -> Self {
            Self {
                message,
                local_namespace_mutations: 1,
            }
        }
    }

    #[repr(C)]
    struct CDirectoryStream {
        _private: [u8; 0],
    }

    #[repr(C)]
    struct CDirectoryEntry {
        d_ino: u64,
        d_off: i64,
        d_reclen: u16,
        d_type: u8,
        d_name: [c_char; 256],
    }

    unsafe extern "C" {
        fn mkdirat(dirfd: i32, pathname: *const std::ffi::c_char, mode: u32) -> i32;
        fn renameat2(
            olddirfd: i32,
            oldpath: *const std::ffi::c_char,
            newdirfd: i32,
            newpath: *const std::ffi::c_char,
            flags: u32,
        ) -> i32;
        fn fdopendir(fd: i32) -> *mut CDirectoryStream;
        fn readdir(directory: *mut CDirectoryStream) -> *mut CDirectoryEntry;
        fn closedir(directory: *mut CDirectoryStream) -> i32;
        fn __errno_location() -> *mut i32;
    }

    fn c_string_path(path: &Path) -> Result<CString, &'static str> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "migration lease path contains an embedded NUL")
    }

    fn c_string_name(name: &str) -> Result<CString, &'static str> {
        CString::new(name).map_err(|_| "migration lease name contains an embedded NUL")
    }

    fn open_at(dirfd: i32, name: &CString, flags: i32, mode: u32) -> io::Result<fs::File> {
        let fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags, mode) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { fs::File::from_raw_fd(fd) })
        }
    }

    fn open_directory_at(dirfd: i32, name: &CString) -> io::Result<fs::File> {
        open_at(
            dirfd,
            name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
    }

    fn open_named_entry(target: &fs::File, name: &str) -> io::Result<fs::File> {
        let name = c_string_name(name).map_err(io::Error::other)?;
        open_at(
            target.as_raw_fd(),
            &name,
            O_PATH | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
    }

    fn directory_entry_names(target: &fs::File) -> Result<Vec<Vec<u8>>, &'static str> {
        let current = c_string_name(".")?;
        let directory = open_at(
            target.as_raw_fd(),
            &current,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
        .map_err(|_| "target custody directory could not be duplicated for enumeration")?;
        let directory_fd = directory.into_raw_fd();
        let stream = unsafe { fdopendir(directory_fd) };
        if stream.is_null() {
            drop(unsafe { fs::File::from_raw_fd(directory_fd) });
            return Err("target custody directory could not be opened for enumeration");
        }
        let read_result = (|| {
            let mut names = Vec::new();
            loop {
                unsafe {
                    *__errno_location() = 0;
                }
                let entry = unsafe { readdir(stream) };
                if entry.is_null() {
                    if unsafe { *__errno_location() } != 0 {
                        return Err("target custody directory enumeration failed");
                    }
                    break;
                }
                let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if name != b"." && name != b".." {
                    if names.len() == MAX_TARGET_CUSTODY_DIRECTORY_ENTRIES {
                        return Err(
                            "target custody directory exceeds the finite enumeration limit",
                        );
                    }
                    names.push(name.to_vec());
                }
            }
            Ok(names)
        })();
        if unsafe { closedir(stream) } != 0 {
            return Err("target custody directory enumeration could not be closed cleanly");
        }
        read_result
    }

    fn entry_present(target: &fs::File, name: &str) -> Result<bool, &'static str> {
        match open_named_entry(target, name) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(_) => {
                Err("target custody entry could not be inspected through its held directory handle")
            }
        }
    }

    fn validate_root_and_ancestors(root: &Path) -> Result<(), &'static str> {
        if !root.is_absolute() {
            return Err("migration lease root must be an absolute path");
        }
        let root_metadata = fs::symlink_metadata(root)
            .map_err(|_| "configured migration lease root is unavailable")?;
        if !private_dir(&root_metadata) {
            return Err(
                "migration lease root must be a real current-operator-owned 0700 directory",
            );
        }
        for ancestor in root.ancestors().skip(1) {
            let metadata = fs::symlink_metadata(ancestor)
                .map_err(|_| "migration lease root ancestor is unavailable")?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("migration lease root has a non-directory or symlink ancestor");
            }
            if !safe_root_ancestor(&metadata) {
                return Err("migration lease root has a writable non-sticky ancestor");
            }
        }
        Ok(())
    }

    fn validate_root_path_binding(
        root_path: &Path,
        root: &fs::File,
        expected: &D1LeaseFileIdentity,
    ) -> Result<(), &'static str> {
        validate_root_and_ancestors(root_path)?;
        let held = root
            .metadata()
            .map_err(|_| "held migration lease root metadata is unavailable")?;
        let by_path = fs::symlink_metadata(root_path)
            .map_err(|_| "migration lease root pathname is unavailable")?;
        if !private_dir(&held)
            || !private_dir(&by_path)
            || identity(&held) != *expected
            || identity(&by_path) != *expected
        {
            return Err("migration lease root no longer matches its held private directory");
        }
        Ok(())
    }

    fn validate_target_binding(
        root: &fs::File,
        target_name: &str,
        target: &fs::File,
        expected: &D1LeaseFileIdentity,
    ) -> Result<(), &'static str> {
        let held = target
            .metadata()
            .map_err(|_| "held target custody directory metadata is unavailable")?;
        let name = c_string_name(target_name)?;
        let named = open_directory_at(root.as_raw_fd(), &name)
            .map_err(|_| "target custody directory is unavailable through its held root handle")?;
        let named_metadata = named.metadata().map_err(
            |_| "target custody directory metadata is unavailable through its held root handle",
        )?;
        if !private_dir(&held)
            || !private_dir(&named_metadata)
            || identity(&held) != *expected
            || identity(&named_metadata) != *expected
        {
            return Err("target custody directory no longer matches its held private directory");
        }
        Ok(())
    }

    fn ensure_target_directory(
        root: &fs::File,
        target_name: &str,
    ) -> Result<(fs::File, D1LeaseFileIdentity), &'static str> {
        let name = c_string_name(target_name)?;
        let target = match open_directory_at(root.as_raw_fd(), &name) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let result = unsafe { mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) };
                if result != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                {
                    return Err("target custody directory could not be created");
                }
                root.sync_all().map_err(
                    |_| "lease root could not be synchronized after target directory creation",
                )?;
                open_directory_at(root.as_raw_fd(), &name)
                    .map_err(|_| "target custody directory could not be opened after creation")?
            }
            Err(_) => return Err("target custody directory is unavailable"),
        };
        let metadata = target
            .metadata()
            .map_err(|_| "target custody directory metadata is unavailable")?;
        if !private_dir(&metadata) {
            return Err(
                "target custody directory is not a private current-operator-owned directory",
            );
        }
        Ok((target, identity(&metadata)))
    }

    fn open_existing_target_directory(
        root: &fs::File,
        target_name: &str,
    ) -> Result<(fs::File, D1LeaseFileIdentity), &'static str> {
        let name = c_string_name(target_name)?;
        let target = open_directory_at(root.as_raw_fd(), &name)
            .map_err(|_| "target custody directory is absent or unavailable")?;
        let metadata = target
            .metadata()
            .map_err(|_| "target custody directory metadata is unavailable")?;
        if !private_dir(&metadata) {
            return Err(
                "target custody directory is not a private current-operator-owned directory",
            );
        }
        Ok((target, identity(&metadata)))
    }

    fn open_or_create_private_lock(
        directory: &fs::File,
        lock_name: &str,
    ) -> Result<(fs::File, D1LeaseFileIdentity), &'static str> {
        let name = c_string_name(lock_name)?;
        let guard = match open_named_entry(directory, lock_name) {
            Ok(existing) => {
                let existing_metadata = existing
                    .metadata()
                    .map_err(|_| "permanent target guard metadata is unavailable")?;
                if !private_file(&existing_metadata) {
                    return Err("permanent target guard is not a private regular file");
                }
                let expected = identity(&existing_metadata);
                let guard = open_at(
                    directory.as_raw_fd(),
                    &name,
                    O_RDWR | O_NOFOLLOW | O_CLOEXEC,
                    0,
                )
                .map_err(|_| "permanent target guard could not be opened")?;
                let opened = guard
                    .metadata()
                    .map_err(|_| "held permanent target guard metadata is unavailable")?;
                if !private_file(&opened) || identity(&opened) != expected {
                    return Err("permanent target guard changed or is not a private regular file");
                }
                guard
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let guard = match open_at(
                    directory.as_raw_fd(),
                    &name,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0o600,
                ) {
                    Ok(guard) => guard,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        return open_or_create_private_lock(directory, lock_name);
                    }
                    Err(_) => return Err("permanent target guard could not be created"),
                };
                guard
                    .set_permissions(fs::Permissions::from_mode(0o600))
                    .and_then(|()| guard.sync_all())
                    .map_err(|_| "permanent target guard could not be synchronized")?;
                sync_d1_lease_directory(directory)
                    .map_err(|_| "custody directory could not be synchronized")?;
                guard
            }
            Err(_) => return Err("permanent target guard could not be inspected"),
        };
        let metadata = guard
            .metadata()
            .map_err(|_| "held permanent target guard metadata is unavailable")?;
        if !private_file(&metadata) {
            return Err("permanent target guard is not a private regular file");
        }
        let expected = identity(&metadata);
        validate_named_private_file(directory, lock_name, &expected)
            .map_err(|_| "permanent target guard changed or is not a private regular file")?;
        Ok((guard, expected))
    }

    fn open_or_create_guard(
        target: &fs::File,
    ) -> Result<(fs::File, D1LeaseFileIdentity), &'static str> {
        open_or_create_private_lock(target, GUARD_NAME)
    }

    fn validate_target_identity_activation_marker(root: &fs::File) -> Result<(), &'static str> {
        let named = open_named_entry(root, TARGET_IDENTITY_ACTIVATION_MARKER_NAME)
            .map_err(|_| "target-identity activation marker is absent or unavailable")?;
        let metadata = named
            .metadata()
            .map_err(|_| "target-identity activation marker metadata is unavailable")?;
        if !private_file(&metadata)
            || metadata.nlink() != 1
            || metadata.len() > MAX_LEASE_PAYLOAD_BYTES
        {
            return Err(
                "target-identity activation marker is not one bounded private regular file",
            );
        }
        let expected = identity(&metadata);
        let name = c_string_name(TARGET_IDENTITY_ACTIVATION_MARKER_NAME)?;
        let marker = open_at(
            root.as_raw_fd(),
            &name,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
        .map_err(|_| "target-identity activation marker could not be rebound")?;
        let held = marker
            .metadata()
            .map_err(|_| "held target-identity activation marker metadata is unavailable")?;
        if !private_file(&held) || held.nlink() != 1 || identity(&held) != expected {
            return Err("target-identity activation marker changed while it was rebound");
        }
        if read_held_file(&marker)? != TARGET_IDENTITY_ACTIVATION_MARKER_BYTES {
            return Err("target-identity activation marker payload is not the exact contract");
        }
        validate_named_private_file(root, TARGET_IDENTITY_ACTIVATION_MARKER_NAME, &expected)
            .map_err(|_| "target-identity activation marker changed after readback")
    }

    fn private_custody_file_snapshot(
        directory: &fs::File,
        name: &str,
    ) -> Result<(CustodyFileSnapshot, Vec<u8>), &'static str> {
        let (_file, file_identity, bytes) = open_retained_named_lease(directory, name)?;
        Ok((
            CustodyFileSnapshot {
                name: name.to_string(),
                file_identity,
                payload_sha256: sha256_bytes_hex(&bytes),
            },
            bytes,
        ))
    }

    fn target_identity_registration_name(target_key_sha256: &str) -> String {
        format!(
            "{TARGET_IDENTITY_REGISTRATION_PREFIX}{target_key_sha256}{TARGET_IDENTITY_REGISTRATION_SUFFIX}"
        )
    }

    fn target_identity_registration_hash(name: &str) -> Option<&str> {
        name.strip_prefix(TARGET_IDENTITY_REGISTRATION_PREFIX)
            .and_then(|value| value.strip_suffix(TARGET_IDENTITY_REGISTRATION_SUFFIX))
            .filter(|value| valid_lower_sha256(value))
    }

    fn canonical_target_identity_registration_bytes(
        target_key_sha256: &str,
    ) -> Result<Vec<u8>, &'static str> {
        if !valid_lower_sha256(target_key_sha256) {
            return Err("target-identity registration target hash is not canonical");
        }
        serde_json::to_vec(&TargetIdentityRegistrationReceipt {
            version: 1,
            target_identity_contract: "lowercase_hyphenated_uuid_v1".to_string(),
            target_key_sha256: target_key_sha256.to_string(),
        })
        .map_err(|_| "target-identity registration could not be encoded")
    }

    fn validate_target_identity_registration(
        root: &fs::File,
        name: &str,
        expected_target_key_sha256: &str,
    ) -> Result<CustodyFileSnapshot, &'static str> {
        let (snapshot, bytes) = private_custody_file_snapshot(root, name)?;
        let receipt: TargetIdentityRegistrationReceipt = serde_json::from_slice(&bytes)
            .map_err(|_| "target-identity registration is malformed or duplicate-keyed")?;
        let canonical = canonical_target_identity_registration_bytes(expected_target_key_sha256)?;
        if receipt.version != 1
            || receipt.target_identity_contract != "lowercase_hyphenated_uuid_v1"
            || receipt.target_key_sha256 != expected_target_key_sha256
            || bytes != canonical
        {
            return Err("target-identity registration contradicts its canonical namespace");
        }
        Ok(snapshot)
    }

    fn create_or_validate_target_identity_registration(
        root: &fs::File,
        target_key_sha256: &str,
    ) -> Result<(), &'static str> {
        let name = target_identity_registration_name(target_key_sha256);
        if entry_present(root, &name)? {
            validate_target_identity_registration(root, &name, target_key_sha256)?;
            return Ok(());
        }
        if directory_entry_names(root)?.len() >= MAX_TARGET_CUSTODY_DIRECTORY_ENTRIES {
            return Err("lease root has no capacity for target-identity registration");
        }
        let bytes = canonical_target_identity_registration_bytes(target_key_sha256)?;
        let name_c = c_string_name(&name)?;
        let mut file = open_at(
            root.as_raw_fd(),
            &name_c,
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600,
        )
        .map_err(|_| "target-identity registration could not be created without replacement")?;
        let metadata = file
            .metadata()
            .map_err(|_| "target-identity registration identity is unavailable")?;
        if !private_file(&metadata) || metadata.nlink() != 1 {
            return Err("target-identity registration is not one private regular file");
        }
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "target-identity registration could not be durably written")?;
        sync_d1_lease_directory(root)
            .map_err(|_| "target-identity registration directory could not be synchronized")?;
        validate_target_identity_registration(root, &name, target_key_sha256)?;
        Ok(())
    }

    fn retained_nonce_from_name<'a>(name: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
        name.strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(suffix))
            .filter(|value| valid_retained_nonce(value))
    }

    fn open_private_dml_directory(
        parent: &fs::File,
        name: &str,
    ) -> Result<(fs::File, D1LeaseFileIdentity), &'static str> {
        let name_c = c_string_name(name)?;
        let directory = open_directory_at(parent.as_raw_fd(), &name_c)
            .map_err(|_| "DML custody directory was absent, linked, or unavailable")?;
        let metadata = directory
            .metadata()
            .map_err(|_| "DML custody directory metadata was unavailable")?;
        if !private_dir(&metadata) {
            return Err("DML custody directory was not current-operator-owned mode 0700");
        }
        let expected = identity(&metadata);
        let rebound = open_directory_at(parent.as_raw_fd(), &name_c)
            .map_err(|_| "DML custody directory could not be rebound")?;
        let rebound_metadata = rebound
            .metadata()
            .map_err(|_| "rebound DML custody directory metadata was unavailable")?;
        if !private_dir(&rebound_metadata) || identity(&rebound_metadata) != expected {
            return Err("DML custody directory changed while it was rebound");
        }
        Ok((directory, expected))
    }

    fn d1_dml_layout_snapshot(
        target: &fs::File,
        authority: &crate::d1_dml_custody_genesis::D1DmlCustodyAuthority,
    ) -> Result<CustodyFileSnapshot, &'static str> {
        use crate::d1_dml_custody_layout::{
            D1_DML_CUSTODY_LAYOUT_MARKER_NAME, D1_DML_CUSTODY_LAYOUT_NAME, validate_layout_marker,
        };
        let (layout, layout_identity) =
            open_private_dml_directory(target, D1_DML_CUSTODY_LAYOUT_NAME)?;
        let mut top = directory_entry_names(&layout)?;
        top.sort();
        if top
            != [
                b"attempt".to_vec(),
                b"claimant".to_vec(),
                b"layout.json".to_vec(),
            ]
        {
            return Err("DML custody layout root contained an unknown or missing entry");
        }
        let (marker, marker_bytes) =
            private_custody_file_snapshot(&layout, D1_DML_CUSTODY_LAYOUT_MARKER_NAME)?;
        if !validate_layout_marker(&marker_bytes, authority) {
            return Err("DML custody layout marker was malformed or contradictory");
        }
        let (claimant, claimant_identity) = open_private_dml_directory(&layout, "claimant")?;
        let mut namespaces = directory_entry_names(&claimant)?;
        namespaces.sort();
        if namespaces
            != [
                b"execution-attempt".to_vec(),
                b"operation".to_vec(),
                b"provider-request".to_vec(),
            ]
        {
            return Err("DML claimant layout contained an unknown or missing namespace");
        }
        let mut namespace_identities = Vec::new();
        for namespace in crate::d1_dml_identity_claimant::D1DmlIdentityNamespace::ALL {
            let (_, namespace_identity) =
                open_private_dml_directory(&claimant, namespace.filename_label())?;
            namespace_identities.push((namespace.filename_label(), namespace_identity));
        }
        let (_, attempt_identity) = open_private_dml_directory(&layout, "attempt")?;
        let payload_sha256 = sha256_bytes_hex(
            format!(
                "{}|{:?}|{:?}|{:?}",
                marker.payload_sha256, claimant_identity, namespace_identities, attempt_identity
            )
            .as_bytes(),
        );
        Ok(CustodyFileSnapshot {
            name: D1_DML_CUSTODY_LAYOUT_NAME.to_string(),
            file_identity: layout_identity,
            payload_sha256,
        })
    }

    fn target_custody_snapshot_once(
        target: &fs::File,
        expected_target_key_sha256: &str,
    ) -> Result<Vec<CustodyFileSnapshot>, &'static str> {
        let raw_names = directory_entry_names(target)?;
        let genesis_name = crate::d1_dml_custody_genesis::D1_DML_CUSTODY_GENESIS_NAME;
        let genesis_authority = if raw_names
            .iter()
            .any(|name| name.as_slice() == genesis_name.as_bytes())
        {
            let (_, bytes) = private_custody_file_snapshot(target, genesis_name)?;
            let authority = crate::d1_dml_custody_genesis::inspect_d1_dml_custody_genesis(&bytes)?;
            if authority.target_key_sha256 != expected_target_key_sha256 {
                return Err("D1 custody genesis contradicted its target identity");
            }
            Some(authority)
        } else {
            None
        };
        let mut entries = Vec::new();
        let mut guard_present = false;
        let mut active_present = false;
        let mut retiring_present = false;
        let mut retained_lease_nonces = BTreeSet::new();
        for raw_name in raw_names {
            let name = String::from_utf8(raw_name)
                .map_err(|_| "target custody namespace contains a non-UTF-8 entry")?;
            if name == GUARD_NAME {
                if guard_present {
                    return Err("target custody namespace contains duplicate guard authority");
                }
                let (snapshot, bytes) = private_custody_file_snapshot(target, &name)?;
                if !bytes.is_empty() {
                    return Err("permanent target guard contains unexpected payload bytes");
                }
                guard_present = true;
                entries.push(snapshot);
                continue;
            }
            if name == genesis_name {
                let (snapshot, _) = private_custody_file_snapshot(target, &name)?;
                entries.push(snapshot);
                continue;
            }
            if name == crate::d1_dml_custody_layout::D1_DML_CUSTODY_LAYOUT_NAME {
                let authority = genesis_authority
                    .as_ref()
                    .ok_or("DML custody layout is orphaned from immutable genesis")?;
                entries.push(d1_dml_layout_snapshot(target, authority)?);
                continue;
            }

            let lease_nonce = if name == ACTIVE_LEASE_NAME {
                active_present = true;
                None
            } else if name == RETIRING_LEASE_NAME {
                retiring_present = true;
                None
            } else if let Some(nonce) = retained_nonce_from_name(&name, "retired.", ".lease.json") {
                Some(nonce)
            } else if let Some(nonce) =
                retained_nonce_from_name(&name, "aborted-create.", ".lease.json")
            {
                Some(nonce)
            } else {
                None
            };
            if name == ACTIVE_LEASE_NAME || name == RETIRING_LEASE_NAME || lease_nonce.is_some() {
                let (snapshot, bytes) = private_custody_file_snapshot(target, &name)?;
                let payload = parse_retained_lease_payload(&bytes)?;
                if payload.target_key_sha256 != expected_target_key_sha256
                    || lease_nonce.is_some_and(|nonce| nonce != payload.nonce)
                {
                    return Err("retained lease entry contradicts its target or filename identity");
                }
                if !retained_lease_nonces.insert(payload.nonce) {
                    return Err(
                        "target custody namespace reuses one lease nonce across contradictory states",
                    );
                }
                entries.push(snapshot);
                continue;
            }

            if let Some(nonce) = retained_nonce_from_name(
                &name,
                BOOTSTRAP_INITIALIZER_ATTEMPT_PREFIX,
                ".receipt.json",
            ) {
                let (snapshot, bytes) = private_custody_file_snapshot(target, &name)?;
                let receipt: D1BootstrapInitializerAttemptReceipt = serde_json::from_slice(&bytes)
                    .map_err(
                        |_| "bootstrap initializer-attempt receipt is malformed or duplicate-keyed",
                    )?;
                if canonical_bootstrap_initializer_attempt_bytes(&receipt)? != bytes
                    || receipt.target_key_sha256 != expected_target_key_sha256
                    || receipt.lease_nonce != nonce
                {
                    return Err(
                        "bootstrap initializer-attempt receipt contradicts its target or filename identity",
                    );
                }
                entries.push(snapshot);
                continue;
            }

            if let Some(nonce) =
                retained_nonce_from_name(&name, TERMINAL_RECEIPT_PREFIX, TERMINAL_RECEIPT_SUFFIX)
            {
                let evidence = open_terminal_receipt(target, &name)?;
                if evidence.target_key_sha256 != expected_target_key_sha256
                    || evidence.lease_nonce != nonce
                {
                    return Err(
                        "terminal reconciliation receipt contradicts its target or filename identity",
                    );
                }
                entries.push(CustodyFileSnapshot {
                    name,
                    file_identity: evidence.file_identity,
                    payload_sha256: evidence.payload_sha256,
                });
                continue;
            }

            return Err("target custody namespace contains an unclassifiable entry");
        }
        if !guard_present {
            return Err("target custody namespace is missing its permanent guard");
        }
        if active_present && retiring_present {
            return Err("target custody namespace contains conflicting active and retiring leases");
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }

    fn target_directory_snapshot_once(
        root: &fs::File,
        target_name: &str,
        target_key_sha256: &str,
    ) -> Result<TargetDirectorySnapshot, &'static str> {
        let target_name_c = c_string_name(target_name)?;
        let target = open_directory_at(root.as_raw_fd(), &target_name_c)
            .map_err(|_| "registered target custody directory is unavailable")?;
        let metadata = target
            .metadata()
            .map_err(|_| "registered target custody directory metadata is unavailable")?;
        if !private_dir(&metadata) {
            return Err("registered target custody directory is not private");
        }
        let directory_identity = identity(&metadata);
        let entries = target_custody_snapshot_once(&target, target_key_sha256)?;
        validate_target_binding(root, target_name, &target, &directory_identity)?;
        Ok(TargetDirectorySnapshot {
            target_key_sha256: target_key_sha256.to_string(),
            directory_identity,
            entries,
        })
    }

    fn stable_target_directory_snapshot(
        root: &fs::File,
        target_name: &str,
        target_key_sha256: &str,
    ) -> Result<TargetDirectorySnapshot, &'static str> {
        let first = target_directory_snapshot_once(root, target_name, target_key_sha256)?;
        let second = target_directory_snapshot_once(root, target_name, target_key_sha256)?;
        if first != second {
            return Err("target custody namespace changed during stable audit");
        }
        Ok(second)
    }

    fn root_namespace_snapshot_once(
        root: &fs::File,
        marker_required: bool,
        targets_allowed: bool,
    ) -> Result<RootNamespaceSnapshot, &'static str> {
        let mut activation_guard_identity = None;
        let mut activation_marker = None;
        let mut registrations = Vec::new();
        let mut registered_hashes = BTreeSet::new();
        let mut target_names = Vec::new();

        for raw_name in directory_entry_names(root)? {
            let name = String::from_utf8(raw_name)
                .map_err(|_| "lease root namespace contains a non-UTF-8 entry")?;
            if name == TARGET_IDENTITY_ACTIVATION_GUARD_NAME {
                let (snapshot, bytes) = private_custody_file_snapshot(root, &name)?;
                if !bytes.is_empty() {
                    return Err("target-identity activation guard contains unexpected bytes");
                }
                activation_guard_identity = Some(snapshot.file_identity);
                continue;
            }
            if name == TARGET_IDENTITY_ACTIVATION_MARKER_NAME {
                validate_target_identity_activation_marker(root)?;
                let (snapshot, bytes) = private_custody_file_snapshot(root, &name)?;
                if bytes != TARGET_IDENTITY_ACTIVATION_MARKER_BYTES {
                    return Err("target-identity activation marker payload is not exact");
                }
                activation_marker = Some(snapshot);
                continue;
            }
            if let Some(target_key_sha256) = target_identity_registration_hash(&name) {
                let snapshot =
                    validate_target_identity_registration(root, &name, target_key_sha256)?;
                if !registered_hashes.insert(target_key_sha256.to_string()) {
                    return Err("lease root contains duplicate target-identity registrations");
                }
                registrations.push(snapshot);
                continue;
            }
            if let Some(target_key_sha256) = name
                .strip_prefix("d1-migration-target-")
                .filter(|value| valid_lower_sha256(value))
            {
                if !targets_allowed {
                    return Err("target directory appeared before root activation completed");
                }
                let target_key_sha256 = target_key_sha256.to_string();
                target_names.push((name, target_key_sha256));
                continue;
            }
            return Err("lease root namespace contains an unclassifiable entry");
        }

        let activation_guard_identity = activation_guard_identity
            .ok_or("lease root namespace is missing its activation guard")?;
        if marker_required && activation_marker.is_none() {
            return Err("lease root namespace is missing its activation marker");
        }
        if !marker_required && activation_marker.is_some() {
            return Err("activation marker appeared during pre-activation audit");
        }
        let mut targets = Vec::new();
        for (target_name, target_key_sha256) in target_names {
            if !registered_hashes.contains(&target_key_sha256) {
                return Err("target directory has no canonical target-identity registration");
            }
            targets.push(target_directory_snapshot_once(
                root,
                &target_name,
                &target_key_sha256,
            )?);
        }
        registrations.sort_by(|left, right| left.name.cmp(&right.name));
        targets.sort_by(|left, right| left.target_key_sha256.cmp(&right.target_key_sha256));
        Ok(RootNamespaceSnapshot {
            activation_guard_identity,
            activation_marker,
            registrations,
            targets,
        })
    }

    fn validate_stable_root_namespace(
        root: &fs::File,
        marker_required: bool,
        targets_allowed: bool,
    ) -> Result<(), &'static str> {
        let first = root_namespace_snapshot_once(root, marker_required, targets_allowed)?;
        maybe_pause_root_namespace_audit_after_first_for_test(root);
        let second = root_namespace_snapshot_once(root, marker_required, targets_allowed)?;
        if first != second {
            return Err("lease root namespace changed during stable activation audit");
        }
        Ok(())
    }

    fn open_and_lock_activation_guard(
        root: &fs::File,
    ) -> Result<(fs::File, D1LeaseFileIdentity), &'static str> {
        let name = c_string_name(TARGET_IDENTITY_ACTIVATION_GUARD_NAME)?;
        let named = open_named_entry(root, TARGET_IDENTITY_ACTIVATION_GUARD_NAME)
            .map_err(|_| "target-identity activation guard is absent or unavailable")?;
        let metadata = named
            .metadata()
            .map_err(|_| "target-identity activation guard metadata is unavailable")?;
        if !private_file(&metadata) || metadata.nlink() != 1 {
            return Err("target-identity activation guard is not one private regular file");
        }
        let expected = identity(&metadata);
        let guard = open_at(root.as_raw_fd(), &name, O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0)
            .map_err(|_| "target-identity activation guard could not be rebound")?;
        let held = guard
            .metadata()
            .map_err(|_| "held target-identity activation guard metadata is unavailable")?;
        if !private_file(&held) || held.nlink() != 1 || identity(&held) != expected {
            return Err("target-identity activation guard changed while it was rebound");
        }
        guard
            .lock()
            .map_err(|_| "target-identity activation guard could not be locked")?;
        validate_named_private_file(root, TARGET_IDENTITY_ACTIVATION_GUARD_NAME, &expected)
            .map_err(|_| "target-identity activation guard changed after locking")?;
        Ok((guard, expected))
    }

    fn validate_target_identity_root(root: &fs::File) -> Result<(), &'static str> {
        let (_guard, _guard_identity) = open_and_lock_activation_guard(root)?;
        validate_stable_root_namespace(root, true, true)
    }

    pub(super) fn ensure_target_identity_activation(
        root: &fs::File,
        target_key_sha256: &str,
    ) -> Result<(), &'static str> {
        let marker_present = entry_present(root, TARGET_IDENTITY_ACTIVATION_MARKER_NAME)?;
        if marker_present {
            validate_target_identity_activation_marker(root)?;
        } else if !directory_entry_names(root)?.is_empty() {
            return Err(
                "unversioned root contains custody evidence; activate this contract only on a fresh empty root",
            );
        }

        let (guard, guard_identity) =
            open_or_create_private_lock(root, TARGET_IDENTITY_ACTIVATION_GUARD_NAME)?;
        guard
            .lock()
            .map_err(|_| "target-identity activation guard could not be locked")?;
        validate_named_private_file(root, TARGET_IDENTITY_ACTIVATION_GUARD_NAME, &guard_identity)
            .map_err(|_| "target-identity activation guard changed after locking")?;

        if marker_present || entry_present(root, TARGET_IDENTITY_ACTIVATION_MARKER_NAME)? {
            validate_stable_root_namespace(root, true, true)?;
            create_or_validate_target_identity_registration(root, target_key_sha256)?;
            return validate_stable_root_namespace(root, true, true);
        }

        let entries = directory_entry_names(root)?;
        if entries.len() != 1
            || entries[0].as_slice() != TARGET_IDENTITY_ACTIVATION_GUARD_NAME.as_bytes()
        {
            return Err(
                "unversioned root contains custody evidence; activate this contract only on a fresh empty root",
            );
        }

        create_or_validate_target_identity_registration(root, target_key_sha256)?;
        validate_stable_root_namespace(root, false, false)?;
        maybe_pause_before_activation_marker_for_test(target_key_sha256);

        let marker_name = c_string_name(TARGET_IDENTITY_ACTIVATION_MARKER_NAME)?;
        let mut marker = open_at(
            root.as_raw_fd(),
            &marker_name,
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600,
        )
        .map_err(
            |_| "target-identity activation marker could not be created without replacement",
        )?;
        let metadata = marker
            .metadata()
            .map_err(|_| "target-identity activation marker identity is unavailable")?;
        if !private_file(&metadata) || metadata.nlink() != 1 {
            return Err("target-identity activation marker is not one private regular file");
        }
        marker
            .write_all(TARGET_IDENTITY_ACTIVATION_MARKER_BYTES)
            .and_then(|()| marker.sync_all())
            .map_err(|_| "target-identity activation marker could not be durably written")?;
        sync_d1_lease_directory(root)
            .map_err(|_| "target-identity activation marker directory could not be synchronized")?;
        validate_stable_root_namespace(root, true, true)
    }

    fn open_existing_guard(
        target: &fs::File,
    ) -> Result<(fs::File, D1LeaseFileIdentity), &'static str> {
        let named = open_named_entry(target, GUARD_NAME)
            .map_err(|_| "permanent target guard is absent or unavailable")?;
        let metadata = named
            .metadata()
            .map_err(|_| "permanent target guard metadata is unavailable")?;
        if !private_file(&metadata) {
            return Err("permanent target guard is not a private regular file");
        }
        let expected = identity(&metadata);
        let name = c_string_name(GUARD_NAME)?;
        let guard = open_at(
            target.as_raw_fd(),
            &name,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
        .map_err(|_| "permanent target guard could not be rebound")?;
        let held = guard
            .metadata()
            .map_err(|_| "held permanent target guard metadata is unavailable")?;
        if !private_file(&held) || identity(&held) != expected {
            return Err("permanent target guard changed while it was rebound");
        }
        Ok((guard, expected))
    }

    fn validate_named_private_file(
        target: &fs::File,
        name: &str,
        expected: &D1LeaseFileIdentity,
    ) -> Result<(), &'static str> {
        let named = open_named_entry(target, name)
            .map_err(|_| "target custody entry is unavailable through its held directory handle")?;
        let metadata = named
            .metadata()
            .map_err(|_| "target custody entry metadata is unavailable")?;
        if !private_file(&metadata) || identity(&metadata) != *expected {
            return Err("target custody entry is not this invocation's private regular file");
        }
        Ok(())
    }

    pub(super) fn validate_d1_lease_custody(
        root_path: &Path,
        root: &fs::File,
        root_identity: &D1LeaseFileIdentity,
        target_name: &str,
        target: &fs::File,
        target_identity: &D1LeaseFileIdentity,
        guard: &fs::File,
        guard_identity: &D1LeaseFileIdentity,
    ) -> Result<(), &'static str> {
        validate_root_path_binding(root_path, root, root_identity)?;
        validate_target_identity_root(root)?;
        validate_target_binding(root, target_name, target, target_identity)?;
        let target_key_sha256 = target_name
            .strip_prefix("d1-migration-target-")
            .filter(|value| valid_lower_sha256(value))
            .ok_or("held target custody namespace is not canonical")?;
        let audited_target =
            stable_target_directory_snapshot(root, target_name, target_key_sha256)?;
        if audited_target.directory_identity != *target_identity {
            return Err("audited target custody directory is not this invocation's directory");
        }
        let held_guard = guard
            .metadata()
            .map_err(|_| "held permanent target guard metadata is unavailable")?;
        if !private_file(&held_guard) || identity(&held_guard) != *guard_identity {
            return Err("held permanent target guard is no longer a private regular file");
        }
        validate_named_private_file(target, GUARD_NAME, guard_identity)
            .map_err(|_| "permanent target guard changed or is not a private regular file")?;
        Ok(())
    }

    fn read_held_file(file: &fs::File) -> Result<Vec<u8>, &'static str> {
        let metadata = file
            .metadata()
            .map_err(|_| "held lease file metadata is unavailable")?;
        if metadata.len() > MAX_LEASE_PAYLOAD_BYTES {
            return Err("held lease file payload exceeds the custody limit");
        }
        let len =
            usize::try_from(metadata.len()).map_err(|_| "held lease file payload is invalid")?;
        let mut bytes = vec![0; len];
        let mut offset = 0;
        while offset < bytes.len() {
            let read = file
                .read_at(&mut bytes[offset..], offset as u64)
                .map_err(|_| "held lease file cannot be read")?;
            if read == 0 {
                return Err("held lease file changed while it was read");
            }
            offset += read;
        }
        Ok(bytes)
    }

    pub(super) fn validate_owned_named_lease(
        target: &fs::File,
        name: &str,
        active: &fs::File,
        expected_file: &D1LeaseFileIdentity,
        expected: &D1MigrationLeaseIdentity,
        require_payload: bool,
    ) -> Result<(), &'static str> {
        let held = active
            .metadata()
            .map_err(|_| "held lease file metadata is unavailable")?;
        if !private_file(&held) || identity(&held) != *expected_file {
            return Err("held lease file no longer matches this invocation");
        }
        validate_named_private_file(target, name, expected_file)
            .map_err(|_| "lease file no longer matches this invocation")?;
        if !require_payload {
            return Ok(());
        }
        let bytes = read_held_file(active)?;
        if sha256_bytes_hex(&bytes) != expected.payload_sha256 {
            return Err("lease payload no longer matches this invocation");
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| "lease payload is no longer valid JSON")?;
        if value["version"] != json!(2)
            || value["target_key_sha256"] != json!(expected.target_key_sha256)
            || value["nonce"] != json!(expected.nonce)
            || value["approved_plan_sha256"].as_str().is_none()
        {
            return Err("lease payload no longer matches this invocation");
        }
        Ok(())
    }

    fn active_is_private_json(target: &fs::File, name: &str) -> bool {
        let named = match open_named_entry(target, name) {
            Ok(named) => named,
            Err(_) => return false,
        };
        let metadata = match named.metadata() {
            Ok(metadata)
                if private_file(&metadata) && metadata.len() <= MAX_LEASE_PAYLOAD_BYTES =>
            {
                metadata
            }
            _ => return false,
        };
        let name = match c_string_name(name) {
            Ok(name) => name,
            Err(_) => return false,
        };
        let file = match open_at(
            target.as_raw_fd(),
            &name,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC,
            0,
        ) {
            Ok(file) => file,
            Err(_) => return false,
        };
        if file
            .metadata()
            .ok()
            .is_none_or(|held| identity(&held) != identity(&metadata))
        {
            return false;
        }
        let bytes = read_held_file(&file).ok();
        bytes
            .as_deref()
            .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
            .is_some_and(|value| value.is_object())
    }

    pub(super) fn retained_entry_present(
        target: &fs::File,
        name: &str,
    ) -> Result<bool, &'static str> {
        entry_present(target, name)
    }

    fn valid_lower_sha256(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn valid_retained_nonce(value: &str) -> bool {
        valid_lower_sha256(value)
    }

    fn valid_retained_family(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
            })
    }

    fn parse_retained_lease_payload(
        bytes: &[u8],
    ) -> Result<D1RetainedMigrationLeasePayload, &'static str> {
        let payload: D1RetainedMigrationLeasePayload = serde_json::from_slice(bytes).map_err(
            |_| "retained lease payload is malformed, duplicate-keyed, or structurally unexpected",
        )?;
        let canonical: Value = serde_json::from_slice(bytes)
            .map_err(|_| "retained lease payload is not valid JSON")?;
        if serde_json::to_vec(&canonical)
            .ok()
            .as_deref()
            .is_none_or(|encoded| encoded != bytes)
        {
            return Err("retained lease payload is not exact canonical JSON");
        }
        if payload.version != 2
            || payload.created_at_unix_ms == 0
            || !valid_lower_sha256(&payload.target_key_sha256)
            || !valid_lower_sha256(&payload.approved_plan_sha256)
            || !valid_retained_nonce(&payload.nonce)
            || !valid_retained_family(&payload.migration_family)
            || payload
                .initializer_dispatch_protocol
                .as_deref()
                .is_some_and(|protocol| {
                    payload.migration_family != "migration-ledger-bootstrap-v1"
                        || protocol != D1_BOOTSTRAP_INITIALIZER_DISPATCH_PROTOCOL
                })
        {
            return Err("retained lease payload contains noncanonical authority fields");
        }
        Ok(payload)
    }

    pub(super) fn approved_plan_from_owned_lease(
        active: &fs::File,
    ) -> Result<String, &'static str> {
        let bytes = read_held_file(active)?;
        Ok(parse_retained_lease_payload(&bytes)?.approved_plan_sha256)
    }

    fn bootstrap_initializer_attempt_name(nonce: &str) -> String {
        format!("{BOOTSTRAP_INITIALIZER_ATTEMPT_PREFIX}{nonce}.receipt.json")
    }

    fn canonical_bootstrap_initializer_attempt_bytes(
        receipt: &D1BootstrapInitializerAttemptReceipt,
    ) -> Result<Vec<u8>, &'static str> {
        if receipt.version != 1
            || receipt.operation != "d1_bootstrap_migration_ledger"
            || !valid_lower_sha256(&receipt.target_key_sha256)
            || !valid_retained_nonce(&receipt.lease_nonce)
            || !valid_lower_sha256(&receipt.lease_payload_sha256)
            || !valid_lower_sha256(&receipt.approved_bootstrap_plan_sha256)
            || receipt.migration_family != "migration-ledger-bootstrap-v1"
            || receipt.dispatch_protocol != D1_BOOTSTRAP_INITIALIZER_DISPATCH_PROTOCOL
            || receipt.state != "attempt_authorized"
        {
            return Err(
                "bootstrap initializer-attempt receipt contains noncanonical authority fields",
            );
        }
        serde_json::to_vec(receipt)
            .map_err(|_| "bootstrap initializer-attempt receipt could not be encoded")
    }

    fn read_bootstrap_initializer_attempt(
        target: &fs::File,
        name: &str,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        let present = entry_present(target, name)?;
        if !present {
            return Ok(None);
        }
        let named = open_named_entry(target, name)
            .map_err(|_| "bootstrap initializer-attempt receipt could not be opened")?;
        let metadata = named
            .metadata()
            .map_err(|_| "bootstrap initializer-attempt receipt metadata is unavailable")?;
        if !private_file(&metadata)
            || metadata.nlink() != 1
            || metadata.len() > MAX_LEASE_PAYLOAD_BYTES
        {
            return Err(
                "bootstrap initializer-attempt receipt is not one bounded private regular file",
            );
        }
        let expected = identity(&metadata);
        let name_c = c_string_name(name)?;
        let file = open_at(
            target.as_raw_fd(),
            &name_c,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
        .map_err(|_| "bootstrap initializer-attempt receipt could not be rebound")?;
        let held = file
            .metadata()
            .map_err(|_| "held bootstrap initializer-attempt receipt metadata is unavailable")?;
        if !private_file(&held) || held.nlink() != 1 || identity(&held) != expected {
            return Err("bootstrap initializer-attempt receipt changed while it was rebound");
        }
        read_held_file(&file).map(Some)
    }

    pub(super) fn persist_bootstrap_initializer_attempt(
        target: &fs::File,
        receipt: &D1BootstrapInitializerAttemptReceipt,
    ) -> Result<(), &'static str> {
        let bytes = canonical_bootstrap_initializer_attempt_bytes(receipt)?;
        let name = bootstrap_initializer_attempt_name(&receipt.lease_nonce);
        if read_bootstrap_initializer_attempt(target, &name)?.is_some() {
            return Err(
                "bootstrap initializer-attempt receipt already exists; initializer replay is forbidden",
            );
        }
        if directory_entry_names(target)?.len() >= MAX_TARGET_CUSTODY_DIRECTORY_ENTRIES {
            return Err(
                "target custody directory has no capacity for initializer-attempt authority",
            );
        }
        let name_c = c_string_name(&name)?;
        let mut file = open_at(
            target.as_raw_fd(),
            &name_c,
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600,
        )
        .map_err(
            |_| "bootstrap initializer-attempt receipt could not be created without replacement",
        )?;
        let metadata = file
            .metadata()
            .map_err(|_| "bootstrap initializer-attempt receipt identity is unavailable")?;
        if !private_file(&metadata) || metadata.nlink() != 1 {
            return Err(
                "bootstrap initializer-attempt receipt is not one private unaliased regular file",
            );
        }
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "bootstrap initializer-attempt receipt could not be durably written")?;
        sync_d1_lease_directory(target).map_err(
            |_| "bootstrap initializer-attempt receipt directory could not be synchronized",
        )?;
        let readback = read_bootstrap_initializer_attempt(target, &name)?
            .ok_or("bootstrap initializer-attempt receipt disappeared after persistence")?;
        if readback != bytes {
            return Err("bootstrap initializer-attempt receipt contradicted exact readback");
        }
        Ok(())
    }

    pub(super) fn prove_bootstrap_initializer_attempt_absent(
        target: &fs::File,
        identity: &D1RetainedMigrationLeaseIdentity,
    ) -> Result<(), &'static str> {
        let name = bootstrap_initializer_attempt_name(&identity.nonce);
        let first = read_bootstrap_initializer_attempt(target, &name)?;
        let second = read_bootstrap_initializer_attempt(target, &name)?;
        match (first, second) {
            (None, None) => Ok(()),
            (Some(first), Some(second)) if first == second => {
                let receipt: D1BootstrapInitializerAttemptReceipt = serde_json::from_slice(&first)
                    .map_err(|_| "bootstrap initializer-attempt evidence is malformed or duplicate-keyed")?;
                let canonical = canonical_bootstrap_initializer_attempt_bytes(&receipt)?;
                if canonical != first
                    || receipt.target_key_sha256 != identity.target_key_sha256
                    || receipt.lease_nonce != identity.nonce
                    || receipt.lease_payload_sha256 != identity.payload_sha256
                    || receipt.approved_bootstrap_plan_sha256 != identity.approved_plan_sha256
                {
                    return Err(
                        "bootstrap initializer-attempt evidence contradicts retained custody",
                    );
                }
                Err(
                    "a bootstrap initializer attempt was durably authorized; zero-dispatch retirement is forbidden",
                )
            }
            _ => Err("bootstrap initializer-attempt evidence changed during stable readback"),
        }
    }

    fn open_retained_named_lease(
        target: &fs::File,
        name: &str,
    ) -> Result<(fs::File, D1LeaseFileIdentity, Vec<u8>), &'static str> {
        let named = open_named_entry(target, name)
            .map_err(|_| "retained lease namespace entry could not be opened")?;
        let metadata = named
            .metadata()
            .map_err(|_| "retained lease namespace metadata is unavailable")?;
        if !private_file(&metadata) || metadata.nlink() != 1 {
            return Err("retained lease namespace entry is not one private unaliased regular file");
        }
        if metadata.len() > MAX_LEASE_PAYLOAD_BYTES {
            return Err("retained lease payload exceeds the custody limit");
        }
        let expected = identity(&metadata);
        let name_c = c_string_name(name)?;
        let file = open_at(
            target.as_raw_fd(),
            &name_c,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
        .map_err(|_| "retained lease namespace entry could not be rebound read-only")?;
        let held = file
            .metadata()
            .map_err(|_| "held retained lease metadata is unavailable")?;
        if !private_file(&held) || held.nlink() != 1 || identity(&held) != expected {
            return Err("retained lease namespace entry changed while it was rebound");
        }
        let bytes = read_held_file(&file)?;
        Ok((file, expected, bytes))
    }

    pub(super) fn validate_retained_named_lease(
        target: &fs::File,
        name: &str,
        evidence: &fs::File,
        expected_file: &D1LeaseFileIdentity,
        expected: &D1RetainedMigrationLeaseIdentity,
    ) -> Result<(), &'static str> {
        let held = evidence
            .metadata()
            .map_err(|_| "held retained lease metadata is unavailable")?;
        if !private_file(&held) || held.nlink() != 1 || identity(&held) != *expected_file {
            return Err("held retained lease no longer matches its private regular file");
        }
        validate_named_private_file(target, name, expected_file)
            .map_err(|_| "retained lease namespace entry no longer matches the held file")?;
        let bytes = read_held_file(evidence)?;
        if sha256_bytes_hex(&bytes) != expected.payload_sha256 {
            return Err("retained lease payload digest changed");
        }
        let payload = parse_retained_lease_payload(&bytes)?;
        if payload.target_key_sha256 != expected.target_key_sha256
            || payload.nonce != expected.nonce
            || payload.approved_plan_sha256 != expected.approved_plan_sha256
        {
            return Err("retained lease payload authority changed");
        }
        Ok(())
    }

    fn terminal_receipt_name(nonce: &str) -> String {
        format!("terminal-reconciliation.{nonce}.receipt.json")
    }

    fn canonical_terminal_receipt_bytes(
        receipt: &D1TerminalReconciliationReceipt,
    ) -> Result<Vec<u8>, &'static str> {
        if receipt.version != 2
            || !valid_terminal_receipt_authority(receipt)
            || !valid_lower_sha256(&receipt.target_key_sha256)
            || !valid_retained_nonce(&receipt.lease_nonce)
            || !valid_lower_sha256(&receipt.lease_payload_sha256)
            || !valid_lower_sha256(&receipt.approved_apply_plan_sha256)
            || !valid_lower_sha256(&receipt.reconciliation_plan_sha256)
            || !valid_lower_sha256(&receipt.expectation_proof_sha256)
            || !valid_lower_sha256(&receipt.query_sha256)
            || !valid_lower_sha256(&receipt.canonical_snapshot_sha256)
            || !valid_lower_sha256(&receipt.terminal_request_sha256)
            || !valid_lower_sha256(&receipt.terminal_attempt_sha256)
            || receipt.terminal_request_sha256 == receipt.terminal_attempt_sha256
            || !valid_lower_sha256(&receipt.terminal_plan_sha256)
            || !valid_receipt_outcome_prefixes(
                &receipt.outcome,
                receipt.original_prefix_length,
                receipt.current_prefix_length,
            )
        {
            return Err("terminal reconciliation receipt contains noncanonical authority fields");
        }
        serde_json::to_vec(receipt)
            .map_err(|_| "terminal reconciliation receipt could not be encoded canonically")
    }

    fn canonical_terminal_receipt_v1_bytes(
        receipt: &D1TerminalReconciliationReceiptV1,
    ) -> Result<Vec<u8>, &'static str> {
        if receipt.version != 1
            || receipt.operation != "d1_finalize_migration_reconciliation"
            || !valid_lower_sha256(&receipt.target_key_sha256)
            || !valid_retained_nonce(&receipt.lease_nonce)
            || !valid_lower_sha256(&receipt.lease_payload_sha256)
            || !valid_lower_sha256(&receipt.approved_apply_plan_sha256)
            || !valid_lower_sha256(&receipt.reconciliation_plan_sha256)
            || !valid_lower_sha256(&receipt.expectation_proof_sha256)
            || !valid_lower_sha256(&receipt.query_sha256)
            || !valid_lower_sha256(&receipt.canonical_snapshot_sha256)
            || !valid_lower_sha256(&receipt.terminal_request_sha256)
            || !valid_lower_sha256(&receipt.terminal_attempt_sha256)
            || receipt.terminal_request_sha256 == receipt.terminal_attempt_sha256
            || !valid_lower_sha256(&receipt.terminal_plan_sha256)
            || !valid_receipt_outcome_prefixes(
                &receipt.outcome,
                receipt.original_prefix_length,
                receipt.current_prefix_length,
            )
        {
            return Err("terminal reconciliation receipt contains noncanonical authority fields");
        }
        serde_json::to_vec(receipt)
            .map_err(|_| "terminal reconciliation receipt could not be encoded canonically")
    }

    enum ParsedTerminalReceipt {
        V1(D1TerminalReconciliationReceiptV1),
        V2(D1TerminalReconciliationReceipt),
    }

    fn parse_canonical_terminal_receipt(
        bytes: &[u8],
    ) -> Result<ParsedTerminalReceipt, &'static str> {
        if let Ok(receipt) = serde_json::from_slice::<D1TerminalReconciliationReceipt>(bytes) {
            let canonical = canonical_terminal_receipt_bytes(&receipt)?;
            if canonical != bytes {
                return Err("terminal reconciliation receipt is not exact canonical JSON");
            }
            return Ok(ParsedTerminalReceipt::V2(receipt));
        }
        let receipt: D1TerminalReconciliationReceiptV1 = serde_json::from_slice(bytes).map_err(
            |_| {
                "terminal reconciliation receipt is malformed, duplicate-keyed, or structurally unexpected"
            },
        )?;
        let canonical = canonical_terminal_receipt_v1_bytes(&receipt)?;
        if canonical != bytes {
            return Err("terminal reconciliation receipt is not exact canonical JSON");
        }
        Ok(ParsedTerminalReceipt::V1(receipt))
    }

    fn open_terminal_receipt(
        target: &fs::File,
        name: &str,
    ) -> Result<D1TerminalReconciliationReceiptEvidence, &'static str> {
        let named = open_named_entry(target, name)
            .map_err(|_| "terminal reconciliation receipt could not be opened")?;
        let metadata = named
            .metadata()
            .map_err(|_| "terminal reconciliation receipt metadata is unavailable")?;
        if !private_file(&metadata) || metadata.nlink() != 1 {
            return Err(
                "terminal reconciliation receipt is not one private unaliased regular file",
            );
        }
        if metadata.len() > MAX_LEASE_PAYLOAD_BYTES {
            return Err("terminal reconciliation receipt exceeds the custody limit");
        }
        let expected = identity(&metadata);
        let name_c = c_string_name(name)?;
        let file = open_at(
            target.as_raw_fd(),
            &name_c,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
        .map_err(|_| "terminal reconciliation receipt could not be rebound read-only")?;
        let held = file
            .metadata()
            .map_err(|_| "held terminal reconciliation receipt metadata is unavailable")?;
        if !private_file(&held) || held.nlink() != 1 || identity(&held) != expected {
            return Err("terminal reconciliation receipt changed while it was rebound");
        }
        let bytes = read_held_file(&file)?;
        let parsed = parse_canonical_terminal_receipt(&bytes)?;
        let (receipt_version, effect_assertion_id, target_key_sha256, lease_nonce) = match parsed {
            ParsedTerminalReceipt::V1(receipt) => (
                1,
                "schema_create_only_v1".to_string(),
                receipt.target_key_sha256,
                receipt.lease_nonce,
            ),
            ParsedTerminalReceipt::V2(receipt) => (
                2,
                receipt.effect_assertion_id,
                receipt.target_key_sha256,
                receipt.lease_nonce,
            ),
        };
        Ok(D1TerminalReconciliationReceiptEvidence {
            file,
            file_identity: expected,
            name: name.to_string(),
            payload_sha256: sha256_bytes_hex(&bytes),
            receipt_version,
            effect_assertion_id,
            target_key_sha256,
            lease_nonce,
        })
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TerminalReceiptNamespaceEntry {
        name: String,
        file_identity: D1LeaseFileIdentity,
        payload_sha256: String,
        receipt_version: u8,
        effect_assertion_id: String,
        target_key_sha256: String,
        lease_nonce: String,
    }

    fn terminal_receipt_namespace_snapshot(
        target: &fs::File,
        expected_target_key_sha256: &str,
    ) -> Result<Vec<TerminalReceiptNamespaceEntry>, &'static str> {
        let mut receipts = Vec::new();
        for name in directory_entry_names(target)? {
            if !name.starts_with(TERMINAL_RECEIPT_PREFIX.as_bytes()) {
                continue;
            }
            let name = String::from_utf8(name)
                .map_err(|_| "terminal reconciliation receipt namespace is not valid UTF-8")?;
            let nonce = name
                .strip_prefix(TERMINAL_RECEIPT_PREFIX)
                .and_then(|value| value.strip_suffix(TERMINAL_RECEIPT_SUFFIX))
                .filter(|value| valid_retained_nonce(value))
                .ok_or(
                    "terminal reconciliation receipt namespace contains an unclassifiable sibling",
                )?;
            let evidence = open_terminal_receipt(target, &name)?;
            if evidence.target_key_sha256 != expected_target_key_sha256
                || evidence.lease_nonce != nonce
            {
                return Err(
                    "terminal reconciliation receipt sibling contradicts its target or filename identity",
                );
            }
            receipts.push(TerminalReceiptNamespaceEntry {
                name,
                file_identity: evidence.file_identity,
                payload_sha256: evidence.payload_sha256,
                receipt_version: evidence.receipt_version,
                effect_assertion_id: evidence.effect_assertion_id,
                target_key_sha256: evidence.target_key_sha256,
                lease_nonce: evidence.lease_nonce,
            });
        }
        receipts.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(receipts)
    }

    fn receipt_matches_namespace_entry(
        evidence: &D1TerminalReconciliationReceiptEvidence,
        entry: &TerminalReceiptNamespaceEntry,
    ) -> bool {
        evidence.name == entry.name
            && evidence.file_identity == entry.file_identity
            && evidence.payload_sha256 == entry.payload_sha256
            && evidence.receipt_version == entry.receipt_version
            && evidence.effect_assertion_id == entry.effect_assertion_id
            && evidence.target_key_sha256 == entry.target_key_sha256
            && evidence.lease_nonce == entry.lease_nonce
    }

    pub(super) fn same_terminal_receipt_evidence(
        left: &D1TerminalReconciliationReceiptEvidence,
        right: &D1TerminalReconciliationReceiptEvidence,
    ) -> bool {
        left.name == right.name
            && left.file_identity == right.file_identity
            && left.payload_sha256 == right.payload_sha256
            && left.receipt_version == right.receipt_version
            && left.effect_assertion_id == right.effect_assertion_id
            && left.target_key_sha256 == right.target_key_sha256
            && left.lease_nonce == right.lease_nonce
    }

    pub(super) fn validate_stable_terminal_receipt_evidence(
        target: &fs::File,
        evidence: &D1TerminalReconciliationReceiptEvidence,
    ) -> Result<(), &'static str> {
        let first = terminal_receipt_namespace_snapshot(target, &evidence.target_key_sha256)?;
        let first_entry = first
            .iter()
            .find(|entry| entry.name == evidence.name)
            .ok_or("exact terminal reconciliation receipt is absent from its namespace")?;
        if !receipt_matches_namespace_entry(evidence, first_entry) {
            return Err("terminal reconciliation receipt namespace contradicts the held evidence");
        }
        validate_terminal_receipt_evidence(target, evidence)?;
        let second = terminal_receipt_namespace_snapshot(target, &evidence.target_key_sha256)?;
        if first != second {
            return Err("terminal reconciliation receipt namespace changed during stable readback");
        }
        let second_entry = second
            .iter()
            .find(|entry| entry.name == evidence.name)
            .ok_or("exact terminal reconciliation receipt is absent from its namespace")?;
        if !receipt_matches_namespace_entry(evidence, second_entry) {
            return Err("terminal reconciliation receipt namespace contradicts the held evidence");
        }
        validate_terminal_receipt_evidence(target, evidence)
    }

    pub(super) fn validate_terminal_receipt_evidence(
        target: &fs::File,
        evidence: &D1TerminalReconciliationReceiptEvidence,
    ) -> Result<(), &'static str> {
        let held = evidence
            .file
            .metadata()
            .map_err(|_| "held terminal reconciliation receipt metadata is unavailable")?;
        if !private_file(&held) || held.nlink() != 1 || identity(&held) != evidence.file_identity {
            return Err("held terminal reconciliation receipt is no longer exact");
        }
        validate_named_private_file(target, &evidence.name, &evidence.file_identity)
            .map_err(|_| "terminal reconciliation receipt namespace changed")?;
        let bytes = read_held_file(&evidence.file)?;
        if sha256_bytes_hex(&bytes) != evidence.payload_sha256 {
            return Err("terminal reconciliation receipt payload changed");
        }
        parse_canonical_terminal_receipt(&bytes)
            .map_err(|_| "terminal reconciliation receipt payload is not canonical")?;
        Ok(())
    }

    pub(super) fn terminal_receipt_state(
        target: &fs::File,
        expected: &D1TerminalReconciliationReceipt,
    ) -> Result<Option<D1TerminalReconciliationReceiptEvidence>, &'static str> {
        let expected_bytes = canonical_terminal_receipt_bytes(expected)?;
        let name = terminal_receipt_name(&expected.lease_nonce);
        let first = terminal_receipt_namespace_snapshot(target, &expected.target_key_sha256)?;
        let Some(first_entry) = first.iter().find(|entry| entry.name == name) else {
            let second = terminal_receipt_namespace_snapshot(target, &expected.target_key_sha256)?;
            if first != second || second.iter().any(|entry| entry.name == name) {
                return Err(
                    "terminal reconciliation receipt namespace changed during stable absence readback",
                );
            }
            return Ok(None);
        };
        let evidence = open_terminal_receipt(target, &name)?;
        if !receipt_matches_namespace_entry(&evidence, first_entry) {
            return Err(
                "terminal reconciliation receipt changed after its initial namespace readback",
            );
        }
        let actual = read_held_file(&evidence.file)?;
        if actual != expected_bytes {
            return Err(
                "terminal reconciliation receipt contradicts the exact request or evidence",
            );
        }
        validate_stable_terminal_receipt_evidence(target, &evidence)?;
        Ok(Some(evidence))
    }

    pub(super) fn compatible_terminal_receipt_state(
        target: &fs::File,
        expected: &D1TerminalReconciliationReceipt,
        legacy_expected: Option<&D1TerminalReconciliationReceiptV1>,
    ) -> Result<Option<D1TerminalReconciliationReceiptEvidence>, &'static str> {
        let expected_bytes = canonical_terminal_receipt_bytes(expected)?;
        let legacy_expected_bytes = legacy_expected
            .map(canonical_terminal_receipt_v1_bytes)
            .transpose()?;
        let name = terminal_receipt_name(&expected.lease_nonce);
        let first = terminal_receipt_namespace_snapshot(target, &expected.target_key_sha256)?;
        let Some(first_entry) = first.iter().find(|entry| entry.name == name) else {
            let second = terminal_receipt_namespace_snapshot(target, &expected.target_key_sha256)?;
            if first != second || second.iter().any(|entry| entry.name == name) {
                return Err(
                    "terminal reconciliation receipt namespace changed during stable absence readback",
                );
            }
            return Ok(None);
        };
        let evidence = open_terminal_receipt(target, &name)?;
        if !receipt_matches_namespace_entry(&evidence, first_entry) {
            return Err(
                "terminal reconciliation receipt changed after its initial namespace readback",
            );
        }
        let actual = read_held_file(&evidence.file)?;
        let exact_current = actual == expected_bytes;
        let exact_legacy = legacy_expected_bytes
            .as_ref()
            .is_some_and(|legacy| actual == *legacy);
        if !exact_current && !exact_legacy {
            return Err(
                "terminal reconciliation receipt contradicts the exact request or evidence",
            );
        }
        validate_stable_terminal_receipt_evidence(target, &evidence)?;
        Ok(Some(evidence))
    }

    pub(super) fn persist_terminal_receipt(
        target: &fs::File,
        expected: &D1TerminalReconciliationReceipt,
    ) -> Result<(D1TerminalReconciliationReceiptEvidence, bool), TerminalReceiptPersistenceFailure>
    {
        if let Some(existing) = terminal_receipt_state(target, expected)
            .map_err(TerminalReceiptPersistenceFailure::before_create)?
        {
            return Ok((existing, false));
        }
        let bytes = canonical_terminal_receipt_bytes(expected)
            .map_err(TerminalReceiptPersistenceFailure::before_create)?;
        let name = terminal_receipt_name(&expected.lease_nonce);
        let name_c =
            c_string_name(&name).map_err(TerminalReceiptPersistenceFailure::before_create)?;
        if directory_entry_names(target)
            .map_err(TerminalReceiptPersistenceFailure::before_create)?
            .len()
            >= MAX_TARGET_CUSTODY_DIRECTORY_ENTRIES
        {
            return Err(TerminalReceiptPersistenceFailure::before_create(
                "target custody directory has no capacity for a terminal reconciliation receipt",
            ));
        }
        maybe_pause_terminal_receipt_pre_create_for_test(&expected.lease_nonce);
        let mut file = match open_at(
            target.as_raw_fd(),
            &name_c,
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return match terminal_receipt_state(target, expected) {
                    Ok(Some(existing)) => Ok((existing, false)),
                    Ok(None) => Err(TerminalReceiptPersistenceFailure::before_create(
                        "terminal reconciliation receipt namespace changed after the exclusive-create race",
                    )),
                    Err(message) => Err(TerminalReceiptPersistenceFailure::before_create(message)),
                };
            }
            Err(_) => {
                return Err(TerminalReceiptPersistenceFailure::before_create(
                    "terminal reconciliation receipt could not be created without replacement",
                ));
            }
        };
        let metadata = file.metadata().map_err(|_| {
            TerminalReceiptPersistenceFailure::after_create(
                "terminal reconciliation receipt identity is unavailable",
            )
        })?;
        if !private_file(&metadata) || metadata.nlink() != 1 {
            return Err(TerminalReceiptPersistenceFailure::after_create(
                "terminal reconciliation receipt is not one private unaliased regular file",
            ));
        }
        if file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            return Err(TerminalReceiptPersistenceFailure::after_create(
                "terminal reconciliation receipt could not be durably written",
            ));
        }
        if sync_d1_lease_directory(target).is_err() {
            return Err(TerminalReceiptPersistenceFailure::after_create(
                "terminal reconciliation receipt directory could not be synchronized",
            ));
        }
        let file_identity = identity(&metadata);
        let evidence = D1TerminalReconciliationReceiptEvidence {
            file,
            file_identity,
            name,
            payload_sha256: sha256_bytes_hex(&bytes),
            receipt_version: expected.version,
            effect_assertion_id: expected.effect_assertion_id.clone(),
            target_key_sha256: expected.target_key_sha256.clone(),
            lease_nonce: expected.lease_nonce.clone(),
        };
        validate_stable_terminal_receipt_evidence(target, &evidence)
            .map_err(TerminalReceiptPersistenceFailure::after_create)?;
        Ok((evidence, true))
    }

    fn active_present_error(target: &fs::File, target_key_sha256: &str) -> CallToolResult {
        let valid = active_is_private_json(target, ACTIVE_LEASE_NAME);
        let code = if valid {
            "d1.migration_target_lease_held"
        } else {
            "d1.migration_target_lease_unreconciled"
        };
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest", "status": if valid { "lease_held" } else { "reconciliation_required" }, "lease_retained": true,
            "lease": {"target_key_sha256": target_key_sha256, "ownership": "active_or_unreadable"},
            "operator_handoff": "Reconcile the permanent active target lease and its terminal provider evidence through the governed recovery path before another apply. The MCP never auto-reclaims active evidence.",
            "error": {"code": code, "message": "this account/database target already has active migration custody evidence", "hint": "Do not run another migration family against this target until the active evidence is reconciled through the governed recovery path."}
        }))
    }

    fn retiring_present_error(target_key_sha256: &str) -> CallToolResult {
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required", "lease_retained": true,
            "lease": {"target_key_sha256": target_key_sha256, "ownership": "retiring"},
            "operator_handoff": "A prior terminal retirement did not complete cleanly. Reconcile the permanent retiring evidence through the governed recovery path before another apply.",
            "error": {"code": "d1.migration_target_retirement_unreconciled", "message": "this account/database target has retiring migration custody evidence", "hint": "Do not run another migration family against this target until the retiring evidence is reconciled through the governed recovery path."}
        }))
    }

    fn rename_at_no_replace(target: &fs::File, source: &str, destination: &str) -> io::Result<()> {
        let source = c_string_name(source).map_err(io::Error::other)?;
        let destination = c_string_name(destination).map_err(io::Error::other)?;
        let result = unsafe {
            renameat2(
                target.as_raw_fd(),
                source.as_ptr(),
                target.as_raw_fd(),
                destination.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn rename_owned_lease_no_replace(
        target: &fs::File,
        source: &str,
        destination: &str,
        active: &fs::File,
        expected_file: &D1LeaseFileIdentity,
        expected: &D1MigrationLeaseIdentity,
    ) -> Result<(), &'static str> {
        validate_owned_named_lease(target, source, active, expected_file, expected, true)?;
        rename_at_no_replace(target, source, destination)
            .map_err(|_| "owned lease namespace transition could not be completed")
    }

    pub(super) fn rename_retained_lease_no_replace(
        target: &fs::File,
        source: &str,
        destination: &str,
        evidence: &fs::File,
        expected_file: &D1LeaseFileIdentity,
        expected: &D1RetainedMigrationLeaseIdentity,
    ) -> Result<(), &'static str> {
        validate_retained_named_lease(target, source, evidence, expected_file, expected)?;
        rename_at_no_replace(target, source, destination)
            .map_err(|_| "retained lease namespace transition could not be completed")
    }

    pub(super) fn abort_owned_active(
        target: &fs::File,
        active: &fs::File,
        expected_file: &D1LeaseFileIdentity,
        identity: &D1MigrationLeaseIdentity,
    ) -> bool {
        let destination = format!("aborted-create.{}.lease.json", identity.nonce);
        validate_owned_named_lease(
            target,
            ACTIVE_LEASE_NAME,
            active,
            expected_file,
            identity,
            false,
        )
        .is_ok()
            && rename_at_no_replace(target, ACTIVE_LEASE_NAME, &destination).is_ok()
            && sync_d1_lease_directory(target).is_ok()
    }

    pub(super) fn restore_active_or_leave_blocker(
        target: &fs::File,
        source: &str,
        active: &fs::File,
        expected_file: &D1LeaseFileIdentity,
        identity: &D1MigrationLeaseIdentity,
    ) -> bool {
        if rename_owned_lease_no_replace(
            target,
            source,
            ACTIVE_LEASE_NAME,
            active,
            expected_file,
            identity,
        )
        .is_ok()
        {
            return sync_d1_lease_directory(target).is_ok();
        }
        if source != RETIRING_LEASE_NAME {
            let _ = rename_owned_lease_no_replace(
                target,
                source,
                RETIRING_LEASE_NAME,
                active,
                expected_file,
                identity,
            );
            let _ = sync_d1_lease_directory(target);
        }
        false
    }

    fn create_failure(
        target: &fs::File,
        active: &fs::File,
        active_identity: &D1LeaseFileIdentity,
        identity: &D1MigrationLeaseIdentity,
        code: &'static str,
        message: &'static str,
    ) -> CallToolResult {
        let aborted = abort_owned_active(target, active, active_identity, identity);
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required", "lease_retained": !aborted, "lease": identity,
            "operator_handoff": if aborted { "Creation was terminally recorded as aborted; begin again only with a fresh dry-run plan." } else { "Creation may have left active or retiring evidence; reconcile the named custody entry through the governed recovery path before another apply." },
            "error": {"code": code, "message": message, "hint": "No provider write was attempted by this failed custody creation."}
        }))
    }

    fn create_active(
        root_path: &Path,
        root: fs::File,
        root_identity: D1LeaseFileIdentity,
        target_name: String,
        target: fs::File,
        target_identity: D1LeaseFileIdentity,
        guard: fs::File,
        guard_identity: D1LeaseFileIdentity,
        identity: D1MigrationLeaseIdentity,
        dml_custody_authorization:
            crate::d1_dml_custody_layout::D1DmlCustodyCompleteAuditAuthorization,
        payload: &[u8],
        bootstrap_initializer_dispatch_protocol: bool,
    ) -> Result<D1MigrationLease, CallToolResult> {
        validate_d1_lease_custody(
            root_path,
            &root,
            &root_identity,
            &target_name,
            &target,
            &target_identity,
            &guard,
            &guard_identity,
        )
        .map_err(|message| d1_lease_root_error("d1.migration_lease_custody_changed", message))?;
        match entry_present(&target, ACTIVE_LEASE_NAME) {
            Ok(true) => return Err(active_present_error(&target, &identity.target_key_sha256)),
            Ok(false) => {}
            Err(message) => {
                return Err(d1_lease_root_error(
                    "d1.migration_lease_custody_changed",
                    message,
                ));
            }
        }
        match entry_present(&target, RETIRING_LEASE_NAME) {
            Ok(true) => return Err(retiring_present_error(&identity.target_key_sha256)),
            Ok(false) => {}
            Err(message) => {
                return Err(d1_lease_root_error(
                    "d1.migration_lease_custody_changed",
                    message,
                ));
            }
        }
        let current_dml_custody_authorization = authorize_target_wide_d1_dml_custody(
            &target,
            &dml_custody_authorization.custody_authority(),
        )
        .map_err(|message| {
            d1_migration_dml_custody_error("d1.migration_dml_custody_unproven", message)
        })?;
        if current_dml_custody_authorization != dml_custody_authorization {
            return Err(d1_migration_dml_custody_error(
                "d1.migration_dml_custody_changed",
                "complete DML custody changed before active migration authority was persisted",
            ));
        }

        let name = c_string_name(ACTIVE_LEASE_NAME)
            .expect("active lease filename is a static valid C string");
        let mut active = match open_at(
            target.as_raw_fd(),
            &name,
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600,
        ) {
            Ok(active) => active,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(active_present_error(&target, &identity.target_key_sha256));
            }
            Err(_) => {
                return Err(CallToolResult::structured_error(json!({
                    "ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required", "lease_retained": false,
                    "error": {"code": "d1.migration_lease_create_failed", "message": "active migration lease could not be created", "hint": "Inspect the permanent target custody directory before retrying."}
                })));
            }
        };
        let metadata = active.metadata().map_err(|_| {
            CallToolResult::structured_error(json!({
                "ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required", "lease_retained": true,
                "error": {"code": "d1.migration_lease_create_identity_failed", "message": "active migration lease identity could not be established", "hint": "Reconcile the active custody entry through the governed recovery path before another apply."}
            }))
        })?;
        let active_identity = D1LeaseFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        if !private_file(&metadata)
            || active
                .set_permissions(fs::Permissions::from_mode(0o600))
                .is_err()
        {
            return Err(create_failure(
                &target,
                &active,
                &active_identity,
                &identity,
                "d1.migration_lease_create_identity_failed",
                "active migration lease is not a private regular file",
            ));
        }
        if active
            .write_all(payload)
            .and_then(|()| active.sync_all())
            .is_err()
        {
            return Err(create_failure(
                &target,
                &active,
                &active_identity,
                &identity,
                "d1.migration_lease_create_write_failed",
                "active migration lease could not be durably written",
            ));
        }
        if sync_d1_lease_directory(&target).is_err() {
            return Err(create_failure(
                &target,
                &active,
                &active_identity,
                &identity,
                "d1.migration_lease_create_sync_failed",
                "active migration lease directory could not be durably synchronized",
            ));
        }
        if validate_owned_named_lease(
            &target,
            ACTIVE_LEASE_NAME,
            &active,
            &active_identity,
            &identity,
            true,
        )
        .is_err()
            || validate_d1_lease_custody(
                root_path,
                &root,
                &root_identity,
                &target_name,
                &target,
                &target_identity,
                &guard,
                &guard_identity,
            )
            .is_err()
        {
            return Err(create_failure(
                &target,
                &active,
                &active_identity,
                &identity,
                "d1.migration_lease_create_readback_failed",
                "active migration lease could not be read back as this invocation's private regular evidence",
            ));
        }
        Ok(D1MigrationLease {
            root_path: root_path.to_path_buf(),
            root,
            root_identity,
            target_name,
            target,
            target_identity,
            guard: Some(guard),
            guard_identity,
            active,
            active_file_identity: active_identity,
            released: false,
            dml_custody_authorization,
            bootstrap_initializer_dispatch_protocol,
            identity,
        })
    }

    pub(super) fn preflight_d1_migration_target_custody_at_linux(
        root_path: PathBuf,
        account_id: &str,
        database_id: &str,
    ) -> Result<(), CallToolResult> {
        validate_root_and_ancestors(&root_path)
            .map_err(|message| d1_lease_root_error("d1.migration_lease_root_unsafe", message))?;
        let root_name = c_string_path(&root_path)
            .map_err(|message| d1_lease_root_error("d1.migration_lease_root_unsafe", message))?;
        let root = open_directory_at(AT_FDCWD, &root_name).map_err(|_| {
            d1_lease_root_error(
                "d1.migration_lease_root_unsafe",
                "configured migration lease root could not be opened without following a symlink",
            )
        })?;
        let root_metadata = root.metadata().map_err(|_| {
            d1_lease_root_error(
                "d1.migration_lease_root_unsafe",
                "configured migration lease root metadata is unavailable",
            )
        })?;
        if !private_dir(&root_metadata) {
            return Err(d1_lease_root_error(
                "d1.migration_lease_root_unsafe",
                "configured migration lease root is not a private current-operator-owned directory",
            ));
        }
        let root_identity = identity(&root_metadata);
        validate_root_path_binding(&root_path, &root, &root_identity)
            .map_err(|message| d1_lease_root_error("d1.migration_lease_root_unsafe", message))?;

        let target_hash = sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes());
        let target_name = format!("d1-migration-target-{target_hash}");
        let target_name_c = c_string_name(&target_name)
            .map_err(|message| d1_lease_root_error("d1.migration_lease_target_unsafe", message))?;
        let target = match open_directory_at(root.as_raw_fd(), &target_name_c) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => {
                return Err(d1_lease_root_error(
                    "d1.migration_lease_target_unsafe",
                    "existing migration target custody directory could not be opened without following a symlink",
                ));
            }
        };
        let target_metadata = target.metadata().map_err(|_| {
            d1_lease_root_error(
                "d1.migration_lease_target_unsafe",
                "existing migration target custody metadata is unavailable",
            )
        })?;
        if !private_dir(&target_metadata) {
            return Err(d1_lease_root_error(
                "d1.migration_lease_target_unsafe",
                "existing migration target is not a private current-operator-owned directory",
            ));
        }
        let target_identity = identity(&target_metadata);
        let (guard, guard_identity) = open_existing_guard(&target)
            .map_err(|message| d1_lease_root_error("d1.migration_lease_guard_unsafe", message))?;
        match guard.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(CallToolResult::structured_error(json!({
                    "ok": false, "operation": "d1_apply_migration_manifest", "status": "lease_held", "lease_retained": true,
                    "lease": {"target_key_sha256": target_hash, "ownership": "guard_locked"},
                    "operator_handoff": "Another process is evaluating or applying this target. Do not issue provider SQL from a concurrent migration call.",
                    "error": {"code": "d1.migration_target_guard_locked", "message": "another MCP process holds the permanent target guard", "hint": "Wait for its terminal result or reconcile its active evidence before retrying."}
                })));
            }
            Err(fs::TryLockError::Error(_)) => {
                return Err(d1_lease_root_error(
                    "d1.migration_lease_guard_lock_failed",
                    "permanent target guard could not be locked",
                ));
            }
        }
        validate_d1_lease_custody(
            &root_path,
            &root,
            &root_identity,
            &target_name,
            &target,
            &target_identity,
            &guard,
            &guard_identity,
        )
        .map_err(|message| d1_lease_root_error("d1.migration_lease_custody_changed", message))?;
        match entry_present(&target, ACTIVE_LEASE_NAME) {
            Ok(true) => return Err(active_present_error(&target, &target_hash)),
            Ok(false) => {}
            Err(message) => {
                return Err(d1_lease_root_error(
                    "d1.migration_lease_custody_changed",
                    message,
                ));
            }
        }
        match entry_present(&target, RETIRING_LEASE_NAME) {
            Ok(true) => return Err(retiring_present_error(&target_hash)),
            Ok(false) => Ok(()),
            Err(message) => Err(d1_lease_root_error(
                "d1.migration_lease_custody_changed",
                message,
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn inspect_retained_d1_migration_lease_at_linux(
        root_path: PathBuf,
        account_id: &str,
        database_id: &str,
        family: &str,
        approved_plan_sha256: &str,
        nonce: &str,
        payload_sha256: &str,
        allow_retired: bool,
    ) -> Result<D1RetainedMigrationLease, CallToolResult> {
        if !valid_retained_family(family)
            || !valid_lower_sha256(approved_plan_sha256)
            || !valid_retained_nonce(nonce)
            || !valid_lower_sha256(payload_sha256)
        {
            return Err(d1_retained_lease_error(
                "d1.migration_reconciliation_identity_invalid",
                "caller-supplied retained lease identity is not canonical",
            ));
        }
        validate_root_and_ancestors(&root_path).map_err(|message| {
            d1_retained_lease_error("d1.migration_reconciliation_lease_root_unsafe", message)
        })?;
        let root_name = c_string_path(&root_path).map_err(|message| {
            d1_retained_lease_error("d1.migration_reconciliation_lease_root_unsafe", message)
        })?;
        let root = open_directory_at(AT_FDCWD, &root_name).map_err(|_| {
            d1_retained_lease_error(
                "d1.migration_reconciliation_lease_root_unsafe",
                "configured migration lease root could not be opened without following a symlink",
            )
        })?;
        let root_metadata = root.metadata().map_err(|_| {
            d1_retained_lease_error(
                "d1.migration_reconciliation_lease_root_unsafe",
                "configured migration lease root metadata is unavailable",
            )
        })?;
        if !private_dir(&root_metadata) {
            return Err(d1_retained_lease_error(
                "d1.migration_reconciliation_lease_root_unsafe",
                "configured migration lease root is not a private current-operator-owned directory",
            ));
        }
        let root_identity = identity(&root_metadata);
        validate_root_path_binding(&root_path, &root, &root_identity).map_err(|message| {
            d1_retained_lease_error("d1.migration_reconciliation_lease_root_unsafe", message)
        })?;

        let target_hash = sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes());
        let target_name = format!("d1-migration-target-{target_hash}");
        let target_name_c = c_string_name(&target_name).map_err(|message| {
            d1_retained_lease_error("d1.migration_reconciliation_target_unsafe", message)
        })?;
        let target = open_directory_at(root.as_raw_fd(), &target_name_c).map_err(|_| {
            d1_retained_lease_error(
                "d1.migration_reconciliation_evidence_absent",
                "the exact account/database target has no retained migration custody directory",
            )
        })?;
        let target_metadata = target.metadata().map_err(|_| {
            d1_retained_lease_error(
                "d1.migration_reconciliation_target_unsafe",
                "retained migration target metadata is unavailable",
            )
        })?;
        if !private_dir(&target_metadata) {
            return Err(d1_retained_lease_error(
                "d1.migration_reconciliation_target_unsafe",
                "retained migration target is not a private current-operator-owned directory",
            ));
        }
        let target_identity = identity(&target_metadata);
        let (guard, guard_identity) = open_existing_guard(&target).map_err(|message| {
            d1_retained_lease_error("d1.migration_reconciliation_guard_unsafe", message)
        })?;
        match guard.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(d1_retained_lease_error(
                    "d1.migration_reconciliation_guard_locked",
                    "another process holds the permanent migration target guard",
                ));
            }
            Err(fs::TryLockError::Error(_)) => {
                return Err(d1_retained_lease_error(
                    "d1.migration_reconciliation_guard_lock_failed",
                    "the permanent migration target guard could not be locked",
                ));
            }
        }
        validate_d1_lease_custody(
            &root_path,
            &root,
            &root_identity,
            &target_name,
            &target,
            &target_identity,
            &guard,
            &guard_identity,
        )
        .map_err(|message| {
            d1_retained_lease_error("d1.migration_reconciliation_custody_changed", message)
        })?;

        let active_present = entry_present(&target, ACTIVE_LEASE_NAME).map_err(|message| {
            d1_retained_lease_error("d1.migration_reconciliation_custody_changed", message)
        })?;
        let retiring_present = entry_present(&target, RETIRING_LEASE_NAME).map_err(|message| {
            d1_retained_lease_error("d1.migration_reconciliation_custody_changed", message)
        })?;
        let retired_name = format!("retired.{nonce}.lease.json");
        let retired_present = entry_present(&target, &retired_name).map_err(|message| {
            d1_retained_lease_error("d1.migration_reconciliation_custody_changed", message)
        })?;
        let (evidence_name, namespace) = match (active_present, retiring_present, retired_present) {
            (true, false, false) => (ACTIVE_LEASE_NAME.to_string(), "active".to_string()),
            (false, true, false) => (RETIRING_LEASE_NAME.to_string(), "retiring".to_string()),
            (false, false, true) if allow_retired => (retired_name, "retired".to_string()),
            (false, false, false) => {
                return Err(d1_retained_lease_error(
                    "d1.migration_reconciliation_evidence_absent",
                    "neither active nor retiring retained migration evidence is present",
                ));
            }
            _ => {
                return Err(d1_retained_lease_error(
                    "d1.migration_reconciliation_evidence_conflict",
                    "active, retiring, or terminal-retired migration evidence conflicts",
                ));
            }
        };
        let (evidence, evidence_file_identity, bytes) =
            open_retained_named_lease(&target, &evidence_name).map_err(|message| {
                d1_retained_lease_error("d1.migration_reconciliation_evidence_malformed", message)
            })?;
        let computed_payload_sha256 = sha256_bytes_hex(&bytes);
        let payload = parse_retained_lease_payload(&bytes).map_err(|message| {
            d1_retained_lease_error("d1.migration_reconciliation_evidence_malformed", message)
        })?;
        if computed_payload_sha256 != payload_sha256
            || payload.target_key_sha256 != target_hash
            || payload.migration_family != family
            || payload.approved_plan_sha256 != approved_plan_sha256
            || payload.nonce != nonce
        {
            return Err(d1_retained_lease_error(
                "d1.migration_reconciliation_evidence_contradictory",
                "retained lease target, family, plan, nonce, or payload digest contradicts the exact caller identity",
            ));
        }
        let current_dml_custody_authorization = authorize_target_wide_d1_dml_custody(
            &target,
            &payload.dml_custody_authorization.custody_authority(),
        )
        .map_err(d1_retained_lease_revalidation_error)?;
        if payload.dml_custody_authorization != current_dml_custody_authorization {
            return Err(d1_retained_lease_error(
                "d1.migration_reconciliation_dml_custody_changed",
                "complete DML custody no longer matches the authority bound into the retained lease",
            ));
        }
        let identity = D1RetainedMigrationLeaseIdentity {
            target_key_sha256: target_hash,
            namespace,
            nonce: nonce.to_string(),
            payload_sha256: payload_sha256.to_string(),
            approved_plan_sha256: approved_plan_sha256.to_string(),
        };
        let lease = D1RetainedMigrationLease {
            root_path,
            root,
            root_identity,
            target_name,
            target,
            target_identity,
            guard,
            guard_identity,
            evidence,
            evidence_file_identity,
            evidence_name,
            dml_custody_authorization: payload.dml_custody_authorization,
            bootstrap_initializer_dispatch_protocol: payload
                .initializer_dispatch_protocol
                .as_deref()
                == Some(D1_BOOTSTRAP_INITIALIZER_DISPATCH_PROTOCOL),
            identity,
        };
        lease.revalidate()?;
        Ok(lease)
    }

    pub(super) fn provision_d1_dml_custody_at_linux(
        root_path: PathBuf,
        canonical_target: D1TargetIdentity,
        expected_authority: crate::d1_dml_custody_genesis::D1DmlCustodyAuthority,
        genesis_bytes: &[u8],
    ) -> Result<D1DmlCustodyProvisionReceipt, CallToolResult> {
        let operation = "d1_provision_dml_custody";
        let target_hash = canonical_target.target_key_sha256();
        validate_root_and_ancestors(&root_path).map_err(|message| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_root_unsafe",
                message,
                &target_hash,
            )
        })?;
        let root_name = c_string_path(&root_path).map_err(|message| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_root_unsafe",
                message,
                &target_hash,
            )
        })?;
        let root = open_directory_at(AT_FDCWD, &root_name).map_err(|_| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_root_unsafe",
                "configured target guard root could not be opened without following a symlink",
                &target_hash,
            )
        })?;
        let root_metadata = root.metadata().map_err(|_| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_root_unsafe",
                "configured target guard root metadata is unavailable",
                &target_hash,
            )
        })?;
        if !private_dir(&root_metadata) {
            return Err(d1_target_guard_error(
                operation,
                "d1.target_guard_root_unsafe",
                "configured target guard root is not a private current-operator-owned directory",
                &target_hash,
            ));
        }
        let root_identity = identity(&root_metadata);
        validate_root_path_binding(&root_path, &root, &root_identity).map_err(|message| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_root_unsafe",
                message,
                &target_hash,
            )
        })?;
        ensure_target_identity_activation(&root, &target_hash).map_err(|message| {
            d1_target_identity_activation_error(operation, message, &target_hash)
        })?;
        let target_name = format!("d1-migration-target-{target_hash}");
        let (target, target_identity) =
            ensure_target_directory(&root, &target_name).map_err(|message| {
                d1_target_guard_error(
                    operation,
                    "d1.target_guard_target_unsafe",
                    message,
                    &target_hash,
                )
            })?;
        let (guard, guard_identity) = open_or_create_guard(&target).map_err(|message| {
            d1_target_guard_error(operation, "d1.target_guard_unsafe", message, &target_hash)
        })?;
        guard.lock().map_err(|_| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_lock_failed",
                "the permanent account/database target guard could not be locked",
                &target_hash,
            )
        })?;
        validate_d1_lease_custody(
            &root_path,
            &root,
            &root_identity,
            &target_name,
            &target,
            &target_identity,
            &guard,
            &guard_identity,
        )
        .map_err(|message| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_custody_changed",
                message,
                &target_hash,
            )
        })?;

        let genesis_name = crate::d1_dml_custody_genesis::D1_DML_CUSTODY_GENESIS_NAME;
        let genesis_present = entry_present(&target, genesis_name).map_err(|message| {
            d1_target_guard_error(
                operation,
                "d1.dml_custody_genesis_unproven",
                message,
                &target_hash,
            )
        })?;
        let layout_present = entry_present(
            &target,
            crate::d1_dml_custody_layout::D1_DML_CUSTODY_LAYOUT_NAME,
        )
        .map_err(|message| {
            d1_target_guard_error(
                operation,
                "d1.dml_custody_layout_unproven",
                message,
                &target_hash,
            )
        })?;
        if layout_present && !genesis_present {
            return Err(d1_target_guard_error(
                operation,
                "d1.dml_custody_orphan_layout",
                "D1 custody layout existed without immutable genesis",
                &target_hash,
            ));
        }
        let mut created = false;
        if genesis_present {
            let (_, incumbent) =
                private_custody_file_snapshot(&target, genesis_name).map_err(|message| {
                    d1_target_guard_error(
                        operation,
                        "d1.dml_custody_genesis_unproven",
                        message,
                        &target_hash,
                    )
                })?;
            if incumbent != genesis_bytes
                || !crate::d1_dml_custody_genesis::validate_d1_dml_custody_genesis(
                    &incumbent,
                    &expected_authority,
                )
            {
                return Err(d1_target_guard_error(
                    operation,
                    "d1.dml_custody_provision_conflict",
                    "incumbent D1 custody genesis conflicted with the exact provision request",
                    &target_hash,
                ));
            }
        } else {
            create_private_dml_state(&target, genesis_name, genesis_bytes).map_err(|message| {
                d1_target_guard_error(
                    operation,
                    "d1.dml_custody_genesis_create_failed",
                    message,
                    &target_hash,
                )
            })?;
            created = true;
        }
        let layout_outcome =
            ensure_d1_dml_custody_layout(&target, &expected_authority).map_err(|message| {
                d1_target_guard_error(
                    operation,
                    "d1.dml_custody_layout_create_failed",
                    message,
                    &target_hash,
                )
            })?;
        created |= matches!(
            layout_outcome,
            crate::d1_dml_custody_layout::D1DmlCustodyLayoutEnsureOutcome::Created
        );
        open_existing_d1_dml_custody(&target, &expected_authority).map_err(|message| {
            d1_target_guard_error(
                operation,
                "d1.dml_custody_provision_readback_failed",
                message,
                &target_hash,
            )
        })?;
        validate_d1_lease_custody(
            &root_path,
            &root,
            &root_identity,
            &target_name,
            &target,
            &target_identity,
            &guard,
            &guard_identity,
        )
        .map_err(|message| {
            d1_target_guard_error(
                operation,
                "d1.dml_custody_provision_readback_failed",
                message,
                &target_hash,
            )
        })?;
        Ok(D1DmlCustodyProvisionReceipt {
            version: 1,
            operation,
            apply_status: if created {
                MutationApplyStatus::Applied
            } else {
                MutationApplyStatus::Proven
            },
            target_key_sha256: expected_authority.target_key_sha256.clone(),
            layout_version: expected_authority.layout_version,
            layout_sha256: expected_authority.layout_sha256.clone(),
            custody_generation_sha256: expected_authority.custody_generation_sha256.clone(),
            authority_sha256: expected_authority.authority_sha256.clone(),
            genesis_sha256: expected_authority.genesis_sha256.clone(),
            provider_calls: 0,
            provider_mutations: 0,
        })
    }

    pub(super) fn acquire_d1_target_mutation_guard_at_linux(
        root_path: PathBuf,
        operation: &'static str,
        canonical_target: D1TargetIdentity,
        expected_authority: crate::d1_dml_custody_genesis::D1DmlCustodyAuthority,
    ) -> Result<D1TargetMutationGuard, CallToolResult> {
        let target_hash = canonical_target.target_key_sha256();
        validate_root_and_ancestors(&root_path).map_err(|message| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_root_unsafe",
                message,
                &target_hash,
            )
        })?;
        let root_name = c_string_path(&root_path).map_err(|message| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_root_unsafe",
                message,
                &target_hash,
            )
        })?;
        let root = open_directory_at(AT_FDCWD, &root_name).map_err(|_| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_root_unsafe",
                "configured target guard root could not be opened without following a symlink",
                &target_hash,
            )
        })?;
        let root_metadata = root.metadata().map_err(|_| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_root_unsafe",
                "configured target guard root metadata is unavailable",
                &target_hash,
            )
        })?;
        if !private_dir(&root_metadata) {
            return Err(d1_target_guard_error(
                operation,
                "d1.target_guard_root_unsafe",
                "configured target guard root is not a private current-operator-owned directory",
                &target_hash,
            ));
        }
        let root_identity = identity(&root_metadata);
        validate_root_path_binding(&root_path, &root, &root_identity).map_err(|message| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_root_unsafe",
                message,
                &target_hash,
            )
        })?;
        validate_target_identity_root(&root).map_err(|message| {
            d1_target_identity_activation_error(operation, message, &target_hash)
        })?;
        validate_target_identity_registration(
            &root,
            &target_identity_registration_name(&target_hash),
            &target_hash,
        )
        .map_err(|message| d1_target_identity_activation_error(operation, message, &target_hash))?;

        let target_name = format!("d1-migration-target-{target_hash}");
        let (target, target_identity) = open_existing_target_directory(&root, &target_name)
            .map_err(|message| {
                d1_target_guard_error(
                    operation,
                    "d1.target_guard_target_unsafe",
                    message,
                    &target_hash,
                )
            })?;
        let (guard, guard_identity) = open_existing_guard(&target).map_err(|message| {
            d1_target_guard_error(operation, "d1.target_guard_unsafe", message, &target_hash)
        })?;
        match guard.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(d1_target_guard_error(
                    operation,
                    "d1.target_guard_locked",
                    "another MCP process holds the permanent account/database target guard",
                    &target_hash,
                ));
            }
            Err(fs::TryLockError::Error(_)) => {
                return Err(d1_target_guard_error(
                    operation,
                    "d1.target_guard_lock_failed",
                    "the permanent account/database target guard could not be locked",
                    &target_hash,
                ));
            }
        }
        validate_d1_lease_custody(
            &root_path,
            &root,
            &root_identity,
            &target_name,
            &target,
            &target_identity,
            &guard,
            &guard_identity,
        )
        .map_err(|message| {
            d1_target_guard_error(
                operation,
                "d1.target_guard_custody_changed",
                message,
                &target_hash,
            )
        })?;
        maybe_pause_after_guard_for_test(&root_path);
        open_existing_d1_dml_custody(&target, &expected_authority).map_err(|message| {
            d1_target_guard_error(
                operation,
                "d1.dml_custody_genesis_unproven",
                message,
                &target_hash,
            )
        })?;
        for (name, message) in [
            (
                ACTIVE_LEASE_NAME,
                "active retained D1 mutation evidence blocks a new target mutation",
            ),
            (
                RETIRING_LEASE_NAME,
                "retiring retained D1 mutation evidence blocks a new target mutation",
            ),
        ] {
            match entry_present(&target, name) {
                Ok(true) => {
                    return Err(d1_target_guard_error(
                        operation,
                        "d1.target_guard_retained_evidence_present",
                        message,
                        &target_hash,
                    ));
                }
                Ok(false) => {}
                Err(message) => {
                    return Err(d1_target_guard_error(
                        operation,
                        "d1.target_guard_custody_changed",
                        message,
                        &target_hash,
                    ));
                }
            }
        }

        Ok(D1TargetMutationGuard {
            operation,
            canonical_target,
            root_path,
            root,
            root_identity,
            target_name,
            target,
            target_identity,
            guard,
            guard_identity,
            target_key_sha256: target_hash,
            dml_custody_authority: expected_authority,
        })
    }

    pub(super) fn acquire_d1_migration_lease_at_linux(
        root_path: PathBuf,
        account_id: &str,
        database_id: &str,
        family: &str,
        plan_sha256: &str,
        expected_authority: crate::d1_dml_custody_genesis::D1DmlCustodyAuthority,
    ) -> Result<D1MigrationLease, CallToolResult> {
        validate_root_and_ancestors(&root_path)
            .map_err(|message| d1_lease_root_error("d1.migration_lease_root_unsafe", message))?;
        let root_name = c_string_path(&root_path)
            .map_err(|message| d1_lease_root_error("d1.migration_lease_root_unsafe", message))?;
        let root = open_directory_at(AT_FDCWD, &root_name).map_err(|_| {
            d1_lease_root_error(
                "d1.migration_lease_root_unsafe",
                "configured migration lease root could not be opened without following a symlink",
            )
        })?;
        let root_metadata = root.metadata().map_err(|_| {
            d1_lease_root_error(
                "d1.migration_lease_root_unsafe",
                "configured migration lease root metadata is unavailable",
            )
        })?;
        if !private_dir(&root_metadata) {
            return Err(d1_lease_root_error(
                "d1.migration_lease_root_unsafe",
                "configured migration lease root is not a private current-operator-owned directory",
            ));
        }
        let root_identity = identity(&root_metadata);
        validate_root_path_binding(&root_path, &root, &root_identity)
            .map_err(|message| d1_lease_root_error("d1.migration_lease_root_unsafe", message))?;
        let target_hash = sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes());
        validate_target_identity_root(&root)
            .map_err(d1_migration_target_identity_activation_error)?;
        validate_target_identity_registration(
            &root,
            &target_identity_registration_name(&target_hash),
            &target_hash,
        )
        .map_err(d1_migration_target_identity_activation_error)?;

        let target_name = format!("d1-migration-target-{target_hash}");
        let (target, target_identity) = open_existing_target_directory(&root, &target_name)
            .map_err(|message| d1_lease_root_error("d1.migration_lease_target_unsafe", message))?;
        let (guard, guard_identity) = open_existing_guard(&target)
            .map_err(|message| d1_lease_root_error("d1.migration_lease_guard_unsafe", message))?;
        match guard.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(CallToolResult::structured_error(json!({
                    "ok": false, "operation": "d1_apply_migration_manifest", "status": "lease_held", "lease_retained": true,
                    "lease": {"target_key_sha256": target_hash, "ownership": "guard_locked"},
                    "operator_handoff": "Another process is evaluating or applying this target. Do not issue provider SQL from a concurrent migration call.",
                    "error": {"code": "d1.migration_target_guard_locked", "message": "another MCP process holds the permanent target guard", "hint": "Wait for its terminal result or reconcile its active evidence before retrying."}
                })));
            }
            Err(fs::TryLockError::Error(_)) => {
                return Err(d1_lease_root_error(
                    "d1.migration_lease_guard_lock_failed",
                    "permanent target guard could not be locked",
                ));
            }
        }
        validate_d1_lease_custody(
            &root_path,
            &root,
            &root_identity,
            &target_name,
            &target,
            &target_identity,
            &guard,
            &guard_identity,
        )
        .map_err(|message| d1_lease_root_error("d1.migration_lease_custody_changed", message))?;
        maybe_pause_after_guard_for_test(&root_path);
        open_existing_d1_dml_custody(&target, &expected_authority).map_err(|message| {
            d1_migration_dml_custody_error("d1.migration_dml_custody_layout_unavailable", message)
        })?;
        let dml_custody_authorization =
            authorize_target_wide_d1_dml_custody(&target, &expected_authority).map_err(
                |message| {
                    d1_migration_dml_custody_error("d1.migration_dml_custody_unproven", message)
                },
            )?;
        let nonce = d1_migration_lease_nonce(&target_hash, plan_sha256);
        let bootstrap_initializer_dispatch_protocol = family == "migration-ledger-bootstrap-v1";
        let mut payload = json!({"version": 2, "target_key_sha256": &target_hash, "nonce": &nonce, "approved_plan_sha256": plan_sha256, "migration_family": family, "created_at_unix_ms": now_unix_ms(), "dml_custody_authorization": &dml_custody_authorization});
        if bootstrap_initializer_dispatch_protocol {
            payload["initializer_dispatch_protocol"] =
                json!(D1_BOOTSTRAP_INITIALIZER_DISPATCH_PROTOCOL);
        }
        let encoded =
            serde_json::to_vec(&payload).expect("serializing lease payload is infallible");
        let identity = D1MigrationLeaseIdentity {
            target_key_sha256: target_hash,
            nonce,
            payload_sha256: sha256_bytes_hex(&encoded),
        };
        create_active(
            &root_path,
            root,
            root_identity,
            target_name,
            target,
            target_identity,
            guard,
            guard_identity,
            identity,
            dml_custody_authorization,
            &encoded,
            bootstrap_initializer_dispatch_protocol,
        )
    }

    pub(super) fn sync_d1_lease_directory(directory: &fs::File) -> io::Result<()> {
        #[cfg(test)]
        if FAIL_NEXT_DIRECTORY_SYNC.with(|fail| fail.replace(false)) {
            return Err(io::Error::other("forced directory sync failure"));
        }
        directory.sync_all()
    }

    fn valid_dml_digest(digest: &str) -> bool {
        digest.len() == 64
            && digest
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'))
    }

    fn create_private_dml_directory(
        parent: &fs::File,
        name: &str,
    ) -> Result<fs::File, &'static str> {
        let name_c = c_string_name(name)?;
        if unsafe { mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
            return Err("DML custody directory could not be created exclusively");
        }
        sync_d1_lease_directory(parent)
            .map_err(|_| "DML custody parent directory could not be synchronized")?;
        open_private_dml_directory(parent, name).map(|(directory, _)| directory)
    }

    fn create_dml_layout_tree(
        target: &fs::File,
        scratch_name: &str,
        authority: &crate::d1_dml_custody_genesis::D1DmlCustodyAuthority,
    ) -> Result<(), &'static str> {
        let layout = create_private_dml_directory(target, scratch_name)?;
        let marker = crate::d1_dml_custody_layout::canonical_layout_marker_bytes(authority);
        create_private_dml_state(
            &layout,
            crate::d1_dml_custody_layout::D1_DML_CUSTODY_LAYOUT_MARKER_NAME,
            &marker,
        )?;
        let claimant = create_private_dml_directory(&layout, "claimant")?;
        for namespace in crate::d1_dml_identity_claimant::D1DmlIdentityNamespace::ALL {
            create_private_dml_directory(&claimant, namespace.filename_label())?;
        }
        create_private_dml_directory(&layout, "attempt")?;
        sync_d1_lease_directory(&layout)
            .map_err(|_| "DML custody layout could not be synchronized")?;
        Ok(())
    }

    pub(super) fn ensure_d1_dml_custody_layout(
        target: &fs::File,
        authority: &crate::d1_dml_custody_genesis::D1DmlCustodyAuthority,
    ) -> Result<crate::d1_dml_custody_layout::D1DmlCustodyLayoutEnsureOutcome, &'static str> {
        use crate::d1_dml_custody_layout::{
            D1_DML_CUSTODY_LAYOUT_NAME, D1DmlCustodyLayoutEnsureOutcome,
        };
        if entry_present(target, D1_DML_CUSTODY_LAYOUT_NAME)? {
            d1_dml_layout_snapshot(target, authority)?;
            return Ok(D1DmlCustodyLayoutEnsureOutcome::AlreadyPresent);
        }
        if directory_entry_names(target)?.len() >= MAX_TARGET_CUSTODY_DIRECTORY_ENTRIES {
            return Err("target custody namespace has no capacity for the DML layout");
        }
        let scratch = ".dml-custody-v1.init";
        create_dml_layout_tree(target, scratch, authority)?;
        rename_at_no_replace(target, scratch, D1_DML_CUSTODY_LAYOUT_NAME)
            .map_err(|_| "DML custody layout could not be installed without replacement")?;
        sync_d1_lease_directory(target).map_err(
            |_| "target custody directory could not be synchronized after DML layout installation",
        )?;
        d1_dml_layout_snapshot(target, authority)?;
        Ok(D1DmlCustodyLayoutEnsureOutcome::Created)
    }

    pub(super) fn open_existing_d1_dml_custody(
        target: &fs::File,
        expected: &crate::d1_dml_custody_genesis::D1DmlCustodyAuthority,
    ) -> Result<(), &'static str> {
        let (_, genesis_bytes) = private_custody_file_snapshot(
            target,
            crate::d1_dml_custody_genesis::D1_DML_CUSTODY_GENESIS_NAME,
        )?;
        if !crate::d1_dml_custody_genesis::validate_d1_dml_custody_genesis(&genesis_bytes, expected)
        {
            return Err("D1 custody genesis did not match configured generation authority");
        }
        d1_dml_layout_snapshot(target, expected)?;
        let (_, second_genesis_bytes) = private_custody_file_snapshot(
            target,
            crate::d1_dml_custody_genesis::D1_DML_CUSTODY_GENESIS_NAME,
        )?;
        if second_genesis_bytes != genesis_bytes {
            return Err("D1 custody genesis changed while layout authority was opened");
        }
        d1_dml_layout_snapshot(target, expected)?;
        Ok(())
    }

    fn d1_dml_attempt_name(binding: &str) -> Result<String, &'static str> {
        if !valid_dml_digest(binding) {
            return Err("DML attempt binding was not canonical SHA-256");
        }
        Ok(format!("{binding}.json"))
    }

    fn d1_dml_identity_claimant_name(
        _namespace: crate::d1_dml_identity_claimant::D1DmlIdentityNamespace,
        identity_sha256: &str,
    ) -> Result<String, &'static str> {
        if !valid_dml_digest(identity_sha256) {
            return Err("DML identity claimant digest was not canonical SHA-256");
        }
        Ok(format!("{identity_sha256}.json"))
    }

    #[derive(Clone, Copy)]
    pub(super) enum DmlLeafKind {
        Claimant(crate::d1_dml_identity_claimant::D1DmlIdentityNamespace),
        Attempt,
    }

    fn open_dml_family_directory(
        target: &fs::File,
        kind: DmlLeafKind,
    ) -> Result<fs::File, &'static str> {
        let (layout, _) = open_private_dml_directory(
            target,
            crate::d1_dml_custody_layout::D1_DML_CUSTODY_LAYOUT_NAME,
        )?;
        match kind {
            DmlLeafKind::Attempt => open_private_dml_directory(&layout, "attempt").map(|v| v.0),
            DmlLeafKind::Claimant(namespace) => {
                let (claimant, _) = open_private_dml_directory(&layout, "claimant")?;
                open_private_dml_directory(&claimant, namespace.filename_label()).map(|v| v.0)
            }
        }
    }

    fn open_or_create_dml_shard(parent: &fs::File, name: &str) -> Result<fs::File, &'static str> {
        match open_private_dml_directory(parent, name) {
            Ok((directory, _)) => Ok(directory),
            Err(_) if !entry_present(parent, name)? => create_private_dml_directory(parent, name),
            Err(_) => Err("DML shard entry was not one canonical private directory"),
        }
    }

    pub(super) fn open_dml_leaf(
        target: &fs::File,
        kind: DmlLeafKind,
        digest: &str,
        create: bool,
    ) -> Result<Option<fs::File>, &'static str> {
        if !valid_dml_digest(digest) {
            return Err("DML custody digest was not canonical SHA-256");
        }
        let family = open_dml_family_directory(target, kind)?;
        let first = &digest[..2];
        let second = &digest[2..4];
        let level_one = if create {
            open_or_create_dml_shard(&family, first)?
        } else if !entry_present(&family, first)? {
            return Ok(None);
        } else {
            open_private_dml_directory(&family, first)?.0
        };
        let leaf = if create {
            open_or_create_dml_shard(&level_one, second)?
        } else if !entry_present(&level_one, second)? {
            return Ok(None);
        } else {
            open_private_dml_directory(&level_one, second)?.0
        };
        Ok(Some(leaf))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DmlScratchAudit {
        name: String,
        record_sha256: String,
        predecessor_sha256: String,
        successor_sha256: String,
        file_identity: D1LeaseFileIdentity,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DmlLeafAudit {
        entry_count: usize,
        scratches: BTreeMap<String, DmlScratchAudit>,
        artifacts: BTreeMap<String, Vec<u8>>,
    }

    #[derive(Debug, Clone, Copy)]
    struct DmlCompleteAuditLimits {
        leaf_limit: usize,
        artifact_limit: usize,
        payload_byte_limit: usize,
    }

    impl DmlCompleteAuditLimits {
        const fn fixed() -> Self {
            Self {
                leaf_limit: crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_LEAF_LIMIT,
                artifact_limit:
                    crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_ARTIFACT_LIMIT,
                payload_byte_limit:
                    crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_PAYLOAD_BYTE_LIMIT,
            }
        }

        fn identity_sha256(self) -> String {
            sha256_bytes_hex(
                format!(
                    "d1-dml-complete-audit-budget-v{}|canonical_leaf_limit={}|physical_artifact_limit={}|artifact_payload_byte_limit={}",
                    crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_VERSION,
                    self.leaf_limit,
                    self.artifact_limit,
                    self.payload_byte_limit,
                )
                .as_bytes(),
            )
        }
    }

    #[derive(Debug)]
    struct DmlCompleteAuditBudget {
        limits: DmlCompleteAuditLimits,
        audited_leaf_count: usize,
        physical_artifact_count: usize,
        artifact_payload_bytes: usize,
    }

    impl DmlCompleteAuditBudget {
        fn new(limits: DmlCompleteAuditLimits) -> Self {
            Self {
                limits,
                audited_leaf_count: 0,
                physical_artifact_count: 0,
                artifact_payload_bytes: 0,
            }
        }

        fn reserve_leaf(&mut self) -> Result<(), &'static str> {
            self.audited_leaf_count = self
                .audited_leaf_count
                .checked_add(1)
                .filter(|count| *count <= self.limits.leaf_limit)
                .ok_or("DML complete audit exceeded its canonical-leaf budget")?;
            Ok(())
        }

        fn reserve_artifacts(&mut self, count: usize) -> Result<(), &'static str> {
            self.physical_artifact_count = self
                .physical_artifact_count
                .checked_add(count)
                .filter(|total| *total <= self.limits.artifact_limit)
                .ok_or("DML complete audit exceeded its physical-artifact budget")?;
            Ok(())
        }

        fn remaining_payload_bytes(&self) -> usize {
            self.limits
                .payload_byte_limit
                .saturating_sub(self.artifact_payload_bytes)
        }

        fn record_payload_bytes(&mut self, count: usize) -> Result<(), &'static str> {
            self.artifact_payload_bytes = self
                .artifact_payload_bytes
                .checked_add(count)
                .filter(|total| *total <= self.limits.payload_byte_limit)
                .ok_or("DML complete audit exceeded its artifact-payload byte budget")?;
            Ok(())
        }

        fn retain_cross_shard_entry(&self, current_len: usize) -> Result<(), &'static str> {
            if current_len >= self.limits.artifact_limit {
                return Err("DML complete audit exceeded its retained-evidence budget");
            }
            Ok(())
        }
    }

    #[derive(Serialize)]
    struct DmlCompleteAuditDigest<'a> {
        version: u8,
        layout_sha256: &'a str,
        audit_budget_version: u8,
        audit_budget_sha256: &'a str,
        audited_leaf_limit: usize,
        physical_artifact_limit: usize,
        artifact_payload_byte_limit: usize,
        audited_leaf_count: usize,
        physical_artifact_count: usize,
        artifact_payload_bytes: usize,
        target_key_sha256: &'a str,
        custody_generation_sha256: &'a str,
        authority_sha256: &'a str,
        genesis_sha256: &'a str,
        claimant_count: usize,
        attempt_count: usize,
        attempt_phase_counts: crate::d1_dml_custody_layout::D1DmlCustodyAttemptPhaseCounts,
        pending_claimant_count: usize,
        bound_claimant_count: usize,
        cas_scratch_count: usize,
        claimant_set_count: usize,
        complete_claimant_set_count: usize,
        matched_claimant_set_count: usize,
        unmatched_claimant_set_count: usize,
        unmatched_attempt_count: usize,
        orphan_claimant_set_count: usize,
        incomplete_claimant_set_count: usize,
        reconciliation_required: bool,
        provider_dispatch_authority:
            crate::d1_dml_custody_layout::D1DmlCustodyAuditProviderAuthority,
        artifact_evidence: &'a [(String, String)],
    }

    fn parse_dml_scratch_name(name: &str) -> Option<(&str, &str, &str)> {
        let value = name.strip_prefix(".next.")?.strip_suffix(".json")?;
        let mut parts = value.split('.');
        let record = parts.next()?;
        let predecessor = parts.next()?;
        let successor = parts.next()?;
        (parts.next().is_none()
            && valid_dml_digest(record)
            && valid_dml_digest(predecessor)
            && valid_dml_digest(successor))
        .then_some((record, predecessor, successor))
    }

    fn audit_dml_leaf(
        leaf: &fs::File,
        kind: DmlLeafKind,
        prefix: &str,
        target_key_sha256: &str,
    ) -> Result<DmlLeafAudit, &'static str> {
        audit_dml_leaf_inner(leaf, kind, prefix, target_key_sha256, None)
    }

    fn audit_dml_leaf_with_complete_budget(
        leaf: &fs::File,
        kind: DmlLeafKind,
        prefix: &str,
        target_key_sha256: &str,
        budget: &mut DmlCompleteAuditBudget,
    ) -> Result<DmlLeafAudit, &'static str> {
        audit_dml_leaf_inner(leaf, kind, prefix, target_key_sha256, Some(budget))
    }

    fn audit_dml_leaf_inner(
        leaf: &fs::File,
        kind: DmlLeafKind,
        prefix: &str,
        target_key_sha256: &str,
        mut complete_budget: Option<&mut DmlCompleteAuditBudget>,
    ) -> Result<DmlLeafAudit, &'static str> {
        let mut names = directory_entry_names(leaf)?;
        names.sort();
        if let Some(budget) = complete_budget.as_deref_mut() {
            budget.reserve_artifacts(names.len())?;
        }
        let mut artifacts = BTreeMap::new();
        let mut scratch_candidates = Vec::new();
        for raw_name in &names {
            let name = std::str::from_utf8(raw_name)
                .map_err(|_| "DML custody leaf contained a non-UTF-8 entry")?;
            let (digest, scratch_binding) =
                if let Some((record, predecessor, successor)) = parse_dml_scratch_name(name) {
                    (record, Some((predecessor, successor)))
                } else if let Some(digest) = name
                    .strip_suffix(".json")
                    .filter(|value| valid_dml_digest(value))
                {
                    (digest, None)
                } else {
                    return Err("DML custody leaf contained an unknown entry");
                };
            if &digest[..4] != prefix {
                return Err("DML custody artifact was placed in a non-canonical shard");
            }
            let payload_limit = complete_budget
                .as_deref()
                .map(DmlCompleteAuditBudget::remaining_payload_bytes);
            let (file_identity, bytes) =
                read_private_dml_state_snapshot_with_payload_limit(leaf, name, payload_limit)?
                    .ok_or("DML custody artifact disappeared during leaf audit")?;
            if let Some(budget) = complete_budget.as_deref_mut() {
                budget.record_payload_bytes(bytes.len())?;
            }
            if scratch_binding.is_some_and(|(_, successor)| sha256_bytes_hex(&bytes) != successor) {
                return Err("DML CAS scratch name contradicted its successor bytes");
            }
            match kind {
                DmlLeafKind::Attempt => {
                    let receipt = crate::d1_attempt_artifact::inspect_d1_attempt_artifact(&bytes)
                        .map_err(|_| "DML attempt state in shard was malformed")?;
                    if receipt.target_key_sha256 != target_key_sha256
                        || receipt.attempt_binding_sha256 != digest
                    {
                        return Err("DML attempt state contradicted its shard placement");
                    }
                }
                DmlLeafKind::Claimant(namespace) => {
                    let product =
                        crate::d1_dml_identity_claimant::inspect_d1_dml_identity_claimant(&bytes)
                            .map_err(|_| "DML claimant state in shard was malformed")?;
                    if product.receipt().target_key_sha256 != target_key_sha256
                        || product.receipt().namespace != namespace
                        || product.receipt().identity_sha256 != digest
                    {
                        return Err("DML claimant state contradicted its shard placement");
                    }
                }
            }
            if let Some((predecessor, successor)) = scratch_binding {
                if predecessor == successor {
                    return Err("DML CAS scratch did not name a distinct successor");
                }
                scratch_candidates.push(DmlScratchAudit {
                    name: name.to_string(),
                    record_sha256: digest.to_string(),
                    predecessor_sha256: predecessor.to_string(),
                    successor_sha256: successor.to_string(),
                    file_identity,
                });
            }
            if artifacts.insert(name.to_string(), bytes).is_some() {
                return Err("DML custody leaf repeated one physical artifact name");
            }
        }
        let mut stable_names = directory_entry_names(leaf)?;
        stable_names.sort();
        if stable_names != names {
            return Err("DML custody leaf changed during stable audit");
        }
        let mut scratches = BTreeMap::new();
        for scratch in scratch_candidates {
            let permanent_name = format!("{}.json", scratch.record_sha256);
            let incumbent = artifacts
                .get(&permanent_name)
                .ok_or("DML CAS scratch had no permanent incumbent record")?;
            if sha256_bytes_hex(incumbent) != scratch.predecessor_sha256 {
                return Err("DML CAS scratch contradicted the exact incumbent bytes");
            }
            let scratch_bytes = artifacts
                .get(&scratch.name)
                .ok_or("DML CAS scratch disappeared during authority validation")?;
            match kind {
                DmlLeafKind::Attempt => {
                    crate::d1_attempt_artifact::validate_d1_attempt_artifact_successor(
                        incumbent,
                        &scratch_bytes,
                    )
                    .map_err(|_| "DML attempt CAS scratch was not a canonical successor")?;
                }
                DmlLeafKind::Claimant(_) => {
                    crate::d1_dml_identity_claimant::validate_d1_dml_identity_claimant_seal(
                        incumbent,
                        &scratch_bytes,
                    )
                    .map_err(|_| "DML claimant CAS scratch was not a canonical successor")?;
                }
            }
            if scratches
                .insert(scratch.record_sha256.clone(), scratch)
                .is_some()
            {
                return Err(
                    "DML custody leaf contained multiple CAS scratch successors for one record",
                );
            }
        }
        Ok(DmlLeafAudit {
            entry_count: names.len(),
            scratches,
            artifacts,
        })
    }

    fn preflight_dml_leaf_capacity(
        target: &fs::File,
        kind: DmlLeafKind,
        digest: &str,
        target_key_sha256: &str,
        missing_permanent_entries: usize,
    ) -> Result<(), &'static str> {
        let leaf = open_dml_leaf(target, kind, digest, true)?
            .ok_or("DML custody leaf could not be installed")?;
        let prefix = &digest[..4];
        let existing = audit_dml_leaf(&leaf, kind, prefix, target_key_sha256)?.entry_count;
        if !dml_leaf_capacity_available(existing, missing_permanent_entries) {
            return Err(
                "DML custody leaf lacks capacity for permanent entries plus one CAS scratch slot",
            );
        }
        Ok(())
    }

    fn dml_cas_scratch_name(record: &str, expected: &[u8], successor: &[u8]) -> String {
        format!(
            ".next.{record}.{}.{}.json",
            sha256_bytes_hex(expected),
            sha256_bytes_hex(successor)
        )
    }

    fn prepare_dml_cas_scratch(
        target: &fs::File,
        leaf: &fs::File,
        kind: DmlLeafKind,
        record: &str,
        target_key_sha256: &str,
        expected: &[u8],
        successor: &[u8],
    ) -> Result<DmlScratchAudit, &'static str> {
        let prefix = &record[..4];
        let initial = audit_dml_leaf(leaf, kind, prefix, target_key_sha256)?;
        let permanent_name = format!("{record}.json");
        match read_private_dml_state(leaf, &permanent_name)? {
            Some(incumbent) if incumbent == expected => {}
            Some(_) => return Err("DML CAS found conflicting permanent incumbent bytes"),
            None => return Err("DML CAS found no permanent incumbent state"),
        }

        let expected_name = dml_cas_scratch_name(record, expected, successor);
        let expected_predecessor_sha256 = sha256_bytes_hex(expected);
        let expected_successor_sha256 = sha256_bytes_hex(successor);
        match initial.scratches.get(record) {
            Some(scratch)
                if scratch.name == expected_name
                    && scratch.predecessor_sha256 == expected_predecessor_sha256
                    && scratch.successor_sha256 == expected_successor_sha256 => {}
            Some(_) => {
                return Err("DML CAS found a contradictory incumbent-bound scratch successor");
            }
            None => {
                preflight_dml_leaf_capacity(target, kind, record, target_key_sha256, 0)?;
                create_private_dml_state(leaf, &expected_name, successor)?;
            }
        }

        let prepared = audit_dml_leaf(leaf, kind, prefix, target_key_sha256)?;
        let scratch = prepared
            .scratches
            .get(record)
            .ok_or("DML CAS scratch was absent after exact preparation")?;
        if scratch.name != expected_name
            || scratch.predecessor_sha256 != expected_predecessor_sha256
            || scratch.successor_sha256 != expected_successor_sha256
        {
            return Err("DML CAS prepared scratch identity contradicted the exact transition");
        }
        validate_named_private_file(leaf, &scratch.name, &scratch.file_identity)
            .map_err(|_| "DML CAS prepared scratch changed before consumption")?;
        match read_private_dml_state(leaf, &scratch.name)? {
            Some(bytes) if bytes == successor => Ok(scratch.clone()),
            _ => Err("DML CAS prepared scratch contradicted canonical successor bytes"),
        }
    }

    fn install_dml_cas_scratch(
        leaf: &fs::File,
        kind: DmlLeafKind,
        record: &str,
        target_key_sha256: &str,
        permanent_name: &str,
        scratch: &DmlScratchAudit,
        successor: &[u8],
    ) -> Result<(), &'static str> {
        let audited = audit_dml_leaf(leaf, kind, &record[..4], target_key_sha256)?;
        let current = audited
            .scratches
            .get(record)
            .ok_or("DML CAS scratch was absent immediately before rename")?;
        if current != scratch {
            return Err("DML CAS scratch identity changed before rename");
        }
        validate_named_private_file(leaf, &current.name, &current.file_identity)
            .map_err(|_| "DML CAS audited scratch changed before rename")?;
        let source = c_string_name(&current.name)?;
        let destination = c_string_name(permanent_name)?;
        let renamed = unsafe {
            libc::renameat(
                leaf.as_raw_fd(),
                source.as_ptr(),
                leaf.as_raw_fd(),
                destination.as_ptr(),
            )
        };
        if renamed != 0 {
            return Err("DML CAS audited scratch successor could not be installed");
        }
        sync_d1_lease_directory(leaf).map_err(|_| "DML CAS successor directory sync failed")?;
        let installed = audit_dml_leaf(leaf, kind, &record[..4], target_key_sha256)?;
        if installed.scratches.contains_key(record) {
            return Err("DML CAS scratch remained after successor rename");
        }
        match read_private_dml_state(leaf, permanent_name)? {
            Some(readback) if readback == successor => Ok(()),
            _ => Err("DML CAS readback contradicted the installed successor bytes"),
        }
    }

    pub(super) fn dml_leaf_capacity_available(
        existing: usize,
        missing_permanent_entries: usize,
    ) -> bool {
        existing
            .checked_add(missing_permanent_entries)
            .and_then(|count| count.checked_add(1))
            .is_some_and(|reserved| {
                reserved <= crate::d1_dml_custody_layout::D1_DML_CUSTODY_LEAF_ENTRY_LIMIT
            })
    }

    #[allow(dead_code)]
    fn canonical_shard_names(directory: &fs::File) -> Result<Vec<String>, &'static str> {
        let mut names = Vec::new();
        for raw in directory_entry_names(directory)? {
            let name = String::from_utf8(raw)
                .map_err(|_| "DML shard namespace contained a non-UTF-8 entry")?;
            if name.len() != 2
                || !name
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'))
            {
                return Err("DML shard namespace contained a non-canonical entry");
            }
            names.push(name);
        }
        names.sort();
        Ok(names)
    }

    #[allow(dead_code)]
    fn complete_dml_audit_once(
        target: &fs::File,
        authority: &crate::d1_dml_custody_genesis::D1DmlCustodyAuthority,
        limits: DmlCompleteAuditLimits,
    ) -> Result<crate::d1_dml_custody_layout::D1DmlCustodyCompleteAuditReceipt, &'static str> {
        use crate::d1_dml_custody_layout::{
            D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_SHA256,
            D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_VERSION, D1_DML_CUSTODY_LAYOUT_SHA256,
            D1_DML_CUSTODY_LAYOUT_VERSION, D1DmlCustodyCompleteAuditReceipt,
        };
        open_existing_d1_dml_custody(target, authority)?;
        let target_key_sha256 = authority.target_key_sha256.as_str();
        let audit_budget_sha256 = limits.identity_sha256();
        if limits.leaf_limit
            == crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_LEAF_LIMIT
            && limits.artifact_limit
                == crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_ARTIFACT_LIMIT
            && limits.payload_byte_limit
                == crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_PAYLOAD_BYTE_LIMIT
            && audit_budget_sha256 != D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_SHA256
        {
            return Err("DML complete-audit fixed budget identity did not rederive");
        }
        let mut budget = DmlCompleteAuditBudget::new(limits);
        let mut claimant_sets: BTreeMap<
            String,
            Vec<crate::d1_dml_identity_claimant::D1DmlIdentityClaimantReceipt>,
        > = BTreeMap::new();
        let mut attempts = BTreeMap::new();
        let mut retained_claimant_count = 0usize;
        let mut scratch_count = 0usize;
        let mut artifact_evidence = Vec::new();

        let kinds = crate::d1_dml_identity_claimant::D1DmlIdentityNamespace::ALL
            .into_iter()
            .map(DmlLeafKind::Claimant)
            .chain(std::iter::once(DmlLeafKind::Attempt));
        for kind in kinds {
            let family = open_dml_family_directory(target, kind)?;
            for aa in canonical_shard_names(&family)? {
                let (level_one, _) = open_private_dml_directory(&family, &aa)?;
                for bb in canonical_shard_names(&level_one)? {
                    budget.reserve_leaf()?;
                    let (leaf, _) = open_private_dml_directory(&level_one, &bb)?;
                    let prefix = format!("{aa}{bb}");
                    let audited = audit_dml_leaf_with_complete_budget(
                        &leaf,
                        kind,
                        &prefix,
                        target_key_sha256,
                        &mut budget,
                    )?;
                    for (name, bytes) in audited.artifacts {
                        let family_label = match kind {
                            DmlLeafKind::Attempt => "attempt".to_string(),
                            DmlLeafKind::Claimant(namespace) => {
                                format!("claimant/{}", namespace.filename_label())
                            }
                        };
                        budget.retain_cross_shard_entry(artifact_evidence.len())?;
                        artifact_evidence.push((
                            format!("{family_label}/{aa}/{bb}/{name}"),
                            sha256_bytes_hex(&bytes),
                        ));
                        if parse_dml_scratch_name(&name).is_some() {
                            scratch_count += 1;
                            continue;
                        }
                        match kind {
                            DmlLeafKind::Claimant(_) => {
                                let receipt = crate::d1_dml_identity_claimant::inspect_d1_dml_identity_claimant(&bytes)
                                    .map_err(|_| "DML claimant was malformed during complete audit")?
                                    .receipt()
                                    .clone();
                                crate::d1_dml_identity_claimant::validate_d1_dml_identity_claimant_audit_binding(&receipt)
                                    .map_err(|_| "DML claimant intent binding did not rederive during complete audit")?;
                                if receipt.custody_generation_sha256
                                    != authority.custody_generation_sha256
                                {
                                    return Err(
                                        "DML claimant belonged to another custody generation",
                                    );
                                }
                                if !claimant_sets.contains_key(&receipt.claimant_set_sha256) {
                                    budget.retain_cross_shard_entry(claimant_sets.len())?;
                                }
                                let receipts = claimant_sets
                                    .entry(receipt.claimant_set_sha256.clone())
                                    .or_default();
                                budget.retain_cross_shard_entry(retained_claimant_count)?;
                                retained_claimant_count = retained_claimant_count
                                    .checked_add(1)
                                    .ok_or("DML complete audit claimant retention overflowed")?;
                                receipts.push(receipt);
                            }
                            DmlLeafKind::Attempt => {
                                let receipt =
                                    crate::d1_attempt_artifact::inspect_d1_attempt_artifact(&bytes)
                                        .map_err(
                                            |_| "DML attempt was malformed during complete audit",
                                        )?;
                                if receipt.custody_generation_sha256
                                    != authority.custody_generation_sha256
                                {
                                    return Err(
                                        "DML attempt belonged to another custody generation",
                                    );
                                }
                                budget.retain_cross_shard_entry(attempts.len())?;
                                if attempts
                                    .insert(receipt.attempt_binding_sha256.clone(), receipt)
                                    .is_some()
                                {
                                    return Err(
                                        "DML complete audit found duplicate attempt binding evidence",
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        let claimant_count = claimant_sets.values().map(Vec::len).sum::<usize>();
        let pending_claimant_count = claimant_sets
            .values()
            .flatten()
            .filter(|receipt| {
                receipt.phase
                    == crate::d1_dml_identity_claimant::D1DmlIdentityClaimantPhase::Pending
            })
            .count();
        let bound_claimant_count = claimant_count - pending_claimant_count;
        let claimant_set_count = claimant_sets.len();
        let mut complete_claimant_set_count = 0usize;
        let mut incomplete_claimant_set_count = 0usize;
        let mut matched_claimant_set_count = 0usize;
        let mut orphan_claimant_set_count = 0usize;
        let mut referenced_attempts = BTreeMap::new();
        let mut matched_attempts = BTreeSet::new();
        for (claimant_set_sha256, receipts) in &mut claimant_sets {
            receipts.sort_by_key(|receipt| receipt.namespace);
            let first = receipts
                .first()
                .expect("claimant-set map entries are never empty");
            if receipts.iter().any(|receipt| {
                receipt.target_key_sha256 != first.target_key_sha256
                    || receipt.custody_generation_sha256 != first.custody_generation_sha256
                    || receipt.execute_plan_sha256 != first.execute_plan_sha256
                    || receipt.intent_binding_sha256 != first.intent_binding_sha256
            }) {
                return Err("DML claimant set contradicted its shared target or intent");
            }
            for namespace in crate::d1_dml_identity_claimant::D1DmlIdentityNamespace::ALL {
                if receipts
                    .iter()
                    .filter(|receipt| receipt.namespace == namespace)
                    .count()
                    > 1
                {
                    return Err("DML claimant set duplicated one physical namespace");
                }
            }
            let complete = receipts.len()
                == crate::d1_dml_identity_claimant::D1DmlIdentityNamespace::ALL.len();
            if complete {
                crate::d1_dml_identity_claimant::validate_complete_d1_dml_identity_claimant_set(
                    receipts,
                )
                .map_err(|_| {
                    "DML complete claimant-set digest did not rederive from physical identities"
                })?;
                complete_claimant_set_count += 1;
            } else {
                incomplete_claimant_set_count += 1;
            }

            let bound = receipts
                .iter()
                .filter(|receipt| {
                    receipt.phase
                        == crate::d1_dml_identity_claimant::D1DmlIdentityClaimantPhase::Bound
                })
                .collect::<Vec<_>>();
            if bound.is_empty() {
                continue;
            }
            let attempt_binding_sha256 = bound[0]
                .attempt_binding_sha256
                .as_deref()
                .expect("inspected Bound claimant has one attempt binding");
            if bound.iter().any(|receipt| {
                receipt.attempt_binding_sha256.as_deref() != Some(attempt_binding_sha256)
            }) {
                return Err("DML claimant set named contradictory attempt bindings");
            }
            let Some(attempt) = attempts.get(attempt_binding_sha256) else {
                orphan_claimant_set_count += 1;
                continue;
            };
            if bound.iter().any(|receipt| {
                receipt.target_key_sha256 != attempt.target_key_sha256
                    || receipt.custody_generation_sha256
                        != attempt.custody_generation_sha256
                    || receipt.execute_plan_sha256 != attempt.execute_plan_sha256
                    || receipt.identity_sha256.as_str()
                        != match receipt.namespace {
                            crate::d1_dml_identity_claimant::D1DmlIdentityNamespace::Operation => {
                                attempt.operation_id_sha256.as_str()
                            }
                            crate::d1_dml_identity_claimant::D1DmlIdentityNamespace::ExecutionAttempt => {
                                attempt.execution_attempt_id_sha256.as_str()
                            }
                            crate::d1_dml_identity_claimant::D1DmlIdentityNamespace::ProviderRequest => {
                                attempt.provider_request_id_sha256.as_str()
                            }
                        }
            }) {
                return Err("DML claimant evidence contradicted its referenced attempt");
            }
            budget.retain_cross_shard_entry(referenced_attempts.len())?;
            if referenced_attempts
                .insert(
                    attempt_binding_sha256.to_string(),
                    claimant_set_sha256.clone(),
                )
                .is_some()
            {
                return Err("DML attempt was claimed by multiple claimant sets");
            }
            if !complete || bound.len() != receipts.len() {
                continue;
            }
            budget.retain_cross_shard_entry(matched_attempts.len())?;
            matched_attempts.insert(attempt_binding_sha256.to_string());
            matched_claimant_set_count += 1;
        }
        let unmatched_claimant_set_count = claimant_set_count - matched_claimant_set_count;
        let unmatched_attempt_count = attempts.len() - matched_attempts.len();
        let mut attempt_phase_counts =
            crate::d1_dml_custody_layout::D1DmlCustodyAttemptPhaseCounts::default();
        for attempt in attempts.values() {
            let count = match attempt.phase {
                crate::d1_dml_attempt_custody::D1DmlAttemptPhase::Prepared => {
                    &mut attempt_phase_counts.prepared
                }
                crate::d1_dml_attempt_custody::D1DmlAttemptPhase::DispatchReserved => {
                    &mut attempt_phase_counts.dispatch_reserved
                }
                crate::d1_dml_attempt_custody::D1DmlAttemptPhase::ReconciliationRequired => {
                    &mut attempt_phase_counts.reconciliation_required
                }
                crate::d1_dml_attempt_custody::D1DmlAttemptPhase::TerminalApplied => {
                    &mut attempt_phase_counts.terminal_applied
                }
                crate::d1_dml_attempt_custody::D1DmlAttemptPhase::TerminalNotApplied => {
                    &mut attempt_phase_counts.terminal_not_applied
                }
            };
            *count = count
                .checked_add(1)
                .ok_or("DML complete audit attempt-phase count overflowed")?;
        }
        let unresolved_attempt_count = attempt_phase_counts
            .unresolved()
            .ok_or("DML complete audit attempt-phase count overflowed")?;
        let reconciliation_required = scratch_count != 0
            || unmatched_claimant_set_count != 0
            || unmatched_attempt_count != 0
            || unresolved_attempt_count != 0;
        artifact_evidence.sort();
        let provider_dispatch_authority =
            crate::d1_dml_custody_layout::D1DmlCustodyAuditProviderAuthority::None;
        let audit_sha256 = sha256_bytes_hex(
            &serde_json::to_vec(&DmlCompleteAuditDigest {
                version: D1_DML_CUSTODY_LAYOUT_VERSION,
                layout_sha256: D1_DML_CUSTODY_LAYOUT_SHA256,
                audit_budget_version: D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_VERSION,
                audit_budget_sha256: &audit_budget_sha256,
                audited_leaf_limit: limits.leaf_limit,
                physical_artifact_limit: limits.artifact_limit,
                artifact_payload_byte_limit: limits.payload_byte_limit,
                audited_leaf_count: budget.audited_leaf_count,
                physical_artifact_count: budget.physical_artifact_count,
                artifact_payload_bytes: budget.artifact_payload_bytes,
                target_key_sha256,
                custody_generation_sha256: &authority.custody_generation_sha256,
                authority_sha256: &authority.authority_sha256,
                genesis_sha256: &authority.genesis_sha256,
                claimant_count,
                attempt_count: attempts.len(),
                attempt_phase_counts,
                pending_claimant_count,
                bound_claimant_count,
                cas_scratch_count: scratch_count,
                claimant_set_count,
                complete_claimant_set_count,
                matched_claimant_set_count,
                unmatched_claimant_set_count,
                unmatched_attempt_count,
                orphan_claimant_set_count,
                incomplete_claimant_set_count,
                reconciliation_required,
                provider_dispatch_authority,
                artifact_evidence: &artifact_evidence,
            })
            .expect("DML complete audit serialization is infallible"),
        );
        Ok(D1DmlCustodyCompleteAuditReceipt {
            version: D1_DML_CUSTODY_LAYOUT_VERSION,
            layout_sha256: D1_DML_CUSTODY_LAYOUT_SHA256.to_string(),
            audit_budget_version: D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_VERSION,
            audit_budget_sha256,
            audited_leaf_limit: limits.leaf_limit,
            physical_artifact_limit: limits.artifact_limit,
            artifact_payload_byte_limit: limits.payload_byte_limit,
            audited_leaf_count: budget.audited_leaf_count,
            physical_artifact_count: budget.physical_artifact_count,
            artifact_payload_bytes: budget.artifact_payload_bytes,
            target_key_sha256: target_key_sha256.to_string(),
            custody_generation_sha256: authority.custody_generation_sha256.clone(),
            authority_sha256: authority.authority_sha256.clone(),
            genesis_sha256: authority.genesis_sha256.clone(),
            claimant_count,
            attempt_count: attempts.len(),
            attempt_phase_counts,
            pending_claimant_count,
            bound_claimant_count,
            cas_scratch_count: scratch_count,
            claimant_set_count,
            complete_claimant_set_count,
            matched_claimant_set_count,
            unmatched_claimant_set_count,
            unmatched_attempt_count,
            orphan_claimant_set_count,
            incomplete_claimant_set_count,
            reconciliation_required,
            provider_dispatch_authority,
            audit_sha256,
        })
    }

    pub(super) fn audit_d1_dml_custody_complete(
        target: &fs::File,
        authority: &crate::d1_dml_custody_genesis::D1DmlCustodyAuthority,
    ) -> Result<crate::d1_dml_custody_layout::D1DmlCustodyCompleteAuditReceipt, &'static str> {
        audit_d1_dml_custody_complete_with_limits(
            target,
            authority,
            DmlCompleteAuditLimits::fixed(),
        )
    }

    pub(super) fn authorize_target_wide_d1_dml_custody(
        target: &fs::File,
        authority: &crate::d1_dml_custody_genesis::D1DmlCustodyAuthority,
    ) -> Result<crate::d1_dml_custody_layout::D1DmlCustodyCompleteAuditAuthorization, &'static str>
    {
        audit_d1_dml_custody_complete(target, authority)?.authorize_target_wide_custody(authority)
    }

    fn audit_d1_dml_custody_complete_with_limits(
        target: &fs::File,
        authority: &crate::d1_dml_custody_genesis::D1DmlCustodyAuthority,
        limits: DmlCompleteAuditLimits,
    ) -> Result<crate::d1_dml_custody_layout::D1DmlCustodyCompleteAuditReceipt, &'static str> {
        let first = complete_dml_audit_once(target, authority, limits)?;
        maybe_pause_complete_dml_audit_after_first_for_test(target);
        let second = complete_dml_audit_once(target, authority, limits)?;
        if first != second {
            return Err("DML custody changed during stable complete audit");
        }
        Ok(second)
    }

    #[cfg(test)]
    pub(super) fn audit_d1_dml_custody_complete_with_test_limits(
        target: &fs::File,
        target_key_sha256: &str,
        leaf_limit: usize,
        artifact_limit: usize,
        payload_byte_limit: usize,
    ) -> Result<crate::d1_dml_custody_layout::D1DmlCustodyCompleteAuditReceipt, &'static str> {
        let (_, genesis_bytes) = private_custody_file_snapshot(
            target,
            crate::d1_dml_custody_genesis::D1_DML_CUSTODY_GENESIS_NAME,
        )?;
        let authority =
            crate::d1_dml_custody_genesis::inspect_d1_dml_custody_genesis(&genesis_bytes)?;
        if authority.target_key_sha256 != target_key_sha256 {
            return Err("test complete-audit target contradicted custody genesis");
        }
        audit_d1_dml_custody_complete_with_limits(
            target,
            &authority,
            DmlCompleteAuditLimits {
                leaf_limit,
                artifact_limit,
                payload_byte_limit,
            },
        )
    }

    fn read_private_dml_state_snapshot(
        target: &fs::File,
        name: &str,
    ) -> Result<Option<(D1LeaseFileIdentity, Vec<u8>)>, &'static str> {
        read_private_dml_state_snapshot_with_payload_limit(target, name, None)
    }

    fn read_private_dml_state_snapshot_with_payload_limit(
        target: &fs::File,
        name: &str,
        payload_byte_limit: Option<usize>,
    ) -> Result<Option<(D1LeaseFileIdentity, Vec<u8>)>, &'static str> {
        let named = match open_named_entry(target, name) {
            Ok(named) => named,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("DML attempt state could not be inspected"),
        };
        let metadata = named
            .metadata()
            .map_err(|_| "DML attempt state metadata was unavailable")?;
        if !private_file(&metadata)
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > crate::d1_dml_attempt_custody::D1_DML_ATTEMPT_STATE_BYTE_CAP as u64
        {
            return Err("DML attempt state was not one bounded private regular file");
        }
        if payload_byte_limit.is_some_and(|limit| {
            usize::try_from(metadata.len()).map_or(true, |length| length > limit)
        }) {
            return Err("DML complete audit exceeded its artifact-payload byte budget");
        }
        let expected = identity(&metadata);
        let name_c = c_string_name(name)?;
        let state = open_at(
            target.as_raw_fd(),
            &name_c,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
        .map_err(|_| "DML attempt state could not be opened")?;
        let held = state
            .metadata()
            .map_err(|_| "held DML attempt state metadata was unavailable")?;
        if !private_file(&held) || held.nlink() != 1 || identity(&held) != expected {
            return Err("DML attempt state changed while it was rebound");
        }
        if payload_byte_limit
            .is_some_and(|limit| usize::try_from(held.len()).map_or(true, |length| length > limit))
        {
            return Err("DML complete audit exceeded its artifact-payload byte budget");
        }
        if held.len() != metadata.len() {
            return Err("DML attempt state changed size while it was rebound");
        }
        let bytes = read_held_file(&state)?;
        let after_read = state
            .metadata()
            .map_err(|_| "held DML attempt state metadata was unavailable after read")?;
        if !private_file(&after_read)
            || after_read.nlink() != 1
            || identity(&after_read) != expected
            || after_read.len() != held.len()
        {
            return Err("DML attempt state changed while its payload was read");
        }
        validate_named_private_file(target, name, &expected)
            .map_err(|_| "DML attempt state changed during readback")?;
        Ok(Some((expected, bytes)))
    }

    fn read_private_dml_state(
        target: &fs::File,
        name: &str,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        read_private_dml_state_snapshot(target, name).map(|state| state.map(|(_, bytes)| bytes))
    }

    pub(super) fn create_private_dml_state(
        target: &fs::File,
        name: &str,
        state: &[u8],
    ) -> Result<(), &'static str> {
        if state.is_empty()
            || state.len() > crate::d1_dml_attempt_custody::D1_DML_ATTEMPT_STATE_BYTE_CAP
        {
            return Err("DML attempt successor exceeded its canonical byte bounds");
        }
        let name_c = c_string_name(name)?;
        let mut file = open_at(
            target.as_raw_fd(),
            &name_c,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600,
        )
        .map_err(|_| "DML attempt state could not be created exclusively")?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|()| file.write_all(state))
            .and_then(|()| file.sync_all())
            .map_err(|_| "DML attempt state could not be written and synchronized")?;
        sync_d1_lease_directory(target)
            .map_err(|_| "DML attempt custody directory could not be synchronized")?;
        match read_private_dml_state(target, name)? {
            Some(readback) if readback == state => Ok(()),
            _ => Err("DML attempt state did not survive exact readback"),
        }
    }

    pub(super) fn read_d1_dml_attempt_state(
        target: &fs::File,
        binding: &str,
        target_key_sha256: &str,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        let Some(leaf) = open_dml_leaf(target, DmlLeafKind::Attempt, binding, false)? else {
            return Ok(None);
        };
        audit_dml_leaf(
            &leaf,
            DmlLeafKind::Attempt,
            &binding[..4],
            target_key_sha256,
        )?;
        read_private_dml_state(&leaf, &d1_dml_attempt_name(binding)?)
    }

    pub(super) fn create_d1_dml_attempt_state(
        target: &fs::File,
        binding: &str,
        state: &[u8],
    ) -> Result<(), &'static str> {
        let receipt = crate::d1_attempt_artifact::inspect_d1_attempt_artifact(state)
            .map_err(|_| "DML attempt state was malformed before storage")?;
        let leaf = open_dml_leaf(target, DmlLeafKind::Attempt, binding, true)?
            .ok_or("DML attempt shard could not be installed")?;
        preflight_dml_leaf_capacity(
            target,
            DmlLeafKind::Attempt,
            binding,
            &receipt.target_key_sha256,
            1,
        )?;
        create_private_dml_state(&leaf, &d1_dml_attempt_name(binding)?, state)
    }

    pub(super) fn preflight_d1_dml_attempt_capacity(
        target: &fs::File,
        binding: &str,
        target_key_sha256: &str,
    ) -> Result<(), &'static str> {
        preflight_dml_leaf_capacity(target, DmlLeafKind::Attempt, binding, target_key_sha256, 1)
    }

    pub(super) fn compare_exchange_d1_dml_attempt_state(
        target: &fs::File,
        binding: &str,
        expected: &[u8],
        successor: &[u8],
    ) -> Result<(), &'static str> {
        let name = d1_dml_attempt_name(binding)?;
        let product = crate::d1_attempt_artifact::inspect_d1_attempt_artifact(successor)
            .map_err(|_| "DML attempt successor was malformed before storage")?;
        crate::d1_attempt_artifact::validate_d1_attempt_artifact_successor(expected, successor)?;
        let leaf = open_dml_leaf(target, DmlLeafKind::Attempt, binding, false)?
            .ok_or("DML attempt compare-and-exchange found no incumbent shard")?;
        let scratch = prepare_dml_cas_scratch(
            target,
            &leaf,
            DmlLeafKind::Attempt,
            binding,
            &product.target_key_sha256,
            expected,
            successor,
        )?;
        install_dml_cas_scratch(
            &leaf,
            DmlLeafKind::Attempt,
            binding,
            &product.target_key_sha256,
            &name,
            &scratch,
            successor,
        )
    }

    pub(super) fn read_d1_dml_identity_claimant(
        target: &fs::File,
        namespace: crate::d1_dml_identity_claimant::D1DmlIdentityNamespace,
        identity_sha256: &str,
        target_key_sha256: &str,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        let Some(leaf) = open_dml_leaf(
            target,
            DmlLeafKind::Claimant(namespace),
            identity_sha256,
            false,
        )?
        else {
            return Ok(None);
        };
        audit_dml_leaf(
            &leaf,
            DmlLeafKind::Claimant(namespace),
            &identity_sha256[..4],
            target_key_sha256,
        )?;
        read_private_dml_state(
            &leaf,
            &d1_dml_identity_claimant_name(namespace, identity_sha256)?,
        )
    }

    pub(super) fn preflight_d1_dml_identity_claimant_set_capacity(
        target: &fs::File,
        set: &crate::d1_dml_identity_claimant::D1DmlIdentityClaimantSet,
        target_key_sha256: &str,
    ) -> Result<(), &'static str> {
        for namespace in crate::d1_dml_identity_claimant::D1DmlIdentityNamespace::ALL {
            let digest = set.identity_sha256(namespace);
            let leaf = open_dml_leaf(target, DmlLeafKind::Claimant(namespace), digest, true)?
                .ok_or("DML claimant shard could not be installed")?;
            let name = d1_dml_identity_claimant_name(namespace, digest)?;
            let missing = usize::from(read_private_dml_state(&leaf, &name)?.is_none());
            preflight_dml_leaf_capacity(
                target,
                DmlLeafKind::Claimant(namespace),
                digest,
                target_key_sha256,
                missing,
            )?;
        }
        Ok(())
    }

    pub(super) fn create_d1_dml_identity_claimant(
        target: &fs::File,
        namespace: crate::d1_dml_identity_claimant::D1DmlIdentityNamespace,
        identity_sha256: &str,
        state: &[u8],
    ) -> Result<(), &'static str> {
        let product = crate::d1_dml_identity_claimant::inspect_d1_dml_identity_claimant(state)
            .map_err(|_| "DML identity claimant was malformed before storage")?;
        let leaf = open_dml_leaf(
            target,
            DmlLeafKind::Claimant(namespace),
            identity_sha256,
            true,
        )?
        .ok_or("DML claimant shard could not be installed")?;
        preflight_dml_leaf_capacity(
            target,
            DmlLeafKind::Claimant(namespace),
            identity_sha256,
            &product.receipt().target_key_sha256,
            1,
        )?;
        create_private_dml_state(
            &leaf,
            &d1_dml_identity_claimant_name(namespace, identity_sha256)?,
            state,
        )
    }

    pub(super) fn compare_exchange_d1_dml_identity_claimant(
        target: &fs::File,
        namespace: crate::d1_dml_identity_claimant::D1DmlIdentityNamespace,
        identity_sha256: &str,
        expected: &[u8],
        successor: &[u8],
    ) -> Result<(), &'static str> {
        let name = d1_dml_identity_claimant_name(namespace, identity_sha256)?;
        let product = crate::d1_dml_identity_claimant::inspect_d1_dml_identity_claimant(successor)
            .map_err(|_| "DML claimant successor was malformed before storage")?;
        let leaf = open_dml_leaf(
            target,
            DmlLeafKind::Claimant(namespace),
            identity_sha256,
            false,
        )?
        .ok_or("DML identity claimant compare-and-exchange found no incumbent shard")?;
        let scratch = prepare_dml_cas_scratch(
            target,
            &leaf,
            DmlLeafKind::Claimant(namespace),
            identity_sha256,
            &product.receipt().target_key_sha256,
            expected,
            successor,
        )?;
        install_dml_cas_scratch(
            &leaf,
            DmlLeafKind::Claimant(namespace),
            identity_sha256,
            &product.receipt().target_key_sha256,
            &name,
            &scratch,
            successor,
        )
    }

    #[cfg(test)]
    use std::{
        cell::Cell,
        sync::{Mutex, OnceLock, mpsc},
    };
    #[cfg(test)]
    std::thread_local! {
        static FAIL_NEXT_DIRECTORY_SYNC: Cell<bool> = const { Cell::new(false) };
    }
    #[cfg(test)]
    pub(super) fn fail_next_directory_sync_for_test() {
        FAIL_NEXT_DIRECTORY_SYNC.with(|fail| fail.set(true));
    }
    #[cfg(test)]
    struct GuardPauseHook {
        root_path: PathBuf,
        entered: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    }
    #[cfg(test)]
    static GUARD_PAUSE_HOOK: OnceLock<Mutex<Option<GuardPauseHook>>> = OnceLock::new();
    #[cfg(test)]
    struct ActivationMarkerPauseHook {
        target_key_sha256: String,
        entered: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    }
    #[cfg(test)]
    static ACTIVATION_MARKER_PAUSE_HOOK: OnceLock<Mutex<Option<ActivationMarkerPauseHook>>> =
        OnceLock::new();
    #[cfg(test)]
    struct RootNamespaceAuditPauseHook {
        root_identity: D1LeaseFileIdentity,
        entered: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    }
    #[cfg(test)]
    static ROOT_NAMESPACE_AUDIT_PAUSE_HOOK: OnceLock<Mutex<Option<RootNamespaceAuditPauseHook>>> =
        OnceLock::new();
    #[cfg(test)]
    struct CompleteDmlAuditPauseHook {
        target_identity: D1LeaseFileIdentity,
        entered: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    }
    #[cfg(test)]
    static COMPLETE_DML_AUDIT_PAUSE_HOOK: OnceLock<Mutex<Option<CompleteDmlAuditPauseHook>>> =
        OnceLock::new();
    #[cfg(test)]
    pub(super) fn install_activation_marker_pause_hook(
        target_key_sha256: String,
        entered: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    ) {
        let mut hook = ACTIVATION_MARKER_PAUSE_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("activation marker pause hook lock");
        *hook = Some(ActivationMarkerPauseHook {
            target_key_sha256,
            entered,
            resume,
        });
    }
    #[cfg(test)]
    pub(super) fn install_root_namespace_audit_pause_hook(
        root_path: &Path,
        entered: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    ) {
        let metadata =
            fs::symlink_metadata(root_path).expect("root namespace audit pause hook root metadata");
        let mut hook = ROOT_NAMESPACE_AUDIT_PAUSE_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("root namespace audit pause hook lock");
        *hook = Some(RootNamespaceAuditPauseHook {
            root_identity: identity(&metadata),
            entered,
            resume,
        });
    }
    #[cfg(test)]
    pub(super) fn install_complete_dml_audit_pause_hook(
        target_path: &Path,
        entered: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    ) {
        let metadata = fs::symlink_metadata(target_path)
            .expect("complete DML audit pause hook target metadata");
        let mut hook = COMPLETE_DML_AUDIT_PAUSE_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("complete DML audit pause hook lock");
        *hook = Some(CompleteDmlAuditPauseHook {
            target_identity: identity(&metadata),
            entered,
            resume,
        });
    }
    #[cfg(test)]
    pub(super) fn install_guard_pause_hook(
        root_path: PathBuf,
        entered: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    ) {
        let mut hook = GUARD_PAUSE_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("guard pause hook lock");
        *hook = Some(GuardPauseHook {
            root_path,
            entered,
            resume,
        });
    }
    #[cfg(test)]
    fn maybe_pause_after_guard_for_test(root_path: &Path) {
        let hook = {
            let mut hook = GUARD_PAUSE_HOOK
                .get_or_init(|| Mutex::new(None))
                .lock()
                .expect("guard pause hook lock");
            if hook
                .as_ref()
                .is_some_and(|candidate| candidate.root_path == root_path)
            {
                hook.take()
            } else {
                None
            }
        };
        if let Some(hook) = hook {
            hook.entered.send(()).expect("guard pause test receiver");
            hook.resume.recv().expect("guard pause test release");
        }
    }
    #[cfg(not(test))]
    fn maybe_pause_after_guard_for_test(_root_path: &Path) {}
    #[cfg(test)]
    fn maybe_pause_before_activation_marker_for_test(target_key_sha256: &str) {
        let hook = {
            let mut hook = ACTIVATION_MARKER_PAUSE_HOOK
                .get_or_init(|| Mutex::new(None))
                .lock()
                .expect("activation marker pause hook lock");
            if hook
                .as_ref()
                .is_some_and(|candidate| candidate.target_key_sha256 == target_key_sha256)
            {
                hook.take()
            } else {
                None
            }
        };
        if let Some(hook) = hook {
            hook.entered
                .send(())
                .expect("activation marker test receiver");
            hook.resume.recv().expect("activation marker test release");
        }
    }
    #[cfg(not(test))]
    fn maybe_pause_before_activation_marker_for_test(_target_key_sha256: &str) {}
    #[cfg(test)]
    fn maybe_pause_root_namespace_audit_after_first_for_test(root: &fs::File) {
        let root_identity = root.metadata().ok().map(|metadata| identity(&metadata));
        let hook = {
            let mut hook = ROOT_NAMESPACE_AUDIT_PAUSE_HOOK
                .get_or_init(|| Mutex::new(None))
                .lock()
                .expect("root namespace audit pause hook lock");
            if hook
                .as_ref()
                .is_some_and(|candidate| Some(candidate.root_identity.clone()) == root_identity)
            {
                hook.take()
            } else {
                None
            }
        };
        if let Some(hook) = hook {
            hook.entered
                .send(())
                .expect("root namespace audit test receiver");
            hook.resume
                .recv()
                .expect("root namespace audit test release");
        }
    }
    #[cfg(not(test))]
    fn maybe_pause_root_namespace_audit_after_first_for_test(_root: &fs::File) {}
    #[cfg(test)]
    fn maybe_pause_complete_dml_audit_after_first_for_test(target: &fs::File) {
        let target_identity = target.metadata().ok().map(|metadata| identity(&metadata));
        let hook = {
            let mut hook = COMPLETE_DML_AUDIT_PAUSE_HOOK
                .get_or_init(|| Mutex::new(None))
                .lock()
                .expect("complete DML audit pause hook lock");
            if hook
                .as_ref()
                .is_some_and(|candidate| Some(candidate.target_identity) == target_identity)
            {
                hook.take()
            } else {
                None
            }
        };
        if let Some(hook) = hook {
            hook.entered
                .send(())
                .expect("complete DML audit test receiver");
            hook.resume.recv().expect("complete DML audit test release");
        }
    }
    #[cfg(not(test))]
    fn maybe_pause_complete_dml_audit_after_first_for_test(_target: &fs::File) {}
}

#[cfg(target_os = "linux")]
use linux::{
    acquire_d1_migration_lease_at_linux, inspect_retained_d1_migration_lease_at_linux,
    preflight_d1_migration_target_custody_at_linux, rename_owned_lease_no_replace,
    restore_active_or_leave_blocker, retained_entry_present, sync_d1_lease_directory,
    validate_d1_lease_custody, validate_owned_named_lease, validate_retained_named_lease,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::time::Duration;

    #[cfg(target_os = "linux")]
    struct DmlClaimantScratchFixture {
        root: PathBuf,
        guard: D1TargetMutationGuard,
        set: crate::d1_dml_identity_claimant::D1DmlIdentityClaimantSet,
        namespace: crate::d1_dml_identity_claimant::D1DmlIdentityNamespace,
        digest: String,
        pending: Vec<u8>,
        bound: Vec<u8>,
    }

    #[cfg(target_os = "linux")]
    struct DmlCompleteAuditFixture {
        root: PathBuf,
        guard: D1TargetMutationGuard,
        set: crate::d1_dml_identity_claimant::D1DmlIdentityClaimantSet,
        attempt: crate::d1_dml_attempt_custody::D1DmlAttemptCustodyProduct,
    }

    #[cfg(target_os = "linux")]
    fn dml_complete_audit_fixture(label: &str) -> DmlCompleteAuditFixture {
        dml_complete_audit_fixture_with_phase(
            label,
            crate::d1_dml_attempt_custody::D1DmlAttemptPhase::TerminalApplied,
        )
    }

    #[cfg(target_os = "linux")]
    fn dml_complete_audit_fixture_with_phase(
        label: &str,
        phase: crate::d1_dml_attempt_custody::D1DmlAttemptPhase,
    ) -> DmlCompleteAuditFixture {
        use crate::d1_dml_attempt_custody::{
            D1DmlAttemptIdentities, synthetic_d1_dml_attempt_for_complete_audit_phase,
        };
        use crate::d1_dml_identity_claimant::derive_d1_dml_identity_claimant_set;
        use crate::d1_target::normalize_d1_target;

        let root = private_test_root(label);
        let guard = acquire_d1_target_mutation_guard_at(
            root.to_path_buf(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("acquire complete-audit target guard");
        guard
            .ensure_d1_dml_custody_layout()
            .expect("install complete-audit layout");
        let target =
            normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000").expect("target");
        let identities = D1DmlAttemptIdentities {
            operation_id: "operation-complete-audit-0001",
            execution_attempt_id: "attempt-complete-audit-0001",
            provider_request_id: "provider-complete-audit-0001",
            custody_generation_sha256:
                crate::d1_dml_attempt_custody::TEST_CUSTODY_GENERATION_SHA256,
        };
        let execute_plan_sha256 = sha256_bytes_hex(label.as_bytes());
        let set = derive_d1_dml_identity_claimant_set(&target, &execute_plan_sha256, identities)
            .expect("derive complete-audit claimant set");
        let attempt = synthetic_d1_dml_attempt_for_complete_audit_phase(
            &target.target_key_sha256(),
            &execute_plan_sha256,
            identities,
            phase,
        );
        DmlCompleteAuditFixture {
            root,
            guard,
            set,
            attempt,
        }
    }

    #[cfg(target_os = "linux")]
    fn install_pending_audit_claimant(
        fixture: &DmlCompleteAuditFixture,
        namespace: crate::d1_dml_identity_claimant::D1DmlIdentityNamespace,
    ) {
        let pending = fixture.set.pending(namespace);
        fixture
            .guard
            .create_d1_dml_identity_claimant(
                namespace,
                fixture.set.identity_sha256(namespace),
                pending.state_bytes(),
            )
            .expect("install complete-audit Pending claimant");
    }

    #[cfg(target_os = "linux")]
    fn seal_audit_claimant(
        fixture: &DmlCompleteAuditFixture,
        namespace: crate::d1_dml_identity_claimant::D1DmlIdentityNamespace,
    ) {
        let pending = fixture.set.pending(namespace);
        let bound = fixture
            .set
            .bound(namespace, &fixture.attempt.receipt().attempt_binding_sha256)
            .expect("derive complete-audit Bound claimant");
        fixture
            .guard
            .compare_exchange_d1_dml_identity_claimant(
                namespace,
                fixture.set.identity_sha256(namespace),
                pending.state_bytes(),
                bound.state_bytes(),
            )
            .expect("seal complete-audit claimant");
    }

    #[cfg(target_os = "linux")]
    fn install_audit_attempt(fixture: &DmlCompleteAuditFixture) {
        fixture
            .guard
            .create_d1_dml_attempt_state(
                &fixture.attempt.receipt().attempt_binding_sha256,
                fixture.attempt.state_bytes(),
            )
            .expect("install complete-audit attempt");
    }

    #[cfg(target_os = "linux")]
    fn install_raw_audit_attempt(fixture: &DmlCompleteAuditFixture, bytes: &[u8]) {
        let binding = &fixture.attempt.receipt().attempt_binding_sha256;
        let leaf = linux::open_dml_leaf(
            &fixture.guard.target,
            linux::DmlLeafKind::Attempt,
            binding,
            true,
        )
        .expect("open raw restored-attempt leaf")
        .expect("raw restored-attempt leaf present");
        linux::create_private_dml_state(&leaf, &format!("{binding}.json"), bytes)
            .expect("install raw restored-attempt evidence");
    }

    #[cfg(target_os = "linux")]
    fn install_phase_graph_on_target(
        target_file: &fs::File,
        target_key_sha256: &str,
        label: &str,
        phase: crate::d1_dml_attempt_custody::D1DmlAttemptPhase,
    ) {
        use crate::d1_dml_attempt_custody::{
            D1DmlAttemptIdentities, synthetic_d1_dml_attempt_for_complete_audit_phase,
        };
        use crate::d1_dml_identity_claimant::{
            D1DmlIdentityNamespace, derive_d1_dml_identity_claimant_set,
        };

        let target =
            crate::d1_target::normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000")
                .expect("canonical phase-graph target");
        assert_eq!(target.target_key_sha256(), target_key_sha256);
        let operation_id = format!("operation-{label}");
        let execution_attempt_id = format!("attempt-{label}");
        let provider_request_id = format!("provider-{label}");
        let identities = D1DmlAttemptIdentities {
            operation_id: &operation_id,
            execution_attempt_id: &execution_attempt_id,
            provider_request_id: &provider_request_id,
            custody_generation_sha256:
                crate::d1_dml_attempt_custody::TEST_CUSTODY_GENERATION_SHA256,
        };
        let execute_plan_sha256 = sha256_bytes_hex(label.as_bytes());
        let set = derive_d1_dml_identity_claimant_set(&target, &execute_plan_sha256, identities)
            .expect("derive phase-graph claimants");
        let attempt = synthetic_d1_dml_attempt_for_complete_audit_phase(
            target_key_sha256,
            &execute_plan_sha256,
            identities,
            phase,
        );
        linux::preflight_d1_dml_identity_claimant_set_capacity(
            target_file,
            &set,
            target_key_sha256,
        )
        .expect("preflight phase-graph claimant set");
        for namespace in D1DmlIdentityNamespace::ALL {
            let pending = set.pending(namespace);
            let bound = set
                .bound(namespace, &attempt.receipt().attempt_binding_sha256)
                .expect("derive phase-graph Bound claimant");
            linux::create_d1_dml_identity_claimant(
                target_file,
                namespace,
                set.identity_sha256(namespace),
                pending.state_bytes(),
            )
            .expect("install phase-graph Pending claimant");
            linux::compare_exchange_d1_dml_identity_claimant(
                target_file,
                namespace,
                set.identity_sha256(namespace),
                pending.state_bytes(),
                bound.state_bytes(),
            )
            .expect("seal phase-graph claimant");
        }
        linux::create_d1_dml_attempt_state(
            target_file,
            &attempt.receipt().attempt_binding_sha256,
            attempt.state_bytes(),
        )
        .expect("install phase-graph attempt");
    }

    #[cfg(target_os = "linux")]
    fn dml_claimant_scratch_fixture(label: &str) -> DmlClaimantScratchFixture {
        use crate::d1_dml_attempt_custody::D1DmlAttemptIdentities;
        use crate::d1_dml_identity_claimant::{
            D1DmlIdentityNamespace, derive_d1_dml_identity_claimant_set,
        };
        use crate::d1_target::normalize_d1_target;

        let root = private_test_root(label);
        let guard = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("acquire target guard");
        guard.ensure_d1_dml_custody_layout().expect("layout");
        let target =
            normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000").expect("target");
        let set = derive_d1_dml_identity_claimant_set(
            &target,
            &"a".repeat(64),
            D1DmlAttemptIdentities {
                operation_id: "operation-scratch-fixture",
                execution_attempt_id: "attempt-scratch-fixture",
                provider_request_id: "provider-scratch-fixture",
                custody_generation_sha256:
                    crate::d1_dml_attempt_custody::TEST_CUSTODY_GENERATION_SHA256,
            },
        )
        .expect("claimant set");
        let namespace = D1DmlIdentityNamespace::Operation;
        let digest = set.identity_sha256(namespace).to_string();
        let pending = set.pending(namespace).state_bytes().to_vec();
        let bound = set
            .bound(namespace, &"b".repeat(64))
            .expect("bound claimant")
            .state_bytes()
            .to_vec();
        guard
            .create_d1_dml_identity_claimant(namespace, &digest, &pending)
            .expect("install Pending claimant");
        DmlClaimantScratchFixture {
            root,
            guard,
            set,
            namespace,
            digest,
            pending,
            bound,
        }
    }

    #[cfg(target_os = "linux")]
    fn claimant_scratch_name(record: &str, expected: &[u8], successor: &[u8]) -> String {
        format!(
            ".next.{record}.{}.{}.json",
            sha256_bytes_hex(expected),
            sha256_bytes_hex(successor)
        )
    }

    #[cfg(target_os = "linux")]
    fn install_claimant_scratch(
        fixture: &DmlClaimantScratchFixture,
        name: &str,
        bytes: &[u8],
    ) -> fs::File {
        let leaf = linux::open_dml_leaf(
            &fixture.guard.target,
            linux::DmlLeafKind::Claimant(fixture.namespace),
            &fixture.digest,
            false,
        )
        .expect("open scratch leaf")
        .expect("scratch leaf present");
        linux::create_private_dml_state(&leaf, name, bytes).expect("install scratch fixture");
        leaf
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dml_identity_claimants_reconcile_partial_install_and_partial_seal() {
        use crate::d1_dml_attempt_custody::D1DmlAttemptIdentities;
        use crate::d1_dml_identity_claimant::{
            D1DmlIdentityClaimantPhase, D1DmlIdentityNamespace, derive_d1_dml_identity_claimant_set,
        };
        use crate::d1_target::normalize_d1_target;

        let root = private_test_root("dml-identity-claimants");
        let guard = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("acquire target guard");
        guard
            .ensure_d1_dml_custody_layout()
            .expect("install sharded custody layout");
        let target =
            normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000").expect("target");
        let set = derive_d1_dml_identity_claimant_set(
            &target,
            &"a".repeat(64),
            D1DmlAttemptIdentities {
                operation_id: "operation-fixture-0001",
                execution_attempt_id: "attempt-fixture-0001",
                provider_request_id: "provider-fixture-0001",
                custody_generation_sha256:
                    crate::d1_dml_attempt_custody::TEST_CUSTODY_GENERATION_SHA256,
            },
        )
        .expect("claimant set");

        for namespace in D1DmlIdentityNamespace::ALL[..2].iter().copied() {
            let pending = set.pending(namespace);
            linux::create_d1_dml_identity_claimant(
                &guard.target,
                namespace,
                set.identity_sha256(namespace),
                pending.state_bytes(),
            )
            .expect("install partial Pending set");
        }
        let last = D1DmlIdentityNamespace::ProviderRequest;
        assert_eq!(
            linux::read_d1_dml_identity_claimant(
                &guard.target,
                last,
                set.identity_sha256(last),
                &guard.target_key_sha256,
            )
            .expect("read partial absence"),
            None
        );

        let pending = set.pending(last);
        linux::create_d1_dml_identity_claimant(
            &guard.target,
            last,
            set.identity_sha256(last),
            pending.state_bytes(),
        )
        .expect("complete Pending set");

        let binding = "b".repeat(64);
        for namespace in D1DmlIdentityNamespace::ALL {
            let incumbent = linux::read_d1_dml_identity_claimant(
                &guard.target,
                namespace,
                set.identity_sha256(namespace),
                &guard.target_key_sha256,
            )
            .expect("read Pending claimant")
            .expect("claimant present");
            let restored = set
                .restore_exact(namespace, &incumbent)
                .expect("exact claimant");
            if namespace == D1DmlIdentityNamespace::Operation {
                let bound = set.bound(namespace, &binding).expect("bound claimant");
                let digest = set.identity_sha256(namespace);
                let leaf = linux::open_dml_leaf(
                    &guard.target,
                    linux::DmlLeafKind::Claimant(namespace),
                    digest,
                    false,
                )
                .expect("open claimant leaf")
                .expect("claimant leaf present");
                let successor_sha256 = sha256_bytes_hex(bound.state_bytes());
                let predecessor_sha256 = sha256_bytes_hex(restored.state_bytes());
                linux::create_private_dml_state(
                    &leaf,
                    &format!(".next.{digest}.{predecessor_sha256}.{successor_sha256}.json"),
                    bound.state_bytes(),
                )
                .expect("install exact crash scratch");
                linux::compare_exchange_d1_dml_identity_claimant(
                    &guard.target,
                    namespace,
                    set.identity_sha256(namespace),
                    restored.state_bytes(),
                    bound.state_bytes(),
                )
                .expect("install partial Bound set");
            }
        }

        for namespace in D1DmlIdentityNamespace::ALL {
            let incumbent = linux::read_d1_dml_identity_claimant(
                &guard.target,
                namespace,
                set.identity_sha256(namespace),
                &guard.target_key_sha256,
            )
            .expect("read mixed claimant")
            .expect("claimant present");
            let restored = set
                .restore_exact(namespace, &incumbent)
                .expect("restore mixed claimant");
            if restored.receipt().phase == D1DmlIdentityClaimantPhase::Pending {
                let bound = set.bound(namespace, &binding).expect("bound claimant");
                linux::compare_exchange_d1_dml_identity_claimant(
                    &guard.target,
                    namespace,
                    set.identity_sha256(namespace),
                    restored.state_bytes(),
                    bound.state_bytes(),
                )
                .expect("complete Bound set");
            }
        }
        for namespace in D1DmlIdentityNamespace::ALL {
            let bytes = linux::read_d1_dml_identity_claimant(
                &guard.target,
                namespace,
                set.identity_sha256(namespace),
                &guard.target_key_sha256,
            )
            .expect("read complete Bound claimant")
            .expect("bound claimant present");
            assert_eq!(
                set.restore_exact(namespace, &bytes)
                    .expect("restore Bound claimant")
                    .receipt()
                    .phase,
                D1DmlIdentityClaimantPhase::Bound
            );
        }
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dml_shards_scale_and_complete_audit_every_canonical_leaf() {
        use crate::d1_dml_attempt_custody::D1DmlAttemptIdentities;
        use crate::d1_dml_identity_claimant::{
            D1DmlIdentityNamespace, derive_d1_dml_identity_claimant_set,
        };
        use crate::d1_target::normalize_d1_target;

        let root = private_test_root("dml-many-shards");
        let guard = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("acquire target guard");
        guard
            .ensure_d1_dml_custody_layout()
            .expect("install fixed layout");
        let target =
            normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000").expect("target");
        let mut leaves = BTreeSet::new();
        for index in 0..64 {
            let operation = format!("operation-volume-{index:04}");
            let attempt = format!("attempt-volume-{index:04}");
            let provider = format!("provider-volume-{index:04}");
            let set = derive_d1_dml_identity_claimant_set(
                &target,
                &sha256_bytes_hex(format!("plan-{index}").as_bytes()),
                D1DmlAttemptIdentities {
                    operation_id: &operation,
                    execution_attempt_id: &attempt,
                    provider_request_id: &provider,
                    custody_generation_sha256:
                        crate::d1_dml_attempt_custody::TEST_CUSTODY_GENERATION_SHA256,
                },
            )
            .expect("derive volume claimant set");
            guard
                .preflight_d1_dml_identity_claimant_set_capacity(&set)
                .expect("preflight complete set before writes");
            for namespace in D1DmlIdentityNamespace::ALL {
                let digest = set.identity_sha256(namespace);
                leaves.insert((namespace, digest[..4].to_string()));
                let pending = set.pending(namespace);
                guard
                    .create_d1_dml_identity_claimant(namespace, digest, pending.state_bytes())
                    .expect("install sharded claimant");
            }
        }
        assert!(
            leaves.len() > 150,
            "volume must exercise many independent leaves"
        );
        let audit = guard
            .audit_d1_dml_custody_complete()
            .expect("stable complete audit");
        assert_eq!(audit.claimant_count, 192);
        assert_eq!(audit.pending_claimant_count, 192);
        assert_eq!(audit.claimant_set_count, 64);
        assert_eq!(audit.complete_claimant_set_count, 64);
        assert_eq!(audit.matched_claimant_set_count, 0);
        assert_eq!(audit.unmatched_claimant_set_count, 64);
        assert_eq!(audit.orphan_claimant_set_count, 0);
        assert_eq!(audit.incomplete_claimant_set_count, 0);
        assert!(audit.reconciliation_required);
        assert_eq!(
            audit.provider_dispatch_authority,
            crate::d1_dml_custody_layout::D1DmlCustodyAuditProviderAuthority::None
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_dml_audit_proves_both_physical_insertion_orders_bidirectionally() {
        use crate::d1_dml_identity_claimant::D1DmlIdentityNamespace;

        let claimants_first = dml_complete_audit_fixture("dml-audit-claimants-first");
        for namespace in D1DmlIdentityNamespace::ALL {
            install_pending_audit_claimant(&claimants_first, namespace);
            seal_audit_claimant(&claimants_first, namespace);
        }
        let orphan = claimants_first
            .guard
            .audit_d1_dml_custody_complete()
            .expect("complete Bound set without attempt is classifiable");
        assert_eq!(orphan.attempt_count, 0);
        assert_eq!(orphan.claimant_set_count, 1);
        assert_eq!(orphan.complete_claimant_set_count, 1);
        assert_eq!(orphan.matched_claimant_set_count, 0);
        assert_eq!(orphan.unmatched_claimant_set_count, 1);
        assert_eq!(orphan.orphan_claimant_set_count, 1);
        assert!(orphan.reconciliation_required);
        assert_eq!(
            orphan.provider_dispatch_authority,
            crate::d1_dml_custody_layout::D1DmlCustodyAuditProviderAuthority::None
        );
        install_audit_attempt(&claimants_first);
        let matched = claimants_first
            .guard
            .audit_d1_dml_custody_complete()
            .expect("attempt closes the exact claimant-first product");
        assert_eq!(matched.attempt_count, 1);
        assert_eq!(
            matched.attempt_phase_counts,
            crate::d1_dml_custody_layout::D1DmlCustodyAttemptPhaseCounts {
                terminal_applied: 1,
                ..Default::default()
            }
        );
        assert_eq!(matched.matched_claimant_set_count, 1);
        assert_eq!(matched.unmatched_claimant_set_count, 0);
        assert_eq!(matched.orphan_claimant_set_count, 0);
        assert!(!matched.reconciliation_required);
        assert_eq!(
            matched.audit_budget_version,
            crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_VERSION
        );
        assert_eq!(
            matched.audit_budget_sha256,
            crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_SHA256
        );
        assert_eq!(
            matched.audited_leaf_limit,
            crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_LEAF_LIMIT
        );
        assert_eq!(
            matched.physical_artifact_limit,
            crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_ARTIFACT_LIMIT
        );
        assert_eq!(
            matched.artifact_payload_byte_limit,
            crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_PAYLOAD_BYTE_LIMIT
        );
        assert_eq!(matched.physical_artifact_count, 4);
        assert!(matched.audited_leaf_count > 0);
        assert!(matched.artifact_payload_bytes > 0);
        let aggregate = serde_json::to_string(&matched).expect("aggregate audit receipt JSON");
        for private_value in [
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "operation-complete-audit-0001",
            "attempt-complete-audit-0001",
            "provider-complete-audit-0001",
            "dml-custody-v1/claimant",
        ] {
            assert!(
                !aggregate.contains(private_value),
                "aggregate complete audit must not expose private identity or path evidence"
            );
        }
        fs::remove_dir_all(claimants_first.root).expect("claimants-first cleanup");

        let attempt_first = dml_complete_audit_fixture("dml-audit-attempt-first");
        install_audit_attempt(&attempt_first);
        let unmatched = attempt_first
            .guard
            .audit_d1_dml_custody_complete()
            .expect("an unmatched canonical attempt is reconciliation evidence");
        assert_eq!(unmatched.attempt_count, 1);
        assert_eq!(unmatched.unmatched_attempt_count, 1);
        assert!(unmatched.reconciliation_required);
        assert_eq!(
            unmatched.provider_dispatch_authority,
            crate::d1_dml_custody_layout::D1DmlCustodyAuditProviderAuthority::None
        );
        install_pending_audit_claimant(&attempt_first, D1DmlIdentityNamespace::Operation);
        seal_audit_claimant(&attempt_first, D1DmlIdentityNamespace::Operation);
        let partial_attempt = attempt_first
            .guard
            .audit_d1_dml_custody_complete()
            .expect("partial exact claimant recovery remains reconciliation evidence");
        assert_eq!(partial_attempt.unmatched_attempt_count, 1);
        assert_eq!(partial_attempt.unmatched_claimant_set_count, 1);
        assert_eq!(partial_attempt.incomplete_claimant_set_count, 1);
        assert!(partial_attempt.reconciliation_required);
        for namespace in D1DmlIdentityNamespace::ALL[1..].iter().copied() {
            install_pending_audit_claimant(&attempt_first, namespace);
            seal_audit_claimant(&attempt_first, namespace);
        }
        let restored = attempt_first
            .guard
            .audit_d1_dml_custody_complete()
            .expect("later exact claimant set closes attempt-first restore");
        assert_eq!(restored.matched_claimant_set_count, 1);
        assert_eq!(restored.unmatched_claimant_set_count, 0);
        assert_eq!(restored.unmatched_attempt_count, 0);
        assert_eq!(
            restored.attempt_phase_counts,
            crate::d1_dml_custody_layout::D1DmlCustodyAttemptPhaseCounts {
                terminal_applied: 1,
                ..Default::default()
            }
        );
        assert!(!restored.reconciliation_required);
        fs::remove_dir_all(attempt_first.root).expect("attempt-first cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_dml_audit_binds_every_canonical_attempt_phase_and_authorizes_only_terminal() {
        use crate::d1_dml_attempt_custody::D1DmlAttemptPhase;
        use crate::d1_dml_custody_layout::D1DmlCustodyAttemptPhaseCounts;
        use crate::d1_dml_identity_claimant::D1DmlIdentityNamespace;

        let cases = [
            (
                "prepared",
                D1DmlAttemptPhase::Prepared,
                D1DmlCustodyAttemptPhaseCounts {
                    prepared: 1,
                    ..Default::default()
                },
                false,
            ),
            (
                "dispatch-reserved",
                D1DmlAttemptPhase::DispatchReserved,
                D1DmlCustodyAttemptPhaseCounts {
                    dispatch_reserved: 1,
                    ..Default::default()
                },
                false,
            ),
            (
                "reconciliation-required",
                D1DmlAttemptPhase::ReconciliationRequired,
                D1DmlCustodyAttemptPhaseCounts {
                    reconciliation_required: 1,
                    ..Default::default()
                },
                false,
            ),
            (
                "terminal-applied",
                D1DmlAttemptPhase::TerminalApplied,
                D1DmlCustodyAttemptPhaseCounts {
                    terminal_applied: 1,
                    ..Default::default()
                },
                true,
            ),
            (
                "terminal-not-applied",
                D1DmlAttemptPhase::TerminalNotApplied,
                D1DmlCustodyAttemptPhaseCounts {
                    terminal_not_applied: 1,
                    ..Default::default()
                },
                true,
            ),
        ];
        let case_count = cases.len();
        let mut audit_digests = BTreeSet::new();
        for (label, phase, expected_counts, terminal) in cases {
            let fixture =
                dml_complete_audit_fixture_with_phase(&format!("dml-phase-{label}"), phase);
            for namespace in D1DmlIdentityNamespace::ALL {
                install_pending_audit_claimant(&fixture, namespace);
                seal_audit_claimant(&fixture, namespace);
            }
            install_audit_attempt(&fixture);

            let audit = fixture
                .guard
                .audit_d1_dml_custody_complete()
                .expect("canonical phase remains classifiable");
            assert_eq!(audit.attempt_count, 1, "{label}");
            assert_eq!(audit.attempt_phase_counts, expected_counts, "{label}");
            assert_eq!(audit.attempt_phase_counts.total(), Some(1), "{label}");
            assert_eq!(
                audit.reconciliation_required, !terminal,
                "{label} authority classification"
            );
            assert_eq!(
                audit
                    .authorize_target_wide_custody(fixture.guard.dml_custody_authority())
                    .is_ok(),
                terminal,
                "{label} target-wide authority"
            );
            assert!(
                audit_digests.insert(audit.audit_sha256),
                "each phase product must bind a distinct audit digest"
            );
            fs::remove_dir_all(fixture.root).expect("phase fixture cleanup");
        }
        assert_eq!(audit_digests.len(), case_count);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_dml_audit_rejects_malformed_unknown_and_alias_restored_phases() {
        use crate::d1_dml_attempt_custody::D1DmlAttemptPhase;
        use crate::d1_dml_identity_claimant::D1DmlIdentityNamespace;

        let cases = [
            ("valid-name-contradiction", "\"prepared\""),
            ("pascal-alias", "\"TerminalApplied\""),
            ("camel-alias", "\"terminalApplied\""),
            ("whitespace-alias", "\"terminal_applied \""),
            ("unknown-future-phase", "\"terminal_confirmed\""),
            ("null-phase", "null"),
            ("numeric-phase", "1"),
            ("array-phase", "[]"),
            ("object-phase", "{}"),
            (
                "duplicate-phase",
                "\"terminal_applied\",\"phase\":\"terminal_not_applied\"",
            ),
        ];
        for (label, replacement) in cases {
            let fixture = dml_complete_audit_fixture_with_phase(
                &format!("dml-restored-phase-{label}"),
                D1DmlAttemptPhase::TerminalApplied,
            );
            for namespace in D1DmlIdentityNamespace::ALL {
                install_pending_audit_claimant(&fixture, namespace);
                seal_audit_claimant(&fixture, namespace);
            }
            let canonical = std::str::from_utf8(fixture.attempt.state_bytes())
                .expect("synthetic attempt is UTF-8");
            let restored = canonical.replace(
                "\"phase\":\"terminal_applied\"",
                &format!("\"phase\":{replacement}"),
            );
            assert_ne!(
                restored, canonical,
                "{label} fixture must change phase bytes"
            );
            install_raw_audit_attempt(&fixture, restored.as_bytes());

            let error = fixture
                .guard
                .authorize_target_wide_d1_dml_custody()
                .expect_err("malformed or aliased restored phase cannot authorize")
                .structured_content
                .expect("structured phase denial");
            assert_eq!(
                error["error"]["code"],
                json!("d1.target_wide_dml_custody_unproven"),
                "{label}"
            );
            assert_eq!(error["provider_calls"], json!(0), "{label}");
            assert_eq!(error["provider_mutations"], json!(0), "{label}");
            assert_eq!(error["status"], json!("reconciliation_required"), "{label}");
            fs::remove_dir_all(fixture.root).expect("restored-phase cleanup");
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_zero_provider_calls(result: CallToolResult, label: &str) -> Value {
        let content = result
            .structured_content
            .unwrap_or_else(|| panic!("{label} must return structured evidence"));
        assert_eq!(content["provider_calls"], json!(0), "{label}");
        assert!(
            content.get("provider_mutations").is_none()
                || content["provider_mutations"] == json!(0),
            "{label}"
        );
        content
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nonterminal_attempt_blocks_every_migration_custody_consumer_before_provider_access() {
        use crate::d1_dml_attempt_custody::D1DmlAttemptPhase;

        let acquisition_root = private_test_root("phase-blocks-migration-acquisition");
        let acquisition_guard = acquire_d1_target_mutation_guard_at(
            acquisition_root.clone(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("acquire phase fixture guard");
        install_phase_graph_on_target(
            &acquisition_guard.target,
            &acquisition_guard.target_key_sha256,
            "migration-acquisition-prepared",
            D1DmlAttemptPhase::Prepared,
        );
        drop(acquisition_guard);
        let acquisition = acquire_d1_migration_lease_at(
            acquisition_root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &"a".repeat(64),
        )
        .expect_err("Prepared evidence must block fresh migration authority");
        let acquisition = assert_zero_provider_calls(acquisition, "migration acquisition");
        assert_eq!(
            acquisition["error"]["code"],
            json!("d1.migration_dml_custody_unproven")
        );
        assert!(
            !acquisition_root
                .join(format!(
                    "d1-migration-target-{}",
                    sha256_bytes_hex(b"acct-1\0123e4567-e89b-42d3-a456-426614174000")
                ))
                .join(ACTIVE_LEASE_NAME)
                .exists(),
            "denied acquisition must not persist target-wide authority"
        );
        fs::remove_dir_all(acquisition_root).expect("acquisition fixture cleanup");

        let owner_root = private_test_root("phase-blocks-owner-revalidation");
        let mut owner = acquire_d1_migration_lease_at(
            owner_root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &"b".repeat(64),
        )
        .expect("create clean owner before unresolved restore");
        install_phase_graph_on_target(
            &owner.target,
            &owner.identity.target_key_sha256,
            "owner-dispatch-reserved",
            D1DmlAttemptPhase::DispatchReserved,
        );
        assert_zero_provider_calls(
            owner
                .revalidate()
                .expect_err("DispatchReserved evidence must block owner revalidation"),
            "owner revalidation",
        );
        assert_zero_provider_calls(
            owner
                .release()
                .expect_err("DispatchReserved evidence must block owner retirement"),
            "owner retirement",
        );
        owner.retain();
        drop(owner);
        fs::remove_dir_all(owner_root).expect("owner fixture cleanup");

        let inspection_root = private_test_root("phase-blocks-retained-inspection");
        let mut inspection_owner = acquire_d1_migration_lease_at(
            inspection_root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &"c".repeat(64),
        )
        .expect("create retained inspection fixture");
        let inspection_identity = inspection_owner.identity.clone();
        let inspection_target = inspection_owner
            .active_path_for_test()
            .expect("inspection active path")
            .parent()
            .expect("inspection target")
            .to_path_buf();
        inspection_owner.retain();
        drop(inspection_owner);
        let inspection_target_file = fs::File::open(&inspection_target).expect("open target");
        install_phase_graph_on_target(
            &inspection_target_file,
            &inspection_identity.target_key_sha256,
            "retained-reconciliation-required",
            D1DmlAttemptPhase::ReconciliationRequired,
        );
        drop(inspection_target_file);
        let inspection = inspect_retained_d1_migration_lease_at(
            inspection_root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &"c".repeat(64),
            &inspection_identity.nonce,
            &inspection_identity.payload_sha256,
        )
        .expect_err("unresolved evidence must block retained inspection");
        assert_zero_provider_calls(inspection, "retained inspection");
        fs::remove_dir_all(inspection_root).expect("inspection fixture cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nonterminal_attempt_blocks_terminal_persistence_readback_and_retirement_without_mutation() {
        use crate::d1_dml_attempt_custody::D1DmlAttemptPhase;

        let root = private_test_root("phase-blocks-terminal-consumers");
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &"d".repeat(64),
        )
        .expect("create terminal-consumer fixture");
        let identity = owner.identity.clone();
        owner.retain();
        drop(owner);
        let mut retained = inspect_retained_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &"d".repeat(64),
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("inspect clean retained fixture");
        let expected = terminal_receipt(&identity, &"e".repeat(64));
        let (receipt_evidence, created) = retained
            .persist_terminal_receipt(&expected)
            .expect("persist terminal receipt before unresolved restore");
        assert!(created);
        install_phase_graph_on_target(
            &retained.target,
            &retained.identity.target_key_sha256,
            "terminal-consumer-prepared",
            D1DmlAttemptPhase::Prepared,
        );

        assert_zero_provider_calls(
            retained
                .revalidate()
                .expect_err("Prepared evidence must block retained revalidation"),
            "retained revalidation",
        );
        let persistence = retained
            .persist_terminal_receipt(&expected)
            .expect_err("Prepared evidence must block terminal receipt replay");
        assert_eq!(persistence.local_namespace_mutations, 0);
        assert_zero_provider_calls(persistence.result, "terminal receipt persistence");
        let readback = retained.terminal_evidence_readback(&expected, None);
        assert_eq!(readback.custody, D1TerminalCustodyNamespace::Unverified);
        assert_eq!(readback.receipt_persisted, None);
        let retirement = retained
            .retire_after_terminal_receipt(&receipt_evidence)
            .expect_err("Prepared evidence must block terminal retirement");
        assert_eq!(retirement.local_namespace_mutations, 0);
        assert_zero_provider_calls(retirement.result, "terminal retirement");
        drop(retained);
        fs::remove_dir_all(root).expect("terminal-consumer fixture cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_wide_dml_authority_rejects_absent_partial_orphan_stale_and_nonfixed_evidence() {
        use crate::d1_dml_identity_claimant::D1DmlIdentityNamespace;

        let absent_root = private_unactivated_test_root("dml-authority-absent");
        let absent = acquire_d1_target_mutation_guard_at(
            absent_root.clone(),
            "d1_delete_database",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect_err("ordinary target-wide acquisition cannot create absent custody")
        .structured_content
        .expect("structured absent-custody error");
        assert_eq!(absent["provider_calls"], json!(0));
        assert_eq!(absent["provider_mutations"], json!(0));
        let target_name = format!(
            "d1-migration-target-{}",
            sha256_bytes_hex(b"acct-1\0123e4567-e89b-42d3-a456-426614174000")
        );
        assert!(
            !absent_root
                .join(&target_name)
                .join(ACTIVE_LEASE_NAME)
                .exists(),
            "failed complete audit must not persist migration authority"
        );
        fs::remove_dir_all(absent_root).expect("absent cleanup");

        let partial = dml_complete_audit_fixture("dml-authority-partial");
        install_pending_audit_claimant(&partial, D1DmlIdentityNamespace::Operation);
        assert!(
            partial
                .guard
                .authorize_target_wide_d1_dml_custody()
                .is_err(),
            "partial claimant custody is reconciliation evidence, not authority"
        );
        fs::remove_dir_all(partial.root).expect("partial cleanup");

        let clean = dml_complete_audit_fixture("dml-authority-stale");
        for namespace in D1DmlIdentityNamespace::ALL {
            install_pending_audit_claimant(&clean, namespace);
            seal_audit_claimant(&clean, namespace);
        }
        assert!(
            clean.guard.authorize_target_wide_d1_dml_custody().is_err(),
            "a complete Bound claimant set without its attempt is orphan evidence"
        );
        install_audit_attempt(&clean);
        let authorization = clean
            .guard
            .authorize_target_wide_d1_dml_custody()
            .expect("matched graph authorizes a target-wide boundary");
        let mut nonfixed_budget = clean
            .guard
            .audit_d1_dml_custody_complete()
            .expect("clean aggregate receipt");
        nonfixed_budget.audited_leaf_limit -= 1;
        assert!(
            nonfixed_budget
                .authorize_target_wide_custody(clean.guard.dml_custody_authority())
                .is_err(),
            "a nonfixed or over-budget receipt identity cannot authorize"
        );

        let attempt_binding = &clean.attempt.receipt().attempt_binding_sha256;
        let attempt_path = clean
            .root
            .join(&clean.guard.target_name)
            .join("dml-custody-v1/attempt")
            .join(&attempt_binding[..2])
            .join(&attempt_binding[2..4])
            .join(format!("{attempt_binding}.json"));
        fs::remove_file(attempt_path).expect("simulate a changed restored graph");
        let stale = clean
            .guard
            .revalidate_target_wide_d1_dml_custody(&authorization)
            .expect_err("stale audit identity must fail at the last authority boundary")
            .structured_content
            .expect("structured stale-custody error");
        assert_eq!(
            stale["error"]["code"],
            json!("d1.target_wide_dml_custody_unproven")
        );
        fs::remove_dir_all(clean.root).expect("stale cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_wide_dml_authority_rejects_a_graph_that_changes_between_complete_passes() {
        use crate::d1_dml_identity_claimant::D1DmlIdentityNamespace;

        let fixture = dml_complete_audit_fixture("dml-authority-unstable");
        for namespace in D1DmlIdentityNamespace::ALL {
            install_pending_audit_claimant(&fixture, namespace);
            seal_audit_claimant(&fixture, namespace);
        }
        install_audit_attempt(&fixture);
        let attempt_binding = fixture.attempt.receipt().attempt_binding_sha256.clone();
        let target_path = fixture.root.join(&fixture.guard.target_name);
        let attempt_path = target_path
            .join("dml-custody-v1/attempt")
            .join(&attempt_binding[..2])
            .join(&attempt_binding[2..4])
            .join(format!("{attempt_binding}.json"));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        linux::install_complete_dml_audit_pause_hook(&target_path, entered_tx, resume_rx);
        let guard = fixture.guard;
        let audited = std::thread::spawn(move || guard.authorize_target_wide_d1_dml_custody());
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("complete audit reached its stable-pass boundary");
        fs::remove_file(attempt_path).expect("change graph between complete passes");
        resume_tx.send(()).expect("resume complete audit");
        let error = audited
            .join()
            .expect("complete-audit thread")
            .expect_err("unstable complete custody cannot authorize")
            .structured_content
            .expect("structured unstable-custody error");
        assert_eq!(
            error["error"]["code"],
            json!("d1.target_wide_dml_custody_unproven")
        );
        assert_eq!(
            error["error"]["message"],
            json!("DML custody changed during stable complete audit")
        );
        fs::remove_dir_all(fixture.root).expect("unstable cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn migration_authority_receipt_binds_complete_audit_and_rechecks_before_retirement() {
        let root = private_test_root("migration-complete-audit-binding");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("clean complete audit permits migration authority");
        let active = owner.active_path_for_test().expect("active lease path");
        let payload = fs::read(&active).expect("read active lease receipt");
        assert_eq!(
            sha256_bytes_hex(&payload),
            owner.identity.payload_sha256,
            "downstream lease identity must bind the complete-audit projection"
        );
        let decoded: Value = serde_json::from_slice(&payload).expect("lease receipt JSON");
        assert_eq!(
            decoded["dml_custody_authorization"]["audit_sha256"],
            json!(&owner.dml_custody_authorization.audit_sha256)
        );

        let marker = active
            .parent()
            .expect("target directory")
            .join("dml-custody-v1/layout.json");
        fs::remove_file(marker).expect("simulate an incomplete restored layout");
        assert!(
            owner.revalidate().is_err(),
            "changed complete custody blocks migration provider authority"
        );
        assert!(
            owner.release().is_err(),
            "changed complete custody blocks terminal retirement"
        );
        assert!(
            active.exists(),
            "blocked retirement retains active evidence"
        );
        owner.retain();
        fs::remove_dir_all(root).expect("migration audit binding cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_dml_custody_provisioning_rejects_orphan_layout_without_repair() {
        use std::os::unix::fs::PermissionsExt;

        let root = private_unactivated_test_root("target-wide-hostile-layout");
        provision_d1_dml_custody_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            TEST_D1_DML_CUSTODY_GENERATION,
            TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
        )
        .expect("install exact baseline before orphan fixture");
        let target_hash = sha256_bytes_hex(b"acct-1\0123e4567-e89b-42d3-a456-426614174000");
        let target = root.join(format!("d1-migration-target-{target_hash}"));
        fs::remove_file(target.join(crate::d1_dml_custody_genesis::D1_DML_CUSTODY_GENESIS_NAME))
            .expect("remove genesis for orphan fixture");
        fs::remove_dir_all(target.join("dml-custody-v1"))
            .expect("remove canonical layout for orphan fixture");
        let layout = target.join("dml-custody-v1");
        fs::create_dir(&layout).expect("install hostile layout directory");
        fs::set_permissions(&layout, fs::Permissions::from_mode(0o700))
            .expect("make hostile layout private");
        let marker = layout.join("layout.json");
        fs::write(&marker, b"{\"version\":1}\n").expect("install hostile marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
            .expect("make hostile marker private");

        let error = provision_d1_dml_custody_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            TEST_D1_DML_CUSTODY_GENERATION,
            TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
        )
        .expect_err("hostile layout must not be repaired")
        .structured_content
        .expect("structured hostile-layout error");
        assert_eq!(error["operation"], json!("d1_provision_dml_custody"));
        assert_eq!(
            error["error"]["code"],
            json!("d1.target_guard_upgrade_activation_required")
        );
        assert_eq!(error["provider_calls"], json!(0));
        assert_eq!(error["provider_mutations"], json!(0));
        assert_eq!(
            fs::read(&marker).expect("read unchanged hostile marker"),
            b"{\"version\":1}\n",
            "fresh provisioning must not replace or repair existing evidence"
        );
        assert!(!target.join(ACTIVE_LEASE_NAME).exists());
        fs::remove_dir_all(root).expect("hostile-layout cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_dml_custody_provisioning_applies_once_converges_and_rejects_conflict() {
        let root = private_unactivated_test_root("explicit-dml-genesis");
        let first = provision_d1_dml_custody_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            TEST_D1_DML_CUSTODY_GENERATION,
            TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
        )
        .expect("first explicit provision applies");
        assert_eq!(first.apply_status, MutationApplyStatus::Applied);
        assert_eq!(first.provider_calls, 0);
        assert_eq!(first.provider_mutations, 0);

        let replay = provision_d1_dml_custody_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            TEST_D1_DML_CUSTODY_GENERATION,
            TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
        )
        .expect("exact replay converges");
        assert_eq!(replay.apply_status, MutationApplyStatus::Proven);
        assert_eq!(replay.genesis_sha256, first.genesis_sha256);

        let error = provision_d1_dml_custody_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "test-custody-generation-v2",
            TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
        )
        .expect_err("changed generation conflicts with immutable genesis")
        .structured_content
        .expect("structured provision conflict");
        assert_eq!(
            error["error"]["code"],
            json!("d1.dml_custody_provision_conflict")
        );
        assert_eq!(error["provider_calls"], json!(0));
        assert_eq!(error["provider_mutations"], json!(0));

        let exact = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("ordinary execution opens exact incumbent custody");
        exact
            .open_existing_d1_dml_custody()
            .expect("ordinary execution proves existing custody");
        drop(exact);
        fs::remove_dir_all(root).expect("explicit provision cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_dml_guard_never_provisions_an_empty_root() {
        let root = private_unactivated_test_root("ordinary-open-only");
        let error = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect_err("ordinary execution cannot provision custody")
        .structured_content
        .expect("structured open-only denial");
        assert_eq!(error["provider_calls"], json!(0));
        assert_eq!(error["provider_mutations"], json!(0));
        assert_eq!(
            fs::read_dir(&root).expect("read untouched root").count(),
            0,
            "ordinary guard acquisition must create no root or target evidence"
        );
        fs::remove_dir_all(root).expect("open-only cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn guard_rejects_attempt_and_claimant_products_from_another_custody_generation() {
        use crate::d1_dml_attempt_custody::{
            D1DmlAttemptIdentities, D1DmlAttemptPhase,
            synthetic_d1_dml_attempt_for_complete_audit_phase,
        };
        use crate::d1_dml_identity_claimant::{
            D1DmlIdentityNamespace, derive_d1_dml_identity_claimant_set,
        };

        const FOREIGN_GENERATION_SHA256: &str =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let root = private_test_root("foreign-dml-generation");
        let guard = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("acquire exact-generation guard");
        let target =
            crate::d1_target::normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000")
                .expect("canonical target");
        let identities = D1DmlAttemptIdentities {
            operation_id: "foreign-operation-0001",
            execution_attempt_id: "foreign-attempt-00001",
            provider_request_id: "foreign-provider-0001",
            custody_generation_sha256: FOREIGN_GENERATION_SHA256,
        };
        let plan = "a".repeat(64);
        let set = derive_d1_dml_identity_claimant_set(&target, &plan, identities)
            .expect("derive foreign-generation claimant set");
        let preflight = guard
            .preflight_d1_dml_identity_claimant_set_capacity(&set)
            .expect_err("foreign-generation set cannot reserve capacity");
        assert_eq!(
            preflight.structured_content.expect("preflight error")["provider_calls"],
            json!(0)
        );
        let pending = set.pending(D1DmlIdentityNamespace::Operation);
        assert!(
            guard
                .create_d1_dml_identity_claimant(
                    D1DmlIdentityNamespace::Operation,
                    set.identity_sha256(D1DmlIdentityNamespace::Operation),
                    pending.state_bytes(),
                )
                .is_err()
        );
        let attempt = synthetic_d1_dml_attempt_for_complete_audit_phase(
            &target.target_key_sha256(),
            &plan,
            identities,
            D1DmlAttemptPhase::Prepared,
        );
        assert!(
            guard
                .create_d1_dml_attempt_state(
                    &attempt.receipt().attempt_binding_sha256,
                    attempt.state_bytes(),
                )
                .is_err()
        );
        assert_eq!(
            guard
                .audit_d1_dml_custody_complete()
                .expect("foreign products were not persisted")
                .physical_artifact_count,
            0
        );
        drop(guard);
        fs::remove_dir_all(root).expect("foreign-generation cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nonterminal_attempts_fail_closed_on_genesis_or_layout_loss_without_recreation() {
        use crate::d1_dml_attempt_custody::D1DmlAttemptPhase;
        use crate::d1_dml_identity_claimant::D1DmlIdentityNamespace;

        for (phase_label, phase) in [
            ("prepared", D1DmlAttemptPhase::Prepared),
            ("dispatch-reserved", D1DmlAttemptPhase::DispatchReserved),
            (
                "reconciliation-required",
                D1DmlAttemptPhase::ReconciliationRequired,
            ),
        ] {
            for lost in ["genesis", "layout"] {
                let fixture = dml_complete_audit_fixture_with_phase(
                    &format!("dml-{phase_label}-{lost}-loss"),
                    phase,
                );
                for namespace in D1DmlIdentityNamespace::ALL {
                    install_pending_audit_claimant(&fixture, namespace);
                    seal_audit_claimant(&fixture, namespace);
                }
                install_audit_attempt(&fixture);
                let root = fixture.root.clone();
                let target = root.join(&fixture.guard.target_name);
                drop(fixture.guard);
                let lost_path = if lost == "genesis" {
                    target.join(crate::d1_dml_custody_genesis::D1_DML_CUSTODY_GENESIS_NAME)
                } else {
                    target.join(crate::d1_dml_custody_layout::D1_DML_CUSTODY_LAYOUT_NAME)
                };
                if lost == "genesis" {
                    fs::remove_file(&lost_path).expect("remove genesis evidence");
                } else {
                    fs::remove_dir_all(&lost_path).expect("remove layout evidence");
                }

                let error = acquire_d1_target_mutation_guard_at(
                    root.clone(),
                    "d1_execute_write",
                    "acct-1",
                    "123e4567-e89b-42d3-a456-426614174000",
                )
                .expect_err("nonterminal custody loss must deny before provider")
                .structured_content
                .expect("structured custody-loss denial");
                assert_eq!(error["provider_calls"], json!(0), "{phase_label}/{lost}");
                assert_eq!(
                    error["provider_mutations"],
                    json!(0),
                    "{phase_label}/{lost}"
                );
                assert!(
                    !lost_path.exists(),
                    "ordinary execution must not recreate {lost} after {phase_label}"
                );
                fs::remove_dir_all(root).expect("custody-loss cleanup");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_reconciliation_does_not_recreate_an_absent_dml_layout() {
        let root = private_test_root("retained-absent-dml-layout");
        let plan = "a".repeat(64);
        let account_id = format!("acct-{}", std::process::id());
        let database_id = format!("123e4567-e89b-42d3-a456-{:012x}", std::process::id());
        provision_d1_dml_custody_at(
            root.clone(),
            &account_id,
            &database_id,
            TEST_D1_DML_CUSTODY_GENERATION,
            TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
        )
        .expect("explicitly provision retained-layout target");
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            &account_id,
            &database_id,
            "newsletter-core",
            &plan,
        )
        .expect("create retained fixture authority");
        let nonce = owner.identity.nonce.clone();
        let payload_sha256 = owner.identity.payload_sha256.clone();
        let target = owner
            .active_path_for_test()
            .expect("retained active path")
            .parent()
            .expect("retained target directory")
            .to_path_buf();
        owner.retain();
        fs::remove_dir_all(target.join("dml-custody-v1")).expect("simulate restored layout loss");

        let error = inspect_retained_d1_migration_lease_at(
            root.clone(),
            &account_id,
            &database_id,
            "newsletter-core",
            &plan,
            &nonce,
            &payload_sha256,
        )
        .expect_err("retained reconciliation must fail closed on absent layout")
        .structured_content
        .expect("structured retained-layout error");
        assert_eq!(
            error["error"]["code"],
            json!("d1.migration_reconciliation_lease_changed")
        );
        assert_eq!(error["provider_calls"], json!(0));
        assert!(
            !target.join("dml-custody-v1").exists(),
            "read-only retained inspection must not recreate custody"
        );
        fs::remove_dir_all(root).expect("retained-layout cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_dml_audit_enforces_each_global_budget_at_the_exact_boundary() {
        use crate::d1_dml_identity_claimant::D1DmlIdentityNamespace;

        let fixture = dml_complete_audit_fixture("dml-audit-global-budget");
        for namespace in D1DmlIdentityNamespace::ALL {
            install_pending_audit_claimant(&fixture, namespace);
            seal_audit_claimant(&fixture, namespace);
        }
        install_audit_attempt(&fixture);
        let baseline = fixture
            .guard
            .audit_d1_dml_custody_complete()
            .expect("default global budget accepts one exact matched graph");
        assert_eq!(baseline.matched_claimant_set_count, 1);
        assert_eq!(baseline.unmatched_claimant_set_count, 0);
        assert_eq!(baseline.unmatched_attempt_count, 0);
        assert!(!baseline.reconciliation_required);

        let exact = linux::audit_d1_dml_custody_complete_with_test_limits(
            &fixture.guard.target,
            &fixture.guard.target_key_sha256,
            baseline.audited_leaf_count,
            baseline.physical_artifact_count,
            baseline.artifact_payload_bytes,
        )
        .expect("both stable passes receive fresh exact-boundary budgets");
        assert_eq!(exact.audited_leaf_count, exact.audited_leaf_limit);
        assert_eq!(exact.physical_artifact_count, exact.physical_artifact_limit);
        assert_eq!(
            exact.artifact_payload_bytes,
            exact.artifact_payload_byte_limit
        );
        assert_eq!(exact.matched_claimant_set_count, 1);
        assert!(!exact.reconciliation_required);
        assert_ne!(exact.audit_budget_sha256, baseline.audit_budget_sha256);
        assert_ne!(exact.audit_sha256, baseline.audit_sha256);

        let cases = [
            (
                baseline
                    .audited_leaf_count
                    .checked_sub(1)
                    .expect("matched graph has at least one canonical leaf"),
                baseline.physical_artifact_count,
                baseline.artifact_payload_bytes,
                "DML complete audit exceeded its canonical-leaf budget",
            ),
            (
                baseline.audited_leaf_count,
                baseline
                    .physical_artifact_count
                    .checked_sub(1)
                    .expect("matched graph has at least one physical artifact"),
                baseline.artifact_payload_bytes,
                "DML complete audit exceeded its physical-artifact budget",
            ),
            (
                baseline.audited_leaf_count,
                baseline.physical_artifact_count,
                baseline
                    .artifact_payload_bytes
                    .checked_sub(1)
                    .expect("matched graph has nonempty payload evidence"),
                "DML complete audit exceeded its artifact-payload byte budget",
            ),
        ];
        for (leaf_limit, artifact_limit, payload_byte_limit, expected_error) in cases {
            let error = linux::audit_d1_dml_custody_complete_with_test_limits(
                &fixture.guard.target,
                &fixture.guard.target_key_sha256,
                leaf_limit,
                artifact_limit,
                payload_byte_limit,
            )
            .expect_err("one-over-budget audit yields no aggregate receipt");
            assert_eq!(error, expected_error);
            for private_value in [
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "operation-complete-audit-0001",
                "attempt-complete-audit-0001",
                "provider-complete-audit-0001",
                "dml-custody-v1",
            ] {
                assert!(
                    !error.contains(private_value),
                    "budget exhaustion must not expose paths, identities, or raw bytes"
                );
            }
        }
        fs::remove_dir_all(fixture.root).expect("global-budget cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_dml_audit_classifies_partial_orphan_and_scratch_products_without_authority() {
        use crate::d1_dml_identity_claimant::D1DmlIdentityNamespace;

        let partial = dml_complete_audit_fixture("dml-audit-partial");
        install_pending_audit_claimant(&partial, D1DmlIdentityNamespace::Operation);
        let pending = partial
            .guard
            .audit_d1_dml_custody_complete()
            .expect("partial Pending set remains bounded reconciliation evidence");
        assert_eq!(pending.claimant_set_count, 1);
        assert_eq!(pending.complete_claimant_set_count, 0);
        assert_eq!(pending.incomplete_claimant_set_count, 1);
        assert_eq!(pending.unmatched_claimant_set_count, 1);
        assert_eq!(pending.orphan_claimant_set_count, 0);
        assert!(pending.reconciliation_required);

        seal_audit_claimant(&partial, D1DmlIdentityNamespace::Operation);
        let bound_partial = partial
            .guard
            .audit_d1_dml_custody_complete()
            .expect("partial Bound set without attempt is orphan reconciliation evidence");
        assert_eq!(bound_partial.incomplete_claimant_set_count, 1);
        assert_eq!(bound_partial.orphan_claimant_set_count, 1);
        assert_eq!(bound_partial.matched_claimant_set_count, 0);
        assert!(bound_partial.reconciliation_required);
        assert_eq!(
            bound_partial.provider_dispatch_authority,
            crate::d1_dml_custody_layout::D1DmlCustodyAuditProviderAuthority::None
        );
        fs::remove_dir_all(partial.root).expect("partial cleanup");

        let scratch = dml_claimant_scratch_fixture("dml-audit-scratch");
        let scratch_name = claimant_scratch_name(&scratch.digest, &scratch.pending, &scratch.bound);
        install_claimant_scratch(&scratch, &scratch_name, &scratch.bound);
        let scratch_audit = scratch
            .guard
            .audit_d1_dml_custody_complete()
            .expect("one valid scratch is explicit reconciliation evidence");
        assert_eq!(scratch_audit.cas_scratch_count, 1);
        assert_eq!(scratch_audit.unmatched_claimant_set_count, 1);
        assert!(scratch_audit.reconciliation_required);
        assert_eq!(
            scratch_audit.provider_dispatch_authority,
            crate::d1_dml_custody_layout::D1DmlCustodyAuditProviderAuthority::None
        );
        fs::remove_dir_all(scratch.root).expect("scratch cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_dml_audit_rejects_digest_tampered_physical_restores() {
        use crate::d1_dml_identity_claimant::D1DmlIdentityNamespace;

        let claimant_drift = dml_complete_audit_fixture("dml-audit-claimant-drift");
        for namespace in D1DmlIdentityNamespace::ALL {
            install_pending_audit_claimant(&claimant_drift, namespace);
            seal_audit_claimant(&claimant_drift, namespace);
        }
        install_audit_attempt(&claimant_drift);
        claimant_drift
            .guard
            .audit_d1_dml_custody_complete()
            .expect("baseline graph is exact");
        let operation_digest = claimant_drift
            .set
            .identity_sha256(D1DmlIdentityNamespace::Operation);
        let operation_path = claimant_drift
            .root
            .join(&claimant_drift.guard.target_name)
            .join("dml-custody-v1/claimant/operation")
            .join(&operation_digest[..2])
            .join(&operation_digest[2..4])
            .join(format!("{operation_digest}.json"));
        let original_claimant = fs::read(&operation_path).expect("read claimant fixture");
        let mut claimant_json: Value =
            serde_json::from_slice(&original_claimant).expect("claimant JSON");
        claimant_json["intent_binding_sha256"] = json!("e".repeat(64));
        fs::write(
            &operation_path,
            serde_json::to_vec(&claimant_json).expect("tampered claimant JSON"),
        )
        .expect("install intent-drift restore");
        assert!(
            claimant_drift
                .guard
                .audit_d1_dml_custody_complete()
                .is_err(),
            "canonical-looking claimant intent drift fails closed"
        );
        fs::write(&operation_path, original_claimant).expect("restore exact claimant");
        claimant_drift
            .guard
            .audit_d1_dml_custody_complete()
            .expect("restored exact claimant graph");
        fs::remove_dir_all(claimant_drift.root).expect("claimant-drift cleanup");

        let attempt_drift = dml_complete_audit_fixture("dml-audit-attempt-drift");
        let original_binding = attempt_drift
            .attempt
            .receipt()
            .attempt_binding_sha256
            .clone();
        let mut attempt_json: Value =
            serde_json::from_slice(attempt_drift.attempt.state_bytes()).expect("attempt JSON");
        let drifted_binding = "f".repeat(64);
        attempt_json["attempt_binding_sha256"] = json!(drifted_binding);
        let mut drifted_bytes = serde_json::to_vec(&attempt_json).expect("drifted attempt JSON");
        drifted_bytes.push(b'\n');
        let drifted_leaf = linux::open_dml_leaf(
            &attempt_drift.guard.target,
            linux::DmlLeafKind::Attempt,
            &drifted_binding,
            true,
        )
        .expect("open drifted attempt leaf")
        .expect("drifted attempt leaf present");
        linux::create_private_dml_state(
            &drifted_leaf,
            &format!("{drifted_binding}.json"),
            &drifted_bytes,
        )
        .expect("install binding-drift attempt");
        assert_ne!(original_binding, drifted_binding);
        assert!(
            attempt_drift.guard.audit_d1_dml_custody_complete().is_err(),
            "canonical-looking attempt binding drift fails closed"
        );
        fs::remove_dir_all(attempt_drift.root).expect("attempt-drift cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_dml_audit_rejects_duplicate_namespace_and_contradictory_bindings() {
        use crate::d1_dml_identity_claimant::D1DmlIdentityNamespace;

        let duplicate = dml_complete_audit_fixture("dml-audit-duplicate-namespace");
        install_pending_audit_claimant(&duplicate, D1DmlIdentityNamespace::Operation);
        let mut duplicate_json: Value = serde_json::from_slice(
            duplicate
                .set
                .pending(D1DmlIdentityNamespace::Operation)
                .state_bytes(),
        )
        .expect("duplicate claimant JSON");
        let duplicate_identity = sha256_bytes_hex(b"second-physical-operation-claimant");
        assert_ne!(
            duplicate_identity,
            duplicate
                .set
                .identity_sha256(D1DmlIdentityNamespace::Operation)
        );
        duplicate_json["identity_sha256"] = json!(duplicate_identity);
        let duplicate_bytes =
            serde_json::to_vec(&duplicate_json).expect("duplicate claimant bytes");
        let duplicate_leaf = linux::open_dml_leaf(
            &duplicate.guard.target,
            linux::DmlLeafKind::Claimant(D1DmlIdentityNamespace::Operation),
            &duplicate_identity,
            true,
        )
        .expect("open duplicate claimant leaf")
        .expect("duplicate claimant leaf present");
        linux::create_private_dml_state(
            &duplicate_leaf,
            &format!("{duplicate_identity}.json"),
            &duplicate_bytes,
        )
        .expect("install duplicate namespace claimant");
        assert!(
            duplicate.guard.audit_d1_dml_custody_complete().is_err(),
            "two physical rows cannot claim one set namespace"
        );
        fs::remove_dir_all(duplicate.root).expect("duplicate cleanup");

        let contradictory = dml_complete_audit_fixture("dml-audit-conflicting-bindings");
        for namespace in D1DmlIdentityNamespace::ALL {
            install_pending_audit_claimant(&contradictory, namespace);
        }
        seal_audit_claimant(&contradictory, D1DmlIdentityNamespace::Operation);
        let conflicting_binding = "c".repeat(64);
        for namespace in [
            D1DmlIdentityNamespace::ExecutionAttempt,
            D1DmlIdentityNamespace::ProviderRequest,
        ] {
            let pending = contradictory.set.pending(namespace);
            let bound = contradictory
                .set
                .bound(namespace, &conflicting_binding)
                .expect("derive conflicting Bound claimant");
            contradictory
                .guard
                .compare_exchange_d1_dml_identity_claimant(
                    namespace,
                    contradictory.set.identity_sha256(namespace),
                    pending.state_bytes(),
                    bound.state_bytes(),
                )
                .expect("install conflicting Bound claimant");
        }
        assert!(
            contradictory.guard.audit_d1_dml_custody_complete().is_err(),
            "one claimant set cannot name contradictory attempt bindings"
        );
        fs::remove_dir_all(contradictory.root).expect("contradictory cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dml_leaf_capacity_reserves_all_missing_entries_and_one_cas_slot() {
        let limit = crate::d1_dml_custody_layout::D1_DML_CUSTODY_LEAF_ENTRY_LIMIT;
        assert!(linux::dml_leaf_capacity_available(limit - 2, 1));
        let before = limit - 1;
        assert!(!linux::dml_leaf_capacity_available(before, 1));
        assert_eq!(before, limit - 1, "failed preflight writes no entry");
        assert!(!linux::dml_leaf_capacity_available(usize::MAX, 1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dml_cas_scratch_crash_before_and_after_rename_converges_exactly_once() {
        let fixture = dml_claimant_scratch_fixture("dml-scratch-crash");
        let scratch_name = claimant_scratch_name(&fixture.digest, &fixture.pending, &fixture.bound);
        install_claimant_scratch(&fixture, &scratch_name, &fixture.bound);

        fixture
            .guard
            .compare_exchange_d1_dml_identity_claimant(
                fixture.namespace,
                &fixture.digest,
                &fixture.pending,
                &fixture.bound,
            )
            .expect("resume exact pre-rename scratch");
        assert_eq!(
            fixture
                .guard
                .read_d1_dml_identity_claimant(fixture.namespace, &fixture.digest)
                .expect("read installed successor"),
            Some(fixture.bound.clone())
        );
        assert!(
            fixture
                .guard
                .compare_exchange_d1_dml_identity_claimant(
                    fixture.namespace,
                    &fixture.digest,
                    &fixture.pending,
                    &fixture.bound,
                )
                .is_err(),
            "post-rename replay must not prepare a second scratch"
        );
        let leaf_path = fixture
            .root
            .join(&fixture.guard.target_name)
            .join("dml-custody-v1/claimant/operation")
            .join(&fixture.digest[..2])
            .join(&fixture.digest[2..4]);
        assert_eq!(
            fs::read_dir(leaf_path)
                .expect("read leaf")
                .filter(|entry| {
                    entry
                        .as_ref()
                        .ok()
                        .and_then(|entry| entry.file_name().into_string().ok())
                        .is_some_and(|name| name.starts_with(".next."))
                })
                .count(),
            0
        );
        fs::remove_dir_all(fixture.root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dml_leaf_audit_rejects_duplicate_wrong_and_stale_scratch_authority() {
        let duplicate = dml_claimant_scratch_fixture("dml-scratch-duplicate");
        let alternative = duplicate
            .set
            .bound(duplicate.namespace, &"c".repeat(64))
            .expect("alternative bound claimant")
            .state_bytes()
            .to_vec();
        let first_name =
            claimant_scratch_name(&duplicate.digest, &duplicate.pending, &duplicate.bound);
        let second_name =
            claimant_scratch_name(&duplicate.digest, &duplicate.pending, &alternative);
        install_claimant_scratch(&duplicate, &first_name, &duplicate.bound);
        install_claimant_scratch(&duplicate, &second_name, &alternative);
        assert!(
            duplicate
                .guard
                .read_d1_dml_identity_claimant(duplicate.namespace, &duplicate.digest)
                .is_err(),
            "two canonical successors for one record must be contradictory"
        );
        fs::remove_dir_all(duplicate.root).expect("duplicate cleanup");

        let wrong_incumbent = dml_claimant_scratch_fixture("dml-scratch-wrong-incumbent");
        let wrong_incumbent_name = format!(
            ".next.{}.{}.{}.json",
            wrong_incumbent.digest,
            "d".repeat(64),
            sha256_bytes_hex(&wrong_incumbent.bound)
        );
        install_claimant_scratch(
            &wrong_incumbent,
            &wrong_incumbent_name,
            &wrong_incumbent.bound,
        );
        assert!(
            wrong_incumbent
                .guard
                .read_d1_dml_identity_claimant(wrong_incumbent.namespace, &wrong_incumbent.digest,)
                .is_err(),
            "scratch predecessor must be the current permanent bytes"
        );
        fs::remove_dir_all(wrong_incumbent.root).expect("wrong incumbent cleanup");

        let wrong_successor = dml_claimant_scratch_fixture("dml-scratch-wrong-successor");
        let wrong_successor_name = format!(
            ".next.{}.{}.{}.json",
            wrong_successor.digest,
            sha256_bytes_hex(&wrong_successor.pending),
            "e".repeat(64)
        );
        install_claimant_scratch(
            &wrong_successor,
            &wrong_successor_name,
            &wrong_successor.bound,
        );
        assert!(
            wrong_successor
                .guard
                .read_d1_dml_identity_claimant(wrong_successor.namespace, &wrong_successor.digest,)
                .is_err(),
            "scratch successor digest must rederive from canonical bytes"
        );
        fs::remove_dir_all(wrong_successor.root).expect("wrong successor cleanup");

        let stale = dml_claimant_scratch_fixture("dml-scratch-stale");
        stale
            .guard
            .compare_exchange_d1_dml_identity_claimant(
                stale.namespace,
                &stale.digest,
                &stale.pending,
                &stale.bound,
            )
            .expect("install successor");
        let stale_name = claimant_scratch_name(&stale.digest, &stale.pending, &stale.bound);
        install_claimant_scratch(&stale, &stale_name, &stale.bound);
        assert!(
            stale
                .guard
                .read_d1_dml_identity_claimant(stale.namespace, &stale.digest)
                .is_err(),
            "scratch bound to a predecessor replaced by rename must be stale"
        );
        fs::remove_dir_all(stale.root).expect("stale cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dml_leaf_audit_rejects_malformed_and_non_private_scratch() {
        use std::os::unix::fs::PermissionsExt;

        let malformed_name = dml_claimant_scratch_fixture("dml-scratch-malformed-name");
        install_claimant_scratch(&malformed_name, ".next.bad.json", &malformed_name.bound);
        assert!(
            malformed_name
                .guard
                .read_d1_dml_identity_claimant(malformed_name.namespace, &malformed_name.digest,)
                .is_err()
        );
        fs::remove_dir_all(malformed_name.root).expect("malformed-name cleanup");

        let malformed_body = dml_claimant_scratch_fixture("dml-scratch-malformed-body");
        let malformed_bytes = b"null\n";
        let malformed_body_name = claimant_scratch_name(
            &malformed_body.digest,
            &malformed_body.pending,
            malformed_bytes,
        );
        install_claimant_scratch(&malformed_body, &malformed_body_name, malformed_bytes);
        assert!(
            malformed_body
                .guard
                .read_d1_dml_identity_claimant(malformed_body.namespace, &malformed_body.digest,)
                .is_err()
        );
        fs::remove_dir_all(malformed_body.root).expect("malformed-body cleanup");

        let unsafe_mode = dml_claimant_scratch_fixture("dml-scratch-mode");
        let unsafe_name = claimant_scratch_name(
            &unsafe_mode.digest,
            &unsafe_mode.pending,
            &unsafe_mode.bound,
        );
        let unsafe_leaf = install_claimant_scratch(&unsafe_mode, &unsafe_name, &unsafe_mode.bound);
        let unsafe_path = unsafe_mode
            .root
            .join(&unsafe_mode.guard.target_name)
            .join("dml-custody-v1/claimant/operation")
            .join(&unsafe_mode.digest[..2])
            .join(&unsafe_mode.digest[2..4])
            .join(&unsafe_name);
        fs::set_permissions(&unsafe_path, fs::Permissions::from_mode(0o640))
            .expect("make scratch non-private");
        assert!(
            unsafe_mode
                .guard
                .read_d1_dml_identity_claimant(unsafe_mode.namespace, &unsafe_mode.digest)
                .is_err()
        );
        drop(unsafe_leaf);
        fs::remove_dir_all(unsafe_mode.root).expect("mode cleanup");

        let hardlink = dml_claimant_scratch_fixture("dml-scratch-hardlink");
        let hardlink_name =
            claimant_scratch_name(&hardlink.digest, &hardlink.pending, &hardlink.bound);
        install_claimant_scratch(&hardlink, &hardlink_name, &hardlink.bound);
        let leaf_path = hardlink
            .root
            .join(&hardlink.guard.target_name)
            .join("dml-custody-v1/claimant/operation")
            .join(&hardlink.digest[..2])
            .join(&hardlink.digest[2..4]);
        fs::hard_link(
            leaf_path.join(&hardlink_name),
            leaf_path.join("linked-scratch"),
        )
        .expect("hardlink scratch fixture");
        assert!(
            hardlink
                .guard
                .read_d1_dml_identity_claimant(hardlink.namespace, &hardlink.digest)
                .is_err()
        );
        fs::remove_dir_all(hardlink.root).expect("hardlink cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dml_layout_and_complete_audit_reject_flat_unknown_misplaced_links_and_mixed_state() {
        use crate::d1_dml_attempt_custody::D1DmlAttemptIdentities;
        use crate::d1_dml_identity_claimant::{
            D1DmlIdentityNamespace, derive_d1_dml_identity_claimant_set,
        };
        use crate::d1_target::normalize_d1_target;
        use std::os::unix::fs::{PermissionsExt, symlink};

        let flat_root = private_test_root("dml-flat-only");
        let flat_guard = acquire_d1_target_mutation_guard_at(
            flat_root.clone(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("acquire flat-only target guard");
        let flat_only = flat_root
            .join(&flat_guard.target_name)
            .join(format!("dml-attempt.{}.state.json", "a".repeat(64)));
        fs::write(&flat_only, b"{}\n").expect("flat-only candidate artifact");
        fs::set_permissions(&flat_only, fs::Permissions::from_mode(0o600))
            .expect("private flat-only file");
        assert!(
            flat_guard.revalidate().is_err(),
            "flat-only layout fails closed"
        );
        drop(flat_guard);
        fs::remove_dir_all(flat_root).expect("flat-only cleanup");

        let root = private_test_root("dml-hostile-layout");
        let guard = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("acquire target guard");
        guard.ensure_d1_dml_custody_layout().expect("layout");
        let target =
            normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000").expect("target");
        let set = derive_d1_dml_identity_claimant_set(
            &target,
            &"a".repeat(64),
            D1DmlAttemptIdentities {
                operation_id: "operation-hostile-0001",
                execution_attempt_id: "attempt-hostile-0001",
                provider_request_id: "provider-hostile-0001",
                custody_generation_sha256:
                    crate::d1_dml_attempt_custody::TEST_CUSTODY_GENERATION_SHA256,
            },
        )
        .expect("set");
        guard
            .preflight_d1_dml_identity_claimant_set_capacity(&set)
            .expect("capacity");
        for namespace in D1DmlIdentityNamespace::ALL {
            let pending = set.pending(namespace);
            guard
                .create_d1_dml_identity_claimant(
                    namespace,
                    set.identity_sha256(namespace),
                    pending.state_bytes(),
                )
                .expect("claimant");
        }
        guard
            .audit_d1_dml_custody_complete()
            .expect("clean structure");

        let target_path = root.join(&guard.target_name);
        let marker = target_path.join("dml-custody-v1/layout.json");
        let marker_bytes = fs::read(&marker).expect("read canonical marker");
        fs::write(&marker, b"null\n").expect("malformed marker fixture");
        assert!(
            guard.revalidate().is_err(),
            "malformed marker must fail closed"
        );
        fs::write(&marker, marker_bytes).expect("restore canonical marker fixture");
        guard.revalidate().expect("restored marker revalidates");

        let flat = target_path.join(format!(
            "dml-claimant.operation.{}.state.json",
            set.identity_sha256(D1DmlIdentityNamespace::Operation)
        ));
        fs::write(&flat, b"{}\n").expect("flat candidate artifact");
        fs::set_permissions(&flat, fs::Permissions::from_mode(0o600)).expect("private flat file");
        assert!(
            guard.revalidate().is_err(),
            "flat plus sharded must fail closed"
        );
        fs::remove_file(&flat).expect("remove hostile flat fixture");

        let digest = set.identity_sha256(D1DmlIdentityNamespace::Operation);
        let leaf = target_path
            .join("dml-custody-v1/claimant/operation")
            .join(&digest[..2])
            .join(&digest[2..4]);
        let unknown = leaf.join("unknown");
        fs::write(&unknown, b"x").expect("unknown leaf entry");
        assert!(guard.audit_d1_dml_custody_complete().is_err());
        fs::remove_file(&unknown).expect("remove unknown fixture");

        let incumbent = leaf.join(format!("{digest}.json"));
        let misplaced_digest = format!(
            "{}{}",
            &digest[..63],
            if digest.ends_with('0') { "1" } else { "0" }
        );
        let misplaced = leaf.join(format!("{misplaced_digest}.json"));
        fs::copy(&incumbent, &misplaced).expect("misplaced claimant");
        fs::set_permissions(&misplaced, fs::Permissions::from_mode(0o600))
            .expect("private misplaced file");
        assert!(guard.audit_d1_dml_custody_complete().is_err());
        fs::remove_file(&misplaced).expect("remove misplaced fixture");

        let linked_digest = format!(
            "{}{}",
            &digest[..63],
            if digest.ends_with('1') { "2" } else { "1" }
        );
        let linked = leaf.join(format!("{linked_digest}.json"));
        fs::hard_link(&incumbent, &linked).expect("hardlink fixture");
        assert!(guard.audit_d1_dml_custody_complete().is_err());
        fs::remove_file(&linked).expect("remove hardlink fixture");

        let symlink_digest = format!(
            "{}{}",
            &digest[..63],
            if digest.ends_with('2') { "3" } else { "2" }
        );
        let linked = leaf.join(format!("{symlink_digest}.json"));
        symlink(&incumbent, &linked).expect("symlink fixture");
        assert!(guard.audit_d1_dml_custody_complete().is_err());
        fs::remove_file(&linked).expect("remove symlink fixture");
        guard
            .audit_d1_dml_custody_complete()
            .expect("restored clean structure");
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[test]
    fn migration_lease_requirements_expose_complete_activation_and_cutover_contract() {
        let target_key_sha256 = sha256_bytes_hex(b"acct-1\0123e4567-e89b-42d3-a456-426614174000");
        assert_eq!(
            d1_migration_lease_requirements(
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
            ),
            json!({
                "required_for_live_apply": true,
                "environment": D1_MANIFEST_LEASE_ROOT_ENV,
                "target_key_sha256": target_key_sha256,
                "migration_family": "newsletter-core",
                "scope": "one permanent directory and guard per account/database target; family is evidence only and cannot split target serialization",
                "active_evidence": "active.lease.json and transient retiring.lease.json are never auto-reclaimed; malformed, symlink, non-regular, or otherwise present active/retiring evidence stops the next apply for governed reconciliation",
                "cross_host_limitation": "Cross-process serialization covers only hosts sharing the same configured operator-owned lease root. It is not a Cloudflare/provider-distributed lease.",
                "platform_requirement": "Linux on a trusted filesystem supporting working renameat2 RENAME_NOREPLACE, directory fsync, and advisory file locks; unsupported platforms or filesystems fail closed before provider I/O. Cross-host or shared-filesystem semantics require separate proof; retained evidence requires the governed recovery path.",
                "complete_dml_custody_authority": {
                    "required": true,
                    "layout_sha256": crate::d1_dml_custody_layout::D1_DML_CUSTODY_LAYOUT_SHA256,
                    "audit_budget_version": crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_VERSION,
                    "audit_budget_sha256": crate::d1_dml_custody_layout::D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_SHA256,
                    "genesis": crate::d1_dml_custody_genesis::D1_DML_CUSTODY_GENESIS_NAME,
                    "generation_environment": crate::d1_dml_custody_genesis::D1_DML_CUSTODY_GENERATION_ENV,
                    "authority_environment": crate::d1_dml_custody_genesis::D1_DML_CUSTODY_AUTHORITY_SHA256_ENV,
                    "provisioning": "explicit_d1_provision_dml_custody_only",
                    "ordinary_execution_may_create": false,
                    "provisioning_provider_dispatch_authority": "none",
                    "retained_or_recovery_absence": "reconciliation_required_without_creation",
                    "binding": "the exact clean complete-audit identity is persisted in the lease payload and therefore inherited by every terminal receipt through lease_payload_sha256",
                    "last_boundary_revalidation": true,
                    "provider_dispatch_authority_from_audit": false,
                },
                "target_identity_activation": {
                    "contract_version": 2,
                    "target_identity_contract": "lowercase_hyphenated_uuid_v1",
                    "activation_marker": {
                        "required": true,
                        "filename": "target-identity-v2.activation.json",
                        "version": 2,
                        "payload_sha256": sha256_bytes_hex(TARGET_IDENTITY_ACTIVATION_MARKER_BYTES),
                    },
                    "target_registration": {
                        "required_for_every_target": true,
                        "create_only": true,
                        "version": 1,
                        "filename_pattern": "target-identity-v2.<target_key_sha256>.receipt.json",
                    },
                    "first_activation": {
                        "requires_fresh_empty_root": true,
                        "bounded_root_entry_limit": 4096,
                        "legacy_in_place_upgrade_allowed": false,
                    },
                    "operator_cutover": {
                        "predecessor_writer_drain_required": true,
                        "preserve_predecessor_root": true,
                        "predecessor_root_reuse_by_upgraded_writers_allowed": false,
                        "older_binary_on_activated_root_allowed": false,
                        "rollback": {
                            "upgraded_writer_drain_required": true,
                            "preserve_activated_root_without_manual_changes": true,
                            "return_all_writers_as_one_predecessor_generation": true,
                            "mixed_roots_or_binary_generations_allowed": false,
                        },
                    },
                },
            })
        );
    }

    #[cfg(target_os = "linux")]
    fn terminal_receipt(
        identity: &D1MigrationLeaseIdentity,
        approved_plan_sha256: &str,
    ) -> D1TerminalReconciliationReceipt {
        D1TerminalReconciliationReceipt {
            version: 2,
            operation: "d1_finalize_migration_reconciliation".to_string(),
            target_key_sha256: identity.target_key_sha256.clone(),
            lease_nonce: identity.nonce.clone(),
            lease_payload_sha256: identity.payload_sha256.clone(),
            approved_apply_plan_sha256: approved_plan_sha256.to_string(),
            effect_assertion_id: "schema_create_only_v1".to_string(),
            reconciliation_plan_sha256: "c".repeat(64),
            expectation_proof_sha256: "d".repeat(64),
            query_sha256: "e".repeat(64),
            canonical_snapshot_sha256: "f".repeat(64),
            terminal_request_sha256: "1".repeat(64),
            terminal_attempt_sha256: "2".repeat(64),
            terminal_plan_sha256: "3".repeat(64),
            outcome: "full_state_converged".to_string(),
            original_prefix_length: 0,
            current_prefix_length: 1,
        }
    }

    #[cfg(target_os = "linux")]
    fn terminal_receipt_v1(
        identity: &D1MigrationLeaseIdentity,
        approved_plan_sha256: &str,
    ) -> D1TerminalReconciliationReceiptV1 {
        D1TerminalReconciliationReceiptV1 {
            version: 1,
            operation: "d1_finalize_migration_reconciliation".to_string(),
            target_key_sha256: identity.target_key_sha256.clone(),
            lease_nonce: identity.nonce.clone(),
            lease_payload_sha256: identity.payload_sha256.clone(),
            approved_apply_plan_sha256: approved_plan_sha256.to_string(),
            reconciliation_plan_sha256: "c".repeat(64),
            expectation_proof_sha256: "d".repeat(64),
            query_sha256: "e".repeat(64),
            canonical_snapshot_sha256: "f".repeat(64),
            terminal_request_sha256: "1".repeat(64),
            terminal_attempt_sha256: "2".repeat(64),
            terminal_plan_sha256: "3".repeat(64),
            outcome: "full_state_converged".to_string(),
            original_prefix_length: 0,
            current_prefix_length: 1,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_terminal_receipt_authority_is_operation_and_effect_exact() {
        let identity = D1MigrationLeaseIdentity {
            target_key_sha256: "a".repeat(64),
            nonce: "b".repeat(64),
            payload_sha256: "c".repeat(64),
        };
        let mut receipt = terminal_receipt(&identity, &"d".repeat(64));
        receipt.operation = "d1_finalize_bootstrap_migration_ledger".to_string();
        receipt.effect_assertion_id = "bootstrap_canonical_empty_ledger_v1".to_string();
        assert!(valid_terminal_receipt_authority(&receipt));

        let mut null_seed_receipt = terminal_receipt(&identity, &"d".repeat(64));
        null_seed_receipt.effect_assertion_id =
            "schema_create_objects_additive_seed_rows_v2".to_string();
        assert!(valid_terminal_receipt_authority(&null_seed_receipt));

        let mut wrong_effect = receipt.clone();
        wrong_effect.effect_assertion_id = "schema_create_only_v1".to_string();
        assert!(!valid_terminal_receipt_authority(&wrong_effect));

        let mut wrong_operation = receipt;
        wrong_operation.operation = "d1_finalize_migration_reconciliation".to_string();
        assert!(!valid_terminal_receipt_authority(&wrong_operation));
    }

    #[cfg(target_os = "linux")]
    fn private_unactivated_test_root(label: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let root = PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-d1-lease-{label}-{}-{}",
            std::process::id(),
            D1_MANIFEST_LEASE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create private root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        root
    }

    #[cfg(target_os = "linux")]
    fn private_test_root(label: &str) -> PathBuf {
        let root = private_unactivated_test_root(label);
        prepare_test_dml_layout(&root);
        root
    }

    #[cfg(target_os = "linux")]
    fn prepare_test_dml_layout(root: &Path) {
        provision_d1_dml_custody_at(
            root.to_path_buf(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            TEST_D1_DML_CUSTODY_GENERATION,
            TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
        )
        .expect("provision clean complete-audit fixture layout");
    }

    #[cfg(target_os = "linux")]
    fn install_unversioned_target_entry(
        root: &Path,
        account_id: &str,
        database_id: &str,
        entry_name: Option<&str>,
        entry_bytes: &[u8],
    ) {
        use std::os::unix::fs::PermissionsExt;

        let target_hash = sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes());
        let target = root.join(format!("d1-migration-target-{target_hash}"));
        fs::create_dir(&target).expect("create unversioned target directory");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
            .expect("private unversioned target directory");
        fs::write(target.join(GUARD_NAME), b"").expect("write legacy guard");
        fs::set_permissions(target.join(GUARD_NAME), fs::Permissions::from_mode(0o600))
            .expect("private legacy guard");
        if let Some(entry_name) = entry_name {
            fs::write(target.join(entry_name), entry_bytes).expect("write legacy evidence");
            fs::set_permissions(target.join(entry_name), fs::Permissions::from_mode(0o600))
                .expect("private legacy evidence");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_identity_upgrade_requires_a_fresh_root_for_every_unversioned_namespace() {
        let canonical_database_id = "123e4567-e89b-42d3-a456-426614174000";
        let alias_database_id = "123E4567-E89B-42D3-A456-426614174000";
        let nonce = "a".repeat(64);
        let cases = vec![
            (
                "alias-active",
                alias_database_id,
                Some(ACTIVE_LEASE_NAME.to_string()),
            ),
            (
                "alias-retiring",
                alias_database_id,
                Some(RETIRING_LEASE_NAME.to_string()),
            ),
            (
                "alias-retired",
                alias_database_id,
                Some(format!("retired.{nonce}.lease.json")),
            ),
            (
                "alias-terminal",
                alias_database_id,
                Some(format!("terminal-reconciliation.{nonce}.receipt.json")),
            ),
            ("canonical-incumbent", canonical_database_id, None),
        ];

        for (label, database_id, entry_name) in cases {
            let root = private_unactivated_test_root(label);
            install_unversioned_target_entry(
                &root,
                "acct-1",
                database_id,
                entry_name.as_deref(),
                br#"{"malformed":"legacy payload lacks canonical target authority"}"#,
            );
            let error = acquire_d1_target_mutation_guard_at(
                root.clone(),
                "d1_execute_write",
                "acct-1",
                canonical_database_id,
            )
            .expect_err("unversioned custody must block canonical target activation")
            .structured_content
            .expect("structured activation failure");
            assert_eq!(
                error["error"]["code"],
                json!("d1.target_guard_upgrade_activation_required"),
                "{label} must not become an invisible sibling namespace"
            );
            assert!(
                !root.join(TARGET_IDENTITY_ACTIVATION_MARKER_NAME).exists(),
                "failed activation must not mint a marker"
            );
            assert!(
                !root.join(TARGET_IDENTITY_ACTIVATION_GUARD_NAME).exists(),
                "pre-existing custody must be rejected without altering its root"
            );
            fs::remove_dir_all(root).expect("test cleanup");
        }

        let root = private_unactivated_test_root("alias-active-migration-lease");
        install_unversioned_target_entry(
            &root,
            "acct-1",
            alias_database_id,
            Some(ACTIVE_LEASE_NAME),
            b"malformed predecessor payload",
        );
        let error = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            canonical_database_id,
            "newsletter-core",
            &"b".repeat(64),
        )
        .expect_err("migration lease must share the upgrade activation gate")
        .structured_content
        .expect("structured migration activation failure");
        assert_eq!(
            error["error"]["code"],
            json!("d1.migration_lease_upgrade_activation_required")
        );
        assert_eq!(error["provider_calls"], json!(0));
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_identity_upgrade_blocks_malformed_root_and_marker_evidence() {
        use std::os::unix::fs::PermissionsExt;

        let database_id = "123e4567-e89b-42d3-a456-426614174000";
        for label in ["unexpected-root-entry", "malformed-marker"] {
            let root = private_unactivated_test_root(label);
            let entry = if label == "malformed-marker" {
                TARGET_IDENTITY_ACTIVATION_MARKER_NAME
            } else {
                "unclassifiable-custody"
            };
            fs::write(root.join(entry), b"not the activation contract")
                .expect("write malformed root evidence");
            fs::set_permissions(root.join(entry), fs::Permissions::from_mode(0o600))
                .expect("private malformed root evidence");
            let error = acquire_d1_target_mutation_guard_at(
                root.clone(),
                "d1_execute_write",
                "acct-1",
                database_id,
            )
            .expect_err("malformed upgrade evidence must fail closed")
            .structured_content
            .expect("structured activation failure");
            assert_eq!(
                error["error"]["code"],
                json!("d1.target_guard_upgrade_activation_required"),
                "{label} must block"
            );
            fs::remove_dir_all(root).expect("test cleanup");
        }

        let root = private_unactivated_test_root("over-limit-root");
        for index in 0..linux::MAX_TARGET_CUSTODY_DIRECTORY_ENTRIES {
            fs::write(root.join(format!("legacy-{index}")), b"").expect("write legacy root entry");
        }
        let error = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            "acct-1",
            database_id,
        )
        .expect_err("an over-limit root must fail closed without partial activation")
        .structured_content
        .expect("structured over-limit activation failure");
        assert_eq!(
            error["error"]["code"],
            json!("d1.target_guard_upgrade_activation_required")
        );
        assert!(!root.join(TARGET_IDENTITY_ACTIVATION_MARKER_NAME).exists());
        assert!(!root.join(TARGET_IDENTITY_ACTIVATION_GUARD_NAME).exists());
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clean_root_activation_reuses_one_canonical_namespace_for_the_same_provider_target() {
        let root = private_unactivated_test_root("clean-upgrade");
        let database_id = "123e4567-e89b-42d3-a456-426614174000";
        provision_d1_dml_custody_at(
            root.clone(),
            "acct-1",
            database_id,
            TEST_D1_DML_CUSTODY_GENERATION,
            TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
        )
        .expect("explicit provision activates the fresh canonical target");
        let first = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            "acct-1",
            database_id,
        )
        .expect("fresh root activates before the first canonical target guard");
        assert_eq!(
            fs::read(root.join(TARGET_IDENTITY_ACTIVATION_MARKER_NAME))
                .expect("read activation marker"),
            TARGET_IDENTITY_ACTIVATION_MARKER_BYTES
        );
        let target_key = first.target_key_sha256.clone();
        drop(first);

        let second = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_rename_database",
            "acct-1",
            database_id,
        )
        .expect("the same canonical provider target reuses its namespace after activation");
        assert_eq!(second.target_key_sha256, target_key);
        let target_directories = fs::read_dir(&root)
            .expect("enumerate activated root")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("d1-migration-target-")
            })
            .count();
        assert_eq!(
            target_directories, 1,
            "one provider target has one namespace"
        );
        drop(second);
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn valid_marker_never_fast_paths_past_a_stale_unregistered_target() {
        let root = private_test_root("valid-marker-stale-entry");
        install_unversioned_target_entry(
            &root,
            "acct-1",
            "123E4567-E89B-42D3-A456-426614174000",
            None,
            b"",
        );
        let error = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect_err("valid marker cannot authorize an unregistered sibling namespace")
        .structured_content
        .expect("structured stale-entry failure");
        assert_eq!(
            error["error"]["code"],
            json!("d1.target_guard_upgrade_activation_required")
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stable_root_audit_rejects_target_entry_change_between_passes() {
        let root = private_test_root("root-entry-change-between-passes");
        let account_id = "acct-1";
        let database_id = "123e4567-e89b-42d3-a456-426614174000";
        let initial = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            account_id,
            database_id,
        )
        .expect("create the canonical target custody directory");
        let target_key_sha256 = initial.target_key_sha256.clone();
        let dml_custody_authorization = initial
            .authorize_target_wide_d1_dml_custody()
            .expect("clean fixture custody authorization");
        drop(initial);

        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        linux::install_root_namespace_audit_pause_hook(&root, entered_tx, resume_rx);
        let thread_root = root.clone();
        let audited = std::thread::spawn(move || {
            acquire_d1_target_mutation_guard_at(
                thread_root,
                "d1_rename_database",
                account_id,
                database_id,
            )
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("root audit completed its first namespace pass");

        let nonce = "b".repeat(64);
        let active = root
            .join(format!("d1-migration-target-{target_key_sha256}"))
            .join(ACTIVE_LEASE_NAME);
        let payload = serde_json::to_vec(&json!({
            "approved_plan_sha256": "a".repeat(64),
            "created_at_unix_ms": 1,
            "dml_custody_authorization": dml_custody_authorization,
            "migration_family": "newsletter-core",
            "nonce": nonce,
            "target_key_sha256": target_key_sha256,
            "version": 2,
        }))
        .expect("canonical synthetic retained lease payload");
        write_private_test_file(&active, &payload);
        resume_tx
            .send(())
            .expect("resume the second root audit pass");

        let error = audited
            .join()
            .expect("root audit thread")
            .expect_err("an entry change between root audit passes must fail closed")
            .structured_content
            .expect("structured root audit failure");
        assert_eq!(
            error["error"]["code"],
            json!("d1.target_guard_upgrade_activation_required")
        );
        assert_eq!(
            error["error"]["message"],
            json!("lease root namespace changed during stable activation audit")
        );
        assert_eq!(error["provider_calls"], json!(0));
        assert_eq!(error["provider_mutations"], json!(0));
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_first_activation_poison_remains_unusable_after_marker_creation() {
        let root = private_unactivated_test_root("poisoned-first-activation");
        let account_id = "acct-poison";
        let database_id = "123e4567-e89b-42d3-a456-426614174099";
        let target_key_sha256 = sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        linux::install_activation_marker_pause_hook(target_key_sha256, entered_tx, resume_rx);
        let thread_root = root.clone();
        let first = std::thread::spawn(move || {
            provision_d1_dml_custody_at(
                thread_root,
                account_id,
                database_id,
                TEST_D1_DML_CUSTODY_GENERATION,
                TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
            )
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("activation reached final pre-marker boundary");
        install_unversioned_target_entry(
            &root,
            "acct-poison",
            "123E4567-E89B-42D3-A456-426614174099",
            None,
            b"",
        );
        resume_tx.send(()).expect("resume poisoned activation");
        let first_error = first
            .join()
            .expect("activation thread")
            .expect_err("concurrent alias must poison first activation")
            .structured_content
            .expect("structured poisoned activation failure");
        assert_eq!(
            first_error["error"]["code"],
            json!("d1.target_guard_upgrade_activation_required")
        );
        assert!(
            root.join(TARGET_IDENTITY_ACTIVATION_MARKER_NAME).is_file(),
            "the failure occurs after marker creation and must remain fail-closed"
        );
        let later = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_rename_database",
            "acct-poison",
            "123e4567-e89b-42d3-a456-426614174099",
        )
        .expect_err("a poisoned marker must never become a later fast path")
        .structured_content
        .expect("structured persistent poison failure");
        assert_eq!(
            later["error"]["code"],
            json!("d1.target_guard_upgrade_activation_required")
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_activation_legacy_insertion_blocks_guard_revalidation_and_lease_release() {
        let root = private_test_root("post-activation-guard-insertion");
        let guard = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("canonical guard before legacy insertion");
        install_unversioned_target_entry(
            &root,
            "acct-1",
            "123E4567-E89B-42D3-A456-426614174000",
            None,
            b"",
        );
        let error = guard
            .revalidate()
            .expect_err("later alias insertion must fail the pre-provider revalidation")
            .structured_content
            .expect("structured guard revalidation failure");
        assert_eq!(
            error["error"]["code"],
            json!("d1.target_guard_custody_changed")
        );
        drop(guard);
        fs::remove_dir_all(root).expect("test cleanup");

        let root = private_test_root("post-activation-lease-insertion");
        let mut lease = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &"a".repeat(64),
        )
        .expect("canonical lease before legacy insertion");
        install_unversioned_target_entry(
            &root,
            "acct-1",
            "123E4567-E89B-42D3-A456-426614174000",
            None,
            b"",
        );
        let error = lease
            .release()
            .expect_err("later alias insertion must block retirement persistence")
            .structured_content
            .expect("structured lease persistence failure");
        assert_eq!(
            error["error"]["code"],
            json!("d1.migration_lease_release_failed")
        );
        lease.retain();
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shared_target_guard_blocks_migration_and_curated_mutation_in_both_orders() {
        let root = private_test_root("shared-target-guard-both-orders");
        let plan = "a".repeat(64);

        let mut migration = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("migration owns shared target guard");
        let blocked = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect_err("curated mutation must not race migration")
        .structured_content
        .expect("structured contention error");
        assert_eq!(blocked["error"]["code"], json!("d1.target_guard_locked"));
        migration.release().expect("retire migration lease");
        drop(migration);

        let guard = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_execute_write",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("curated mutation owns shared target guard");
        let blocked = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &"b".repeat(64),
        )
        .expect_err("migration must not race curated mutation")
        .structured_content
        .expect("structured contention error");
        assert_eq!(
            blocked["error"]["code"],
            json!("d1.migration_target_guard_locked")
        );
        drop(guard);
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shared_target_guard_allows_distinct_databases_concurrently() {
        let root = private_test_root("shared-target-guard-distinct-targets");
        provision_d1_dml_custody_at(
            root.clone(),
            "acct-1",
            "223e4567-e89b-42d3-a456-426614174000",
            TEST_D1_DML_CUSTODY_GENERATION,
            TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
        )
        .expect("explicitly provision distinct target custody");
        let first = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_rename_database",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("first target guard");
        let second = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_delete_database",
            "acct-1",
            "223e4567-e89b-42d3-a456-426614174000",
        )
        .expect("different target guard");
        assert_ne!(first.target_key_sha256, second.target_key_sha256);
        drop((first, second));
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shared_target_guard_blocks_a_second_curated_mutation_on_the_same_database() {
        let root = private_test_root("shared-target-guard-same-target");
        let first = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_rename_database",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("first curated mutation owns shared target guard");
        let alias = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_delete_database",
            "acct-1",
            "123E4567-E89B-42D3-A456-426614174000",
        )
        .expect_err("case alias must fail before selecting another guard namespace")
        .structured_content
        .expect("structured alias error");
        assert_eq!(
            alias,
            json!({
                "ok": false,
                "error": {
                    "code": "d1.invalid_target_identity",
                    "message": "database_id must be a canonical lowercase hyphenated UUID",
                    "hint": "Use the exact lowercase database_id returned by Cloudflare; uppercase, mixed-case, compact, braced, whitespace, path and percent-encoded aliases are rejected."
                }
            })
        );
        let blocked = acquire_d1_target_mutation_guard_at(
            root.clone(),
            "d1_delete_database",
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect_err("second same-target mutation must fail closed")
        .structured_content
        .expect("structured contention error");
        assert_eq!(blocked["error"]["code"], json!("d1.target_guard_locked"));
        assert_eq!(blocked["operation"], json!("d1_delete_database"));
        drop(first);
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    fn write_private_test_file(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, bytes).expect("write private test file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set private test file mode");
    }

    #[cfg(target_os = "linux")]
    fn remove_test_path(path: &Path) {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                fs::remove_file(path).expect("remove test symlink or file");
            }
            Ok(_) => fs::remove_dir_all(path).expect("remove test directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("inspect test cleanup path: {error}"),
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_revalidation_failed(error: CallToolResult, label: &str) {
        let content = error.structured_content.expect("revalidation error");
        assert_eq!(
            content["error"]["code"],
            json!("d1.migration_lease_revalidation_failed"),
            "{label}"
        );
        assert_eq!(content["lease_retained"], json!(true), "{label}");
    }

    #[test]
    fn nonce_keyed_terminal_readback_pause_hooks_are_parallel_and_collision_safe() {
        use std::sync::mpsc::{Receiver, Sender};
        use std::time::Duration;

        type Installer =
            fn(String, Sender<()>, Receiver<()>) -> Result<TerminalTestHookGuard, &'static str>;
        type Pauser = fn(&str);

        fn exercise_registry(label: &str, install: Installer, pause: Pauser) {
            let first_nonce = format!("{label}-nonce-first");
            let second_nonce = format!("{label}-nonce-second");
            let (first_entered_tx, first_entered_rx) = mpsc::channel();
            let (first_resume_tx, first_resume_rx) = mpsc::channel();
            let (second_entered_tx, second_entered_rx) = mpsc::channel();
            let (second_resume_tx, second_resume_rx) = mpsc::channel();
            let first_guard = install(first_nonce.clone(), first_entered_tx, first_resume_rx)
                .expect("install first nonce-scoped pause hook");
            let second_guard = install(second_nonce.clone(), second_entered_tx, second_resume_rx)
                .expect("install second nonce-scoped pause hook");
            let (duplicate_entered_tx, _duplicate_entered_rx) = mpsc::channel();
            let (_duplicate_resume_tx, duplicate_resume_rx) = mpsc::channel();
            assert!(
                install(
                    first_nonce.clone(),
                    duplicate_entered_tx,
                    duplicate_resume_rx,
                )
                .is_err(),
                "{label} registry must reject duplicate nonce installation"
            );

            let first = std::thread::spawn(move || pause(&first_nonce));
            let second = std::thread::spawn(move || pause(&second_nonce));
            first_entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("first nonce reached its independent pause");
            second_entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("second nonce reached its independent pause");
            first_resume_tx.send(()).expect("resume first nonce");
            second_resume_tx.send(()).expect("resume second nonce");
            first.join().expect("first nonce pause thread");
            second.join().expect("second nonce pause thread");
            drop(first_guard);
            drop(second_guard);
        }

        fn exercise_unreached_disarm(label: &str, install: Installer) {
            let nonce = format!("{label}-unreached-reuse");
            let (entered_tx, _entered_rx) = mpsc::channel();
            let (_resume_tx, resume_rx) = mpsc::channel();
            let guard = install(nonce.clone(), entered_tx, resume_rx)
                .expect("install unreached nonce-scoped pause hook");
            drop(guard);

            let (replacement_entered_tx, _replacement_entered_rx) = mpsc::channel();
            let (_replacement_resume_tx, replacement_resume_rx) = mpsc::channel();
            let replacement = install(nonce, replacement_entered_tx, replacement_resume_rx)
                .expect("dropped unreached hook permits exact nonce reuse");
            drop(replacement);
        }

        exercise_registry(
            "receipt-pre-create",
            install_terminal_receipt_pre_create_pause_hook,
            maybe_pause_terminal_receipt_pre_create_for_test,
        );
        exercise_registry(
            "receipt",
            install_terminal_receipt_readback_pause_hook,
            maybe_pause_terminal_receipt_readback_for_test,
        );
        exercise_registry(
            "lease-namespace",
            install_terminal_lease_namespace_readback_pause_hook,
            maybe_pause_terminal_lease_namespace_readback_for_test,
        );
        exercise_unreached_disarm(
            "receipt-pre-create",
            install_terminal_receipt_pre_create_pause_hook,
        );
        exercise_unreached_disarm("receipt", install_terminal_receipt_readback_pause_hook);
        exercise_unreached_disarm(
            "lease-namespace",
            install_terminal_lease_namespace_readback_pause_hook,
        );
    }

    #[test]
    fn nonce_keyed_terminal_retirement_fault_guard_disarms_and_cannot_remove_reuse() {
        let nonce = "terminal-retirement-fault-guard-reuse".to_string();
        let unreached = install_terminal_retirement_failure_after(nonce.clone(), 2)
            .expect("install unreached retirement fault");
        assert!(
            !terminal_retirement_test_failure_after(&nonce, 1),
            "an earlier transition must not consume the later fault"
        );
        drop(unreached);

        let consumed = install_terminal_retirement_failure_after(nonce.clone(), 1)
            .expect("dropped unreached fault permits exact nonce reuse");
        assert!(terminal_retirement_test_failure_after(&nonce, 1));
        let replacement = install_terminal_retirement_failure_after(nonce.clone(), 2)
            .expect("consumed fault permits a newer same-nonce registration");
        drop(consumed);
        assert!(
            terminal_retirement_test_failure_after(&nonce, 2),
            "stale guard must not remove the newer same-nonce registration"
        );
        drop(replacement);

        let final_reuse = install_terminal_retirement_failure_after(nonce, 1)
            .expect("consumed replacement leaves the nonce reusable");
        drop(final_reuse);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_permanent_guard_blocks_another_thread_before_active_creation() {
        use std::sync::mpsc;

        let root = private_test_root("race");
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        linux::install_guard_pause_hook(root.clone(), entered_tx, resume_rx);
        let first_root = root.clone();
        let first = std::thread::spawn(move || {
            acquire_d1_migration_lease_at(
                first_root,
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "first",
                &"a".repeat(64),
            )
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first holds guard within the bounded test window");
        let unrelated_root = private_test_root("race-unrelated");
        let mut unrelated = acquire_d1_migration_lease_at(
            unrelated_root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "unrelated",
            &"c".repeat(64),
        )
        .expect("unrelated root must complete while the scoped owner remains paused");
        unrelated.release().expect("retire unrelated lease");
        fs::remove_dir_all(unrelated_root).expect("unrelated test cleanup");
        let contender = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "second",
            &"b".repeat(64),
        )
        .expect_err("guard held");
        assert_eq!(
            contender.structured_content.expect("contender")["error"]["code"],
            json!("d1.migration_target_guard_locked")
        );
        resume_tx.send(()).expect("resume first");
        let mut first = first.join().expect("first thread").expect("first lease");
        first.release().expect("retire first lease");
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_retirement_sync_restores_active_evidence_before_releasing_guard() {
        let root = private_test_root("release");
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "first",
            &"a".repeat(64),
        )
        .expect("owner lease");
        let active = owner.active_path_for_test().expect("linux active path");
        let original = fs::read(&active).expect("original active evidence");
        linux::fail_next_directory_sync_for_test();
        let release = owner.release().expect_err("forced sync failure");
        assert_eq!(
            release.structured_content.expect("release error")["error"]["code"],
            json!("d1.migration_lease_release_failed")
        );
        assert_eq!(fs::read(&active).expect("restored active"), original);
        assert!(
            matches!(
                fs::symlink_metadata(
                    active
                        .parent()
                        .expect("target parent")
                        .join(RETIRING_LEASE_NAME)
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ),
            "successful restoration must not leave a retiring entry"
        );
        owner.retain();
        let contender = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "second",
            &"b".repeat(64),
        )
        .expect_err("restored active evidence must block a fresh owner");
        assert_eq!(
            contender.structured_content.expect("contender")["error"]["code"],
            json!("d1.migration_target_lease_held")
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_custody_preflight_is_read_only_when_absent_and_blocks_retained_active() {
        let root = private_unactivated_test_root("preflight-existing-target");
        preflight_d1_migration_target_custody_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("absent target is clear without creating custody");
        assert_eq!(
            fs::read_dir(&root).expect("read untouched root").count(),
            0,
            "the absence preflight must not create a target directory or guard"
        );

        prepare_test_dml_layout(&root);

        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &"a".repeat(64),
        )
        .expect("create active custody for blocker proof");
        owner.retain();
        drop(owner);

        let error = preflight_d1_migration_target_custody_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect_err("retained active evidence blocks before a provider read");
        assert_eq!(
            error.structured_content.expect("preflight error")["error"]["code"],
            json!("d1.migration_target_lease_held")
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_path_replacement_cannot_redirect_revalidation_or_release() {
        use std::os::unix::fs::PermissionsExt;

        let root = private_test_root("target-replacement");
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "first",
            &"a".repeat(64),
        )
        .expect("owner lease");
        let target = owner
            .active_path_for_test()
            .expect("active path")
            .parent()
            .expect("target path")
            .to_path_buf();
        let displaced = root.join("displaced-target");
        fs::rename(&target, &displaced).expect("displace held target");
        fs::create_dir(&target).expect("replacement target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
            .expect("private replacement target");
        fs::write(target.join(ACTIVE_LEASE_NAME), b"replacement evidence")
            .expect("replacement active evidence");
        fs::set_permissions(
            target.join(ACTIVE_LEASE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private replacement active evidence");
        let replacement = fs::read(target.join(ACTIVE_LEASE_NAME)).expect("replacement bytes");
        assert!(
            owner.revalidate().is_err(),
            "replacement must fail revalidation"
        );
        assert!(owner.release().is_err(), "replacement must fail release");
        assert_eq!(
            fs::read(target.join(ACTIVE_LEASE_NAME)).expect("replacement after release"),
            replacement,
            "held-dirfd release must not mutate the replacement namespace"
        );
        owner.retain();
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_verified_abort_does_not_move_a_replacement_active_entry() {
        use std::os::unix::fs::PermissionsExt;

        let root = private_test_root("abort-replacement");
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "first",
            &"a".repeat(64),
        )
        .expect("owner lease");
        let active = owner.active_path_for_test().expect("active path");
        let displaced = active.with_extension("displaced");
        fs::rename(&active, &displaced).expect("displace owner active entry");
        fs::write(&active, b"replacement active evidence").expect("replacement active");
        fs::set_permissions(&active, fs::Permissions::from_mode(0o600))
            .expect("private replacement active");
        let replacement = fs::read(&active).expect("replacement bytes");
        assert!(
            !linux::abort_owned_active(
                &owner.target,
                &owner.active,
                &owner.active_file_identity,
                &owner.identity,
            ),
            "abort must verify the active namespace entry belongs to its held descriptor"
        );
        assert_eq!(
            fs::read(&active).expect("replacement after abort"),
            replacement
        );
        owner.retain();
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hostile_active_or_retiring_namespace_entries_fail_before_lease_acquisition() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        for (label, install) in [
            (
                "symlink",
                Box::new(|entry: &Path| symlink("/dev/null", entry))
                    as Box<dyn Fn(&Path) -> std::io::Result<()>>,
            ),
            (
                "nonregular",
                Box::new(|entry: &Path| fs::create_dir(entry))
                    as Box<dyn Fn(&Path) -> std::io::Result<()>>,
            ),
            (
                "mode",
                Box::new(|entry: &Path| {
                    fs::write(entry, b"{}")?;
                    fs::set_permissions(entry, fs::Permissions::from_mode(0o644))
                }) as Box<dyn Fn(&Path) -> std::io::Result<()>>,
            ),
        ] {
            let root = private_test_root(label);
            let target = root.join(format!(
                "d1-migration-target-{}",
                sha256_bytes_hex(b"acct-1\0123e4567-e89b-42d3-a456-426614174000")
            ));
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
                .expect("private target directory");
            install(&target.join(ACTIVE_LEASE_NAME)).expect("install hostile active entry");
            let error = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "first",
                &"a".repeat(64),
            )
            .expect_err("hostile active entry must fail closed");
            assert_eq!(
                error.structured_content.expect("active error")["error"]["code"],
                json!("d1.migration_lease_upgrade_activation_required"),
                "{label} active entry must fail the activated root audit before lease ownership or provider I/O"
            );
            fs::remove_dir_all(root).expect("test cleanup");
        }

        let root = private_test_root("retiring");
        let target = root.join(format!(
            "d1-migration-target-{}",
            sha256_bytes_hex(b"acct-1\0123e4567-e89b-42d3-a456-426614174000")
        ));
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
            .expect("private target directory");
        fs::write(target.join(RETIRING_LEASE_NAME), b"retiring evidence")
            .expect("retiring evidence");
        fs::set_permissions(
            target.join(RETIRING_LEASE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private retiring evidence");
        let error = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "first",
            &"a".repeat(64),
        )
        .expect_err("retiring entry must block a fresh owner");
        assert_eq!(
            error.structured_content.expect("retiring error")["error"]["code"],
            json!("d1.migration_lease_upgrade_activation_required")
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn guard_mode_or_identity_drift_fails_revalidation_before_provider_boundary() {
        use std::os::unix::fs::PermissionsExt;

        for label in ["mode", "identity"] {
            let root = private_test_root(label);
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "first",
                &"a".repeat(64),
            )
            .expect("owner lease");
            let target = owner
                .active_path_for_test()
                .expect("active path")
                .parent()
                .expect("target path")
                .to_path_buf();
            let guard = target.join(GUARD_NAME);
            if label == "mode" {
                fs::set_permissions(&guard, fs::Permissions::from_mode(0o644))
                    .expect("make guard unsafe");
            } else {
                fs::rename(&guard, target.join("displaced-guard.lock")).expect("displace guard");
                fs::write(&guard, b"replacement guard").expect("replacement guard");
                fs::set_permissions(&guard, fs::Permissions::from_mode(0o600))
                    .expect("private replacement guard");
            }
            assert!(
                owner.revalidate().is_err(),
                "{label} guard drift must fail before provider I/O"
            );
            owner.retain();
            fs::remove_dir_all(root).expect("test cleanup");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_and_ancestor_unsafe_or_symlink_drift_fails_revalidation() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        for label in [
            "root-mode",
            "root-symlink",
            "ancestor-mode",
            "ancestor-symlink",
        ] {
            let base = private_test_root(label);
            let root = if label.starts_with("ancestor-") {
                let root = base.join("root");
                fs::create_dir(&root).expect("nested lease root");
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                    .expect("nested lease root permissions");
                prepare_test_dml_layout(&root);
                root
            } else {
                base.clone()
            };
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "first",
                &"a".repeat(64),
            )
            .expect("owner lease");
            match label {
                "root-mode" => fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
                    .expect("unsafe root mode"),
                "root-symlink" => {
                    let displaced = root.with_extension("displaced");
                    fs::rename(&root, &displaced).expect("displace root");
                    symlink(&displaced, &root).expect("replace root with symlink");
                }
                "ancestor-mode" => fs::set_permissions(&base, fs::Permissions::from_mode(0o775))
                    .expect("unsafe ancestor mode"),
                "ancestor-symlink" => {
                    let displaced = base.with_extension("displaced");
                    fs::rename(&base, &displaced).expect("displace ancestor");
                    symlink(&displaced, &base).expect("replace ancestor with symlink");
                }
                _ => unreachable!(),
            }
            assert_revalidation_failed(owner.revalidate().expect_err("unsafe custody"), label);
            owner.retain();
            if label == "root-symlink" {
                remove_test_path(&root);
                remove_test_path(&root.with_extension("displaced"));
            } else if label == "ancestor-symlink" {
                remove_test_path(&base);
                remove_test_path(&base.with_extension("displaced"));
            } else {
                remove_test_path(&root);
            }
            if label == "ancestor-mode" {
                remove_test_path(&base);
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn active_inode_mode_payload_or_symlink_tampering_fails_revalidation() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        for label in ["mode", "inode", "payload", "symlink"] {
            let root = private_test_root(&format!("active-{label}"));
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "first",
                &"a".repeat(64),
            )
            .expect("owner lease");
            let active = owner.active_path_for_test().expect("active path");
            match label {
                "mode" => fs::set_permissions(&active, fs::Permissions::from_mode(0o644))
                    .expect("unsafe active mode"),
                "inode" => {
                    let displaced = active.with_extension("displaced");
                    fs::rename(&active, &displaced).expect("displace active evidence");
                    fs::write(&active, b"replacement active evidence").expect("replacement active");
                    fs::set_permissions(&active, fs::Permissions::from_mode(0o600))
                        .expect("private replacement active");
                    let original = fs::symlink_metadata(&displaced).expect("old active metadata");
                    let replacement = fs::symlink_metadata(&active).expect("replacement metadata");
                    assert_ne!(
                        (original.dev(), original.ino()),
                        (replacement.dev(), replacement.ino())
                    );
                }
                "payload" => {
                    let before = fs::read(&active).expect("active payload");
                    fs::write(&active, b"tampered payload").expect("tamper active payload");
                    assert_ne!(before, fs::read(&active).expect("tampered payload"));
                }
                "symlink" => {
                    let displaced = active.with_extension("displaced");
                    fs::rename(&active, &displaced).expect("displace active evidence");
                    symlink("/dev/null", &active).expect("replace active with symlink");
                }
                _ => unreachable!(),
            }
            assert_revalidation_failed(owner.revalidate().expect_err("tampered active"), label);
            owner.retain();
            remove_test_path(&root);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn second_release_is_inert_after_terminal_retirement() {
        use std::os::unix::fs::MetadataExt;

        let root = private_test_root("release-idempotent");
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "first",
            &"a".repeat(64),
        )
        .expect("owner lease");
        owner.release().expect("first release");
        let target = owner
            .active_path_for_test()
            .expect("active path")
            .parent()
            .expect("target path")
            .to_path_buf();
        let active = target.join(ACTIVE_LEASE_NAME);
        assert!(
            matches!(fs::symlink_metadata(&active), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "normal release removes active namespace entry"
        );
        let retired = fs::read_dir(&target)
            .expect("read target")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("retired."))
            .map(|entry| {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).expect("retired metadata");
                assert!(metadata.is_file() && !metadata.file_type().is_symlink());
                let bytes = fs::read(&path).expect("retired bytes");
                (path, metadata, bytes)
            })
            .collect::<Vec<_>>();
        assert_eq!(retired.len(), 1, "one terminal retirement record");
        let (retired_path, retired_metadata, retired_bytes) =
            retired.into_iter().next().expect("terminal retirement");
        owner.release().expect("second release is inert");
        let after_metadata =
            fs::symlink_metadata(&retired_path).expect("retired metadata after inert release");
        assert_eq!(
            (
                retired_metadata.dev(),
                retired_metadata.ino(),
                retired_metadata.mode()
            ),
            (
                after_metadata.dev(),
                after_metadata.ino(),
                after_metadata.mode()
            ),
            "an inert second release must not replace terminal evidence"
        );
        assert_eq!(
            retired_bytes,
            fs::read(&retired_path).expect("retired bytes after inert release")
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_release_failure_before_dispatch_retains_provable_abort_authority() {
        let root = private_test_root("bootstrap-zero-dispatch-release-failure");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "migration-ledger-bootstrap-v1",
            &plan,
        )
        .expect("marker-aware bootstrap lease");
        let identity = owner.identity.clone();
        linux::fail_next_directory_sync_for_test();
        let failure = owner
            .release()
            .expect_err("forced pre-dispatch release failure");
        let content = failure.structured_content.expect("release failure content");
        assert_eq!(
            content["error"]["code"],
            json!("d1.migration_lease_release_failed")
        );
        owner.retain();
        drop(owner);

        let retained = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "migration-ledger-bootstrap-v1",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("exact retained bootstrap custody");
        assert_eq!(retained.identity.namespace, "active");
        retained
            .prove_bootstrap_initializer_not_dispatched()
            .expect("marker-aware stable absence proves zero initializer dispatches");
        drop(retained);
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_attempt_marker_permanently_blocks_zero_dispatch_abort() {
        let root = private_test_root("bootstrap-attempt-marker");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "migration-ledger-bootstrap-v1",
            &plan,
        )
        .expect("marker-aware bootstrap lease");
        let identity = owner.identity.clone();
        owner
            .record_bootstrap_initializer_attempt()
            .expect("durable attempt marker before provider boundary");
        owner.retain();
        drop(owner);

        let retained = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "migration-ledger-bootstrap-v1",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("exact attempted bootstrap custody");
        let error = retained
            .prove_bootstrap_initializer_not_dispatched()
            .expect_err("attempted initializer can never use zero-dispatch abort");
        assert_eq!(
            error.structured_content.expect("attempt rejection")["error"]["code"],
            json!("d1.bootstrap_abort_dispatch_not_absent")
        );
        drop(retained);
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_reconciliation_inspection_rebinds_exact_active_without_mutation() {
        let root = private_test_root("reconcile-exact");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("create retained evidence");
        let identity = owner.identity.clone();
        let active = owner.active_path_for_test().expect("active path");
        let before = fs::read(&active).expect("active bytes");
        owner.retain();
        drop(owner);

        let retained = inspect_retained_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("inspect exact retained evidence");
        assert_eq!(retained.identity.namespace, "active");
        retained.revalidate().expect("stable retained evidence");
        drop(retained);
        assert_eq!(before, fs::read(&active).expect("unchanged active bytes"));
        assert!(!active.with_file_name(RETIRING_LEASE_NAME).exists());
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_reconciliation_accepts_exact_retiring_namespace_without_retiring_it() {
        let root = private_test_root("reconcile-retiring");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("create retained evidence");
        let identity = owner.identity.clone();
        let active = owner.active_path_for_test().expect("active path");
        owner.retain();
        drop(owner);
        let retiring = active.with_file_name(RETIRING_LEASE_NAME);
        fs::rename(&active, &retiring).expect("install exact retiring evidence");
        let before = fs::read(&retiring).expect("retiring bytes");
        let retained = inspect_retained_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("inspect exact retiring evidence");
        assert_eq!(retained.identity.namespace, "retiring");
        drop(retained);
        assert_eq!(
            before,
            fs::read(&retiring).expect("unchanged retiring bytes")
        );
        assert!(!active.exists());
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_reconciliation_rejects_missing_both_malformed_and_cross_target_evidence() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        for label in [
            "missing",
            "both",
            "malformed",
            "symlink",
            "hardlink",
            "cross-target",
            "contradictory",
        ] {
            let root = private_test_root(&format!("reconcile-{label}"));
            let plan = "a".repeat(64);
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
            )
            .expect("create retained evidence");
            let identity = owner.identity.clone();
            let active = owner.active_path_for_test().expect("active path");
            owner.retain();
            drop(owner);
            match label {
                "missing" => fs::rename(&active, active.with_extension("displaced"))
                    .expect("remove active namespace"),
                "both" => {
                    fs::copy(&active, active.with_file_name(RETIRING_LEASE_NAME))
                        .expect("copy retiring evidence");
                    fs::set_permissions(
                        active.with_file_name(RETIRING_LEASE_NAME),
                        fs::Permissions::from_mode(0o600),
                    )
                    .expect("private retiring evidence");
                }
                "malformed" => fs::write(&active, b"{not-json").expect("malform active"),
                "symlink" => {
                    fs::rename(&active, active.with_extension("displaced"))
                        .expect("displace active");
                    symlink("/dev/null", &active).expect("replace active with symlink");
                }
                "hardlink" => fs::hard_link(&active, active.with_extension("duplicate"))
                    .expect("install hard-linked retained evidence"),
                "cross-target" => {}
                "contradictory" => {}
                _ => unreachable!(),
            }
            let database_id = if label == "cross-target" {
                "223e4567-e89b-42d3-a456-426614174000"
            } else {
                "123e4567-e89b-42d3-a456-426614174000"
            };
            let payload_sha256 = if label == "contradictory" {
                "c".repeat(64)
            } else {
                identity.payload_sha256.clone()
            };
            let error = inspect_retained_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                database_id,
                "newsletter-core",
                &plan,
                &identity.nonce,
                &payload_sha256,
            )
            .expect_err("unsafe retained evidence must fail closed");
            let content = error.structured_content.expect("structured custody error");
            assert_eq!(content["retry_decision"], "do_not_retry_same_attempt");
            assert_eq!(content["lease_decision"], "not_acquired");
            assert_eq!(content["lease_retained"], Value::Null);
            assert_eq!(content["custody_status"], "inspection_failed");
            assert_eq!(content["provider_calls"], 0);
            remove_test_path(&root);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_reconciliation_stops_at_held_guard() {
        let root = private_test_root("reconcile-guard");
        let plan = "a".repeat(64);
        let owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("held owner");
        let error = inspect_retained_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &owner.identity.nonce,
            &owner.identity.payload_sha256,
        )
        .expect_err("held guard must stop reconciliation");
        assert_eq!(
            error.structured_content.expect("guard error")["error"]["code"],
            "d1.migration_reconciliation_guard_locked"
        );
        drop(owner);
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_receipt_is_create_only_replayable_and_precedes_retirement() {
        let root = private_test_root("terminal-exact");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("create retained evidence");
        let identity = owner.identity.clone();
        owner.retain();
        drop(owner);
        let expected = terminal_receipt(&identity, &plan);
        let mut retained = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("inspect retained lease");
        let (receipt, created) = retained
            .persist_terminal_receipt(&expected)
            .expect("persist exact terminal receipt");
        assert!(created);
        let (replayed, created_again) = retained
            .persist_terminal_receipt(&expected)
            .expect("exact receipt replay converges");
        assert!(!created_again);
        assert_eq!(receipt.payload_sha256, replayed.payload_sha256);
        assert_eq!(
            retained
                .retire_after_terminal_receipt(&receipt)
                .expect("retire")
                .local_namespace_mutations,
            2
        );
        assert!(retained.is_retired());
        assert!(
            retained
                .terminal_receipt_state(&expected)
                .expect("terminal receipt after retirement")
                .is_some()
        );
        drop(retained);

        let completed = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("reopen completed terminal state");
        assert!(completed.is_retired());
        assert!(
            completed
                .terminal_receipt_state(&expected)
                .expect("exact completed replay")
                .is_some()
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_receipt_exclusive_create_race_attributes_only_the_creator() {
        let root = private_test_root("terminal-receipt-exclusive-create-race");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("create retained evidence");
        let identity = owner.identity.clone();
        owner.retain();
        drop(owner);
        let retained = std::sync::Arc::new(
            inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
                &identity.nonce,
                &identity.payload_sha256,
            )
            .expect("inspect retained lease"),
        );
        let expected = terminal_receipt(&identity, &plan);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let _pre_create_guard = install_terminal_receipt_pre_create_pause_hook(
            identity.nonce.clone(),
            entered_tx,
            resume_rx,
        )
        .expect("install exact pre-create pause");

        let delayed_retained = std::sync::Arc::clone(&retained);
        let delayed_expected = expected.clone();
        let delayed = std::thread::spawn(move || {
            delayed_retained.persist_terminal_receipt(&delayed_expected)
        });
        entered_rx
            .recv()
            .expect("delayed contender passed stable absence readback");
        let (created_receipt, creator_mutated) = retained
            .persist_terminal_receipt(&expected)
            .expect("unpaused creator wins exclusive creation");
        assert!(creator_mutated, "exclusive creator owns one mutation");
        resume_tx.send(()).expect("resume delayed contender");
        let (raced_receipt, delayed_mutated) = delayed
            .join()
            .expect("delayed contender thread")
            .expect("exact O_EXCL loser converges on the incumbent receipt");
        assert!(
            !delayed_mutated,
            "the losing O_EXCL racer must not claim the creator's mutation"
        );
        assert!(linux::same_terminal_receipt_evidence(
            &created_receipt,
            &raced_receipt
        ));
        drop(raced_receipt);
        drop(created_receipt);
        drop(retained);
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_receipt_failures_distinguish_pre_create_from_post_create_mutation() {
        let root = private_test_root("terminal-receipt-failure-accounting");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("create retained evidence");
        let identity = owner.identity.clone();
        let target = owner
            .active_path_for_test()
            .expect("active path")
            .parent()
            .expect("target")
            .to_path_buf();
        owner.retain();
        drop(owner);
        let expected = terminal_receipt(&identity, &plan);
        let retained = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("inspect retained lease");

        let mut invalid = expected.clone();
        invalid.version = 9;
        let (entered_tx, _entered_rx) = mpsc::channel();
        let (_resume_tx, resume_rx) = mpsc::channel();
        let unreached_guard = install_terminal_receipt_pre_create_pause_hook(
            identity.nonce.clone(),
            entered_tx,
            resume_rx,
        )
        .expect("install pre-create hook before earlier validation failure");
        let pre_create = retained
            .persist_terminal_receipt(&invalid)
            .expect_err("noncanonical authority fails before exclusive creation");
        assert_eq!(pre_create.local_namespace_mutations, 0);
        drop(pre_create);
        drop(unreached_guard);
        let (replacement_entered_tx, _replacement_entered_rx) = mpsc::channel();
        let (_replacement_resume_tx, replacement_resume_rx) = mpsc::channel();
        let replacement_guard = install_terminal_receipt_pre_create_pause_hook(
            identity.nonce.clone(),
            replacement_entered_tx,
            replacement_resume_rx,
        )
        .expect("early validation exit cleanup permits same-nonce hook reuse");
        drop(replacement_guard);
        assert!(
            !target
                .join(format!(
                    "terminal-reconciliation.{}.receipt.json",
                    identity.nonce
                ))
                .exists(),
            "pre-create failure leaves the receipt namespace absent"
        );

        linux::fail_next_directory_sync_for_test();
        let post_create = retained
            .persist_terminal_receipt(&expected)
            .expect_err("directory sync fails after exclusive creation");
        assert_eq!(post_create.local_namespace_mutations, 1);
        assert_eq!(
            retained
                .terminal_evidence_readback(&expected, None)
                .receipt_persisted,
            Some(true),
            "post-create failure leaves exact receipt evidence"
        );
        drop(retained);
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_evidence_readback_rejects_an_altered_receipt_as_unknown_custody() {
        let root = private_test_root("terminal-readback-altered-receipt");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("create retained evidence");
        let identity = owner.identity.clone();
        let target = owner
            .active_path_for_test()
            .expect("active path")
            .parent()
            .expect("target")
            .to_path_buf();
        owner.retain();
        drop(owner);
        let expected = terminal_receipt(&identity, &plan);
        let retained = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("inspect retained lease");
        retained
            .persist_terminal_receipt(&expected)
            .expect("persist exact terminal receipt");
        let exact = retained.terminal_evidence_readback(&expected, None);
        assert_eq!(exact.custody, D1TerminalCustodyNamespace::Active);
        assert_eq!(exact.receipt_persisted, Some(true));

        fs::write(
            target.join(format!(
                "terminal-reconciliation.{}.receipt.json",
                identity.nonce
            )),
            b"{}",
        )
        .expect("alter terminal receipt after an exact readback");
        let altered = retained.terminal_evidence_readback(&expected, None);
        assert_eq!(altered.custody, D1TerminalCustodyNamespace::Unverified);
        assert_eq!(altered.receipt_persisted, None);
        drop(retained);
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_evidence_readback_rechecks_receipt_after_preliminary_stable_read() {
        let root = private_test_root("terminal-readback-final-recheck");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("create retained evidence");
        let identity = owner.identity.clone();
        let target = owner
            .active_path_for_test()
            .expect("active path")
            .parent()
            .expect("target")
            .to_path_buf();
        owner.retain();
        drop(owner);
        let expected = terminal_receipt(&identity, &plan);
        let retained = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("inspect retained lease");
        retained
            .persist_terminal_receipt(&expected)
            .expect("persist exact terminal receipt");

        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let _readback_guard = install_terminal_receipt_readback_pause_hook(
            identity.nonce.clone(),
            entered_tx,
            resume_rx,
        )
        .expect("install nonce-scoped terminal receipt readback pause");
        let expected_for_readback = expected.clone();
        let readback = std::thread::spawn(move || {
            retained.terminal_evidence_readback(&expected_for_readback, None)
        });
        entered_rx
            .recv()
            .expect("preliminary receipt and lease readback completed");
        let receipt_path = target.join(format!(
            "terminal-reconciliation.{}.receipt.json",
            identity.nonce
        ));
        let displaced = root.join("displaced-terminal-receipt.json");
        fs::rename(&receipt_path, &displaced).expect("displace incumbent receipt inode");
        write_private_test_file(
            &receipt_path,
            &serde_json::to_vec(&expected).expect("canonical replacement receipt"),
        );
        resume_tx.send(()).expect("resume final receipt readback");
        let result = readback.join().expect("readback thread");
        assert_eq!(result.custody, D1TerminalCustodyNamespace::Unverified);
        assert_eq!(result.receipt_persisted, None);
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_evidence_readback_rechecks_lease_namespace_after_final_receipt_read() {
        let root = private_test_root("terminal-readback-final-lease-recheck");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("create retained evidence");
        let identity = owner.identity.clone();
        let target = owner
            .active_path_for_test()
            .expect("active path")
            .parent()
            .expect("target")
            .to_path_buf();
        owner.retain();
        drop(owner);
        let expected = terminal_receipt(&identity, &plan);
        let retained = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("inspect retained lease");
        retained
            .persist_terminal_receipt(&expected)
            .expect("persist exact terminal receipt");

        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let _namespace_guard = install_terminal_lease_namespace_readback_pause_hook(
            identity.nonce.clone(),
            entered_tx,
            resume_rx,
        )
        .expect("install nonce-scoped terminal lease namespace pause");
        let expected_for_readback = expected.clone();
        let readback = std::thread::spawn(move || {
            retained.terminal_evidence_readback(&expected_for_readback, None)
        });
        entered_rx
            .recv()
            .expect("final stable receipt snapshot completed");
        fs::rename(
            target.join(ACTIVE_LEASE_NAME),
            target.join(RETIRING_LEASE_NAME),
        )
        .expect("change lease namespace after final receipt readback");
        resume_tx
            .send(())
            .expect("resume final lease namespace validation");
        let result = readback.join().expect("readback thread");
        assert_eq!(result.custody, D1TerminalCustodyNamespace::Unverified);
        assert_eq!(result.receipt_persisted, None);
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_evidence_linearization_rejects_receipt_drift_during_final_lease_pause() {
        for variant in ["mutated", "removed", "replaced"] {
            let root = private_test_root(&format!("terminal-linearization-{variant}"));
            let plan = "a".repeat(64);
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
            )
            .expect("create retained evidence");
            let identity = owner.identity.clone();
            let target = owner
                .active_path_for_test()
                .expect("active path")
                .parent()
                .expect("target")
                .to_path_buf();
            owner.retain();
            drop(owner);
            let expected = terminal_receipt(&identity, &plan);
            let retained = inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
                &identity.nonce,
                &identity.payload_sha256,
            )
            .expect("inspect retained lease");
            retained
                .persist_terminal_receipt(&expected)
                .expect("persist exact terminal receipt");

            let (entered_tx, entered_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let _namespace_guard = install_terminal_lease_namespace_readback_pause_hook(
                identity.nonce.clone(),
                entered_tx,
                resume_rx,
            )
            .expect("install nonce-scoped terminal lease namespace pause");
            let expected_for_readback = expected.clone();
            let readback = std::thread::spawn(move || {
                retained.terminal_evidence_readback(&expected_for_readback, None)
            });
            entered_rx
                .recv()
                .expect("final stable receipt snapshot completed");
            let receipt_path = target.join(format!(
                "terminal-reconciliation.{}.receipt.json",
                identity.nonce
            ));
            match variant {
                "mutated" => fs::write(&receipt_path, b"{}")
                    .expect("mutate receipt during final lease pause"),
                "removed" => {
                    fs::remove_file(&receipt_path).expect("remove receipt during final lease pause")
                }
                "replaced" => {
                    fs::rename(&receipt_path, root.join("displaced-terminal-receipt.json"))
                        .expect("displace receipt during final lease pause");
                    write_private_test_file(
                        &receipt_path,
                        &serde_json::to_vec(&expected).expect("canonical replacement receipt"),
                    );
                }
                _ => unreachable!(),
            }
            resume_tx
                .send(())
                .expect("resume final lease namespace validation");
            let result = readback.join().expect("readback thread");
            assert_eq!(
                result.custody,
                D1TerminalCustodyNamespace::Unverified,
                "{variant} receipt must invalidate custody"
            );
            assert_eq!(
                result.receipt_persisted, None,
                "{variant} receipt must make persistence unknown"
            );
            fs::remove_dir_all(root).expect("test cleanup");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_directory_enumeration_fails_closed_at_total_entry_limit() {
        let root = private_test_root("terminal-enumeration-total-limit");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("create retained evidence");
        let identity = owner.identity.clone();
        let target = owner
            .active_path_for_test()
            .expect("active path")
            .parent()
            .expect("target")
            .to_path_buf();
        owner.retain();
        drop(owner);
        let retained = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("inspect retained lease");
        for index in 0..linux::MAX_TARGET_CUSTODY_DIRECTORY_ENTRIES {
            let name = match index % 3 {
                0 => format!("retired.excess-{index}.lease.json"),
                1 => format!("aborted-create.excess-{index}.lease.json"),
                _ => format!("unrelated-evidence-{index}.json"),
            };
            fs::write(target.join(name), b"").expect("install bounded namespace entry");
        }
        let expected = terminal_receipt(&identity, &plan);
        assert!(
            retained.terminal_receipt_state(&expected).is_err(),
            "mixed retired, aborted, and unrelated entries must hit the total enumeration cap"
        );
        assert!(
            retained.persist_terminal_receipt(&expected).is_err(),
            "enumeration exhaustion must fail before receipt creation"
        );
        assert!(
            !target
                .join(format!(
                    "terminal-reconciliation.{}.receipt.json",
                    identity.nonce
                ))
                .exists(),
            "fail-closed enumeration must preserve create-only absence"
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_receipt_creation_respects_exact_total_directory_capacity_boundary() {
        use std::os::unix::fs::PermissionsExt;

        for (label, entries_before_persist, should_create) in [
            (
                "one-slot",
                linux::MAX_TARGET_CUSTODY_DIRECTORY_ENTRIES - 1,
                true,
            ),
            (
                "at-capacity",
                linux::MAX_TARGET_CUSTODY_DIRECTORY_ENTRIES,
                false,
            ),
        ] {
            let root = private_test_root(&format!("terminal-capacity-{label}"));
            let plan = "a".repeat(64);
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
            )
            .expect("create retained evidence");
            let identity = owner.identity.clone();
            let target = owner
                .active_path_for_test()
                .expect("active path")
                .parent()
                .expect("target")
                .to_path_buf();
            owner.retain();
            drop(owner);
            let retained = inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
                &identity.nonce,
                &identity.payload_sha256,
            )
            .expect("inspect retained lease");
            let existing_entries = fs::read_dir(&target)
                .expect("read initial target directory")
                .count();
            assert_eq!(
                existing_entries, 4,
                "permanent guard, immutable genesis, complete DML layout, and retained lease consume four entries"
            );
            let mut retained_payload: Value = serde_json::from_slice(
                &fs::read(target.join(ACTIVE_LEASE_NAME)).expect("read retained payload"),
            )
            .expect("decode retained payload");
            for index in existing_entries..entries_before_persist {
                let nonce = sha256_bytes_hex(format!("capacity-evidence-{index}").as_bytes());
                retained_payload["nonce"] = json!(nonce);
                let path = target.join(format!("retired.{nonce}.lease.json"));
                fs::write(
                    &path,
                    serde_json::to_vec(&retained_payload).expect("encode retained payload"),
                )
                .expect("fill exact target directory capacity");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("private retained capacity evidence");
            }
            assert_eq!(
                fs::read_dir(&target)
                    .expect("read filled target directory")
                    .count(),
                entries_before_persist,
                "{label} fixture must reach the exact pre-persist boundary"
            );

            let expected = terminal_receipt(&identity, &plan);
            if should_create {
                let (receipt, created) = retained
                    .persist_terminal_receipt(&expected)
                    .expect("one remaining entry must permit receipt creation");
                assert!(created);
                assert_eq!(
                    fs::read_dir(&target)
                        .expect("read target directory at cap")
                        .count(),
                    linux::MAX_TARGET_CUSTODY_DIRECTORY_ENTRIES
                );
                let (replayed, created_again) = retained
                    .persist_terminal_receipt(&expected)
                    .expect("exact replay must remain readable at the cap");
                assert!(!created_again);
                assert!(linux::same_terminal_receipt_evidence(&receipt, &replayed));
                assert_eq!(
                    retained
                        .terminal_evidence_readback(&expected, None)
                        .receipt_persisted,
                    Some(true),
                    "exact stable readback must remain valid at the cap"
                );
            } else {
                assert!(
                    retained.persist_terminal_receipt(&expected).is_err(),
                    "a full target directory must fail before O_EXCL receipt creation"
                );
                assert!(
                    !target
                        .join(format!(
                            "terminal-reconciliation.{}.receipt.json",
                            identity.nonce
                        ))
                        .exists(),
                    "capacity failure must preserve receipt absence"
                );
                assert_eq!(
                    fs::read_dir(&target)
                        .expect("read unchanged full target directory")
                        .count(),
                    linux::MAX_TARGET_CUSTODY_DIRECTORY_ENTRIES
                );
            }
            fs::remove_dir_all(root).expect("test cleanup");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_receipt_namespace_conflicts_fail_closed_in_both_insertion_orders() {
        for order in ["conflict-first", "exact-first"] {
            let root = private_test_root(&format!("terminal-receipt-order-{order}"));
            let plan = "a".repeat(64);
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
            )
            .expect("create retained evidence");
            let identity = owner.identity.clone();
            let target = owner
                .active_path_for_test()
                .expect("active path")
                .parent()
                .expect("target")
                .to_path_buf();
            owner.retain();
            drop(owner);
            let expected = terminal_receipt(&identity, &plan);
            let mut retained = inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
                &identity.nonce,
                &identity.payload_sha256,
            )
            .expect("inspect retained lease");
            let sibling_nonce = "9".repeat(64);
            assert_ne!(sibling_nonce, identity.nonce);
            let sibling_path = target.join(format!(
                "terminal-reconciliation.{sibling_nonce}.receipt.json"
            ));
            let conflicting_sibling = serde_json::to_vec(&expected)
                .expect("canonical receipt with contradictory filename identity");
            if order == "conflict-first" {
                write_private_test_file(&sibling_path, &conflicting_sibling);
                assert!(
                    retained.persist_terminal_receipt(&expected).is_err(),
                    "conflicting sibling must block exact receipt creation"
                );
                assert!(
                    !target
                        .join(format!(
                            "terminal-reconciliation.{}.receipt.json",
                            identity.nonce
                        ))
                        .exists(),
                    "failed create-only custody must not install the exact receipt"
                );
            } else {
                let (receipt, created) = retained
                    .persist_terminal_receipt(&expected)
                    .expect("persist exact incumbent before conflict");
                assert!(created);
                write_private_test_file(&sibling_path, &conflicting_sibling);
                assert!(retained.terminal_receipt_state(&expected).is_err());
                let failure = retained
                    .retire_after_terminal_receipt(&receipt)
                    .expect_err("conflicting sibling must block retirement");
                assert_eq!(failure.local_namespace_mutations, 0);
                assert_eq!(retained.identity.namespace, "active");
            }
            fs::remove_dir_all(root).expect("test cleanup");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canonical_historical_receipt_sibling_preserves_exact_current_replay() {
        let root = private_test_root("terminal-receipt-historical-sibling");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("create retained evidence");
        let identity = owner.identity.clone();
        let target = owner
            .active_path_for_test()
            .expect("active path")
            .parent()
            .expect("target")
            .to_path_buf();
        owner.retain();
        drop(owner);
        let expected = terminal_receipt(&identity, &plan);
        let mut historical = expected.clone();
        historical.lease_nonce = "9".repeat(64);
        assert_ne!(historical.lease_nonce, identity.nonce);
        historical.lease_payload_sha256 = "8".repeat(64);
        write_private_test_file(
            &target.join(format!(
                "terminal-reconciliation.{}.receipt.json",
                historical.lease_nonce
            )),
            &serde_json::to_vec(&historical).expect("canonical historical receipt"),
        );
        let mut retained = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("inspect retained lease beside historical receipt");
        let (receipt, created) = retained
            .persist_terminal_receipt(&expected)
            .expect("create current receipt beside canonical historical evidence");
        assert!(created);
        let (replayed, created_again) = retained
            .persist_terminal_receipt(&expected)
            .expect("exact current receipt replay converges");
        assert!(!created_again);
        assert!(linux::same_terminal_receipt_evidence(&receipt, &replayed));
        assert_eq!(
            retained
                .retire_after_terminal_receipt(&receipt)
                .expect("retire current evidence")
                .local_namespace_mutations,
            2
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_retired_active_and_retiring_namespace_conflicts_all_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        for namespace in ["active", "retiring", "retired"] {
            let root = private_test_root(&format!("terminal-namespace-{namespace}"));
            let plan = "a".repeat(64);
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
            )
            .expect("create retained evidence");
            let identity = owner.identity.clone();
            let target = owner
                .active_path_for_test()
                .expect("active path")
                .parent()
                .expect("target")
                .to_path_buf();
            owner.retain();
            drop(owner);
            let active = target.join(ACTIVE_LEASE_NAME);
            let retiring = target.join(RETIRING_LEASE_NAME);
            let retired = target.join(format!("retired.{}.lease.json", identity.nonce));
            match namespace {
                "active" => {}
                "retiring" => fs::rename(&active, &retiring).expect("install retiring state"),
                "retired" => fs::rename(&active, &retired).expect("install retired state"),
                _ => unreachable!(),
            }
            let retained = inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
                &identity.nonce,
                &identity.payload_sha256,
            )
            .expect("inspect one exact namespace state");
            let (source, conflict) = match namespace {
                "active" => (&active, &retired),
                "retiring" => (&retiring, &retired),
                "retired" => (&retired, &active),
                _ => unreachable!(),
            };
            fs::copy(source, conflict).expect("install conflicting exact namespace sibling");
            fs::set_permissions(conflict, fs::Permissions::from_mode(0o600))
                .expect("private conflicting namespace sibling");
            assert!(
                retained.revalidate().is_err(),
                "{namespace} plus an exact sibling state must be contradictory"
            );
            let readback =
                retained.terminal_evidence_readback(&terminal_receipt(&identity, &plan), None);
            assert_eq!(readback.custody, D1TerminalCustodyNamespace::Unverified);
            assert_eq!(readback.receipt_persisted, None);
            fs::remove_dir_all(root).expect("test cleanup");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_retirement_directory_sync_failure_reports_each_physical_namespace_transition() {
        for (after_mutations, expected_namespace) in [(1, "retiring"), (2, "retired")] {
            let root = private_test_root(&format!("terminal-partial-{after_mutations}"));
            let plan = "a".repeat(64);
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
            )
            .expect("create retained evidence");
            let identity = owner.identity.clone();
            let target = owner
                .active_path_for_test()
                .expect("active path")
                .parent()
                .expect("target")
                .to_path_buf();
            owner.retain();
            drop(owner);
            let expected = terminal_receipt(&identity, &plan);
            let mut retained = inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
                &identity.nonce,
                &identity.payload_sha256,
            )
            .expect("inspect retained lease");
            let (receipt, created) = retained
                .persist_terminal_receipt(&expected)
                .expect("persist exact terminal receipt");
            assert!(created);
            let _retirement_fault_guard = install_terminal_retirement_failure_after(
                identity.nonce.clone(),
                after_mutations as usize,
            )
            .expect("install nonce-scoped retirement fault");
            let failure = retained
                .retire_after_terminal_receipt(&receipt)
                .expect_err("test failure follows a physical namespace rename");
            let failure_content = failure
                .result
                .structured_content
                .as_ref()
                .expect("structured directory-sync failure");
            assert_eq!(
                failure_content["error"]["message"],
                if expected_namespace == "retiring" {
                    json!("retained lease entered retiring state but the directory sync failed")
                } else {
                    json!(
                        "retained lease entered terminal retirement but the directory sync failed"
                    )
                }
            );
            assert_eq!(failure.local_namespace_mutations, after_mutations as usize);
            assert_eq!(retained.identity.namespace, expected_namespace);
            let expected_path = if expected_namespace == "retiring" {
                target.join(RETIRING_LEASE_NAME)
            } else {
                target.join(format!("retired.{}.lease.json", identity.nonce))
            };
            assert!(
                expected_path.exists(),
                "{expected_namespace} evidence exists"
            );
            let readback = retained.terminal_evidence_readback(&expected, None);
            assert_eq!(readback.receipt_persisted, Some(true));
            assert_eq!(
                readback.custody,
                if expected_namespace == "retiring" {
                    D1TerminalCustodyNamespace::Retiring
                } else {
                    D1TerminalCustodyNamespace::Retired
                }
            );
            drop(retained);
            fs::remove_dir_all(root).expect("test cleanup");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_retirement_sync_and_readback_failure_never_infers_retired_custody() {
        let root = private_test_root("terminal-sync-readback-failure");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("create retained evidence");
        let identity = owner.identity.clone();
        let target = owner
            .active_path_for_test()
            .expect("active path")
            .parent()
            .expect("target")
            .to_path_buf();
        owner.retain();
        drop(owner);
        let expected = terminal_receipt(&identity, &plan);
        let mut retained = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("inspect retained lease");
        let (receipt, created) = retained
            .persist_terminal_receipt(&expected)
            .expect("persist exact terminal receipt");
        assert!(created);
        let _retirement_fault_guard =
            install_terminal_retirement_failure_after(identity.nonce.clone(), 2)
                .expect("install post-rename directory-sync fault");
        let failure = retained
            .retire_after_terminal_receipt(&receipt)
            .expect_err("second rename succeeds before the directory-sync fault");
        assert_eq!(failure.local_namespace_mutations, 2);
        let retired = target.join(format!("retired.{}.lease.json", identity.nonce));
        assert!(retired.is_file(), "physical retirement rename completed");
        assert!(
            target
                .join(format!(
                    "terminal-reconciliation.{}.receipt.json",
                    identity.nonce
                ))
                .is_file(),
            "the exact receipt remains physically present"
        );

        fs::remove_file(&retired).expect("inject descriptor readback failure");
        let readback = retained.terminal_evidence_readback(&expected, None);
        assert_eq!(readback.custody, D1TerminalCustodyNamespace::Unverified);
        assert_eq!(readback.receipt_persisted, None);

        drop(retained);
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_retirement_fault_isolation_survives_parallel_unrelated_retirement() {
        fn prepared_retirement(
            label: &str,
        ) -> (
            PathBuf,
            D1RetainedMigrationLease,
            D1TerminalReconciliationReceiptEvidence,
            String,
        ) {
            let root = private_test_root(label);
            let plan = "a".repeat(64);
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
            )
            .expect("create retained evidence");
            let identity = owner.identity.clone();
            owner.retain();
            drop(owner);
            let expected = terminal_receipt(&identity, &plan);
            let retained = inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
                &identity.nonce,
                &identity.payload_sha256,
            )
            .expect("inspect retained lease");
            let (receipt, created) = retained
                .persist_terminal_receipt(&expected)
                .expect("persist exact receipt");
            assert!(created);
            (root, retained, receipt, identity.nonce)
        }

        let (faulted_root, mut faulted, faulted_receipt, faulted_nonce) =
            prepared_retirement("terminal-retire-faulted-parallel");
        let (unrelated_root, mut unrelated, unrelated_receipt, _unrelated_nonce) =
            prepared_retirement("terminal-retire-unrelated-parallel");
        let _retirement_fault_guard = install_terminal_retirement_failure_after(faulted_nonce, 1)
            .expect("install exact nonce-scoped retirement fault");
        let start = std::sync::Arc::new(std::sync::Barrier::new(3));
        let faulted_start = std::sync::Arc::clone(&start);
        let faulted_thread = std::thread::spawn(move || {
            faulted_start.wait();
            faulted.retire_after_terminal_receipt(&faulted_receipt)
        });
        let unrelated_start = std::sync::Arc::clone(&start);
        let unrelated_thread = std::thread::spawn(move || {
            unrelated_start.wait();
            unrelated.retire_after_terminal_receipt(&unrelated_receipt)
        });
        start.wait();
        let unrelated_result = unrelated_thread
            .join()
            .expect("unrelated retirement thread")
            .expect("unrelated retirement cannot consume scoped fault");
        assert_eq!(unrelated_result.local_namespace_mutations, 2);
        let faulted_result = faulted_thread
            .join()
            .expect("faulted retirement thread")
            .expect_err("exact scoped retirement fails after its first transition");
        assert_eq!(faulted_result.local_namespace_mutations, 1);
        fs::remove_dir_all(faulted_root).expect("faulted test cleanup");
        fs::remove_dir_all(unrelated_root).expect("unrelated test cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canonical_v1_terminal_receipt_recovers_active_retiring_and_retired_as_legacy_only() {
        use std::os::unix::fs::PermissionsExt;

        for namespace in ["active", "retiring"] {
            let root = private_test_root(&format!("terminal-v1-{namespace}"));
            let plan = "a".repeat(64);
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
            )
            .expect("create retained evidence");
            let identity = owner.identity.clone();
            let target = owner
                .active_path_for_test()
                .expect("active path")
                .parent()
                .expect("target")
                .to_path_buf();
            owner.retain();
            drop(owner);
            let legacy = terminal_receipt_v1(&identity, &plan);
            let receipt_path = target.join(format!(
                "terminal-reconciliation.{}.receipt.json",
                identity.nonce
            ));
            fs::write(
                &receipt_path,
                serde_json::to_vec(&legacy).expect("canonical v1 receipt"),
            )
            .expect("install v1 receipt");
            fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600))
                .expect("private v1 receipt");
            if namespace == "retiring" {
                fs::rename(
                    target.join(ACTIVE_LEASE_NAME),
                    target.join(RETIRING_LEASE_NAME),
                )
                .expect("simulate predecessor retiring boundary");
            }
            let mut retained = inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
                &identity.nonce,
                &identity.payload_sha256,
            )
            .expect("inspect predecessor receipt state");
            let current = terminal_receipt(&identity, &plan);
            let evidence = retained
                .compatible_terminal_receipt_state(&current, Some(&legacy))
                .expect("v1 receipt is compatible with legacy expectation")
                .expect("v1 receipt exists");
            assert_eq!(evidence.receipt_version, 1);
            assert_eq!(evidence.effect_assertion_id, "schema_create_only_v1");
            assert!(
                retained
                    .compatible_terminal_receipt_state(&current, None)
                    .is_err(),
                "v1 receipt must not attest the extended/current-only expectation"
            );
            let expected_mutations = usize::from(namespace == "active") + 1;
            assert_eq!(
                retained
                    .retire_after_terminal_receipt(&evidence)
                    .expect("retire exact predecessor receipt")
                    .local_namespace_mutations,
                expected_mutations
            );
            drop(retained);
            let retired = inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
                &identity.nonce,
                &identity.payload_sha256,
            )
            .expect("reopen retired predecessor state");
            let replay = retired
                .compatible_terminal_receipt_state(&current, Some(&legacy))
                .expect("retired v1 replay validates")
                .expect("retired v1 receipt exists");
            assert_eq!(replay.receipt_version, 1);
            assert_eq!(replay.effect_assertion_id, "schema_create_only_v1");
            fs::remove_dir_all(root).expect("test cleanup");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn malformed_noncanonical_and_unknown_field_v1_terminal_receipts_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        for variant in ["noncanonical", "unknown", "duplicate"] {
            let root = private_test_root(&format!("terminal-v1-{variant}"));
            let plan = "a".repeat(64);
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
            )
            .expect("create retained evidence");
            let identity = owner.identity.clone();
            let target = owner
                .active_path_for_test()
                .expect("active path")
                .parent()
                .expect("target")
                .to_path_buf();
            owner.retain();
            drop(owner);
            let legacy = terminal_receipt_v1(&identity, &plan);
            let canonical = serde_json::to_vec(&legacy).expect("canonical v1 receipt");
            let bytes = match variant {
                "noncanonical" => serde_json::to_vec_pretty(&legacy).expect("pretty v1"),
                "unknown" => {
                    let mut value = serde_json::to_value(&legacy).expect("v1 value");
                    value.as_object_mut().expect("v1 object").insert(
                        "effect_assertion_id".to_string(),
                        json!("schema_create_only_v1"),
                    );
                    serde_json::to_vec(&value).expect("unknown-field v1")
                }
                "duplicate" => {
                    let mut duplicate = br#"{"version":1,"#.to_vec();
                    duplicate.extend_from_slice(&canonical[1..]);
                    duplicate
                }
                _ => unreachable!(),
            };
            let receipt_path = target.join(format!(
                "terminal-reconciliation.{}.receipt.json",
                identity.nonce
            ));
            fs::write(&receipt_path, bytes).expect("install invalid v1 receipt");
            fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600))
                .expect("private invalid v1 receipt");
            let error = inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
                &identity.nonce,
                &identity.payload_sha256,
            )
            .expect_err("invalid receipt must fail the activated root audit");
            assert_eq!(
                error.structured_content.expect("inspection error")["error"]["code"],
                json!("d1.migration_reconciliation_custody_changed"),
                "{variant} v1 receipt must fail closed during custody inspection"
            );
            fs::remove_dir_all(root).expect("test cleanup");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restored_terminal_receipt_negative_payload_matrix_fails_closed() {
        use std::os::unix::fs::PermissionsExt;

        let variants = [
            ("absent-json", b"".to_vec()),
            ("null", b"null".to_vec()),
            ("array", b"[]".to_vec()),
            ("primitive", b"1".to_vec()),
            ("malformed", b"{".to_vec()),
            ("unknown", br#"{"unknown":true}"#.to_vec()),
            ("duplicate", br#"{"version":1,"version":1}"#.to_vec()),
            ("noncanonical", Vec::new()),
        ];
        for (label, bytes) in variants {
            let root = private_test_root(&format!("terminal-{label}"));
            let plan = "a".repeat(64);
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
            )
            .expect("create retained evidence");
            let identity = owner.identity.clone();
            let target = owner
                .active_path_for_test()
                .expect("active path")
                .parent()
                .expect("target")
                .to_path_buf();
            owner.retain();
            drop(owner);
            let receipt_path = target.join(format!(
                "terminal-reconciliation.{}.receipt.json",
                identity.nonce
            ));
            let expected = terminal_receipt(&identity, &plan);
            let bytes = if label == "noncanonical" {
                serde_json::to_string_pretty(&expected)
                    .expect("pretty noncanonical receipt")
                    .into_bytes()
            } else {
                bytes
            };
            fs::write(&receipt_path, bytes).expect("install restored receipt payload");
            fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600))
                .expect("private restored receipt");
            let error = inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "newsletter-core",
                &plan,
                &identity.nonce,
                &identity.payload_sha256,
            )
            .expect_err("invalid restored receipt must fail the activated root audit");
            assert_eq!(
                error.structured_content.expect("inspection error")["error"]["code"],
                json!("d1.migration_reconciliation_custody_changed"),
                "{label} restored receipt must fail closed during custody inspection"
            );
            fs::remove_dir_all(root).expect("test cleanup");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_retirement_without_receipt_and_conflicting_replay_fail_closed() {
        let root = private_test_root("terminal-order");
        let plan = "a".repeat(64);
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("create retained evidence");
        let identity = owner.identity.clone();
        owner.release().expect("install retirement before receipt");
        drop(owner);
        let expected = terminal_receipt(&identity, &plan);
        let retired = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("inspect terminal retirement");
        assert!(retired.is_retired());
        assert!(
            retired
                .terminal_receipt_state(&expected)
                .expect("receipt absence is explicit")
                .is_none()
        );
        assert!(
            retired.persist_terminal_receipt(&expected).is_err(),
            "retirement must never be retroactively authorized by creating a receipt"
        );
        fs::remove_dir_all(root).expect("test cleanup");

        let root = private_test_root("terminal-conflict");
        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
        )
        .expect("create retained evidence");
        let identity = owner.identity.clone();
        owner.retain();
        drop(owner);
        let retained = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "newsletter-core",
            &plan,
            &identity.nonce,
            &identity.payload_sha256,
        )
        .expect("inspect retained evidence");
        let expected = terminal_receipt(&identity, &plan);
        retained
            .persist_terminal_receipt(&expected)
            .expect("persist incumbent receipt");
        let mut conflict = expected.clone();
        conflict.terminal_attempt_sha256 = "4".repeat(64);
        assert!(
            retained.persist_terminal_receipt(&conflict).is_err(),
            "changed request or evidence must conflict with the incumbent receipt"
        );
        let mut assertion_conflict = expected.clone();
        assertion_conflict.effect_assertion_id =
            "schema_create_tables_indexes_views_triggers_v1".to_string();
        assert!(
            retained
                .persist_terminal_receipt(&assertion_conflict)
                .is_err(),
            "changed effect assertion must conflict with the incumbent receipt"
        );
        let receipt_path = root
            .join(format!(
                "d1-migration-target-{}",
                identity.target_key_sha256
            ))
            .join(format!(
                "terminal-reconciliation.{}.receipt.json",
                identity.nonce
            ));
        fs::hard_link(&receipt_path, receipt_path.with_extension("duplicate"))
            .expect("install duplicate physical claimant");
        assert!(
            retained.terminal_receipt_state(&expected).is_err(),
            "a hard-linked duplicate physical claimant must fail closed"
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }
}
