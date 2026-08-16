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

use rmcp::model::CallToolResult;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::d1_migration_terminal_semantics::valid_receipt_outcome_prefixes;
use crate::tools::{invalid_argument_result, sha256_bytes_hex};
use crate::verification::now_unix_ms;

pub(crate) const D1_MANIFEST_LEASE_ROOT_ENV: &str = "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT";
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
    pub(crate) identity: D1MigrationLeaseIdentity,
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
    migration_family: String,
    nonce: String,
    target_key_sha256: String,
    version: u8,
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
    pub(crate) identity: D1RetainedMigrationLeaseIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct D1LeaseFileIdentity {
    device: u64,
    inode: u64,
}

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
            Ok(())
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

    fn release_failure(&self, message: &'static str) -> CallToolResult {
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest",
            "status": "reconciliation_required", "lease_retained": true, "lease": self.identity,
            "error": {"code": "d1.migration_lease_release_failed", "message": message,
                "hint": "Inspect the permanent target custody directory and reconcile the named owner through the governed recovery path before another apply."}
        }))
    }

    fn revalidation_failure(&self, message: &'static str) -> CallToolResult {
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest",
            "status": "reconciliation_required", "lease_retained": true, "lease": self.identity,
            "error": {"code": "d1.migration_lease_revalidation_failed", "message": message,
                "hint": "Do not issue provider SQL. Reconcile the permanent target custody evidence through the governed recovery path first."}
        }))
    }
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
            .map_err(d1_retained_lease_revalidation_error)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(d1_retained_lease_platform_unsupported())
        }
    }

    pub(crate) fn is_retired(&self) -> bool {
        self.identity.namespace == "retired"
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
                if sync_d1_lease_directory(&self.target).is_err() {
                    return Err(D1TerminalRetirementFailure {
                        result: d1_terminal_reconciliation_error(
                            "retained lease entered retiring state but the directory sync failed",
                        ),
                        local_namespace_mutations,
                    });
                }
                if terminal_retirement_test_failure_after(
                    &self.identity.nonce,
                    local_namespace_mutations,
                ) {
                    return Err(D1TerminalRetirementFailure {
                        result: d1_terminal_reconciliation_error(
                            "test-only failure after active lease entered retiring state",
                        ),
                        local_namespace_mutations,
                    });
                }
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
            if sync_d1_lease_directory(&self.target).is_err() {
                return Err(D1TerminalRetirementFailure {
                    result: d1_terminal_reconciliation_error(
                        "retained lease entered terminal retirement but the directory sync failed",
                    ),
                    local_namespace_mutations,
                });
            }
            if terminal_retirement_test_failure_after(
                &self.identity.nonce,
                local_namespace_mutations,
            ) {
                return Err(D1TerminalRetirementFailure {
                    result: d1_terminal_reconciliation_error(
                        "test-only failure after retiring lease entered terminal retirement",
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

#[cfg(not(test))]
fn terminal_retirement_test_failure_after(
    _lease_nonce: &str,
    _local_namespace_mutations: usize,
) -> bool {
    false
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
        "platform_requirement": "Linux on a trusted filesystem supporting working renameat2 RENAME_NOREPLACE, directory fsync, and advisory file locks; unsupported platforms or filesystems fail closed before provider I/O. Cross-host or shared-filesystem semantics require separate proof; retained evidence requires the governed recovery path."
    })
}

pub(crate) fn acquire_d1_migration_lease(
    account_id: &str,
    database_id: &str,
    family: &str,
    approved_plan_sha256: Option<&str>,
) -> Result<D1MigrationLease, CallToolResult> {
    let plan_sha256 = approved_plan_sha256
        .map(str::trim)
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| {
            invalid_argument_result(
                "d1.approved_plan_sha256_required",
                "approved_plan_sha256 is required for live apply and must be a SHA-256 hex digest",
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
    acquire_d1_migration_lease_at(root, account_id, database_id, family, plan_sha256)
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
    preflight_d1_migration_target_custody_at(root, account_id, database_id)
}

pub(crate) fn preflight_d1_migration_target_custody_at(
    root: PathBuf,
    account_id: &str,
    database_id: &str,
) -> Result<(), CallToolResult> {
    #[cfg(target_os = "linux")]
    {
        preflight_d1_migration_target_custody_at_linux(root, account_id, database_id)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, account_id, database_id);
        Err(d1_lease_platform_unsupported())
    }
}

pub(crate) fn acquire_d1_migration_lease_at(
    root: PathBuf,
    account_id: &str,
    database_id: &str,
    family: &str,
    plan_sha256: &str,
) -> Result<D1MigrationLease, CallToolResult> {
    #[cfg(target_os = "linux")]
    {
        acquire_d1_migration_lease_at_linux(root, account_id, database_id, family, plan_sha256)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, account_id, database_id, family, plan_sha256);
        Err(d1_lease_platform_unsupported())
    }
}

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
    use std::ffi::{CStr, CString, c_char};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};

    const AT_FDCWD: i32 = -100;
    const O_RDONLY: i32 = 0;
    const O_RDWR: i32 = 2;
    const O_CREAT: i32 = 0o100;
    const O_EXCL: i32 = 0o200;
    const O_DIRECTORY: i32 = 0o200000;
    const O_NOFOLLOW: i32 = 0o400000;
    const O_CLOEXEC: i32 = 0o2000000;
    const O_PATH: i32 = 0o10000000;
    const RENAME_NOREPLACE: u32 = 1;
    const MAX_LEASE_PAYLOAD_BYTES: u64 = 4096;
    pub(super) const MAX_TARGET_CUSTODY_DIRECTORY_ENTRIES: usize = 4096;
    const TERMINAL_RECEIPT_PREFIX: &str = "terminal-reconciliation.";
    const TERMINAL_RECEIPT_SUFFIX: &str = ".receipt.json";

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
        fn geteuid() -> u32;
        fn openat(dirfd: i32, pathname: *const std::ffi::c_char, flags: i32, mode: u32) -> i32;
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

    fn current_effective_uid() -> u32 {
        unsafe { geteuid() }
    }

    fn identity(metadata: &fs::Metadata) -> D1LeaseFileIdentity {
        D1LeaseFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn private_file(metadata: &fs::Metadata) -> bool {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == current_effective_uid()
            && metadata.mode() & 0o077 == 0
    }

    fn private_dir(metadata: &fs::Metadata) -> bool {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == current_effective_uid()
            && metadata.mode() & 0o077 == 0
    }

    fn c_string_path(path: &Path) -> Result<CString, &'static str> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "migration lease path contains an embedded NUL")
    }

    fn c_string_name(name: &str) -> Result<CString, &'static str> {
        CString::new(name).map_err(|_| "migration lease name contains an embedded NUL")
    }

    fn open_at(dirfd: i32, name: &CString, flags: i32, mode: u32) -> io::Result<fs::File> {
        let fd = unsafe { openat(dirfd, name.as_ptr(), flags, mode) };
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
            if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
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

    fn open_or_create_guard(
        target: &fs::File,
    ) -> Result<(fs::File, D1LeaseFileIdentity), &'static str> {
        let name = c_string_name(GUARD_NAME)?;
        let guard = match open_named_entry(target, GUARD_NAME) {
            Ok(existing) => {
                let existing_metadata = existing
                    .metadata()
                    .map_err(|_| "permanent target guard metadata is unavailable")?;
                if !private_file(&existing_metadata) {
                    return Err("permanent target guard is not a private regular file");
                }
                let expected = identity(&existing_metadata);
                let guard = open_at(
                    target.as_raw_fd(),
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
                    target.as_raw_fd(),
                    &name,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0o600,
                ) {
                    Ok(guard) => guard,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        return open_or_create_guard(target);
                    }
                    Err(_) => return Err("permanent target guard could not be created"),
                };
                guard
                    .set_permissions(fs::Permissions::from_mode(0o600))
                    .and_then(|()| guard.sync_all())
                    .map_err(|_| "permanent target guard could not be synchronized")?;
                sync_d1_lease_directory(target)
                    .map_err(|_| "target custody directory could not be synchronized")?;
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
        validate_named_private_file(target, GUARD_NAME, &expected)
            .map_err(|_| "permanent target guard changed or is not a private regular file")?;
        Ok((guard, expected))
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
        validate_target_binding(root, target_name, target, target_identity)?;
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
        {
            return Err("retained lease payload contains noncanonical authority fields");
        }
        Ok(payload)
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
            || receipt.operation != "d1_finalize_migration_reconciliation"
            || !valid_lower_sha256(&receipt.target_key_sha256)
            || !valid_retained_nonce(&receipt.lease_nonce)
            || !valid_lower_sha256(&receipt.lease_payload_sha256)
            || !valid_lower_sha256(&receipt.approved_apply_plan_sha256)
            || !matches!(
                receipt.effect_assertion_id.as_str(),
                "schema_create_only_v1"
                    | "schema_create_tables_indexes_views_triggers_v1"
                    | "schema_create_objects_additive_v1"
                    | "schema_create_objects_additive_seed_rows_v1"
            )
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
        payload: &[u8],
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
            identity,
        };
        lease.revalidate()?;
        Ok(lease)
    }

    pub(super) fn acquire_d1_migration_lease_at_linux(
        root_path: PathBuf,
        account_id: &str,
        database_id: &str,
        family: &str,
        plan_sha256: &str,
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
        let target_name = format!("d1-migration-target-{target_hash}");
        let (target, target_identity) = ensure_target_directory(&root, &target_name)
            .map_err(|message| d1_lease_root_error("d1.migration_lease_target_unsafe", message))?;
        let (guard, guard_identity) = open_or_create_guard(&target)
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
        let nonce = d1_migration_lease_nonce(&target_hash, plan_sha256);
        let payload = json!({"version": 2, "target_key_sha256": &target_hash, "nonce": &nonce, "approved_plan_sha256": plan_sha256.to_ascii_lowercase(), "migration_family": family, "created_at_unix_ms": now_unix_ms()});
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
            &encoded,
        )
    }

    pub(super) fn sync_d1_lease_directory(directory: &fs::File) -> io::Result<()> {
        #[cfg(test)]
        if FAIL_NEXT_DIRECTORY_SYNC.with(|fail| fail.replace(false)) {
            return Err(io::Error::other("forced directory sync failure"));
        }
        directory.sync_all()
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
    fn private_test_root(label: &str) -> PathBuf {
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
            acquire_d1_migration_lease_at(first_root, "acct-1", "db-1", "first", &"a".repeat(64))
        });
        entered_rx.recv().expect("first holds guard");
        let unrelated_root = private_test_root("race-unrelated");
        let mut unrelated = acquire_d1_migration_lease_at(
            unrelated_root.clone(),
            "acct-1",
            "db-1",
            "unrelated",
            &"c".repeat(64),
        )
        .expect("unrelated root must complete while the scoped owner remains paused");
        unrelated.release().expect("retire unrelated lease");
        fs::remove_dir_all(unrelated_root).expect("unrelated test cleanup");
        let contender = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "db-1",
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "first", &"a".repeat(64))
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
            "db-1",
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
        let root = private_test_root("preflight-existing-target");
        preflight_d1_migration_target_custody_at(root.clone(), "acct-1", "db-1")
            .expect("absent target is clear without creating custody");
        assert_eq!(
            fs::read_dir(&root).expect("read untouched root").count(),
            0,
            "the absence preflight must not create a target directory or guard"
        );

        let mut owner = acquire_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "db-1",
            "newsletter-core",
            &"a".repeat(64),
        )
        .expect("create active custody for blocker proof");
        owner.retain();
        drop(owner);

        let error = preflight_d1_migration_target_custody_at(root.clone(), "acct-1", "db-1")
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "first", &"a".repeat(64))
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "first", &"a".repeat(64))
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
                sha256_bytes_hex(b"acct-1\0db-1")
            ));
            fs::create_dir(&target).expect("target directory");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
                .expect("private target directory");
            install(&target.join(ACTIVE_LEASE_NAME)).expect("install hostile active entry");
            let error = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "db-1",
                "first",
                &"a".repeat(64),
            )
            .expect_err("hostile active entry must fail closed");
            assert_eq!(
                error.structured_content.expect("active error")["error"]["code"],
                json!("d1.migration_target_lease_unreconciled"),
                "{label} active entry must stop before lease ownership or provider I/O"
            );
            fs::remove_dir_all(root).expect("test cleanup");
        }

        let root = private_test_root("retiring");
        let target = root.join(format!(
            "d1-migration-target-{}",
            sha256_bytes_hex(b"acct-1\0db-1")
        ));
        fs::create_dir(&target).expect("target directory");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
            .expect("private target directory");
        fs::write(target.join(RETIRING_LEASE_NAME), b"retiring evidence")
            .expect("retiring evidence");
        fs::set_permissions(
            target.join(RETIRING_LEASE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private retiring evidence");
        let error =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "first", &"a".repeat(64))
                .expect_err("retiring entry must block a fresh owner");
        assert_eq!(
            error.structured_content.expect("retiring error")["error"]["code"],
            json!("d1.migration_target_retirement_unreconciled")
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
                "db-1",
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
                root
            } else {
                base.clone()
            };
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "db-1",
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
                "db-1",
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "first", &"a".repeat(64))
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
    fn retained_reconciliation_inspection_rebinds_exact_active_without_mutation() {
        let root = private_test_root("reconcile-exact");
        let plan = "a".repeat(64);
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "newsletter-core", &plan)
                .expect("create retained evidence");
        let identity = owner.identity.clone();
        let active = owner.active_path_for_test().expect("active path");
        let before = fs::read(&active).expect("active bytes");
        owner.retain();
        drop(owner);

        let retained = inspect_retained_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "db-1",
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "newsletter-core", &plan)
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
            "db-1",
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
                "db-1",
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
                "db-2"
            } else {
                "db-1"
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
        let owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "newsletter-core", &plan)
                .expect("held owner");
        let error = inspect_retained_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "db-1",
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "newsletter-core", &plan)
                .expect("create retained evidence");
        let identity = owner.identity.clone();
        owner.retain();
        drop(owner);
        let expected = terminal_receipt(&identity, &plan);
        let mut retained = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "db-1",
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
            "db-1",
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "newsletter-core", &plan)
                .expect("create retained evidence");
        let identity = owner.identity.clone();
        owner.retain();
        drop(owner);
        let retained = std::sync::Arc::new(
            inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "db-1",
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "newsletter-core", &plan)
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
            "db-1",
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "newsletter-core", &plan)
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
            "db-1",
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "newsletter-core", &plan)
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
            "db-1",
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "newsletter-core", &plan)
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
            "db-1",
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
                "db-1",
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
                "db-1",
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "newsletter-core", &plan)
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
            "db-1",
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
                "db-1",
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
                "db-1",
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
                existing_entries, 2,
                "permanent guard and retained lease consume two entries"
            );
            for index in existing_entries..entries_before_persist {
                fs::write(target.join(format!("capacity-evidence-{index}.json")), b"")
                    .expect("fill exact target directory capacity");
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
                "db-1",
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
                "db-1",
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "newsletter-core", &plan)
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
            "db-1",
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
                "db-1",
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
                "db-1",
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
    fn terminal_retirement_failure_reports_each_physical_partial_namespace_transition() {
        for (after_mutations, expected_namespace) in [(1, "retiring"), (2, "retired")] {
            let root = private_test_root(&format!("terminal-partial-{after_mutations}"));
            let plan = "a".repeat(64);
            let mut owner = acquire_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "db-1",
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
                "db-1",
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
                "db-1",
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
                "db-1",
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
                "db-1",
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
                "db-1",
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
                "db-1",
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
                "db-1",
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
            let retained = inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "db-1",
                "newsletter-core",
                &plan,
                &identity.nonce,
                &identity.payload_sha256,
            )
            .expect("retained lease remains inspectable");
            assert!(
                retained
                    .compatible_terminal_receipt_state(
                        &terminal_receipt(&identity, &plan),
                        Some(&legacy),
                    )
                    .is_err(),
                "{variant} v1 receipt must fail closed"
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
                "db-1",
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
            let retained = inspect_terminal_d1_migration_lease_at(
                root.clone(),
                "acct-1",
                "db-1",
                "newsletter-core",
                &plan,
                &identity.nonce,
                &identity.payload_sha256,
            )
            .expect("retained lease remains inspectable");
            assert!(
                retained.terminal_receipt_state(&expected).is_err(),
                "{label} restored receipt must fail closed"
            );
            fs::remove_dir_all(root).expect("test cleanup");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_retirement_without_receipt_and_conflicting_replay_fail_closed() {
        let root = private_test_root("terminal-order");
        let plan = "a".repeat(64);
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "newsletter-core", &plan)
                .expect("create retained evidence");
        let identity = owner.identity.clone();
        owner.release().expect("install retirement before receipt");
        drop(owner);
        let expected = terminal_receipt(&identity, &plan);
        let retired = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "db-1",
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
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "newsletter-core", &plan)
                .expect("create retained evidence");
        let identity = owner.identity.clone();
        owner.retain();
        drop(owner);
        let retained = inspect_terminal_d1_migration_lease_at(
            root.clone(),
            "acct-1",
            "db-1",
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
