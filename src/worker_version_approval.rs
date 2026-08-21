//! Private, create-only approval custody for one exact Worker version candidate.
//!
//! The opaque handle is random and is the only public candidate reference. All
//! deterministic candidate evidence remains below the private custody root.
//! This module never performs provider I/O.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::worker_upload::MAX_WORKER_UPLOAD_BYTES;

pub(crate) const WORKER_VERSION_APPROVAL_ROOT_ENV: &str =
    "CLOUDFLARE_MCP_WORKER_VERSION_APPROVAL_ROOT";

const ROOT_GUARD_NAME: &str = "guard.lock";
const ROOT_RETIRED_NAME: &str = "retired-root.json";
const PLAN_GUARD_NAME: &str = "guard.lock";
const CANDIDATE_NAME: &str = "candidate.body";
const PREPARED_NAME: &str = "prepared.json";
const CONSUMED_NAME: &str = "consumed.json";
const EXPIRED_NAME: &str = "expired.json";
const REJECTED_NAME: &str = "rejected.json";
const RETIRED_NAME: &str = "retired.json";
const HANDLE_PREFIX: &str = "wvpa-";
const HANDLE_RANDOM_BYTES: usize = 32;
const APPROVAL_TTL_MS: u64 = 15 * 60 * 1000;
const MAX_RECEIPT_BYTES: u64 = 256 * 1024;
const MAX_ROOT_ENTRIES: usize = 4_097;
const MAX_PLAN_ENTRIES: usize = 5;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RootRetirementReceipt {
    version: u8,
    state: String,
    generation: String,
    retired_at_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct WorkerVersionApprovalCandidate<'a> {
    pub(crate) account_id: &'a str,
    pub(crate) script_name: &'a str,
    pub(crate) base_version_id: &'a str,
    pub(crate) base_version_etag: &'a str,
    pub(crate) pre_upload_version_snapshot_sha256: &'a str,
    pub(crate) pre_upload_deployment_snapshot_sha256: &'a str,
    pub(crate) per_page: u32,
    pub(crate) content_type: &'a str,
    pub(crate) canonical_metadata: &'a Value,
    pub(crate) body: &'a [u8],
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct WorkerVersionApprovalEvidence {
    pub(crate) approval_handle: String,
    pub(crate) state: &'static str,
    pub(crate) expires_in_seconds: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct WorkerVersionApprovalError {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
    pub(crate) hint: &'static str,
    pub(crate) state: Option<&'static str>,
    pub(crate) local_mutation_performed: Option<bool>,
    pub(crate) custody_capacity: Option<WorkerVersionCustodyCapacityEvidence>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct WorkerVersionCustodyCapacityEvidence {
    pub(crate) root_entry_count: usize,
    pub(crate) root_entry_limit: usize,
    pub(crate) rotation_required: bool,
    pub(crate) safe_to_rotate: bool,
    pub(crate) blocking_authority: &'static str,
    pub(crate) operator_contract: &'static str,
}

#[derive(Debug)]
pub(crate) struct WorkerVersionApproval {
    root_path: PathBuf,
    root_handle: File,
    root_identity: FileIdentity,
    plan_name: String,
    plan_dir_handle: File,
    plan_identity: FileIdentity,
    _root_guard: File,
    _plan_guard: File,
    prepared: PreparedReceipt,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct PreparedReceipt {
    version: u8,
    operation: String,
    approval_handle: String,
    state: String,
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    account_id: String,
    script_name: String,
    base_version_id: String,
    base_version_etag: String,
    pre_upload_version_snapshot_sha256: String,
    pre_upload_deployment_snapshot_sha256: String,
    per_page: u32,
    content_type: String,
    canonical_metadata: Value,
    candidate_body_sha256: String,
    candidate_body_size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TransitionReceipt {
    version: u8,
    operation: String,
    approval_handle: String,
    state: String,
    predecessor_receipt_sha256: String,
    transitioned_at_unix_ms: u64,
}

impl WorkerVersionApproval {
    pub(crate) fn evidence(&self, state: &'static str) -> WorkerVersionApprovalEvidence {
        WorkerVersionApprovalEvidence {
            approval_handle: self.prepared.approval_handle.clone(),
            state,
            expires_in_seconds: 0,
        }
    }

    pub(crate) fn validate_for_provider_dispatch(&self) -> Result<(), WorkerVersionApprovalError> {
        self.validate_namespace()
    }

    /// Consume approval before any provider access. A crash or response loss
    /// after this boundary can never make the plan reusable.
    pub(crate) fn consume(
        &mut self,
    ) -> Result<WorkerVersionApprovalEvidence, WorkerVersionApprovalError> {
        self.consume_at(now_unix_ms()?)
    }

    fn consume_at(
        &mut self,
        now: u64,
    ) -> Result<WorkerVersionApprovalEvidence, WorkerVersionApprovalError> {
        self.validate_namespace()?;
        self.revalidate_candidate_before_consume(now)?;
        if now < self.prepared.created_at_unix_ms {
            return Err(custody_error(
                "system time precedes the approval creation time",
            ));
        }
        if now >= self.prepared.expires_at_unix_ms {
            let expired = TransitionReceipt {
                version: 1,
                operation: "workers_upload_version".to_string(),
                approval_handle: self.prepared.approval_handle.clone(),
                state: "expired".to_string(),
                predecessor_receipt_sha256: prepared_sha256(&self.prepared)?,
                transitioned_at_unix_ms: now,
            };
            write_new_receipt(&self.plan_dir_handle, EXPIRED_NAME, &expired)?;
            self.validate_namespace()?;
            let mut error = state_error(
                "workers.version_upload_approval_expired",
                "this approval handle expired before consumption",
                "Create and review a fresh approval plan.",
                "expired",
            );
            error.local_mutation_performed = Some(true);
            return Err(error);
        }
        let receipt = TransitionReceipt {
            version: 1,
            operation: "workers_upload_version".to_string(),
            approval_handle: self.prepared.approval_handle.clone(),
            state: "consumed".to_string(),
            predecessor_receipt_sha256: prepared_sha256(&self.prepared)?,
            transitioned_at_unix_ms: now,
        };
        write_new_receipt(&self.plan_dir_handle, CONSUMED_NAME, &receipt)?;
        self.validate_namespace()?;
        Ok(self.evidence("consumed"))
    }

    /// Retire approval only after downstream dispatch-attempt custody exists.
    pub(crate) fn retire(
        &mut self,
    ) -> Result<WorkerVersionApprovalEvidence, WorkerVersionApprovalError> {
        self.validate_namespace()?;
        self.retire_at(now_unix_ms()?)
    }

    fn retire_at(
        &mut self,
        now: u64,
    ) -> Result<WorkerVersionApprovalEvidence, WorkerVersionApprovalError> {
        let consumed: TransitionReceipt = read_receipt(&self.plan_dir_handle, CONSUMED_NAME)?;
        validate_transition(
            &consumed,
            &self.prepared,
            "consumed",
            &prepared_sha256(&self.prepared)?,
            self.prepared.created_at_unix_ms,
            now,
        )?;
        if consumed.transitioned_at_unix_ms >= self.prepared.expires_at_unix_ms {
            return Err(custody_error(
                "consumed approval transition is outside its validity window",
            ));
        }
        let receipt = TransitionReceipt {
            version: 1,
            operation: "workers_upload_version".to_string(),
            approval_handle: self.prepared.approval_handle.clone(),
            state: "retired".to_string(),
            predecessor_receipt_sha256: transition_sha256(&consumed)?,
            transitioned_at_unix_ms: now,
        };
        write_new_receipt(&self.plan_dir_handle, RETIRED_NAME, &receipt)?;
        self.validate_namespace()?;
        Ok(self.evidence("retired"))
    }

    fn validate_namespace(&self) -> Result<(), WorkerVersionApprovalError> {
        validate_root_identity(&self.root_path, &self.root_handle, self.root_identity)?;
        ensure_root_active(&self.root_handle)?;
        validate_child_identity(
            &self.root_handle,
            &self.plan_name,
            &self.plan_dir_handle,
            self.plan_identity,
        )
    }

    fn revalidate_candidate_before_consume(
        &self,
        now: u64,
    ) -> Result<(), WorkerVersionApprovalError> {
        let presence = inspect_plan_namespace(&self.plan_name_path(), self.plan_identity)?;
        if !presence.prepared || !presence.candidate {
            return Err(custody_error(
                "approval namespace omits required physical evidence before consumption",
            ));
        }
        let prepared: PreparedReceipt = read_receipt(&self.plan_dir_handle, PREPARED_NAME)?;
        if prepared != self.prepared {
            return Err(custody_error(
                "prepared approval receipt changed before consumption",
            ));
        }
        let body = read_bounded_file(
            &self.plan_dir_handle,
            CANDIDATE_NAME,
            MAX_WORKER_UPLOAD_BYTES,
        )?;
        if body.len() as u64 != prepared.candidate_body_size_bytes
            || sha256_bytes(&body) != prepared.candidate_body_sha256
        {
            return Err(custody_error(
                "private approval candidate changed before consumption",
            ));
        }
        validate_existing_transitions(&self.plan_dir_handle, &prepared, &presence, now)?;
        if presence.consumed || presence.expired || presence.rejected || presence.retired {
            return Err(custody_error("approval state changed before consumption"));
        }
        Ok(())
    }

    fn plan_name_path(&self) -> PathBuf {
        self.root_path.join(&self.plan_name)
    }
}

pub(crate) fn prepare_worker_version_approval(
    candidate: &WorkerVersionApprovalCandidate<'_>,
) -> Result<WorkerVersionApprovalEvidence, WorkerVersionApprovalError> {
    let root = configured_root()?;
    prepare_worker_version_approval_at(&root, candidate, now_unix_ms()?)
}

pub(crate) fn load_worker_version_approval(
    handle: &str,
    candidate: &WorkerVersionApprovalCandidate<'_>,
) -> Result<WorkerVersionApproval, WorkerVersionApprovalError> {
    let root = configured_root()?;
    load_worker_version_approval_at(&root, handle, candidate, now_unix_ms()?)
}

fn configured_root() -> Result<PathBuf, WorkerVersionApprovalError> {
    std::env::var_os(WORKER_VERSION_APPROVAL_ROOT_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| error(
            "workers.version_upload_approval_root_unconfigured",
            "Worker version approval custody requires a configured private root",
            "Set CLOUDFLARE_MCP_WORKER_VERSION_APPROVAL_ROOT to a pre-created operator-owned mode-0700 directory shared by every upload process.",
        ))
}

pub(crate) fn retire_worker_version_approval_root_at(
    root: &Path,
    generation: &str,
    now: u64,
) -> Result<(), WorkerVersionApprovalError> {
    validate_generation(generation)?;
    let root_handle = open_private_root(root)?;
    let root_identity = metadata_identity(
        &root_handle
            .metadata()
            .map_err(|_| custody_error("approval root metadata is unavailable"))?,
    );
    let root_guard = open_or_create_private_file(&root_handle, ROOT_GUARD_NAME)?;
    try_lock_exclusive(&root_guard, "workers.version_upload_approval_root_locked")?;
    validate_root_namespace(root, root_identity, false)?;
    audit_terminal_root(&root_handle, root, now)?;
    let receipt = RootRetirementReceipt {
        version: 1,
        state: "retired".to_string(),
        generation: generation.to_string(),
        retired_at_unix_ms: now,
    };
    write_new_receipt(&root_handle, ROOT_RETIRED_NAME, &receipt)?;
    validate_root_identity(root, &root_handle, root_identity)?;
    validate_root_retirement(&read_receipt(&root_handle, ROOT_RETIRED_NAME)?)?;
    Ok(())
}

pub(crate) fn retire_worker_version_approval_root(
    root: &Path,
    generation: &str,
) -> Result<(), WorkerVersionApprovalError> {
    retire_worker_version_approval_root_at(root, generation, now_unix_ms()?)
}

fn audit_terminal_root(
    root_handle: &File,
    root: &Path,
    now: u64,
) -> Result<(), WorkerVersionApprovalError> {
    for entry in fs::read_dir(root)
        .map_err(|_| custody_error("approval root could not be audited for retirement"))?
    {
        let entry =
            entry.map_err(|_| custody_error("approval root retirement audit was incomplete"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| custody_error("approval root contains a non-UTF-8 entry"))?;
        if name == ROOT_GUARD_NAME || name == ROOT_RETIRED_NAME {
            continue;
        }
        let directory = open_private_directory_at(root_handle, &name)?;
        let identity = metadata_identity(
            &directory
                .metadata()
                .map_err(|_| custody_error("approval namespace metadata is unavailable"))?,
        );
        let guard = open_or_create_private_file(&directory, PLAN_GUARD_NAME)?;
        try_lock_exclusive(&guard, "workers.version_upload_approval_guard_locked")?;
        let presence = inspect_plan_namespace(&entry.path(), identity)?;
        if !presence.prepared || !presence.candidate {
            return Err(custody_error(
                "root retirement audit found incomplete approval authority",
            ));
        }
        let prepared: PreparedReceipt = read_receipt(&directory, PREPARED_NAME)?;
        validate_prepared(&prepared, &name)?;
        let body = read_bounded_file(&directory, CANDIDATE_NAME, MAX_WORKER_UPLOAD_BYTES)?;
        if body.len() as u64 != prepared.candidate_body_size_bytes
            || sha256_bytes(&body) != prepared.candidate_body_sha256
        {
            return Err(custody_error(
                "root retirement audit found conflicting candidate evidence",
            ));
        }
        validate_existing_transitions(&directory, &prepared, &presence, now)?;
        if !presence.expired && !presence.rejected && !presence.retired {
            return Err(custody_error(
                "root retirement requires every approval to have durable terminal evidence",
            ));
        }
    }
    Ok(())
}

fn prepare_worker_version_approval_at(
    root: &Path,
    candidate: &WorkerVersionApprovalCandidate<'_>,
    now: u64,
) -> Result<WorkerVersionApprovalEvidence, WorkerVersionApprovalError> {
    validate_candidate_bounds(candidate)?;
    let root_handle = open_private_root(root)?;
    let root_identity = metadata_identity(
        &root_handle
            .metadata()
            .map_err(|_| custody_error("approval root metadata is unavailable"))?,
    );
    let root_guard = open_or_create_private_file(&root_handle, ROOT_GUARD_NAME)?;
    try_lock_exclusive(&root_guard, "workers.version_upload_approval_root_locked")?;
    validate_root_namespace(root, root_identity, true)?;

    for _ in 0..16 {
        let handle = random_handle()?;
        let name = c_name(&handle)?;
        let created = unsafe { libc::mkdirat(root_handle.as_raw_fd(), name.as_ptr(), 0o700) };
        if created != 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(custody_error(
                "approval namespace could not be created exclusively",
            ));
        }
        root_handle
            .sync_all()
            .map_err(|_| custody_error("approval root could not be synchronized"))?;
        let plan_dir_handle = open_private_directory_at(&root_handle, &handle)?;
        let plan_guard = open_or_create_private_file(&plan_dir_handle, PLAN_GUARD_NAME)?;
        try_lock_exclusive(&plan_guard, "workers.version_upload_approval_guard_locked")?;
        write_new_bytes(&plan_dir_handle, CANDIDATE_NAME, candidate.body)?;
        let prepared = PreparedReceipt {
            version: 1,
            operation: "workers_upload_version".to_string(),
            approval_handle: handle.clone(),
            state: "prepared".to_string(),
            created_at_unix_ms: now,
            expires_at_unix_ms: now
                .checked_add(APPROVAL_TTL_MS)
                .ok_or_else(|| custody_error("approval expiry overflowed"))?,
            account_id: candidate.account_id.to_string(),
            script_name: candidate.script_name.to_string(),
            base_version_id: candidate.base_version_id.to_string(),
            base_version_etag: candidate.base_version_etag.to_string(),
            pre_upload_version_snapshot_sha256: candidate
                .pre_upload_version_snapshot_sha256
                .to_string(),
            pre_upload_deployment_snapshot_sha256: candidate
                .pre_upload_deployment_snapshot_sha256
                .to_string(),
            per_page: candidate.per_page,
            content_type: candidate.content_type.to_string(),
            canonical_metadata: candidate.canonical_metadata.clone(),
            candidate_body_sha256: sha256_bytes(candidate.body),
            candidate_body_size_bytes: candidate.body.len() as u64,
        };
        write_new_receipt(&plan_dir_handle, PREPARED_NAME, &prepared)?;
        validate_root_identity(root, &root_handle, root_identity)?;
        return Ok(WorkerVersionApprovalEvidence {
            approval_handle: handle,
            state: "prepared",
            expires_in_seconds: APPROVAL_TTL_MS / 1000,
        });
    }
    Err(custody_error(
        "cryptographically random approval handle collisions exceeded the bounded retry limit",
    ))
}

fn load_worker_version_approval_at(
    root: &Path,
    handle: &str,
    candidate: &WorkerVersionApprovalCandidate<'_>,
    now: u64,
) -> Result<WorkerVersionApproval, WorkerVersionApprovalError> {
    validate_handle(handle)?;
    validate_candidate_bounds(candidate)?;
    let root_handle = open_private_root(root)?;
    let root_identity = metadata_identity(
        &root_handle
            .metadata()
            .map_err(|_| custody_error("approval root metadata is unavailable"))?,
    );
    let root_guard = open_or_create_private_file(&root_handle, ROOT_GUARD_NAME)?;
    try_lock_shared(&root_guard, "workers.version_upload_approval_root_locked")?;
    validate_root_namespace(root, root_identity, false)?;
    let plan_dir = root.join(handle);
    let plan_dir_handle = open_private_directory_at(&root_handle, handle)?;
    let plan_identity = metadata_identity(
        &plan_dir_handle
            .metadata()
            .map_err(|_| custody_error("approval namespace metadata is unavailable"))?,
    );
    let plan_guard = open_or_create_private_file(&plan_dir_handle, PLAN_GUARD_NAME)?;
    try_lock_exclusive(&plan_guard, "workers.version_upload_approval_guard_locked")?;
    let presence = inspect_plan_namespace(&plan_dir, plan_identity)?;
    if !presence.prepared || !presence.candidate {
        return Err(custody_error(
            "approval namespace omits required physical evidence",
        ));
    }
    let prepared: PreparedReceipt = read_receipt(&plan_dir_handle, PREPARED_NAME)?;
    validate_prepared(&prepared, handle)?;
    let stored_body = read_bounded_file(&plan_dir_handle, CANDIDATE_NAME, MAX_WORKER_UPLOAD_BYTES)?;
    if stored_body.len() as u64 != prepared.candidate_body_size_bytes
        || sha256_bytes(&stored_body) != prepared.candidate_body_sha256
    {
        return Err(custody_error(
            "private approval candidate body conflicts with its receipt",
        ));
    }
    validate_existing_transitions(&plan_dir_handle, &prepared, &presence, now)?;
    if presence.consumed || presence.retired || presence.rejected {
        return Err(state_error(
            "workers.version_upload_approval_consumed",
            "this approval handle was already consumed",
            "Create and review a new approval plan; never replay a consumed Worker version approval.",
            if presence.retired {
                "retired"
            } else if presence.rejected {
                "rejected"
            } else {
                "consumed"
            },
        ));
    }
    if presence.expired {
        return Err(state_error(
            "workers.version_upload_approval_expired",
            "this approval handle is expired",
            "Create and review a fresh approval plan.",
            "expired",
        ));
    }
    if now < prepared.created_at_unix_ms {
        return Err(custody_error(
            "system time precedes the approval creation time",
        ));
    }
    if now >= prepared.expires_at_unix_ms {
        let expired = TransitionReceipt {
            version: 1,
            operation: "workers_upload_version".to_string(),
            approval_handle: handle.to_string(),
            state: "expired".to_string(),
            predecessor_receipt_sha256: prepared_sha256(&prepared)?,
            transitioned_at_unix_ms: now,
        };
        write_new_receipt(&plan_dir_handle, EXPIRED_NAME, &expired)?;
        validate_root_identity(root, &root_handle, root_identity)?;
        validate_child_identity(&root_handle, handle, &plan_dir_handle, plan_identity)?;
        let mut error = state_error(
            "workers.version_upload_approval_expired",
            "this approval handle expired before apply",
            "Create and review a fresh approval plan.",
            "expired",
        );
        error.local_mutation_performed = Some(true);
        return Err(error);
    }
    if !candidate_matches(&prepared, candidate, &stored_body) {
        let rejected = TransitionReceipt {
            version: 1,
            operation: "workers_upload_version".to_string(),
            approval_handle: handle.to_string(),
            state: "rejected".to_string(),
            predecessor_receipt_sha256: prepared_sha256(&prepared)?,
            transitioned_at_unix_ms: now,
        };
        write_new_receipt(&plan_dir_handle, REJECTED_NAME, &rejected)?;
        validate_root_identity(root, &root_handle, root_identity)?;
        validate_child_identity(&root_handle, handle, &plan_dir_handle, plan_identity)?;
        let mut error = state_error(
            "workers.version_upload_approval_candidate_conflict",
            "this approval was closed because the supplied candidate did not match private custody",
            "Create and review a fresh approval plan; the rejected handle can never be retried.",
            "rejected",
        );
        error.local_mutation_performed = Some(true);
        return Err(error);
    }
    validate_root_identity(root, &root_handle, root_identity)?;
    Ok(WorkerVersionApproval {
        root_path: root.to_path_buf(),
        root_handle,
        root_identity,
        plan_name: handle.to_string(),
        plan_dir_handle,
        plan_identity,
        _root_guard: root_guard,
        _plan_guard: plan_guard,
        prepared,
    })
}

#[derive(Default)]
struct Presence {
    candidate: bool,
    prepared: bool,
    consumed: bool,
    expired: bool,
    rejected: bool,
    retired: bool,
}

fn inspect_plan_namespace(
    path: &Path,
    expected_identity: FileIdentity,
) -> Result<Presence, WorkerVersionApprovalError> {
    let mut presence = Presence::default();
    let mut count = 0usize;
    for entry in fs::read_dir(path)
        .map_err(|_| custody_error("approval namespace could not be enumerated"))?
    {
        count += 1;
        if count > MAX_PLAN_ENTRIES {
            return Err(custody_error(
                "approval namespace exceeds its closed entry cap",
            ));
        }
        let name = entry
            .map_err(|_| custody_error("approval namespace enumeration was incomplete"))?
            .file_name()
            .into_string()
            .map_err(|_| custody_error("approval namespace contains a non-UTF-8 entry"))?;
        match name.as_str() {
            PLAN_GUARD_NAME => {}
            CANDIDATE_NAME => presence.candidate = true,
            PREPARED_NAME => presence.prepared = true,
            CONSUMED_NAME => presence.consumed = true,
            EXPIRED_NAME => presence.expired = true,
            REJECTED_NAME => presence.rejected = true,
            RETIRED_NAME => presence.retired = true,
            _ => {
                return Err(custody_error(
                    "approval namespace contains an unexpected entry",
                ));
            }
        }
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| custody_error("approval namespace disappeared during inspection"))?;
    if !private_directory(&metadata) || metadata_identity(&metadata) != expected_identity {
        return Err(custody_error(
            "approval namespace changed during inspection",
        ));
    }
    Ok(presence)
}

fn validate_existing_transitions(
    directory: &File,
    prepared: &PreparedReceipt,
    presence: &Presence,
    observed_now: u64,
) -> Result<(), WorkerVersionApprovalError> {
    if (presence.expired || presence.rejected) && (presence.consumed || presence.retired)
        || (presence.expired && presence.rejected)
    {
        return Err(custody_error(
            "approval namespace contains contradictory terminal states",
        ));
    }
    if presence.rejected {
        let rejected: TransitionReceipt = read_receipt(directory, REJECTED_NAME)?;
        validate_transition(
            &rejected,
            prepared,
            "rejected",
            &prepared_sha256(prepared)?,
            prepared.created_at_unix_ms,
            observed_now,
        )?;
    }
    if presence.retired && !presence.consumed {
        return Err(custody_error("retired approval omits consumed authority"));
    }
    if presence.consumed {
        let consumed: TransitionReceipt = read_receipt(directory, CONSUMED_NAME)?;
        validate_transition(
            &consumed,
            prepared,
            "consumed",
            &prepared_sha256(prepared)?,
            prepared.created_at_unix_ms,
            observed_now,
        )?;
        if consumed.transitioned_at_unix_ms >= prepared.expires_at_unix_ms {
            return Err(custody_error(
                "consumed approval transition is outside its validity window",
            ));
        }
        if presence.retired {
            let retired: TransitionReceipt = read_receipt(directory, RETIRED_NAME)?;
            validate_transition(
                &retired,
                prepared,
                "retired",
                &transition_sha256(&consumed)?,
                consumed.transitioned_at_unix_ms,
                observed_now,
            )?;
        }
    }
    if presence.expired {
        let expired: TransitionReceipt = read_receipt(directory, EXPIRED_NAME)?;
        validate_transition(
            &expired,
            prepared,
            "expired",
            &prepared_sha256(prepared)?,
            prepared.expires_at_unix_ms,
            observed_now,
        )?;
    }
    Ok(())
}

fn validate_prepared(
    receipt: &PreparedReceipt,
    handle: &str,
) -> Result<(), WorkerVersionApprovalError> {
    if receipt.version != 1
        || receipt.operation != "workers_upload_version"
        || receipt.approval_handle != handle
        || receipt.state != "prepared"
        || receipt.created_at_unix_ms == 0
        || receipt.expires_at_unix_ms != receipt.created_at_unix_ms.saturating_add(APPROVAL_TTL_MS)
        || receipt.candidate_body_size_bytes == 0
        || receipt.candidate_body_size_bytes > MAX_WORKER_UPLOAD_BYTES
        || !is_lower_hex_sha256(&receipt.candidate_body_sha256)
    {
        return Err(custody_error(
            "prepared approval receipt is malformed or contradictory",
        ));
    }
    Ok(())
}

fn validate_transition(
    receipt: &TransitionReceipt,
    prepared: &PreparedReceipt,
    state: &str,
    predecessor: &str,
    minimum_timestamp: u64,
    observed_now: u64,
) -> Result<(), WorkerVersionApprovalError> {
    if receipt.version != 1
        || receipt.operation != prepared.operation
        || receipt.approval_handle != prepared.approval_handle
        || receipt.state != state
        || receipt.predecessor_receipt_sha256 != predecessor
        || receipt.transitioned_at_unix_ms < minimum_timestamp
        || receipt.transitioned_at_unix_ms > observed_now
    {
        return Err(custody_error(
            "approval transition receipt is malformed or contradictory",
        ));
    }
    Ok(())
}

fn candidate_matches(
    prepared: &PreparedReceipt,
    candidate: &WorkerVersionApprovalCandidate<'_>,
    stored_body: &[u8],
) -> bool {
    prepared.account_id == candidate.account_id
        && prepared.script_name == candidate.script_name
        && prepared.base_version_id == candidate.base_version_id
        && prepared.base_version_etag == candidate.base_version_etag
        && prepared.pre_upload_version_snapshot_sha256
            == candidate.pre_upload_version_snapshot_sha256
        && prepared.pre_upload_deployment_snapshot_sha256
            == candidate.pre_upload_deployment_snapshot_sha256
        && prepared.per_page == candidate.per_page
        && prepared.content_type == candidate.content_type
        && prepared.canonical_metadata == *candidate.canonical_metadata
        && stored_body == candidate.body
}

fn validate_candidate_bounds(
    candidate: &WorkerVersionApprovalCandidate<'_>,
) -> Result<(), WorkerVersionApprovalError> {
    if candidate.body.is_empty() || candidate.body.len() as u64 > MAX_WORKER_UPLOAD_BYTES {
        return Err(custody_error(
            "approval candidate body is outside the bounded upload contract",
        ));
    }
    let metadata = serde_json::to_vec(candidate.canonical_metadata)
        .map_err(|_| custody_error("approval metadata is not finite JSON"))?;
    if metadata.len() as u64 > MAX_RECEIPT_BYTES / 2 {
        return Err(custody_error(
            "approval metadata exceeds its private receipt bound",
        ));
    }
    Ok(())
}

fn validate_root_namespace(
    root: &Path,
    expected_identity: FileIdentity,
    require_free_entry: bool,
) -> Result<(), WorkerVersionApprovalError> {
    validate_root_namespace_with_limit(
        root,
        expected_identity,
        MAX_ROOT_ENTRIES,
        require_free_entry,
    )
}

fn validate_root_namespace_with_limit(
    root: &Path,
    expected_identity: FileIdentity,
    limit: usize,
    require_free_entry: bool,
) -> Result<(), WorkerVersionApprovalError> {
    let mut count = 0usize;
    for entry in
        fs::read_dir(root).map_err(|_| custody_error("approval root could not be enumerated"))?
    {
        let entry = entry.map_err(|_| custody_error("approval root enumeration was incomplete"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| custody_error("approval root contains a non-UTF-8 entry"))?;
        if name != ROOT_RETIRED_NAME {
            count += 1;
            if count > limit {
                return Err(capacity_error(count, limit));
            }
        }
        let entry_metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| custody_error("approval root entry metadata is unavailable"))?;
        let valid_entry = if name == ROOT_GUARD_NAME || name == ROOT_RETIRED_NAME {
            private_file(&entry_metadata)
        } else {
            valid_handle(&name) && private_directory(&entry_metadata)
        };
        if !valid_entry {
            return Err(custody_error("approval root contains an unexpected entry"));
        }
    }
    let metadata = fs::symlink_metadata(root)
        .map_err(|_| custody_error("approval root disappeared during inspection"))?;
    if !private_directory(&metadata) || metadata_identity(&metadata) != expected_identity {
        return Err(custody_error("approval root changed during inspection"));
    }
    ensure_root_active(&open_private_root(root)?)?;
    if require_free_entry && count >= limit {
        return Err(capacity_error(count, limit));
    }
    Ok(())
}

fn ensure_root_active(directory: &File) -> Result<(), WorkerVersionApprovalError> {
    let name = c_name(ROOT_RETIRED_NAME)?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let status = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(custody_error(
            "approval root retirement fence could not be inspected",
        ));
    }
    let receipt: RootRetirementReceipt = read_receipt(directory, ROOT_RETIRED_NAME)?;
    validate_root_retirement(&receipt)?;
    Err(state_error(
        "workers.version_upload_approval_root_retired",
        "this approval custody root is durably retired",
        "Use only the freshly provisioned approval root generation; never prepare or consume authority from this retired root.",
        "root_retired",
    ))
}

fn validate_root_retirement(
    receipt: &RootRetirementReceipt,
) -> Result<(), WorkerVersionApprovalError> {
    if receipt.version != 1 || receipt.state != "retired" {
        return Err(custody_error(
            "approval root retirement fence is semantically malformed",
        ));
    }
    validate_generation(&receipt.generation)
}

fn validate_generation(generation: &str) -> Result<(), WorkerVersionApprovalError> {
    if !(8..=128).contains(&generation.len())
        || !generation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(custody_error(
            "approval root generation is outside its canonical grammar",
        ));
    }
    Ok(())
}

fn write_new_receipt<T: Serialize + for<'de> Deserialize<'de> + PartialEq>(
    directory: &File,
    name: &str,
    receipt: &T,
) -> Result<(), WorkerVersionApprovalError> {
    let bytes = canonical_bytes(receipt)?;
    write_new_bytes(directory, name, &bytes)?;
    let readback: T = read_receipt(directory, name)?;
    if &readback != receipt {
        return Err(custody_error("approval receipt changed after creation"));
    }
    Ok(())
}

fn write_new_bytes(
    directory: &File,
    name: &str,
    bytes: &[u8],
) -> Result<(), WorkerVersionApprovalError> {
    let name_c = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(custody_error(
            "approval artifact could not be created exclusively",
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| custody_error("approval artifact could not be durably synchronized"))?;
    let metadata = file
        .metadata()
        .map_err(|_| custody_error("approval artifact metadata is unavailable"))?;
    if !private_file(&metadata) || metadata.len() != bytes.len() as u64 {
        return Err(custody_error(
            "created approval artifact is not one exact private regular file",
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| custody_error("approval artifact could not be rewound for readback"))?;
    let mut readback = Vec::with_capacity(bytes.len());
    Read::by_ref(&mut file)
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut readback)
        .map_err(|_| custody_error("approval artifact could not be read back completely"))?;
    let after = file
        .metadata()
        .map_err(|_| custody_error("approval artifact metadata is unavailable after readback"))?;
    if readback != bytes
        || !private_file(&after)
        || metadata_identity(&after) != metadata_identity(&metadata)
        || after.len() != metadata.len()
    {
        return Err(custody_error(
            "approval artifact changed during same-descriptor readback",
        ));
    }
    directory
        .sync_all()
        .map_err(|_| custody_error("approval namespace could not be synchronized"))?;
    Ok(())
}

fn read_receipt<T: for<'de> Deserialize<'de> + Serialize>(
    directory: &File,
    name: &str,
) -> Result<T, WorkerVersionApprovalError> {
    let bytes = read_bounded_file(directory, name, MAX_RECEIPT_BYTES)?;
    let receipt: T = serde_json::from_slice(&bytes).map_err(|_| {
        custody_error("approval receipt JSON is malformed or structurally unexpected")
    })?;
    if canonical_bytes(&receipt)? != bytes {
        return Err(custody_error(
            "approval receipt is not exact canonical JSON",
        ));
    }
    Ok(receipt)
}

fn read_bounded_file(
    directory: &File,
    name: &str,
    cap: u64,
) -> Result<Vec<u8>, WorkerVersionApprovalError> {
    let name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(custody_error(
            "approval artifact is absent or cannot be opened safely",
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = file
        .metadata()
        .map_err(|_| custody_error("approval artifact metadata is unavailable"))?;
    if !private_file(&before) || before.len() > cap {
        return Err(custody_error(
            "approval artifact is not one bounded private regular file",
        ));
    }
    let identity = metadata_identity(&before);
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| custody_error("approval artifact could not be read completely"))?;
    let after = file
        .metadata()
        .map_err(|_| custody_error("approval artifact metadata is unavailable after read"))?;
    if bytes.len() as u64 > cap
        || !private_file(&after)
        || metadata_identity(&after) != identity
        || after.len() != before.len()
        || bytes.len() as u64 != after.len()
    {
        return Err(custody_error(
            "approval artifact changed or was incomplete while being read",
        ));
    }
    Ok(bytes)
}

fn open_private_root(root: &Path) -> Result<File, WorkerVersionApprovalError> {
    if !root.is_absolute() {
        return Err(custody_error("approval root must be an absolute path"));
    }
    let canonical = fs::canonicalize(root)
        .map_err(|_| custody_error("approval root could not be resolved safely"))?;
    if canonical != root {
        return Err(custody_error(
            "approval root contains a symlink, alias, or noncanonical component",
        ));
    }
    validate_canonical_ancestor_chain(root, "approval")?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let directory = options
        .open(root)
        .map_err(|_| custody_error("approval root could not be opened safely"))?;
    let metadata = directory
        .metadata()
        .map_err(|_| custody_error("approval root metadata is unavailable"))?;
    if !private_directory(&metadata) {
        return Err(custody_error(
            "approval root is not private and operator-owned",
        ));
    }
    Ok(directory)
}

fn validate_canonical_ancestor_chain(
    root: &Path,
    label: &'static str,
) -> Result<(), WorkerVersionApprovalError> {
    let effective_uid = unsafe { libc::geteuid() };
    for ancestor in root.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|_| custody_error("custody ancestor metadata is unavailable"))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (!matches!(metadata.uid(), 0) && metadata.uid() != effective_uid)
            || metadata.mode() & 0o022 != 0
        {
            return Err(custody_error(match label {
                "approval" => "approval root has an untrusted writable or non-directory ancestor",
                _ => "custody root has an untrusted writable or non-directory ancestor",
            }));
        }
    }
    Ok(())
}

fn open_private_directory_at(
    parent: &File,
    name: &str,
) -> Result<File, WorkerVersionApprovalError> {
    let name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(custody_error(
            "approval namespace is absent or cannot be opened safely",
        ));
    }
    let directory = unsafe { File::from_raw_fd(fd) };
    let metadata = directory
        .metadata()
        .map_err(|_| custody_error("approval namespace metadata is unavailable"))?;
    if !private_directory(&metadata) {
        return Err(custody_error(
            "approval namespace is not private and operator-owned",
        ));
    }
    Ok(directory)
}

fn open_or_create_private_file(
    directory: &File,
    name: &str,
) -> Result<File, WorkerVersionApprovalError> {
    let name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(custody_error("approval guard could not be opened safely"));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .map_err(|_| custody_error("approval guard metadata is unavailable"))?;
    if !private_file(&metadata) {
        return Err(custody_error(
            "approval guard is not a private regular file",
        ));
    }
    Ok(file)
}

fn validate_root_identity(
    root: &Path,
    handle: &File,
    expected: FileIdentity,
) -> Result<(), WorkerVersionApprovalError> {
    let descriptor = handle
        .metadata()
        .map_err(|_| custody_error("approval root descriptor metadata is unavailable"))?;
    let path = fs::symlink_metadata(root)
        .map_err(|_| custody_error("approval root pathname is unavailable"))?;
    if !private_directory(&descriptor)
        || !private_directory(&path)
        || metadata_identity(&descriptor) != expected
        || metadata_identity(&path) != expected
    {
        return Err(custody_error(
            "approval root identity drifted during the operation",
        ));
    }
    Ok(())
}

fn validate_child_identity(
    root: &File,
    name: &str,
    held: &File,
    expected: FileIdentity,
) -> Result<(), WorkerVersionApprovalError> {
    let reachable = open_private_directory_at(root, name)?;
    let reachable_metadata = reachable
        .metadata()
        .map_err(|_| custody_error("approval namespace metadata is unavailable"))?;
    let held_metadata = held
        .metadata()
        .map_err(|_| custody_error("held approval namespace metadata is unavailable"))?;
    if !private_directory(&reachable_metadata)
        || !private_directory(&held_metadata)
        || metadata_identity(&reachable_metadata) != expected
        || metadata_identity(&held_metadata) != expected
    {
        return Err(custody_error(
            "approval namespace is no longer reachable from its configured root",
        ));
    }
    Ok(())
}

fn try_lock_exclusive(file: &File, code: &'static str) -> Result<(), WorkerVersionApprovalError> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(state_error(
            code,
            "another invocation owns this approval custody guard",
            "Wait for the incumbent invocation to finish, then inspect the same handle state before deciding whether a fresh approval is required.",
            "locked",
        ))
    }
}

fn try_lock_shared(file: &File, code: &'static str) -> Result<(), WorkerVersionApprovalError> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(state_error(
            code,
            "another invocation owns the approval-root retirement guard",
            "Wait for the incumbent root operation to finish, then re-read the same root generation before proceeding.",
            "locked",
        ))
    }
}

fn random_handle() -> Result<String, WorkerVersionApprovalError> {
    let mut bytes = [0u8; HANDLE_RANDOM_BYTES];
    let mut offset = 0usize;
    while offset < bytes.len() {
        let count = unsafe {
            libc::getrandom(bytes[offset..].as_mut_ptr().cast(), bytes.len() - offset, 0)
        };
        if count < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(custody_error(
                "kernel cryptographic randomness is unavailable",
            ));
        }
        if count == 0 {
            return Err(custody_error(
                "kernel cryptographic randomness returned no bytes",
            ));
        }
        offset += count as usize;
    }
    Ok(format!("{HANDLE_PREFIX}{}", hex(&bytes)))
}

fn validate_handle(handle: &str) -> Result<(), WorkerVersionApprovalError> {
    if valid_handle(handle) {
        Ok(())
    } else {
        Err(error(
            "workers.version_upload_approval_handle_invalid",
            "approval_handle must be one exact opaque Worker version approval handle",
            "Use the handle returned by the explicit prepare phase without modification.",
        ))
    }
}
fn valid_handle(value: &str) -> bool {
    value.len() == HANDLE_PREFIX.len() + HANDLE_RANDOM_BYTES * 2
        && value.starts_with(HANDLE_PREFIX)
        && value[HANDLE_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn c_name(name: &str) -> Result<CString, WorkerVersionApprovalError> {
    CString::new(name)
        .map_err(|_| custody_error("approval namespace name contains an invalid byte"))
}
fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, WorkerVersionApprovalError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|_| custody_error("approval receipt could not be serialized canonically"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(custody_error("approval receipt exceeds its private bound"));
    }
    Ok(bytes)
}
fn prepared_sha256(value: &PreparedReceipt) -> Result<String, WorkerVersionApprovalError> {
    Ok(sha256_bytes(&canonical_bytes(value)?))
}
fn transition_sha256(value: &TransitionReceipt) -> Result<String, WorkerVersionApprovalError> {
    Ok(sha256_bytes(&canonical_bytes(value)?))
}
fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
fn now_unix_ms() -> Result<u64, WorkerVersionApprovalError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| custody_error("system time precedes the Unix epoch"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| custody_error("system time exceeds the approval clock bound"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}
fn metadata_identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}
fn private_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o077 == 0
}
fn private_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o077 == 0
}
fn error(
    code: &'static str,
    message: &'static str,
    hint: &'static str,
) -> WorkerVersionApprovalError {
    WorkerVersionApprovalError {
        code,
        message,
        hint,
        state: None,
        local_mutation_performed: Some(false),
        custody_capacity: None,
    }
}
fn state_error(
    code: &'static str,
    message: &'static str,
    hint: &'static str,
    state: &'static str,
) -> WorkerVersionApprovalError {
    WorkerVersionApprovalError {
        code,
        message,
        hint,
        state: Some(state),
        local_mutation_performed: Some(false),
        custody_capacity: None,
    }
}

fn capacity_error(count: usize, limit: usize) -> WorkerVersionApprovalError {
    WorkerVersionApprovalError {
        code: "workers.version_upload_approval_rotation_required",
        message: "approval custody root reached its bounded namespace capacity",
        hint: "Keep the incumbent root immutable. Rotate only after a bounded offline audit proves zero unexpired prepared, consumed-only, locked, or malformed namespaces; archive terminal evidence, create a fresh trusted root, update every process atomically, and retain the old root until its audit retention expires.",
        state: Some("rotation_required"),
        local_mutation_performed: Some(false),
        custody_capacity: Some(WorkerVersionCustodyCapacityEvidence {
            root_entry_count: count.min(limit.saturating_add(1)),
            root_entry_limit: limit,
            rotation_required: true,
            safe_to_rotate: false,
            blocking_authority: "offline audit required; any unexpired prepared, consumed-only, locked, or malformed namespace blocks rotation",
            operator_contract: "preserve incumbent root; prove zero blocking authority; archive terminal evidence; create a new canonical trusted root; atomically update and restart all upload processes",
        }),
    }
}
fn custody_error(message: &'static str) -> WorkerVersionApprovalError {
    let mut error = error(
        "workers.version_upload_approval_custody_malformed",
        message,
        "Preserve the private approval namespace; do not repair, delete, or reuse it in place.",
    );
    error.local_mutation_performed = None;
    error
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;
    use std::time::Duration;

    use super::*;
    use serde_json::json;

    fn trusted_test_base() -> PathBuf {
        let passwd = unsafe { libc::getpwuid(libc::geteuid()) };
        assert!(!passwd.is_null(), "effective user has no passwd entry");
        let home = unsafe { CStr::from_ptr((*passwd).pw_dir) };
        PathBuf::from(OsStr::from_bytes(home.to_bytes())).join(".cloudflare-mcp-custody-tests")
    }

    fn test_root(label: &str) -> PathBuf {
        let base = trusted_test_base();
        fs::create_dir_all(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let path = base.join(format!(
            "cfmcp-version-approval-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn private_root_below_world_writable_ancestor_fails_closed() {
        let parent = trusted_test_base().join(format!(
            "cfmcp-untrusted-ancestor-parent-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir_all(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o770)).unwrap();
        let root = parent.join("approval-root");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = json!({"bindings":[]});
        assert_eq!(
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap_err()
                .code,
            "workers.version_upload_approval_custody_malformed"
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn bounded_capacity_emits_fail_closed_rotation_contract() {
        let root = test_root("capacity");
        for digit in ['a', 'b'] {
            let namespace = root.join(format!("{HANDLE_PREFIX}{}", digit.to_string().repeat(64)));
            fs::create_dir(&namespace).unwrap();
            fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let identity = metadata_identity(&fs::symlink_metadata(&root).unwrap());
        validate_root_namespace_with_limit(&root, identity, 2, false).unwrap();
        let error = validate_root_namespace_with_limit(&root, identity, 2, true).unwrap_err();
        assert_eq!(
            error.code,
            "workers.version_upload_approval_rotation_required"
        );
        let evidence = error.custody_capacity.unwrap();
        assert_eq!(evidence.root_entry_count, 2);
        assert_eq!(evidence.root_entry_limit, 2);
        assert!(evidence.rotation_required);
        assert!(!evidence.safe_to_rotate);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retired_root_fence_blocks_prepare_load_and_survives_restart() {
        let root = test_root("retired-root");
        let metadata = json!({"bindings":[]});
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();

        let loaded = load_worker_version_approval_at(
            &root,
            &prepared.approval_handle,
            &candidate(b"one", &metadata),
            2_000,
        )
        .unwrap();
        assert_eq!(
            retire_worker_version_approval_root_at(&root, "generation-0001", 3_000)
                .unwrap_err()
                .code,
            "workers.version_upload_approval_root_locked"
        );
        drop(loaded);

        assert_eq!(
            load_worker_version_approval_at(
                &root,
                &prepared.approval_handle,
                &candidate(b"one", &metadata),
                1_000 + APPROVAL_TTL_MS,
            )
            .unwrap_err()
            .code,
            "workers.version_upload_approval_expired"
        );
        retire_worker_version_approval_root_at(&root, "generation-0001", 1_001 + APPROVAL_TTL_MS)
            .unwrap();

        for error in [
            prepare_worker_version_approval_at(
                &root,
                &candidate(b"two", &metadata),
                1_002 + APPROVAL_TTL_MS,
            )
            .unwrap_err(),
            load_worker_version_approval_at(
                &root,
                &prepared.approval_handle,
                &candidate(b"one", &metadata),
                1_002 + APPROVAL_TTL_MS,
            )
            .unwrap_err(),
        ] {
            assert_eq!(error.code, "workers.version_upload_approval_root_retired");
        }
        let receipt: RootRetirementReceipt =
            read_receipt(&open_private_root(&root).unwrap(), ROOT_RETIRED_NAME).unwrap();
        assert_eq!(receipt.generation, "generation-0001");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn consume_rechecks_retired_root_fence_under_held_guards() {
        let root = test_root("retired-before-consume");
        let metadata = json!({"bindings":[]});
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();
        let mut loaded = load_worker_version_approval_at(
            &root,
            &prepared.approval_handle,
            &candidate(b"one", &metadata),
            2_000,
        )
        .unwrap();
        write_new_receipt(
            &open_private_root(&root).unwrap(),
            ROOT_RETIRED_NAME,
            &RootRetirementReceipt {
                version: 1,
                state: "retired".to_string(),
                generation: "generation-0002".to_string(),
                retired_at_unix_ms: 2_500,
            },
        )
        .unwrap();
        assert_eq!(
            loaded.consume_at(3_000).unwrap_err().code,
            "workers.version_upload_approval_root_retired"
        );
        drop(loaded);
        fs::remove_dir_all(root).unwrap();
    }
    fn candidate<'a>(body: &'a [u8], metadata: &'a Value) -> WorkerVersionApprovalCandidate<'a> {
        WorkerVersionApprovalCandidate {
            account_id: "account",
            script_name: "script",
            base_version_id: "base",
            base_version_etag: "a",
            pre_upload_version_snapshot_sha256: "b",
            pre_upload_deployment_snapshot_sha256: "c",
            per_page: 100,
            content_type: "application/javascript",
            canonical_metadata: metadata,
            body,
        }
    }

    #[test]
    fn prepare_uses_random_handle_and_exact_candidate_consumes_and_retires_once() {
        let root = test_root("lifecycle");
        let metadata =
            json!({"bindings":[{"name":"SECRET","text":"low entropy","type":"secret_text"}]});
        let body = b"export default{}";
        let first =
            prepare_worker_version_approval_at(&root, &candidate(body, &metadata), 1_000).unwrap();
        let second =
            prepare_worker_version_approval_at(&root, &candidate(body, &metadata), 1_000).unwrap();
        assert_ne!(first.approval_handle, second.approval_handle);
        assert!(valid_handle(&first.approval_handle));
        let mut approval = load_worker_version_approval_at(
            &root,
            &first.approval_handle,
            &candidate(body, &metadata),
            2_000,
        )
        .unwrap();
        assert_eq!(approval.consume_at(2_000).unwrap().state, "consumed");
        assert_eq!(approval.retire_at(2_500).unwrap().state, "retired");
        drop(approval);
        let replay = load_worker_version_approval_at(
            &root,
            &first.approval_handle,
            &candidate(body, &metadata),
            3_000,
        )
        .unwrap_err();
        assert_eq!(replay.code, "workers.version_upload_approval_consumed");
        assert_eq!(replay.state, Some("retired"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn first_candidate_conflict_terminally_rejects_the_approval() {
        let root = test_root("conflict");
        let metadata = json!({"bindings":[]});
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();
        let conflict = load_worker_version_approval_at(
            &root,
            &prepared.approval_handle,
            &candidate(b"two", &metadata),
            2_000,
        )
        .unwrap_err();
        assert_eq!(
            conflict.code,
            "workers.version_upload_approval_candidate_conflict"
        );
        assert_eq!(conflict.state, Some("rejected"));
        assert_eq!(conflict.local_mutation_performed, Some(true));
        let replay = load_worker_version_approval_at(
            &root,
            &prepared.approval_handle,
            &candidate(b"one", &metadata),
            2_000,
        )
        .unwrap_err();
        assert_eq!(replay.code, "workers.version_upload_approval_consumed");
        assert_eq!(replay.state, Some("rejected"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loaded_approval_rejects_root_replacement_before_consumption() {
        let root = test_root("loaded-root-drift");
        let metadata = json!({"bindings":[]});
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();
        let mut approval = load_worker_version_approval_at(
            &root,
            &prepared.approval_handle,
            &candidate(b"one", &metadata),
            2_000,
        )
        .unwrap();
        let displaced = root.with_extension("displaced");
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(
            approval.consume_at(2_000).unwrap_err().code,
            "workers.version_upload_approval_custody_malformed"
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(displaced).unwrap();
    }

    #[test]
    fn expiry_is_durable_and_restart_safe() {
        let root = test_root("expiry");
        let metadata = json!({"bindings":[]});
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();
        let expired = load_worker_version_approval_at(
            &root,
            &prepared.approval_handle,
            &candidate(b"one", &metadata),
            1_000 + APPROVAL_TTL_MS,
        )
        .unwrap_err();
        assert_eq!(expired.state, Some("expired"));
        let replay = load_worker_version_approval_at(
            &root,
            &prepared.approval_handle,
            &candidate(b"one", &metadata),
            1_000 + APPROVAL_TTL_MS + 1,
        )
        .unwrap_err();
        assert_eq!(replay.state, Some("expired"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_apply_has_one_lock_owner_and_then_one_consumption() {
        let root = test_root("concurrency");
        let metadata = json!({"bindings":[]});
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let threads = (0..2)
            .map(|_| {
                let root = root.clone();
                let handle = prepared.approval_handle.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    let metadata = json!({"bindings":[]});
                    barrier.wait();
                    load_worker_version_approval_at(
                        &root,
                        &handle,
                        &candidate(b"one", &metadata),
                        2_000,
                    )
                    .map(|mut a| {
                        a.consume_at(2_000).unwrap();
                        thread::sleep(Duration::from_millis(50));
                    })
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = threads
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|r| r.is_err()).count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_json_shapes_symlink_fifo_special_and_oversized_evidence_never_authorize() {
        for (label, bytes) in [
            ("null", b"null\n".as_slice()),
            ("array", b"[]\n".as_slice()),
            ("primitive", b"1\n".as_slice()),
            ("object", b"{}\n".as_slice()),
        ] {
            let root = test_root(label);
            let metadata = json!({"bindings":[]});
            let prepared =
                prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                    .unwrap();
            let path = root.join(&prepared.approval_handle).join(PREPARED_NAME);
            fs::write(&path, bytes).unwrap();
            assert_eq!(
                load_worker_version_approval_at(
                    &root,
                    &prepared.approval_handle,
                    &candidate(b"one", &metadata),
                    2_000
                )
                .unwrap_err()
                .code,
                "workers.version_upload_approval_custody_malformed"
            );
            fs::remove_dir_all(root).unwrap();
        }
        let root = test_root("fifo");
        let metadata = json!({"bindings":[]});
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();
        let path = root.join(&prepared.approval_handle).join(CANDIDATE_NAME);
        fs::remove_file(&path).unwrap();
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = mpsc::channel();
        let root2 = root.clone();
        let handle = prepared.approval_handle.clone();
        thread::spawn(move || {
            let metadata = json!({"bindings":[]});
            tx.send(
                load_worker_version_approval_at(
                    &root2,
                    &handle,
                    &candidate(b"one", &metadata),
                    2_000,
                )
                .unwrap_err()
                .code,
            )
            .unwrap();
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            "workers.version_upload_approval_custody_malformed"
        );
        fs::remove_dir_all(root).unwrap();

        let root = test_root("symlink");
        let metadata = json!({"bindings":[]});
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();
        let path = root.join(&prepared.approval_handle).join(CANDIDATE_NAME);
        fs::remove_file(&path).unwrap();
        symlink("missing", &path).unwrap();
        assert_eq!(
            load_worker_version_approval_at(
                &root,
                &prepared.approval_handle,
                &candidate(b"one", &metadata),
                2_000
            )
            .unwrap_err()
            .code,
            "workers.version_upload_approval_custody_malformed"
        );
        fs::remove_dir_all(root).unwrap();

        let root = test_root("socket");
        let metadata = json!({"bindings":[]});
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();
        let path = root.join(&prepared.approval_handle).join(CANDIDATE_NAME);
        fs::remove_file(&path).unwrap();
        let short_socket =
            std::env::temp_dir().join(format!("cfmcp-approval-socket-{}", std::process::id()));
        let _ = fs::remove_file(&short_socket);
        let _listener = UnixListener::bind(&short_socket).unwrap();
        fs::rename(&short_socket, &path).unwrap();
        assert_eq!(
            load_worker_version_approval_at(
                &root,
                &prepared.approval_handle,
                &candidate(b"one", &metadata),
                2_000
            )
            .unwrap_err()
            .code,
            "workers.version_upload_approval_custody_malformed"
        );
        fs::remove_dir_all(root).unwrap();

        let root = test_root("oversized-artifact");
        let metadata = json!({"bindings":[]});
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();
        let path = root.join(&prepared.approval_handle).join(CANDIDATE_NAME);
        let file = OpenOptions::new().write(true).open(path).unwrap();
        file.set_len(MAX_WORKER_UPLOAD_BYTES + 1).unwrap();
        assert_eq!(
            load_worker_version_approval_at(
                &root,
                &prepared.approval_handle,
                &candidate(b"one", &metadata),
                2_000
            )
            .unwrap_err()
            .code,
            "workers.version_upload_approval_custody_malformed"
        );
        fs::remove_dir_all(root).unwrap();

        let root = test_root("oversized");
        let metadata = json!({"bindings":[]});
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();
        let dir = root.join(&prepared.approval_handle);
        for i in 0..4 {
            fs::write(dir.join(format!("extra-{i}")), b"x").unwrap();
        }
        assert_eq!(
            load_worker_version_approval_at(
                &root,
                &prepared.approval_handle,
                &candidate(b"one", &metadata),
                2_000
            )
            .unwrap_err()
            .code,
            "workers.version_upload_approval_custody_malformed"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn contradictory_transition_and_private_root_drift_fail_closed() {
        let root = test_root("contradictory");
        let metadata = json!({"bindings":[]});
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();
        let bogus = TransitionReceipt {
            version: 1,
            operation: "workers_upload_version".into(),
            approval_handle: prepared.approval_handle.clone(),
            state: "retired".into(),
            predecessor_receipt_sha256: "0".repeat(64),
            transitioned_at_unix_ms: 2_000,
        };
        let handle = open_private_root(&root).unwrap();
        write_new_receipt(
            &open_private_directory_at(&handle, &prepared.approval_handle).unwrap(),
            RETIRED_NAME,
            &bogus,
        )
        .unwrap();
        assert_eq!(
            load_worker_version_approval_at(
                &root,
                &prepared.approval_handle,
                &candidate(b"one", &metadata),
                2_000
            )
            .unwrap_err()
            .code,
            "workers.version_upload_approval_custody_malformed"
        );
        fs::remove_dir_all(root).unwrap();

        let real = test_root("root-drift");
        let alias = real.with_extension("alias");
        symlink(&real, &alias).unwrap();
        assert_eq!(
            prepare_worker_version_approval_at(&alias, &candidate(b"one", &metadata), 1_000)
                .unwrap_err()
                .code,
            "workers.version_upload_approval_custody_malformed"
        );
        fs::remove_file(alias).unwrap();
        fs::remove_dir_all(real).unwrap();
    }

    #[test]
    fn restored_transition_timestamps_must_be_observed_and_monotonic() {
        let metadata = json!({"bindings":[]});

        let root = test_root("future-transition");
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();
        let root_handle = open_private_root(&root).unwrap();
        let plan = open_private_directory_at(&root_handle, &prepared.approval_handle).unwrap();
        let prepared_receipt: PreparedReceipt = read_receipt(&plan, PREPARED_NAME).unwrap();
        let future = TransitionReceipt {
            version: 1,
            operation: "workers_upload_version".into(),
            approval_handle: prepared.approval_handle.clone(),
            state: "consumed".into(),
            predecessor_receipt_sha256: prepared_sha256(&prepared_receipt).unwrap(),
            transitioned_at_unix_ms: 4_000,
        };
        write_new_receipt(&plan, CONSUMED_NAME, &future).unwrap();
        assert_eq!(
            load_worker_version_approval_at(
                &root,
                &prepared.approval_handle,
                &candidate(b"one", &metadata),
                3_000,
            )
            .unwrap_err()
            .code,
            "workers.version_upload_approval_custody_malformed"
        );
        fs::remove_dir_all(root).unwrap();

        let root = test_root("nonmonotonic-transition");
        let prepared =
            prepare_worker_version_approval_at(&root, &candidate(b"one", &metadata), 1_000)
                .unwrap();
        let mut approval = load_worker_version_approval_at(
            &root,
            &prepared.approval_handle,
            &candidate(b"one", &metadata),
            2_000,
        )
        .unwrap();
        approval.consume_at(2_000).unwrap();
        drop(approval);
        let root_handle = open_private_root(&root).unwrap();
        let plan = open_private_directory_at(&root_handle, &prepared.approval_handle).unwrap();
        let consumed: TransitionReceipt = read_receipt(&plan, CONSUMED_NAME).unwrap();
        let retired = TransitionReceipt {
            version: 1,
            operation: "workers_upload_version".into(),
            approval_handle: prepared.approval_handle.clone(),
            state: "retired".into(),
            predecessor_receipt_sha256: transition_sha256(&consumed).unwrap(),
            transitioned_at_unix_ms: 1_500,
        };
        write_new_receipt(&plan, RETIRED_NAME, &retired).unwrap();
        assert_eq!(
            load_worker_version_approval_at(
                &root,
                &prepared.approval_handle,
                &candidate(b"one", &metadata),
                3_000,
            )
            .unwrap_err()
            .code,
            "workers.version_upload_approval_custody_malformed"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
