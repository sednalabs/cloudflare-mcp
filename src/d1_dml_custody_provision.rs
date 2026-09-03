//! Privileged offline authority for first-time D1 DML custody provisioning.
//!
//! The MCP server never receives the external seal root or an entitlement
//! path. This module is reachable only from the explicit offline CLI mode.

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

use mcp_toolkit_private_artifact::{DescriptorBoundArtifact, PrivateArtifactPolicy};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::d1_dml_custody_genesis::{
    D1_DML_CUSTODY_GENESIS_VERSION, derive_d1_dml_custody_authority,
};
use crate::d1_dml_custody_layout::{D1_DML_CUSTODY_LAYOUT_SHA256, D1_DML_CUSTODY_LAYOUT_VERSION};
use crate::d1_migration_lease::{
    D1DmlCustodyLocalReadback, inspect_d1_dml_custody_provision_root, prove_d1_dml_custody_at,
};
use crate::d1_opaque_identity::valid_d1_opaque_identity;
use crate::d1_target::normalize_d1_target;
use crate::private_file_custody::{UnixFileIdentity, file_identity, private_regular_file};

const MAX_EXTERNAL_SEAL_ARTIFACT_BYTES: u64 = 64 * 1024;
const ENTITLEMENT_CONTRACT: &str = "d1-dml-custody-entitlement-v1";
const CONSUMPTION_CONTRACT: &str = "d1-dml-custody-consumption-v1";
const RECEIPT_CONTRACT: &str = "d1-dml-custody-external-receipt-v1";
const OFFLINE_OPERATION: &str = "d1_provision_dml_custody_offline";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EntitlementTarget {
    account_id: String,
    database_id: String,
    target_key_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct D1DmlCustodyEntitlement {
    version: u8,
    contract: String,
    state: String,
    operation_id: String,
    lease_root_identity: UnixFileIdentity,
    external_seal_root_identity: UnixFileIdentity,
    target: EntitlementTarget,
    custody_generation: String,
    custody_generation_sha256: String,
    authority_sha256: String,
    genesis_version: u8,
    genesis_sha256: String,
    layout_version: u8,
    layout_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct D1DmlCustodyConsumption {
    version: u8,
    contract: String,
    state: String,
    operation_id: String,
    entitlement_sha256: String,
    entitlement_identity: UnixFileIdentity,
    lease_root_identity: UnixFileIdentity,
    external_seal_root_identity: UnixFileIdentity,
    target_key_sha256: String,
    custody_generation_sha256: String,
    authority_sha256: String,
    genesis_sha256: String,
    layout_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct D1DmlCustodyExternalReceipt {
    version: u8,
    contract: String,
    state: String,
    operation_id: String,
    entitlement_sha256: String,
    entitlement_identity: UnixFileIdentity,
    consumption_sha256: String,
    consumption_state: String,
    lease_root_identity: UnixFileIdentity,
    external_seal_root_identity: UnixFileIdentity,
    target: EntitlementTarget,
    custody_generation_sha256: String,
    authority_sha256: String,
    genesis_version: u8,
    genesis_sha256: String,
    layout_version: u8,
    layout_sha256: String,
    local_readback: D1DmlCustodyLocalReadback,
}

/// Run one separately privileged, provider-free provisioning operation.
/// Paths are CLI-only and are never part of the MCP server configuration.
pub fn run_offline_d1_dml_custody_provision(
    lease_root: &Path,
    external_seal_root: &Path,
    entitlement_path: &Path,
) -> Result<Value, Value> {
    if !normal_absolute_path(lease_root)
        || !normal_absolute_path(external_seal_root)
        || !normal_absolute_path(entitlement_path)
    {
        return Err(error(
            "d1.dml_custody_offline_path_invalid",
            "offline custody paths must be absolute and lexically normalized",
        ));
    }
    if lease_root.starts_with(external_seal_root) || external_seal_root.starts_with(lease_root) {
        return Err(error(
            "d1.dml_custody_external_seal_not_independent",
            "external seal root must be outside and disjoint from the D1 custody root",
        ));
    }

    let external_root = ExternalSealRoot::open(external_seal_root)?;

    let policy = PrivateArtifactPolicy::new(MAX_EXTERNAL_SEAL_ARTIFACT_BYTES)
        .map_err(|failure| artifact_error(failure.code()))?;
    let held_entitlement =
        DescriptorBoundArtifact::open(external_seal_root, entitlement_path, policy)
            .map_err(|failure| artifact_error(failure.code()))?;
    let entitlement_read = held_entitlement
        .read()
        .map_err(|failure| artifact_error(failure.code()))?;
    let entitlement_sha256 = entitlement_read.proof().sha256_hex();
    let entitlement_identity = exact_private_file_identity(entitlement_path)?;
    let entitlement = parse_canonical::<D1DmlCustodyEntitlement>(
        entitlement_read.bytes(),
        "d1.dml_custody_entitlement_invalid",
    )?;
    if entitlement.external_seal_root_identity != external_root.identity {
        return Err(error(
            "d1.dml_custody_external_seal_root_mismatch",
            "external entitlement did not bind the exact current private seal root identity",
        ));
    }
    let target = normalize_d1_target(
        &entitlement.target.account_id,
        &entitlement.target.database_id,
    )
    .map_err(call_tool_error)?;
    let (authority, _) = derive_d1_dml_custody_authority(
        &target.target_key_sha256(),
        &entitlement.custody_generation,
        &entitlement.authority_sha256,
    )
    .map_err(|message| error("d1.dml_custody_entitlement_invalid", message))?;
    if entitlement.version != 1
        || entitlement.contract != ENTITLEMENT_CONTRACT
        || entitlement.state != "available"
        || !valid_operation_id(&entitlement.operation_id)
        || entitlement.target.account_id != target.account_id
        || entitlement.target.database_id != target.database_id
        || entitlement.target.target_key_sha256 != target.target_key_sha256()
        || entitlement.custody_generation_sha256 != authority.custody_generation_sha256
        || entitlement.authority_sha256 != authority.authority_sha256
        || entitlement.genesis_version != D1_DML_CUSTODY_GENESIS_VERSION
        || entitlement.genesis_sha256 != authority.genesis_sha256
        || entitlement.layout_version != D1_DML_CUSTODY_LAYOUT_VERSION
        || entitlement.layout_sha256 != D1_DML_CUSTODY_LAYOUT_SHA256
    {
        return Err(error(
            "d1.dml_custody_entitlement_invalid",
            "external entitlement was non-canonical or contradicted its derived custody authority",
        ));
    }

    let root = inspect_d1_dml_custody_provision_root(
        lease_root.to_path_buf(),
        &target.target_key_sha256(),
    )
    .map_err(call_tool_error)?;
    if root.root_identity != entitlement.lease_root_identity {
        return Err(error(
            "d1.dml_custody_entitlement_root_mismatch",
            "external entitlement did not bind the exact current virgin-root identity",
        ));
    }
    // Serialize every offline operation at the lease-root scope.  The
    // operation-id lock below only serializes exact replay; this descriptor
    // lock prevents distinct entitlements from both consuming authority for
    // one virgin root.
    let root_scope = LeaseRootScopeLock::open(lease_root, entitlement.lease_root_identity)?;
    root_scope.lock()?;
    root_scope.revalidate()?;

    let operation_sha256 = sha256_hex(entitlement.operation_id.as_bytes());
    let lock_name = format!("d1-custody-{operation_sha256}.lock");
    let consumption_name = format!("d1-custody-{operation_sha256}.consumed.json");
    let receipt_name = format!("d1-custody-{operation_sha256}.receipt.json");
    let lock = open_external_lock(&external_root, &lock_name)?;
    lock.lock().map_err(|_| {
        error(
            "d1.dml_custody_external_lock_failed",
            "external entitlement operation lock could not be acquired",
        )
    })?;

    // Revalidate the originally admitted descriptor after acquiring the
    // operation lock so a pathname replacement cannot become authority.
    let locked_read = held_entitlement
        .read()
        .map_err(|failure| artifact_error(failure.code()))?;
    if locked_read.proof().sha256_hex() != entitlement_sha256
        || exact_private_file_identity(entitlement_path)? != entitlement_identity
    {
        return Err(error(
            "d1.dml_custody_entitlement_changed",
            "external entitlement changed while its operation lock was acquired",
        ));
    }

    // The root was inspected before the operation lock only to reject an
    // obviously unrelated target early. Rebind it after locking so a root
    // replacement or a competing local writer cannot turn the stale
    // pre-lock virginity result into authority for this operation.
    root_scope.revalidate()?;
    let locked_root = inspect_d1_dml_custody_provision_root(
        lease_root.to_path_buf(),
        &target.target_key_sha256(),
    )
    .map_err(call_tool_error)?;
    if locked_root.root_identity != entitlement.lease_root_identity
        || locked_root.root_identity != root.root_identity
    {
        return Err(error(
            "d1.dml_custody_lease_root_changed",
            "the entitlement-bound lease root changed while its operation lock was acquired",
        ));
    }
    let root = locked_root;
    external_root.revalidate()?;

    let expected_consumption = D1DmlCustodyConsumption {
        version: 1,
        contract: CONSUMPTION_CONTRACT.to_string(),
        state: "in_progress".to_string(),
        operation_id: entitlement.operation_id.clone(),
        entitlement_sha256: entitlement_sha256.clone(),
        entitlement_identity,
        lease_root_identity: entitlement.lease_root_identity,
        external_seal_root_identity: external_root.identity,
        target_key_sha256: target.target_key_sha256(),
        custody_generation_sha256: authority.custody_generation_sha256.clone(),
        authority_sha256: authority.authority_sha256.clone(),
        genesis_sha256: authority.genesis_sha256.clone(),
        layout_sha256: authority.layout_sha256.clone(),
    };
    let consumption_bytes = canonical_bytes(&expected_consumption);
    let consumption_sha256 = sha256_hex(&consumption_bytes);
    let existing_consumption = read_optional_external(&external_root, &consumption_name)?;
    let existing_receipt = read_optional_external(&external_root, &receipt_name)?;

    if let Some(receipt_bytes) = existing_receipt {
        let Some(consumed_bytes) = existing_consumption else {
            return Err(error(
                "d1.dml_custody_external_receipt_orphaned",
                "external completion receipt existed without exact entitlement consumption",
            ));
        };
        if consumed_bytes != consumption_bytes {
            return Err(error(
                "d1.dml_custody_consumption_conflict",
                "incumbent external consumption contradicted this exact entitlement operation",
            ));
        }
        let stored = parse_canonical::<D1DmlCustodyExternalReceipt>(
            &receipt_bytes,
            "d1.dml_custody_external_receipt_invalid",
        )?;
        let proof = prove_d1_dml_custody_at(
            lease_root.to_path_buf(),
            &target.account_id,
            &target.database_id,
            &entitlement.custody_generation,
            &entitlement.authority_sha256,
        )
        .map_err(call_tool_error)?;
        root_scope.revalidate()?;
        external_root.revalidate()?;
        let expected = final_receipt(
            &entitlement,
            &entitlement_sha256,
            entitlement_identity,
            &consumption_sha256,
            proof.local_readback,
        );
        if stored != expected {
            return Err(error(
                "d1.dml_custody_external_receipt_conflict",
                "external completion receipt did not match exact current local readback",
            ));
        }
        return Ok(success(
            "proven",
            &entitlement_sha256,
            &consumption_sha256,
            &sha256_hex(&receipt_bytes),
            &stored.local_readback.local_readback_sha256,
        ));
    }

    let resuming = if let Some(consumed_bytes) = existing_consumption {
        if consumed_bytes != consumption_bytes {
            return Err(error(
                "d1.dml_custody_consumption_conflict",
                "incumbent external consumption contradicted this exact entitlement operation",
            ));
        }
        true
    } else {
        if !root.is_virgin {
            return Err(error(
                "d1.dml_custody_entitlement_root_not_virgin",
                "first entitlement consumption requires the exact bound custody root to be empty",
            ));
        }
        external_root.revalidate()?;
        let consumption_writer =
            write_external_exclusive(&external_root, &consumption_name, &consumption_bytes)?;
        consumption_writer.exact_readback(&consumption_bytes, "consumption")?;
        external_root.revalidate()?;
        consumption_writer.verify_path(&external_root, &consumption_name)?;
        external_root.revalidate()?;
        false
    };

    external_root.revalidate()?;
    root_scope.revalidate()?;
    let provision = if resuming && !root.is_virgin {
        // Once local creation began, an interrupted operation may only prove a
        // fully complete exact product. Missing or partial local evidence is
        // reconciliation evidence and must never be repaired.
        prove_d1_dml_custody_at(
            lease_root.to_path_buf(),
            &target.account_id,
            &target.database_id,
            &entitlement.custody_generation,
            &entitlement.authority_sha256,
        )
        .map_err(call_tool_error)?
    } else {
        crate::d1_migration_lease::provision_d1_dml_custody_at_expected_root(
            lease_root.to_path_buf(),
            &target.account_id,
            &target.database_id,
            &entitlement.custody_generation,
            &entitlement.authority_sha256,
            entitlement.lease_root_identity,
        )
        .map_err(call_tool_error)?
    };
    if provision.local_readback.root_identity != entitlement.lease_root_identity {
        return Err(error(
            "d1.dml_custody_local_readback_root_mismatch",
            "final local readback did not retain the entitlement-bound root identity",
        ));
    }
    root_scope.revalidate()?;
    external_root.revalidate()?;
    let receipt = final_receipt(
        &entitlement,
        &entitlement_sha256,
        entitlement_identity,
        &consumption_sha256,
        provision.local_readback,
    );
    let receipt_bytes = canonical_bytes(&receipt);
    let receipt_writer = write_external_exclusive(&external_root, &receipt_name, &receipt_bytes)?;
    receipt_writer.exact_readback(&receipt_bytes, "completion receipt")?;
    root_scope.revalidate()?;
    external_root.revalidate()?;
    receipt_writer.verify_path(&external_root, &receipt_name)?;
    external_root.revalidate()?;
    Ok(success(
        if resuming {
            "resumed_and_proven"
        } else {
            "provisioned"
        },
        &entitlement_sha256,
        &consumption_sha256,
        &sha256_hex(&receipt_bytes),
        &receipt.local_readback.local_readback_sha256,
    ))
}

fn final_receipt(
    entitlement: &D1DmlCustodyEntitlement,
    entitlement_sha256: &str,
    entitlement_identity: UnixFileIdentity,
    consumption_sha256: &str,
    local_readback: D1DmlCustodyLocalReadback,
) -> D1DmlCustodyExternalReceipt {
    D1DmlCustodyExternalReceipt {
        version: 1,
        contract: RECEIPT_CONTRACT.to_string(),
        state: "complete".to_string(),
        operation_id: entitlement.operation_id.clone(),
        entitlement_sha256: entitlement_sha256.to_string(),
        entitlement_identity,
        consumption_sha256: consumption_sha256.to_string(),
        consumption_state: "consumed".to_string(),
        lease_root_identity: entitlement.lease_root_identity,
        external_seal_root_identity: entitlement.external_seal_root_identity,
        target: entitlement.target.clone(),
        custody_generation_sha256: entitlement.custody_generation_sha256.clone(),
        authority_sha256: entitlement.authority_sha256.clone(),
        genesis_version: entitlement.genesis_version,
        genesis_sha256: entitlement.genesis_sha256.clone(),
        layout_version: entitlement.layout_version,
        layout_sha256: entitlement.layout_sha256.clone(),
        local_readback,
    }
}

fn success(
    status: &str,
    entitlement_sha256: &str,
    consumption_sha256: &str,
    receipt_sha256: &str,
    local_readback_sha256: &str,
) -> Value {
    json!({
        "ok": true,
        "operation": OFFLINE_OPERATION,
        "status": status,
        "entitlement_sha256": entitlement_sha256,
        "consumption_sha256": consumption_sha256,
        "external_receipt_sha256": receipt_sha256,
        "local_readback_sha256": local_readback_sha256,
        "provider_calls": 0,
        "provider_mutations": 0,
    })
}

fn error(code: &str, message: &str) -> Value {
    json!({
        "ok": false,
        "operation": OFFLINE_OPERATION,
        "status": "reconciliation_required",
        "provider_calls": 0,
        "provider_mutations": 0,
        "error": {
            "code": code,
            "message": message,
            "hint": "Preserve the external entitlement, consumption, receipt, and local custody evidence; reconcile the exact operation without creating replacement authority.",
        }
    })
}

fn artifact_error(code: &str) -> Value {
    error(
        "d1.dml_custody_external_artifact_invalid",
        &format!("external private artifact admission failed: {code}"),
    )
}

fn call_tool_error(result: rmcp::model::CallToolResult) -> Value {
    result.structured_content.unwrap_or_else(|| {
        error(
            "d1.dml_custody_local_reconciliation_required",
            "local custody proof failed without a structured receipt",
        )
    })
}

fn parse_canonical<T>(bytes: &[u8], code: &str) -> Result<T, Value>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let parsed = serde_json::from_slice::<T>(bytes)
        .map_err(|_| error(code, "external artifact was malformed or duplicate-keyed"))?;
    if canonical_bytes(&parsed) != bytes {
        return Err(error(
            code,
            "external artifact was not exact canonical JSON",
        ));
    }
    Ok(parsed)
}

fn canonical_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("closed custody receipt serialization");
    bytes.push(b'\n');
    bytes
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_operation_id(value: &str) -> bool {
    (16..=128).contains(&value.len()) && valid_d1_opaque_identity(value)
}

fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn exact_private_file_identity(path: &Path) -> Result<UnixFileIdentity, Value> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        error(
            "d1.dml_custody_external_artifact_invalid",
            "external artifact metadata was unavailable",
        )
    })?;
    if !private_regular_file(&metadata) || metadata.nlink() != 1 {
        return Err(error(
            "d1.dml_custody_external_artifact_invalid",
            "external artifact was not one private single-link regular file",
        ));
    }
    Ok(file_identity(&metadata))
}

#[derive(Debug)]
struct ExternalSealRoot {
    path: std::path::PathBuf,
    file: File,
    identity: UnixFileIdentity,
}

impl ExternalSealRoot {
    fn open(path: &Path) -> Result<Self, Value> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| {
                error(
                    "d1.dml_custody_external_artifact_invalid",
                    "external seal root could not be opened without following a symlink",
                )
            })?;
        let metadata = file.metadata().map_err(|_| {
            error(
                "d1.dml_custody_external_artifact_invalid",
                "external seal root metadata was unavailable",
            )
        })?;
        if !private_directory(&metadata) {
            return Err(error(
                "d1.dml_custody_external_artifact_invalid",
                "external seal root was not one private current-operator-owned directory",
            ));
        }
        let identity = file_identity(&metadata);
        let root = Self {
            path: path.to_path_buf(),
            file,
            identity,
        };
        root.revalidate()?;
        Ok(root)
    }

    fn revalidate(&self) -> Result<(), Value> {
        let held = self.file.metadata().map_err(|_| {
            error(
                "d1.dml_custody_external_seal_root_changed",
                "held external seal root metadata was unavailable",
            )
        })?;
        let current = fs::symlink_metadata(&self.path).map_err(|_| {
            error(
                "d1.dml_custody_external_seal_root_changed",
                "external seal root pathname could not be revalidated",
            )
        })?;
        if !private_directory(&held)
            || !private_directory(&current)
            || file_identity(&held) != self.identity
            || file_identity(&current) != self.identity
        {
            return Err(error(
                "d1.dml_custody_external_seal_root_changed",
                "external seal root identity changed during custody persistence",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct LeaseRootScopeLock {
    path: std::path::PathBuf,
    file: File,
    identity: UnixFileIdentity,
}

impl LeaseRootScopeLock {
    fn open(path: &Path, expected: UnixFileIdentity) -> Result<Self, Value> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| {
                error(
                    "d1.dml_custody_lease_root_changed",
                    "entitlement-bound lease root could not be opened safely",
                )
            })?;
        let metadata = file.metadata().map_err(|_| {
            error(
                "d1.dml_custody_lease_root_changed",
                "entitlement-bound lease root metadata was unavailable",
            )
        })?;
        let identity = file_identity(&metadata);
        if !private_directory(&metadata) || identity != expected {
            return Err(error(
                "d1.dml_custody_lease_root_changed",
                "entitlement-bound lease root identity changed before custody creation",
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity,
        })
    }

    fn lock(&self) -> Result<(), Value> {
        self.file.lock().map_err(|_| {
            error(
                "d1.dml_custody_lease_root_lock_failed",
                "lease root scope lock could not be acquired",
            )
        })
    }

    fn revalidate(&self) -> Result<(), Value> {
        let held = self.file.metadata().map_err(|_| {
            error(
                "d1.dml_custody_lease_root_changed",
                "held lease root metadata was unavailable",
            )
        })?;
        let current = fs::symlink_metadata(&self.path).map_err(|_| {
            error(
                "d1.dml_custody_lease_root_changed",
                "lease root pathname could not be revalidated",
            )
        })?;
        if !private_directory(&held)
            || !private_directory(&current)
            || file_identity(&held) != self.identity
            || file_identity(&current) != self.identity
        {
            return Err(error(
                "d1.dml_custody_lease_root_changed",
                "lease root identity changed during custody provisioning",
            ));
        }
        Ok(())
    }
}

fn private_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o077 == 0
}

fn open_external_relative(
    root: &ExternalSealRoot,
    name: &str,
    flags: i32,
) -> std::io::Result<File> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "unsafe name"))?;
    let fd = unsafe {
        libc::openat(
            root.file.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_external_lock(root: &ExternalSealRoot, name: &str) -> Result<File, Value> {
    let file = open_external_relative(root, name, libc::O_RDWR | libc::O_CREAT).map_err(|_| {
        error(
            "d1.dml_custody_external_lock_failed",
            "external entitlement operation lock could not be opened safely",
        )
    })?;
    let metadata = file.metadata().map_err(|_| {
        error(
            "d1.dml_custody_external_lock_failed",
            "external entitlement operation lock metadata was unavailable",
        )
    })?;
    if !private_regular_file(&metadata) || metadata.nlink() != 1 {
        return Err(error(
            "d1.dml_custody_external_lock_failed",
            "external entitlement operation lock was not one private single-link regular file",
        ));
    }
    Ok(file)
}

#[derive(Debug)]
struct ExternalCreatedFile {
    file: File,
    identity: UnixFileIdentity,
}

impl ExternalCreatedFile {
    fn exact_readback(&self, expected: &[u8], label: &str) -> Result<(), Value> {
        let readback = read_external_file_exact(&self.file)?;
        if readback != expected {
            let code = match label {
                "consumption" => "d1.dml_custody_consumption_readback_failed",
                _ => "d1.dml_custody_external_receipt_readback_failed",
            };
            return Err(error(
                code,
                &format!("external {label} did not survive exact private readback"),
            ));
        }
        Ok(())
    }

    fn verify_path(&self, root: &ExternalSealRoot, name: &str) -> Result<(), Value> {
        root.revalidate()?;
        let rebound = open_external_relative(root, name, libc::O_RDONLY).map_err(|_| {
            error(
                "d1.dml_custody_external_output_replaced",
                "external output pathname no longer named the creator inode",
            )
        })?;
        let metadata = rebound.metadata().map_err(|_| {
            error(
                "d1.dml_custody_external_output_replaced",
                "external output creator inode could not be revalidated",
            )
        })?;
        if !private_regular_file(&metadata)
            || metadata.nlink() != 1
            || file_identity(&metadata) != self.identity
        {
            return Err(error(
                "d1.dml_custody_external_output_replaced",
                "external output pathname no longer named the creator inode",
            ));
        }
        root.revalidate()?;
        Ok(())
    }
}

fn write_external_exclusive(
    root: &ExternalSealRoot,
    name: &str,
    bytes: &[u8],
) -> Result<ExternalCreatedFile, Value> {
    root.revalidate()?;
    let mut file = open_external_relative(root, name, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)
        .map_err(|_| {
            error(
                "d1.dml_custody_external_cas_failed",
                "external receipt could not be created exclusively",
            )
        })?;
    let metadata = file.metadata().map_err(|_| {
        error(
            "d1.dml_custody_external_write_failed",
            "external output creator metadata was unavailable",
        )
    })?;
    if !private_regular_file(&metadata) || metadata.nlink() != 1 {
        return Err(error(
            "d1.dml_custody_external_write_failed",
            "external output creator was not one private single-link regular file",
        ));
    }
    let identity = file_identity(&metadata);
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| {
            error(
                "d1.dml_custody_external_write_failed",
                "external receipt could not be durably written",
            )
        })?;
    root.file.sync_all().map_err(|_| {
        error(
            "d1.dml_custody_external_write_failed",
            "external seal directory could not be synchronized",
        )
    })?;
    let created = ExternalCreatedFile { file, identity };
    created.exact_readback(bytes, "output")?;
    root.revalidate()?;
    created.verify_path(root, name)?;
    root.revalidate()?;
    Ok(created)
}

fn read_optional_external(root: &ExternalSealRoot, name: &str) -> Result<Option<Vec<u8>>, Value> {
    root.revalidate()?;
    match open_external_relative(root, name, libc::O_RDONLY) {
        Ok(file) => {
            let bytes = read_external_file_exact(&file)?;
            root.revalidate()?;
            Ok(Some(bytes))
        }
        Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(error(
            "d1.dml_custody_external_artifact_invalid",
            "external receipt namespace could not be inspected",
        )),
    }
}

fn read_external_file_exact(file: &File) -> Result<Vec<u8>, Value> {
    let metadata = file.metadata().map_err(|_| {
        error(
            "d1.dml_custody_external_artifact_invalid",
            "external artifact metadata was unavailable",
        )
    })?;
    if !private_regular_file(&metadata) || metadata.nlink() != 1 {
        return Err(error(
            "d1.dml_custody_external_artifact_invalid",
            "external artifact was not one private single-link regular file",
        ));
    }
    let identity = file_identity(&metadata);
    let expected_len = metadata.len();
    let mut bytes = Vec::new();
    let mut reader = file;
    reader.seek(SeekFrom::Start(0)).map_err(|_| {
        error(
            "d1.dml_custody_external_artifact_invalid",
            "external artifact could not seek for exact readback",
        )
    })?;
    std::io::Read::read_to_end(&mut reader, &mut bytes).map_err(|_| {
        error(
            "d1.dml_custody_external_artifact_invalid",
            "external artifact could not be read",
        )
    })?;
    let final_metadata = file.metadata().map_err(|_| {
        error(
            "d1.dml_custody_external_artifact_invalid",
            "external artifact metadata changed during read",
        )
    })?;
    if file_identity(&final_metadata) != identity
        || final_metadata.len() != expected_len
        || bytes.len() as u64 != expected_len
        || bytes.len() as u64 > MAX_EXTERNAL_SEAL_ARTIFACT_BYTES
    {
        return Err(error(
            "d1.dml_custody_external_artifact_invalid",
            "external artifact changed during exact readback",
        ));
    }
    Ok(bytes)
}

/// Aggregate-safe planning projection used by the public MCP tool.
pub(crate) fn public_entitlement_requirements(
    target_key_sha256: &str,
    custody_generation_sha256: &str,
    authority_sha256: &str,
    genesis_sha256: &str,
) -> Value {
    json!({
        "contract": ENTITLEMENT_CONTRACT,
        "state": "available",
        "operation_id": "operator_preallocated_16_to_128_byte_opaque_identity",
        "lease_root_identity": "operator_proven_virgin_device_and_inode",
        "external_seal_root_identity": "operator_proven_private_seal_root_device_and_inode",
        "target_key_sha256": target_key_sha256,
        "custody_generation_sha256": custody_generation_sha256,
        "authority_sha256": authority_sha256,
        "genesis_version": D1_DML_CUSTODY_GENESIS_VERSION,
        "genesis_sha256": genesis_sha256,
        "layout_version": D1_DML_CUSTODY_LAYOUT_VERSION,
        "layout_sha256": D1_DML_CUSTODY_LAYOUT_SHA256,
        "external_seal": "required_outside_d1_custody_root",
        "mcp_live_apply_authority": false,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture {
        base: std::path::PathBuf,
        lease_root: std::path::PathBuf,
        seal_root: std::path::PathBuf,
        entitlement: std::path::PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let base = std::path::PathBuf::from("/tmp").join(format!(
                "cloudflare-mcp-offline-custody-{label}-{}-{nonce}",
                std::process::id()
            ));
            let lease_root = base.join("lease");
            let seal_root = base.join("seal");
            fs::create_dir_all(&lease_root).expect("create lease root");
            fs::create_dir_all(&seal_root).expect("create seal root");
            fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).expect("private base");
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("private lease root");
            fs::set_permissions(&seal_root, fs::Permissions::from_mode(0o700))
                .expect("private seal root");
            let entitlement = seal_root.join("entitlement.json");
            Self {
                base,
                lease_root,
                seal_root,
                entitlement,
            }
        }

        fn write_entitlement(&self, operation_id: &str) -> D1DmlCustodyEntitlement {
            let root_identity =
                file_identity(&fs::symlink_metadata(&self.lease_root).expect("root"));
            let external_seal_root_identity =
                file_identity(&fs::symlink_metadata(&self.seal_root).expect("seal root"));
            let target = normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000")
                .expect("target");
            let authority_pin = "73cc578c679ad9a10bba8ca71ef85a1efc39e8edfb46a38516fb61ab08c98548";
            let (authority, _) = derive_d1_dml_custody_authority(
                &target.target_key_sha256(),
                "test-custody-generation-v1",
                authority_pin,
            )
            .expect("authority");
            let entitlement = D1DmlCustodyEntitlement {
                version: 1,
                contract: ENTITLEMENT_CONTRACT.to_string(),
                state: "available".to_string(),
                operation_id: operation_id.to_string(),
                lease_root_identity: root_identity,
                external_seal_root_identity,
                target: EntitlementTarget {
                    account_id: target.account_id,
                    database_id: target.database_id,
                    target_key_sha256: authority.target_key_sha256,
                },
                custody_generation: "test-custody-generation-v1".to_string(),
                custody_generation_sha256: authority.custody_generation_sha256,
                authority_sha256: authority.authority_sha256,
                genesis_version: D1_DML_CUSTODY_GENESIS_VERSION,
                genesis_sha256: authority.genesis_sha256,
                layout_version: D1_DML_CUSTODY_LAYOUT_VERSION,
                layout_sha256: D1_DML_CUSTODY_LAYOUT_SHA256.to_string(),
            };
            fs::write(&self.entitlement, canonical_bytes(&entitlement)).expect("entitlement");
            fs::set_permissions(&self.entitlement, fs::Permissions::from_mode(0o600))
                .expect("private entitlement");
            entitlement
        }

        fn install_exact_consumption(&self, entitlement: &D1DmlCustodyEntitlement) {
            let entitlement_bytes = fs::read(&self.entitlement).expect("entitlement bytes");
            let entitlement_identity =
                exact_private_file_identity(&self.entitlement).expect("entitlement identity");
            let consumption = D1DmlCustodyConsumption {
                version: 1,
                contract: CONSUMPTION_CONTRACT.to_string(),
                state: "in_progress".to_string(),
                operation_id: entitlement.operation_id.clone(),
                entitlement_sha256: sha256_hex(&entitlement_bytes),
                entitlement_identity,
                lease_root_identity: entitlement.lease_root_identity,
                external_seal_root_identity: entitlement.external_seal_root_identity,
                target_key_sha256: entitlement.target.target_key_sha256.clone(),
                custody_generation_sha256: entitlement.custody_generation_sha256.clone(),
                authority_sha256: entitlement.authority_sha256.clone(),
                genesis_sha256: entitlement.genesis_sha256.clone(),
                layout_sha256: entitlement.layout_sha256.clone(),
            };
            let operation_sha256 = sha256_hex(entitlement.operation_id.as_bytes());
            let path = self
                .seal_root
                .join(format!("d1-custody-{operation_sha256}.consumed.json"));
            let seal_root = ExternalSealRoot::open(&self.seal_root).expect("seal root");
            write_external_exclusive(
                &seal_root,
                path.file_name().unwrap().to_str().unwrap(),
                &canonical_bytes(&consumption),
            )
            .expect("exact external consumption");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn offline_entitlement_is_consumed_before_provision_and_exact_replay_only_proves() {
        let fixture = Fixture::new("roundtrip");
        fixture.write_entitlement("custody-operation-0001");
        let first = run_offline_d1_dml_custody_provision(
            &fixture.lease_root,
            &fixture.seal_root,
            &fixture.entitlement,
        )
        .expect("first provision");
        assert_eq!(first["status"], "provisioned");
        assert_eq!(first["provider_calls"], 0);
        let replay = run_offline_d1_dml_custody_provision(
            &fixture.lease_root,
            &fixture.seal_root,
            &fixture.entitlement,
        )
        .expect("exact replay proof");
        assert_eq!(replay["status"], "proven");
        assert_eq!(
            replay["external_receipt_sha256"],
            first["external_receipt_sha256"]
        );
    }

    #[test]
    fn consumed_completion_never_repairs_missing_local_authority() {
        let fixture = Fixture::new("loss");
        fixture.write_entitlement("custody-operation-0002");
        run_offline_d1_dml_custody_provision(
            &fixture.lease_root,
            &fixture.seal_root,
            &fixture.entitlement,
        )
        .expect("first provision");
        fs::remove_file(
            fixture
                .lease_root
                .join(format!(
                    "d1-migration-target-{}",
                    sha256_hex(b"acct-1\0123e4567-e89b-42d3-a456-426614174000")
                ))
                .join("dml-custody-genesis-v1.json"),
        )
        .expect("remove genesis");
        let error = run_offline_d1_dml_custody_provision(
            &fixture.lease_root,
            &fixture.seal_root,
            &fixture.entitlement,
        )
        .expect_err("completed entitlement must never repair loss");
        assert_eq!(error["ok"], false);
        assert_eq!(error["provider_calls"], 0);
        assert!(
            !fixture
                .lease_root
                .join(format!(
                    "d1-migration-target-{}",
                    sha256_hex(b"acct-1\0123e4567-e89b-42d3-a456-426614174000")
                ))
                .join("dml-custody-genesis-v1.json")
                .exists()
        );
    }

    #[test]
    fn conflicting_consumed_entitlement_cannot_reuse_operation() {
        let fixture = Fixture::new("conflict");
        fixture.write_entitlement("custody-operation-0003");
        run_offline_d1_dml_custody_provision(
            &fixture.lease_root,
            &fixture.seal_root,
            &fixture.entitlement,
        )
        .expect("first provision");
        let mut bytes = fs::read(&fixture.entitlement).expect("read entitlement");
        let position = bytes
            .windows("custody-operation-0003".len())
            .position(|window| window == b"custody-operation-0003")
            .expect("operation bytes");
        bytes[position + "custody-operation-".len()..position + "custody-operation-".len() + 4]
            .copy_from_slice(b"9999");
        fs::write(&fixture.entitlement, bytes).expect("replace entitlement bytes");
        let error = run_offline_d1_dml_custody_provision(
            &fixture.lease_root,
            &fixture.seal_root,
            &fixture.entitlement,
        )
        .expect_err("changed entitlement must fail closed");
        assert_eq!(error["ok"], false);
        assert_eq!(error["provider_calls"], 0);
    }

    #[test]
    fn exact_consumed_interruption_resumes_once_and_binds_final_readback() {
        let fixture = Fixture::new("resume");
        let entitlement = fixture.write_entitlement("custody-operation-0004");
        fixture.install_exact_consumption(&entitlement);
        assert_eq!(
            fs::read_dir(&fixture.lease_root)
                .expect("virgin lease root")
                .count(),
            0
        );

        let resumed = run_offline_d1_dml_custody_provision(
            &fixture.lease_root,
            &fixture.seal_root,
            &fixture.entitlement,
        )
        .expect("exact interrupted operation resumes");
        assert_eq!(resumed["status"], "resumed_and_proven");
        assert_eq!(resumed["provider_calls"], 0);

        let proven = run_offline_d1_dml_custody_provision(
            &fixture.lease_root,
            &fixture.seal_root,
            &fixture.entitlement,
        )
        .expect("completed operation only proves");
        assert_eq!(proven["status"], "proven");
        assert_eq!(
            proven["external_receipt_sha256"],
            resumed["external_receipt_sha256"]
        );
    }

    #[test]
    fn in_progress_partial_local_tree_fails_without_repair() {
        let fixture = Fixture::new("partial");
        let entitlement = fixture.write_entitlement("custody-operation-0006");
        fixture.install_exact_consumption(&entitlement);
        let target_path = fixture.lease_root.join(format!(
            "d1-migration-target-{}",
            entitlement.target.target_key_sha256
        ));
        fs::create_dir(&target_path).expect("simulate interrupted target creation");
        fs::set_permissions(&target_path, fs::Permissions::from_mode(0o700))
            .expect("private partial target");

        let error = run_offline_d1_dml_custody_provision(
            &fixture.lease_root,
            &fixture.seal_root,
            &fixture.entitlement,
        )
        .expect_err("partial local product must not be repaired");
        assert_eq!(error["ok"], false);
        assert_eq!(error["provider_calls"], 0);
        assert_eq!(
            fs::read_dir(&target_path)
                .expect("unchanged partial target")
                .count(),
            0
        );
    }

    #[test]
    fn concurrent_exact_provision_converges_under_external_operation_lock() {
        let fixture = Fixture::new("concurrent");
        fixture.write_entitlement("custody-operation-0005");
        let lease_root = fixture.lease_root.clone();
        let seal_root = fixture.seal_root.clone();
        let entitlement_path = fixture.entitlement.clone();
        let first = std::thread::spawn({
            let lease_root = lease_root.clone();
            let seal_root = seal_root.clone();
            let entitlement_path = entitlement_path.clone();
            move || run_offline_d1_dml_custody_provision(&lease_root, &seal_root, &entitlement_path)
        });
        let second = std::thread::spawn(move || {
            run_offline_d1_dml_custody_provision(&lease_root, &seal_root, &entitlement_path)
        });
        let first = first.join().expect("first thread").expect("first result");
        let second = second
            .join()
            .expect("second thread")
            .expect("second result");
        let mut statuses = vec![
            first["status"].as_str().expect("first status"),
            second["status"].as_str().expect("second status"),
        ];
        statuses.sort_unstable();
        assert_eq!(statuses, vec!["proven", "provisioned"]);
        assert_eq!(
            first["external_receipt_sha256"],
            second["external_receipt_sha256"]
        );
        assert_eq!(first["provider_calls"], 0);
        assert_eq!(second["provider_calls"], 0);
    }

    #[test]
    fn lease_root_replacement_is_rejected_before_first_local_create() {
        let fixture = Fixture::new("lease-root-swap");
        let entitlement = fixture.write_entitlement("custody-operation-0007");
        let old_root = fixture.base.join("lease-original");
        fs::rename(&fixture.lease_root, &old_root).expect("retain original lease root");
        fs::create_dir(&fixture.lease_root).expect("replacement lease root");
        fs::set_permissions(&fixture.lease_root, fs::Permissions::from_mode(0o700))
            .expect("private replacement lease root");

        let error = run_offline_d1_dml_custody_provision(
            &fixture.lease_root,
            &fixture.seal_root,
            &fixture.entitlement,
        )
        .expect_err("replacement lease root must fail before creation");
        assert_eq!(error["ok"], false);
        assert_eq!(
            error["error"]["code"],
            "d1.dml_custody_entitlement_root_mismatch"
        );
        let target_path = fixture.lease_root.join(format!(
            "d1-migration-target-{}",
            entitlement.target.target_key_sha256
        ));
        assert!(!target_path.exists(), "replacement root remained untouched");
    }

    #[test]
    fn distinct_operations_cannot_both_consume_one_lease_root() {
        let fixture = Fixture::new("distinct-operations");
        let first_entitlement = fixture.write_entitlement("custody-operation-0008");
        let second_path = fixture.seal_root.join("entitlement-2.json");
        let mut second_entitlement = first_entitlement.clone();
        second_entitlement.operation_id = "custody-operation-0009".to_string();
        fs::write(&second_path, canonical_bytes(&second_entitlement)).expect("second entitlement");
        fs::set_permissions(&second_path, fs::Permissions::from_mode(0o600))
            .expect("private second entitlement");
        let lease_root = fixture.lease_root.clone();
        let seal_root = fixture.seal_root.clone();
        let first_path = fixture.entitlement.clone();
        let first = std::thread::spawn({
            let lease_root = lease_root.clone();
            let seal_root = seal_root.clone();
            move || run_offline_d1_dml_custody_provision(&lease_root, &seal_root, &first_path)
        });
        let second = std::thread::spawn(move || {
            run_offline_d1_dml_custody_provision(&lease_root, &seal_root, &second_path)
        });
        let first = first.join().expect("first thread");
        let second = second.join().expect("second thread");
        assert_eq!(
            first.is_ok(),
            second.is_err(),
            "exactly one operation may win"
        );
        let failure = first.err().or_else(|| second.err()).expect("loser error");
        assert_eq!(failure["ok"], false);
        assert_eq!(
            failure["error"]["code"],
            "d1.dml_custody_entitlement_root_not_virgin"
        );
    }

    #[test]
    fn external_seal_root_replacement_is_rejected_before_consumption() {
        let fixture = Fixture::new("seal-root-swap");
        fixture.write_entitlement("custody-operation-0010");
        let old_root = fixture.base.join("seal-original");
        fs::rename(&fixture.seal_root, &old_root).expect("retain original seal root");
        fs::create_dir(&fixture.seal_root).expect("replacement seal root");
        fs::set_permissions(&fixture.seal_root, fs::Permissions::from_mode(0o700))
            .expect("private replacement seal root");
        fs::copy(
            old_root.join("entitlement.json"),
            fixture.seal_root.join("entitlement.json"),
        )
        .expect("copy entitlement into replacement namespace");
        fs::set_permissions(
            fixture.seal_root.join("entitlement.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private replacement entitlement");

        let error = run_offline_d1_dml_custody_provision(
            &fixture.lease_root,
            &fixture.seal_root,
            &fixture.seal_root.join("entitlement.json"),
        )
        .expect_err("replacement seal root must fail closed");
        assert_eq!(error["ok"], false);
        assert_eq!(
            error["error"]["code"],
            "d1.dml_custody_external_seal_root_mismatch"
        );
        assert_eq!(
            fs::read_dir(&fixture.seal_root)
                .expect("replacement seal root")
                .count(),
            1,
            "replacement seal root contains only the copied entitlement"
        );
    }

    #[test]
    fn byte_identical_external_output_replacement_is_rejected_by_creator_identity() {
        let fixture = Fixture::new("output-replacement");
        let root = ExternalSealRoot::open(&fixture.seal_root).expect("seal root");
        let name = "injected-output.json";
        let bytes = b"{\"state\":\"complete\"}\n";
        let creator = write_external_exclusive(&root, name, bytes).expect("creator output");
        let path = fixture.seal_root.join(name);
        // Keep the creator inode linked while replacing the published name so
        // inode reuse cannot make this regression nondeterministic.
        fs::rename(&path, fixture.seal_root.join("creator-held.json")).expect("move creator aside");
        let mut replacement = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("replacement output");
        replacement
            .write_all(bytes)
            .expect("byte-identical replacement");
        replacement.sync_all().expect("sync replacement");

        let error = creator
            .verify_path(&root, name)
            .expect_err("byte-identical pathname replacement must fail");
        assert_eq!(error["ok"], false);
        assert_eq!(
            error["error"]["code"],
            "d1.dml_custody_external_output_replaced"
        );
    }
}
