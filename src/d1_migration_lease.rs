//! Local custody and cross-process lease for D1 migration applies.
//!
//! This module intentionally has no MCP registration or provider calls. It owns
//! the filesystem boundary that serializes one account/database migration target.

use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::{Value, json};

use crate::tools::{invalid_argument_result, sha256_bytes_hex};
use crate::verification::now_unix_ms;

pub(crate) const D1_MANIFEST_LEASE_ROOT_ENV: &str = "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT";
static D1_MANIFEST_LEASE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(crate) struct D1MigrationLease {
    pub(crate) path: PathBuf,
    pub(crate) identity: D1MigrationLeaseIdentity,
    file_identity: D1LeaseFileIdentity,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct D1MigrationLeaseIdentity {
    pub(crate) target_key_sha256: String,
    pub(crate) nonce: String,
    pub(crate) payload_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct D1LeaseFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl D1MigrationLease {
    pub(crate) fn release(&self) -> Result<(), CallToolResult> {
        let observed = d1_lease_file_identity(&self.path)
            .ok_or_else(|| self.release_failure("lease file is unavailable or changed"))?;
        let bytes =
            fs::read(&self.path).map_err(|_| self.release_failure("lease file cannot be read"))?;
        if observed != self.file_identity
            || sha256_bytes_hex(&bytes) != self.identity.payload_sha256
        {
            return Err(self.release_failure("lease ownership no longer matches this operation"));
        }
        if !d1_remove_owned_lease_file(&self.path, &self.file_identity) {
            return Err(self.release_failure("lease file cannot be removed safely"));
        }
        Ok(())
    }

    fn release_failure(&self, message: &'static str) -> CallToolResult {
        CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "d1_apply_migration_manifest",
            "status": "reconciliation_required",
            "lease_retained": true,
            "lease": self.identity,
            "error": {"code": "d1.migration_lease_release_failed", "message": message, "hint": "Inspect the shared lease root and reconcile the owner identity before another migration apply."},
        }))
    }

    pub(crate) fn retain(&self) {
        // Deliberately no-op. An unknown provider outcome must retain the
        // cross-process target lease until an operator reconciles it.
    }
}

fn d1_lease_file_identity_from_metadata(metadata: &fs::Metadata) -> Option<D1LeaseFileIdentity> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(D1LeaseFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Some(D1LeaseFileIdentity {})
    }
}

fn d1_lease_file_identity(path: &Path) -> Option<D1LeaseFileIdentity> {
    let metadata = fs::symlink_metadata(path).ok()?;
    d1_lease_file_identity_from_metadata(&metadata)
}

fn d1_remove_owned_lease_file(path: &Path, expected: &D1LeaseFileIdentity) -> bool {
    d1_lease_file_identity(path).as_ref() == Some(expected)
        && fs::remove_file(path).is_ok()
        && path
            .parent()
            .is_some_and(|parent| sync_d1_lease_parent_directory(parent).is_ok())
}

#[cfg(unix)]
fn sync_d1_lease_parent_directory(root: &Path) -> std::io::Result<()> {
    fs::File::open(root)?.sync_all()
}

#[cfg(not(unix))]
fn sync_d1_lease_parent_directory(_: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_d1_lease_file_mode(file: &fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_d1_lease_file_mode(_: &fs::File) -> std::io::Result<()> {
    Ok(())
}

fn d1_lease_root_error(code: &'static str, message: &'static str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_apply_migration_manifest",
        "status": "reconciliation_required",
        "lease_retained": false,
        "error": {"code": code, "message": message, "hint": "Use an absolute, operator-owned 0700 lease root with safe ancestors."},
    }))
}

fn d1_migration_lease_nonce(target_hash: &str, plan_sha256: &str) -> String {
    let sequence = D1_MANIFEST_LEASE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let material = format!(
        "{target_hash}\0{plan_sha256}\0{}\0{sequence}",
        now_unix_ms()
    );
    blake3::hash(material.as_bytes()).to_hex().to_string()
}

#[cfg(unix)]
fn current_effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no arguments and no side effects beyond reading the
    // current process credential.
    unsafe { geteuid() }
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
        "scope": "one lease per account/database target; family is evidence only and cannot split target serialization",
        "cross_host_limitation": "Cross-process serialization covers only hosts sharing the same configured operator-owned lease root. It is not a Cloudflare/provider-distributed lease.",
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
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
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
            "ok": false,
            "operation": "d1_apply_migration_manifest",
            "error": {
                "code": "d1.migration_lease_root_unconfigured",
                "message": "live migration apply requires a configured operator-owned shared lease root",
                "hint": format!("Set {D1_MANIFEST_LEASE_ROOT_ENV} to a pre-created private directory shared by all MCP processes that can target this D1 database."),
            },
        })))?;
    acquire_d1_migration_lease_at(root, account_id, database_id, family, plan_sha256)
}

pub(crate) fn acquire_d1_migration_lease_at(
    root: PathBuf,
    account_id: &str,
    database_id: &str,
    family: &str,
    plan_sha256: &str,
) -> Result<D1MigrationLease, CallToolResult> {
    if !root.is_absolute() {
        return Err(d1_lease_root_error(
            "d1.migration_lease_root_invalid",
            "migration lease root must be an absolute path",
        ));
    }
    let metadata = fs::symlink_metadata(&root).map_err(|_| CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_apply_migration_manifest",
        "error": {"code": "d1.migration_lease_root_invalid", "message": "configured migration lease root is unavailable", "hint": "Create a private operator-owned directory and configure every relevant MCP process with the same path."},
    })))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "d1_apply_migration_manifest",
            "error": {"code": "d1.migration_lease_root_invalid", "message": "migration lease root must be a real directory, not a symlink", "hint": "Use a private operator-owned directory."},
        })));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != current_effective_uid() || metadata.mode() & 0o077 != 0 {
            return Err(d1_lease_root_error(
                "d1.migration_lease_root_unsafe",
                "migration lease root must be owned by the current operator and mode 0700 or stricter",
            ));
        }
        for ancestor in root.ancestors().skip(1) {
            let ancestor_metadata = fs::symlink_metadata(ancestor).map_err(|_| {
                d1_lease_root_error(
                    "d1.migration_lease_root_invalid",
                    "migration lease root ancestor is unavailable",
                )
            })?;
            if ancestor_metadata.file_type().is_symlink() {
                return Err(d1_lease_root_error(
                    "d1.migration_lease_root_invalid",
                    "migration lease root has a symlink ancestor",
                ));
            }
            let mode = ancestor_metadata.mode();
            if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                return Err(d1_lease_root_error(
                    "d1.migration_lease_root_unsafe",
                    "migration lease root has a writable non-sticky ancestor",
                ));
            }
        }
    }
    let target_hash = sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes());
    let path = root.join(format!("d1-migration-target-{target_hash}.lease.json"));
    let nonce = d1_migration_lease_nonce(&target_hash, plan_sha256);
    let payload = json!({
        "version": 1,
        "target_key_sha256": &target_hash,
        "nonce": &nonce,
        "account_id": account_id,
        "database_id": database_id,
        "migration_family": family,
        "approved_plan_sha256": plan_sha256.to_ascii_lowercase(),
    });
    let encoded = serde_json::to_vec(&payload).expect("serializing lease payload is infallible");
    let identity = D1MigrationLeaseIdentity {
        target_key_sha256: target_hash,
        nonce,
        payload_sha256: sha256_bytes_hex(&encoded),
    };
    let mut open_options = OpenOptions::new();
    open_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.mode(0o600);
    }
    match open_options.open(&path) {
        Ok(mut file) => {
            let created_file_identity = match file
                .metadata()
                .ok()
                .and_then(|metadata| d1_lease_file_identity_from_metadata(&metadata))
            {
                Some(file_identity) => file_identity,
                None => {
                    return Err(CallToolResult::structured_error(json!({
                        "ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required",
                        "lease_retained": true, "lease": identity,
                        "operator_handoff": "Reconcile the newly created lease root entry before any subsequent apply.",
                        "error": {"code": "d1.migration_lease_identity_unreadable", "message": "new lease file could not be identified as an owned regular file", "hint": "Do not start another apply until the lease root has been reconciled."},
                    })));
                }
            };
            if set_d1_lease_file_mode(&file).is_err() {
                let cleanup = d1_remove_owned_lease_file(&path, &created_file_identity);
                return Err(CallToolResult::structured_error(json!({
                    "ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required",
                    "lease_retained": !cleanup, "lease": identity,
                    "operator_handoff": "Reconcile the named lease owner identity before any subsequent apply.",
                    "error": {"code": "d1.migration_lease_mode_failed", "message": "new lease file could not be set to mode 0600", "hint": "Reconcile the lease identity if cleanup was incomplete before another apply."},
                })));
            }
            if file
                .write_all(&encoded)
                .and_then(|()| file.sync_all())
                .is_err()
            {
                let cleanup = d1_remove_owned_lease_file(&path, &created_file_identity);
                return Err(CallToolResult::structured_error(json!({
                    "ok": false,
                    "operation": "d1_apply_migration_manifest",
                    "status": "reconciliation_required",
                    "lease_retained": !cleanup,
                    "lease": identity,
                    "operator_handoff": "Reconcile the named lease owner identity before any subsequent apply.",
                    "error": {"code": "d1.migration_lease_write_failed", "message": "migration lease payload could not be durably written", "hint": "Reconcile the lease identity if cleanup was incomplete before another apply."},
                })));
            }
            if sync_d1_lease_parent_directory(&root).is_err() {
                let cleanup = d1_remove_owned_lease_file(&path, &created_file_identity);
                return Err(CallToolResult::structured_error(json!({
                    "ok": false,
                    "operation": "d1_apply_migration_manifest",
                    "status": "reconciliation_required",
                    "lease_retained": !cleanup,
                    "lease": identity,
                    "operator_handoff": "Reconcile the named lease owner identity before any subsequent apply.",
                    "error": {"code": "d1.migration_lease_parent_sync_failed", "message": "new lease entry was written but its parent directory could not be durably synchronized", "hint": "Reconcile the lease identity if cleanup was incomplete before another apply."},
                })));
            }
            let file_identity = match d1_lease_file_identity(&path) {
                Some(file_identity) if file_identity == created_file_identity => file_identity,
                None => {
                    let cleanup = d1_remove_owned_lease_file(&path, &created_file_identity);
                    return Err(CallToolResult::structured_error(json!({
                        "ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required",
                        "lease_retained": !cleanup, "lease": identity,
                        "operator_handoff": "Reconcile the named lease owner identity before any subsequent apply.",
                        "error": {"code": "d1.migration_lease_identity_unreadable", "message": "new lease file could not be read back as an owned regular file", "hint": "Reconcile the lease identity if cleanup was incomplete before another apply."},
                    })));
                }
                Some(_) => {
                    return Err(CallToolResult::structured_error(json!({
                        "ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required",
                        "lease_retained": true, "lease": identity,
                        "operator_handoff": "Reconcile the named lease owner identity before any subsequent apply.",
                        "error": {"code": "d1.migration_lease_identity_changed", "message": "new lease pathname no longer resolves to the created lease file", "hint": "Do not start another apply until the lease root has been reconciled."},
                    })));
                }
            };
            Ok(D1MigrationLease {
                path,
                identity,
                file_identity,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "d1_apply_migration_manifest",
                "status": "lease_held",
                "lease_retained": true,
                "lease": {"target_key_sha256": identity.target_key_sha256, "ownership": "other_or_unreadable"},
                "operator_handoff": "Reconcile the target lease holder or its terminal provider evidence before any subsequent apply.",
                "error": {"code": "d1.migration_target_lease_held", "message": "another migration operation holds this account/database target lease", "hint": "Wait for terminal provider readback or reconcile the retained lease; do not start another family against this target."},
            })))
        }
        Err(_) => Err(CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "d1_apply_migration_manifest",
            "error": {"code": "d1.migration_lease_acquire_failed", "message": "could not atomically acquire the target migration lease", "hint": "Verify the configured lease root and retry only after no active target lease remains."},
        }))),
    }
}
