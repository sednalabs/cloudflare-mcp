//! Durable, cross-process custody for exact-byte D1 migration applies.
//!
//! A target directory and its guard are permanent. `active.lease.json` is
//! evidence, not garbage: later processes stop for reconciliation when it is
//! present. This module deliberately owns no MCP registration or provider I/O.

use std::fs;
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
    #[cfg(unix)]
    root: PathBuf,
    #[cfg(unix)]
    target_dir: PathBuf,
    #[cfg(unix)]
    active_path: PathBuf,
    #[cfg(unix)]
    guard_path: PathBuf,
    #[cfg(unix)]
    guard: Option<fs::File>,
    pub(crate) identity: D1MigrationLeaseIdentity,
    #[cfg(unix)]
    active_file_identity: D1LeaseFileIdentity,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct D1MigrationLeaseIdentity {
    pub(crate) target_key_sha256: String,
    pub(crate) nonce: String,
    pub(crate) payload_sha256: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct D1LeaseFileIdentity {
    device: u64,
    inode: u64,
}

impl D1MigrationLease {
    /// Record normal terminal completion without unlinking the active evidence.
    pub(crate) fn release(&mut self) -> Result<(), CallToolResult> {
        #[cfg(unix)]
        {
            self.release_unix()
        }
        #[cfg(not(unix))]
        {
            Err(d1_lease_platform_unsupported())
        }
    }

    /// Preserve active evidence on every uncertain outcome.
    pub(crate) fn retain(&mut self) {
        #[cfg(unix)]
        {
            self.guard.take();
        }
    }

    /// Re-check the held custody chain immediately before a provider boundary.
    pub(crate) fn revalidate(&self) -> Result<(), CallToolResult> {
        #[cfg(unix)]
        {
            let guard = self.guard.as_ref().ok_or_else(|| {
                self.revalidation_failure(
                    "this invocation no longer holds the permanent target guard",
                )
            })?;
            validate_d1_lease_custody(&self.root, &self.target_dir, &self.guard_path, guard)
                .map_err(|message| self.revalidation_failure(message))?;
            validate_owned_active_lease(
                &self.active_path,
                &self.active_file_identity,
                &self.identity,
            )
            .map_err(|message| self.revalidation_failure(message))?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Err(d1_lease_platform_unsupported())
        }
    }

    #[cfg(test)]
    pub(crate) fn active_path_for_test(&self) -> Option<&Path> {
        #[cfg(unix)]
        {
            Some(&self.active_path)
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    #[cfg(unix)]
    fn release_unix(&mut self) -> Result<(), CallToolResult> {
        let guard = self.guard.as_ref().ok_or_else(|| {
            self.release_failure("this invocation no longer holds the permanent target guard")
        })?;
        validate_d1_lease_custody(&self.root, &self.target_dir, &self.guard_path, guard)
            .map_err(|message| self.release_failure(message))?;
        validate_owned_active_lease(
            &self.active_path,
            &self.active_file_identity,
            &self.identity,
        )
        .map_err(|message| self.release_failure(message))?;
        let retired = self
            .target_dir
            .join(format!("retired.{}.lease.json", self.identity.nonce));
        rename_d1_lease_no_replace(&self.active_path, &retired).map_err(|_| {
            self.release_failure("active lease could not be retired without replacement")
        })?;
        if sync_d1_lease_directory(&self.target_dir).is_err() {
            // A terminal record that has not survived the directory sync is not
            // sufficient authority to allow the next invocation. Put the same
            // evidence back at the active name while this invocation still
            // holds the guard; either way, the caller must reconcile rather
            // than starting a fresh provider apply.
            let restored = rename_d1_lease_no_replace(&retired, &self.active_path)
                .and_then(|()| sync_d1_lease_directory(&self.target_dir));
            let message = if restored.is_ok() {
                "retired lease directory could not be durably synchronized; active evidence was restored"
            } else {
                "retired lease directory could not be durably synchronized and active evidence could not be restored"
            };
            return Err(self.release_failure(message));
        }
        self.guard.take();
        Ok(())
    }

    fn release_failure(&self, message: &'static str) -> CallToolResult {
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest",
            "status": "reconciliation_required", "lease_retained": true, "lease": self.identity,
            "error": {"code": "d1.migration_lease_release_failed", "message": message,
                "hint": "Inspect the permanent target custody directory and reconcile the named owner before another apply."}
        }))
    }

    fn revalidation_failure(&self, message: &'static str) -> CallToolResult {
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest",
            "status": "reconciliation_required", "lease_retained": true, "lease": self.identity,
            "error": {"code": "d1.migration_lease_revalidation_failed", "message": message,
                "hint": "Do not issue provider SQL. Reconcile the permanent target custody evidence first."}
        }))
    }
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
        "active_evidence": "active.lease.json is never auto-reclaimed; malformed, symlink, non-regular, or otherwise present active evidence stops the next apply for reconciliation",
        "cross_host_limitation": "Cross-process serialization covers only hosts sharing the same configured operator-owned lease root. It is not a Cloudflare/provider-distributed lease.",
        "platform_requirement": "Unix with std::fs::File::try_lock support; unsupported platforms fail closed before provider I/O."
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
    let root = std::env::var(D1_MANIFEST_LEASE_ROOT_ENV).ok().map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty()).ok_or_else(|| CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest",
            "error": {"code": "d1.migration_lease_root_unconfigured", "message": "live migration apply requires a configured operator-owned shared lease root", "hint": format!("Set {D1_MANIFEST_LEASE_ROOT_ENV} to a pre-created private directory shared by all MCP processes that can target this D1 database.")}
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
    #[cfg(not(unix))]
    {
        let _ = (root, account_id, database_id, family, plan_sha256);
        Err(d1_lease_platform_unsupported())
    }
    #[cfg(unix)]
    {
        acquire_d1_migration_lease_at_unix(root, account_id, database_id, family, plan_sha256)
    }
}

fn d1_lease_platform_unsupported() -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required", "lease_retained": false,
        "error": {"code": "d1.migration_lease_platform_unsupported", "message": "permanent cross-process migration custody requires Unix file locking on this MCP build", "hint": "Use a supported Unix MCP installation; do not issue provider migration writes from this platform."}
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

#[cfg(unix)]
mod unix {
    use super::*;
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    const AT_FDCWD: i32 = -100;
    const RENAME_NOREPLACE: u32 = 1;
    unsafe extern "C" {
        fn geteuid() -> u32;
        fn renameat2(
            olddirfd: i32,
            oldpath: *const std::ffi::c_char,
            newdirfd: i32,
            newpath: *const std::ffi::c_char,
            flags: u32,
        ) -> i32;
    }
    fn current_effective_uid() -> u32 {
        unsafe { geteuid() }
    }
    fn file_identity(metadata: &fs::Metadata) -> Option<D1LeaseFileIdentity> {
        (!metadata.file_type().is_symlink() && metadata.is_file()).then_some(D1LeaseFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
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

    fn ensure_target_directory(root: &Path, target: &Path) -> Result<(), &'static str> {
        match fs::symlink_metadata(target) {
            Ok(meta) if private_dir(&meta) => {}
            Ok(_) => {
                return Err(
                    "target custody directory is not a private current-operator-owned directory",
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::create_dir(target) {
                    Ok(()) => {
                        fs::set_permissions(target, fs::Permissions::from_mode(0o700))
                            .map_err(|_| "target custody directory mode could not be set")?;
                        sync_d1_lease_directory(root).map_err(|_| "lease root could not be synchronized after target directory creation")?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err("target custody directory could not be created"),
                }
            }
            Err(_) => return Err("target custody directory is unavailable"),
        }
        let metadata = fs::symlink_metadata(target)
            .map_err(|_| "target custody directory is unavailable after creation")?;
        private_dir(&metadata)
            .then_some(())
            .ok_or("target custody directory is not a private current-operator-owned directory")
    }

    fn ensure_guard(target: &Path, guard_path: &Path) -> Result<fs::File, &'static str> {
        match fs::symlink_metadata(guard_path) {
            Ok(metadata) if private_file(&metadata) => {}
            Ok(_) => return Err("permanent target guard is not a private regular file"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut options = fs::OpenOptions::new();
                options.read(true).write(true).create_new(true).mode(0o600);
                match options.open(guard_path) {
                    Ok(file) => {
                        file.set_permissions(fs::Permissions::from_mode(0o600))
                            .map_err(|_| "permanent target guard mode could not be set")?;
                        file.sync_all()
                            .map_err(|_| "permanent target guard could not be synchronized")?;
                        sync_d1_lease_directory(target)
                            .map_err(|_| "target custody directory could not be synchronized")?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err("permanent target guard could not be created"),
                }
            }
            Err(_) => return Err("permanent target guard is unavailable"),
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(guard_path)
            .map_err(|_| "permanent target guard could not be opened")?;
        let held = file
            .metadata()
            .map_err(|_| "permanent target guard metadata is unavailable")?;
        let by_path = fs::symlink_metadata(guard_path)
            .map_err(|_| "permanent target guard pathname is unavailable")?;
        if !private_file(&held)
            || !private_file(&by_path)
            || file_identity(&held) != file_identity(&by_path)
        {
            return Err("permanent target guard changed or is not a private regular file");
        }
        Ok(file)
    }

    pub(super) fn validate_d1_lease_custody(
        root: &Path,
        target: &Path,
        guard_path: &Path,
        guard: &fs::File,
    ) -> Result<(), &'static str> {
        validate_root_and_ancestors(root)?;
        ensure_target_directory(root, target)?;
        let held = guard
            .metadata()
            .map_err(|_| "held permanent target guard metadata is unavailable")?;
        let by_path = fs::symlink_metadata(guard_path)
            .map_err(|_| "permanent target guard pathname is unavailable")?;
        if !private_file(&held)
            || !private_file(&by_path)
            || file_identity(&held) != file_identity(&by_path)
        {
            return Err("permanent target guard changed or is not a private regular file");
        }
        Ok(())
    }

    fn active_present_error(path: &Path, identity: &D1MigrationLeaseIdentity) -> CallToolResult {
        let valid = fs::symlink_metadata(path)
            .ok()
            .is_some_and(|meta| private_file(&meta))
            && fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .is_some_and(|v| v.is_object());
        let code = if valid {
            "d1.migration_target_lease_held"
        } else {
            "d1.migration_target_lease_unreconciled"
        };
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest", "status": if valid { "lease_held" } else { "reconciliation_required" }, "lease_retained": true,
            "lease": {"target_key_sha256": &identity.target_key_sha256, "ownership": "active_or_unreadable"},
            "operator_handoff": "Reconcile the permanent active target lease and its terminal provider evidence before another apply. The MCP never auto-reclaims active evidence.",
            "error": {"code": code, "message": "this account/database target already has active migration custody evidence", "hint": "Do not run another migration family against this target until the active evidence is reconciled through the governed recovery path."}
        }))
    }

    pub(super) fn validate_owned_active_lease(
        path: &Path,
        expected_file: &D1LeaseFileIdentity,
        expected: &D1MigrationLeaseIdentity,
    ) -> Result<(), &'static str> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| "active lease file is unavailable")?;
        if !private_file(&metadata) || file_identity(&metadata).as_ref() != Some(expected_file) {
            return Err("active lease file no longer matches this invocation");
        }
        let bytes = fs::read(path).map_err(|_| "active lease file cannot be read")?;
        if sha256_bytes_hex(&bytes) != expected.payload_sha256 {
            return Err("active lease payload no longer matches this invocation");
        }
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| "active lease payload is no longer valid JSON")?;
        if value["version"] != json!(2)
            || value["target_key_sha256"] != json!(expected.target_key_sha256)
            || value["nonce"] != json!(expected.nonce)
            || value["approved_plan_sha256"].as_str().is_none()
        {
            return Err("active lease payload no longer matches this invocation");
        }
        Ok(())
    }

    fn abort_create(active: &Path, target: &Path, nonce: &str) -> bool {
        let destination = target.join(format!("aborted-create.{nonce}.lease.json"));
        rename_d1_lease_no_replace(active, &destination)
            .and_then(|()| sync_d1_lease_directory(target))
            .is_ok()
    }

    fn create_failure(
        active: &Path,
        target: &Path,
        identity: &D1MigrationLeaseIdentity,
        code: &'static str,
        message: &'static str,
    ) -> CallToolResult {
        let aborted = abort_create(active, target, &identity.nonce);
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required", "lease_retained": !aborted, "lease": identity,
            "operator_handoff": if aborted { "Creation was terminally recorded as aborted; begin again only with a fresh dry-run plan." } else { "Creation may have left active evidence; reconcile the named custody entry before another apply." },
            "error": {"code": code, "message": message, "hint": "No provider write was attempted by this failed custody creation."}
        }))
    }

    fn create_active(
        root: &Path,
        target: &Path,
        guard_path: &Path,
        guard: &fs::File,
        identity: D1MigrationLeaseIdentity,
        payload: &[u8],
    ) -> Result<D1MigrationLease, CallToolResult> {
        validate_d1_lease_custody(root, target, guard_path, guard).map_err(|message| {
            d1_lease_root_error("d1.migration_lease_custody_changed", message)
        })?;
        let active = target.join("active.lease.json");
        if fs::symlink_metadata(&active).is_ok() {
            return Err(active_present_error(&active, &identity));
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = match options.open(&active) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(active_present_error(&active, &identity));
            }
            Err(_) => {
                return Err(CallToolResult::structured_error(
                    json!({"ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required", "lease_retained": false, "error": {"code": "d1.migration_lease_create_failed", "message": "active migration lease could not be created", "hint": "Inspect the permanent target custody directory before retrying."}}),
                ));
            }
        };
        let file_identity = match file.metadata().ok().and_then(|meta| file_identity(&meta)) {
            Some(id) => id,
            None => {
                return Err(create_failure(
                    &active,
                    target,
                    &identity,
                    "d1.migration_lease_create_identity_failed",
                    "active migration lease identity could not be established",
                ));
            }
        };
        if file
            .set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|()| file.write_all(payload))
            .and_then(|()| file.sync_all())
            .is_err()
        {
            return Err(create_failure(
                &active,
                target,
                &identity,
                "d1.migration_lease_create_write_failed",
                "active migration lease could not be durably written",
            ));
        }
        if sync_d1_lease_directory(target).is_err() {
            return Err(create_failure(
                &active,
                target,
                &identity,
                "d1.migration_lease_create_sync_failed",
                "active migration lease directory could not be durably synchronized",
            ));
        }
        if validate_owned_active_lease(&active, &file_identity, &identity).is_err()
            || validate_d1_lease_custody(root, target, guard_path, guard).is_err()
        {
            return Err(create_failure(
                &active,
                target,
                &identity,
                "d1.migration_lease_create_readback_failed",
                "active migration lease could not be read back as this invocation's private regular evidence",
            ));
        }
        let guard = guard.try_clone().map_err(|_| {
            create_failure(
                &active,
                target,
                &identity,
                "d1.migration_lease_guard_clone_failed",
                "held target guard could not be preserved for the active lease",
            )
        })?;
        Ok(D1MigrationLease {
            root: root.to_path_buf(),
            target_dir: target.to_path_buf(),
            active_path: active,
            guard_path: guard_path.to_path_buf(),
            guard: Some(guard),
            identity,
            active_file_identity: file_identity,
        })
    }

    pub(super) fn acquire_d1_migration_lease_at_unix(
        root: PathBuf,
        account_id: &str,
        database_id: &str,
        family: &str,
        plan_sha256: &str,
    ) -> Result<D1MigrationLease, CallToolResult> {
        validate_root_and_ancestors(&root)
            .map_err(|message| d1_lease_root_error("d1.migration_lease_root_unsafe", message))?;
        let target_hash = sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes());
        let target = root.join(format!("d1-migration-target-{target_hash}"));
        ensure_target_directory(&root, &target)
            .map_err(|message| d1_lease_root_error("d1.migration_lease_target_unsafe", message))?;
        let guard_path = target.join("guard.lock");
        let guard = ensure_guard(&target, &guard_path)
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
        validate_d1_lease_custody(&root, &target, &guard_path, &guard).map_err(|message| {
            d1_lease_root_error("d1.migration_lease_custody_changed", message)
        })?;
        maybe_pause_after_guard_for_test();
        let nonce = d1_migration_lease_nonce(&target_hash, plan_sha256);
        let payload = json!({"version": 2, "target_key_sha256": &target_hash, "nonce": &nonce, "approved_plan_sha256": plan_sha256.to_ascii_lowercase(), "migration_family": family, "created_at_unix_ms": now_unix_ms()});
        let encoded =
            serde_json::to_vec(&payload).expect("serializing lease payload is infallible");
        let identity = D1MigrationLeaseIdentity {
            target_key_sha256: target_hash,
            nonce,
            payload_sha256: sha256_bytes_hex(&encoded),
        };
        let result = create_active(&root, &target, &guard_path, &guard, identity, &encoded);
        drop(guard);
        result
    }

    pub(super) fn rename_d1_lease_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
        let source = CString::new(source.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in lease source path"))?;
        let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "NUL in lease destination path")
        })?;
        #[cfg(target_os = "linux")]
        {
            let result = unsafe {
                renameat2(
                    AT_FDCWD,
                    source.as_ptr(),
                    AT_FDCWD,
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
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (source, destination);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no-replace same-directory retirement requires Linux renameat2",
            ))
        }
    }
    pub(super) fn sync_d1_lease_directory(directory: &Path) -> io::Result<()> {
        #[cfg(test)]
        if FAIL_NEXT_DIRECTORY_SYNC.with(|fail| fail.replace(false)) {
            return Err(io::Error::other("forced directory sync failure"));
        }
        fs::File::open(directory)?.sync_all()
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
        entered: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    }
    #[cfg(test)]
    static GUARD_PAUSE_HOOK: OnceLock<Mutex<Option<GuardPauseHook>>> = OnceLock::new();
    #[cfg(test)]
    pub(super) fn install_guard_pause_hook(entered: mpsc::Sender<()>, resume: mpsc::Receiver<()>) {
        *GUARD_PAUSE_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("guard pause hook lock") = Some(GuardPauseHook { entered, resume });
    }
    #[cfg(test)]
    fn maybe_pause_after_guard_for_test() {
        if let Some(hook) = GUARD_PAUSE_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("guard pause hook lock")
            .take()
        {
            hook.entered.send(()).expect("guard pause test receiver");
            hook.resume.recv().expect("guard pause test release");
        }
    }
    #[cfg(not(test))]
    fn maybe_pause_after_guard_for_test() {}
}

#[cfg(unix)]
use unix::{
    acquire_d1_migration_lease_at_unix, rename_d1_lease_no_replace, sync_d1_lease_directory,
    validate_d1_lease_custody, validate_owned_active_lease,
};

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn held_permanent_guard_blocks_another_thread_before_active_creation() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::mpsc;
        let root = PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-d1-lease-race-{}-{}",
            std::process::id(),
            D1_MANIFEST_LEASE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create private root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        unix::install_guard_pause_hook(entered_tx, resume_rx);
        let first_root = root.clone();
        let first = std::thread::spawn(move || {
            acquire_d1_migration_lease_at(first_root, "acct-1", "db-1", "first", &"a".repeat(64))
        });
        entered_rx.recv().expect("first holds guard");
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

    #[cfg(unix)]
    #[test]
    fn failed_retirement_sync_restores_active_evidence_before_releasing_guard() {
        use std::os::unix::fs::PermissionsExt;
        let root = PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-d1-lease-release-{}-{}",
            std::process::id(),
            D1_MANIFEST_LEASE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create private root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "first", &"a".repeat(64))
                .expect("owner lease");
        unix::fail_next_directory_sync_for_test();
        let release = owner.release().expect_err("forced sync failure");
        assert_eq!(
            release.structured_content.expect("release error")["error"]["code"],
            json!("d1.migration_lease_release_failed")
        );
        assert!(
            owner
                .active_path_for_test()
                .expect("unix active path")
                .is_file(),
            "release uncertainty must leave active evidence for reconciliation"
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
}
