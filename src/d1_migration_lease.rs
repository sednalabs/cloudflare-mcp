//! Durable, cross-process custody for exact-byte D1 migration applies.
//!
//! A target directory and its guard are permanent. `active.lease.json` is
//! evidence, not garbage: later processes stop for reconciliation when it is
//! present. This module deliberately owns no MCP registration or provider I/O.

#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Write;

use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::{Value, json};

use crate::tools::{invalid_argument_result, sha256_bytes_hex};
use crate::verification::now_unix_ms;

pub(crate) const D1_MANIFEST_LEASE_ROOT_ENV: &str = "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT";
static D1_MANIFEST_LEASE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

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
                "hint": "Inspect the permanent target custody directory and reconcile the named owner through w11990 before another apply."}
        }))
    }

    fn revalidation_failure(&self, message: &'static str) -> CallToolResult {
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest",
            "status": "reconciliation_required", "lease_retained": true, "lease": self.identity,
            "error": {"code": "d1.migration_lease_revalidation_failed", "message": message,
                "hint": "Do not issue provider SQL. Reconcile the permanent target custody evidence through w11990 first."}
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
        "active_evidence": "active.lease.json and transient retiring.lease.json are never auto-reclaimed; malformed, symlink, non-regular, or otherwise present active/retiring evidence stops the next apply for w11990 reconciliation",
        "cross_host_limitation": "Cross-process serialization covers only hosts sharing the same configured operator-owned lease root. It is not a Cloudflare/provider-distributed lease.",
        "platform_requirement": "Linux with dirfd-bound file locking and renameat2 support; unsupported platforms fail closed before provider I/O."
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
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
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

    fn active_present_error(
        target: &fs::File,
        identity: &D1MigrationLeaseIdentity,
    ) -> CallToolResult {
        let valid = active_is_private_json(target, ACTIVE_LEASE_NAME);
        let code = if valid {
            "d1.migration_target_lease_held"
        } else {
            "d1.migration_target_lease_unreconciled"
        };
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest", "status": if valid { "lease_held" } else { "reconciliation_required" }, "lease_retained": true,
            "lease": {"target_key_sha256": &identity.target_key_sha256, "ownership": "active_or_unreadable"},
            "operator_handoff": "Reconcile the permanent active target lease and its terminal provider evidence through w11990 before another apply. The MCP never auto-reclaims active evidence.",
            "error": {"code": code, "message": "this account/database target already has active migration custody evidence", "hint": "Do not run another migration family against this target until the active evidence is reconciled through the governed recovery path."}
        }))
    }

    fn retiring_present_error(identity: &D1MigrationLeaseIdentity) -> CallToolResult {
        CallToolResult::structured_error(json!({
            "ok": false, "operation": "d1_apply_migration_manifest", "status": "reconciliation_required", "lease_retained": true,
            "lease": {"target_key_sha256": &identity.target_key_sha256, "ownership": "retiring"},
            "operator_handoff": "A prior terminal retirement did not complete cleanly. Reconcile the permanent retiring evidence through w11990 before another apply.",
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

    fn rename_owned_lease_no_replace(
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

    fn abort_owned_active(
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

    fn restore_active_or_leave_blocker(
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
            "operator_handoff": if aborted { "Creation was terminally recorded as aborted; begin again only with a fresh dry-run plan." } else { "Creation may have left active or retiring evidence; reconcile the named custody entry through w11990 before another apply." },
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
            Ok(true) => return Err(active_present_error(&target, &identity)),
            Ok(false) => {}
            Err(message) => {
                return Err(d1_lease_root_error(
                    "d1.migration_lease_custody_changed",
                    message,
                ));
            }
        }
        match entry_present(&target, RETIRING_LEASE_NAME) {
            Ok(true) => return Err(retiring_present_error(&identity)),
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
                return Err(active_present_error(&target, &identity));
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
                "error": {"code": "d1.migration_lease_create_identity_failed", "message": "active migration lease identity could not be established", "hint": "Reconcile the active custody entry through w11990 before another apply."}
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

#[cfg(target_os = "linux")]
use linux::{
    acquire_d1_migration_lease_at_linux, sync_d1_lease_directory, validate_d1_lease_custody,
    validate_owned_named_lease,
};

#[cfg(test)]
mod tests {
    use super::*;

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
    #[test]
    fn held_permanent_guard_blocks_another_thread_before_active_creation() {
        use std::sync::mpsc;

        let root = private_test_root("race");
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        linux::install_guard_pause_hook(entered_tx, resume_rx);
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
            !active
                .parent()
                .expect("target parent")
                .join(RETIRING_LEASE_NAME)
                .exists(),
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
    fn second_release_is_inert_after_terminal_retirement() {
        let root = private_test_root("release-idempotent");
        let mut owner =
            acquire_d1_migration_lease_at(root.clone(), "acct-1", "db-1", "first", &"a".repeat(64))
                .expect("owner lease");
        owner.release().expect("first release");
        owner.release().expect("second release is inert");
        let target = owner
            .active_path_for_test()
            .expect("active path")
            .parent()
            .expect("target path")
            .to_path_buf();
        assert!(!target.join(ACTIVE_LEASE_NAME).exists());
        assert_eq!(
            fs::read_dir(&target)
                .expect("read target")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("retired."))
                .count(),
            1,
            "an inert second release must not create another terminal record"
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }
}
