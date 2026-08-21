//! Durable one-use authority for non-idempotent Worker version dispatches.
//!
//! This module owns local custody only. It never performs provider I/O. An
//! attempt namespace is permanent evidence: once prepared, every later
//! invocation must reconcile rather than reuse the reviewed provider POST.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const WORKER_VERSION_ATTEMPT_ROOT_ENV: &str =
    "CLOUDFLARE_MCP_WORKER_VERSION_ATTEMPT_ROOT";

const GUARD_NAME: &str = "guard.lock";
const PREPARED_NAME: &str = "prepared.json";
const DISPATCHED_NAME: &str = "dispatched.json";
const TERMINAL_NAME: &str = "terminal.json";
const MAX_RECEIPT_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct WorkerVersionAttemptInput<'a> {
    pub(crate) account_id: &'a str,
    pub(crate) script_name: &'a str,
    pub(crate) confirmation_token: &'a str,
    pub(crate) upload_contract_sha256: &'a str,
    pub(crate) base_version_id: &'a str,
    pub(crate) base_version_etag: &'a str,
    pub(crate) pre_upload_version_snapshot_sha256: &'a str,
    pub(crate) pre_upload_deployment_snapshot_sha256: &'a str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct WorkerVersionAttemptEvidence {
    pub(crate) attempt_key_sha256: String,
    pub(crate) authority_sha256: String,
    pub(crate) state: &'static str,
    pub(crate) reconciliation_only: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct WorkerVersionAttemptError {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
    pub(crate) hint: &'static str,
    pub(crate) evidence: Option<WorkerVersionAttemptEvidence>,
}

#[derive(Debug)]
pub(crate) struct WorkerVersionDispatchAttempt {
    attempt_dir: PathBuf,
    attempt_dir_handle: File,
    _root_guard: File,
    prepared: AttemptReceipt,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AttemptReceipt {
    version: u8,
    operation: String,
    attempt_key_sha256: String,
    authority_sha256: String,
    state: String,
    predecessor_receipt_sha256: Option<String>,
    terminal_outcome: Option<String>,
    response_artifact_sha256: Option<String>,
}

impl WorkerVersionAttemptInput<'_> {
    fn authority_sha256(&self) -> String {
        sha256_fields(&[
            "worker-version-dispatch-authority-v1",
            self.account_id,
            self.script_name,
            self.confirmation_token,
            self.upload_contract_sha256,
            self.base_version_id,
            self.base_version_etag,
            self.pre_upload_version_snapshot_sha256,
            self.pre_upload_deployment_snapshot_sha256,
        ])
    }

    fn attempt_key_sha256(&self) -> String {
        sha256_fields(&[
            "worker-version-dispatch-attempt-v1",
            self.account_id,
            self.script_name,
            self.confirmation_token,
        ])
    }
}

impl WorkerVersionDispatchAttempt {
    pub(crate) fn evidence(&self, state: &'static str) -> WorkerVersionAttemptEvidence {
        WorkerVersionAttemptEvidence {
            attempt_key_sha256: self.prepared.attempt_key_sha256.clone(),
            authority_sha256: self.prepared.authority_sha256.clone(),
            state,
            reconciliation_only: state != "absent",
        }
    }

    /// Persist and fsync the one-use consume before provider dispatch begins.
    pub(crate) fn consume_for_dispatch(
        &mut self,
    ) -> Result<WorkerVersionAttemptEvidence, WorkerVersionAttemptError> {
        let predecessor = receipt_sha256(&self.prepared)?;
        let dispatched = AttemptReceipt {
            version: 1,
            operation: "workers_upload_version".to_string(),
            attempt_key_sha256: self.prepared.attempt_key_sha256.clone(),
            authority_sha256: self.prepared.authority_sha256.clone(),
            state: "dispatched".to_string(),
            predecessor_receipt_sha256: Some(predecessor),
            terminal_outcome: None,
            response_artifact_sha256: None,
        };
        write_new_receipt(
            &self.attempt_dir,
            &self.attempt_dir_handle,
            DISPATCHED_NAME,
            &dispatched,
        )?;
        Ok(self.evidence("dispatched"))
    }

    pub(crate) fn mark_terminal(
        &mut self,
        terminal_outcome: &'static str,
        response_artifact_sha256: Option<&str>,
    ) -> Result<WorkerVersionAttemptEvidence, WorkerVersionAttemptError> {
        let dispatched = read_receipt(&self.attempt_dir, DISPATCHED_NAME)?;
        validate_receipt_link(&self.prepared, &dispatched, "dispatched")?;
        let predecessor = receipt_sha256(&dispatched)?;
        let terminal = AttemptReceipt {
            version: 1,
            operation: "workers_upload_version".to_string(),
            attempt_key_sha256: self.prepared.attempt_key_sha256.clone(),
            authority_sha256: self.prepared.authority_sha256.clone(),
            state: "terminal".to_string(),
            predecessor_receipt_sha256: Some(predecessor),
            terminal_outcome: Some(terminal_outcome.to_string()),
            response_artifact_sha256: response_artifact_sha256.map(str::to_string),
        };
        write_new_receipt(
            &self.attempt_dir,
            &self.attempt_dir_handle,
            TERMINAL_NAME,
            &terminal,
        )?;
        Ok(self.evidence("terminal"))
    }
}

pub(crate) fn prepare_worker_version_dispatch_attempt(
    input: &WorkerVersionAttemptInput<'_>,
) -> Result<WorkerVersionDispatchAttempt, WorkerVersionAttemptError> {
    let root = configured_attempt_root()?;
    prepare_worker_version_dispatch_attempt_at(&root, input)
}

/// Check permanent custody before any provider preflight. The actual create is
/// repeated after provider reads because only a successful local consume may
/// authorize dispatch; concurrent callers still converge at that create.
pub(crate) fn preflight_worker_version_dispatch_attempt(
    input: &WorkerVersionAttemptInput<'_>,
) -> Result<(), WorkerVersionAttemptError> {
    let root = configured_attempt_root()?;
    let _root = open_private_root(&root)?;
    let guard = open_or_create_private_file(&root, GUARD_NAME)?;
    try_lock_exclusive(&guard)?;
    let attempt_key_sha256 = input.attempt_key_sha256();
    let authority_sha256 = input.authority_sha256();
    let attempt_dir = root.join(&attempt_key_sha256);
    match fs::symlink_metadata(&attempt_dir) {
        Ok(_) => Err(inspect_existing_attempt(
            &attempt_dir,
            &attempt_key_sha256,
            &authority_sha256,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(custody_error(
            "attempt namespace presence could not be established safely",
        )),
    }
}

fn configured_attempt_root() -> Result<PathBuf, WorkerVersionAttemptError> {
    std::env::var_os(WORKER_VERSION_ATTEMPT_ROOT_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| error(
            "workers.version_upload_attempt_root_unconfigured",
            "live Worker version upload requires a configured operator-owned attempt root",
            "Set CLOUDFLARE_MCP_WORKER_VERSION_ATTEMPT_ROOT to a pre-created private directory shared by every MCP process that can upload Worker versions.",
        ))
}

pub(crate) fn prepare_worker_version_dispatch_attempt_at(
    root: &Path,
    input: &WorkerVersionAttemptInput<'_>,
) -> Result<WorkerVersionDispatchAttempt, WorkerVersionAttemptError> {
    let root_handle = open_private_root(root)?;
    let guard = open_or_create_private_file(root, GUARD_NAME)?;
    try_lock_exclusive(&guard)?;

    let attempt_key_sha256 = input.attempt_key_sha256();
    let authority_sha256 = input.authority_sha256();
    let attempt_dir = root.join(&attempt_key_sha256);
    match fs::create_dir(&attempt_dir) {
        Ok(()) => {
            fs::set_permissions(&attempt_dir, fs::Permissions::from_mode(0o700)).map_err(|_| {
                custody_error("new attempt directory permissions could not be fixed")
            })?;
            root_handle
                .sync_all()
                .map_err(|_| custody_error("attempt-root directory could not be synchronized"))?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(inspect_existing_attempt(
                &attempt_dir,
                &attempt_key_sha256,
                &authority_sha256,
            ));
        }
        Err(_) => {
            return Err(custody_error(
                "attempt directory could not be created exclusively",
            ));
        }
    }
    let attempt_dir_handle = open_private_directory(&attempt_dir)?;
    let prepared = AttemptReceipt {
        version: 1,
        operation: "workers_upload_version".to_string(),
        attempt_key_sha256,
        authority_sha256,
        state: "prepared".to_string(),
        predecessor_receipt_sha256: None,
        terminal_outcome: None,
        response_artifact_sha256: None,
    };
    if let Err(err) = write_new_receipt(&attempt_dir, &attempt_dir_handle, PREPARED_NAME, &prepared)
    {
        // The namespace remains permanent fail-closed evidence even when the
        // first receipt could not be completed.
        return Err(err);
    }
    Ok(WorkerVersionDispatchAttempt {
        attempt_dir,
        attempt_dir_handle,
        _root_guard: guard,
        prepared,
    })
}

fn inspect_existing_attempt(
    attempt_dir: &Path,
    expected_key: &str,
    expected_authority: &str,
) -> WorkerVersionAttemptError {
    let directory = match open_private_directory(attempt_dir) {
        Ok(directory) => directory,
        Err(error) => return error,
    };
    drop(directory);
    let names = match fs::read_dir(attempt_dir) {
        Ok(entries) => {
            let mut names = Vec::new();
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => {
                        return custody_error(
                            "existing attempt namespace could not be enumerated completely",
                        );
                    }
                };
                let name = match entry.file_name().into_string() {
                    Ok(name) => name,
                    Err(_) => {
                        return custody_error(
                            "existing attempt namespace contains a non-UTF-8 entry",
                        );
                    }
                };
                names.push(name);
            }
            names
        }
        Err(_) => return custody_error("existing attempt namespace could not be enumerated"),
    };
    if names.iter().any(|name| {
        !matches!(
            name.as_str(),
            PREPARED_NAME | DISPATCHED_NAME | TERMINAL_NAME
        )
    }) {
        return custody_error("existing attempt namespace contains an unexpected entry");
    }
    let prepared = match read_receipt(attempt_dir, PREPARED_NAME) {
        Ok(receipt) => receipt,
        Err(error) => return error,
    };
    if prepared.version != 1
        || prepared.operation != "workers_upload_version"
        || prepared.state != "prepared"
        || prepared.attempt_key_sha256 != expected_key
        || prepared.authority_sha256 != expected_authority
        || prepared.predecessor_receipt_sha256.is_some()
        || prepared.terminal_outcome.is_some()
        || prepared.response_artifact_sha256.is_some()
    {
        return custody_error("existing prepared receipt conflicts with the requested authority");
    }
    let mut state = "prepared";
    if attempt_dir.join(DISPATCHED_NAME).exists() {
        let dispatched = match read_receipt(attempt_dir, DISPATCHED_NAME) {
            Ok(receipt) => receipt,
            Err(error) => return error,
        };
        if let Err(error) = validate_receipt_link(&prepared, &dispatched, "dispatched") {
            return error;
        }
        state = "dispatched";
        if attempt_dir.join(TERMINAL_NAME).exists() {
            let terminal = match read_receipt(attempt_dir, TERMINAL_NAME) {
                Ok(receipt) => receipt,
                Err(error) => return error,
            };
            if let Err(error) = validate_receipt_link(&dispatched, &terminal, "terminal") {
                return error;
            }
            if terminal.terminal_outcome.as_deref().is_none_or(|outcome| {
                !matches!(
                    outcome,
                    "provider_response_received" | "provider_outcome_ambiguous_or_rejected"
                )
            }) {
                return custody_error("terminal attempt receipt has an invalid outcome");
            }
            if terminal
                .response_artifact_sha256
                .as_deref()
                .is_some_and(|digest| {
                    digest.len() != 64
                        || !digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
            {
                return custody_error("terminal attempt receipt has an invalid response digest");
            }
            state = "terminal";
        }
    } else if attempt_dir.join(TERMINAL_NAME).exists() {
        return custody_error("terminal receipt exists without dispatched authority");
    }
    WorkerVersionAttemptError {
        code: "workers.version_upload_attempt_reconciliation_required",
        message: "this reviewed Worker version dispatch attempt already has durable custody",
        hint: "Do not replay the provider POST. Use workers_reconcile_version_upload against the pinned pre-upload evidence.",
        evidence: Some(WorkerVersionAttemptEvidence {
            attempt_key_sha256: expected_key.to_string(),
            authority_sha256: expected_authority.to_string(),
            state,
            reconciliation_only: true,
        }),
    }
}

fn validate_receipt_link(
    predecessor: &AttemptReceipt,
    receipt: &AttemptReceipt,
    expected_state: &str,
) -> Result<(), WorkerVersionAttemptError> {
    if receipt.version != 1
        || receipt.operation != predecessor.operation
        || receipt.attempt_key_sha256 != predecessor.attempt_key_sha256
        || receipt.authority_sha256 != predecessor.authority_sha256
        || receipt.state != expected_state
        || receipt.predecessor_receipt_sha256.as_deref()
            != Some(receipt_sha256(predecessor)?.as_str())
    {
        return Err(custody_error(
            "attempt receipt chain is malformed or contradictory",
        ));
    }
    if expected_state == "dispatched"
        && (receipt.terminal_outcome.is_some() || receipt.response_artifact_sha256.is_some())
    {
        return Err(custody_error(
            "dispatched receipt contains terminal-only fields",
        ));
    }
    Ok(())
}

fn write_new_receipt(
    directory: &Path,
    directory_handle: &File,
    name: &str,
    receipt: &AttemptReceipt,
) -> Result<(), WorkerVersionAttemptError> {
    let bytes = canonical_receipt_bytes(receipt)?;
    let path = directory.join(name);
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(&path)
        .map_err(|_| custody_error("attempt receipt could not be created exclusively"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| custody_error("attempt receipt could not be durably synchronized"))?;
    let readback = read_receipt(directory, name)?;
    if &readback != receipt {
        return Err(custody_error(
            "attempt receipt readback changed after creation",
        ));
    }
    directory_handle
        .sync_all()
        .map_err(|_| custody_error("attempt directory could not be durably synchronized"))?;
    Ok(())
}

fn read_receipt(directory: &Path, name: &str) -> Result<AttemptReceipt, WorkerVersionAttemptError> {
    let path = directory.join(name);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .map_err(|_| custody_error("attempt receipt is absent or cannot be opened safely"))?;
    let metadata = file
        .metadata()
        .map_err(|_| custody_error("attempt receipt metadata is unavailable"))?;
    if !private_file(&metadata) || metadata.len() > MAX_RECEIPT_BYTES {
        return Err(custody_error(
            "attempt receipt is not one bounded private regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| custody_error("attempt receipt could not be read completely"))?;
    let receipt: AttemptReceipt = serde_json::from_slice(&bytes).map_err(|_| {
        custody_error("attempt receipt JSON is malformed or structurally unexpected")
    })?;
    if canonical_receipt_bytes(&receipt)? != bytes {
        return Err(custody_error("attempt receipt is not exact canonical JSON"));
    }
    Ok(receipt)
}

fn canonical_receipt_bytes(receipt: &AttemptReceipt) -> Result<Vec<u8>, WorkerVersionAttemptError> {
    let mut bytes = serde_json::to_vec(receipt)
        .map_err(|_| custody_error("attempt receipt could not be serialized canonically"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn receipt_sha256(receipt: &AttemptReceipt) -> Result<String, WorkerVersionAttemptError> {
    Ok(sha256_bytes(&canonical_receipt_bytes(receipt)?))
}

fn open_private_root(root: &Path) -> Result<File, WorkerVersionAttemptError> {
    if !root.is_absolute() {
        return Err(custody_error("attempt root must be an absolute path"));
    }
    let canonical = fs::canonicalize(root)
        .map_err(|_| custody_error("attempt root could not be resolved safely"))?;
    if canonical != root {
        return Err(custody_error(
            "attempt root contains a symlink, alias, or noncanonical component",
        ));
    }
    let directory = open_private_directory(root)?;
    Ok(directory)
}

fn open_private_directory(path: &Path) -> Result<File, WorkerVersionAttemptError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let directory = options
        .open(path)
        .map_err(|_| custody_error("attempt custody directory could not be opened safely"))?;
    let metadata = directory
        .metadata()
        .map_err(|_| custody_error("attempt custody directory metadata is unavailable"))?;
    if !private_directory(&metadata) {
        return Err(custody_error(
            "attempt custody directory is not private and operator-owned",
        ));
    }
    Ok(directory)
}

fn open_or_create_private_file(root: &Path, name: &str) -> Result<File, WorkerVersionAttemptError> {
    let path = root.join(name);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|_| custody_error("attempt-root guard could not be opened safely"))?;
    let metadata = file
        .metadata()
        .map_err(|_| custody_error("attempt-root guard metadata is unavailable"))?;
    if !private_file(&metadata) {
        return Err(custody_error(
            "attempt-root guard is not a private regular file",
        ));
    }
    Ok(file)
}

fn try_lock_exclusive(file: &File) -> Result<(), WorkerVersionAttemptError> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        Ok(())
    } else {
        Err(error(
            "workers.version_upload_attempt_guard_locked",
            "another Worker version attempt currently owns the shared custody guard",
            "Wait for that invocation to reach a durable result, then reconcile its exact attempt before any new provider POST.",
        ))
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

fn sha256_fields(fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn error(
    code: &'static str,
    message: &'static str,
    hint: &'static str,
) -> WorkerVersionAttemptError {
    WorkerVersionAttemptError {
        code,
        message,
        hint,
        evidence: None,
    }
}

fn custody_error(message: &'static str) -> WorkerVersionAttemptError {
    error(
        "workers.version_upload_attempt_custody_malformed",
        message,
        "Preserve the attempt namespace and reconcile its provider state; do not repair, delete, or replay it in place.",
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    fn root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cloudflare-mcp-worker-version-attempt-{label}-{}-{}",
            std::process::id(),
            sha256_fields(&[label, &format!("{:?}", std::thread::current().id())])
        ));
        fs::create_dir(&path).expect("create attempt test root");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private root");
        path
    }

    fn input<'a>() -> WorkerVersionAttemptInput<'a> {
        WorkerVersionAttemptInput {
            account_id: "account",
            script_name: "script",
            confirmation_token: "confirmation",
            upload_contract_sha256: "1",
            base_version_id: "base",
            base_version_etag: "2",
            pre_upload_version_snapshot_sha256: "3",
            pre_upload_deployment_snapshot_sha256: "4",
        }
    }

    #[test]
    fn attempt_is_one_use_across_dispatch_terminal_and_restart() {
        let root = root("lifecycle");
        let mut attempt =
            prepare_worker_version_dispatch_attempt_at(&root, &input()).expect("prepare attempt");
        assert_eq!(attempt.evidence("prepared").state, "prepared");
        assert_eq!(
            attempt.consume_for_dispatch().expect("dispatch").state,
            "dispatched"
        );
        assert_eq!(
            attempt
                .mark_terminal("provider_response_received", Some(&"a".repeat(64)))
                .expect("terminal")
                .state,
            "terminal"
        );
        drop(attempt);
        let replay = prepare_worker_version_dispatch_attempt_at(&root, &input())
            .expect_err("terminal replay must stop");
        assert_eq!(
            replay.code,
            "workers.version_upload_attempt_reconciliation_required"
        );
        assert_eq!(replay.evidence.expect("evidence").state, "terminal");
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn response_loss_after_dispatch_remains_reconciliation_only_after_restart() {
        let root = root("ambiguous");
        let mut attempt =
            prepare_worker_version_dispatch_attempt_at(&root, &input()).expect("prepare attempt");
        attempt.consume_for_dispatch().expect("dispatch");
        drop(attempt);
        let replay = prepare_worker_version_dispatch_attempt_at(&root, &input())
            .expect_err("dispatched replay must stop");
        assert_eq!(replay.evidence.expect("evidence").state, "dispatched");
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn prepared_restart_and_conflicting_or_malformed_custody_fail_closed() {
        let root = root("prepared");
        let attempt =
            prepare_worker_version_dispatch_attempt_at(&root, &input()).expect("prepare attempt");
        let attempt_dir = attempt.attempt_dir.clone();
        drop(attempt);
        let replay = prepare_worker_version_dispatch_attempt_at(&root, &input())
            .expect_err("prepared replay must stop");
        assert_eq!(replay.evidence.expect("evidence").state, "prepared");

        let prepared_path = attempt_dir.join(PREPARED_NAME);
        let mut receipt = read_receipt(&attempt_dir, PREPARED_NAME).expect("read prepared");
        receipt.authority_sha256 = "f".repeat(64);
        fs::write(
            &prepared_path,
            canonical_receipt_bytes(&receipt).expect("serialize"),
        )
        .expect("corrupt receipt");
        let conflict = prepare_worker_version_dispatch_attempt_at(&root, &input())
            .expect_err("conflicting custody must stop");
        assert_eq!(
            conflict.code,
            "workers.version_upload_attempt_custody_malformed"
        );
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn concurrent_invocations_create_exactly_one_prepared_authority() {
        let root = root("concurrent");
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let root = root.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    prepare_worker_version_dispatch_attempt_at(&root, &input())
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("join"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        fs::remove_dir_all(root).expect("remove test root");
    }
}
