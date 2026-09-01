use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use md5::Md5;
use rmcp::model::CallToolResult;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::cloudflare::client::{CloudflareClient, D1ImportResult};
use crate::d1_migration_lease::preflight_d1_migration_target_custody;
use crate::d1_migration_manifest::validate_d1_manifest_write_result;

pub(crate) const D1_IMPORT_INPUT_ROOT_ENV: &str = "CLOUDFLARE_MCP_D1_IMPORT_INPUT_ROOT";
pub(crate) const D1_IMPORT_CUSTODY_ROOT_ENV: &str = "CLOUDFLARE_MCP_D1_IMPORT_CUSTODY_ROOT";
pub(crate) const D1_IMPORT_ADMISSION_TABLE: &str = "mcp_d1_import_attempt_admissions";
const MAX_IMPORT_BYTES: usize = 256 * 1024 * 1024;
const MAX_POLL_ATTEMPTS: usize = 60;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct D1AdmitSqlFileImportAttemptArgs {
    #[serde(default)]
    pub(crate) account_id: Option<String>,
    pub(crate) database_id: String,
    pub(crate) import_plan_sha256: String,
    pub(crate) execution_session_sha256: String,
    #[serde(default)]
    pub(crate) inventory_sha256: Option<String>,
    #[serde(default)]
    pub(crate) dry_run: bool,
    #[serde(default)]
    pub(crate) approved_request_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct D1ReadSqlFileImportAttemptAdmissionArgs {
    #[serde(default)]
    pub(crate) account_id: Option<String>,
    pub(crate) database_id: String,
    pub(crate) request_sha256: String,
    pub(crate) inventory_sha256: String,
    pub(crate) import_plan_sha256: String,
    pub(crate) execution_session_sha256: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct D1ImportSqlFileArgs {
    #[serde(default)]
    pub(crate) account_id: Option<String>,
    pub(crate) database_id: String,
    pub(crate) input_path: String,
    #[serde(default)]
    pub(crate) dry_run: bool,
    #[serde(default)]
    pub(crate) approved_plan_sha256: Option<String>,
    #[serde(default)]
    pub(crate) admission_request_sha256: Option<String>,
    #[serde(default)]
    pub(crate) inventory_sha256: Option<String>,
    #[serde(default)]
    pub(crate) import_plan_sha256: Option<String>,
    #[serde(default)]
    pub(crate) execution_session_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct D1ReconcileSqlFileImportArgs {
    #[serde(default)]
    pub(crate) account_id: Option<String>,
    pub(crate) database_id: String,
    pub(crate) approved_plan_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ImportHandoff {
    schema_version: u8,
    target_key_sha256: String,
    request_sha256: String,
    inventory_sha256: String,
    import_plan_sha256: String,
    execution_session_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ActiveImport {
    schema_version: u8,
    target_key_sha256: String,
    request_sha256: String,
    inventory_sha256: String,
    import_plan_sha256: String,
    execution_session_sha256: String,
    file_sha256: String,
    file_md5: String,
    content_plan_sha256: String,
    execution_plan_sha256: String,
    stage: ImportStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bookmark: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ImportStage {
    BeforeInit,
    InitAccepted,
    UploadAccepted,
    IngestAccepted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TerminalImport {
    schema_version: u8,
    target_key_sha256: String,
    request_sha256: String,
    inventory_sha256: String,
    import_plan_sha256: String,
    execution_session_sha256: String,
    file_sha256: String,
    content_plan_sha256: String,
    execution_plan_sha256: String,
    status: String,
}

struct ImportFile {
    bytes: Vec<u8>,
    sha256: String,
    md5: String,
}

struct CustodyGuard {
    directory: PathBuf,
    lock: File,
}

impl Drop for CustodyGuard {
    fn drop(&mut self) {
        unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN) };
    }
}

use std::os::fd::AsRawFd;

pub(crate) fn target_key_sha256(account_id: &str, database_id: &str) -> String {
    sha256_bytes(format!("d1-import-target-v1\0{account_id}\0{database_id}").as_bytes())
}

pub(crate) fn content_plan_sha256(
    account_id: &str,
    database_id: &str,
    file_sha256: &str,
    size_bytes: usize,
) -> String {
    digest_json(&json!({
        "contract": "d1-sql-file-content-plan-v1",
        "target_key_sha256": target_key_sha256(account_id, database_id),
        "file_sha256": file_sha256,
        "size_bytes": size_bytes,
    }))
}

fn request_sha256(target_key: &str, inventory_sha256: &str, import_plan_sha256: &str) -> String {
    digest_json(&json!({
        "contract": "d1-sql-file-import-admission-v1",
        "target_key_sha256": target_key,
        "inventory_sha256": inventory_sha256,
        "import_plan_sha256": import_plan_sha256,
    }))
}

fn execution_plan_sha256(handoff: &ImportHandoff, content_plan_sha256: &str) -> String {
    digest_json(&json!({
        "contract": "d1-sql-file-import-execution-v1",
        "target_key_sha256": handoff.target_key_sha256,
        "admission_request_sha256": handoff.request_sha256,
        "inventory_sha256": handoff.inventory_sha256,
        "import_plan_sha256": handoff.import_plan_sha256,
        "execution_session_sha256": handoff.execution_session_sha256,
        "content_plan_sha256": content_plan_sha256,
    }))
}

pub(crate) async fn admit_sql_file_import_attempt(
    client: &CloudflareClient,
    account_id: &str,
    args: &D1AdmitSqlFileImportAttemptArgs,
) -> CallToolResult {
    if let Err(result) = require_sha("import_plan_sha256", &args.import_plan_sha256)
        .and_then(|_| require_sha("execution_session_sha256", &args.execution_session_sha256))
    {
        return result;
    }
    let target_key = target_key_sha256(account_id, &args.database_id);
    let inventory_sha256 =
        match stable_inventory_sha256(client, account_id, &args.database_id).await {
            Ok(value) => value,
            Err(result) => return result,
        };
    if let Some(expected) = args.inventory_sha256.as_deref() {
        if let Err(result) = require_sha("inventory_sha256", expected) {
            return result;
        }
        if expected != inventory_sha256 {
            return import_error(
                "d1.import_inventory_mismatch",
                "current D1 inventory does not match the supplied inventory digest",
                2,
            );
        }
    }
    let request_sha256 = request_sha256(&target_key, &inventory_sha256, &args.import_plan_sha256);
    let base = json!({
        "ok": true,
        "operation": "d1_admit_sql_file_import_attempt",
        "target_key_sha256": target_key,
        "inventory_sha256": inventory_sha256,
        "import_plan_sha256": args.import_plan_sha256,
        "execution_session_sha256": args.execution_session_sha256,
        "request_sha256": request_sha256,
        "inventory_attestation": {"inventory_sha256": inventory_sha256},
    });
    if args.dry_run {
        return structured_with(
            base,
            json!({"status": "previewed", "dry_run": true, "provider_mutations": 0}),
        );
    }
    if args.approved_request_sha256.as_deref() != Some(request_sha256.as_str()) {
        return import_error(
            "d1.import_approval_mismatch",
            "live admission requires the exact request_sha256 returned by dry run",
            2,
        );
    }
    if let Err(result) = preflight_d1_migration_target_custody(account_id, &args.database_id) {
        return contextualize_foreign_custody(result, "d1_admit_sql_file_import_attempt");
    }
    let custody = match open_custody(account_id, &args.database_id) {
        Ok(value) => value,
        Err(result) => return result,
    };
    if custody_path(&custody, "active.json").exists() {
        return import_error(
            "d1.import_active",
            "an import is already active for this D1 target",
            0,
        );
    }
    let handoff = ImportHandoff {
        schema_version: 1,
        target_key_sha256: target_key,
        request_sha256: request_sha256.clone(),
        inventory_sha256: inventory_sha256.clone(),
        import_plan_sha256: args.import_plan_sha256.clone(),
        execution_session_sha256: args.execution_session_sha256.clone(),
    };
    match read_json::<ImportHandoff>(&custody_path(&custody, "handoff.json")) {
        Ok(Some(existing)) if existing == handoff => {}
        Ok(Some(_)) => {
            return import_error(
                "d1.import_handoff_conflict",
                "retained import handoff custody conflicts with this admission",
                0,
            );
        }
        Ok(None) => {
            if let Err(result) =
                write_json_exclusive(&custody_path(&custody, "handoff.json"), &handoff)
            {
                return result;
            }
        }
        Err(result) => return result,
    }
    let readback = read_admission(client, account_id, &args.database_id, &handoff).await;
    if matches!(readback, AdmissionRead::Exact) {
        return structured_with(
            base,
            json!({"status": "exact_replay_converged", "dry_run": false, "provider_mutations": 0}),
        );
    }
    match readback {
        AdmissionRead::Conflict => {
            return reconciliation_required(
                "d1.import_admission_conflict",
                "the provider admission row conflicts with retained local custody",
                1,
            );
        }
        AdmissionRead::Unavailable => {
            return reconciliation_required(
                "d1.import_admission_read_unavailable",
                "provider admission state could not be proven before mutation",
                1,
            );
        }
        AdmissionRead::Exact | AdmissionRead::Absent => {}
    }
    let sql = format!(
        "INSERT INTO {D1_IMPORT_ADMISSION_TABLE} (request_sha256, target_key_sha256, inventory_sha256, import_plan_sha256, execution_session_sha256) VALUES (?, ?, ?, ?, ?)"
    );
    let params = [
        json!(handoff.request_sha256),
        json!(handoff.target_key_sha256),
        json!(handoff.inventory_sha256),
        json!(handoff.import_plan_sha256),
        json!(handoff.execution_session_sha256),
    ];
    let write = client
        .execute_d1_migration_manifest_write(account_id, &args.database_id, &sql, &params)
        .await;
    if write
        .as_ref()
        .ok()
        .is_none_or(|write| validate_d1_manifest_write_result(&write.result).is_err())
    {
        return match read_admission(client, account_id, &args.database_id, &handoff).await {
            AdmissionRead::Exact => structured_with(
                base,
                json!({"status": "exact_replay_converged", "dry_run": false, "provider_mutations": 1}),
            ),
            _ => reconciliation_required(
                "d1.import_admission_outcome_ambiguous",
                "provider admission outcome is ambiguous",
                2,
            ),
        };
    }
    match read_admission(client, account_id, &args.database_id, &handoff).await {
        AdmissionRead::Exact => structured_with(
            base,
            json!({"status": "admitted", "dry_run": false, "provider_mutations": 1}),
        ),
        AdmissionRead::Conflict => reconciliation_required(
            "d1.import_admission_conflict",
            "provider admission readback conflicts with retained local custody",
            2,
        ),
        AdmissionRead::Absent | AdmissionRead::Unavailable => reconciliation_required(
            "d1.import_admission_readback_missing",
            "provider admission write lacks exact readback",
            2,
        ),
    }
}

pub(crate) async fn read_sql_file_import_attempt_admission(
    client: &CloudflareClient,
    account_id: &str,
    args: &D1ReadSqlFileImportAttemptAdmissionArgs,
) -> CallToolResult {
    for (name, value) in [
        ("request_sha256", args.request_sha256.as_str()),
        ("inventory_sha256", args.inventory_sha256.as_str()),
        ("import_plan_sha256", args.import_plan_sha256.as_str()),
        (
            "execution_session_sha256",
            args.execution_session_sha256.as_str(),
        ),
    ] {
        if let Err(result) = require_sha(name, value) {
            return result;
        }
    }
    let handoff = ImportHandoff {
        schema_version: 1,
        target_key_sha256: target_key_sha256(account_id, &args.database_id),
        request_sha256: args.request_sha256.clone(),
        inventory_sha256: args.inventory_sha256.clone(),
        import_plan_sha256: args.import_plan_sha256.clone(),
        execution_session_sha256: args.execution_session_sha256.clone(),
    };
    match read_admission(client, account_id, &args.database_id, &handoff).await {
        AdmissionRead::Exact => CallToolResult::structured(json!({
            "ok": true, "operation": "d1_read_sql_file_import_attempt_admission",
            "status": "admitted_exact", "read_only": true, "provider_mutations": 0,
            "target_key_sha256": handoff.target_key_sha256,
            "request_sha256": handoff.request_sha256,
            "inventory_sha256": handoff.inventory_sha256,
            "import_plan_sha256": handoff.import_plan_sha256,
            "execution_session_sha256": handoff.execution_session_sha256,
        })),
        AdmissionRead::Conflict => import_error(
            "d1.import_admission_conflict",
            "provider admission row conflicts with the requested binding",
            1,
        ),
        AdmissionRead::Absent => import_error(
            "d1.import_admission_not_proven",
            "exact provider admission is absent",
            1,
        ),
        AdmissionRead::Unavailable => import_error(
            "d1.import_admission_read_unavailable",
            "provider admission state could not be proven",
            1,
        ),
    }
}

pub(crate) async fn import_sql_file(
    client: &CloudflareClient,
    account_id: &str,
    args: &D1ImportSqlFileArgs,
) -> CallToolResult {
    let file = match inspect_import_file(&args.input_path) {
        Ok(file) => file,
        Err(result) => return result,
    };
    let target_key = target_key_sha256(account_id, &args.database_id);
    let content_plan = content_plan_sha256(
        account_id,
        &args.database_id,
        &file.sha256,
        file.bytes.len(),
    );
    let binding = match import_binding(args) {
        Ok(value) => value,
        Err(result) => return result,
    };
    let Some((request, inventory, import_plan, session)) = binding else {
        if !args.dry_run {
            return import_error(
                "d1.import_binding_required",
                "live import requires the complete admission binding",
                0,
            );
        }
        return CallToolResult::structured(json!({
            "ok": true, "operation": "d1_import_sql_file", "status": "content_plan_previewed",
            "dry_run": true, "provider_mutations": 0, "target_key_sha256": target_key,
            "file_sha256": file.sha256, "size_bytes": file.bytes.len(), "import_plan_sha256": content_plan,
        }));
    };
    let handoff = ImportHandoff {
        schema_version: 1,
        target_key_sha256: target_key.clone(),
        request_sha256: request.to_string(),
        inventory_sha256: inventory.to_string(),
        import_plan_sha256: import_plan.to_string(),
        execution_session_sha256: session.to_string(),
    };
    let plan_sha256 = execution_plan_sha256(&handoff, &content_plan);
    let base = json!({
        "ok": true, "operation": "d1_import_sql_file", "target_key_sha256": target_key,
        "admission_request_sha256": request, "inventory_sha256": inventory,
        "import_plan_sha256": import_plan, "execution_session_sha256": session,
        "file_sha256": file.sha256, "content_plan_sha256": content_plan,
        "plan_sha256": plan_sha256,
    });
    if args.dry_run {
        return structured_with(
            base,
            json!({"status": "previewed", "dry_run": true, "provider_mutations": 0}),
        );
    }
    if args.approved_plan_sha256.as_deref() != Some(plan_sha256.as_str()) {
        return import_error(
            "d1.import_approval_mismatch",
            "live import requires the exact plan_sha256 returned by bound dry run",
            0,
        );
    }
    if let Err(result) = preflight_d1_migration_target_custody(account_id, &args.database_id) {
        return contextualize_foreign_custody(result, "d1_import_sql_file");
    }
    let custody = match open_custody(account_id, &args.database_id) {
        Ok(value) => value,
        Err(result) => return result,
    };
    let terminal_path = custody_path(&custody, &format!("terminal.{plan_sha256}.json"));
    match read_json::<TerminalImport>(&terminal_path) {
        Ok(Some(terminal))
            if terminal.execution_plan_sha256 == plan_sha256 && terminal.status == "complete" =>
        {
            return structured_with(
                base,
                json!({"status": "complete", "dry_run": false, "exact_replay": true, "provider_mutations": 0}),
            );
        }
        Ok(Some(_)) => {
            return import_error(
                "d1.import_terminal_conflict",
                "retained terminal receipt conflicts with the requested execution",
                0,
            );
        }
        Ok(None) => {}
        Err(result) => return result,
    }
    let handoff_path = custody_path(&custody, "handoff.json");
    let active_path = custody_path(&custody, "active.json");
    if active_path.exists() {
        return reconciliation_required(
            "d1.import_active",
            "retained active import custody requires reconciliation",
            0,
        );
    }
    match read_json::<ImportHandoff>(&handoff_path) {
        Ok(Some(existing)) if existing == handoff => {}
        Ok(Some(_)) => {
            return reconciliation_required(
                "d1.import_handoff_conflict",
                "retained import handoff conflicts with this execution",
                0,
            );
        }
        Ok(None) => {
            return reconciliation_required(
                "d1.import_handoff_absent",
                "live import has no retained admitted handoff custody",
                0,
            );
        }
        Err(result) => return result,
    }
    let mut active = ActiveImport {
        schema_version: 1,
        target_key_sha256: handoff.target_key_sha256.clone(),
        request_sha256: handoff.request_sha256.clone(),
        inventory_sha256: handoff.inventory_sha256.clone(),
        import_plan_sha256: handoff.import_plan_sha256.clone(),
        execution_session_sha256: handoff.execution_session_sha256.clone(),
        file_sha256: file.sha256.clone(),
        file_md5: file.md5.clone(),
        content_plan_sha256: content_plan.clone(),
        execution_plan_sha256: plan_sha256.clone(),
        stage: ImportStage::BeforeInit,
        filename: None,
        bookmark: None,
    };
    if let Err(result) = write_json_exclusive(&active_path, &active) {
        return result;
    }
    if let Err(error) = fs::remove_file(&handoff_path) {
        return reconciliation_required(
            "d1.import_handoff_retire_failed",
            &format!("active custody was created but handoff retirement failed: {error}"),
            0,
        );
    }
    if let Err(result) = persist_directory(&custody.directory) {
        return result;
    }
    let init = match client
        .begin_d1_sql_import(account_id, &args.database_id, &file.md5)
        .await
    {
        Ok(value) => value,
        Err(_) => {
            return reconciliation_required(
                "d1.import_init_ambiguous",
                "D1 import init outcome is ambiguous",
                1,
            );
        }
    };
    let (upload_url, filename) = match validate_init(&init) {
        Ok(value) => value,
        Err(result) => return result,
    };
    active.stage = ImportStage::InitAccepted;
    active.filename = Some(filename.clone());
    if let Err(result) = replace_json(&active_path, &active) {
        return result;
    }
    let uploaded_etag = match client.upload_d1_sql_import(&upload_url, file.bytes).await {
        Ok(value) => value,
        Err(_) => {
            return reconciliation_required(
                "d1.import_upload_ambiguous",
                "D1 import upload outcome is ambiguous",
                2,
            );
        }
    };
    if uploaded_etag != file.md5 {
        return reconciliation_required(
            "d1.import_upload_etag_mismatch",
            "D1 import upload ETag does not match the source MD5",
            2,
        );
    }
    active.stage = ImportStage::UploadAccepted;
    if let Err(result) = replace_json(&active_path, &active) {
        return result;
    }
    let ingest = match client
        .ingest_d1_sql_import(account_id, &args.database_id, &file.md5, &filename)
        .await
    {
        Ok(value) => value,
        Err(_) => {
            return reconciliation_required(
                "d1.import_ingest_ambiguous",
                "D1 import ingest outcome is ambiguous",
                3,
            );
        }
    };
    let bookmark = match validate_ingest(&ingest) {
        Ok(value) => value,
        Err(result) => return result,
    };
    active.stage = ImportStage::IngestAccepted;
    active.bookmark = Some(bookmark);
    if let Err(result) = replace_json(&active_path, &active) {
        return result;
    }
    finish_import(
        client,
        account_id,
        &args.database_id,
        &custody,
        active,
        base,
        3,
    )
    .await
}

pub(crate) async fn reconcile_sql_file_import(
    client: &CloudflareClient,
    account_id: &str,
    args: &D1ReconcileSqlFileImportArgs,
) -> CallToolResult {
    if let Err(result) = require_sha("approved_plan_sha256", &args.approved_plan_sha256) {
        return result;
    }
    let custody = match open_custody(account_id, &args.database_id) {
        Ok(value) => value,
        Err(result) => return result,
    };
    let terminal_path = custody_path(
        &custody,
        &format!("terminal.{}.json", args.approved_plan_sha256),
    );
    match read_json::<TerminalImport>(&terminal_path) {
        Ok(Some(terminal))
            if terminal.execution_plan_sha256 == args.approved_plan_sha256
                && terminal.status == "complete" =>
        {
            return terminal_result(&terminal, true, 0);
        }
        Ok(Some(_)) => {
            return import_error(
                "d1.import_terminal_conflict",
                "retained terminal receipt conflicts with the approved plan",
                0,
            );
        }
        Ok(None) => {}
        Err(result) => return result,
    }
    let active = match read_json::<ActiveImport>(&custody_path(&custody, "active.json")) {
        Ok(Some(value)) => value,
        Ok(None) => {
            return import_error(
                "d1.import_active_absent",
                "no active import custody exists for this target",
                0,
            );
        }
        Err(result) => return result,
    };
    if active.execution_plan_sha256 != args.approved_plan_sha256 {
        return import_error(
            "d1.import_active_conflict",
            "active import custody conflicts with the approved plan",
            0,
        );
    }
    if active.stage != ImportStage::IngestAccepted || active.bookmark.is_none() {
        return reconciliation_required(
            "d1.import_stage_not_pollable",
            "active import custody cannot be safely resumed by polling",
            0,
        );
    }
    let base = active_base(&active);
    finish_import(
        client,
        account_id,
        &args.database_id,
        &custody,
        active,
        base,
        0,
    )
    .await
}

async fn finish_import(
    client: &CloudflareClient,
    account_id: &str,
    database_id: &str,
    custody: &CustodyGuard,
    mut active: ActiveImport,
    base: Value,
    provider_calls: usize,
) -> CallToolResult {
    let mut calls = provider_calls;
    for _ in 0..MAX_POLL_ATTEMPTS {
        let bookmark = active
            .bookmark
            .as_deref()
            .expect("pollable stage has bookmark");
        let poll = match client
            .poll_d1_sql_import(account_id, database_id, bookmark)
            .await
        {
            Ok(value) => value,
            Err(_) => {
                return reconciliation_required(
                    "d1.import_poll_unavailable",
                    "D1 import terminal status is unavailable",
                    calls + 1,
                );
            }
        };
        calls += 1;
        if poll.error.as_deref().is_some_and(|value| !value.is_empty())
            || poll.status.as_deref() == Some("error")
            || !is_successful_import_result(&poll)
        {
            return reconciliation_required(
                "d1.import_provider_failed",
                "D1 import reported non-success terminal evidence",
                calls,
            );
        }
        if poll.status.as_deref() == Some("complete") {
            if poll.success != Some(true)
                || poll.result_type.as_deref() != Some("import")
                || !poll.result.as_ref().is_some_and(Value::is_object)
            {
                return reconciliation_required(
                    "d1.import_terminal_malformed",
                    "D1 import terminal result is incomplete or contradictory",
                    calls,
                );
            }
            let terminal = TerminalImport {
                schema_version: 1,
                target_key_sha256: active.target_key_sha256,
                request_sha256: active.request_sha256,
                inventory_sha256: active.inventory_sha256,
                import_plan_sha256: active.import_plan_sha256,
                execution_session_sha256: active.execution_session_sha256,
                file_sha256: active.file_sha256,
                content_plan_sha256: active.content_plan_sha256,
                execution_plan_sha256: active.execution_plan_sha256,
                status: "complete".to_string(),
            };
            let path = custody_path(
                custody,
                &format!("terminal.{}.json", terminal.execution_plan_sha256),
            );
            if let Err(result) = write_json_exclusive(&path, &terminal) {
                return result;
            }
            if fs::remove_file(custody_path(custody, "active.json")).is_err() {
                return reconciliation_required(
                    "d1.import_active_retire_failed",
                    "terminal receipt exists but active custody retirement failed",
                    calls,
                );
            }
            if let Err(result) = persist_directory(&custody.directory) {
                return result;
            }
            return structured_with(
                base,
                json!({"status": "complete", "dry_run": false, "exact_replay": false, "provider_calls": calls}),
            );
        }
        let next = match poll.at_bookmark.filter(|value| !value.is_empty()) {
            Some(value) => value,
            None => {
                return reconciliation_required(
                    "d1.import_poll_bookmark_missing",
                    "non-terminal D1 import poll omitted its next bookmark",
                    calls,
                );
            }
        };
        active.bookmark = Some(next);
        if let Err(result) = replace_json(&custody_path(custody, "active.json"), &active) {
            return result;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    reconciliation_required(
        "d1.import_poll_budget_exhausted",
        "D1 import did not reach terminal state within the bounded poll budget",
        calls,
    )
}

fn validate_init(result: &D1ImportResult) -> Result<(String, String), CallToolResult> {
    if result
        .error
        .as_deref()
        .is_some_and(|value| !value.is_empty())
        || !is_successful_import_result(result)
    {
        return Err(reconciliation_required(
            "d1.import_init_rejected",
            "D1 import init returned failure evidence",
            1,
        ));
    }
    let upload_url = result.upload_url.clone().filter(|value| !value.is_empty());
    let filename = result.filename.clone().filter(|value| !value.is_empty());
    match (upload_url, filename) {
        (Some(upload_url), Some(filename)) => Ok((upload_url, filename)),
        _ => Err(reconciliation_required(
            "d1.import_init_malformed",
            "D1 import init omitted upload authority",
            1,
        )),
    }
}

fn validate_ingest(result: &D1ImportResult) -> Result<String, CallToolResult> {
    if result
        .error
        .as_deref()
        .is_some_and(|value| !value.is_empty())
        || !is_successful_import_result(result)
    {
        return Err(reconciliation_required(
            "d1.import_ingest_rejected",
            "D1 import ingest returned failure evidence",
            3,
        ));
    }
    result
        .at_bookmark
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            reconciliation_required(
                "d1.import_ingest_malformed",
                "D1 import ingest omitted its bookmark",
                3,
            )
        })
}

fn is_successful_import_result(result: &D1ImportResult) -> bool {
    result.success == Some(true) && result.result_type.as_deref() == Some("import")
}

#[derive(Clone, Copy)]
enum AdmissionRead {
    Exact,
    Conflict,
    Absent,
    Unavailable,
}

async fn read_admission(
    client: &CloudflareClient,
    account_id: &str,
    database_id: &str,
    expected: &ImportHandoff,
) -> AdmissionRead {
    let sql = format!(
        "SELECT request_sha256, target_key_sha256, inventory_sha256, import_plan_sha256, execution_session_sha256 FROM {D1_IMPORT_ADMISSION_TABLE} WHERE request_sha256 = ?"
    );
    let value = match client
        .query_d1_database_read_only(
            account_id,
            database_id,
            &sql,
            &[json!(expected.request_sha256)],
        )
        .await
    {
        Ok(value) => value,
        Err(_) => return AdmissionRead::Unavailable,
    };
    let rows = match strict_d1_rows(&value) {
        Some(rows) => rows,
        None => return AdmissionRead::Unavailable,
    };
    if rows.is_empty() {
        return AdmissionRead::Absent;
    }
    if rows.len() != 1 {
        return AdmissionRead::Conflict;
    }
    let row = rows[0];
    let exact = row.get("request_sha256").and_then(Value::as_str)
        == Some(expected.request_sha256.as_str())
        && row.get("target_key_sha256").and_then(Value::as_str)
            == Some(expected.target_key_sha256.as_str())
        && row.get("inventory_sha256").and_then(Value::as_str)
            == Some(expected.inventory_sha256.as_str())
        && row.get("import_plan_sha256").and_then(Value::as_str)
            == Some(expected.import_plan_sha256.as_str())
        && row.get("execution_session_sha256").and_then(Value::as_str)
            == Some(expected.execution_session_sha256.as_str());
    if exact {
        AdmissionRead::Exact
    } else {
        AdmissionRead::Conflict
    }
}

fn strict_d1_rows(value: &Value) -> Option<Vec<&serde_json::Map<String, Value>>> {
    let result_sets = value.as_array()?;
    if result_sets.len() != 1 {
        return None;
    }
    let result_set = result_sets[0].as_object()?;
    let errors_empty = match result_set.get("errors") {
        None => true,
        Some(Value::Array(errors)) => errors.is_empty(),
        _ => false,
    };
    if result_set.get("success").and_then(Value::as_bool) != Some(true)
        || !errors_empty
        || result_set
            .get("meta")
            .and_then(Value::as_object)
            .and_then(|meta| meta.get("served_by_primary"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        return None;
    }
    result_set
        .get("results")?
        .as_array()?
        .iter()
        .map(Value::as_object)
        .collect()
}

async fn stable_inventory_sha256(
    client: &CloudflareClient,
    account_id: &str,
    database_id: &str,
) -> Result<String, CallToolResult> {
    let first = client
        .get_d1_database(account_id, database_id)
        .await
        .map_err(|_| {
            import_error(
                "d1.import_inventory_unavailable",
                "D1 inventory read is unavailable",
                1,
            )
        })?;
    let second = client
        .get_d1_database(account_id, database_id)
        .await
        .map_err(|_| {
            import_error(
                "d1.import_inventory_unavailable",
                "D1 inventory confirmation read is unavailable",
                2,
            )
        })?;
    let first = serde_json::to_value(first).map_err(|_| {
        import_error(
            "d1.import_inventory_malformed",
            "D1 inventory could not be canonicalized",
            2,
        )
    })?;
    let second = serde_json::to_value(second).map_err(|_| {
        import_error(
            "d1.import_inventory_malformed",
            "D1 inventory could not be canonicalized",
            2,
        )
    })?;
    if first != second || first.get("uuid").and_then(Value::as_str) != Some(database_id) {
        return Err(import_error(
            "d1.import_inventory_unstable",
            "D1 inventory identity was absent, mismatched, or changed between reads",
            2,
        ));
    }
    Ok(digest_json(&json!({
        "contract": "d1-sql-file-import-inventory-v1",
        "target_key_sha256": target_key_sha256(account_id, database_id),
        "inventory": first,
    })))
}

fn import_binding(
    args: &D1ImportSqlFileArgs,
) -> Result<Option<(&str, &str, &str, &str)>, CallToolResult> {
    let values = [
        args.admission_request_sha256.as_deref(),
        args.inventory_sha256.as_deref(),
        args.import_plan_sha256.as_deref(),
        args.execution_session_sha256.as_deref(),
    ];
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    if values.iter().any(Option::is_none) {
        return Err(import_error(
            "d1.import_binding_incomplete",
            "import binding fields must be supplied together",
            0,
        ));
    }
    let names = [
        "admission_request_sha256",
        "inventory_sha256",
        "import_plan_sha256",
        "execution_session_sha256",
    ];
    for (name, value) in names.into_iter().zip(values) {
        require_sha(name, value.expect("checked"))?;
    }
    Ok(Some((
        values[0].unwrap(),
        values[1].unwrap(),
        values[2].unwrap(),
        values[3].unwrap(),
    )))
}

fn inspect_import_file(input_path: &str) -> Result<ImportFile, CallToolResult> {
    let root = private_root(D1_IMPORT_INPUT_ROOT_ENV)?;
    let path = PathBuf::from(input_path);
    if !path.is_absolute() {
        return Err(import_error(
            "d1.import_input_path_invalid",
            "input_path must be absolute",
            0,
        ));
    }
    if fs::symlink_metadata(&path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(true)
    {
        return Err(import_error(
            "d1.import_input_path_unsafe",
            "input_path must exist and must not be a symlink",
            0,
        ));
    }
    let canonical = fs::canonicalize(&path).map_err(|_| {
        import_error(
            "d1.import_input_unavailable",
            "input file is unavailable",
            0,
        )
    })?;
    if !canonical.starts_with(&root) {
        return Err(import_error(
            "d1.import_input_outside_root",
            "input file is outside the configured private input root",
            0,
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&canonical)
        .map_err(|_| {
            import_error(
                "d1.import_input_unavailable",
                "input file could not be opened safely",
                0,
            )
        })?;
    let meta = file.metadata().map_err(|_| {
        import_error(
            "d1.import_input_unavailable",
            "input file metadata is unavailable",
            0,
        )
    })?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
    {
        return Err(import_error(
            "d1.import_input_unsafe",
            "input file must be owner-held, single-link, regular, and mode 0600 or stricter",
            0,
        ));
    }
    let mut bytes = Vec::with_capacity((meta.len() as usize).min(MAX_IMPORT_BYTES));
    std::io::Read::by_ref(&mut file)
        .take((MAX_IMPORT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            import_error(
                "d1.import_input_unavailable",
                "input file could not be read",
                0,
            )
        })?;
    if bytes.is_empty() || bytes.len() > MAX_IMPORT_BYTES {
        return Err(import_error(
            "d1.import_input_size_invalid",
            "input file must be non-empty and at most 256 MiB",
            0,
        ));
    }
    let sql = std::str::from_utf8(&bytes).map_err(|_| {
        import_error(
            "d1.import_input_not_utf8",
            "input file must contain valid UTF-8 SQL",
            0,
        )
    })?;
    if sql.as_bytes().contains(&0) {
        return Err(import_error(
            "d1.import_input_contains_nul",
            "input SQL must not contain NUL bytes",
            0,
        ));
    }
    if sql_mentions_reserved_import_admission(sql) {
        return Err(import_error(
            "d1.import_admission_relation_reserved",
            "SQL-file imports may not create or mutate the guarded import admission relation",
            0,
        ));
    }
    let sha256 = sha256_bytes(&bytes);
    let md5 = format!("{:x}", Md5::digest(&bytes));
    Ok(ImportFile { bytes, sha256, md5 })
}

fn open_custody(account_id: &str, database_id: &str) -> Result<CustodyGuard, CallToolResult> {
    let root = private_root(D1_IMPORT_CUSTODY_ROOT_ENV)?;
    let directory = root.join(target_key_sha256(account_id, database_id));
    if !directory.exists() {
        fs::create_dir(&directory).map_err(|_| {
            import_error(
                "d1.import_custody_create_failed",
                "import custody directory could not be created",
                0,
            )
        })?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(|_| {
            import_error(
                "d1.import_custody_create_failed",
                "import custody permissions could not be secured",
                0,
            )
        })?;
        persist_directory(&root)?;
    }
    validate_private_directory(&directory)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("guard.lock"))
        .map_err(|_| {
            import_error(
                "d1.import_custody_lock_failed",
                "import custody lock could not be opened",
                0,
            )
        })?;
    let lock_meta = lock.metadata().map_err(|_| {
        import_error(
            "d1.import_custody_lock_failed",
            "import custody lock metadata is unavailable",
            0,
        )
    })?;
    if !lock_meta.is_file()
        || lock_meta.nlink() != 1
        || lock_meta.uid() != unsafe { libc::geteuid() }
        || lock_meta.mode() & 0o077 != 0
    {
        return Err(import_error(
            "d1.import_custody_lock_unsafe",
            "import custody lock must be owner-held, single-link, regular, and mode 0600 or stricter",
            0,
        ));
    }
    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        return Err(import_error(
            "d1.import_custody_busy",
            "another process owns this D1 import target",
            0,
        ));
    }
    Ok(CustodyGuard { directory, lock })
}

fn private_root(env: &'static str) -> Result<PathBuf, CallToolResult> {
    let raw = std::env::var(env).map_err(|_| {
        import_error(
            "d1.import_private_root_unconfigured",
            "required private import root is not configured",
            0,
        )
    })?;
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(import_error(
            "d1.import_private_root_unsafe",
            "private import root must be absolute",
            0,
        ));
    }
    let configured_meta = fs::symlink_metadata(&path).map_err(|_| {
        import_error(
            "d1.import_private_root_unavailable",
            "private import root is unavailable",
            0,
        )
    })?;
    if configured_meta.file_type().is_symlink() {
        return Err(import_error(
            "d1.import_private_root_unsafe",
            "private import root must not be a symlink",
            0,
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|_| {
        import_error(
            "d1.import_private_root_unavailable",
            "private import root is unavailable",
            0,
        )
    })?;
    validate_private_directory(&canonical)?;
    Ok(canonical)
}

fn validate_private_directory(path: &Path) -> Result<(), CallToolResult> {
    let meta = fs::symlink_metadata(path).map_err(|_| {
        import_error(
            "d1.import_private_root_unavailable",
            "private import directory metadata is unavailable",
            0,
        )
    })?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
    {
        return Err(import_error(
            "d1.import_private_root_unsafe",
            "private import directories must be owner-held, non-symlink, and mode 0700 or stricter",
            0,
        ));
    }
    Ok(())
}

fn custody_path(custody: &CustodyGuard, name: &str) -> PathBuf {
    custody.directory.join(name)
}

fn read_json<T: for<'de> Deserialize<'de> + Serialize>(
    path: &Path,
) -> Result<Option<T>, CallToolResult> {
    if !path.exists() {
        return Ok(None);
    }
    let meta = fs::symlink_metadata(path).map_err(|_| {
        import_error(
            "d1.import_custody_unreadable",
            "retained import custody metadata is unavailable",
            0,
        )
    })?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.nlink() != 1
        || meta.mode() & 0o077 != 0
        || meta.len() > 64 * 1024
    {
        return Err(import_error(
            "d1.import_custody_malformed",
            "retained import custody has an unsafe physical shape",
            0,
        ));
    }
    let bytes = fs::read(path).map_err(|_| {
        import_error(
            "d1.import_custody_unreadable",
            "retained import custody could not be read",
            0,
        )
    })?;
    let value: T = serde_json::from_slice(&bytes).map_err(|_| {
        import_error(
            "d1.import_custody_malformed",
            "retained import custody is not exact canonical JSON",
            0,
        )
    })?;
    if canonical_json_bytes(&value)? != bytes {
        return Err(import_error(
            "d1.import_custody_malformed",
            "retained import custody is not exact canonical JSON",
            0,
        ));
    }
    Ok(Some(value))
}

fn write_json_exclusive<T: Serialize>(path: &Path, value: &T) -> Result<(), CallToolResult> {
    let bytes = canonical_json_bytes(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| {
            import_error(
                "d1.import_custody_conflict",
                "retained import custody already exists or could not be created",
                0,
            )
        })?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| {
            import_error(
                "d1.import_custody_write_failed",
                "retained import custody could not be persisted",
                0,
            )
        })?;
    persist_directory(path.parent().expect("custody path has parent"))
}

fn replace_json<T: Serialize>(path: &Path, value: &T) -> Result<(), CallToolResult> {
    let bytes = canonical_json_bytes(value)?;
    let tmp = path.with_extension("json.next");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)
        .map_err(|_| {
            import_error(
                "d1.import_custody_conflict",
                "temporary import custody already exists",
                0,
            )
        })?;
    if let Err(error) = file
        .write_all(&bytes)
        .and_then(|_| file.sync_all())
        .and_then(|_| fs::rename(&tmp, path))
    {
        let _ = fs::remove_file(&tmp);
        return Err(import_error(
            "d1.import_custody_write_failed",
            &format!("retained import custody could not be replaced: {error}"),
            0,
        ));
    }
    persist_directory(path.parent().expect("custody path has parent"))
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CallToolResult> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| {
        import_error(
            "d1.import_custody_encode_failed",
            "import custody could not be encoded",
            0,
        )
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn persist_directory(path: &Path) -> Result<(), CallToolResult> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| {
            import_error(
                "d1.import_custody_sync_failed",
                "import custody directory could not be synchronized",
                0,
            )
        })
}

fn active_base(active: &ActiveImport) -> Value {
    json!({
        "ok": true, "operation": "d1_import_sql_file", "target_key_sha256": active.target_key_sha256,
        "admission_request_sha256": active.request_sha256, "inventory_sha256": active.inventory_sha256,
        "import_plan_sha256": active.import_plan_sha256, "execution_session_sha256": active.execution_session_sha256,
        "file_sha256": active.file_sha256, "content_plan_sha256": active.content_plan_sha256,
        "plan_sha256": active.execution_plan_sha256,
    })
}

fn terminal_result(
    terminal: &TerminalImport,
    replay: bool,
    provider_calls: usize,
) -> CallToolResult {
    CallToolResult::structured(json!({
        "ok": true, "operation": "d1_import_sql_file", "status": "complete",
        "exact_replay": replay, "provider_calls": provider_calls,
        "target_key_sha256": terminal.target_key_sha256,
        "admission_request_sha256": terminal.request_sha256,
        "inventory_sha256": terminal.inventory_sha256,
        "import_plan_sha256": terminal.import_plan_sha256,
        "execution_session_sha256": terminal.execution_session_sha256,
        "file_sha256": terminal.file_sha256,
        "content_plan_sha256": terminal.content_plan_sha256,
        "plan_sha256": terminal.execution_plan_sha256,
    }))
}

fn require_sha(name: &str, value: &str) -> Result<(), CallToolResult> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(import_error(
            "d1.import_digest_invalid",
            &format!("{name} must be one exact lowercase SHA-256 digest"),
            0,
        ))
    }
}

fn digest_json(value: &Value) -> String {
    sha256_bytes(&serde_json::to_vec(value).expect("digest input is serializable"))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn structured_with(mut base: Value, additions: Value) -> CallToolResult {
    if let (Some(base), Some(additions)) = (base.as_object_mut(), additions.as_object()) {
        base.extend(additions.clone());
    }
    CallToolResult::structured(base)
}

fn import_error(code: &'static str, message: &str, provider_calls: usize) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false, "operation": "d1_sql_file_import", "provider_calls": provider_calls,
        "provider_mutations": 0,
        "error": {"code": code, "message": message, "hint": "Resolve this fail-closed boundary before another provider mutation."}
    }))
}

fn reconciliation_required(
    code: &'static str,
    message: &str,
    provider_calls: usize,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false, "operation": "d1_import_sql_file", "status": "reconciliation_required",
        "retry_decision": "do_not_retry_same_attempt", "custody_retained": true,
        "provider_calls": provider_calls,
        "error": {"code": code, "message": message, "hint": "Use d1_reconcile_sql_file_import with the exact approved plan; never repeat a provider mutation after ambiguity."}
    }))
}

fn contextualize_foreign_custody(
    _result: CallToolResult,
    operation: &'static str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false, "operation": operation, "provider_calls": 0,
        "error": {"code": "d1.import_foreign_custody_unavailable", "message": "existing migration custody could not be proven absent for this D1 target", "hint": "Configure and reconcile the shared migration custody root before importing."}
    }))
}

pub(crate) fn preflight_import_target_custody(
    account_id: &str,
    database_id: &str,
    operation: &'static str,
) -> Result<(), CallToolResult> {
    match std::env::var(D1_IMPORT_CUSTODY_ROOT_ENV) {
        Ok(value) if !value.trim().is_empty() => {}
        _ => return Ok(()),
    }
    let root = private_root(D1_IMPORT_CUSTODY_ROOT_ENV)?;
    let target = root.join(target_key_sha256(account_id, database_id));
    if !target.exists() {
        return Ok(());
    }
    validate_private_directory(&target)?;
    for name in ["handoff.json", "active.json"] {
        if target.join(name).exists() {
            return Err(CallToolResult::structured_error(json!({
                "ok": false, "operation": operation, "provider_calls": 0,
                "error": {"code": "d1.import_custody_active", "message": "D1 target has retained import handoff or active custody", "hint": "Complete or reconcile the import before another D1 writer."}
            })));
        }
    }
    Ok(())
}

pub(crate) fn sql_mentions_reserved_import_admission(sql: &str) -> bool {
    let lowered = strip_sql_literals_and_comments(sql).to_ascii_lowercase();
    lowered
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .any(|token| token == D1_IMPORT_ADMISSION_TABLE)
}

fn strip_sql_literals_and_comments(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\'' {
            out.push(' ');
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\'' {
                    index += 1;
                    if index < bytes.len() && bytes[index] == b'\'' {
                        index += 1;
                        continue;
                    }
                    break;
                }
                index += 1;
            }
        } else if bytes[index..].starts_with(b"--") {
            out.push(' ');
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes[index..].starts_with(b"/*") {
            out.push(' ');
            index += 2;
            while index + 1 < bytes.len() && !bytes[index..].starts_with(b"*/") {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
        } else {
            out.push(bytes[index] as char);
            index += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_relation_scan_ignores_literals_and_comments_but_catches_quoted_identifiers() {
        assert!(sql_mentions_reserved_import_admission(
            "INSERT INTO \"mcp_d1_import_attempt_admissions\" VALUES (1)"
        ));
        assert!(sql_mentions_reserved_import_admission(
            "UPDATE [mcp_d1_import_attempt_admissions] SET x=1"
        ));
        assert!(!sql_mentions_reserved_import_admission(
            "INSERT INTO x VALUES ('mcp_d1_import_attempt_admissions') -- mcp_d1_import_attempt_admissions"
        ));
    }

    #[test]
    fn request_identity_excludes_execution_session() {
        let target = "a".repeat(64);
        let inventory = "b".repeat(64);
        let plan = "c".repeat(64);
        let request = request_sha256(&target, &inventory, &plan);
        let first = ImportHandoff {
            schema_version: 1,
            target_key_sha256: target.clone(),
            request_sha256: request.clone(),
            inventory_sha256: inventory.clone(),
            import_plan_sha256: plan.clone(),
            execution_session_sha256: "d".repeat(64),
        };
        let second = ImportHandoff {
            execution_session_sha256: "e".repeat(64),
            ..first.clone()
        };
        assert_eq!(first.request_sha256, second.request_sha256);
        assert_ne!(
            execution_plan_sha256(&first, &"f".repeat(64)),
            execution_plan_sha256(&second, &"f".repeat(64))
        );
    }

    #[test]
    fn admission_read_requires_one_primary_success_result_set() {
        assert_eq!(
            strict_d1_rows(&json!([{
                "success": true,
                "errors": [],
                "results": [],
                "meta": {"served_by_primary": true}
            }]))
            .map(|rows| rows.len()),
            Some(0)
        );
        for malformed in [
            Value::Null,
            json!([]),
            json!([{"success": true, "results": [], "meta": {"served_by_primary": false}}]),
            json!([{"success": true, "results": [], "meta": {"served_by_primary": true}}, {"success": true, "results": [], "meta": {"served_by_primary": true}}]),
            json!([{"success": true, "errors": {}, "results": [], "meta": {"served_by_primary": true}}]),
        ] {
            assert!(strict_d1_rows(&malformed).is_none(), "{malformed}");
        }
    }
}
