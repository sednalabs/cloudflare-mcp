use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::worker_upload::{
    WorkerUploadBody, WorkerUploadError, WorkerUploadInput, build_worker_upload,
};

const MAX_BINDINGS: usize = 256;
const ALLOWED_VERSION_METADATA_FIELDS: [&str; 4] = [
    "bindings",
    "compatibility_date",
    "compatibility_flags",
    "main_module",
];

#[derive(Debug, Clone)]
pub(crate) struct WorkerVersionUploadArtifact {
    pub(crate) content_type: String,
    pub(crate) body: Vec<u8>,
    pub(crate) canonical_metadata: Value,
    pub(crate) summary: WorkerVersionUploadSummary,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WorkerVersionUploadSummary {
    pub(crate) source_kind: &'static str,
    pub(crate) size_bytes: usize,
    pub(crate) body_sha256: String,
    pub(crate) metadata_sha256: String,
    pub(crate) metadata_keys: Vec<String>,
    pub(crate) main_module: String,
    pub(crate) base_version_id: String,
    pub(crate) bindings_inherit: &'static str,
    pub(crate) inherited_binding_count: usize,
    pub(crate) explicit_binding_count: usize,
    pub(crate) upload_contract_sha256: String,
}

pub(crate) fn build_worker_version_upload(
    input: WorkerUploadInput<'_>,
    base_version_id: &str,
) -> Result<WorkerVersionUploadArtifact, WorkerUploadError> {
    let base_version_id = canonical_version_id(base_version_id).map_err(|message| {
        version_upload_error(
            "workers.version_upload_base_version_invalid",
            message,
            "Provide the exact canonical base version ID captured by workers_capture_version_evidence.",
        )
    })?;
    let metadata = input.metadata.as_object().ok_or_else(|| {
        version_upload_error(
            "workers.version_upload_metadata_invalid",
            "metadata must be a complete JSON object for a Worker version upload",
            "Provide the reviewed version metadata, including main_module and the complete binding plan.",
        )
    })?;
    let (canonical_metadata, inherited_binding_count, explicit_binding_count) =
        canonicalize_version_metadata(metadata, &base_version_id)?;
    let metadata = canonical_metadata
        .as_object()
        .expect("canonical version metadata is an object");
    let main_module = metadata
        .get("main_module")
        .and_then(Value::as_str)
        .and_then(canonical_nonempty)
        .map(str::to_string)
        .ok_or_else(|| {
            version_upload_error(
                "workers.version_upload_main_module_missing",
                "metadata.main_module must be a canonical non-empty string",
                "Version upload requires module syntax and an explicit main_module in the reviewed metadata.",
            )
        })?;
    if input
        .main_module
        .and_then(canonical_nonempty)
        .is_some_and(|requested| requested != main_module.as_str())
    {
        return Err(version_upload_error(
            "workers.version_upload_main_module_conflict",
            "main_module argument conflicts with metadata.main_module",
            "Use one byte-identical main module identity in the reviewed metadata and module artifact.",
        ));
    }
    let upload = build_worker_upload(WorkerUploadInput {
        script_path: input.script_path,
        script_content: input.script_content,
        script_content_base64: input.script_content_base64,
        multipart_path: input.multipart_path,
        main_module: Some(&main_module),
        metadata: &canonical_metadata,
        content_type: input.content_type,
    })?;
    let metadata_bytes = serde_json::to_vec(&canonical_metadata).map_err(|_| {
        version_upload_error(
            "workers.version_upload_metadata_invalid",
            "metadata could not be serialized canonically",
            "Provide a finite JSON metadata object.",
        )
    })?;
    let metadata_sha256 = sha256_hex(&metadata_bytes);
    let metadata_keys = metadata.keys().cloned().collect::<Vec<_>>();

    let (source_kind, content_type, body) = match upload.body {
        WorkerUploadBody::Module {
            module_name,
            file_name,
            content_type,
            bytes,
            ..
        } => {
            let boundary_seed = json!({
                "schema_version": 1,
                "metadata_sha256": metadata_sha256,
                "module_name": module_name,
                "module_sha256": sha256_hex(&bytes),
            });
            let boundary_digest = sha256_hex(
                &serde_json::to_vec(&boundary_seed).expect("finite version upload boundary seed"),
            );
            let boundary = format!("cfmcp-version-{}", &boundary_digest[..32]);
            let body = deterministic_module_multipart(
                &boundary,
                &metadata_bytes,
                &module_name,
                &file_name,
                &content_type,
                &bytes,
            );
            (
                "module",
                format!("multipart/form-data; boundary={boundary}"),
                body,
            )
        }
        WorkerUploadBody::Multipart {
            content_type,
            bytes,
        } => {
            validate_multipart_metadata(&content_type, &bytes, &canonical_metadata, &main_module)?;
            ("multipart", content_type, bytes)
        }
    };
    let body_sha256 = sha256_hex(&body);
    let body_size_bytes = body.len();
    let upload_contract = json!({
        "schema_version": 1,
        "base_version_id": base_version_id,
        "bindings_inherit": "strict",
        "content_type": content_type,
        "body_sha256": body_sha256,
        "body_size_bytes": body_size_bytes,
        "metadata_sha256": metadata_sha256,
        "main_module": main_module,
        "inherited_binding_count": inherited_binding_count,
        "explicit_binding_count": explicit_binding_count,
    });
    let upload_contract_sha256 =
        sha256_hex(&serde_json::to_vec(&upload_contract).expect("finite version upload contract"));

    Ok(WorkerVersionUploadArtifact {
        content_type,
        body,
        canonical_metadata,
        summary: WorkerVersionUploadSummary {
            source_kind,
            size_bytes: body_size_bytes,
            body_sha256,
            metadata_sha256,
            metadata_keys,
            main_module,
            base_version_id,
            bindings_inherit: "strict",
            inherited_binding_count,
            explicit_binding_count,
            upload_contract_sha256,
        },
    })
}

fn canonicalize_version_metadata(
    metadata: &Map<String, Value>,
    base_version_id: &str,
) -> Result<(Value, usize, usize), WorkerUploadError> {
    if metadata
        .keys()
        .any(|key| !ALLOWED_VERSION_METADATA_FIELDS.contains(&key.as_str()))
    {
        return Err(version_upload_error(
            "workers.version_upload_metadata_unknown_field",
            "metadata contained a field outside the closed guarded version-upload contract",
            "Provide only main_module, compatibility_date, compatibility_flags, and the complete bindings array.",
        ));
    }
    let main_module = metadata
        .get("main_module")
        .and_then(Value::as_str)
        .and_then(canonical_nonempty)
        .ok_or_else(|| {
            version_upload_error(
                "workers.version_upload_main_module_missing",
                "metadata.main_module must be a canonical non-empty string",
                "Provide the exact main module name used by the reviewed artifact.",
            )
        })?;
    let compatibility_date = metadata
        .get("compatibility_date")
        .and_then(Value::as_str)
        .filter(|value| canonical_compatibility_date(value))
        .ok_or_else(|| {
            version_upload_error(
                "workers.version_upload_compatibility_date_invalid",
                "metadata.compatibility_date must be a valid YYYY-MM-DD date",
                "Provide the exact reviewed Worker compatibility date.",
            )
        })?;
    let flags = metadata
        .get("compatibility_flags")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            version_upload_error(
                "workers.version_upload_compatibility_flags_invalid",
                "metadata.compatibility_flags must be a complete array",
                "Provide the complete reviewed compatibility flag set, using an empty array when none apply.",
            )
        })?;
    let mut flag_set = BTreeSet::new();
    for flag in flags {
        let flag = flag
            .as_str()
            .and_then(canonical_compatibility_flag)
            .ok_or_else(|| {
                version_upload_error(
                    "workers.version_upload_compatibility_flags_invalid",
                    "metadata.compatibility_flags contained a non-canonical flag",
                    "Use distinct non-empty ASCII compatibility flag names.",
                )
            })?;
        if !flag_set.insert(flag.to_string()) {
            return Err(version_upload_error(
                "workers.version_upload_compatibility_flags_duplicate",
                "metadata.compatibility_flags contained a duplicate flag",
                "Provide each reviewed compatibility flag exactly once.",
            ));
        }
    }
    let bindings = metadata
        .get("bindings")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            version_upload_error(
                "workers.version_upload_bindings_missing",
                "metadata.bindings must be a complete array",
                "Provide the complete reviewed binding plan, using an empty array only when the candidate truly has no bindings.",
            )
        })?;
    let mut canonical_metadata = Map::new();
    canonical_metadata.insert("bindings".to_string(), Value::Array(Vec::new()));
    canonical_metadata.insert(
        "compatibility_date".to_string(),
        Value::String(compatibility_date.to_string()),
    );
    canonical_metadata.insert(
        "compatibility_flags".to_string(),
        Value::Array(flag_set.into_iter().map(Value::String).collect()),
    );
    canonical_metadata.insert(
        "main_module".to_string(),
        Value::String(main_module.to_string()),
    );
    if bindings.len() > MAX_BINDINGS {
        return Err(version_upload_error(
            "workers.version_upload_bindings_over_cap",
            format!("metadata.bindings exceeds the {MAX_BINDINGS}-binding evidence cap"),
            "Reduce the binding plan or extend the bounded contract in a reviewed change.",
        ));
    }
    let mut names = BTreeSet::new();
    let mut inherited = 0usize;
    let mut explicit = 0usize;
    let mut canonical_bindings = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let binding = binding.as_object().ok_or_else(|| {
            version_upload_error(
                "workers.version_upload_binding_invalid",
                "every metadata.bindings entry must be an object",
                "Provide a complete typed binding object.",
            )
        })?;
        let canonical = canonicalize_binding(binding, Some(base_version_id))?;
        let name = canonical
            .get("name")
            .and_then(Value::as_str)
            .expect("canonical binding has a name");
        if !names.insert(name.to_string()) {
            return Err(version_upload_error(
                "workers.version_upload_binding_duplicate",
                "metadata.bindings contains a duplicate binding name",
                "Each binding name must appear exactly once in the complete upload metadata.",
            ));
        }
        let binding_type = canonical
            .get("type")
            .and_then(Value::as_str)
            .expect("canonical binding has a type");
        if binding_type == "inherit" {
            inherited += 1;
        } else {
            explicit += 1;
        }
        canonical_bindings.push(Value::Object(canonical));
    }
    canonical_metadata.insert("bindings".to_string(), Value::Array(canonical_bindings));
    Ok((Value::Object(canonical_metadata), inherited, explicit))
}

fn canonical_compatibility_flag(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    .then_some(value)
}

fn canonical_compatibility_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return false;
    }
    let number = |slice: &[u8]| {
        slice
            .iter()
            .fold(0u32, |value, byte| value * 10 + u32::from(byte - b'0'))
    };
    let year = number(&bytes[..4]);
    let month = number(&bytes[5..7]);
    let day = number(&bytes[8..]);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year != 0 && (1..=max_day).contains(&day)
}

pub(crate) fn canonicalize_provider_binding(
    binding: &Map<String, Value>,
) -> Result<Map<String, Value>, WorkerUploadError> {
    if binding.get("type").and_then(Value::as_str) == Some("inherit") {
        return Err(version_upload_error(
            "workers.version_binding_provider_inherit_unresolved",
            "provider version detail retained an inherit binding but this bounded ceremony has no captured recursive inheritance chain",
            "Capture a provider detail whose binding projection is fully materialized; implicit, latest, and unresolved provider inheritance cannot be proven.",
        ));
    }
    canonicalize_binding(binding, None)
}

fn canonicalize_binding(
    binding: &Map<String, Value>,
    upload_base_version_id: Option<&str>,
) -> Result<Map<String, Value>, WorkerUploadError> {
    let name = binding
        .get("name")
        .and_then(Value::as_str)
        .and_then(canonical_binding_name)
        .ok_or_else(binding_invalid)?;
    let binding_type = binding
        .get("type")
        .and_then(Value::as_str)
        .and_then(canonical_binding_type)
        .ok_or_else(binding_invalid)?;
    let mut canonical = Map::new();
    canonical.insert("name".to_string(), Value::String(name.to_string()));
    canonical.insert("type".to_string(), Value::String(binding_type.to_string()));

    match binding_type {
        "inherit" => {
            require_only_fields(binding, &["name", "type", "old_name", "version_id"])?;
            let base_version_id = upload_base_version_id.ok_or_else(|| {
                version_upload_error(
                    "workers.version_binding_provider_inherit_invalid",
                    "provider version detail contained an unresolved inherit binding",
                    "Treat the provider binding projection as malformed.",
                )
            })?;
            let inherited_from = required_nonempty_string(binding, "version_id").map_err(|_| {
                version_upload_error(
                    "workers.version_upload_inherit_base_missing",
                    "every inherit binding must name the exact base version_id",
                    "Never use implicit or explicit latest inheritance for a guarded version upload.",
                )
            })?;
            if inherited_from == "latest" || inherited_from != base_version_id {
                return Err(version_upload_error(
                    "workers.version_upload_inherit_base_mismatch",
                    "an inherit binding did not name the exact supplied base version",
                    "Set every inherit binding version_id to the exact reviewed base version ID.",
                ));
            }
            canonical.insert(
                "version_id".to_string(),
                Value::String(inherited_from.to_string()),
            );
            if let Some(old_name) = optional_nonempty_string(binding, "old_name")? {
                let old_name = canonical_binding_name(old_name).ok_or_else(binding_invalid)?;
                canonical.insert("old_name".to_string(), Value::String(old_name.to_string()));
            }
        }
        "d1" => {
            require_only_fields(binding, &["name", "type", "database_id", "id"])?;
            let database_id = optional_nonempty_string(binding, "database_id")?;
            let deprecated_id = optional_nonempty_string(binding, "id")?;
            let database_id = match (database_id, deprecated_id) {
                (Some(current), Some(deprecated)) if current == deprecated => current,
                (Some(_), Some(_)) => {
                    return Err(version_upload_error(
                        "workers.version_binding_alias_conflict",
                        "D1 binding database_id and deprecated id disagreed",
                        "Use one canonical database_id value.",
                    ));
                }
                (Some(current), None) => current,
                (None, Some(deprecated)) => deprecated,
                (None, None) => return Err(binding_invalid()),
            };
            canonical.insert(
                "database_id".to_string(),
                Value::String(database_id.to_string()),
            );
        }
        "ai_search" => {
            require_only_fields(binding, &["name", "type", "instance_name", "namespace"])?;
            insert_required_string(&mut canonical, binding, "instance_name")?;
            let namespace = optional_nonempty_string(binding, "namespace")?.unwrap_or("default");
            canonical.insert(
                "namespace".to_string(),
                Value::String(namespace.to_string()),
            );
        }
        "ai_search_namespace" => {
            require_only_fields(binding, &["name", "type", "namespace"])?;
            insert_required_string(&mut canonical, binding, "namespace")?;
        }
        "plain_text" | "secret_text" => {
            require_only_fields(binding, &["name", "type", "text"])?;
            insert_required_string_allow_empty(&mut canonical, binding, "text")?;
        }
        "json" => {
            require_only_fields(binding, &["name", "type", "json"])?;
            let value = binding.get("json").ok_or_else(binding_invalid)?;
            canonical.insert("json".to_string(), value.clone());
        }
        "service" => {
            require_only_fields(
                binding,
                &["name", "type", "service", "environment", "entrypoint"],
            )?;
            insert_required_string(&mut canonical, binding, "service")?;
            insert_optional_string(&mut canonical, binding, "environment")?;
            insert_optional_string(&mut canonical, binding, "entrypoint")?;
        }
        "r2_bucket" => {
            require_only_fields(binding, &["name", "type", "bucket_name", "jurisdiction"])?;
            insert_required_string(&mut canonical, binding, "bucket_name")?;
            if let Some(jurisdiction) = optional_nonempty_string(binding, "jurisdiction")? {
                if !matches!(jurisdiction, "eu" | "fedramp" | "fedramp-high") {
                    return Err(binding_invalid());
                }
                canonical.insert(
                    "jurisdiction".to_string(),
                    Value::String(jurisdiction.to_string()),
                );
            }
        }
        "queue" => canonicalize_one_string_field(binding, &mut canonical, "queue_name")?,
        "analytics_engine" => canonicalize_one_string_field(binding, &mut canonical, "dataset")?,
        "kv_namespace" => canonicalize_one_string_field(binding, &mut canonical, "namespace_id")?,
        "vectorize" => canonicalize_one_string_field(binding, &mut canonical, "index_name")?,
        "hyperdrive" => canonicalize_one_string_field(binding, &mut canonical, "id")?,
        "pipelines" => canonicalize_one_string_field(binding, &mut canonical, "pipeline")?,
        "mtls_certificate" => {
            canonicalize_one_string_field(binding, &mut canonical, "certificate_id")?
        }
        "messaging" => canonicalize_one_string_field(binding, &mut canonical, "namespace")?,
        "secrets_store_secret" => {
            require_only_fields(binding, &["name", "type", "secret_name", "store_id"])?;
            insert_required_string(&mut canonical, binding, "secret_name")?;
            insert_required_string(&mut canonical, binding, "store_id")?;
        }
        "ai" | "assets" | "browser" | "images" | "media" | "version_metadata" => {
            require_only_fields(binding, &["name", "type"])?;
        }
        _ => {
            return Err(version_upload_error(
                "workers.version_binding_type_unsupported",
                "binding type is outside the closed guarded version-upload projection",
                "Use a supported canonical binding or extend the projection in a reviewed change.",
            ));
        }
    }
    Ok(canonical)
}

fn canonicalize_one_string_field(
    binding: &Map<String, Value>,
    canonical: &mut Map<String, Value>,
    field: &'static str,
) -> Result<(), WorkerUploadError> {
    require_only_fields(binding, &["name", "type", field])?;
    insert_required_string(canonical, binding, field)
}

fn insert_required_string(
    canonical: &mut Map<String, Value>,
    binding: &Map<String, Value>,
    field: &'static str,
) -> Result<(), WorkerUploadError> {
    let value = required_nonempty_string(binding, field)?;
    canonical.insert(field.to_string(), Value::String(value.to_string()));
    Ok(())
}

fn insert_required_string_allow_empty(
    canonical: &mut Map<String, Value>,
    binding: &Map<String, Value>,
    field: &'static str,
) -> Result<(), WorkerUploadError> {
    let value = binding
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(binding_invalid)?;
    canonical.insert(field.to_string(), Value::String(value.to_string()));
    Ok(())
}

fn insert_optional_string(
    canonical: &mut Map<String, Value>,
    binding: &Map<String, Value>,
    field: &'static str,
) -> Result<(), WorkerUploadError> {
    if let Some(value) = optional_nonempty_string(binding, field)? {
        canonical.insert(field.to_string(), Value::String(value.to_string()));
    }
    Ok(())
}

fn required_nonempty_string<'a>(
    binding: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, WorkerUploadError> {
    optional_nonempty_string(binding, field)?.ok_or_else(binding_invalid)
}

fn optional_nonempty_string<'a>(
    binding: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, WorkerUploadError> {
    match binding.get(field) {
        None => Ok(None),
        Some(Value::String(value)) => canonical_nonempty(value)
            .map(Some)
            .ok_or_else(binding_invalid),
        Some(_) => Err(binding_invalid()),
    }
}

fn require_only_fields(
    binding: &Map<String, Value>,
    allowed: &[&str],
) -> Result<(), WorkerUploadError> {
    if binding.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(version_upload_error(
            "workers.version_binding_unknown_field",
            "binding contained a field outside its closed canonical projection",
            "Remove unknown fields or extend the projection in a reviewed change.",
        ));
    }
    Ok(())
}

fn canonical_binding_name(value: &str) -> Option<&str> {
    let mut bytes = value.bytes();
    let first = bytes.next()?;
    (value.len() <= 128
        && (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    .then_some(value)
}

fn canonical_binding_type(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
    .then_some(value)
}

fn binding_invalid() -> WorkerUploadError {
    version_upload_error(
        "workers.version_upload_binding_invalid",
        "binding did not match its closed canonical field and value contract",
        "Correct the reviewed binding plan before upload.",
    )
}

fn deterministic_module_multipart(
    boundary: &str,
    metadata: &[u8],
    module_name: &str,
    file_name: &str,
    module_content_type: &str,
    module: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(metadata.len() + module.len() + 512);
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"metadata\"\r\n");
    body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
    body.extend_from_slice(metadata);
    body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{module_name}\"; filename=\"{file_name}\"\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {module_content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(module);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

fn validate_multipart_metadata(
    content_type: &str,
    bytes: &[u8],
    expected_metadata: &Value,
    main_module: &str,
) -> Result<(), WorkerUploadError> {
    let boundary = content_type
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("boundary="))
        .map(|value| value.trim_matches('"'))
        .and_then(canonical_nonempty)
        .ok_or_else(|| {
            version_upload_error(
                "workers.version_upload_multipart_boundary_missing",
                "multipart content type omitted a canonical boundary",
                "Provide the exact reviewed multipart content type and artifact.",
            )
        })?;
    let delimiter = format!("--{boundary}").into_bytes();
    let mut metadata_parts = 0usize;
    let mut main_parts = 0usize;
    let mut cursor = 0usize;
    while let Some(relative) = find_bytes(&bytes[cursor..], &delimiter) {
        let start = cursor + relative + delimiter.len();
        if bytes.get(start..start + 2) == Some(b"--") {
            break;
        }
        let start = if bytes.get(start..start + 2) == Some(b"\r\n") {
            start + 2
        } else {
            return Err(version_upload_error(
                "workers.version_upload_multipart_invalid",
                "multipart boundary was not followed by CRLF",
                "Regenerate the reviewed multipart artifact with a standards-compliant builder.",
            ));
        };
        let header_end = find_bytes(&bytes[start..], b"\r\n\r\n")
            .map(|offset| start + offset)
            .ok_or_else(|| {
                version_upload_error(
                    "workers.version_upload_multipart_invalid",
                    "multipart part omitted the header terminator",
                    "Regenerate the reviewed multipart artifact.",
                )
            })?;
        let next_boundary = find_bytes(&bytes[header_end + 4..], &delimiter)
            .map(|offset| header_end + 4 + offset)
            .ok_or_else(|| {
                version_upload_error(
                    "workers.version_upload_multipart_invalid",
                    "multipart part was not terminated by the reviewed boundary",
                    "Regenerate the reviewed multipart artifact.",
                )
            })?;
        if next_boundary < 2 || bytes.get(next_boundary - 2..next_boundary) != Some(b"\r\n") {
            return Err(version_upload_error(
                "workers.version_upload_multipart_invalid",
                "multipart part body was not terminated by CRLF",
                "Regenerate the reviewed multipart artifact.",
            ));
        }
        let headers = std::str::from_utf8(&bytes[start..header_end]).map_err(|_| {
            version_upload_error(
                "workers.version_upload_multipart_invalid",
                "multipart headers were not valid UTF-8",
                "Regenerate the reviewed multipart artifact.",
            )
        })?;
        let name = multipart_part_name(headers)?;
        let body = &bytes[header_end + 4..next_boundary - 2];
        if name == "metadata" {
            metadata_parts += 1;
            let observed: Value = serde_json::from_slice(body).map_err(|_| {
                version_upload_error(
                    "workers.version_upload_multipart_metadata_invalid",
                    "multipart metadata part was not valid JSON",
                    "Regenerate the reviewed multipart artifact from the complete metadata.",
                )
            })?;
            if observed != *expected_metadata {
                return Err(version_upload_error(
                    "workers.version_upload_multipart_metadata_mismatch",
                    "multipart metadata did not match the separately reviewed metadata object",
                    "Use one exact metadata object for review, plan digest, and upload bytes.",
                ));
            }
        }
        if name == main_module {
            main_parts += 1;
        }
        cursor = next_boundary;
    }
    if metadata_parts != 1 || main_parts != 1 {
        return Err(version_upload_error(
            "workers.version_upload_multipart_parts_invalid",
            "multipart artifact must contain exactly one metadata part and one part named by metadata.main_module",
            "Regenerate the reviewed multipart artifact with the complete version metadata and module graph.",
        ));
    }
    Ok(())
}

fn multipart_part_name(headers: &str) -> Result<&str, WorkerUploadError> {
    let disposition = headers
        .split("\r\n")
        .find(|line| {
            line.to_ascii_lowercase()
                .starts_with("content-disposition:")
        })
        .ok_or_else(|| {
            version_upload_error(
                "workers.version_upload_multipart_invalid",
                "multipart part omitted Content-Disposition",
                "Regenerate the reviewed multipart artifact.",
            )
        })?;
    disposition
        .split(';')
        .map(str::trim)
        .find_map(|part| {
            part.strip_prefix("name=\"")
                .and_then(|value| value.strip_suffix('"'))
        })
        .and_then(canonical_nonempty)
        .ok_or_else(|| {
            version_upload_error(
                "workers.version_upload_multipart_invalid",
                "multipart Content-Disposition omitted a canonical quoted name",
                "Regenerate the reviewed multipart artifact.",
            )
        })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn canonical_nonempty(value: &str) -> Option<&str> {
    (!value.is_empty() && value.trim() == value).then_some(value)
}

fn canonical_version_id(value: &str) -> Result<String, &'static str> {
    let value = canonical_nonempty(value).ok_or("version ID must be non-empty and byte-exact")?;
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || ![8usize, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        || bytes.iter().enumerate().any(|(index, byte)| {
            ![8usize, 13, 18, 23].contains(&index)
                && !byte.is_ascii_digit()
                && !(b'a'..=b'f').contains(byte)
        })
    {
        return Err("version ID must be a canonical lowercase UUID");
    }
    Ok(value.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn version_upload_error(
    code: &'static str,
    message: impl Into<String>,
    hint: &'static str,
) -> WorkerUploadError {
    WorkerUploadError {
        code,
        message: message.into(),
        hint,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{build_worker_version_upload, canonicalize_provider_binding};
    use crate::worker_upload::WorkerUploadInput;

    const BASE: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn module_upload_is_deterministic_and_pins_exact_inherit_base() {
        let metadata = json!({
            "main_module": "index.js",
            "compatibility_date": "2026-07-10",
            "compatibility_flags": [],
            "bindings": [
                {"name":"DB","type":"inherit","version_id":BASE},
                {"name":"MODE","type":"plain_text","text":"disabled"}
            ]
        });
        let input = || WorkerUploadInput {
            script_path: None,
            script_content: Some("export default { fetch() { return new Response('ok') } }"),
            script_content_base64: None,
            multipart_path: None,
            main_module: Some("index.js"),
            metadata: &metadata,
            content_type: None,
        };
        let first = build_worker_version_upload(input(), BASE).expect("first");
        let second = build_worker_version_upload(input(), BASE).expect("second");
        assert_eq!(first.body, second.body);
        assert_eq!(first.summary.body_sha256, second.summary.body_sha256);
        assert_eq!(first.summary.inherited_binding_count, 1);
        assert_eq!(first.summary.explicit_binding_count, 1);
        assert_eq!(first.summary.bindings_inherit, "strict");
    }

    #[test]
    fn inline_and_base64_sources_produce_the_same_digest_only_request() {
        let metadata = json!({
            "main_module": "index.js",
            "compatibility_date": "2026-07-10",
            "compatibility_flags": [],
            "bindings": []
        });
        let build = |script_content, script_content_base64| {
            build_worker_version_upload(
                WorkerUploadInput {
                    script_path: None,
                    script_content,
                    script_content_base64,
                    multipart_path: None,
                    main_module: Some("index.js"),
                    metadata: &metadata,
                    content_type: None,
                },
                BASE,
            )
            .expect("version upload")
        };
        let inline = build(Some("export default {}"), None);
        let encoded = build(None, Some("ZXhwb3J0IGRlZmF1bHQge30="));
        assert_eq!(inline.body, encoded.body);
        assert_eq!(inline.summary.body_sha256, encoded.summary.body_sha256);
        assert_eq!(inline.summary.size_bytes, encoded.summary.size_bytes);
        assert_eq!(
            inline.summary.upload_contract_sha256,
            encoded.summary.upload_contract_sha256
        );
    }

    #[test]
    fn implicit_latest_inheritance_fails_closed() {
        let metadata = json!({
            "main_module": "index.js",
            "compatibility_date": "2026-07-10",
            "compatibility_flags": [],
            "bindings": [{"name":"DB","type":"inherit"}]
        });
        let error = build_worker_version_upload(
            WorkerUploadInput {
                script_path: None,
                script_content: Some("export default {}"),
                script_content_base64: None,
                multipart_path: None,
                main_module: Some("index.js"),
                metadata: &metadata,
                content_type: None,
            },
            BASE,
        )
        .expect_err("must fail");
        assert_eq!(error.code, "workers.version_upload_inherit_base_missing");
    }

    #[test]
    fn canonical_bindings_remain_exact_and_ai_search_default_is_explicit() {
        let metadata = json!({
            "main_module":"index.js",
            "compatibility_date": "2026-07-10",
            "compatibility_flags": [],
            "bindings":[
                {"name":"DB","type":"d1","database_id":"db-canonical"},
                {"name":"SEARCH","type":"ai_search","instance_name":"articles"}
            ]
        });
        let artifact = build_worker_version_upload(
            WorkerUploadInput {
                script_path: None,
                script_content: Some("export default {}"),
                script_content_base64: None,
                multipart_path: None,
                main_module: Some("index.js"),
                metadata: &metadata,
                content_type: None,
            },
            BASE,
        )
        .expect("canonical upload");
        assert_eq!(
            artifact.canonical_metadata["bindings"][0],
            json!({"name":"DB","type":"d1","database_id":"db-canonical"})
        );
        assert_eq!(
            artifact.canonical_metadata["bindings"][1],
            json!({
                "name":"SEARCH",
                "type":"ai_search",
                "instance_name":"articles",
                "namespace":"default"
            })
        );

        let omitted = json!({"name":"SEARCH","type":"ai_search","instance_name":"articles"});
        let explicit = json!({
            "name":"SEARCH",
            "type":"ai_search",
            "instance_name":"articles",
            "namespace":"default"
        });
        assert_eq!(
            canonicalize_provider_binding(omitted.as_object().expect("binding"))
                .expect("omitted default"),
            canonicalize_provider_binding(explicit.as_object().expect("binding"))
                .expect("explicit default")
        );
    }

    #[test]
    fn deprecated_d1_id_alias_normalizes_before_request_hashing() {
        let canonical_metadata = json!({
            "main_module":"index.js",
            "compatibility_date": "2026-07-10",
            "compatibility_flags": [],
            "bindings":[{"name":"DB","type":"d1","database_id":"db-1"}]
        });
        let deprecated_metadata = json!({
            "main_module":"index.js",
            "compatibility_date": "2026-07-10",
            "compatibility_flags": [],
            "bindings":[{"name":"DB","type":"d1","id":"db-1"}]
        });
        let build = |metadata: &Value| {
            build_worker_version_upload(
                WorkerUploadInput {
                    script_path: None,
                    script_content: Some("export default {}"),
                    script_content_base64: None,
                    multipart_path: None,
                    main_module: Some("index.js"),
                    metadata,
                    content_type: None,
                },
                BASE,
            )
            .expect("version upload")
        };
        let canonical = build(&canonical_metadata);
        let deprecated = build(&deprecated_metadata);
        assert_eq!(canonical.canonical_metadata, deprecated.canonical_metadata);
        assert_eq!(
            canonical.summary.metadata_sha256,
            deprecated.summary.metadata_sha256
        );
        assert_eq!(
            canonical.summary.body_sha256,
            deprecated.summary.body_sha256
        );
        assert_eq!(
            deprecated.canonical_metadata["bindings"][0],
            json!({"name":"DB","type":"d1","database_id":"db-1"})
        );

        let conflicting = json!({
            "main_module":"index.js",
            "compatibility_date": "2026-07-10",
            "compatibility_flags": [],
            "bindings":[{
                "name":"DB",
                "type":"d1",
                "database_id":"db-1",
                "id":"db-2"
            }]
        });
        let error = build_worker_version_upload(
            WorkerUploadInput {
                script_path: None,
                script_content: Some("export default {}"),
                script_content_base64: None,
                multipart_path: None,
                main_module: Some("index.js"),
                metadata: &conflicting,
                content_type: None,
            },
            BASE,
        )
        .expect_err("conflicting aliases must fail");
        assert_eq!(error.code, "workers.version_binding_alias_conflict");
    }

    #[test]
    fn unknown_binding_fields_fail_before_artifact_construction() {
        let metadata = json!({
            "main_module":"index.js",
            "compatibility_date": "2026-07-10",
            "compatibility_flags": [],
            "bindings":[{
                "name":"DB",
                "type":"d1",
                "database_id":"db-1",
                "unreviewed":"must-not-be-ignored"
            }]
        });
        let error = build_worker_version_upload(
            WorkerUploadInput {
                script_path: None,
                script_content: Some("export default {}"),
                script_content_base64: None,
                multipart_path: None,
                main_module: Some("index.js"),
                metadata: &metadata,
                content_type: None,
            },
            BASE,
        )
        .expect_err("unknown field must fail");
        assert_eq!(error.code, "workers.version_binding_unknown_field");
        assert!(
            !serde_json::to_string(&error.payload())
                .expect("serialize error")
                .contains("must-not-be-ignored")
        );
    }

    #[test]
    fn provider_normalization_preserves_semantic_drift() {
        let expected = json!({
            "name":"SEARCH",
            "type":"ai_search",
            "instance_name":"articles"
        });
        let drifted = json!({
            "name":"SEARCH",
            "type":"ai_search",
            "instance_name":"articles",
            "namespace":"tenant-a"
        });
        let expected = canonicalize_provider_binding(expected.as_object().expect("binding"))
            .expect("expected projection");
        let drifted = canonicalize_provider_binding(drifted.as_object().expect("binding"))
            .expect("drifted projection");
        assert_ne!(expected, drifted);
        assert_eq!(expected["namespace"], json!("default"));
        assert_eq!(drifted["namespace"], json!("tenant-a"));
    }

    #[test]
    fn metadata_contract_is_closed_and_requires_complete_runtime_and_bindings() {
        let build = |metadata: &Value| {
            build_worker_version_upload(
                WorkerUploadInput {
                    script_path: None,
                    script_content: Some("export default {}"),
                    script_content_base64: None,
                    multipart_path: None,
                    main_module: Some("index.js"),
                    metadata,
                    content_type: None,
                },
                BASE,
            )
        };
        for forbidden in [
            "annotations",
            "assets",
            "cache_options",
            "dependencies",
            "exports_reconciliation",
            "keep_assets",
            "limits",
            "logpush",
            "migrations",
            "observability",
            "placement",
            "tags",
            "tails",
            "usage_model",
        ] {
            let mut metadata = json!({
                "main_module":"index.js",
                "compatibility_date":"2026-07-10",
                "compatibility_flags":[],
                "bindings":[]
            });
            metadata[forbidden] = json!(true);
            let error = build(&metadata).expect_err("unknown metadata must fail");
            assert_eq!(error.code, "workers.version_upload_metadata_unknown_field");
        }

        for (missing, code) in [
            ("bindings", "workers.version_upload_bindings_missing"),
            (
                "compatibility_date",
                "workers.version_upload_compatibility_date_invalid",
            ),
            (
                "compatibility_flags",
                "workers.version_upload_compatibility_flags_invalid",
            ),
        ] {
            let mut metadata = json!({
                "main_module":"index.js",
                "compatibility_date":"2026-07-10",
                "compatibility_flags":[],
                "bindings":[]
            });
            metadata.as_object_mut().expect("metadata").remove(missing);
            assert_eq!(build(&metadata).expect_err("required").code, code);
        }
    }

    #[test]
    fn compatibility_flags_are_duplicate_free_and_canonicalized() {
        let metadata = json!({
            "main_module":"index.js",
            "compatibility_date":"2024-02-29",
            "compatibility_flags":["nodejs_compat","global_fetch_strictly_public"],
            "bindings":[]
        });
        let artifact = build_worker_version_upload(
            WorkerUploadInput {
                script_path: None,
                script_content: Some("export default {}"),
                script_content_base64: None,
                multipart_path: None,
                main_module: Some("index.js"),
                metadata: &metadata,
                content_type: None,
            },
            BASE,
        )
        .expect("canonical flags");
        assert_eq!(
            artifact.canonical_metadata["compatibility_flags"],
            json!(["global_fetch_strictly_public", "nodejs_compat"])
        );

        let duplicate = json!({
            "main_module":"index.js",
            "compatibility_date":"2026-07-10",
            "compatibility_flags":["nodejs_compat","nodejs_compat"],
            "bindings":[]
        });
        let error = build_worker_version_upload(
            WorkerUploadInput {
                script_path: None,
                script_content: Some("export default {}"),
                script_content_base64: None,
                multipart_path: None,
                main_module: Some("index.js"),
                metadata: &duplicate,
                content_type: None,
            },
            BASE,
        )
        .expect_err("duplicate flag");
        assert_eq!(
            error.code,
            "workers.version_upload_compatibility_flags_duplicate"
        );
    }
}
