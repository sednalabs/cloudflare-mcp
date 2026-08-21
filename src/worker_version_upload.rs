use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::worker_upload::{
    WorkerUploadBody, WorkerUploadError, WorkerUploadInput, build_worker_upload,
};

const MAX_BINDINGS: usize = 256;

#[derive(Debug, Clone)]
pub(crate) struct WorkerVersionUploadArtifact {
    pub(crate) content_type: String,
    pub(crate) body: Vec<u8>,
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
    let metadata_value = input.metadata;
    let base_version_id = canonical_version_id(base_version_id).map_err(|message| {
        version_upload_error(
            "workers.version_upload_base_version_invalid",
            message,
            "Provide the exact canonical base version ID captured by workers_capture_version_evidence.",
        )
    })?;
    let metadata = metadata_value.as_object().ok_or_else(|| {
        version_upload_error(
            "workers.version_upload_metadata_invalid",
            "metadata must be a complete JSON object for a Worker version upload",
            "Provide the reviewed version metadata, including main_module and the complete binding plan.",
        )
    })?;
    let main_module = metadata
        .get("main_module")
        .and_then(Value::as_str)
        .and_then(canonical_nonempty)
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
        .is_some_and(|requested| requested != main_module)
    {
        return Err(version_upload_error(
            "workers.version_upload_main_module_conflict",
            "main_module argument conflicts with metadata.main_module",
            "Use one byte-identical main module identity in the reviewed metadata and module artifact.",
        ));
    }
    let (inherited_binding_count, explicit_binding_count) =
        validate_bindings(metadata_value, &base_version_id)?;
    let upload = build_worker_upload(WorkerUploadInput {
        main_module: Some(main_module),
        ..input
    })?;
    let metadata_bytes = serde_json::to_vec(metadata_value).map_err(|_| {
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
            validate_multipart_metadata(&content_type, &bytes, metadata_value, main_module)?;
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
        summary: WorkerVersionUploadSummary {
            source_kind,
            size_bytes: body_size_bytes,
            body_sha256,
            metadata_sha256,
            metadata_keys,
            main_module: main_module.to_string(),
            base_version_id,
            bindings_inherit: "strict",
            inherited_binding_count,
            explicit_binding_count,
            upload_contract_sha256,
        },
    })
}

fn validate_bindings(
    metadata: &Value,
    base_version_id: &str,
) -> Result<(usize, usize), WorkerUploadError> {
    let Some(bindings) = metadata.get("bindings") else {
        return Ok((0, 0));
    };
    let bindings = bindings.as_array().ok_or_else(|| {
        version_upload_error(
            "workers.version_upload_bindings_invalid",
            "metadata.bindings must be an array when present",
            "Provide the complete reviewed binding array for the version upload.",
        )
    })?;
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
    for binding in bindings {
        let binding = binding.as_object().ok_or_else(|| {
            version_upload_error(
                "workers.version_upload_binding_invalid",
                "every metadata.bindings entry must be an object",
                "Provide a complete typed binding object.",
            )
        })?;
        let name = binding
            .get("name")
            .and_then(Value::as_str)
            .and_then(canonical_nonempty)
            .ok_or_else(|| {
                version_upload_error(
                    "workers.version_upload_binding_invalid",
                    "every binding must have a canonical non-empty name",
                    "Correct the reviewed binding plan before upload.",
                )
            })?;
        if !names.insert(name.to_string()) {
            return Err(version_upload_error(
                "workers.version_upload_binding_duplicate",
                "metadata.bindings contains a duplicate binding name",
                "Each binding name must appear exactly once in the complete upload metadata.",
            ));
        }
        let binding_type = binding
            .get("type")
            .and_then(Value::as_str)
            .and_then(canonical_nonempty)
            .ok_or_else(|| {
                version_upload_error(
                    "workers.version_upload_binding_invalid",
                    "every binding must have a canonical non-empty type",
                    "Correct the reviewed binding plan before upload.",
                )
            })?;
        if binding_type == "inherit" {
            let inherited_from = binding
                .get("version_id")
                .and_then(Value::as_str)
                .and_then(canonical_nonempty)
                .ok_or_else(|| {
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
            inherited += 1;
        } else {
            if binding.contains_key("version_id") {
                return Err(version_upload_error(
                    "workers.version_upload_binding_invalid",
                    "only inherit bindings may contain version_id",
                    "Correct the reviewed binding plan before upload.",
                ));
            }
            explicit += 1;
        }
    }
    Ok((inherited, explicit))
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
    use serde_json::json;

    use super::build_worker_version_upload;
    use crate::worker_upload::WorkerUploadInput;

    const BASE: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn module_upload_is_deterministic_and_pins_exact_inherit_base() {
        let metadata = json!({
            "main_module": "index.js",
            "compatibility_date": "2026-07-10",
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
    fn implicit_latest_inheritance_fails_closed() {
        let metadata = json!({
            "main_module": "index.js",
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
}
