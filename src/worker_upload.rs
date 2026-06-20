use std::fs;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub(crate) const MAX_WORKER_UPLOAD_BYTES: u64 = 25 * 1024 * 1024;

#[derive(Debug, Clone)]
pub(crate) enum WorkerUploadBody {
    Module {
        metadata: Value,
        module_name: String,
        file_name: String,
        content_type: String,
        bytes: Vec<u8>,
    },
    Multipart {
        content_type: String,
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct WorkerUploadRequest {
    pub(crate) summary: WorkerUploadSummary,
    pub(crate) body: WorkerUploadBody,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WorkerUploadSummary {
    pub(crate) source_kind: &'static str,
    pub(crate) source_label: String,
    pub(crate) main_module: Option<String>,
    pub(crate) content_type: String,
    pub(crate) size_bytes: usize,
    pub(crate) sha256: String,
    pub(crate) metadata_keys: Vec<String>,
    pub(crate) metadata_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct WorkerUploadInput<'a> {
    pub(crate) script_path: Option<&'a str>,
    pub(crate) script_content: Option<&'a str>,
    pub(crate) script_content_base64: Option<&'a str>,
    pub(crate) multipart_path: Option<&'a str>,
    pub(crate) main_module: Option<&'a str>,
    pub(crate) metadata: &'a Value,
    pub(crate) content_type: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WorkerUploadErrorPayload {
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) hint: &'static str,
}

#[derive(Debug, Clone)]
pub(crate) struct WorkerUploadError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) hint: &'static str,
}

impl WorkerUploadError {
    fn new(code: &'static str, message: impl Into<String>, hint: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            hint,
        }
    }

    pub(crate) fn payload(&self) -> WorkerUploadErrorPayload {
        WorkerUploadErrorPayload {
            code: self.code,
            message: self.message.clone(),
            hint: self.hint,
        }
    }
}

pub(crate) fn build_worker_upload(
    input: WorkerUploadInput<'_>,
) -> Result<WorkerUploadRequest, WorkerUploadError> {
    let source_count = [
        input.script_path,
        input.script_content,
        input.script_content_base64,
        input.multipart_path,
    ]
    .into_iter()
    .flatten()
    .filter(|value| !value.trim().is_empty())
    .count();
    if source_count != 1 {
        return Err(WorkerUploadError::new(
            "workers.upload_source_count_invalid",
            "provide exactly one of script_path, script_content, script_content_base64, or multipart_path",
            "Use script_path/script_content for a single module upload, or multipart_path for a Wrangler-generated multipart Worker bundle.",
        ));
    }

    if let Some(path) = input
        .multipart_path
        .filter(|value| !value.trim().is_empty())
    {
        return build_multipart_upload(path, input.content_type);
    }

    let main_module = input
        .main_module
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            input
                .script_path
                .and_then(|path| Path::new(path).file_name())
                .and_then(|value| value.to_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "index.js".to_string());
    validate_module_name(&main_module)?;

    let (source_kind, source_label, bytes) =
        if let Some(path) = input.script_path.filter(|value| !value.trim().is_empty()) {
            (
                "script_path",
                path.trim().to_string(),
                read_regular_file(path)?,
            )
        } else if let Some(content) = input.script_content {
            (
                "script_content",
                "inline script_content".to_string(),
                content.as_bytes().to_vec(),
            )
        } else if let Some(content) = input.script_content_base64 {
            (
                "script_content_base64",
                "inline script_content_base64".to_string(),
                BASE64_STANDARD.decode(content.trim()).map_err(|err| {
                    WorkerUploadError::new(
                        "workers.upload_base64_invalid",
                        format!("script_content_base64 is not valid base64: {err}"),
                        "Pass UTF-8 script_content or a valid base64-encoded Worker module.",
                    )
                })?,
            )
        } else {
            unreachable!("source_count already validated")
        };

    enforce_size(bytes.len() as u64)?;
    let metadata = module_metadata(input.metadata, &main_module)?;
    let metadata_value = Value::Object(metadata.clone());
    let metadata_keys = metadata.keys().cloned().collect::<Vec<_>>();
    let content_type = input
        .content_type
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("application/javascript+module")
        .to_string();

    Ok(WorkerUploadRequest {
        summary: WorkerUploadSummary {
            source_kind,
            source_label,
            main_module: Some(main_module.clone()),
            content_type: content_type.clone(),
            size_bytes: bytes.len(),
            sha256: sha256_hex(&bytes),
            metadata_keys,
            metadata_sha256: Some(sha256_hex(metadata_value.to_string().as_bytes())),
        },
        body: WorkerUploadBody::Module {
            metadata: metadata_value,
            module_name: main_module.clone(),
            file_name: main_module,
            content_type,
            bytes,
        },
    })
}

fn build_multipart_upload(
    path: &str,
    content_type: Option<&str>,
) -> Result<WorkerUploadRequest, WorkerUploadError> {
    let bytes = read_regular_file(path)?;
    enforce_size(bytes.len() as u64)?;
    let content_type = content_type
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| infer_multipart_content_type(&bytes))
        .ok_or_else(|| {
            WorkerUploadError::new(
                "workers.upload_multipart_boundary_missing",
                "multipart_path did not start with a recognizable multipart boundary and no content_type override was provided",
                "Provide a raw multipart Worker bundle that begins with --<boundary>, or pass content_type=\"multipart/form-data; boundary=<boundary>\".",
            )
        })?;

    Ok(WorkerUploadRequest {
        summary: WorkerUploadSummary {
            source_kind: "multipart_path",
            source_label: path.trim().to_string(),
            main_module: None,
            content_type: content_type.clone(),
            size_bytes: bytes.len(),
            sha256: sha256_hex(&bytes),
            metadata_keys: Vec::new(),
            metadata_sha256: None,
        },
        body: WorkerUploadBody::Multipart {
            content_type,
            bytes,
        },
    })
}

fn read_regular_file(path: &str) -> Result<Vec<u8>, WorkerUploadError> {
    let path = Path::new(path.trim());
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        WorkerUploadError::new(
            "workers.upload_file_metadata_failed",
            format!("failed reading Worker upload file metadata: {err}"),
            "Check the path and permissions, then retry.",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WorkerUploadError::new(
            "workers.upload_file_not_regular",
            "Worker upload path must be a regular file, not a directory or symlink",
            "Provide a checked-in build artifact or generated Worker bundle file.",
        ));
    }
    enforce_size(metadata.len())?;
    fs::read(path).map_err(|err| {
        WorkerUploadError::new(
            "workers.upload_file_read_failed",
            format!("failed reading Worker upload file: {err}"),
            "Check the path and permissions, then retry.",
        )
    })
}

fn enforce_size(size: u64) -> Result<(), WorkerUploadError> {
    if size == 0 {
        return Err(WorkerUploadError::new(
            "workers.upload_empty",
            "Worker upload body must not be empty",
            "Provide a non-empty Worker module or multipart bundle.",
        ));
    }
    if size > MAX_WORKER_UPLOAD_BYTES {
        return Err(WorkerUploadError::new(
            "workers.upload_too_large",
            format!(
                "Worker upload body is {size} bytes, above this MCP tool's {} byte safety limit",
                MAX_WORKER_UPLOAD_BYTES
            ),
            "Use a smaller Worker bundle or the documented Wrangler deploy path if Cloudflare accepts the larger artifact.",
        ));
    }
    Ok(())
}

fn validate_module_name(value: &str) -> Result<(), WorkerUploadError> {
    if value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(WorkerUploadError::new(
            "workers.upload_main_module_invalid",
            "main_module must be a relative module file name without empty, . or .. path segments",
            "Use a module name like index.js, worker.mjs, or src/index.js.",
        ));
    }
    Ok(())
}

fn module_metadata(
    metadata: &Value,
    main_module: &str,
) -> Result<Map<String, Value>, WorkerUploadError> {
    let mut object = match metadata {
        Value::Null => Map::new(),
        Value::Object(object) => object.clone(),
        _ => {
            return Err(WorkerUploadError::new(
                "workers.upload_metadata_invalid",
                "metadata must be a JSON object",
                "Pass metadata as an object accepted by Cloudflare's Worker module upload endpoint.",
            ));
        }
    };
    object.insert("main_module".to_string(), json!(main_module));
    Ok(object)
}

fn infer_multipart_content_type(bytes: &[u8]) -> Option<String> {
    let line_end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(bytes.len());
    let first_line = std::str::from_utf8(&bytes[..line_end])
        .ok()?
        .trim_end_matches('\r');
    let boundary = first_line.strip_prefix("--")?;
    if boundary.trim().is_empty() || boundary.contains('"') || boundary.contains(';') {
        return None;
    }
    Some(format!("multipart/form-data; boundary={boundary}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_single_module_upload_with_main_module_metadata() {
        let upload = build_worker_upload(WorkerUploadInput {
            script_path: None,
            script_content: Some("export default {};"),
            script_content_base64: None,
            multipart_path: None,
            main_module: Some("worker.js"),
            metadata: &json!({"compatibility_date": "2026-06-03"}),
            content_type: None,
        })
        .expect("upload");

        assert_eq!(upload.summary.source_kind, "script_content");
        assert_eq!(upload.summary.main_module.as_deref(), Some("worker.js"));
        assert_eq!(
            upload.summary.metadata_keys,
            vec!["compatibility_date".to_string(), "main_module".to_string()]
        );
        assert!(upload.summary.metadata_sha256.is_some());
    }

    #[test]
    fn rejects_ambiguous_sources() {
        let err = build_worker_upload(WorkerUploadInput {
            script_path: Some("worker.js"),
            script_content: Some("export default {};"),
            script_content_base64: None,
            multipart_path: None,
            main_module: None,
            metadata: &Value::Null,
            content_type: None,
        })
        .expect_err("ambiguous");
        assert_eq!(err.code, "workers.upload_source_count_invalid");
    }

    #[test]
    fn infers_multipart_content_type_from_first_boundary() {
        let content_type =
            infer_multipart_content_type(b"------formdata-worker-bundle\r\nContent-Disposition: form-data; name=\"metadata\"\r\n");
        assert_eq!(
            content_type.as_deref(),
            Some("multipart/form-data; boundary=----formdata-worker-bundle")
        );
    }
}
