//! One sensitive, bounded content/v2 GET. No body or provider error is model-visible.

use futures::StreamExt;
use reqwest::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;
use url::Url;

use super::client::{AdapterError, CloudflareClient};

const MAX_BYTES: usize = 10 * 1024 * 1024;
const MAX_DEADLINE: Duration = Duration::from_secs(15);

pub(super) fn content_error(code: &'static str) -> AdapterError {
    AdapterError::new(
        code,
        "Worker content read did not produce a verified private artifact",
        "Inspect the content-free error code; do not infer source or active-version equivalence.",
    )
}

pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

impl CloudflareClient {
    pub(crate) async fn get_worker_content(
        &self,
        account_id: &str,
        script_name: &str,
        acknowledge_private_source: bool,
        max_bytes: usize,
    ) -> Result<Value, AdapterError> {
        if !acknowledge_private_source {
            return Err(content_error("workers.content_acknowledgement_required"));
        }
        if !(1..=MAX_BYTES).contains(&max_bytes) {
            return Err(content_error("workers.content_limit_invalid"));
        }
        for target in [account_id, script_name] {
            if target.is_empty()
                || target.len() > 128
                || !target
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(content_error("workers.content_target_invalid"));
            }
        }
        let base = Url::parse(&self.cfg.api_base_url)
            .map_err(|_| content_error("workers.content_origin_denied"))?;
        let synthetic = base.scheme() == "http"
            && base.host_str().is_some_and(|host| {
                host.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            })
            && crate::config::worker_content_fixture_http_enabled();
        if !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path().trim_end_matches('/') != "/client/v4"
            || !(synthetic
                || (base.scheme() == "https"
                    && base.host_str() == Some("api.cloudflare.com")
                    && base.port_or_known_default() == Some(443)))
        {
            return Err(content_error("workers.content_origin_denied"));
        }
        // Validate and hold custody before attaching credentials or dispatching.
        let custody = custody::ContentCustody::open()?;
        let path = format!("/accounts/{account_id}/workers/scripts/{script_name}/content/v2");
        let token = self
            .bearer_token()
            .map_err(|_| content_error("workers.content_token_unavailable"))?;
        let deadline = self.cfg.request_timeout.min(MAX_DEADLINE);
        let result = tokio::time::timeout(deadline, async {
            let request = self
                .worker_version_http
                .get(self.endpoint(&path))
                .bearer_auth(token)
                .header(
                    ACCEPT,
                    "multipart/form-data, application/javascript, text/javascript, text/plain",
                )
                .header(ACCEPT_ENCODING, "identity")
                .build()
                .map_err(|_| content_error("workers.content_request_invalid"))?;
            let response = self
                .worker_version_http
                .execute(request)
                .await
                .map_err(|error| {
                    content_error(if error.is_timeout() {
                        "workers.content_timeout"
                    } else {
                        "workers.content_transport_failed"
                    })
                })?;
            if response.status().as_u16() != 200 {
                return Err(content_error(if response.status().is_redirection() {
                    "workers.content_redirect_denied"
                } else if matches!(response.status().as_u16(), 401 | 403) {
                    "workers.content_permission_denied"
                } else {
                    "workers.content_provider_rejected"
                }));
            }
            let headers = response.headers();
            if headers.get_all(CONTENT_ENCODING).iter().count() > 1
                || headers
                    .get(CONTENT_ENCODING)
                    .is_some_and(|value| value.as_bytes() != b"identity")
            {
                return Err(content_error("workers.content_encoding_unsupported"));
            }
            let length = match headers.get(CONTENT_LENGTH) {
                None => None,
                Some(value) => Some(
                    value
                        .to_str()
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .ok_or_else(|| content_error("workers.content_length_invalid"))?,
                ),
            };
            if headers.get_all(CONTENT_LENGTH).iter().count() > 1 {
                return Err(content_error("workers.content_length_invalid"));
            }
            if length.is_some_and(|length| length > max_bytes) {
                return Err(content_error("workers.content_over_cap"));
            }
            if headers.get_all(CONTENT_TYPE).iter().count() != 1 {
                return Err(content_error("workers.content_format_unsupported"));
            }
            let content_type = headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| content_error("workers.content_format_unsupported"))?
                .to_string();
            let mut bytes = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| content_error("workers.content_incomplete"))?;
                if bytes.len().saturating_add(chunk.len()) > max_bytes {
                    return Err(content_error("workers.content_over_cap"));
                }
                bytes.extend_from_slice(&chunk);
            }
            if length.is_some_and(|length| length != bytes.len()) {
                return Err(content_error("workers.content_incomplete"));
            }
            let (format, part_count) = validate_format(&content_type, &bytes)?;
            Ok((bytes, format, part_count))
        })
        .await
        .map_err(|_| content_error("workers.content_timeout"))??;
        let (bytes, format, part_count) = result;
        let artifact_name = custody.retain(&bytes, max_bytes)?;
        Ok(json!({
            "ok": true,
            "operation": "workers_get_script_content",
            "read_only": true,
            "provenance": if synthetic { "synthetic_http_fixture" } else { "cloudflare_api" },
            "endpoint": "/accounts/{account_id}/workers/scripts/{script_name}/content/v2",
            "target_sha256": digest(format!("{account_id}\0{script_name}").as_bytes()),
            "http_status": 200,
            "body_complete": true,
            "format": format,
            "part_count": part_count,
            "artifact": { "name": artifact_name, "size_bytes": bytes.len(), "sha256": digest(&bytes),
                "custody": "verified_private_file", "representation": "exact_response_body" },
            "source_generation": "unversioned_endpoint_content",
            "active_version_equivalence": "unverified",
            "syntax_validated": false,
            "max_bytes": max_bytes,
            "deadline_ms": deadline.as_millis(),
        }))
    }
}

fn validate_format(
    content_type: &str,
    bytes: &[u8],
) -> Result<(&'static str, usize), AdapterError> {
    let mut fields = content_type.split(';').map(str::trim);
    let media_type = fields.next().unwrap_or_default().to_ascii_lowercase();
    if matches!(
        media_type.as_str(),
        "application/javascript" | "text/javascript" | "text/plain"
    ) {
        if fields.any(|field| !field.eq_ignore_ascii_case("charset=utf-8")) {
            return Err(content_error("workers.content_format_unsupported"));
        }
        if bytes.is_empty() || bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
            return Err(content_error("workers.content_format_invalid"));
        }
        return Ok(("javascript_text", 1));
    }
    if media_type != "multipart/form-data" {
        return Err(content_error("workers.content_format_unsupported"));
    }
    let parameter = fields
        .next()
        .ok_or_else(|| content_error("workers.content_format_invalid"))?;
    let boundary_value = parameter.strip_prefix("boundary=").unwrap_or_default();
    let boundary = if boundary_value.starts_with('"') {
        boundary_value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or_default()
    } else {
        boundary_value
    };
    if fields.next().is_some()
        || boundary.is_empty()
        || boundary.len() > 70
        || !boundary
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=?".contains(&b))
    {
        return Err(content_error("workers.content_format_invalid"));
    }
    let delimiter = format!("--{boundary}");
    let mut rest = bytes
        .strip_prefix(delimiter.as_bytes())
        .ok_or_else(|| content_error("workers.content_format_invalid"))?;
    let marker = format!("\r\n{delimiter}");
    let mut count = 0;
    let mut part_names = std::collections::BTreeSet::new();
    loop {
        if rest == b"--\r\n" || rest == b"--" {
            return if count > 0 {
                Ok(("multipart_form_data", count))
            } else {
                Err(content_error("workers.content_format_invalid"))
            };
        }
        rest = rest
            .strip_prefix(b"\r\n")
            .ok_or_else(|| content_error("workers.content_format_invalid"))?;
        let header_end = rest
            .windows(4)
            .position(|v| v == b"\r\n\r\n")
            .filter(|end| *end <= 8192)
            .ok_or_else(|| content_error("workers.content_format_invalid"))?;
        let headers = std::str::from_utf8(&rest[..header_end])
            .map_err(|_| content_error("workers.content_format_invalid"))?;
        let mut disposition = false;
        let mut seen = std::collections::BTreeSet::new();
        for header in headers.split("\r\n") {
            let (name, value) = header
                .split_once(':')
                .ok_or_else(|| content_error("workers.content_format_invalid"))?;
            let name = name.to_ascii_lowercase();
            if !seen.insert(name.clone()) || value.bytes().any(|b| b < 32 && b != b'\t') {
                return Err(content_error("workers.content_format_invalid"));
            }
            match name.as_str() {
                "content-disposition" => {
                    let mut parameters = value.trim().split(';').map(str::trim);
                    if parameters.next() != Some("form-data") {
                        return Err(content_error("workers.content_format_invalid"));
                    }
                    let mut keys = std::collections::BTreeSet::new();
                    for parameter in parameters {
                        let (key, value) = parameter
                            .split_once('=')
                            .ok_or_else(|| content_error("workers.content_format_invalid"))?;
                        let value = value
                            .strip_prefix('"')
                            .and_then(|v| v.strip_suffix('"'))
                            .filter(|v| {
                                !v.is_empty()
                                    && !v.chars().any(|c| c.is_control() || c == '"' || c == '\\')
                            })
                            .ok_or_else(|| content_error("workers.content_format_invalid"))?;
                        if !matches!(key, "name" | "filename") || !keys.insert(key) {
                            return Err(content_error("workers.content_format_invalid"));
                        }
                        if key == "name" {
                            if !part_names.insert(value.to_string()) {
                                return Err(content_error("workers.content_format_invalid"));
                            }
                            disposition = true;
                        }
                    }
                }
                "content-type" => {
                    let media = value.trim().split(';').next().unwrap_or_default();
                    let valid_token = |v: &str| {
                        !v.is_empty()
                            && v.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b))
                    };
                    if !media
                        .split_once('/')
                        .is_some_and(|(a, b)| valid_token(a) && valid_token(b))
                    {
                        return Err(content_error("workers.content_format_invalid"));
                    }
                }
                _ => return Err(content_error("workers.content_format_unsupported")),
            }
        }
        if !disposition {
            return Err(content_error("workers.content_format_invalid"));
        }
        rest = &rest[header_end + 4..];
        let end = rest
            .windows(marker.len())
            .position(|v| v == marker.as_bytes())
            .ok_or_else(|| content_error("workers.content_format_invalid"))?;
        count += 1;
        if count > 256 {
            return Err(content_error("workers.content_format_invalid"));
        }
        rest = &rest[end + marker.len()..];
    }
}

#[cfg(target_os = "linux")]
mod custody;

#[cfg(not(target_os = "linux"))]
mod custody {
    use super::*;
    pub(super) struct ContentCustody;
    impl ContentCustody {
        pub(super) fn open() -> Result<Self, AdapterError> {
            Err(content_error("workers.content_platform_unsupported"))
        }
        pub(super) fn retain(&self, _: &[u8], _: usize) -> Result<String, AdapterError> {
            Err(content_error("workers.content_platform_unsupported"))
        }
    }
}
