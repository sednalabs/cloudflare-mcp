use std::collections::{BTreeMap, BTreeSet};

use futures::StreamExt;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::client::{AdapterError, CloudflareClient, decode_json_rejecting_duplicate_object_keys};
use crate::worker_version_upload::canonicalize_provider_binding;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_VERSION_IDS: usize = 4096;
const MAX_VERSION_PAGES: usize = MAX_VERSION_IDS + 1;
const MAX_DEPLOYMENTS: usize = 100;
const MAX_BINDINGS: usize = 256;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct WorkerProviderProof {
    pub(crate) request_artifact_sha256: String,
    pub(crate) response_artifact_sha256: String,
    pub(crate) response_body_sha256: String,
    pub(crate) response_body_size_bytes: usize,
    pub(crate) http_status: u16,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct WorkerVersionPageEvidence {
    pub(crate) page_ordinal: u32,
    pub(crate) per_page: u32,
    pub(crate) version_ids: Vec<String>,
    pub(crate) result_version_ids_sha256: String,
    pub(crate) provider_proof: WorkerProviderProof,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct WorkerVersionSnapshot {
    pub(crate) per_page: u32,
    pub(crate) before_pages: Vec<WorkerVersionPageEvidence>,
    pub(crate) after_pages: Vec<WorkerVersionPageEvidence>,
    pub(crate) version_ids: Vec<String>,
    pub(crate) version_ids_sha256: String,
    pub(crate) semantic_snapshot_sha256: String,
    pub(crate) provider_proof_manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct WorkerBindingDescriptor {
    pub(crate) name: String,
    pub(crate) binding_type: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct WorkerVersionDetailEvidence {
    pub(crate) version_id: String,
    pub(crate) script_etag: String,
    pub(crate) binding_descriptors: Vec<WorkerBindingDescriptor>,
    pub(crate) binding_descriptors_sha256: String,
    pub(crate) binding_projection_sha256: String,
    pub(crate) raw_result_sha256: String,
    pub(crate) provider_proof: WorkerProviderProof,
    #[serde(skip_serializing)]
    binding_projection: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct WorkerBindingVerification {
    pub(crate) expected_binding_count: usize,
    pub(crate) observed_binding_count: usize,
    pub(crate) expected_projection_sha256: String,
    pub(crate) observed_projection_sha256: String,
    pub(crate) missing_binding_names: Vec<String>,
    pub(crate) unexpected_binding_names: Vec<String>,
    pub(crate) changed_binding_names: Vec<String>,
    pub(crate) matched: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct WorkerBindingExpectation {
    pub(crate) binding_count: usize,
    pub(crate) projection_sha256: String,
    #[serde(skip_serializing)]
    projection: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct WorkerDeploymentVersion {
    pub(crate) version_id: String,
    pub(crate) percentage: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct WorkerDeploymentProjection {
    pub(crate) deployment_id: String,
    pub(crate) versions: Vec<WorkerDeploymentVersion>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct WorkerDeploymentReadEvidence {
    pub(crate) deployments: Vec<WorkerDeploymentProjection>,
    pub(crate) projection_sha256: String,
    pub(crate) provider_proof: WorkerProviderProof,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct WorkerDeploymentSnapshot {
    pub(crate) first_read: WorkerDeploymentReadEvidence,
    pub(crate) second_read: WorkerDeploymentReadEvidence,
    pub(crate) deployments: Vec<WorkerDeploymentProjection>,
    pub(crate) semantic_snapshot_sha256: String,
    pub(crate) provider_proof_manifest_sha256: String,
    pub(crate) candidate_absent: Option<bool>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct WorkerVersionStateEvidence {
    pub(crate) script_name: String,
    pub(crate) versions: WorkerVersionSnapshot,
    pub(crate) detail: Option<WorkerVersionDetailEvidence>,
    pub(crate) deployments: WorkerDeploymentSnapshot,
    pub(crate) evidence_sha256: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct WorkerVersionUploadEvidence {
    pub(crate) candidate_version_id: String,
    pub(crate) script_etag: String,
    pub(crate) binding_projection_sha256: String,
    pub(crate) raw_result_sha256: String,
    pub(crate) request_body_sha256: String,
    pub(crate) request_body_size_bytes: usize,
    pub(crate) provider_proof: WorkerProviderProof,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WorkerVersionOperationError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) hint: &'static str,
    pub(crate) retryable: bool,
    pub(crate) outcome_ambiguous: bool,
    pub(crate) provider_request_lifecycle: WorkerRequestLifecycle,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) request_artifact_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_artifact_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_body_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_body_size_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) http_status: Option<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub(crate) struct WorkerRequestLifecycle {
    pub(crate) request_prepared: bool,
    pub(crate) dispatch_attempted: bool,
    pub(crate) provider_response_received: bool,
}

fn worker_request_lifecycle(
    request_prepared: bool,
    dispatch_attempted: bool,
    provider_response_received: bool,
) -> WorkerRequestLifecycle {
    WorkerRequestLifecycle {
        request_prepared,
        dispatch_attempted,
        provider_response_received,
    }
}

struct ExactExchange {
    result: Value,
    proof: WorkerProviderProof,
}

impl CloudflareClient {
    pub(crate) async fn capture_worker_version_state(
        &self,
        account_id: &str,
        script_name: &str,
        per_page: u32,
        detail_version_id: Option<&str>,
        candidate_must_be_absent: Option<&str>,
    ) -> Result<WorkerVersionStateEvidence, WorkerVersionOperationError> {
        validate_target(account_id, script_name)?;
        if !(1..=100).contains(&per_page) {
            return Err(operation_error(
                "workers.version_evidence_page_size_invalid",
                "per_page must be from 1 through 100",
                "Use one fixed bounded page size for both complete version-list passes.",
            ));
        }
        let before_pages = self
            .capture_worker_version_pass(account_id, script_name, per_page)
            .await?;
        let after_pages = self
            .capture_worker_version_pass(account_id, script_name, per_page)
            .await?;
        let before_semantic = version_page_semantics(&before_pages);
        let after_semantic = version_page_semantics(&after_pages);
        if before_semantic != after_semantic {
            return Err(operation_error(
                "workers.version_evidence_snapshot_drift",
                "Worker version inventory changed between the two complete pagination passes",
                "Capture a fresh stable snapshot before planning or applying a version upload.",
            ));
        }
        let version_ids = before_pages
            .iter()
            .flat_map(|page| page.version_ids.iter().cloned())
            .collect::<Vec<_>>();
        let semantic_snapshot_sha256 =
            semantic_version_snapshot_sha256(script_name, per_page, &before_semantic);
        let provider_proof_manifest_sha256 = proof_manifest_sha256(
            before_pages
                .iter()
                .chain(after_pages.iter())
                .map(|page| &page.provider_proof),
        );
        let versions = WorkerVersionSnapshot {
            per_page,
            before_pages,
            after_pages,
            version_ids_sha256: sha256_json(&version_ids),
            version_ids,
            semantic_snapshot_sha256,
            provider_proof_manifest_sha256,
        };

        let detail = if let Some(version_id) = detail_version_id {
            let version_id = canonical_uuid(version_id, "version_id")?;
            if !versions.version_ids.iter().any(|id| id == &version_id) {
                return Err(operation_error(
                    "workers.version_evidence_detail_not_in_snapshot",
                    "requested version detail ID was absent from the stable complete snapshot",
                    "Use an exact version ID captured by the same evidence ceremony.",
                ));
            }
            Some(
                self.get_worker_version_detail_evidence(account_id, script_name, &version_id)
                    .await?,
            )
        } else {
            None
        };

        let first_read = self
            .get_worker_deployments_evidence(account_id, script_name)
            .await?;
        let second_read = self
            .get_worker_deployments_evidence(account_id, script_name)
            .await?;
        if first_read.deployments != second_read.deployments {
            return Err(operation_error(
                "workers.version_evidence_deployment_drift",
                "Worker deployments changed between the two complete reads",
                "Capture a fresh stable deployment snapshot before continuing.",
            ));
        }
        let candidate_absent = match candidate_must_be_absent {
            Some(candidate) => {
                let candidate = canonical_uuid(candidate, "candidate version ID")?;
                let absent = first_read.deployments.iter().all(|deployment| {
                    deployment
                        .versions
                        .iter()
                        .all(|version| version.version_id != candidate)
                });
                if !absent {
                    return Err(operation_error(
                        "workers.version_evidence_candidate_deployed",
                        "candidate version appears in a nonzero deployment weight",
                        "Do not treat this version as a disabled candidate; reconcile active traffic first.",
                    ));
                }
                Some(true)
            }
            None => None,
        };
        let semantic_snapshot_sha256 = sha256_json(&json!({
            "schema_version": 1,
            "script_name": script_name,
            "deployments": first_read.deployments,
        }));
        let provider_proof_manifest_sha256 =
            proof_manifest_sha256([&first_read.provider_proof, &second_read.provider_proof]);
        let deployments = WorkerDeploymentSnapshot {
            deployments: first_read.deployments.clone(),
            first_read,
            second_read,
            semantic_snapshot_sha256,
            provider_proof_manifest_sha256,
            candidate_absent,
        };
        let evidence_sha256 = sha256_json(&json!({
            "schema_version": 1,
            "script_name": script_name,
            "version_snapshot_sha256": versions.semantic_snapshot_sha256,
            "version_proof_manifest_sha256": versions.provider_proof_manifest_sha256,
            "detail": detail,
            "deployment_snapshot_sha256": deployments.semantic_snapshot_sha256,
            "deployment_proof_manifest_sha256": deployments.provider_proof_manifest_sha256,
        }));
        Ok(WorkerVersionStateEvidence {
            script_name: script_name.to_string(),
            versions,
            detail,
            deployments,
            evidence_sha256,
        })
    }

    pub(crate) async fn upload_worker_version_once(
        &self,
        account_id: &str,
        script_name: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<WorkerVersionUploadEvidence, WorkerVersionOperationError> {
        validate_target(account_id, script_name)?;
        if !content_type
            .to_ascii_lowercase()
            .starts_with("multipart/form-data;")
            || !content_type.to_ascii_lowercase().contains("boundary=")
        {
            return Err(operation_error(
                "workers.version_upload_content_type_invalid",
                "version upload requires a multipart/form-data content type with an explicit boundary",
                "Use the exact reviewed module or multipart artifact prepared by workers_upload_version dry-run.",
            ));
        }
        let path = format!(
            "/accounts/{}/workers/scripts/{}/versions",
            path_segment(account_id),
            path_segment(script_name)
        );
        let request_body_sha256 = sha256_hex(&body);
        let request_body_size_bytes = body.len();
        let exchange = self
            .exact_worker_exchange(
                reqwest::Method::POST,
                &path,
                &[(&"bindings_inherit", &"strict")],
                Some(content_type),
                Some(body),
                true,
            )
            .await?;
        let detail = sanitize_version_detail(exchange.result, None, exchange.proof.clone())
            .map_err(|mut error| {
                error.outcome_ambiguous = true;
                error.retryable = false;
                error.provider_request_lifecycle = worker_request_lifecycle(true, true, true);
                error.request_artifact_sha256 =
                    Some(exchange.proof.request_artifact_sha256.clone());
                error.response_artifact_sha256 =
                    Some(exchange.proof.response_artifact_sha256.clone());
                error.response_body_sha256 = Some(exchange.proof.response_body_sha256.clone());
                error.response_body_size_bytes = Some(exchange.proof.response_body_size_bytes);
                error.http_status = Some(exchange.proof.http_status);
                error
            })?;
        Ok(WorkerVersionUploadEvidence {
            candidate_version_id: detail.version_id,
            script_etag: detail.script_etag,
            binding_projection_sha256: detail.binding_projection_sha256,
            raw_result_sha256: detail.raw_result_sha256,
            request_body_sha256,
            request_body_size_bytes,
            provider_proof: exchange.proof,
        })
    }

    async fn capture_worker_version_pass(
        &self,
        account_id: &str,
        script_name: &str,
        per_page: u32,
    ) -> Result<Vec<WorkerVersionPageEvidence>, WorkerVersionOperationError> {
        let mut pages = Vec::new();
        let mut seen = BTreeSet::new();
        for page in 1..=MAX_VERSION_PAGES as u32 {
            let path = format!(
                "/accounts/{}/workers/scripts/{}/versions",
                path_segment(account_id),
                path_segment(script_name)
            );
            let page_value = page.to_string();
            let per_page_value = per_page.to_string();
            let exchange = self
                .exact_worker_exchange(
                    reqwest::Method::GET,
                    &path,
                    &[
                        ("page", page_value.as_str()),
                        ("per_page", per_page_value.as_str()),
                    ],
                    None,
                    None,
                    false,
                )
                .await?;
            let items = version_page_items(&exchange.result)?;
            if items.len() > per_page as usize {
                return Err(operation_error(
                    "workers.version_evidence_page_overflow",
                    "version page contained more items than the requested per_page",
                    "Treat the provider pagination response as malformed.",
                ));
            }
            let mut version_ids = Vec::with_capacity(items.len());
            for item in items {
                let id = item
                    .as_object()
                    .and_then(|item| item.get("id"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        operation_error(
                            "workers.version_evidence_item_invalid",
                            "version-list item omitted its canonical ID",
                            "Treat the provider version inventory as malformed.",
                        )
                    })?;
                let id = canonical_uuid(id, "listed version ID")?;
                if !seen.insert(id.clone()) {
                    return Err(operation_error(
                        "workers.version_evidence_duplicate",
                        "complete version pagination contained a duplicate version ID",
                        "Reconcile the provider version inventory before continuing.",
                    ));
                }
                version_ids.push(id);
                if seen.len() > MAX_VERSION_IDS {
                    return Err(operation_error(
                        "workers.version_evidence_over_cap",
                        "complete version inventory exceeded the 4096-version safety cap",
                        "Extend the bounded evidence contract in a reviewed change before continuing.",
                    ));
                }
            }
            let terminal = version_ids.len() < per_page as usize;
            let result_version_ids_sha256 = sha256_json(&version_ids);
            pages.push(WorkerVersionPageEvidence {
                page_ordinal: page,
                per_page,
                version_ids,
                result_version_ids_sha256,
                provider_proof: exchange.proof,
            });
            if terminal {
                return Ok(pages);
            }
        }
        Err(operation_error(
            "workers.version_evidence_pagination_unbounded",
            "version pagination did not reach a short terminal page within the bounded contract",
            "Treat the provider version inventory as incomplete.",
        ))
    }

    async fn get_worker_version_detail_evidence(
        &self,
        account_id: &str,
        script_name: &str,
        version_id: &str,
    ) -> Result<WorkerVersionDetailEvidence, WorkerVersionOperationError> {
        let path = format!(
            "/accounts/{}/workers/scripts/{}/versions/{}",
            path_segment(account_id),
            path_segment(script_name),
            path_segment(version_id)
        );
        let exchange = self
            .exact_worker_exchange(reqwest::Method::GET, &path, &[], None, None, false)
            .await?;
        sanitize_version_detail(exchange.result, Some(version_id), exchange.proof)
    }

    async fn get_worker_deployments_evidence(
        &self,
        account_id: &str,
        script_name: &str,
    ) -> Result<WorkerDeploymentReadEvidence, WorkerVersionOperationError> {
        let path = format!(
            "/accounts/{}/workers/scripts/{}/deployments",
            path_segment(account_id),
            path_segment(script_name)
        );
        let exchange = self
            .exact_worker_exchange(reqwest::Method::GET, &path, &[], None, None, false)
            .await?;
        let deployments = sanitize_deployments(&exchange.result)?;
        Ok(WorkerDeploymentReadEvidence {
            projection_sha256: sha256_json(&deployments),
            deployments,
            provider_proof: exchange.proof,
        })
    }

    async fn exact_worker_exchange(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, &str)],
        content_type: Option<&str>,
        body: Option<Vec<u8>>,
        non_idempotent: bool,
    ) -> Result<ExactExchange, WorkerVersionOperationError> {
        let token = self.bearer_token().map_err(adapter_pre_dispatch_error)?;
        let mut builder = self
            .worker_version_http
            .request(method, self.endpoint(path))
            .bearer_auth(&token)
            .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .query(query);
        if let Some(content_type) = content_type {
            let value = HeaderValue::from_str(content_type).map_err(|_| {
                operation_error(
                    "workers.version_upload_content_type_invalid",
                    "version upload content type was not a valid HTTP header value",
                    "Use the exact reviewed multipart content type.",
                )
            })?;
            builder = builder.header(reqwest::header::CONTENT_TYPE, value);
        }
        let body_bytes = body.unwrap_or_default();
        if !body_bytes.is_empty() {
            builder = builder.body(body_bytes.clone());
        }
        let request = builder.build().map_err(|_| {
            operation_error(
                "workers.version_request_build_failed",
                "Worker version request could not be built",
                "Correct the target, content type, and bounded artifact before retrying.",
            )
        })?;
        let request_artifact_sha256 = request_artifact_sha256(&request, &body_bytes);
        let response = self
            .worker_version_http
            .execute(request)
            .await
            .map_err(|error| WorkerVersionOperationError {
                code: if error.is_timeout() {
                    "workers.version_request_timeout"
                } else {
                    "workers.version_transport_error"
                },
                message: if non_idempotent {
                    "Worker version upload was dispatched without a complete response".to_string()
                } else {
                    "Worker version evidence request failed before a complete response".to_string()
                },
                hint: if non_idempotent {
                    "Do not retry the upload. Use workers_reconcile_version_upload against the pinned pre-upload snapshot."
                } else {
                    "Retry the read-only evidence capture when the provider is available."
                },
                retryable: !non_idempotent,
                outcome_ambiguous: non_idempotent,
                provider_request_lifecycle: worker_request_lifecycle(true, true, false),
                request_artifact_sha256: Some(request_artifact_sha256.clone()),
                response_artifact_sha256: None,
                response_body_sha256: None,
                response_body_size_bytes: None,
                http_status: None,
            })?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        if !identity_content_encoding(&headers) {
            return Err(WorkerVersionOperationError {
                code: "workers.version_response_encoding_unsupported",
                message: "Worker version response used a non-identity content encoding".to_string(),
                hint: if non_idempotent {
                    "Treat the upload outcome as ambiguous and reconcile; never repeat the POST."
                } else {
                    "Treat the evidence read as unavailable and capture it again."
                },
                retryable: !non_idempotent,
                outcome_ambiguous: non_idempotent,
                provider_request_lifecycle: worker_request_lifecycle(true, true, true),
                request_artifact_sha256: Some(request_artifact_sha256),
                response_artifact_sha256: None,
                response_body_sha256: None,
                response_body_size_bytes: None,
                http_status: Some(status),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(WorkerVersionOperationError {
                code: "workers.version_response_over_cap",
                message: "Worker version response exceeded the 1 MiB exact-evidence cap"
                    .to_string(),
                hint: if non_idempotent {
                    "Treat the upload outcome as ambiguous and reconcile; never repeat the POST."
                } else {
                    "Treat the provider evidence as unavailable until the bounded contract is deliberately extended."
                },
                retryable: false,
                outcome_ambiguous: non_idempotent,
                provider_request_lifecycle: worker_request_lifecycle(true, true, true),
                request_artifact_sha256: Some(request_artifact_sha256),
                response_artifact_sha256: None,
                response_body_sha256: None,
                response_body_size_bytes: response.content_length().map(|value| value as usize),
                http_status: Some(status),
            });
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| WorkerVersionOperationError {
                code: "workers.version_response_read_failed",
                message: "Worker version response body could not be read completely".to_string(),
                hint: if non_idempotent {
                    "Treat the upload outcome as ambiguous and reconcile; never repeat the POST."
                } else {
                    "Treat the evidence read as unavailable and capture it again."
                },
                retryable: !non_idempotent,
                outcome_ambiguous: non_idempotent,
                provider_request_lifecycle: worker_request_lifecycle(true, true, true),
                request_artifact_sha256: Some(request_artifact_sha256.clone()),
                response_artifact_sha256: None,
                response_body_sha256: None,
                response_body_size_bytes: Some(bytes.len()),
                http_status: Some(status),
            })?;
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(WorkerVersionOperationError {
                    code: "workers.version_response_over_cap",
                    message: "Worker version response exceeded the 1 MiB exact-evidence cap"
                        .to_string(),
                    hint: if non_idempotent {
                        "Treat the upload outcome as ambiguous and reconcile; never repeat the POST."
                    } else {
                        "Treat the provider evidence as unavailable until the bounded contract is deliberately extended."
                    },
                    retryable: false,
                    outcome_ambiguous: non_idempotent,
                    provider_request_lifecycle: worker_request_lifecycle(true, true, true),
                    request_artifact_sha256: Some(request_artifact_sha256),
                    response_artifact_sha256: None,
                    response_body_sha256: None,
                    response_body_size_bytes: Some(bytes.len().saturating_add(chunk.len())),
                    http_status: Some(status),
                });
            }
            bytes.extend_from_slice(&chunk);
        }
        let response_body_sha256 = sha256_hex(&bytes);
        let response_artifact_sha256 = response_artifact_sha256(status, &headers, &bytes);
        let evidence = WorkerProviderProof {
            request_artifact_sha256: request_artifact_sha256.clone(),
            response_artifact_sha256: response_artifact_sha256.clone(),
            response_body_sha256: response_body_sha256.clone(),
            response_body_size_bytes: bytes.len(),
            http_status: status,
        };
        if !(200..=299).contains(&status) {
            return Err(WorkerVersionOperationError {
                code: "workers.version_provider_rejected",
                message: "Cloudflare rejected the Worker version request".to_string(),
                hint: if non_idempotent {
                    "Do not retry automatically. Inspect the status and exact evidence, then reconcile if the provider outcome is not definitive."
                } else {
                    "Verify the exact target and Workers Scripts permissions."
                },
                retryable: false,
                // A non-idempotent upload may have reached the provider even
                // when its HTTP response is an error envelope. Never turn a
                // provider rejection into permission to repeat the POST; the
                // pinned version snapshot is the only reconciliation basis.
                outcome_ambiguous: non_idempotent,
                provider_request_lifecycle: worker_request_lifecycle(true, true, true),
                request_artifact_sha256: Some(request_artifact_sha256),
                response_artifact_sha256: Some(response_artifact_sha256),
                response_body_sha256: Some(response_body_sha256),
                response_body_size_bytes: Some(bytes.len()),
                http_status: Some(status),
            });
        }
        let envelope_text =
            std::str::from_utf8(&bytes).map_err(|_| WorkerVersionOperationError {
                code: "workers.version_response_invalid",
                message: "Worker version response was not valid UTF-8 JSON".to_string(),
                hint: if non_idempotent {
                    "Treat the upload outcome as ambiguous and reconcile; never repeat the POST."
                } else {
                    "Treat the provider evidence as malformed."
                },
                retryable: false,
                outcome_ambiguous: non_idempotent,
                provider_request_lifecycle: worker_request_lifecycle(true, true, true),
                request_artifact_sha256: Some(request_artifact_sha256.clone()),
                response_artifact_sha256: Some(response_artifact_sha256.clone()),
                response_body_sha256: Some(response_body_sha256.clone()),
                response_body_size_bytes: Some(bytes.len()),
                http_status: Some(status),
            })?;
        let envelope: Value =
            decode_json_rejecting_duplicate_object_keys(envelope_text).map_err(|_| {
                WorkerVersionOperationError {
                code: "workers.version_response_invalid",
                message:
                    "Worker version response was malformed or contained duplicate JSON object keys"
                        .to_string(),
                hint: if non_idempotent {
                    "Treat the upload outcome as ambiguous and reconcile; never repeat the POST."
                } else {
                    "Treat the provider evidence as malformed."
                },
                retryable: false,
                outcome_ambiguous: non_idempotent,
                provider_request_lifecycle: worker_request_lifecycle(true, true, true),
                request_artifact_sha256: Some(request_artifact_sha256.clone()),
                response_artifact_sha256: Some(response_artifact_sha256.clone()),
                response_body_sha256: Some(response_body_sha256.clone()),
                response_body_size_bytes: Some(bytes.len()),
                http_status: Some(status),
            }
            })?;
        let result = valid_envelope_result(&envelope).map_err(|mut error| {
            error.outcome_ambiguous = non_idempotent;
            error.retryable = false;
            error.provider_request_lifecycle = worker_request_lifecycle(true, true, true);
            error.request_artifact_sha256 = Some(request_artifact_sha256);
            error.response_artifact_sha256 = Some(response_artifact_sha256);
            error.response_body_sha256 = Some(response_body_sha256);
            error.response_body_size_bytes = Some(bytes.len());
            error.http_status = Some(status);
            error
        })?;
        Ok(ExactExchange {
            result: result.clone(),
            proof: evidence,
        })
    }
}

fn valid_envelope_result(envelope: &Value) -> Result<&Value, WorkerVersionOperationError> {
    let object = envelope.as_object().ok_or_else(|| {
        operation_error(
            "workers.version_response_invalid",
            "Worker version response envelope was not an object",
            "Treat the provider evidence as malformed.",
        )
    })?;
    if object.get("success") != Some(&Value::Bool(true))
        || !object
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        return Err(operation_error(
            "workers.version_response_contradictory",
            "Worker version response did not contain success=true with an empty errors array",
            "Treat the provider response as contradictory and do not continue.",
        ));
    }
    object
        .get("result")
        .filter(|value| !value.is_null())
        .ok_or_else(|| {
            operation_error(
                "workers.version_response_result_missing",
                "Worker version response omitted a non-null result",
                "Treat a write outcome as ambiguous and a read outcome as unavailable.",
            )
        })
}

fn version_page_items(result: &Value) -> Result<&Vec<Value>, WorkerVersionOperationError> {
    result
        .as_array()
        .or_else(|| result.as_object()?.get("items")?.as_array())
        .ok_or_else(|| {
            operation_error(
                "workers.version_evidence_page_invalid",
                "version-list result did not contain the expected items array",
                "Treat the provider version inventory as malformed.",
            )
        })
}

fn sanitize_version_detail(
    result: Value,
    expected_version_id: Option<&str>,
    provider_proof: WorkerProviderProof,
) -> Result<WorkerVersionDetailEvidence, WorkerVersionOperationError> {
    let object = result.as_object().ok_or_else(|| {
        operation_error(
            "workers.version_detail_invalid",
            "version detail result was not an object",
            "Treat the exact version evidence as malformed.",
        )
    })?;
    let version_id = object.get("id").and_then(Value::as_str).ok_or_else(|| {
        operation_error(
            "workers.version_detail_id_missing",
            "version detail omitted its canonical ID",
            "Treat the exact version evidence as malformed.",
        )
    })?;
    let version_id = canonical_uuid(version_id, "version detail ID")?;
    if expected_version_id.is_some_and(|expected| expected != version_id) {
        return Err(operation_error(
            "workers.version_detail_cross_target",
            "version detail returned an ID different from the exact requested version",
            "Treat the provider evidence as cross-target and fail closed.",
        ));
    }
    let resources = object
        .get("resources")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            operation_error(
                "workers.version_detail_resources_missing",
                "version detail omitted its resources object",
                "Treat the exact version evidence as incomplete.",
            )
        })?;
    let script_etag = resources
        .get("script")
        .and_then(Value::as_object)
        .and_then(|script| script.get("etag"))
        .and_then(Value::as_str)
        .and_then(canonical_script_etag)
        .ok_or_else(|| {
            operation_error(
                "workers.version_detail_etag_missing",
                "version detail omitted a canonical 64-character lowercase script ETag",
                "Treat the exact version evidence as incomplete.",
            )
        })?;
    let bindings = match resources.get("bindings") {
        None => &[][..],
        Some(Value::Array(bindings)) => bindings.as_slice(),
        Some(_) => {
            return Err(operation_error(
                "workers.version_detail_bindings_invalid",
                "version detail resources.bindings was not an array",
                "Treat the exact version evidence as malformed.",
            ));
        }
    };
    if bindings.len() > MAX_BINDINGS {
        return Err(operation_error(
            "workers.version_detail_bindings_over_cap",
            "version detail exceeded the 256-binding projection cap",
            "Extend the bounded evidence contract in a reviewed change.",
        ));
    }
    let mut names = BTreeSet::new();
    let mut binding_descriptors = Vec::with_capacity(bindings.len());
    let mut binding_projection = BTreeMap::new();
    for binding in bindings {
        let binding = binding.as_object().ok_or_else(|| {
            operation_error(
                "workers.version_detail_binding_invalid",
                "version detail binding was not an object",
                "Treat the exact version evidence as malformed.",
            )
        })?;
        let name = binding
            .get("name")
            .and_then(Value::as_str)
            .and_then(canonical_binding_name)
            .ok_or_else(|| {
                operation_error(
                    "workers.version_detail_binding_invalid",
                    "version detail binding omitted a canonical name",
                    "Treat the exact version evidence as malformed.",
                )
            })?;
        let binding_type = binding
            .get("type")
            .and_then(Value::as_str)
            .and_then(canonical_binding_type)
            .ok_or_else(|| {
                operation_error(
                    "workers.version_detail_binding_invalid",
                    "version detail binding omitted a canonical type",
                    "Treat the exact version evidence as malformed.",
                )
            })?;
        if !names.insert(name.to_string()) {
            return Err(operation_error(
                "workers.version_detail_binding_duplicate",
                "version detail contained a duplicate binding name",
                "Treat the exact version evidence as contradictory.",
            ));
        }
        let canonical_binding = canonicalize_provider_binding(binding).map_err(|_| {
            operation_error(
                "workers.version_detail_binding_projection_invalid",
                "version detail binding was outside the closed canonical provider projection",
                "Treat the exact version evidence as malformed.",
            )
        })?;
        binding_descriptors.push(WorkerBindingDescriptor {
            name: name.to_string(),
            binding_type: binding_type.to_string(),
        });
        binding_projection.insert(name.to_string(), Value::Object(canonical_binding));
    }
    let raw_result_sha256 = sha256_json(&result);
    let binding_descriptors_sha256 = sha256_json(&binding_descriptors);
    let binding_projection_sha256 = sha256_json(&binding_projection);
    Ok(WorkerVersionDetailEvidence {
        version_id,
        script_etag: script_etag.to_string(),
        binding_descriptors,
        binding_descriptors_sha256,
        binding_projection_sha256,
        raw_result_sha256,
        provider_proof,
        binding_projection,
    })
}

pub(crate) fn prepare_worker_binding_expectation(
    base: &WorkerVersionDetailEvidence,
    metadata: &Value,
) -> Result<WorkerBindingExpectation, WorkerVersionOperationError> {
    let bindings = metadata
        .as_object()
        .and_then(|metadata| metadata.get("bindings"))
        .map(|bindings| {
            bindings.as_array().ok_or_else(|| {
                operation_error(
                    "workers.version_binding_plan_invalid",
                    "reviewed metadata bindings were not an array",
                    "Use the exact complete metadata accepted by the version-upload preview.",
                )
            })
        })
        .transpose()?
        .map(Vec::as_slice)
        .unwrap_or_default();
    if bindings.len() > MAX_BINDINGS {
        return Err(operation_error(
            "workers.version_binding_plan_invalid",
            "reviewed metadata bindings exceeded the bounded evidence cap",
            "Use the exact complete metadata accepted by the version-upload preview.",
        ));
    }

    let mut expected = BTreeMap::<String, Value>::new();
    for binding in bindings {
        let binding = binding.as_object().ok_or_else(|| {
            operation_error(
                "workers.version_binding_plan_invalid",
                "reviewed metadata contained a non-object binding",
                "Use the exact complete metadata accepted by the version-upload preview.",
            )
        })?;
        let name = binding
            .get("name")
            .and_then(Value::as_str)
            .and_then(canonical_binding_name)
            .ok_or_else(|| {
                operation_error(
                    "workers.version_binding_plan_invalid",
                    "reviewed metadata binding omitted a canonical name",
                    "Use the exact complete metadata accepted by the version-upload preview.",
                )
            })?;
        let binding_type = binding
            .get("type")
            .and_then(Value::as_str)
            .and_then(canonical_binding_type)
            .ok_or_else(|| {
                operation_error(
                    "workers.version_binding_plan_invalid",
                    "reviewed metadata binding omitted a canonical type",
                    "Use the exact complete metadata accepted by the version-upload preview.",
                )
            })?;
        let expected_binding = if binding_type == "inherit" {
            let source_name = binding
                .get("old_name")
                .map(|value| {
                    value
                        .as_str()
                        .and_then(canonical_binding_name)
                        .ok_or_else(|| {
                            operation_error(
                                "workers.version_binding_plan_invalid",
                                "inherit old_name was not a canonical binding name",
                                "Use the exact reviewed base binding identity.",
                            )
                        })
                })
                .transpose()?
                .unwrap_or(name);
            let mut inherited = base
                .binding_projection
                .get(source_name)
                .and_then(Value::as_object)
                .cloned()
                .ok_or_else(|| {
                    operation_error(
                        "workers.version_binding_inherit_source_missing",
                        "an inherited binding was absent from the exact base version detail",
                        "Do not upload or deploy until the reviewed inheritance plan matches the base version.",
                    )
                })?;
            inherited.insert("name".to_string(), Value::String(name.to_string()));
            Value::Object(inherited)
        } else {
            Value::Object(canonicalize_provider_binding(binding).map_err(|_| {
                operation_error(
                    "workers.version_binding_plan_invalid",
                    "reviewed explicit binding was outside the closed canonical projection",
                    "Use the canonical metadata accepted by the version-upload preview.",
                )
            })?)
        };
        if expected
            .insert(name.to_string(), expected_binding)
            .is_some()
        {
            return Err(operation_error(
                "workers.version_binding_plan_duplicate",
                "reviewed metadata contained a duplicate binding name",
                "Use one complete unambiguous binding plan.",
            ));
        }
    }

    Ok(WorkerBindingExpectation {
        binding_count: expected.len(),
        projection_sha256: sha256_json(&expected),
        projection: expected,
    })
}

pub(crate) fn verify_worker_candidate_bindings(
    expectation: &WorkerBindingExpectation,
    candidate: &WorkerVersionDetailEvidence,
) -> WorkerBindingVerification {
    let observed = &candidate.binding_projection;
    let missing_binding_names = expectation
        .projection
        .keys()
        .filter(|name| !observed.contains_key(*name))
        .cloned()
        .collect::<Vec<_>>();
    let unexpected_binding_names = observed
        .keys()
        .filter(|name| !expectation.projection.contains_key(*name))
        .cloned()
        .collect::<Vec<_>>();
    let changed_binding_names = expectation
        .projection
        .iter()
        .filter_map(|(name, expected_value)| {
            observed
                .get(name)
                .is_some_and(|observed_value| observed_value != expected_value)
                .then(|| name.clone())
        })
        .collect::<Vec<_>>();
    let observed_projection_sha256 = candidate.binding_projection_sha256.clone();
    let matched = missing_binding_names.is_empty()
        && unexpected_binding_names.is_empty()
        && changed_binding_names.is_empty()
        && expectation.projection_sha256 == observed_projection_sha256;
    WorkerBindingVerification {
        expected_binding_count: expectation.binding_count,
        observed_binding_count: observed.len(),
        expected_projection_sha256: expectation.projection_sha256.clone(),
        observed_projection_sha256,
        missing_binding_names,
        unexpected_binding_names,
        changed_binding_names,
        matched,
    }
}

fn sanitize_deployments(
    result: &Value,
) -> Result<Vec<WorkerDeploymentProjection>, WorkerVersionOperationError> {
    let deployments = result
        .as_object()
        .and_then(|result| result.get("deployments"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            operation_error(
                "workers.version_deployments_invalid",
                "deployment-list result omitted its deployments array",
                "Treat the provider deployment evidence as malformed.",
            )
        })?;
    if deployments.len() > MAX_DEPLOYMENTS {
        return Err(operation_error(
            "workers.version_deployments_over_cap",
            "deployment-list result exceeded the 100-deployment safety cap",
            "Extend the bounded deployment evidence contract in a reviewed change.",
        ));
    }
    let mut deployment_ids = BTreeSet::new();
    let mut projections = Vec::with_capacity(deployments.len());
    for deployment in deployments {
        let deployment = deployment.as_object().ok_or_else(|| {
            operation_error(
                "workers.version_deployment_invalid",
                "deployment-list item was not an object",
                "Treat the provider deployment evidence as malformed.",
            )
        })?;
        let deployment_id = deployment
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                operation_error(
                    "workers.version_deployment_invalid",
                    "deployment-list item omitted its canonical ID",
                    "Treat the provider deployment evidence as malformed.",
                )
            })?;
        let deployment_id = canonical_uuid(deployment_id, "deployment ID")?;
        if !deployment_ids.insert(deployment_id.clone()) {
            return Err(operation_error(
                "workers.version_deployment_duplicate",
                "deployment-list result contained a duplicate deployment ID",
                "Treat the provider deployment evidence as contradictory.",
            ));
        }
        let versions = deployment
            .get("versions")
            .and_then(Value::as_array)
            .filter(|versions| (1..=2).contains(&versions.len()))
            .ok_or_else(|| {
                operation_error(
                    "workers.version_deployment_weights_invalid",
                    "deployment must contain one or two positive version weights",
                    "Treat the provider deployment evidence as malformed.",
                )
            })?;
        let mut version_ids = BTreeSet::new();
        let mut total = 0.0f64;
        let mut projected_versions = Vec::with_capacity(versions.len());
        for version in versions {
            let version = version.as_object().ok_or_else(|| {
                operation_error(
                    "workers.version_deployment_weights_invalid",
                    "deployment version weight was not an object",
                    "Treat the provider deployment evidence as malformed.",
                )
            })?;
            let version_id = version
                .get("version_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    operation_error(
                        "workers.version_deployment_weights_invalid",
                        "deployment weight omitted its canonical version ID",
                        "Treat the provider deployment evidence as malformed.",
                    )
                })?;
            let version_id = canonical_uuid(version_id, "deployed version ID")?;
            if !version_ids.insert(version_id.clone()) {
                return Err(operation_error(
                    "workers.version_deployment_weights_invalid",
                    "deployment contained a duplicate version ID",
                    "Treat the provider deployment evidence as contradictory.",
                ));
            }
            let percentage = version
                .get("percentage")
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite() && (0.01..=100.0).contains(value))
                .ok_or_else(|| {
                    operation_error(
                        "workers.version_deployment_weights_invalid",
                        "deployment percentage was outside 0.01 through 100",
                        "Treat the provider deployment evidence as malformed.",
                    )
                })?;
            total += percentage;
            projected_versions.push(WorkerDeploymentVersion {
                version_id,
                percentage,
            });
        }
        if (total - 100.0).abs() > 0.000_001 {
            return Err(operation_error(
                "workers.version_deployment_weights_invalid",
                "deployment version weights did not total 100",
                "Treat the provider deployment evidence as contradictory.",
            ));
        }
        projections.push(WorkerDeploymentProjection {
            deployment_id,
            versions: projected_versions,
        });
    }
    Ok(projections)
}

pub(crate) fn validate_worker_version_ids(
    version_ids: &[String],
) -> Result<String, WorkerVersionOperationError> {
    if version_ids.len() > MAX_VERSION_IDS {
        return Err(operation_error(
            "workers.version_reconciliation_snapshot_over_cap",
            "pre-upload version snapshot exceeded the 4096-version safety cap",
            "Use the exact bounded snapshot returned by workers_capture_version_evidence.",
        ));
    }
    let mut seen = BTreeSet::new();
    for version_id in version_ids {
        let version_id = canonical_uuid(version_id, "pre-upload version ID")?;
        if !seen.insert(version_id) {
            return Err(operation_error(
                "workers.version_reconciliation_snapshot_duplicate",
                "pre-upload version snapshot contained a duplicate ID",
                "Use the exact bounded snapshot returned by workers_capture_version_evidence.",
            ));
        }
    }
    Ok(sha256_json(&version_ids))
}

pub(crate) fn validate_worker_deployment_projection(
    script_name: &str,
    deployments: &Value,
) -> Result<(Vec<WorkerDeploymentProjection>, String), WorkerVersionOperationError> {
    let projected = sanitize_deployments(&json!({"deployments": deployments}))?;
    let digest = sha256_json(&json!({
        "schema_version": 1,
        "script_name": script_name,
        "deployments": projected,
    }));
    Ok((projected, digest))
}

fn validate_target(account_id: &str, script_name: &str) -> Result<(), WorkerVersionOperationError> {
    if account_id.is_empty() || account_id.trim() != account_id {
        return Err(operation_error(
            "workers.version_target_invalid",
            "account_id must be a canonical non-empty string",
            "Use the exact account identity from authenticated inventory.",
        ));
    }
    if script_name.is_empty() || script_name.trim() != script_name {
        return Err(operation_error(
            "workers.version_target_invalid",
            "script_name must be a canonical non-empty string",
            "Use the exact script identity from authenticated inventory.",
        ));
    }
    Ok(())
}

fn canonical_uuid(value: &str, label: &str) -> Result<String, WorkerVersionOperationError> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || value.trim() != value
        || ![8usize, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        || bytes.iter().enumerate().any(|(index, byte)| {
            ![8usize, 13, 18, 23].contains(&index)
                && !byte.is_ascii_digit()
                && !(b'a'..=b'f').contains(byte)
        })
    {
        return Err(operation_error(
            "workers.version_identity_invalid",
            format!("{label} must be a canonical lowercase UUID"),
            "Reconcile the exact provider identity before continuing.",
        ));
    }
    Ok(value.to_string())
}

fn canonical_script_etag(value: &str) -> Option<&str> {
    (value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(value)
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

fn version_page_semantics(pages: &[WorkerVersionPageEvidence]) -> Vec<Value> {
    pages
        .iter()
        .map(|page| {
            json!({
                "page_ordinal": page.page_ordinal,
                "per_page": page.per_page,
                "version_ids": page.version_ids,
            })
        })
        .collect()
}

fn semantic_version_snapshot_sha256(script_name: &str, per_page: u32, pages: &[Value]) -> String {
    sha256_json(&json!({
        "schema_version": 1,
        "script_name": script_name,
        "per_page": per_page,
        "pages": pages,
    }))
}

fn proof_manifest_sha256<'a>(proofs: impl IntoIterator<Item = &'a WorkerProviderProof>) -> String {
    sha256_json(&proofs.into_iter().collect::<Vec<_>>())
}

fn request_artifact_sha256(request: &reqwest::Request, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cloudflare-mcp.worker-request-artifact.v1\0");
    hasher.update(request.method().as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(request.url().as_str().as_bytes());
    hash_headers(&mut hasher, request.headers());
    hasher.update(b"\0body\0");
    hasher.update(body);
    format!("{:x}", hasher.finalize())
}

fn response_artifact_sha256(status: u16, headers: &HeaderMap, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cloudflare-mcp.worker-response-artifact.v1\0");
    hasher.update(status.to_string().as_bytes());
    hash_headers(&mut hasher, headers);
    hasher.update(b"\0body\0");
    hasher.update(body);
    format!("{:x}", hasher.finalize())
}

fn hash_headers(hasher: &mut Sha256, headers: &HeaderMap) {
    let mut fields = BTreeMap::<String, Vec<Vec<u8>>>::new();
    for (name, value) in headers {
        fields
            .entry(name.as_str().to_ascii_lowercase())
            .or_default()
            .push(value.as_bytes().to_vec());
    }
    for (name, mut values) in fields {
        values.sort();
        hasher.update(b"\0header\0");
        hasher.update(name.as_bytes());
        for value in values {
            hasher.update(b"\0value\0");
            hasher.update(&value);
        }
    }
}

fn identity_content_encoding(headers: &HeaderMap) -> bool {
    headers
        .get_all(reqwest::header::CONTENT_ENCODING)
        .iter()
        .all(|value| {
            value.to_str().ok().is_some_and(|value| {
                value
                    .split(',')
                    .all(|encoding| encoding.trim().eq_ignore_ascii_case("identity"))
            })
        })
}

fn path_segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn sha256_json(value: &impl Serialize) -> String {
    sha256_hex(&serde_json::to_vec(value).expect("finite Worker evidence value"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn adapter_pre_dispatch_error(error: AdapterError) -> WorkerVersionOperationError {
    WorkerVersionOperationError {
        code: error.code,
        message: error.message,
        hint: error.hint,
        retryable: false,
        outcome_ambiguous: false,
        provider_request_lifecycle: worker_request_lifecycle(false, false, false),
        request_artifact_sha256: None,
        response_artifact_sha256: None,
        response_body_sha256: None,
        response_body_size_bytes: None,
        http_status: error.status,
    }
}

fn operation_error(
    code: &'static str,
    message: impl Into<String>,
    hint: &'static str,
) -> WorkerVersionOperationError {
    WorkerVersionOperationError {
        code,
        message: message.into(),
        hint,
        retryable: false,
        outcome_ambiguous: false,
        provider_request_lifecycle: worker_request_lifecycle(false, false, false),
        request_artifact_sha256: None,
        response_artifact_sha256: None,
        response_body_sha256: None,
        response_body_size_bytes: None,
        http_status: None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::body::{Body, Bytes};
    use axum::extract::Query;
    use axum::http::HeaderMap;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::{
        WorkerProviderProof, prepare_worker_binding_expectation, sanitize_deployments,
        sanitize_version_detail, verify_worker_candidate_bindings,
    };
    use crate::cloudflare::CloudflareClient;
    use crate::config::{ApiTokenSource, CloudflareApiConfig};

    fn test_config(base_url: String) -> CloudflareApiConfig {
        CloudflareApiConfig {
            api_base_url: base_url,
            api_token: Some("fixture-worker-version-token".to_string()),
            api_token_source: ApiTokenSource::Config,
            api_token_header: "x-cloudflare-api-token".to_string(),
            r2_access_key_id: None,
            r2_secret_access_key: None,
            r2_endpoint: None,
            default_account_id: Some("acct-1".to_string()),
            default_zone_id: None,
            request_timeout: Duration::from_secs(2),
            max_retries: 4,
            retry_base_delay: Duration::from_millis(1),
            retry_max_delay: Duration::from_millis(2),
            user_agent: "cloudflare-mcp-worker-version-test".to_string(),
        }
    }

    async fn spawn_router(router: Router) -> String {
        // DevSkim: ignore DS162092 -- loopback-only test fixture listener.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        // DevSkim: ignore DS137138 -- loopback-only test fixture URL.
        format!("http://{addr}")
    }

    fn proof() -> WorkerProviderProof {
        WorkerProviderProof {
            request_artifact_sha256: "a".repeat(64),
            response_artifact_sha256: "b".repeat(64),
            response_body_sha256: "c".repeat(64),
            response_body_size_bytes: 1,
            http_status: 200,
        }
    }

    #[test]
    fn detail_projection_omits_binding_values_and_requires_etag() {
        let detail = sanitize_version_detail(
            json!({
                "id":"11111111-1111-4111-8111-111111111111",
                "resources":{
                    "script":{"etag":"a".repeat(64)},
                    "bindings":[
                        {"name":"SECRET","type":"secret_text","text":"must-not-leak"},
                        {"name":"DB","type":"d1","database_id":"private-id"}
                    ]
                }
            }),
            Some("11111111-1111-4111-8111-111111111111"),
            proof(),
        )
        .expect("detail");
        let outward = serde_json::to_string(&detail).expect("serialize");
        assert!(!outward.contains("must-not-leak"));
        assert!(!outward.contains("private-id"));
        assert_eq!(detail.binding_descriptors.len(), 2);
        assert_eq!(detail.binding_projection_sha256.len(), 64);
    }

    #[test]
    fn candidate_binding_verification_detects_resource_and_secret_safe_drift() {
        let base_id = "11111111-1111-4111-8111-111111111111";
        let candidate_id = "22222222-2222-4222-8222-222222222222";
        let base_bindings = json!([
            {"name":"DB","type":"d1","database_id":"db-private"},
            {"name":"SERVICE","type":"service","service":"service-private"},
            {"name":"QUEUE","type":"queue","queue_name":"queue-private"},
            {"name":"BUCKET","type":"r2_bucket","bucket_name":"bucket-private"},
            {"name":"SECRET","type":"secret_text","text":"secret-private"}
        ]);
        let metadata = json!({
            "main_module":"index.js",
            "bindings":[
                {"name":"DB","type":"inherit","version_id":base_id},
                {"name":"SERVICE","type":"inherit","version_id":base_id},
                {"name":"QUEUE","type":"inherit","version_id":base_id},
                {"name":"BUCKET","type":"inherit","version_id":base_id},
                {"name":"SECRET","type":"inherit","version_id":base_id},
                {"name":"MODE","type":"plain_text","text":"plain-private"}
            ]
        });
        let base = sanitize_version_detail(
            json!({
                "id":base_id,
                "resources":{"script":{"etag":"a".repeat(64)},"bindings":base_bindings}
            }),
            Some(base_id),
            proof(),
        )
        .expect("base");
        let expectation =
            prepare_worker_binding_expectation(&base, &metadata).expect("expectation");
        let candidate_bindings = json!([
            {"name":"DB","type":"d1","database_id":"db-private"},
            {"name":"SERVICE","type":"service","service":"service-private"},
            {"name":"QUEUE","type":"queue","queue_name":"queue-private"},
            {"name":"BUCKET","type":"r2_bucket","bucket_name":"bucket-private"},
            {"name":"SECRET","type":"secret_text","text":"secret-private"},
            {"name":"MODE","type":"plain_text","text":"plain-private"}
        ]);
        let exact = sanitize_version_detail(
            json!({
                "id":candidate_id,
                "resources":{"script":{"etag":"b".repeat(64)},"bindings":candidate_bindings.clone()}
            }),
            Some(candidate_id),
            proof(),
        )
        .expect("candidate");
        let verification = verify_worker_candidate_bindings(&expectation, &exact);
        assert!(verification.matched, "{verification:?}");

        for (name, field, replacement) in [
            ("DB", "database_id", "db-drift"),
            ("SERVICE", "service", "service-drift"),
            ("QUEUE", "queue_name", "queue-drift"),
            ("BUCKET", "bucket_name", "bucket-drift"),
            ("SECRET", "text", "secret-drift"),
            ("MODE", "text", "plain-drift"),
        ] {
            let mut drifted = candidate_bindings.clone();
            let binding = drifted
                .as_array_mut()
                .expect("bindings")
                .iter_mut()
                .find(|binding| binding["name"] == json!(name))
                .expect("named binding");
            binding[field] = json!(replacement);
            let detail = sanitize_version_detail(
                json!({
                    "id":candidate_id,
                    "resources":{"script":{"etag":"b".repeat(64)},"bindings":drifted}
                }),
                Some(candidate_id),
                proof(),
            )
            .expect("drifted candidate");
            let verification = verify_worker_candidate_bindings(&expectation, &detail);
            assert!(!verification.matched, "{name}");
            assert_eq!(verification.changed_binding_names, vec![name.to_string()]);
            let outward = serde_json::to_string(&verification).expect("serialize verification");
            for secret in [
                "db-private",
                "service-private",
                "queue-private",
                "bucket-private",
                "secret-private",
                "plain-private",
                replacement,
            ] {
                assert!(!outward.contains(secret), "{name}: {secret}");
            }
        }

        let mut missing = candidate_bindings.clone();
        missing
            .as_array_mut()
            .expect("bindings")
            .retain(|binding| binding["name"] != json!("QUEUE"));
        let missing = sanitize_version_detail(
            json!({
                "id":candidate_id,
                "resources":{"script":{"etag":"b".repeat(64)},"bindings":missing}
            }),
            Some(candidate_id),
            proof(),
        )
        .expect("missing candidate");
        let verification = verify_worker_candidate_bindings(&expectation, &missing);
        assert!(!verification.matched);
        assert_eq!(verification.missing_binding_names, vec!["QUEUE"]);

        let mut unexpected = candidate_bindings;
        unexpected
            .as_array_mut()
            .expect("bindings")
            .push(json!({"name":"EXTRA","type":"plain_text","text":"extra-private"}));
        let unexpected = sanitize_version_detail(
            json!({
                "id":candidate_id,
                "resources":{"script":{"etag":"b".repeat(64)},"bindings":unexpected}
            }),
            Some(candidate_id),
            proof(),
        )
        .expect("unexpected candidate");
        let verification = verify_worker_candidate_bindings(&expectation, &unexpected);
        assert!(!verification.matched);
        assert_eq!(verification.unexpected_binding_names, vec!["EXTRA"]);
        assert!(
            !serde_json::to_string(&verification)
                .expect("serialize verification")
                .contains("extra-private")
        );
    }

    #[test]
    fn binding_projection_normalizes_documented_aliases_and_defaults_only() {
        let base_id = "11111111-1111-4111-8111-111111111111";
        let candidate_id = "22222222-2222-4222-8222-222222222222";
        let base = sanitize_version_detail(
            json!({
                "id":base_id,
                "resources":{"script":{"etag":"a".repeat(64)},"bindings":[]}
            }),
            Some(base_id),
            proof(),
        )
        .expect("base");
        let expectation = prepare_worker_binding_expectation(
            &base,
            &json!({
                "main_module":"index.js",
                "bindings":[
                    {"name":"DB","type":"d1","id":"db-1"},
                    {"name":"SEARCH","type":"ai_search","instance_name":"articles"}
                ]
            }),
        )
        .expect("canonical expectation");
        let candidate = sanitize_version_detail(
            json!({
                "id":candidate_id,
                "resources":{
                    "script":{"etag":"b".repeat(64)},
                    "bindings":[
                        {"name":"DB","type":"d1","database_id":"db-1"},
                        {
                            "name":"SEARCH",
                            "type":"ai_search",
                            "instance_name":"articles",
                            "namespace":"default"
                        }
                    ]
                }
            }),
            Some(candidate_id),
            proof(),
        )
        .expect("provider-normalized candidate");
        assert!(
            verify_worker_candidate_bindings(&expectation, &candidate).matched,
            "documented aliases and defaults should normalize"
        );

        let drifted = sanitize_version_detail(
            json!({
                "id":candidate_id,
                "resources":{
                    "script":{"etag":"b".repeat(64)},
                    "bindings":[
                        {"name":"DB","type":"d1","database_id":"db-1"},
                        {
                            "name":"SEARCH",
                            "type":"ai_search",
                            "instance_name":"articles",
                            "namespace":"tenant-a"
                        }
                    ]
                }
            }),
            Some(candidate_id),
            proof(),
        )
        .expect("drifted candidate");
        let verification = verify_worker_candidate_bindings(&expectation, &drifted);
        assert!(!verification.matched);
        assert_eq!(verification.changed_binding_names, vec!["SEARCH"]);

        let error = sanitize_version_detail(
            json!({
                "id":candidate_id,
                "resources":{
                    "script":{"etag":"b".repeat(64)},
                    "bindings":[{
                        "name":"DB",
                        "type":"d1",
                        "database_id":"db-1",
                        "unknown":"must-not-be-ignored"
                    }]
                }
            }),
            Some(candidate_id),
            proof(),
        )
        .expect_err("unknown provider field must fail closed");
        assert_eq!(
            error.code,
            "workers.version_detail_binding_projection_invalid"
        );
        assert!(
            !serde_json::to_string(&error)
                .expect("serialize error")
                .contains("must-not-be-ignored")
        );
    }

    #[test]
    fn deployment_projection_rejects_non_total_weights() {
        let error = sanitize_deployments(&json!({
            "deployments":[{
                "id":"22222222-2222-4222-8222-222222222222",
                "versions":[{
                    "version_id":"11111111-1111-4111-8111-111111111111",
                    "percentage":99
                }]
            }]
        }))
        .expect_err("must fail");
        assert_eq!(error.code, "workers.version_deployment_weights_invalid");
    }

    #[tokio::test]
    async fn version_upload_posts_once_with_strict_query_and_redacted_evidence() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/accounts/acct-1/workers/scripts/worker-a/versions",
            post({
                let calls = calls.clone();
                move |Query(query): Query<HashMap<String, String>>,
                      headers: HeaderMap,
                      body: Bytes| {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(query.get("bindings_inherit").map(String::as_str), Some("strict"));
                        assert!(headers.get("authorization").is_some());
                        assert_eq!(
                            headers.get("accept-encoding").and_then(|value| value.to_str().ok()),
                            Some("identity")
                        );
                        assert!(headers
                            .get("content-type")
                            .and_then(|value| value.to_str().ok())
                            .is_some_and(|value| value.starts_with("multipart/form-data;")));
                        assert_eq!(body.as_ref(), b"reviewed-multipart");
                        Json(json!({
                            "success":true,
                            "errors":[],
                            "messages":[],
                            "result":{
                                "id":"11111111-1111-4111-8111-111111111111",
                                "resources":{
                                    "script":{"etag":"a".repeat(64)},
                                    "bindings":[{"name":"SECRET","type":"secret_text","text":"never-return"}]
                                }
                            }
                        }))
                    }
                }
            }),
        );
        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let evidence = client
            .upload_worker_version_once(
                "acct-1",
                "worker-a",
                "multipart/form-data; boundary=fixture",
                b"reviewed-multipart".to_vec(),
            )
            .await
            .expect("upload");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            evidence.candidate_version_id,
            "11111111-1111-4111-8111-111111111111"
        );
        let outward = serde_json::to_string(&evidence).expect("serialize");
        assert!(!outward.contains("never-return"));
        assert!(!outward.contains("fixture-worker-version-token"));
        assert_eq!(evidence.provider_proof.request_artifact_sha256.len(), 64);
        assert_eq!(evidence.provider_proof.response_artifact_sha256.len(), 64);
    }

    #[tokio::test]
    async fn malformed_success_is_ambiguous_and_never_retried() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/accounts/acct-1/workers/scripts/worker-a/versions",
            post({
                let calls = calls.clone();
                move || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Json(json!({
                            "success":true,
                            "errors":[],
                            "messages":[],
                            "result":null
                        }))
                    }
                }
            }),
        );
        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let error = client
            .upload_worker_version_once(
                "acct-1",
                "worker-a",
                "multipart/form-data; boundary=fixture",
                b"reviewed-multipart".to_vec(),
            )
            .await
            .expect_err("must be ambiguous");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(error.outcome_ambiguous);
        assert!(!error.retryable);
        assert!(error.request_artifact_sha256.is_some());
        assert!(error.response_artifact_sha256.is_some());
        assert_eq!(
            error.provider_request_lifecycle,
            super::worker_request_lifecycle(true, true, true)
        );
    }

    #[tokio::test]
    async fn duplicate_response_keys_are_ambiguous_and_never_retried() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/accounts/acct-1/workers/scripts/worker-a/versions",
            post({
                let calls = calls.clone();
                move || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        axum::response::Response::builder()
                            .header("content-type", "application/json")
                            .body(Body::from(
                                r#"{"success":true,"success":false,"errors":[],"result":{}}"#,
                            ))
                            .expect("duplicate-key response")
                    }
                }
            }),
        );
        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let error = client
            .upload_worker_version_once(
                "acct-1",
                "worker-a",
                "multipart/form-data; boundary=fixture",
                b"reviewed-multipart".to_vec(),
            )
            .await
            .expect_err("duplicate keys must be ambiguous");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(error.code, "workers.version_response_invalid");
        assert!(error.outcome_ambiguous);
        assert!(!error.retryable);
        assert_eq!(
            error.provider_request_lifecycle,
            super::worker_request_lifecycle(true, true, true)
        );
    }

    #[tokio::test]
    async fn malformed_upload_detail_retains_complete_response_lifecycle_and_proof() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/accounts/acct-1/workers/scripts/worker-a/versions",
            post({
                let calls = calls.clone();
                move || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Json(json!({
                            "success":true,
                            "errors":[],
                            "messages":[],
                            "result":{"resources":{"script":{"etag":"a".repeat(64)},"bindings":[]}}
                        }))
                    }
                }
            }),
        );
        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let error = client
            .upload_worker_version_once(
                "acct-1",
                "worker-a",
                "multipart/form-data; boundary=fixture",
                b"reviewed-multipart".to_vec(),
            )
            .await
            .expect_err("malformed detail must remain ambiguous");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(error.outcome_ambiguous);
        assert!(!error.retryable);
        assert_eq!(
            error.provider_request_lifecycle,
            super::worker_request_lifecycle(true, true, true)
        );
        assert!(error.request_artifact_sha256.is_some());
        assert!(error.response_artifact_sha256.is_some());
        assert!(error.response_body_sha256.is_some());
        assert_eq!(error.http_status, Some(200));
    }

    #[tokio::test]
    async fn stable_capture_is_bounded_and_detects_cross_target_detail() {
        let version_calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route(
                "/accounts/acct-1/workers/scripts/worker-a/versions",
                get({
                    let version_calls = version_calls.clone();
                    move |Query(query): Query<HashMap<String, String>>| {
                        let version_calls = version_calls.clone();
                        async move {
                            version_calls.fetch_add(1, Ordering::SeqCst);
                            let page = query.get("page").map(String::as_str).unwrap_or_default();
                            let items = if page == "1" {
                                vec![json!({"id":"11111111-1111-4111-8111-111111111111"})]
                            } else {
                                Vec::new()
                            };
                            Json(json!({"success":true,"errors":[],"messages":[],"result":{"items":items}}))
                        }
                    }
                }),
            )
            .route(
                "/accounts/acct-1/workers/scripts/worker-a/versions/11111111-1111-4111-8111-111111111111",
                get(|| async {
                    Json(json!({
                        "success":true,"errors":[],"messages":[],
                        "result":{
                            "id":"22222222-2222-4222-8222-222222222222",
                            "resources":{"script":{"etag":"a".repeat(64)},"bindings":[]}
                        }
                    }))
                }),
            )
            .route(
                "/accounts/acct-1/workers/scripts/worker-a/deployments",
                get(|| async {
                    Json(json!({"success":true,"errors":[],"messages":[],"result":{"deployments":[]}}))
                }),
            );
        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let error = client
            .capture_worker_version_state(
                "acct-1",
                "worker-a",
                100,
                Some("11111111-1111-4111-8111-111111111111"),
                None,
            )
            .await
            .expect_err("cross target must fail");
        assert_eq!(error.code, "workers.version_detail_cross_target");
        assert_eq!(version_calls.load(Ordering::SeqCst), 2);
    }
}
