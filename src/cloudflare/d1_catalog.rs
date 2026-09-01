//! Provider-owned custody for the staged D1 catalog evidence boundary.
//!
//! This module is the only path that may turn Cloudflare HTTP observations into
//! `D1CatalogObservationFrame`s. It preallocates four private identities, sends
//! the immutable catalog projection twice through a no-redirect, one-attempt
//! client, proves each complete bounded response at EOF, and retains exact
//! request bindings before constructing frames. It has no public tool route and
//! no mutation, DDL, graph, admission, deployment, or send capability.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::client::{
    CloudflareClient, DuplicateSafeJsonError, decode_json_rejecting_duplicate_object_keys,
};
use crate::d1_catalog_evidence::{
    D1CatalogEvidencePlan, D1CatalogObservationFrame, derive_d1_catalog_evidence_plan,
};
use crate::d1_target::D1TargetIdentity;

const D1_CATALOG_PROVIDER_CUSTODY_VERSION: u8 = 1;
const D1_CATALOG_PROVIDER_CUSTODY_OPERATION: &str = "d1_catalog_provider_custody";
const D1_CATALOG_PROJECTION_VERSION: u8 = 1;

static D1_CATALOG_ID_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1CatalogProviderCustodyClassification {
    PlanMismatch,
    IdentityAllocationFailed,
    IdentityInvalid,
    IdentityReused,
    RequestBindingMismatch,
    ResponseBindingMismatch,
    NetworkAmbiguous,
    HttpStatusUnavailable,
    ResponseBodyIncomplete,
    ResponseBodyLimitExceeded,
    ResponseDuplicateObjectKey,
    ResponseNestingLimitExceeded,
    ResponseMalformed,
    ProviderQueryUnsuccessful,
    ProviderNotPrimary,
    ProviderReportedMutation,
    ProviderResultTruncated,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1CatalogProviderCustodyError {
    pub(crate) code: &'static str,
    pub(crate) classification: D1CatalogProviderCustodyClassification,
    pub(crate) message: &'static str,
    pub(crate) retryable: bool,
    pub(crate) provider_calls: usize,
    pub(crate) complete_response_bodies: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1CatalogProviderCustodyReceipt {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) target_key_sha256: String,
    pub(crate) query_plan_sha256: String,
    pub(crate) query_sha256: String,
    pub(crate) provider_calls: usize,
    pub(crate) preallocated_dispatch_identities: usize,
    pub(crate) preallocated_read_identities: usize,
    pub(crate) complete_response_bodies: usize,
    pub(crate) primary_read_only_observations: usize,
    pub(crate) provider_row_cap: usize,
    pub(crate) provider_byte_cap: usize,
    pub(crate) provider_row_counts: [usize; 2],
    pub(crate) provider_response_body_sha256: [String; 2],
    pub(crate) provider_response_body_sizes: [usize; 2],
    pub(crate) projection_body_sizes: [usize; 2],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct D1CatalogProviderRequestBinding {
    target: D1TargetIdentity,
    target_key_sha256: String,
    query_plan_sha256: String,
    query_sha256: String,
    query: String,
    provider_row_cap: usize,
    provider_byte_cap: usize,
    dispatch_id: String,
    read_id: String,
}

impl D1CatalogProviderRequestBinding {
    fn matches_plan(
        &self,
        target: &D1TargetIdentity,
        plan: &D1CatalogEvidencePlan,
        plan_sha256: &str,
    ) -> bool {
        self.target == *target
            && self.target_key_sha256 == target.target_key_sha256()
            && self.query_plan_sha256 == plan_sha256
            && self.query_sha256 == plan.query_sha256
            && self.query == plan.query
            && self.provider_row_cap == plan.provider_row_cap
            && self.provider_byte_cap == plan.provider_byte_cap
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct D1CatalogProviderReadLifecycle {
    dispatch_attempted: bool,
    response_received: bool,
    body_complete: bool,
    http_status: Option<u16>,
}

impl D1CatalogProviderReadLifecycle {
    const fn pre_dispatch() -> Self {
        Self {
            dispatch_attempted: false,
            response_received: false,
            body_complete: false,
            http_status: None,
        }
    }

    const fn attempted_without_response() -> Self {
        Self {
            dispatch_attempted: true,
            response_received: false,
            body_complete: false,
            http_status: None,
        }
    }

    const fn response_received(http_status: u16) -> Self {
        Self {
            dispatch_attempted: true,
            response_received: true,
            body_complete: false,
            http_status: Some(http_status),
        }
    }

    const fn body_complete(http_status: u16) -> Self {
        Self {
            dispatch_attempted: true,
            response_received: true,
            body_complete: true,
            http_status: Some(http_status),
        }
    }

    const fn provider_calls(self) -> usize {
        self.dispatch_attempted as usize
    }

    const fn complete_response_bodies(self) -> usize {
        self.body_complete as usize
    }
}

#[derive(Debug, Clone)]
struct D1CatalogProviderObservation {
    binding: D1CatalogProviderRequestBinding,
    lifecycle: D1CatalogProviderReadLifecycle,
    provider_response_body_sha256: String,
    provider_response_body_size: usize,
    provider_row_count: usize,
    primary_read_only: bool,
    projection_body: Vec<u8>,
}

#[derive(Debug, Clone)]
struct D1CatalogOwnedObservation {
    dispatch_id: String,
    read_id: String,
    projection_body: Vec<u8>,
}

/// Owned custody product whose borrowed frames can be passed to the pure
/// verifier without exposing their private dispatch/read identities.
#[derive(Debug)]
pub(crate) struct D1CatalogProviderCustody {
    target: D1TargetIdentity,
    query_plan_sha256: String,
    observations: [D1CatalogOwnedObservation; 2],
    pub(crate) receipt: D1CatalogProviderCustodyReceipt,
}

impl D1CatalogProviderCustody {
    pub(crate) fn target(&self) -> &D1TargetIdentity {
        &self.target
    }

    pub(crate) fn query_plan_sha256(&self) -> &str {
        &self.query_plan_sha256
    }

    pub(crate) fn observation_frames(&self) -> [D1CatalogObservationFrame<'_>; 2] {
        self.observations.each_ref().map(|observation| {
            D1CatalogObservationFrame::from_adapter_observation(
                &self.target,
                &self.query_plan_sha256,
                &observation.dispatch_id,
                &observation.read_id,
                self.receipt.provider_row_cap,
                self.receipt.provider_byte_cap,
                true,
                observation.projection_body.len(),
                &observation.projection_body,
            )
        })
    }

    pub(crate) fn frames_and_receipt(
        &self,
    ) -> (
        [D1CatalogObservationFrame<'_>; 2],
        &D1CatalogProviderCustodyReceipt,
    ) {
        (self.observation_frames(), &self.receipt)
    }
}

#[allow(async_fn_in_trait)]
trait D1CatalogProviderBoundary {
    async fn read_catalog(
        &self,
        request: &D1CatalogProviderRequestBinding,
    ) -> Result<D1CatalogProviderObservation, D1CatalogProviderCustodyError>;
}

trait D1CatalogIdentitySource {
    fn allocate(
        &self,
        role: &'static str,
        target_key_sha256: &str,
        query_plan_sha256: &str,
    ) -> Result<String, D1CatalogProviderCustodyError>;
}

struct ProcessD1CatalogIdentitySource;

impl D1CatalogIdentitySource for ProcessD1CatalogIdentitySource {
    fn allocate(
        &self,
        role: &'static str,
        target_key_sha256: &str,
        query_plan_sha256: &str,
    ) -> Result<String, D1CatalogProviderCustodyError> {
        let sequence = D1_CATALOG_ID_SEQUENCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| {
                custody_error(
                    D1CatalogProviderCustodyClassification::IdentityAllocationFailed,
                    "catalog provider identity sequence was exhausted before dispatch",
                    D1CatalogProviderReadLifecycle::pre_dispatch(),
                )
            })?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                custody_error(
                    D1CatalogProviderCustodyClassification::IdentityAllocationFailed,
                    "catalog provider identity clock was unavailable before dispatch",
                    D1CatalogProviderReadLifecycle::pre_dispatch(),
                )
            })?
            .as_nanos();
        let process_id = std::process::id().to_be_bytes();
        let timestamp = timestamp.to_be_bytes();
        let sequence = sequence.to_be_bytes();
        let mut hasher = Sha256::new();
        for part in [
            role.as_bytes(),
            target_key_sha256.as_bytes(),
            query_plan_sha256.as_bytes(),
            &process_id,
            &timestamp,
            &sequence,
        ] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        let digest = format!("{:x}", hasher.finalize());
        Ok(format!("d1-cat-{role}-{}", &digest[..32]))
    }
}

/// Collect two physical observations for the exact plan. All four identities
/// are allocated and validated before either request can reach the provider.
pub(crate) async fn collect_d1_catalog_provider_custody(
    client: &CloudflareClient,
    target: &D1TargetIdentity,
    supplied_plan: &D1CatalogEvidencePlan,
    expected_plan_sha256: &str,
) -> Result<D1CatalogProviderCustody, D1CatalogProviderCustodyError> {
    collect_with_boundary(
        client,
        &ProcessD1CatalogIdentitySource,
        target,
        supplied_plan,
        expected_plan_sha256,
    )
    .await
}

async fn collect_with_boundary<P, I>(
    provider: &P,
    identities: &I,
    target: &D1TargetIdentity,
    supplied_plan: &D1CatalogEvidencePlan,
    expected_plan_sha256: &str,
) -> Result<D1CatalogProviderCustody, D1CatalogProviderCustodyError>
where
    P: D1CatalogProviderBoundary,
    I: D1CatalogIdentitySource,
{
    let (derived_plan, derived_plan_sha256) =
        derive_d1_catalog_evidence_plan(target).map_err(|_| {
            custody_error(
                D1CatalogProviderCustodyClassification::PlanMismatch,
                "catalog provider custody did not receive one canonical exact plan",
                D1CatalogProviderReadLifecycle::pre_dispatch(),
            )
        })?;
    if supplied_plan != &derived_plan || expected_plan_sha256 != derived_plan_sha256 {
        return Err(custody_error(
            D1CatalogProviderCustodyClassification::PlanMismatch,
            "catalog provider custody plan did not exactly rederive before dispatch",
            D1CatalogProviderReadLifecycle::pre_dispatch(),
        ));
    }

    let target_key_sha256 = target.target_key_sha256();
    let allocated = [
        identities.allocate("dispatch-first", &target_key_sha256, &derived_plan_sha256)?,
        identities.allocate("read-first", &target_key_sha256, &derived_plan_sha256)?,
        identities.allocate("dispatch-second", &target_key_sha256, &derived_plan_sha256)?,
        identities.allocate("read-second", &target_key_sha256, &derived_plan_sha256)?,
    ];
    validate_preallocated_identities(&allocated)?;

    let requests = [
        provider_request(
            target,
            &derived_plan,
            &derived_plan_sha256,
            allocated[0].clone(),
            allocated[1].clone(),
        ),
        provider_request(
            target,
            &derived_plan,
            &derived_plan_sha256,
            allocated[2].clone(),
            allocated[3].clone(),
        ),
    ];

    let first = provider.read_catalog(&requests[0]).await?;
    validate_provider_observation(
        &first,
        &requests[0],
        target,
        &derived_plan,
        &derived_plan_sha256,
    )?;
    let second = provider
        .read_catalog(&requests[1])
        .await
        .map_err(|mut error| {
            error.provider_calls = error.provider_calls.saturating_add(1);
            error.complete_response_bodies = error.complete_response_bodies.saturating_add(1);
            error
        })?;
    validate_provider_observation(
        &second,
        &requests[1],
        target,
        &derived_plan,
        &derived_plan_sha256,
    )
    .map_err(|mut error| {
        error.provider_calls = error.provider_calls.saturating_add(1);
        error.complete_response_bodies = error.complete_response_bodies.saturating_add(1);
        error
    })?;

    let receipt = D1CatalogProviderCustodyReceipt {
        version: D1_CATALOG_PROVIDER_CUSTODY_VERSION,
        operation: D1_CATALOG_PROVIDER_CUSTODY_OPERATION,
        target_key_sha256,
        query_plan_sha256: derived_plan_sha256.clone(),
        query_sha256: derived_plan.query_sha256.clone(),
        provider_calls: 2,
        preallocated_dispatch_identities: 2,
        preallocated_read_identities: 2,
        complete_response_bodies: 2,
        primary_read_only_observations: 2,
        provider_row_cap: derived_plan.provider_row_cap,
        provider_byte_cap: derived_plan.provider_byte_cap,
        provider_row_counts: [first.provider_row_count, second.provider_row_count],
        provider_response_body_sha256: [
            first.provider_response_body_sha256.clone(),
            second.provider_response_body_sha256.clone(),
        ],
        provider_response_body_sizes: [
            first.provider_response_body_size,
            second.provider_response_body_size,
        ],
        projection_body_sizes: [first.projection_body.len(), second.projection_body.len()],
    };
    Ok(D1CatalogProviderCustody {
        target: target.clone(),
        query_plan_sha256: derived_plan_sha256,
        observations: [
            D1CatalogOwnedObservation {
                dispatch_id: allocated[0].clone(),
                read_id: allocated[1].clone(),
                projection_body: first.projection_body,
            },
            D1CatalogOwnedObservation {
                dispatch_id: allocated[2].clone(),
                read_id: allocated[3].clone(),
                projection_body: second.projection_body,
            },
        ],
        receipt,
    })
}

fn provider_request(
    target: &D1TargetIdentity,
    plan: &D1CatalogEvidencePlan,
    plan_sha256: &str,
    dispatch_id: String,
    read_id: String,
) -> D1CatalogProviderRequestBinding {
    D1CatalogProviderRequestBinding {
        target: target.clone(),
        target_key_sha256: target.target_key_sha256(),
        query_plan_sha256: plan_sha256.to_string(),
        query_sha256: plan.query_sha256.clone(),
        query: plan.query.to_string(),
        provider_row_cap: plan.provider_row_cap,
        provider_byte_cap: plan.provider_byte_cap,
        dispatch_id,
        read_id,
    }
}

fn validate_preallocated_identities(
    identities: &[String; 4],
) -> Result<(), D1CatalogProviderCustodyError> {
    if identities
        .iter()
        .any(|identity| !canonical_observation_identity(identity))
    {
        return Err(custody_error(
            D1CatalogProviderCustodyClassification::IdentityInvalid,
            "catalog provider custody identity was not canonical bounded ASCII",
            D1CatalogProviderReadLifecycle::pre_dispatch(),
        ));
    }
    if identities.iter().collect::<BTreeSet<_>>().len() != identities.len() {
        return Err(custody_error(
            D1CatalogProviderCustodyClassification::IdentityReused,
            "catalog provider custody identities were not four distinct preallocated values",
            D1CatalogProviderReadLifecycle::pre_dispatch(),
        ));
    }
    Ok(())
}

fn canonical_observation_identity(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_provider_observation(
    observation: &D1CatalogProviderObservation,
    request: &D1CatalogProviderRequestBinding,
    target: &D1TargetIdentity,
    plan: &D1CatalogEvidencePlan,
    plan_sha256: &str,
) -> Result<(), D1CatalogProviderCustodyError> {
    if !request.matches_plan(target, plan, plan_sha256) {
        return Err(custody_error(
            D1CatalogProviderCustodyClassification::RequestBindingMismatch,
            "catalog provider request was not bound to the exact target, query and caps",
            D1CatalogProviderReadLifecycle::pre_dispatch(),
        ));
    }
    if observation.binding != *request {
        return Err(custody_error(
            D1CatalogProviderCustodyClassification::ResponseBindingMismatch,
            "catalog provider response was not bound to its exact request",
            observation.lifecycle,
        ));
    }
    if !observation.lifecycle.dispatch_attempted
        || !observation.lifecycle.response_received
        || !observation.lifecycle.body_complete
        || !observation
            .lifecycle
            .http_status
            .is_some_and(|status| (200..300).contains(&status))
    {
        return Err(custody_error(
            D1CatalogProviderCustodyClassification::ResponseBodyIncomplete,
            "catalog provider observation did not prove a successful complete response body",
            observation.lifecycle,
        ));
    }
    if observation.provider_response_body_size > plan.provider_byte_cap
        || observation.projection_body.len() > plan.provider_byte_cap
    {
        return Err(custody_error(
            D1CatalogProviderCustodyClassification::ResponseBodyLimitExceeded,
            "catalog provider observation exceeded the exact plan-bound byte cap",
            observation.lifecycle,
        ));
    }
    if !canonical_sha256(&observation.provider_response_body_sha256) {
        return Err(custody_error(
            D1CatalogProviderCustodyClassification::ResponseBindingMismatch,
            "catalog provider response did not retain one canonical complete-body digest",
            observation.lifecycle,
        ));
    }
    if observation.provider_row_count >= plan.provider_row_cap {
        return Err(custody_error(
            D1CatalogProviderCustodyClassification::ProviderResultTruncated,
            "catalog provider observation reached the exact row sentinel",
            observation.lifecycle,
        ));
    }
    if !observation.primary_read_only {
        return Err(custody_error(
            D1CatalogProviderCustodyClassification::ProviderNotPrimary,
            "catalog provider observation did not retain primary read-only evidence",
            observation.lifecycle,
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct D1CatalogProviderEnvelope {
    success: bool,
    result: Vec<D1CatalogProviderResultSet>,
    errors: Vec<D1CatalogProviderIssue>,
    #[serde(default)]
    messages: Vec<D1CatalogProviderIssue>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct D1CatalogProviderIssue {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct D1CatalogProviderResultSet {
    success: bool,
    results: Vec<D1CatalogProviderRow>,
    meta: D1CatalogProviderMetadata,
    errors: Vec<D1CatalogProviderIssue>,
}

#[derive(Debug, Deserialize)]
struct D1CatalogProviderMetadata {
    served_by_primary: bool,
    changed_db: bool,
    changes: u64,
    rows_written: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct D1CatalogProviderRow {
    object_type: String,
    object_name_hex: String,
    parent_name_hex: String,
    definition_is_null: u8,
    definition_hex: String,
}

#[derive(Debug, Serialize)]
struct D1CatalogProjectionPayload {
    version: u8,
    results_truncated: bool,
    meta: D1CatalogProjectionMetadata,
    rows: Vec<D1CatalogProviderRow>,
}

#[derive(Debug, Serialize)]
struct D1CatalogProjectionMetadata {
    query_succeeded: bool,
    served_by_primary: bool,
    changed_db: bool,
    changes: u64,
    rows_written: u64,
}

impl D1CatalogProviderBoundary for CloudflareClient {
    async fn read_catalog(
        &self,
        request: &D1CatalogProviderRequestBinding,
    ) -> Result<D1CatalogProviderObservation, D1CatalogProviderCustodyError> {
        let token = self.bearer_token().map_err(|_| {
            custody_error(
                D1CatalogProviderCustodyClassification::NetworkAmbiguous,
                "catalog provider credentials were unavailable before dispatch",
                D1CatalogProviderReadLifecycle::pre_dispatch(),
            )
        })?;
        let url = self.endpoint(&format!(
            "/accounts/{}/d1/database/{}/query",
            request.target.account_id, request.target.database_id
        ));
        let response = self
            .reconciliation_http
            .post(url)
            .bearer_auth(&token)
            .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
            .json(&serde_json::json!({"sql": request.query}))
            .send()
            .await
            .map_err(|error| {
                let lifecycle = if error.is_builder() {
                    D1CatalogProviderReadLifecycle::pre_dispatch()
                } else {
                    D1CatalogProviderReadLifecycle::attempted_without_response()
                };
                custody_error(
                    D1CatalogProviderCustodyClassification::NetworkAmbiguous,
                    "catalog provider request did not yield an authenticated response",
                    lifecycle,
                )
            })?;
        let status = response.status();
        let status_code = status.as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > request.provider_byte_cap as u64)
        {
            return Err(custody_error(
                D1CatalogProviderCustodyClassification::ResponseBodyLimitExceeded,
                "catalog provider response exceeded the exact plan-bound byte cap",
                D1CatalogProviderReadLifecycle::response_received(status_code),
            ));
        }

        let mut body = Vec::with_capacity(
            response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or(0)
                .min(request.provider_byte_cap),
        );
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| {
                custody_error(
                    D1CatalogProviderCustodyClassification::ResponseBodyIncomplete,
                    "catalog provider response body did not reach EOF",
                    D1CatalogProviderReadLifecycle::response_received(status_code),
                )
            })?;
            if body.len().saturating_add(chunk.len()) > request.provider_byte_cap {
                return Err(custody_error(
                    D1CatalogProviderCustodyClassification::ResponseBodyLimitExceeded,
                    "catalog provider response exceeded the exact plan-bound byte cap",
                    D1CatalogProviderReadLifecycle::response_received(status_code),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        let lifecycle = D1CatalogProviderReadLifecycle::body_complete(status_code);
        let provider_response_body_sha256 = format!("{:x}", Sha256::digest(&body));
        if !status.is_success() {
            return Err(custody_error(
                D1CatalogProviderCustodyClassification::HttpStatusUnavailable,
                "catalog provider response returned a non-success HTTP status",
                lifecycle,
            ));
        }

        let body = std::str::from_utf8(&body).map_err(|_| {
            custody_error(
                D1CatalogProviderCustodyClassification::ResponseMalformed,
                "catalog provider response was not valid bounded JSON evidence",
                lifecycle,
            )
        })?;
        let envelope = decode_json_rejecting_duplicate_object_keys(body).map_err(|error| {
            let (classification, message) = match error {
                DuplicateSafeJsonError::DuplicateObjectKey => (
                    D1CatalogProviderCustodyClassification::ResponseDuplicateObjectKey,
                    "catalog provider response contained a duplicate JSON object key",
                ),
                DuplicateSafeJsonError::NestingDepthExceeded => (
                    D1CatalogProviderCustodyClassification::ResponseNestingLimitExceeded,
                    "catalog provider response exceeded the shared JSON nesting limit",
                ),
                DuplicateSafeJsonError::Malformed(_) => (
                    D1CatalogProviderCustodyClassification::ResponseMalformed,
                    "catalog provider response was not valid bounded JSON evidence",
                ),
            };
            custody_error(classification, message, lifecycle)
        })?;
        let envelope: D1CatalogProviderEnvelope =
            serde_json::from_value(envelope).map_err(|_| {
                custody_error(
                    D1CatalogProviderCustodyClassification::ResponseMalformed,
                    "catalog provider response was not the exact bounded envelope",
                    lifecycle,
                )
            })?;
        let [result_set] = envelope.result.as_slice() else {
            return Err(custody_error(
                D1CatalogProviderCustodyClassification::ResponseMalformed,
                "catalog provider response did not contain exactly one result set",
                lifecycle,
            ));
        };
        if !envelope.success || !envelope.errors.is_empty() || !envelope.messages.is_empty() {
            return Err(custody_error(
                D1CatalogProviderCustodyClassification::ProviderQueryUnsuccessful,
                "catalog provider envelope did not prove one successful error-free query",
                lifecycle,
            ));
        }
        if !result_set.success || !result_set.errors.is_empty() {
            return Err(custody_error(
                D1CatalogProviderCustodyClassification::ProviderQueryUnsuccessful,
                "catalog provider result set did not prove one successful error-free query",
                lifecycle,
            ));
        }
        if !result_set.meta.served_by_primary {
            return Err(custody_error(
                D1CatalogProviderCustodyClassification::ProviderNotPrimary,
                "catalog provider result set did not prove primary service",
                lifecycle,
            ));
        }
        if result_set.meta.changed_db
            || result_set.meta.changes != 0
            || result_set.meta.rows_written != 0
        {
            return Err(custody_error(
                D1CatalogProviderCustodyClassification::ProviderReportedMutation,
                "catalog provider result set did not prove exact read-only metadata",
                lifecycle,
            ));
        }
        if result_set.results.len() >= request.provider_row_cap {
            return Err(custody_error(
                D1CatalogProviderCustodyClassification::ProviderResultTruncated,
                "catalog provider result set reached the exact row sentinel",
                lifecycle,
            ));
        }
        let projection_body = serde_json::to_vec(&D1CatalogProjectionPayload {
            version: D1_CATALOG_PROJECTION_VERSION,
            results_truncated: false,
            meta: D1CatalogProjectionMetadata {
                query_succeeded: true,
                served_by_primary: true,
                changed_db: false,
                changes: 0,
                rows_written: 0,
            },
            rows: result_set.results.clone(),
        })
        .expect("catalog projection serialization is infallible");
        if projection_body.len() > request.provider_byte_cap {
            return Err(custody_error(
                D1CatalogProviderCustodyClassification::ResponseBodyLimitExceeded,
                "catalog normalized projection exceeded the exact plan-bound byte cap",
                lifecycle,
            ));
        }

        Ok(D1CatalogProviderObservation {
            binding: request.clone(),
            lifecycle,
            provider_response_body_sha256,
            provider_response_body_size: body.len(),
            provider_row_count: result_set.results.len(),
            primary_read_only: true,
            projection_body,
        })
    }
}

fn custody_error(
    classification: D1CatalogProviderCustodyClassification,
    message: &'static str,
    lifecycle: D1CatalogProviderReadLifecycle,
) -> D1CatalogProviderCustodyError {
    D1CatalogProviderCustodyError {
        code: "d1.catalog_provider_custody_unproven",
        classification,
        message,
        retryable: false,
        provider_calls: lifecycle.provider_calls(),
        complete_response_bodies: lifecycle.complete_response_bodies(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::Json;
    use axum::Router;
    use axum::body::Body;
    use axum::extract::{OriginalUri, State};
    use axum::http::StatusCode;
    use axum::response::Response;
    use axum::routing::post;
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::cloudflare::client::D1_MIGRATION_JSON_MAX_CONTAINER_DEPTH;
    use crate::config::{ApiTokenSource, CloudflareApiConfig};
    use crate::d1_catalog_evidence::prove_d1_catalog_evidence;
    use crate::d1_target::normalize_d1_target;

    const DATABASE_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

    fn target() -> D1TargetIdentity {
        normalize_d1_target("acct-1", DATABASE_ID).expect("canonical target")
    }

    fn test_config(base_url: String) -> CloudflareApiConfig {
        CloudflareApiConfig {
            api_base_url: base_url,
            api_token: Some("fixture-api-value".to_string()),
            api_token_source: ApiTokenSource::Config,
            api_token_header: "x-cloudflare-api-token".to_string(),
            r2_access_key_id: None,
            r2_secret_access_key: None,
            r2_endpoint: None,
            default_account_id: Some("acct-1".to_string()),
            default_zone_id: None,
            request_timeout: Duration::from_secs(2),
            max_retries: 3,
            retry_base_delay: Duration::from_millis(1),
            retry_max_delay: Duration::from_millis(5),
            user_agent: "cloudflare-mcp-catalog-test".to_string(),
        }
    }

    async fn spawn_router(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        format!("http://{address}")
    }

    async fn spawn_raw_provider_body(body: String) -> String {
        async fn response(State(body): State<String>) -> Response {
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("raw provider response")
        }

        spawn_router(
            Router::new()
                .route(
                    &format!("/accounts/acct-1/d1/database/{DATABASE_ID}/query"),
                    post(response),
                )
                .with_state(body),
        )
        .await
    }

    fn exact_provider_body(
        outer_success_fields: &str,
        inner_success_fields: &str,
        result_errors_fragment: &str,
        metadata_fields: &str,
    ) -> String {
        format!(
            r#"{{{outer_success_fields},"errors":[],"messages":[],"result":[{{{inner_success_fields}{result_errors_fragment},"results":[],"meta":{{{metadata_fields}}}}}]}}"#
        )
    }

    fn primary_read_only_metadata(extra: &str) -> String {
        format!(
            r#""served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0{extra}"#
        )
    }

    async fn raw_provider_result(
        body: String,
    ) -> Result<D1CatalogProviderCustody, D1CatalogProviderCustodyError> {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let base = spawn_raw_provider_body(body).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        collect_d1_catalog_provider_custody(&client, &target, &plan, &plan_sha256).await
    }

    async fn raw_provider_error(body: String) -> D1CatalogProviderCustodyError {
        raw_provider_result(body)
            .await
            .expect_err("raw provider fixture must fail closed")
    }

    fn nested_array_json(container_depth: usize) -> String {
        format!(
            "{}0{}",
            "[".repeat(container_depth),
            "]".repeat(container_depth)
        )
    }

    fn provider_envelope(rows: Vec<Value>) -> Value {
        json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": [{
                "success": true,
                "errors": [],
                "results": rows,
                "meta": {
                    "served_by_primary": true,
                    "changed_db": false,
                    "changes": 0,
                    "rows_written": 0,
                    "duration": 0.25,
                    "rows_read": 1
                }
            }]
        })
    }

    fn provider_row(name: &str) -> Value {
        let hex = |value: &str| {
            value
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>()
        };
        json!({
            "object_type": "table",
            "object_name_hex": hex(name),
            "parent_name_hex": hex(name),
            "definition_is_null": 0,
            "definition_hex": hex("CREATE TABLE item (id INTEGER)")
        })
    }

    #[tokio::test]
    async fn exact_two_read_http_custody_constructs_verifier_frames() {
        #[derive(Clone)]
        struct FixtureState {
            plan_query: String,
            bodies: Arc<Mutex<Vec<Value>>>,
        }

        async fn query(
            State(state): State<FixtureState>,
            OriginalUri(uri): OriginalUri,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            assert_eq!(
                uri.path(),
                format!("/accounts/acct-1/d1/database/{DATABASE_ID}/query")
            );
            assert_eq!(body, json!({"sql": state.plan_query}));
            state.bodies.lock().expect("bodies").push(body);
            Json(provider_envelope(vec![provider_row("item")]))
        }

        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let state = FixtureState {
            plan_query: plan.query.to_string(),
            bodies: bodies.clone(),
        };
        let base = spawn_router(
            Router::new()
                .route(
                    &format!("/accounts/acct-1/d1/database/{DATABASE_ID}/query"),
                    post(query),
                )
                .with_state(state),
        )
        .await;
        let client = CloudflareClient::new(test_config(base)).expect("client");

        let custody = collect_d1_catalog_provider_custody(&client, &target, &plan, &plan_sha256)
            .await
            .expect("custody");
        let ([first, second], custody_receipt) = custody.frames_and_receipt();
        let evidence = prove_d1_catalog_evidence(
            custody.target(),
            &plan,
            custody.query_plan_sha256(),
            &first,
            &second,
        )
        .expect("pure evidence");

        assert_eq!(bodies.lock().expect("bodies").len(), 2);
        assert_eq!(custody_receipt.provider_calls, 2);
        assert_eq!(custody_receipt.complete_response_bodies, 2);
        assert_eq!(custody_receipt.primary_read_only_observations, 2);
        assert_eq!(custody_receipt.preallocated_dispatch_identities, 2);
        assert_eq!(custody_receipt.preallocated_read_identities, 2);
        assert_eq!(custody_receipt.provider_row_counts, [1, 1]);
        assert_eq!(
            custody_receipt.provider_response_body_sha256[0],
            custody_receipt.provider_response_body_sha256[1]
        );
        assert!(
            custody_receipt
                .provider_response_body_sha256
                .iter()
                .all(|digest| canonical_sha256(digest))
        );
        assert!(
            custody_receipt
                .provider_response_body_sizes
                .iter()
                .all(|size| *size > 0)
        );
        assert_eq!(evidence.stable_primary_observations, 2);
        let receipt_json = serde_json::to_value(custody_receipt).expect("receipt");
        assert!(receipt_json.get("dispatch_id").is_none());
        assert!(receipt_json.get("read_id").is_none());
        assert!(!receipt_json.to_string().contains("CREATE TABLE"));
    }

    struct ScriptedIdentities {
        values: Mutex<VecDeque<String>>,
    }

    impl D1CatalogIdentitySource for ScriptedIdentities {
        fn allocate(
            &self,
            _role: &'static str,
            _target_key_sha256: &str,
            _query_plan_sha256: &str,
        ) -> Result<String, D1CatalogProviderCustodyError> {
            Ok(self
                .values
                .lock()
                .expect("identities")
                .pop_front()
                .expect("identity"))
        }
    }

    #[derive(Clone, Copy)]
    enum MockMode {
        Valid,
        WrongTarget,
        WrongQuery,
    }

    struct MockProvider {
        mode: MockMode,
    }

    impl D1CatalogProviderBoundary for MockProvider {
        async fn read_catalog(
            &self,
            request: &D1CatalogProviderRequestBinding,
        ) -> Result<D1CatalogProviderObservation, D1CatalogProviderCustodyError> {
            let mut binding = request.clone();
            match self.mode {
                MockMode::Valid => {}
                MockMode::WrongTarget => {
                    binding.target.database_id = DATABASE_ID.replacen('1', "2", 1)
                }
                MockMode::WrongQuery => binding.query.push_str(" "),
            }
            let projection_body = serde_json::to_vec(&D1CatalogProjectionPayload {
                version: 1,
                results_truncated: false,
                meta: D1CatalogProjectionMetadata {
                    query_succeeded: true,
                    served_by_primary: true,
                    changed_db: false,
                    changes: 0,
                    rows_written: 0,
                },
                rows: Vec::new(),
            })
            .expect("projection");
            let provider_response_body_sha256 = format!("{:x}", Sha256::digest(&projection_body));
            Ok(D1CatalogProviderObservation {
                binding,
                lifecycle: D1CatalogProviderReadLifecycle::body_complete(200),
                provider_response_body_sha256,
                provider_response_body_size: projection_body.len(),
                provider_row_count: 0,
                primary_read_only: true,
                projection_body,
            })
        }
    }

    fn distinct_identities() -> ScriptedIdentities {
        ScriptedIdentities {
            values: Mutex::new(VecDeque::from([
                "dispatch-first-0001".to_string(),
                "read-first-00000001".to_string(),
                "dispatch-second-001".to_string(),
                "read-second-0000001".to_string(),
            ])),
        }
    }

    #[tokio::test]
    async fn wrong_target_or_query_response_binding_fails_closed() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        for mode in [MockMode::WrongTarget, MockMode::WrongQuery] {
            let error = collect_with_boundary(
                &MockProvider { mode },
                &distinct_identities(),
                &target,
                &plan,
                &plan_sha256,
            )
            .await
            .expect_err("binding drift must fail");
            assert_eq!(
                error.classification,
                D1CatalogProviderCustodyClassification::ResponseBindingMismatch
            );
            assert_eq!(error.provider_calls, 1);
            assert_eq!(error.complete_response_bodies, 1);
        }
    }

    #[tokio::test]
    async fn reused_or_invalid_identity_stops_before_provider_dispatch() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        for (values, expected) in [
            (
                [
                    "dispatch-first-0001",
                    "read-first-00000001",
                    "dispatch-first-0001",
                    "read-second-0000001",
                ],
                D1CatalogProviderCustodyClassification::IdentityReused,
            ),
            (
                [
                    "short",
                    "read-first-00000001",
                    "dispatch-second-001",
                    "read-second-0000001",
                ],
                D1CatalogProviderCustodyClassification::IdentityInvalid,
            ),
        ] {
            let identities = ScriptedIdentities {
                values: Mutex::new(values.into_iter().map(str::to_string).collect()),
            };
            let error = collect_with_boundary(
                &MockProvider {
                    mode: MockMode::Valid,
                },
                &identities,
                &target,
                &plan,
                &plan_sha256,
            )
            .await
            .expect_err("identity failure");
            assert_eq!(error.classification, expected);
            assert_eq!(error.provider_calls, 0);
        }
    }

    #[tokio::test]
    async fn non_primary_mutating_and_malformed_provider_responses_fail_closed() {
        async fn response(State(body): State<Value>) -> Json<Value> {
            Json(body)
        }

        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let mut cases = Vec::new();
        let mut non_primary = provider_envelope(Vec::new());
        non_primary["result"][0]["meta"]["served_by_primary"] = json!(false);
        cases.push((
            non_primary,
            D1CatalogProviderCustodyClassification::ProviderNotPrimary,
        ));
        let mut mutating = provider_envelope(Vec::new());
        mutating["result"][0]["meta"]["changed_db"] = json!(true);
        mutating["result"][0]["meta"]["changes"] = json!(1);
        cases.push((
            mutating,
            D1CatalogProviderCustodyClassification::ProviderReportedMutation,
        ));
        let mut malformed = provider_envelope(Vec::new());
        malformed["result"][0]["meta"]["served_by_primary"] = json!("true");
        cases.push((
            malformed,
            D1CatalogProviderCustodyClassification::ResponseMalformed,
        ));

        for (body, expected) in cases {
            let base = spawn_router(
                Router::new()
                    .route(
                        &format!("/accounts/acct-1/d1/database/{DATABASE_ID}/query"),
                        post(response),
                    )
                    .with_state(body),
            )
            .await;
            let client = CloudflareClient::new(test_config(base)).expect("client");
            let error = collect_d1_catalog_provider_custody(&client, &target, &plan, &plan_sha256)
                .await
                .expect_err("provider evidence must fail");
            assert_eq!(error.classification, expected);
            assert_eq!(error.provider_calls, 1);
            assert_eq!(error.complete_response_bodies, 1);
            let error_json = serde_json::to_string(&error).expect("error");
            assert!(!error_json.contains("served_by_primary"));
            assert!(!error_json.contains("dispatch-first"));
        }
    }

    #[tokio::test]
    async fn top_level_and_nested_duplicate_authority_keys_fail_closed_in_both_orders() {
        let clean_meta = primary_read_only_metadata("");
        let mut bodies = vec![
            exact_provider_body(
                r#""success":false,"success":true"#,
                r#""success":true"#,
                r#","errors":[]"#,
                &clean_meta,
            ),
            exact_provider_body(
                r#""success":true,"success":false"#,
                r#""success":true"#,
                r#","errors":[]"#,
                &clean_meta,
            ),
            exact_provider_body(
                r#""success":true"#,
                r#""success":false,"success":true"#,
                r#","errors":[]"#,
                &clean_meta,
            ),
            exact_provider_body(
                r#""success":true"#,
                r#""success":true,"success":false"#,
                r#","errors":[]"#,
                &clean_meta,
            ),
        ];
        for metadata in [
            r#""served_by_primary":false,"served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0"#,
            r#""served_by_primary":true,"served_by_primary":false,"changed_db":false,"changes":0,"rows_written":0"#,
            r#""served_by_primary":true,"changed_db":true,"changed_db":false,"changes":0,"rows_written":0"#,
            r#""served_by_primary":true,"changed_db":false,"changed_db":true,"changes":0,"rows_written":0"#,
            r#""served_by_primary":true,"changed_db":false,"changes":1,"changes":0,"rows_written":0"#,
            r#""served_by_primary":true,"changed_db":false,"changes":0,"changes":1,"rows_written":0"#,
            r#""served_by_primary":true,"changed_db":false,"changes":0,"rows_written":1,"rows_written":0"#,
            r#""served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0,"rows_written":1"#,
        ] {
            bodies.push(exact_provider_body(
                r#""success":true"#,
                r#""success":true"#,
                r#","errors":[]"#,
                metadata,
            ));
        }

        for body in bodies {
            let error = raw_provider_error(body).await;
            assert_eq!(
                error.classification,
                D1CatalogProviderCustodyClassification::ResponseDuplicateObjectKey
            );
            assert_eq!(error.provider_calls, 1);
            assert_eq!(error.complete_response_bodies, 1);
            let error_json = serde_json::to_string(&error).expect("error");
            assert!(!error_json.contains("served_by_primary"));
            assert!(!error_json.contains("rows_written"));
        }
    }

    #[tokio::test]
    async fn result_set_errors_must_be_present_typed_and_empty() {
        let metadata = primary_read_only_metadata("");
        for fragment in [
            "",
            r#","errors":null"#,
            r#","errors":{}"#,
            r#","errors":"empty""#,
        ] {
            let body = exact_provider_body(
                r#""success":true"#,
                r#""success":true"#,
                fragment,
                &metadata,
            );
            let error = raw_provider_error(body).await;
            assert_eq!(
                error.classification,
                D1CatalogProviderCustodyClassification::ResponseMalformed
            );
        }

        let body = exact_provider_body(
            r#""success":true"#,
            r#""success":true"#,
            r#","errors":[{"code":7500,"message":"private fixture detail"}]"#,
            &metadata,
        );
        let error = raw_provider_error(body).await;
        assert_eq!(
            error.classification,
            D1CatalogProviderCustodyClassification::ProviderQueryUnsuccessful
        );
        assert!(
            !serde_json::to_string(&error)
                .expect("error")
                .contains("private fixture detail")
        );
    }

    #[tokio::test]
    async fn shared_json_depth_limit_accepts_the_limit_and_rejects_one_more() {
        let at_limit_nesting = D1_MIGRATION_JSON_MAX_CONTAINER_DEPTH - 4;
        let at_limit = exact_provider_body(
            r#""success":true"#,
            r#""success":true"#,
            r#","errors":[]"#,
            &primary_read_only_metadata(&format!(
                r#","bounded_extension":{}"#,
                nested_array_json(at_limit_nesting)
            )),
        );
        decode_json_rejecting_duplicate_object_keys(&at_limit)
            .expect("provider envelope at the shared limit must decode");
        let custody = raw_provider_result(at_limit)
            .await
            .expect("provider envelope at the shared limit must retain custody");
        assert_eq!(custody.receipt.complete_response_bodies, 2);

        let over_limit = exact_provider_body(
            r#""success":true"#,
            r#""success":true"#,
            r#","errors":[]"#,
            &primary_read_only_metadata(&format!(
                r#","bounded_extension":{}"#,
                nested_array_json(at_limit_nesting + 1)
            )),
        );
        assert!(matches!(
            decode_json_rejecting_duplicate_object_keys(&over_limit),
            Err(DuplicateSafeJsonError::NestingDepthExceeded)
        ));
        let error = raw_provider_error(over_limit).await;
        assert_eq!(
            error.classification,
            D1CatalogProviderCustodyClassification::ResponseNestingLimitExceeded
        );
        assert_eq!(error.provider_calls, 1);
        assert_eq!(error.complete_response_bodies, 1);
    }

    #[tokio::test]
    async fn row_sentinel_and_body_cap_fail_closed_without_second_call() {
        async fn rows() -> Json<Value> {
            Json(provider_envelope(
                (0..1_001)
                    .map(|index| provider_row(&format!("item_{index:04}")))
                    .collect(),
            ))
        }
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let base = spawn_router(Router::new().route(
            &format!("/accounts/acct-1/d1/database/{DATABASE_ID}/query"),
            post(rows),
        ))
        .await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let error = collect_d1_catalog_provider_custody(&client, &target, &plan, &plan_sha256)
            .await
            .expect_err("sentinel");
        assert_eq!(
            error.classification,
            D1CatalogProviderCustodyClassification::ProviderResultTruncated
        );
        assert_eq!(error.provider_calls, 1);

        async fn oversized() -> Response {
            let body = vec![b'x'; 4 * 1024 * 1024 + 1];
            Response::builder()
                .status(StatusCode::OK)
                .header("content-length", body.len().to_string())
                .body(Body::from(body))
                .expect("response")
        }
        let base = spawn_router(Router::new().route(
            &format!("/accounts/acct-1/d1/database/{DATABASE_ID}/query"),
            post(oversized),
        ))
        .await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let error = collect_d1_catalog_provider_custody(&client, &target, &plan, &plan_sha256)
            .await
            .expect_err("body cap");
        assert_eq!(
            error.classification,
            D1CatalogProviderCustodyClassification::ResponseBodyLimitExceeded
        );
        assert_eq!(error.provider_calls, 1);
        assert_eq!(error.complete_response_bodies, 0);
    }

    #[tokio::test]
    async fn transport_loss_and_truncated_body_are_ambiguous_without_retry() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");

        let refused = format!("http://{}:9", std::net::Ipv4Addr::LOCALHOST);
        let client = CloudflareClient::new(test_config(refused)).expect("client");
        let error = collect_d1_catalog_provider_custody(&client, &target, &plan, &plan_sha256)
            .await
            .expect_err("transport loss");
        assert_eq!(
            error.classification,
            D1CatalogProviderCustodyClassification::NetworkAmbiguous
        );
        assert_eq!(error.provider_calls, 1);
        assert!(!error.retryable);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = vec![0_u8; 8 * 1024];
            let _ = stream.read(&mut request).await.expect("read");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: 64\r\n\r\n{",
                )
                .await
                .expect("write partial response");
        });
        let client =
            CloudflareClient::new(test_config(format!("http://{address}"))).expect("client");
        let error = collect_d1_catalog_provider_custody(&client, &target, &plan, &plan_sha256)
            .await
            .expect_err("truncated response");
        assert_eq!(
            error.classification,
            D1CatalogProviderCustodyClassification::ResponseBodyIncomplete
        );
        assert_eq!(error.provider_calls, 1);
        assert_eq!(error.complete_response_bodies, 0);
    }
}
