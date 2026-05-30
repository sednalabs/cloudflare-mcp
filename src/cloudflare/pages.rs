use reqwest::multipart::{Form, Part};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::cloudflare::client::{CloudflareClient, CloudflareEnvelope, RetryPolicy};
use crate::cloudflare::model::{
    Page, PagesDeployment, PagesDeploymentTriggerRequest, PagesDomain, PagesProject,
};
use crate::cloudflare::{AdapterError, PageInfo};
use crate::pages_deploy::{
    PagesAssetFile, PagesDirectoryError, PagesDirectoryPackage, PagesSpecialFiles,
    chunk_pages_assets, read_asset_base64,
};

#[derive(Debug, Deserialize)]
struct PagesUploadToken {
    jwt: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PagesDirectUploadResult {
    pub(crate) deployment: PagesDeployment,
    pub(crate) upload: PagesDirectUploadSummary,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PagesDirectUploadSummary {
    pub(crate) skip_caching: bool,
    pub(crate) requested_asset_count: usize,
    pub(crate) uploaded_asset_count: usize,
    pub(crate) cached_asset_count: usize,
    pub(crate) batch_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cache_update_warning: Option<crate::cloudflare::AdapterErrorPayload>,
}

impl CloudflareClient {
    pub async fn list_pages_projects(
        &self,
        account_id: &str,
        page: u32,
        per_page: u32,
    ) -> Result<Page<PagesProject>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/accounts/{account_id}/pages/projects"));

        let envelope: CloudflareEnvelope<Vec<PagesProject>> = self
            .send_envelope(
                "cloudflare.pages.projects.list",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .query(&[("page", page), ("per_page", per_page)])
                },
            )
            .await?;

        Ok(Page {
            items: envelope.result.unwrap_or_default(),
            page_info: envelope.result_info,
        })
    }

    pub async fn get_pages_project(
        &self,
        account_id: &str,
        project_name: &str,
    ) -> Result<PagesProject, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let project_name = require_non_empty("project_name", project_name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/pages/projects/{}",
            path_segment(project_name)
        ));

        let envelope: CloudflareEnvelope<PagesProject> = self
            .send_envelope(
                "cloudflare.pages.projects.get",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a Pages project result",
                "Verify Pages project response schema.",
            )
        })
    }

    pub async fn update_pages_project(
        &self,
        account_id: &str,
        project_name: &str,
        settings: &Value,
    ) -> Result<PagesProject, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let project_name = require_non_empty("project_name", project_name)?;
        require_non_empty_object("settings", settings)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/pages/projects/{}",
            path_segment(project_name)
        ));

        let envelope: CloudflareEnvelope<PagesProject> = self
            .send_envelope(
                "cloudflare.pages.projects.update",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .patch(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(settings)
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a Pages project update result",
                "Verify Pages project update response schema.",
            )
        })
    }

    pub async fn list_pages_deployments(
        &self,
        account_id: &str,
        project_name: &str,
        environment: Option<&str>,
        page: u32,
        per_page: u32,
    ) -> Result<Page<PagesDeployment>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let project_name = require_non_empty("project_name", project_name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/pages/projects/{}/deployments",
            path_segment(project_name)
        ));
        let environment = environment
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);

        let envelope: CloudflareEnvelope<Vec<PagesDeployment>> = self
            .send_envelope(
                "cloudflare.pages.deployments.list",
                RetryPolicy::Idempotent,
                || {
                    let builder = self
                        .http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .query(&[("page", page), ("per_page", per_page)]);
                    if let Some(environment) = environment.as_deref() {
                        builder.query(&[("env", environment)])
                    } else {
                        builder
                    }
                },
            )
            .await?;

        let items = envelope.result.unwrap_or_default();
        let page_info = envelope.result_info.or_else(|| {
            Some(PageInfo {
                page: Some(page),
                per_page: Some(per_page),
                count: Some(items.len() as u32),
                total_count: None,
                total_pages: None,
            })
        });
        Ok(Page { items, page_info })
    }

    pub async fn get_pages_deployment(
        &self,
        account_id: &str,
        project_name: &str,
        deployment_id: &str,
    ) -> Result<PagesDeployment, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let project_name = require_non_empty("project_name", project_name)?;
        let deployment_id = require_non_empty("deployment_id", deployment_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/pages/projects/{}/deployments/{}",
            path_segment(project_name),
            path_segment(deployment_id)
        ));

        let envelope: CloudflareEnvelope<PagesDeployment> = self
            .send_envelope(
                "cloudflare.pages.deployments.get",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a Pages deployment result",
                "Verify Pages deployment response schema.",
            )
        })
    }

    pub async fn trigger_pages_deployment(
        &self,
        account_id: &str,
        project_name: &str,
        request: &PagesDeploymentTriggerRequest,
    ) -> Result<PagesDeployment, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let project_name = require_non_empty("project_name", project_name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/pages/projects/{}/deployments",
            path_segment(project_name)
        ));

        let envelope: CloudflareEnvelope<PagesDeployment> = self
            .send_envelope(
                "cloudflare.pages.deployments.create",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .post(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .multipart(pages_deployment_trigger_form(request))
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a Pages deployment create result",
                "Verify Pages deployment create response schema.",
            )
        })
    }

    pub(crate) async fn get_pages_upload_token(
        &self,
        account_id: &str,
        project_name: &str,
    ) -> Result<String, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let project_name = require_non_empty("project_name", project_name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/pages/projects/{}/upload-token",
            path_segment(project_name)
        ));

        let envelope: CloudflareEnvelope<PagesUploadToken> = self
            .send_envelope(
                "cloudflare.pages.upload_token.get",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;

        let result = envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a Pages upload token",
                "Verify Pages direct-upload token response schema.",
            )
        })?;
        require_non_empty("jwt", &result.jwt).map(str::to_string)
    }

    pub(crate) async fn check_missing_pages_assets(
        &self,
        upload_token: &str,
        hashes: &[String],
    ) -> Result<Vec<String>, AdapterError> {
        let upload_token = require_non_empty("upload_token", upload_token)?;
        let url = self.endpoint("/pages/assets/check-missing");
        let body = json!({ "hashes": hashes });

        let envelope: CloudflareEnvelope<Vec<String>> = self
            .send_envelope(
                "cloudflare.pages.assets.check_missing",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .post(url.clone())
                        .bearer_auth(upload_token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&body)
                },
            )
            .await?;

        Ok(envelope.result.unwrap_or_default())
    }

    pub(crate) async fn upload_pages_assets(
        &self,
        upload_token: &str,
        assets: &[PagesAssetFile],
    ) -> Result<(), AdapterError> {
        let upload_token = require_non_empty("upload_token", upload_token)?;
        let url = self.endpoint("/pages/assets/upload");
        let payload = pages_asset_upload_payload(assets)?;

        let _envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.pages.assets.upload",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .post(url.clone())
                        .bearer_auth(upload_token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&payload)
                },
            )
            .await?;

        Ok(())
    }

    pub(crate) async fn upsert_pages_asset_hashes(
        &self,
        upload_token: &str,
        hashes: &[String],
    ) -> Result<(), AdapterError> {
        let upload_token = require_non_empty("upload_token", upload_token)?;
        let url = self.endpoint("/pages/assets/upsert-hashes");
        let body = json!({ "hashes": hashes });

        let _envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.pages.assets.upsert_hashes",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .post(url.clone())
                        .bearer_auth(upload_token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&body)
                },
            )
            .await?;

        Ok(())
    }

    pub(crate) async fn create_pages_direct_upload_deployment(
        &self,
        account_id: &str,
        project_name: &str,
        manifest: &std::collections::BTreeMap<String, String>,
        request: &PagesDeploymentTriggerRequest,
        special_files: &PagesSpecialFiles,
    ) -> Result<PagesDeployment, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let project_name = require_non_empty("project_name", project_name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/pages/projects/{}/deployments",
            path_segment(project_name)
        ));
        let manifest = serde_json::to_string(manifest).map_err(|err| {
            AdapterError::new(
                "cloudflare.invalid_argument",
                format!("failed serializing Pages deployment manifest: {err}"),
                "Retry with a normal Pages deployment directory.",
            )
        })?;
        let special_files = read_pages_special_files(special_files)?;

        let envelope: CloudflareEnvelope<PagesDeployment> = self
            .send_envelope(
                "cloudflare.pages.deployments.direct_upload",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .post(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .multipart(pages_direct_upload_deployment_form(
                            manifest.clone(),
                            request,
                            special_files.clone(),
                        ))
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a Pages direct-upload deployment result",
                "Verify Pages deployment create response schema.",
            )
        })
    }

    pub(crate) async fn deploy_pages_directory_direct_upload(
        &self,
        account_id: &str,
        project_name: &str,
        package: &PagesDirectoryPackage,
        request: &PagesDeploymentTriggerRequest,
        skip_caching: bool,
    ) -> Result<PagesDirectUploadResult, AdapterError> {
        let upload_token = self
            .get_pages_upload_token(account_id, project_name)
            .await?;
        let hashes = package.hashes();
        let missing_hashes = if skip_caching {
            hashes.clone()
        } else {
            self.check_missing_pages_assets(&upload_token, &hashes)
                .await?
        };
        let assets_to_upload = package.assets_for_hashes(&missing_hashes);
        let batches = chunk_pages_assets(&assets_to_upload);
        for batch in &batches {
            self.upload_pages_assets(&upload_token, batch).await?;
        }

        let cache_update_warning = if hashes.is_empty() {
            None
        } else {
            self.upsert_pages_asset_hashes(&upload_token, &hashes)
                .await
                .err()
                .map(|err| err.payload())
        };
        let deployment = self
            .create_pages_direct_upload_deployment(
                account_id,
                project_name,
                &package.manifest,
                request,
                &package.special_files,
            )
            .await?;

        Ok(PagesDirectUploadResult {
            deployment,
            upload: PagesDirectUploadSummary {
                skip_caching,
                requested_asset_count: hashes.len(),
                uploaded_asset_count: assets_to_upload.len(),
                cached_asset_count: hashes.len().saturating_sub(assets_to_upload.len()),
                batch_count: batches.len(),
                cache_update_warning,
            },
        })
    }

    pub async fn retry_pages_deployment(
        &self,
        account_id: &str,
        project_name: &str,
        deployment_id: &str,
    ) -> Result<PagesDeployment, AdapterError> {
        self.deployment_action(
            "cloudflare.pages.deployments.retry",
            account_id,
            project_name,
            deployment_id,
            "retry",
        )
        .await
    }

    pub async fn rollback_pages_deployment(
        &self,
        account_id: &str,
        project_name: &str,
        deployment_id: &str,
    ) -> Result<PagesDeployment, AdapterError> {
        self.deployment_action(
            "cloudflare.pages.deployments.rollback",
            account_id,
            project_name,
            deployment_id,
            "rollback",
        )
        .await
    }

    async fn deployment_action(
        &self,
        operation: &'static str,
        account_id: &str,
        project_name: &str,
        deployment_id: &str,
        action: &str,
    ) -> Result<PagesDeployment, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let project_name = require_non_empty("project_name", project_name)?;
        let deployment_id = require_non_empty("deployment_id", deployment_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/pages/projects/{}/deployments/{}/{}",
            path_segment(project_name),
            path_segment(deployment_id),
            action
        ));

        let envelope: CloudflareEnvelope<PagesDeployment> = self
            .send_envelope(operation, RetryPolicy::NonIdempotent, || {
                self.http
                    .post(url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                    .json(&json!({}))
            })
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                format!("Cloudflare returned success without a Pages deployment {action} result"),
                "Verify Pages deployment action response schema.",
            )
        })
    }

    pub async fn list_pages_domains(
        &self,
        account_id: &str,
        project_name: &str,
    ) -> Result<Vec<PagesDomain>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let project_name = require_non_empty("project_name", project_name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/pages/projects/{}/domains",
            path_segment(project_name)
        ));

        let envelope: CloudflareEnvelope<Vec<PagesDomain>> = self
            .send_envelope(
                "cloudflare.pages.domains.list",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;

        Ok(envelope.result.unwrap_or_default())
    }

    pub async fn get_pages_domain(
        &self,
        account_id: &str,
        project_name: &str,
        domain_name: &str,
    ) -> Result<PagesDomain, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let project_name = require_non_empty("project_name", project_name)?;
        let domain_name = require_non_empty("domain_name", domain_name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/pages/projects/{}/domains/{}",
            path_segment(project_name),
            path_segment(domain_name)
        ));

        let envelope: CloudflareEnvelope<PagesDomain> = self
            .send_envelope(
                "cloudflare.pages.domains.get",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a Pages domain result",
                "Verify Pages domain response schema.",
            )
        })
    }

    pub async fn add_pages_domain(
        &self,
        account_id: &str,
        project_name: &str,
        domain_name: &str,
    ) -> Result<PagesDomain, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let project_name = require_non_empty("project_name", project_name)?;
        let domain_name = require_non_empty("domain_name", domain_name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/pages/projects/{}/domains",
            path_segment(project_name)
        ));

        let envelope: CloudflareEnvelope<PagesDomain> = self
            .send_envelope(
                "cloudflare.pages.domains.create",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .post(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&json!({ "name": domain_name }))
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a Pages domain create result",
                "Verify Pages domain create response schema.",
            )
        })
    }

    pub async fn retry_pages_domain_validation(
        &self,
        account_id: &str,
        project_name: &str,
        domain_name: &str,
    ) -> Result<PagesDomain, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let project_name = require_non_empty("project_name", project_name)?;
        let domain_name = require_non_empty("domain_name", domain_name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/pages/projects/{}/domains/{}",
            path_segment(project_name),
            path_segment(domain_name)
        ));

        let envelope: CloudflareEnvelope<PagesDomain> = self
            .send_envelope(
                "cloudflare.pages.domains.retry_validation",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .patch(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&json!({}))
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a Pages domain validation result",
                "Verify Pages domain validation response schema.",
            )
        })
    }
}

fn pages_deployment_trigger_form(request: &PagesDeploymentTriggerRequest) -> Form {
    let mut form = Form::new();
    if let Some(branch) = request
        .branch
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        form = form.text("branch", branch.to_string());
    }
    if let Some(commit_hash) = request
        .commit_hash
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        form = form.text("commit_hash", commit_hash.to_string());
    }
    if let Some(commit_message) = request
        .commit_message
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        form = form.text("commit_message", commit_message.to_string());
    }
    if let Some(commit_dirty) = request.commit_dirty {
        form = form.text("commit_dirty", commit_dirty.to_string());
    }
    form
}

#[derive(Clone)]
struct PagesSpecialFileBytes {
    form_name: &'static str,
    file_name: &'static str,
    bytes: Vec<u8>,
}

fn pages_asset_upload_payload(assets: &[PagesAssetFile]) -> Result<Vec<Value>, AdapterError> {
    assets
        .iter()
        .map(|asset| {
            let value = read_asset_base64(asset).map_err(pages_directory_error)?;
            Ok(json!({
                "key": asset.hash,
                "value": value,
                "metadata": {
                    "contentType": asset.content_type,
                },
                "base64": true,
            }))
        })
        .collect()
}

fn read_pages_special_files(
    special_files: &PagesSpecialFiles,
) -> Result<Vec<PagesSpecialFileBytes>, AdapterError> {
    let mut files = Vec::new();
    for file in [
        special_files.headers.as_ref(),
        special_files.redirects.as_ref(),
        special_files.routes.as_ref(),
        special_files.worker.as_ref(),
        special_files.worker_bundle.as_ref(),
        special_files.functions_filepath_routing_config.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        files.push(PagesSpecialFileBytes {
            form_name: file.form_name,
            file_name: file.file_name,
            bytes: file.read_bytes().map_err(pages_directory_error)?,
        });
    }
    Ok(files)
}

fn pages_direct_upload_deployment_form(
    manifest: String,
    request: &PagesDeploymentTriggerRequest,
    special_files: Vec<PagesSpecialFileBytes>,
) -> Form {
    let mut form = pages_deployment_trigger_form(request).text("manifest", manifest);
    for file in special_files {
        form = form.part(
            file.form_name,
            Part::bytes(file.bytes).file_name(file.file_name),
        );
    }
    form
}

fn pages_directory_error(err: PagesDirectoryError) -> AdapterError {
    AdapterError::new(err.code, err.message, err.hint)
}

pub(crate) fn path_segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn require_non_empty<'a>(name: &'static str, value: &'a str) -> Result<&'a str, AdapterError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AdapterError::new(
            "cloudflare.invalid_argument",
            format!("{name} must not be empty"),
            "Provide a non-empty identifier.",
        ));
    }
    Ok(trimmed)
}

fn require_non_empty_object(name: &'static str, value: &Value) -> Result<(), AdapterError> {
    match value.as_object() {
        Some(object) if !object.is_empty() => Ok(()),
        _ => Err(AdapterError::new(
            "cloudflare.invalid_argument",
            format!("{name} must be a non-empty JSON object"),
            "Provide at least one Pages project setting to update.",
        )),
    }
}
