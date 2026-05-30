use serde_json::{Value, json};

use crate::cloudflare::client::{CloudflareClient, CloudflareEnvelope, RetryPolicy};
use crate::cloudflare::model::CapabilityProbe;

impl CloudflareClient {
    pub async fn check_capabilities(
        &self,
        account_id: Option<&str>,
        zone_id: Option<&str>,
    ) -> Vec<CapabilityProbe> {
        let mut probes = Vec::new();

        probes.push(
            self.probe_zone_get("dns", zone_id, "DNS Read or DNS Write", |zone_id| {
                format!("/zones/{zone_id}/dns_records?type=CNAME&per_page=1")
            })
            .await,
        );
        probes.push(
            self.probe_account_get(
                "tunnels",
                account_id,
                "Cloudflare Tunnel Read or Cloudflare Tunnel Write",
                |account_id| format!("/accounts/{account_id}/cfd_tunnel?per_page=1"),
            )
            .await,
        );
        probes.push(
            self.probe_account_get(
                "access_apps",
                account_id,
                "Access: Apps and Policies Read or Write",
                |account_id| format!("/accounts/{account_id}/access/apps?per_page=1"),
            )
            .await,
        );
        probes.push(
            self.probe_account_get(
                "pages",
                account_id,
                "Pages Read or Pages Write",
                |account_id| format!("/accounts/{account_id}/pages/projects?per_page=1"),
            )
            .await,
        );
        probes.push(
            self.probe_account_get("d1", account_id, "D1 Read or D1 Write", |account_id| {
                format!("/accounts/{account_id}/d1/database?per_page=1")
            })
            .await,
        );
        probes.push(
            self.probe_account_get(
                "queues",
                account_id,
                "Queues Read, Queues Write, Workers Scripts Read, or Workers Scripts Write",
                |account_id| format!("/accounts/{account_id}/queues"),
            )
            .await,
        );
        probes.push(
            self.probe_account_get(
                "workers_scripts",
                account_id,
                "Workers Scripts Read or Workers Scripts Write",
                |account_id| format!("/accounts/{account_id}/workers/scripts"),
            )
            .await,
        );
        probes.push(
            self.probe_account_post(
                "workers_observability",
                account_id,
                "Workers Observability Write",
                |account_id| format!("/accounts/{account_id}/workers/observability/telemetry/keys"),
                json!({}),
            )
            .await,
        );
        probes.push(
            self.probe_zone_get(
                "email_routing",
                zone_id,
                "Zone Settings Read or Zone Settings Write",
                |zone_id| format!("/zones/{zone_id}/email/routing"),
            )
            .await,
        );
        probes.push(
            self.probe_zone_get(
                "email_routing_rules",
                zone_id,
                "Email Routing Rules Read or Email Routing Rules Write",
                |zone_id| format!("/zones/{zone_id}/email/routing/rules?per_page=5"),
            )
            .await,
        );
        probes.push(
            self.probe_account_get(
                "email_routing_addresses",
                account_id,
                "Email Routing Addresses Read or Email Routing Addresses Write",
                |account_id| format!("/accounts/{account_id}/email/routing/addresses"),
            )
            .await,
        );
        probes.push(
            self.probe_account_get("r2", account_id, "R2 Storage Read or Write", |account_id| {
                format!("/accounts/{account_id}/r2/buckets?per_page=1")
            })
            .await,
        );
        probes.push(
            self.probe_account_get(
                "rules_lists",
                account_id,
                "Account Rules Lists Read or Write",
                |account_id| format!("/accounts/{account_id}/rules/lists"),
            )
            .await,
        );
        probes.push(
            self.probe_account_get_allow_not_found(
                "rulesets",
                account_id,
                "Account Rulesets Read or Write",
                |account_id| {
                    format!(
                        "/accounts/{account_id}/rulesets/phases/http_request_redirect/entrypoint"
                    )
                },
            )
            .await,
        );
        probes.push(CapabilityProbe {
            capability: "cache_purge".to_string(),
            checked: false,
            ok: false,
            status: None,
            code: Some("capability.not_probed_without_mutation".to_string()),
            permission_hint: "Cache Purge".to_string(),
            skipped_reason: Some(
                "Cloudflare Cache Purge permission cannot be safely verified with a read-only API call."
                    .to_string(),
            ),
        });

        probes
    }

    async fn probe_account_get<F>(
        &self,
        capability: &str,
        account_id: Option<&str>,
        permission_hint: &str,
        path: F,
    ) -> CapabilityProbe
    where
        F: FnOnce(&str) -> String,
    {
        let Some(account_id) = account_id.map(str::trim).filter(|value| !value.is_empty()) else {
            return skipped_probe(
                capability,
                permission_hint,
                "account_id is unavailable; pass account_id or configure CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID.",
            );
        };
        self.probe_get(capability, permission_hint, &path(account_id))
            .await
    }

    async fn probe_account_post<F>(
        &self,
        capability: &str,
        account_id: Option<&str>,
        permission_hint: &str,
        path: F,
        body: Value,
    ) -> CapabilityProbe
    where
        F: FnOnce(&str) -> String,
    {
        let Some(account_id) = account_id.map(str::trim).filter(|value| !value.is_empty()) else {
            return skipped_probe(
                capability,
                permission_hint,
                "account_id is unavailable; pass account_id or configure CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID.",
            );
        };
        self.probe_post(capability, permission_hint, &path(account_id), &body)
            .await
    }

    async fn probe_account_get_allow_not_found<F>(
        &self,
        capability: &str,
        account_id: Option<&str>,
        permission_hint: &str,
        path: F,
    ) -> CapabilityProbe
    where
        F: FnOnce(&str) -> String,
    {
        let Some(account_id) = account_id.map(str::trim).filter(|value| !value.is_empty()) else {
            return skipped_probe(
                capability,
                permission_hint,
                "account_id is unavailable; pass account_id or configure CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID.",
            );
        };
        self.probe_get_allow_not_found(capability, permission_hint, &path(account_id))
            .await
    }

    async fn probe_zone_get<F>(
        &self,
        capability: &str,
        zone_id: Option<&str>,
        permission_hint: &str,
        path: F,
    ) -> CapabilityProbe
    where
        F: FnOnce(&str) -> String,
    {
        let Some(zone_id) = zone_id.map(str::trim).filter(|value| !value.is_empty()) else {
            return skipped_probe(
                capability,
                permission_hint,
                "zone_id is unavailable; pass zone_id or configure CLOUDFLARE_MCP_DEFAULT_ZONE_ID.",
            );
        };
        self.probe_get(capability, permission_hint, &path(zone_id))
            .await
    }

    async fn probe_get(
        &self,
        capability: &str,
        permission_hint: &str,
        path: &str,
    ) -> CapabilityProbe {
        self.probe_get_inner(capability, permission_hint, path, false)
            .await
    }

    async fn probe_get_allow_not_found(
        &self,
        capability: &str,
        permission_hint: &str,
        path: &str,
    ) -> CapabilityProbe {
        self.probe_get_inner(capability, permission_hint, path, true)
            .await
    }

    async fn probe_post(
        &self,
        capability: &str,
        permission_hint: &str,
        path: &str,
        body: &Value,
    ) -> CapabilityProbe {
        let token = match self.bearer_token() {
            Ok(token) => token,
            Err(err) => {
                return CapabilityProbe {
                    capability: capability.to_string(),
                    checked: false,
                    ok: false,
                    status: err.status,
                    code: Some(err.code.to_string()),
                    permission_hint: permission_hint.to_string(),
                    skipped_reason: Some(err.message),
                };
            }
        };
        let url = self.endpoint(path);
        let result: Result<CloudflareEnvelope<Value>, _> = self
            .send_envelope(
                "cloudflare.capabilities.probe",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .post(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(body)
                },
            )
            .await;

        match result {
            Ok(_) => CapabilityProbe {
                capability: capability.to_string(),
                checked: true,
                ok: true,
                status: Some(200),
                code: None,
                permission_hint: permission_hint.to_string(),
                skipped_reason: None,
            },
            Err(err) => CapabilityProbe {
                capability: capability.to_string(),
                checked: true,
                ok: false,
                status: err.status,
                code: Some(err.code.to_string()),
                permission_hint: permission_hint.to_string(),
                skipped_reason: None,
            },
        }
    }

    async fn probe_get_inner(
        &self,
        capability: &str,
        permission_hint: &str,
        path: &str,
        not_found_ok: bool,
    ) -> CapabilityProbe {
        let token = match self.bearer_token() {
            Ok(token) => token,
            Err(err) => {
                return CapabilityProbe {
                    capability: capability.to_string(),
                    checked: false,
                    ok: false,
                    status: err.status,
                    code: Some(err.code.to_string()),
                    permission_hint: permission_hint.to_string(),
                    skipped_reason: Some(err.message),
                };
            }
        };
        let url = self.endpoint(path);
        let result: Result<CloudflareEnvelope<Value>, _> = self
            .send_envelope(
                "cloudflare.capabilities.probe",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await;

        match result {
            Ok(_) => CapabilityProbe {
                capability: capability.to_string(),
                checked: true,
                ok: true,
                status: Some(200),
                code: None,
                permission_hint: permission_hint.to_string(),
                skipped_reason: None,
            },
            Err(err) if not_found_ok && err.status == Some(404) => CapabilityProbe {
                capability: capability.to_string(),
                checked: true,
                ok: true,
                status: err.status,
                code: Some("capability.not_configured".to_string()),
                permission_hint: permission_hint.to_string(),
                skipped_reason: None,
            },
            Err(err) => CapabilityProbe {
                capability: capability.to_string(),
                checked: true,
                ok: false,
                status: err.status,
                code: Some(err.code.to_string()),
                permission_hint: permission_hint.to_string(),
                skipped_reason: None,
            },
        }
    }
}

fn skipped_probe(capability: &str, permission_hint: &str, reason: &str) -> CapabilityProbe {
    CapabilityProbe {
        capability: capability.to_string(),
        checked: false,
        ok: false,
        status: None,
        code: Some("capability.skipped_missing_identifier".to_string()),
        permission_hint: permission_hint.to_string(),
        skipped_reason: Some(reason.to_string()),
    }
}
