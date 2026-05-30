use mcp_toolkit_policy_core::Decision;
use serde::Serialize;
use std::collections::BTreeSet;

use crate::cloudflare::{AdapterError, CloudflareClient};
use crate::policy::{extract_allowlist_principals, principal_fingerprint};

#[derive(Debug, Clone, Serialize)]
pub struct PublishGateEvidence {
    pub account_id: String,
    pub hostname: String,
    pub app_id: Option<String>,
    pub app_name: Option<String>,
    pub app_count_for_hostname: usize,
    pub policy_count_for_app: usize,
    pub allow_principal_count: usize,
    pub allow_principal_fingerprint: String,
    pub allow_principals: Vec<String>,
    pub override_requested: bool,
    pub override_used: bool,
    pub override_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublishGateReport {
    pub decision: Decision,
    pub evidence: PublishGateEvidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublishTransition {
    pub from: &'static str,
    pub to: &'static str,
    pub event: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublishStateTrace {
    pub terminal_state: &'static str,
    pub transitions: Vec<PublishTransition>,
}

pub async fn evaluate_publish_gate(
    client: &CloudflareClient,
    account_id: &str,
    hostname: &str,
    override_requested: bool,
    override_reason: Option<&str>,
) -> Result<PublishGateReport, AdapterError> {
    let hostname = hostname.trim().to_ascii_lowercase();
    let override_reason = override_reason
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    let apps = client.list_access_apps(account_id, Some(&hostname)).await?;
    let app = apps
        .items
        .iter()
        .find(|app| {
            app.domain
                .as_deref()
                .map(|domain| domain.eq_ignore_ascii_case(&hostname))
                .unwrap_or(false)
        })
        .cloned();

    let mut evidence = PublishGateEvidence {
        account_id: account_id.to_string(),
        hostname: hostname.clone(),
        app_id: app.as_ref().map(|item| item.id.clone()),
        app_name: app.as_ref().map(|item| item.name.clone()),
        app_count_for_hostname: apps.items.len(),
        policy_count_for_app: 0,
        allow_principal_count: 0,
        allow_principal_fingerprint: principal_fingerprint(&BTreeSet::new()),
        allow_principals: Vec::new(),
        override_requested,
        override_used: false,
        override_reason,
    };

    if override_requested && evidence.override_reason.is_none() {
        return Ok(PublishGateReport {
            decision: Decision::deny_raw(
                "PUBLISH_OVERRIDE_REASON_REQUIRED",
                Some("override_reason_required"),
            ),
            evidence,
        });
    }

    let Some(app) = app else {
        return Ok(gate_or_override(
            evidence,
            "PUBLISH_GATE_NO_ACCESS_APP",
            "no_access_app_for_hostname",
        ));
    };

    let policies = client.list_access_policies(account_id, &app.id).await?;
    let principals = extract_allowlist_principals(&policies);
    evidence.policy_count_for_app = policies.len();
    evidence.allow_principal_count = principals.len();
    evidence.allow_principal_fingerprint = principal_fingerprint(&principals);
    evidence.allow_principals = principals.iter().cloned().collect();

    if !principals.is_empty() {
        return Ok(PublishGateReport {
            decision: Decision::allow(),
            evidence,
        });
    }

    Ok(gate_or_override(
        evidence,
        "PUBLISH_GATE_NO_ACTIVE_ALLOW_POLICY",
        "no_active_allow_policy",
    ))
}

pub fn preflight_trace(report: &PublishGateReport) -> PublishStateTrace {
    let mut transitions = Vec::with_capacity(2);
    transitions.push(PublishTransition {
        from: "init",
        to: "policy_gate_checked",
        event: "preflight",
    });
    if report.decision.allow {
        transitions.push(PublishTransition {
            from: "policy_gate_checked",
            to: "policy_gate_passed",
            event: "allow",
        });
        PublishStateTrace {
            terminal_state: "policy_gate_passed",
            transitions,
        }
    } else {
        transitions.push(PublishTransition {
            from: "policy_gate_checked",
            to: "blocked",
            event: "deny",
        });
        PublishStateTrace {
            terminal_state: "blocked",
            transitions,
        }
    }
}

pub fn lock_first_publish_trace(
    report: &PublishGateReport,
    route_applied: bool,
) -> PublishStateTrace {
    let mut trace = preflight_trace(report);
    if !report.decision.allow {
        return trace;
    }
    if route_applied {
        trace.transitions.push(PublishTransition {
            from: "policy_gate_passed",
            to: "route_applied",
            event: "apply_route",
        });
        trace.transitions.push(PublishTransition {
            from: "route_applied",
            to: "published",
            event: "verify_terminal_state",
        });
        trace.terminal_state = "published";
        return trace;
    }
    trace.transitions.push(PublishTransition {
        from: "policy_gate_passed",
        to: "blocked",
        event: "route_apply_failed",
    });
    trace.terminal_state = "blocked";
    trace
}

pub fn emergency_unpublish_trace(removed_route: bool) -> PublishStateTrace {
    let mut transitions = vec![PublishTransition {
        from: "init",
        to: "route_disable_attempted",
        event: "emergency_unpublish",
    }];
    if removed_route {
        transitions.push(PublishTransition {
            from: "route_disable_attempted",
            to: "unpublished",
            event: "route_disabled",
        });
    } else {
        transitions.push(PublishTransition {
            from: "route_disable_attempted",
            to: "unpublished",
            event: "already_unpublished",
        });
    }
    PublishStateTrace {
        terminal_state: "unpublished",
        transitions,
    }
}

fn gate_or_override(
    mut evidence: PublishGateEvidence,
    deny_code: &str,
    deny_reason: &str,
) -> PublishGateReport {
    if evidence.override_requested {
        evidence.override_used = true;
        return PublishGateReport {
            decision: Decision {
                allow: true,
                code: Some("PUBLISH_OVERRIDE_ALLOW".to_string()),
                reason: Some("explicit_override".to_string()),
                required_scopes: None,
            },
            evidence,
        };
    }
    PublishGateReport {
        decision: Decision::deny_raw(deny_code, Some(deny_reason)),
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::{PublishGateEvidence, gate_or_override};
    use mcp_toolkit_policy_core::Decision;

    fn base_evidence() -> PublishGateEvidence {
        PublishGateEvidence {
            account_id: "acct-1".to_string(),
            hostname: "preview.example.com".to_string(),
            app_id: None,
            app_name: None,
            app_count_for_hostname: 0,
            policy_count_for_app: 0,
            allow_principal_count: 0,
            allow_principal_fingerprint: "f".to_string(),
            allow_principals: Vec::new(),
            override_requested: false,
            override_used: false,
            override_reason: None,
        }
    }

    #[test]
    fn deny_without_override_when_gate_fails() {
        let report = gate_or_override(
            base_evidence(),
            "PUBLISH_GATE_NO_ACCESS_APP",
            "no_access_app_for_hostname",
        );
        assert_eq!(
            report.decision,
            Decision::deny_raw(
                "PUBLISH_GATE_NO_ACCESS_APP",
                Some("no_access_app_for_hostname")
            )
        );
        assert!(!report.evidence.override_used);
    }

    #[test]
    fn override_allows_when_requested() {
        let mut evidence = base_evidence();
        evidence.override_requested = true;
        evidence.override_reason = Some("approved emergency".to_string());
        let report = gate_or_override(
            evidence,
            "PUBLISH_GATE_NO_ACTIVE_ALLOW_POLICY",
            "no_active_allow_policy",
        );
        assert!(report.decision.allow);
        assert_eq!(
            report.decision.code.as_deref(),
            Some("PUBLISH_OVERRIDE_ALLOW")
        );
        assert!(report.evidence.override_used);
    }
}
