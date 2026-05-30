use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::cloudflare::Tunnel;

const FNV_OFFSET_BASIS_64: u64 = 0xcbf29ce484222325;
const FNV_PRIME_64: u64 = 0x100000001b3;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelEnsureAction {
    Created,
    Reused,
}

#[derive(Debug, Clone, Serialize)]
pub struct TunnelIdentity {
    pub account_id: String,
    pub tunnel_name: String,
    pub identity_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TunnelConflict {
    pub code: &'static str,
    pub message: String,
    pub hint: &'static str,
    pub tunnel_name: String,
    pub conflicting_tunnel_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IngressRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub service: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IngressConfig {
    pub tunnel_id: String,
    pub tunnel_name: String,
    pub tunnel_target: String,
    pub fingerprint: String,
    pub rules: Vec<IngressRule>,
    pub yaml: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IngressValidationError {
    pub code: &'static str,
    pub message: String,
    pub hint: &'static str,
    pub duplicate_hostnames: Vec<String>,
    pub invalid_rule_indices: Vec<usize>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorState {
    Stopped,
    Running,
}

impl ConnectorState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Running => "running",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectorRuntimeSnapshot {
    pub connector_key: String,
    pub state: ConnectorState,
    pub restart_count: u64,
    pub transition_count: u64,
    pub last_event: String,
    pub updated_at_unix_ms: u128,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorControlAction {
    Start,
    Stop,
    Restart,
}

impl ConnectorControlAction {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "start" => Ok(Self::Start),
            "stop" => Ok(Self::Stop),
            "restart" => Ok(Self::Restart),
            _ => Err(format!(
                "unsupported action {raw:?}; use 'start', 'stop', or 'restart'"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectorTransition {
    pub from: &'static str,
    pub to: &'static str,
    pub event: &'static str,
    pub idempotent: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectorControlOutcome {
    pub connector: ConnectorRuntimeSnapshot,
    pub transition: ConnectorTransition,
    pub orphan_processes_detected: u32,
}

pub fn canonical_tunnel_name(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    Some(normalized)
}

pub fn tunnel_identity(account_id: &str, tunnel_name: &str) -> Option<TunnelIdentity> {
    let account_id = account_id.trim().to_ascii_lowercase();
    let tunnel_name = canonical_tunnel_name(tunnel_name)?;
    if account_id.is_empty() {
        return None;
    }
    Some(TunnelIdentity {
        identity_key: format!("{account_id}::{tunnel_name}"),
        account_id,
        tunnel_name,
    })
}

pub fn tunnel_target(tunnel_id: &str) -> String {
    format!("{}.cfargotunnel.com", tunnel_id.trim())
}

pub fn select_existing_tunnel(
    tunnels: &[Tunnel],
    requested_tunnel_name: &str,
) -> Result<Option<Tunnel>, TunnelConflict> {
    let Some(requested) = canonical_tunnel_name(requested_tunnel_name) else {
        return Ok(None);
    };
    let matches = tunnels
        .iter()
        .filter(|tunnel| canonical_tunnel_name(&tunnel.name).as_deref() == Some(requested.as_str()))
        .cloned()
        .collect::<Vec<_>>();

    if matches.len() > 1 {
        return Err(TunnelConflict {
            code: "tunnel.duplicate_name_conflict",
            message: format!(
                "multiple tunnels matched requested name {requested:?}; reconciliation is ambiguous"
            ),
            hint: "Delete or rename duplicate tunnels before retrying ensure_tunnel.",
            tunnel_name: requested,
            conflicting_tunnel_ids: matches.into_iter().map(|tunnel| tunnel.id).collect(),
        });
    }

    Ok(matches.into_iter().next())
}

pub fn build_ingress_config(
    tunnel_id: &str,
    tunnel_name: &str,
    rules: &[IngressRule],
) -> Result<IngressConfig, IngressValidationError> {
    let tunnel_id = tunnel_id.trim().to_string();
    let tunnel_name = canonical_tunnel_name(tunnel_name).ok_or_else(|| IngressValidationError {
        code: "tunnel.ingress.invalid_tunnel_name",
        message: "tunnel_name must not be empty".to_string(),
        hint: "Provide a non-empty tunnel_name.",
        duplicate_hostnames: Vec::new(),
        invalid_rule_indices: Vec::new(),
    })?;
    if tunnel_id.is_empty() {
        return Err(IngressValidationError {
            code: "tunnel.ingress.invalid_tunnel_id",
            message: "tunnel_id must not be empty".to_string(),
            hint: "Provide a non-empty tunnel_id.",
            duplicate_hostnames: Vec::new(),
            invalid_rule_indices: Vec::new(),
        });
    }
    if rules.is_empty() {
        return Err(IngressValidationError {
            code: "tunnel.ingress.empty_rules",
            message: "at least one ingress rule is required".to_string(),
            hint: "Provide one or more hostname->service ingress rules.",
            duplicate_hostnames: Vec::new(),
            invalid_rule_indices: Vec::new(),
        });
    }

    let mut invalid_rule_indices = Vec::new();
    let mut normalized_rules = Vec::with_capacity(rules.len());
    for (index, rule) in rules.iter().enumerate() {
        let hostname = match rule.hostname.as_deref() {
            Some(raw_hostname) if raw_hostname.trim().is_empty() => {
                invalid_rule_indices.push(index);
                continue;
            }
            Some(raw_hostname) => {
                let hostname = raw_hostname.trim().to_ascii_lowercase();
                if hostname == "*" {
                    None
                } else {
                    Some(hostname)
                }
            }
            None => None,
        };
        let service = rule.service.trim().to_string();
        if service.is_empty() {
            invalid_rule_indices.push(index);
            continue;
        }
        normalized_rules.push(IngressRule { hostname, service });
    }
    if !invalid_rule_indices.is_empty() {
        return Err(IngressValidationError {
            code: "tunnel.ingress.invalid_rule_fields",
            message: "ingress rules must include a non-empty service and any provided hostname must be non-empty".to_string(),
            hint: "Remove empty service values, omit hostname for the final catch-all rule, or provide a non-empty hostname.",
            duplicate_hostnames: Vec::new(),
            invalid_rule_indices,
        });
    }

    let mut duplicate_hostnames = Vec::new();
    let mut seen_hostnames = BTreeSet::new();
    for rule in &normalized_rules {
        let Some(hostname) = rule.hostname.as_ref() else {
            continue;
        };
        if !seen_hostnames.insert(hostname.clone())
            && duplicate_hostnames
                .last()
                .map(|last: &String| last != hostname)
                .unwrap_or(true)
        {
            duplicate_hostnames.push(hostname.clone());
        }
    }
    if !duplicate_hostnames.is_empty() {
        return Err(IngressValidationError {
            code: "tunnel.ingress.duplicate_hostnames",
            message: "duplicate hostnames detected in ingress rules".to_string(),
            hint: "Provide exactly one ingress rule per hostname.",
            duplicate_hostnames,
            invalid_rule_indices: Vec::new(),
        });
    }

    let catch_all_indices = normalized_rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| {
            if rule.hostname.as_deref() == Some("*") || rule.hostname.is_none() {
                Some(index)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if catch_all_indices.len() > 1
        || catch_all_indices
            .last()
            .is_some_and(|index| *index != normalized_rules.len().saturating_sub(1))
    {
        return Err(IngressValidationError {
            code: "tunnel.ingress.invalid_catch_all_order",
            message: "catch-all ingress rule must be the final rule".to_string(),
            hint: "Move the service-only or '*' catch-all rule to the end, and provide at most one catch-all rule.",
            duplicate_hostnames: Vec::new(),
            invalid_rule_indices: catch_all_indices,
        });
    }

    let mut lines = Vec::new();
    lines.push(format!("tunnel: {tunnel_id}"));
    lines.push(format!(
        "credentials-file: /etc/cloudflared/{tunnel_name}.json"
    ));
    lines.push("ingress:".to_string());
    let mut has_catch_all = false;
    for rule in &normalized_rules {
        if let Some(hostname) = &rule.hostname {
            lines.push(format!("  - hostname: {hostname}"));
            lines.push(format!("    service: {}", rule.service));
            if hostname == "*" {
                has_catch_all = true;
            }
        } else {
            lines.push(format!("  - service: {}", rule.service));
            has_catch_all = true;
        }
    }
    if !has_catch_all {
        lines.push("  - service: http_status:404".to_string());
    }
    let yaml = format!("{}\n", lines.join("\n"));

    Ok(IngressConfig {
        tunnel_target: tunnel_target(&tunnel_id),
        fingerprint: fingerprint(&lines),
        tunnel_id,
        tunnel_name,
        rules: normalized_rules,
        yaml,
    })
}

pub fn apply_connector_control(
    current: Option<&ConnectorRuntimeSnapshot>,
    connector_key: &str,
    action: ConnectorControlAction,
) -> ConnectorControlOutcome {
    let mut snapshot = current
        .cloned()
        .unwrap_or_else(|| ConnectorRuntimeSnapshot {
            connector_key: connector_key.to_string(),
            state: ConnectorState::Stopped,
            restart_count: 0,
            transition_count: 0,
            last_event: "initial_state".to_string(),
            updated_at_unix_ms: now_unix_ms(),
        });

    let (next_state, event, idempotent, restart_delta) = match (snapshot.state, action) {
        (ConnectorState::Stopped, ConnectorControlAction::Start) => {
            (ConnectorState::Running, "start", false, 0)
        }
        (ConnectorState::Running, ConnectorControlAction::Start) => {
            (ConnectorState::Running, "already_running", true, 0)
        }
        (ConnectorState::Running, ConnectorControlAction::Stop) => {
            (ConnectorState::Stopped, "stop", false, 0)
        }
        (ConnectorState::Stopped, ConnectorControlAction::Stop) => {
            (ConnectorState::Stopped, "already_stopped", true, 0)
        }
        (ConnectorState::Running, ConnectorControlAction::Restart) => {
            (ConnectorState::Running, "restart", false, 1)
        }
        (ConnectorState::Stopped, ConnectorControlAction::Restart) => {
            (ConnectorState::Running, "restart_from_stopped", false, 1)
        }
    };

    let previous_state = snapshot.state;
    snapshot.state = next_state;
    snapshot.restart_count = snapshot.restart_count.saturating_add(restart_delta);
    if !idempotent {
        snapshot.transition_count = snapshot.transition_count.saturating_add(1);
    }
    snapshot.last_event = event.to_string();
    snapshot.updated_at_unix_ms = now_unix_ms();

    ConnectorControlOutcome {
        transition: ConnectorTransition {
            from: previous_state.as_str(),
            to: snapshot.state.as_str(),
            event,
            idempotent,
        },
        connector: snapshot,
        orphan_processes_detected: 0,
    }
}

fn fingerprint(lines: &[String]) -> String {
    let mut hash = FNV_OFFSET_BASIS_64;
    for line in lines {
        for byte in line.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME_64);
        }
        hash ^= u64::from(b'\n');
        hash = hash.wrapping_mul(FNV_PRIME_64);
    }
    format!("{hash:016x}")
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use crate::cloudflare::Tunnel;

    use super::{
        ConnectorControlAction, ConnectorState, IngressRule, apply_connector_control,
        build_ingress_config, select_existing_tunnel,
    };

    #[test]
    fn detects_duplicate_tunnel_name_conflicts() {
        let tunnels = vec![
            Tunnel {
                id: "t-1".to_string(),
                name: "preview".to_string(),
                status: Some("healthy".to_string()),
                created_at: None,
            },
            Tunnel {
                id: "t-2".to_string(),
                name: "Preview".to_string(),
                status: Some("healthy".to_string()),
                created_at: None,
            },
        ];
        let conflict = select_existing_tunnel(&tunnels, "preview")
            .expect_err("duplicate names should fail closed");
        assert_eq!(conflict.code, "tunnel.duplicate_name_conflict");
        assert_eq!(conflict.conflicting_tunnel_ids.len(), 2);
    }

    #[test]
    fn ingress_config_preserves_ingress_order() {
        let config = build_ingress_config(
            "tunnel-1",
            "preview",
            &[
                IngressRule {
                    hostname: Some("b.example.com".to_string()),
                    service: "http://127.0.0.1:8080".to_string(),
                },
                IngressRule {
                    hostname: Some("a.example.com".to_string()),
                    service: "http://127.0.0.1:9090".to_string(),
                },
            ],
        )
        .expect("config");

        assert!(config.yaml.contains(
            "ingress:\n  - hostname: b.example.com\n    service: http://127.0.0.1:8080\n  - hostname: a.example.com\n    service: http://127.0.0.1:9090\n  - service: http_status:404\n"
        ));
    }

    #[test]
    fn ingress_config_accepts_explicit_catch_all_without_extra_fallback() {
        let config = build_ingress_config(
            "tunnel-1",
            "preview",
            &[
                IngressRule {
                    hostname: Some("preview.example.com".to_string()),
                    service: "http://127.0.0.1:9090".to_string(),
                },
                IngressRule {
                    hostname: None,
                    service: "http_status:404".to_string(),
                },
            ],
        )
        .expect("config");

        assert_eq!(config.yaml.matches("service: http_status:404").count(), 1);
        assert!(config.rules[1].hostname.is_none());
    }

    #[test]
    fn ingress_config_rejects_non_terminal_catch_all() {
        let err = build_ingress_config(
            "tunnel-1",
            "preview",
            &[
                IngressRule {
                    hostname: None,
                    service: "http_status:404".to_string(),
                },
                IngressRule {
                    hostname: Some("preview.example.com".to_string()),
                    service: "http://127.0.0.1:9090".to_string(),
                },
            ],
        )
        .expect_err("catch-all before hostname should fail");

        assert_eq!(err.code, "tunnel.ingress.invalid_catch_all_order");
        assert_eq!(err.invalid_rule_indices, vec![0]);
    }

    #[test]
    fn ingress_config_rejects_blank_hostname_values() {
        let err = build_ingress_config(
            "tunnel-1",
            "preview",
            &[IngressRule {
                hostname: Some("   ".to_string()),
                service: "http_status:404".to_string(),
            }],
        )
        .expect_err("blank hostname should fail");

        assert_eq!(err.code, "tunnel.ingress.invalid_rule_fields");
        assert_eq!(err.invalid_rule_indices, vec![0]);
    }

    #[test]
    fn connector_start_is_idempotent_when_already_running() {
        let started = apply_connector_control(None, "acct::preview", ConnectorControlAction::Start);
        assert_eq!(started.connector.state, ConnectorState::Running);

        let started_again = apply_connector_control(
            Some(&started.connector),
            "acct::preview",
            ConnectorControlAction::Start,
        );
        assert_eq!(started_again.connector.state, ConnectorState::Running);
        assert!(started_again.transition.idempotent);
        assert_eq!(started_again.transition.event, "already_running");
    }

    #[test]
    fn connector_restart_increments_restart_count() {
        let running = apply_connector_control(None, "acct::preview", ConnectorControlAction::Start);
        let restarted = apply_connector_control(
            Some(&running.connector),
            "acct::preview",
            ConnectorControlAction::Restart,
        );
        assert_eq!(restarted.connector.state, ConnectorState::Running);
        assert_eq!(restarted.connector.restart_count, 1);
        assert_eq!(restarted.transition.event, "restart");
        assert!(!restarted.transition.idempotent);
    }
}
