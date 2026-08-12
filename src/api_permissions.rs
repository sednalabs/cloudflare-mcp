use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::{Value, json};

pub const BOT_MANAGEMENT_UPDATE_OPERATION_ID: &str = "bot-management-for-a-zone-update-config";
pub const BOT_MANAGEMENT_READ_OPERATION_ID: &str = "bot-management-for-a-zone-get-config";

const BOT_MANAGEMENT_UPDATE_PERMISSIONS: [&str; 2] =
    ["Bot Management Write", "Zone Settings Write"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MutationPermissionPreflight {
    pub operation_id: String,
    pub status: &'static str,
    pub ready: bool,
    pub required_permissions: Vec<String>,
    pub observed_required_permissions: Vec<String>,
    pub missing_permissions: Vec<String>,
    pub unverified_permissions: Vec<String>,
}

impl MutationPermissionPreflight {
    pub fn guarded_recovery(&self) -> Value {
        let permissions_to_plan = if self.missing_permissions.is_empty() {
            self.required_permissions.clone()
        } else {
            self.missing_permissions.clone()
        };

        json!({
            "status": "mcp_recovery_required",
            "first_forbidden_goal_blocking": false,
            "steps": [
                {
                    "order": 1,
                    "tool": "account_api_tokens",
                    "arguments": {
                        "account_id": "<account-id>",
                        "action": "get",
                        "token_id": "<account-owned-token-id>"
                    },
                    "proof": "fresh token policy and permission-group readback"
                },
                {
                    "order": 2,
                    "tool": "account_api_token_permission_plan",
                    "arguments": {
                        "account_id": "<account-id>",
                        "token_id": "<account-owned-token-id>",
                        "add_permissions": permissions_to_plan,
                        "remove_permissions": []
                    },
                    "proof": "permission delta that preserves unrelated token policy"
                },
                {
                    "order": 3,
                    "tool": "account_api_tokens",
                    "arguments_from": "account_api_token_permission_plan.next_call.arguments",
                    "contract": "run dry_run first, then echo its exact required_confirmation_token once"
                },
                {
                    "order": 4,
                    "tool": "account_api_tokens",
                    "arguments": {
                        "account_id": "<account-id>",
                        "action": "get",
                        "token_id": "<account-owned-token-id>"
                    },
                    "proof": "fresh readback contains every required permission"
                },
                {
                    "order": 5,
                    "tool": "api_mutate",
                    "arguments_from": "original api_mutate request",
                    "arguments_override": {
                        "dry_run": true,
                        "confirmation_token": null,
                        "token_permissions": self.required_permissions
                    },
                    "contract": "retry the mutation at most once after repair using a new dry-run confirmation token"
                },
                {
                    "order": 6,
                    "tool": "api_read",
                    "arguments": {
                        "operation_id": BOT_MANAGEMENT_READ_OPERATION_ID,
                        "path_params": {
                            "zone_id": "<zone-id>"
                        }
                    },
                    "proof": "authoritative Bot Management configuration readback"
                }
            ],
            "external_escalation": {
                "allowed": false,
                "becomes_allowed_only_when": [
                    "account token inspection or guarded update is positively unavailable through the MCP",
                    "a distinct external authority requirement is proven by exact provider evidence"
                ]
            }
        })
    }
}

pub fn mutation_permission_preflight(
    operation_id: &str,
    token_permissions: &[String],
) -> Option<MutationPermissionPreflight> {
    if operation_id != BOT_MANAGEMENT_UPDATE_OPERATION_ID {
        return None;
    }

    let observed = token_permissions
        .iter()
        .map(|permission| normalize_permission_name(permission))
        .collect::<BTreeSet<_>>();
    let required_permissions = BOT_MANAGEMENT_UPDATE_PERMISSIONS
        .iter()
        .map(|permission| (*permission).to_string())
        .collect::<Vec<_>>();
    let observed_required_permissions = BOT_MANAGEMENT_UPDATE_PERMISSIONS
        .iter()
        .filter(|permission| observed.contains(&normalize_permission_name(permission)))
        .map(|permission| (*permission).to_string())
        .collect::<Vec<_>>();
    let missing_permissions = BOT_MANAGEMENT_UPDATE_PERMISSIONS
        .iter()
        .filter(|permission| !observed.contains(&normalize_permission_name(permission)))
        .map(|permission| (*permission).to_string())
        .collect::<Vec<_>>();
    let unverified_permissions = if token_permissions.is_empty() {
        required_permissions.clone()
    } else {
        Vec::new()
    };
    let ready = missing_permissions.is_empty();
    let status = if ready {
        "ready"
    } else if token_permissions.is_empty() {
        "verification_required"
    } else {
        "repair_required"
    };

    Some(MutationPermissionPreflight {
        operation_id: operation_id.to_string(),
        status,
        ready,
        required_permissions,
        observed_required_permissions,
        missing_permissions: if token_permissions.is_empty() {
            Vec::new()
        } else {
            missing_permissions
        },
        unverified_permissions,
    })
}

fn normalize_permission_name(value: &str) -> String {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bot_management_write_alone_names_only_zone_settings_write_as_missing() {
        let preflight = mutation_permission_preflight(
            BOT_MANAGEMENT_UPDATE_OPERATION_ID,
            &["Bot Management Write".to_string()],
        )
        .expect("Bot Management preflight");

        assert!(!preflight.ready);
        assert_eq!(preflight.status, "repair_required");
        assert_eq!(
            preflight.required_permissions,
            vec!["Bot Management Write", "Zone Settings Write"]
        );
        assert_eq!(preflight.missing_permissions, vec!["Zone Settings Write"]);
    }

    #[test]
    fn bot_management_permission_pair_is_ready_regardless_of_case_or_order() {
        let preflight = mutation_permission_preflight(
            BOT_MANAGEMENT_UPDATE_OPERATION_ID,
            &[
                "zone settings write".to_string(),
                "BOT-MANAGEMENT-WRITE".to_string(),
            ],
        )
        .expect("Bot Management preflight");

        assert!(preflight.ready);
        assert_eq!(preflight.status, "ready");
        assert!(preflight.missing_permissions.is_empty());
        assert!(preflight.unverified_permissions.is_empty());
    }

    #[test]
    fn guarded_recovery_is_machine_actionable_without_interactive_ui_advice() {
        let preflight = mutation_permission_preflight(
            BOT_MANAGEMENT_UPDATE_OPERATION_ID,
            &["Bot Management Write".to_string()],
        )
        .expect("Bot Management preflight");
        let recovery = preflight.guarded_recovery();
        let rendered = recovery.to_string().to_ascii_lowercase();

        assert_eq!(recovery["first_forbidden_goal_blocking"], json!(false));
        assert!(rendered.contains("account_api_token_permission_plan"));
        assert!(rendered.contains("api_read"));
        for forbidden in ["dashboard", "novnc", "human"] {
            assert!(
                !rendered.contains(forbidden),
                "found {forbidden}: {rendered}"
            );
        }
    }
}
