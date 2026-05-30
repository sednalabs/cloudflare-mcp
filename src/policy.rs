use std::collections::BTreeSet;

use mcp_toolkit_policy_core::Decision;
use serde::Serialize;
use serde_json::json;

use crate::cloudflare::{AccessPolicy, AccessPolicyWrite};

const FNV_OFFSET_BASIS_64: u64 = 0xcbf29ce484222325;
const FNV_PRIME_64: u64 = 0x100000001b3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowlistMutationMode {
    Replace,
    Additive,
}

impl AllowlistMutationMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "replace" | "single_owner" | "single-owner" | "singleowner" => Ok(Self::Replace),
            "additive" | "add" => Ok(Self::Additive),
            _ => Err(format!(
                "unsupported mode {raw:?}; use 'replace' or 'additive'"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Replace => "replace",
            Self::Additive => "additive",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyInvariantDiff {
    pub missing_from_result: Vec<String>,
    pub unexpected_in_result: Vec<String>,
    pub removed_from_previous: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyEvidence {
    pub mode: &'static str,
    pub before_count: usize,
    pub requested_count: usize,
    pub target_count: usize,
    pub after_count: usize,
    pub before_fingerprint: String,
    pub requested_fingerprint: String,
    pub target_fingerprint: String,
    pub after_fingerprint: String,
    pub before_principals: Vec<String>,
    pub requested_principals: Vec<String>,
    pub target_principals: Vec<String>,
    pub after_principals: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyInvariantViolation {
    pub code: &'static str,
    pub message: String,
    pub hint: &'static str,
    pub decision: Decision,
    pub diff: PolicyInvariantDiff,
    pub evidence: PolicyEvidence,
}

pub fn canonicalize_requested_principals(
    requested: &[String],
) -> Result<BTreeSet<String>, PolicyInvariantViolation> {
    let principals = canonicalize_principals(requested.iter().map(String::as_str));
    if principals.is_empty() {
        return Err(PolicyInvariantViolation {
            code: "access_policy.invalid_requested_principals",
            message: "requested_principals must include at least one non-empty principal"
                .to_string(),
            hint: "Provide at least one valid email principal for policy mutation.",
            decision: Decision::deny_raw(
                "ACCESS_POLICY_INVALID_REQUEST",
                Some("requested_principals_empty"),
            ),
            diff: PolicyInvariantDiff {
                missing_from_result: Vec::new(),
                unexpected_in_result: Vec::new(),
                removed_from_previous: Vec::new(),
            },
            evidence: PolicyEvidence {
                mode: "replace",
                before_count: 0,
                requested_count: 0,
                target_count: 0,
                after_count: 0,
                before_fingerprint: principal_fingerprint(&BTreeSet::new()),
                requested_fingerprint: principal_fingerprint(&BTreeSet::new()),
                target_fingerprint: principal_fingerprint(&BTreeSet::new()),
                after_fingerprint: principal_fingerprint(&BTreeSet::new()),
                before_principals: Vec::new(),
                requested_principals: Vec::new(),
                target_principals: Vec::new(),
                after_principals: Vec::new(),
            },
        });
    }
    Ok(principals)
}

pub fn extract_allowlist_principals(policies: &[AccessPolicy]) -> BTreeSet<String> {
    let mut principals = BTreeSet::new();
    for policy in policies {
        let is_allow = policy
            .decision
            .as_deref()
            .map(|decision| decision.eq_ignore_ascii_case("allow"))
            .unwrap_or(false);
        if !is_allow {
            continue;
        }
        let Some(include) = policy.include.as_ref() else {
            continue;
        };
        let Some(email_selector) = include.get("email") else {
            continue;
        };
        collect_principals_from_email_selector(email_selector, &mut principals);
    }
    principals
}

pub fn plan_target_principals(
    mode: AllowlistMutationMode,
    before_principals: &BTreeSet<String>,
    requested_principals: &BTreeSet<String>,
) -> BTreeSet<String> {
    match mode {
        AllowlistMutationMode::Replace => requested_principals.clone(),
        AllowlistMutationMode::Additive => before_principals
            .union(requested_principals)
            .cloned()
            .collect(),
    }
}

pub fn build_managed_allowlist_policy(principals: &BTreeSet<String>) -> AccessPolicyWrite {
    let principals: Vec<String> = principals.iter().cloned().collect();
    AccessPolicyWrite {
        id: None,
        name: "mcp-managed-allowlist-email".to_string(),
        decision: "allow".to_string(),
        include: json!({
            "email": {
                "email": principals,
            }
        }),
        exclude: None,
        require: None,
        precedence: Some(1),
    }
}

pub fn evaluate_mutation_invariants(
    mode: AllowlistMutationMode,
    before_principals: &BTreeSet<String>,
    requested_principals: &BTreeSet<String>,
    after_principals: &BTreeSet<String>,
) -> Result<PolicyEvidence, PolicyInvariantViolation> {
    let target_principals = plan_target_principals(mode, before_principals, requested_principals);
    let diff = PolicyInvariantDiff {
        missing_from_result: set_diff(&target_principals, after_principals),
        unexpected_in_result: match mode {
            AllowlistMutationMode::Replace => set_diff(after_principals, &target_principals),
            AllowlistMutationMode::Additive => Vec::new(),
        },
        removed_from_previous: set_diff(before_principals, after_principals),
    };

    let evidence = build_evidence(
        mode,
        before_principals,
        requested_principals,
        &target_principals,
        after_principals,
    );

    let violated = !diff.missing_from_result.is_empty()
        || !diff.unexpected_in_result.is_empty()
        || (mode == AllowlistMutationMode::Additive && !diff.removed_from_previous.is_empty());
    if violated {
        let (code, reason) = match mode {
            AllowlistMutationMode::Replace => (
                "access_policy.replace_invariant_failed",
                "replace_set_mismatch",
            ),
            AllowlistMutationMode::Additive => (
                "access_policy.additive_invariant_failed",
                "additive_superset_violation",
            ),
        };
        return Err(PolicyInvariantViolation {
            code,
            message: format!(
                "policy post-apply validation failed for {} mode",
                mode.as_str()
            ),
            hint: "Inspect the invariant diff and reconcile policy state before retrying.",
            decision: Decision::deny_raw("ACCESS_POLICY_INVARIANT_FAILED", Some(reason)),
            diff,
            evidence,
        });
    }

    Ok(evidence)
}

pub fn principal_fingerprint(principals: &BTreeSet<String>) -> String {
    let mut hash = FNV_OFFSET_BASIS_64;
    for principal in principals {
        for byte in principal.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME_64);
        }
        hash ^= u64::from(b'\n');
        hash = hash.wrapping_mul(FNV_PRIME_64);
    }
    format!("{hash:016x}")
}

fn build_evidence(
    mode: AllowlistMutationMode,
    before_principals: &BTreeSet<String>,
    requested_principals: &BTreeSet<String>,
    target_principals: &BTreeSet<String>,
    after_principals: &BTreeSet<String>,
) -> PolicyEvidence {
    PolicyEvidence {
        mode: mode.as_str(),
        before_count: before_principals.len(),
        requested_count: requested_principals.len(),
        target_count: target_principals.len(),
        after_count: after_principals.len(),
        before_fingerprint: principal_fingerprint(before_principals),
        requested_fingerprint: principal_fingerprint(requested_principals),
        target_fingerprint: principal_fingerprint(target_principals),
        after_fingerprint: principal_fingerprint(after_principals),
        before_principals: before_principals.iter().cloned().collect(),
        requested_principals: requested_principals.iter().cloned().collect(),
        target_principals: target_principals.iter().cloned().collect(),
        after_principals: after_principals.iter().cloned().collect(),
    }
}

fn collect_principals_from_email_selector(
    selector: &serde_json::Value,
    principals: &mut BTreeSet<String>,
) {
    match selector {
        serde_json::Value::String(value) => {
            if let Some(value) = canonicalize_principal(value) {
                principals.insert(value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_principals_from_email_selector(value, principals);
            }
        }
        serde_json::Value::Object(values) => {
            if let Some(nested) = values.get("email") {
                collect_principals_from_email_selector(nested, principals);
            }
        }
        _ => {}
    }
}

fn canonicalize_principal(value: &str) -> Option<String> {
    let trimmed = value.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed)
}

fn canonicalize_principals<'a>(values: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
    values.filter_map(canonicalize_principal).collect()
}

fn set_diff(left: &BTreeSet<String>, right: &BTreeSet<String>) -> Vec<String> {
    left.difference(right).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::{
        AllowlistMutationMode, build_managed_allowlist_policy, canonicalize_requested_principals,
        evaluate_mutation_invariants, extract_allowlist_principals, principal_fingerprint,
    };
    use crate::cloudflare::AccessPolicy;
    use serde_json::json;
    use std::collections::BTreeSet;

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn canonicalization_dedupes_and_normalizes_inputs() {
        let requested = vec![
            " Alice@Example.com ".to_string(),
            "alice@example.com".to_string(),
            "".to_string(),
            "bob@example.com".to_string(),
        ];
        let principals =
            canonicalize_requested_principals(&requested).expect("canonicalized principals");
        assert_eq!(principals, set(&["alice@example.com", "bob@example.com"]));
    }

    #[test]
    fn fingerprints_are_stable_for_set_equivalent_inputs() {
        let first = set(&["a@example.com", "b@example.com"]);
        let second = set(&["b@example.com", "a@example.com"]);
        assert_eq!(
            principal_fingerprint(&first),
            principal_fingerprint(&second)
        );
    }

    #[test]
    fn extract_allowlist_principals_uses_allow_email_entries_only() {
        let policies = vec![
            AccessPolicy {
                id: "pol-1".to_string(),
                name: "allow".to_string(),
                decision: Some("allow".to_string()),
                include: Some(json!({
                    "email": {
                        "email": ["a@example.com", "B@Example.com"]
                    }
                })),
                exclude: None,
                require: None,
            },
            AccessPolicy {
                id: "pol-2".to_string(),
                name: "bypass".to_string(),
                decision: Some("bypass".to_string()),
                include: Some(json!({
                    "email": {
                        "email": ["ignored@example.com"]
                    }
                })),
                exclude: None,
                require: None,
            },
        ];
        let principals = extract_allowlist_principals(&policies);
        assert_eq!(principals, set(&["a@example.com", "b@example.com"]));
    }

    #[test]
    fn replace_mode_requires_exact_target_set() {
        let before = set(&["a@example.com", "b@example.com"]);
        let requested = set(&["a@example.com"]);
        let after = set(&["a@example.com", "extra@example.com"]);
        let violation = evaluate_mutation_invariants(
            AllowlistMutationMode::Replace,
            &before,
            &requested,
            &after,
        )
        .expect_err("replace invariant should fail");
        assert_eq!(violation.code, "access_policy.replace_invariant_failed");
        assert_eq!(violation.diff.missing_from_result, Vec::<String>::new());
        assert_eq!(
            violation.diff.unexpected_in_result,
            vec!["extra@example.com".to_string()]
        );
    }

    #[test]
    fn additive_mode_requires_superset_without_removals() {
        let before = set(&["a@example.com"]);
        let requested = set(&["b@example.com"]);
        let after = set(&["b@example.com"]);
        let violation = evaluate_mutation_invariants(
            AllowlistMutationMode::Additive,
            &before,
            &requested,
            &after,
        )
        .expect_err("additive invariant should fail");
        assert_eq!(violation.code, "access_policy.additive_invariant_failed");
        assert_eq!(
            violation.diff.removed_from_previous,
            vec!["a@example.com".to_string()]
        );
    }

    #[test]
    fn managed_policy_is_deterministic_and_sorted() {
        let principals = set(&["b@example.com", "a@example.com"]);
        let policy = build_managed_allowlist_policy(&principals);
        assert_eq!(policy.name, "mcp-managed-allowlist-email");
        assert_eq!(policy.decision, "allow");
        assert_eq!(
            policy.include,
            json!({
                "email": {
                    "email": ["a@example.com", "b@example.com"]
                }
            })
        );
    }
}
