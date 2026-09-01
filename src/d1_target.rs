//! Canonical identity for one existing Cloudflare D1 account/database target.
//!
//! Every curated provider mutation and every local custody key must cross this
//! boundary before it can hash or dispatch the target. Generic catalog
//! mutations are denied separately; they must not grow a parallel identity
//! grammar.

use rmcp::model::CallToolResult;

use crate::tools::{invalid_argument_result, sha256_bytes_hex};

const MAX_D1_TARGET_COMPONENT_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1TargetIdentity {
    pub(crate) account_id: String,
    pub(crate) database_id: String,
}

impl D1TargetIdentity {
    pub(crate) fn target_key_sha256(&self) -> String {
        sha256_bytes_hex(format!("{}\0{}", self.account_id, self.database_id).as_bytes())
    }
}

pub(crate) fn normalize_d1_target(
    account_id: &str,
    database_id: &str,
) -> Result<D1TargetIdentity, CallToolResult> {
    fn component(label: &'static str, value: &str) -> Result<String, CallToolResult> {
        let valid = !value.is_empty()
            && value.len() <= MAX_D1_TARGET_COMPONENT_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
        if !valid {
            return Err(invalid_argument_result(
                "d1.invalid_target_identity",
                format!(
                    "{label} must be an exact 1..={MAX_D1_TARGET_COMPONENT_BYTES} byte ASCII identifier containing only letters, digits, '_' or '-'"
                ),
                "Use the exact account_id and database_id returned by Cloudflare; whitespace, NUL, dot, path, percent-encoded and other equivalent aliases are rejected.",
            ));
        }
        Ok(value.to_string())
    }

    Ok(D1TargetIdentity {
        account_id: component("account_id", account_id)?,
        database_id: component("database_id", database_id)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_target_identity_rejects_alias_pairs() {
        let aliases = [
            ("acct-1", " acct-1"),
            ("acct-1", "acct-1 "),
            ("acct-1", "acct%2d1"),
            ("acct-1", "acct/../acct-1"),
            ("acct-1", "acct\\..\\acct-1"),
            ("acct-1", "."),
            ("acct-1", ".."),
            ("acct-1", "acct-1\0ignored"),
        ];

        for (canonical, alias) in aliases {
            assert!(normalize_d1_target(canonical, "db-1").is_ok());
            let result = normalize_d1_target(alias, "db-1")
                .expect_err("account alias must fail closed")
                .structured_content
                .expect("structured error");
            assert_eq!(result["error"]["code"], json!("d1.invalid_target_identity"));

            let result = normalize_d1_target("acct-1", alias)
                .expect_err("database alias must fail closed")
                .structured_content
                .expect("structured error");
            assert_eq!(result["error"]["code"], json!("d1.invalid_target_identity"));
        }
    }

    #[test]
    fn target_key_is_stable_only_for_exact_canonical_identity() {
        let first = normalize_d1_target("acct-1", "db-1").expect("canonical target");
        let second = normalize_d1_target("acct-1", "db-1").expect("canonical target");
        let other = normalize_d1_target("acct-1", "db-2").expect("canonical target");
        assert_eq!(first.target_key_sha256(), second.target_key_sha256());
        assert_ne!(first.target_key_sha256(), other.target_key_sha256());
    }
}
