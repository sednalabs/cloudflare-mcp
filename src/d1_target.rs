//! Canonical identity for one existing Cloudflare D1 account/database target.
//!
//! Every curated provider mutation and every local custody key must cross this
//! boundary before it can hash or dispatch the target. Generic catalog
//! mutations are denied separately; they must not grow a parallel identity
//! grammar.

use rmcp::model::CallToolResult;

use crate::tools::{invalid_argument_result, sha256_bytes_hex};

const MAX_D1_ACCOUNT_ID_BYTES: usize = 256;

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
    fn canonical_account_id(value: &str) -> Result<String, CallToolResult> {
        let valid = !value.is_empty()
            && value.len() <= MAX_D1_ACCOUNT_ID_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
        if !valid {
            return Err(invalid_argument_result(
                "d1.invalid_target_identity",
                format!(
                    "account_id must be an exact 1..={MAX_D1_ACCOUNT_ID_BYTES} byte ASCII identifier containing only letters, digits, '_' or '-'"
                ),
                "Use the exact account_id and database_id returned by Cloudflare; whitespace, NUL, dot, path, percent-encoded and other equivalent aliases are rejected.",
            ));
        }
        Ok(value.to_string())
    }

    fn canonical_database_id(value: &str) -> Result<String, CallToolResult> {
        let valid = value.len() == 36
            && value.bytes().enumerate().all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
            });
        if !valid {
            return Err(invalid_argument_result(
                "d1.invalid_target_identity",
                "database_id must be a canonical lowercase hyphenated UUID",
                "Use the exact lowercase database_id returned by Cloudflare; uppercase, mixed-case, compact, braced, whitespace, path and percent-encoded aliases are rejected.",
            ));
        }
        Ok(value.to_string())
    }

    Ok(D1TargetIdentity {
        account_id: canonical_account_id(account_id)?,
        database_id: canonical_database_id(database_id)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_target_identity_rejects_alias_pairs() {
        const DATABASE_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
        let account_aliases = [
            ("acct-1", " acct-1"),
            ("acct-1", "acct-1 "),
            ("acct-1", "acct%2d1"),
            ("acct-1", "acct/../acct-1"),
            ("acct-1", "acct\\..\\acct-1"),
            ("acct-1", "."),
            ("acct-1", ".."),
            ("acct-1", "acct-1\0ignored"),
        ];

        for (canonical, alias) in account_aliases {
            assert!(normalize_d1_target(canonical, DATABASE_ID).is_ok());
            let result = normalize_d1_target(alias, DATABASE_ID)
                .expect_err("account alias must fail closed")
                .structured_content
                .expect("structured error");
            assert_eq!(result["error"]["code"], json!("d1.invalid_target_identity"));
        }

        for alias in [
            "123E4567-E89B-42D3-A456-426614174000",
            "123e4567-e89b-42D3-a456-426614174000",
            "123e4567e89b42d3a456426614174000",
            "{123e4567-e89b-42d3-a456-426614174000}",
            "123e4567-e89b-42d3-a456-42661417400g",
            " 123e4567-e89b-42d3-a456-426614174000",
            "123e4567-e89b-42d3-a456-426614174000 ",
            "123e4567-e89b-42d3-a456-426614174000/other",
            "123e4567-e89b-42d3-a456-426614174000\0ignored",
        ] {
            let result = normalize_d1_target("acct-1", alias)
                .expect_err("database alias must fail closed")
                .structured_content
                .expect("structured error");
            assert_eq!(result["error"]["code"], json!("d1.invalid_target_identity"));
            assert_eq!(
                result["error"]["message"],
                json!("database_id must be a canonical lowercase hyphenated UUID")
            );
        }
    }

    #[test]
    fn target_key_is_stable_only_for_exact_canonical_identity() {
        let first = normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000")
            .expect("canonical target");
        let second = normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000")
            .expect("canonical target");
        let other = normalize_d1_target("acct-1", "223e4567-e89b-42d3-a456-426614174000")
            .expect("canonical target");
        assert_eq!(first.target_key_sha256(), second.target_key_sha256());
        assert_ne!(first.target_key_sha256(), other.target_key_sha256());
    }
}
