//! Conditional publication policy. No provider I/O or retained approval state.

use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "mode", content = "etag", rename_all = "snake_case")]
pub enum R2WriteCondition {
    Unconditional,
    CreateOnly,
    Match(String),
}

impl R2WriteCondition {
    pub fn parse(
        if_none_match: Option<&str>,
        if_match: Option<&str>,
    ) -> Result<Self, &'static str> {
        match (if_none_match, if_match) {
            (None, None) => Ok(Self::Unconditional),
            (Some("*"), None) => Ok(Self::CreateOnly),
            (None, Some(etag)) if is_strong_etag(etag) => Ok(Self::Match(etag.to_string())),
            _ => Err(
                "Use only if_none_match='*' or one quoted strong if_match ETag from a complete GET; conditions are mutually exclusive.",
            ),
        }
    }

    pub fn header(&self) -> Option<(&'static str, &str)> {
        match self {
            Self::Unconditional => None,
            Self::CreateOnly => Some(("if-none-match", "*")),
            Self::Match(etag) => Some(("if-match", etag)),
        }
    }
}

/// Conservative ASCII subset of one RFC 9110 strong entity-tag. No list,
/// wildcard, weak prefix, whitespace normalization or control-byte repair.
pub fn is_strong_etag(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=1024).contains(&bytes.len())
        && bytes.first() == Some(&b'"')
        && bytes.last() == Some(&b'"')
        && bytes[1..bytes.len() - 1]
            .iter()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e) && *byte != b',')
}

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn complete_read(
    status: u16,
    requested_range: Option<&str>,
    returned_range: Option<&str>,
    truncated: bool,
    length: Option<u64>,
    returned_bytes: u64,
) -> bool {
    status == 200
        && requested_range.is_none()
        && returned_range.is_none()
        && !truncated
        && length.is_some_and(|length| length == returned_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditions_are_exact_and_exclusive() {
        for bad in [
            "*",
            "W/\"v1\"",
            "v1",
            "\"v1\",\"v2\"",
            " \"v1\"",
            "\"v1\r\n\"",
            "\"\"",
            "\"a b\"",
        ] {
            assert!(R2WriteCondition::parse(None, Some(bad)).is_err(), "{bad:?}");
        }
        assert!(R2WriteCondition::parse(Some("*"), Some("\"v1\"")).is_err());
        assert!(R2WriteCondition::parse(Some("\"v1\""), None).is_err());
        assert_eq!(
            R2WriteCondition::parse(None, Some("\"v1-2\""))
                .unwrap()
                .header(),
            Some(("if-match", "\"v1-2\""))
        );
    }

    #[test]
    fn only_full_get_can_supply_update_authority() {
        assert!(complete_read(200, None, None, false, Some(3), 3));
        assert!(!complete_read(206, None, None, false, Some(3), 3));
        assert!(!complete_read(
            200,
            Some("bytes=0-2"),
            None,
            false,
            Some(3),
            3
        ));
        assert!(!complete_read(
            200,
            None,
            Some("bytes 0-2/4"),
            false,
            Some(3),
            3
        ));
        assert!(!complete_read(200, None, None, true, Some(3), 3));
        assert!(!complete_read(200, None, None, false, Some(4), 3));
        assert!(!complete_read(200, None, None, false, None, 3));
    }
}
