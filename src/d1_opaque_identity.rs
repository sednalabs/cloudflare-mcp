//! Canonical opaque identities shared by D1 custody boundaries.

pub(crate) const D1_OPAQUE_IDENTITY_MIN_BYTES: usize = 16;
pub(crate) const D1_OPAQUE_IDENTITY_MAX_BYTES: usize = 128;

pub(crate) fn valid_d1_opaque_identity(value: &str) -> bool {
    (D1_OPAQUE_IDENTITY_MIN_BYTES..=D1_OPAQUE_IDENTITY_MAX_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::valid_d1_opaque_identity;

    #[test]
    fn identity_grammar_is_bounded_and_canonical() {
        assert!(valid_d1_opaque_identity("operation-00000001"));
        assert!(!valid_d1_opaque_identity("too-short"));
        assert!(!valid_d1_opaque_identity("operation with spaces"));
        assert!(!valid_d1_opaque_identity(&"a".repeat(129)));
    }
}
