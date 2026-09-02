//! Canonical opaque-identity grammar shared by D1 write preflight, custody,
//! and the final provider adapter boundary.

pub(crate) const D1_OPAQUE_IDENTITY_MIN_BYTES: usize = 16;
pub(crate) const D1_OPAQUE_IDENTITY_MAX_BYTES: usize = 128;

pub(crate) fn valid_d1_opaque_identity(value: &str) -> bool {
    (D1_OPAQUE_IDENTITY_MIN_BYTES..=D1_OPAQUE_IDENTITY_MAX_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}
