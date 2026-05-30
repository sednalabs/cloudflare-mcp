use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    AccessGated,
    OriginReachable,
    Misconfigured,
    Timeout,
    TransportError,
}

impl VerificationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccessGated => "access_gated",
            Self::OriginReachable => "origin_reachable",
            Self::Misconfigured => "misconfigured",
            Self::Timeout => "timeout",
            Self::TransportError => "transport_error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationStatus {
    pub source: &'static str,
    pub target: String,
    pub state: VerificationState,
    pub code: &'static str,
    pub reason: &'static str,
    pub hint: &'static str,
    pub status_code: Option<u16>,
    pub redirect_location: Option<String>,
    pub checked_at_unix_ms: u128,
    pub latency_ms: u128,
    pub transport_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedVerificationState {
    Any,
    AccessGated,
    OriginReachable,
}

impl ExpectedVerificationState {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "any" => Ok(Self::Any),
            "access_gated" => Ok(Self::AccessGated),
            "origin_reachable" => Ok(Self::OriginReachable),
            other => Err(format!(
                "unsupported expected_state {other:?}; use 'access_gated', 'origin_reachable', or 'any'"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::AccessGated => "access_gated",
            Self::OriginReachable => "origin_reachable",
        }
    }

    pub fn matches(self, observed: VerificationState) -> bool {
        match self {
            Self::Any => true,
            Self::AccessGated => observed == VerificationState::AccessGated,
            Self::OriginReachable => observed == VerificationState::OriginReachable,
        }
    }
}

pub fn classify_http_result(
    target: &str,
    status_code: u16,
    redirect_location: Option<String>,
    latency_ms: u128,
) -> VerificationStatus {
    let redirect_to_access = redirect_location
        .as_deref()
        .map(|location| location.contains("/cdn-cgi/access/login"))
        .unwrap_or(false);
    let (state, code, reason, hint) = if redirect_to_access || matches!(status_code, 401 | 403) {
        (
            VerificationState::AccessGated,
            "verification.access_gated",
            "access_challenge_detected",
            "Access gate appears active for this endpoint.",
        )
    } else if (200..300).contains(&status_code) {
        (
            VerificationState::OriginReachable,
            "verification.origin_reachable",
            "origin_responded_without_access_challenge",
            "Origin is directly reachable; confirm this is intended.",
        )
    } else {
        (
            VerificationState::Misconfigured,
            "verification.misconfigured",
            "unexpected_http_response_for_gate_probe",
            "Inspect route/app configuration and verify expected Access gate wiring.",
        )
    };

    VerificationStatus {
        source: "verify_http_gate",
        target: target.to_string(),
        state,
        code,
        reason,
        hint,
        status_code: Some(status_code),
        redirect_location,
        checked_at_unix_ms: now_unix_ms(),
        latency_ms,
        transport_error: None,
    }
}

pub fn timeout_result(target: &str, latency_ms: u128) -> VerificationStatus {
    VerificationStatus {
        source: "verify_http_gate",
        target: target.to_string(),
        state: VerificationState::Timeout,
        code: "verification.timeout",
        reason: "probe_request_timed_out",
        hint: "Increase timeout_ms or verify origin/connectivity for this endpoint.",
        status_code: None,
        redirect_location: None,
        checked_at_unix_ms: now_unix_ms(),
        latency_ms,
        transport_error: None,
    }
}

pub fn transport_error_result(
    target: &str,
    latency_ms: u128,
    message: String,
) -> VerificationStatus {
    VerificationStatus {
        source: "verify_http_gate",
        target: target.to_string(),
        state: VerificationState::TransportError,
        code: "verification.transport_error",
        reason: "probe_transport_failure",
        hint: "Verify DNS/network reachability and TLS configuration for this endpoint.",
        status_code: None,
        redirect_location: None,
        checked_at_unix_ms: now_unix_ms(),
        latency_ms,
        transport_error: Some(message),
    }
}

pub fn now_unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        ExpectedVerificationState, VerificationState, classify_http_result, timeout_result,
        transport_error_result,
    };

    #[test]
    fn classifies_access_gated_redirect() {
        let result = classify_http_result(
            "https://preview.example.com",
            302,
            Some("https://preview.example.com/cdn-cgi/access/login".to_string()),
            25,
        );
        assert_eq!(result.state, VerificationState::AccessGated);
        assert_eq!(result.code, "verification.access_gated");
    }

    #[test]
    fn classifies_origin_reachable() {
        let result = classify_http_result("https://preview.example.com", 200, None, 12);
        assert_eq!(result.state, VerificationState::OriginReachable);
        assert_eq!(result.code, "verification.origin_reachable");
    }

    #[test]
    fn classifies_misconfigured_route() {
        let result = classify_http_result("https://preview.example.com", 404, None, 19);
        assert_eq!(result.state, VerificationState::Misconfigured);
        assert_eq!(result.code, "verification.misconfigured");
    }

    #[test]
    fn classifies_timeout_result() {
        let result = timeout_result("https://preview.example.com", 5001);
        assert_eq!(result.state, VerificationState::Timeout);
        assert_eq!(result.code, "verification.timeout");
    }

    #[test]
    fn classifies_transport_error_result() {
        let result = transport_error_result(
            "https://preview.example.com",
            2,
            "connection refused".to_string(),
        );
        assert_eq!(result.state, VerificationState::TransportError);
        assert_eq!(result.code, "verification.transport_error");
    }

    #[test]
    fn expected_state_matching_is_explicit() {
        assert!(ExpectedVerificationState::AccessGated.matches(VerificationState::AccessGated));
        assert!(
            !ExpectedVerificationState::AccessGated.matches(VerificationState::OriginReachable)
        );
        assert!(ExpectedVerificationState::Any.matches(VerificationState::Timeout));
    }
}
