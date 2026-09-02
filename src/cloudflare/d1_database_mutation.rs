//! Aggregate-safe lifecycle receipts for curated D1 database mutations.
//!
//! Rename and delete share this narrow client boundary. It records where the
//! single HTTP attempt stopped without exposing request headers or response
//! bodies and without inviting string-based error inference by callers.

use mcp_toolkit_core::response_contract::MutationApplyStatus;
use serde::Serialize;

use super::AdapterError;

#[derive(Debug, Clone)]
pub(crate) struct D1DatabaseMutation<T> {
    pub(crate) result: T,
    pub(crate) lifecycle: D1DatabaseMutationLifecycle,
}

#[derive(Debug, Clone)]
pub(crate) struct D1DatabaseMutationError {
    pub(crate) error: AdapterError,
    pub(crate) lifecycle: D1DatabaseMutationLifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct D1DatabaseMutationLifecycle {
    pub(crate) dispatch_stage: &'static str,
    pub(crate) response_stage: &'static str,
    pub(crate) body_stage: &'static str,
    pub(crate) http_status: Option<u16>,
    pub(crate) apply_status: MutationApplyStatus,
}

impl D1DatabaseMutationLifecycle {
    pub(crate) const fn pre_dispatch() -> Self {
        Self {
            dispatch_stage: "pre_dispatch",
            response_stage: "not_received",
            body_stage: "not_read",
            http_status: None,
            apply_status: MutationApplyStatus::RejectedBeforeApply,
        }
    }

    pub(crate) const fn attempted_without_response() -> Self {
        Self {
            dispatch_stage: "attempted",
            response_stage: "not_received",
            body_stage: "not_read",
            http_status: None,
            apply_status: MutationApplyStatus::UncertainAfterDispatch,
        }
    }

    pub(crate) const fn response_received(http_status: u16) -> Self {
        Self {
            dispatch_stage: "attempted",
            response_stage: "received",
            body_stage: "not_read",
            http_status: Some(http_status),
            apply_status: MutationApplyStatus::UncertainAfterDispatch,
        }
    }

    pub(crate) const fn body_read_failed(http_status: u16, partial: bool) -> Self {
        Self {
            dispatch_stage: "attempted",
            response_stage: "received",
            body_stage: if partial {
                "partially_read"
            } else {
                "read_failed"
            },
            http_status: Some(http_status),
            apply_status: MutationApplyStatus::UncertainAfterDispatch,
        }
    }

    pub(crate) const fn body_completely_read(http_status: u16) -> Self {
        Self {
            dispatch_stage: "attempted",
            response_stage: "received",
            body_stage: "completely_read",
            http_status: Some(http_status),
            apply_status: MutationApplyStatus::UncertainAfterDispatch,
        }
    }

    pub(crate) const fn succeeded(http_status: u16) -> Self {
        Self {
            dispatch_stage: "attempted",
            response_stage: "received",
            body_stage: "completely_read",
            http_status: Some(http_status),
            apply_status: MutationApplyStatus::Applied,
        }
    }

    pub(crate) fn provider_calls(self) -> u8 {
        match self.apply_status {
            MutationApplyStatus::RejectedBeforeApply => 0,
            MutationApplyStatus::Applied
            | MutationApplyStatus::Proven
            | MutationApplyStatus::UncertainAfterDispatch => 1,
        }
    }

    pub(crate) fn provider_mutations(self) -> Option<u8> {
        match self.apply_status {
            MutationApplyStatus::RejectedBeforeApply => Some(0),
            MutationApplyStatus::Applied | MutationApplyStatus::Proven => Some(1),
            MutationApplyStatus::UncertainAfterDispatch => None,
        }
    }

    pub(crate) fn failed_before_dispatch(self) -> bool {
        matches!(self.apply_status, MutationApplyStatus::RejectedBeforeApply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_counts_follow_the_apply_boundary() {
        let pre_dispatch = D1DatabaseMutationLifecycle::pre_dispatch();
        assert_eq!(pre_dispatch.provider_calls(), 0);
        assert_eq!(pre_dispatch.provider_mutations(), Some(0));
        assert!(pre_dispatch.failed_before_dispatch());

        for uncertain in [
            D1DatabaseMutationLifecycle::attempted_without_response(),
            D1DatabaseMutationLifecycle::response_received(503),
            D1DatabaseMutationLifecycle::body_read_failed(200, false),
            D1DatabaseMutationLifecycle::body_read_failed(200, true),
            D1DatabaseMutationLifecycle::body_completely_read(200),
        ] {
            assert_eq!(uncertain.provider_calls(), 1);
            assert_eq!(uncertain.provider_mutations(), None);
            assert!(!uncertain.failed_before_dispatch());
        }

        let success = D1DatabaseMutationLifecycle::succeeded(200);
        assert_eq!(success.provider_calls(), 1);
        assert_eq!(success.provider_mutations(), Some(1));
        assert!(!success.failed_before_dispatch());
    }
}
