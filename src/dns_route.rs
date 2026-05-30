use serde::Serialize;

use crate::cloudflare::{DnsRecord, DnsRecordUpsertRequest};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsRouteAction {
    Create,
    Update,
    Noop,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsRouteVerificationState {
    Matched,
    Missing,
    Mismatch,
    Conflict,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsRouteDesired {
    pub hostname: String,
    pub target: String,
    pub proxied: Option<bool>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsRouteObserved {
    pub record_id: String,
    pub hostname: String,
    pub target: String,
    pub proxied: Option<bool>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsRouteDiff {
    pub content_changed: bool,
    pub proxied_changed: bool,
    pub ttl_changed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsRoutePlan {
    pub action: DnsRouteAction,
    pub reason: &'static str,
    pub desired: DnsRouteDesired,
    pub observed: Option<DnsRouteObserved>,
    pub diff: DnsRouteDiff,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsRouteConflict {
    pub code: &'static str,
    pub message: String,
    pub hint: &'static str,
    pub desired: DnsRouteDesired,
    pub conflicting_record_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsRouteVerification {
    pub state: DnsRouteVerificationState,
    pub code: &'static str,
    pub reason: &'static str,
    pub hint: &'static str,
    pub desired: DnsRouteDesired,
    pub observed: Option<DnsRouteObserved>,
    pub conflicting_record_ids: Vec<String>,
    pub diff: Option<DnsRouteDiff>,
}

pub fn plan_dns_route_reconciliation(
    records: &[DnsRecord],
    request: &DnsRecordUpsertRequest,
) -> Result<DnsRoutePlan, DnsRouteConflict> {
    let desired = desired_from_request(request);
    let matching_records = matching_cname_records(records, &desired.hostname);

    if matching_records.len() > 1 {
        return Err(DnsRouteConflict {
            code: "dns_route.conflict_multiple_records",
            message: format!(
                "multiple CNAME records found for hostname {:?}; reconciliation is ambiguous",
                desired.hostname
            ),
            hint: "Remove duplicate CNAME records and retry route reconciliation.",
            conflicting_record_ids: matching_records
                .iter()
                .map(|record| record.id.clone())
                .collect(),
            desired,
        });
    }

    let observed = matching_records
        .first()
        .map(|record| observed_record(record));
    if let Some(observed) = observed {
        let diff = route_diff(&observed, &desired);
        if !diff.content_changed && !diff.proxied_changed && !diff.ttl_changed {
            return Ok(DnsRoutePlan {
                action: DnsRouteAction::Noop,
                reason: "already_converged",
                desired,
                observed: Some(observed),
                diff,
            });
        }
        return Ok(DnsRoutePlan {
            action: DnsRouteAction::Update,
            reason: "target_or_settings_mismatch",
            desired,
            observed: Some(observed),
            diff,
        });
    }

    Ok(DnsRoutePlan {
        action: DnsRouteAction::Create,
        reason: "no_existing_route",
        desired,
        observed: None,
        diff: DnsRouteDiff {
            content_changed: true,
            proxied_changed: true,
            ttl_changed: true,
        },
    })
}

pub fn verify_dns_route(
    records: &[DnsRecord],
    request: &DnsRecordUpsertRequest,
) -> DnsRouteVerification {
    let desired = desired_from_request(request);
    let matching_records = matching_cname_records(records, &desired.hostname);

    if matching_records.len() > 1 {
        return DnsRouteVerification {
            state: DnsRouteVerificationState::Conflict,
            code: "dns_route.conflict_multiple_records",
            reason: "multiple_cname_records",
            hint: "Remove duplicate CNAME records for hostname before retrying publish.",
            desired,
            observed: None,
            conflicting_record_ids: matching_records
                .iter()
                .map(|record| record.id.clone())
                .collect(),
            diff: None,
        };
    }

    let Some(record) = matching_records.first() else {
        return DnsRouteVerification {
            state: DnsRouteVerificationState::Missing,
            code: "dns_route.route_missing",
            reason: "missing_hostname_route",
            hint: "Create the CNAME route and retry verification.",
            desired,
            observed: None,
            conflicting_record_ids: Vec::new(),
            diff: None,
        };
    };

    let observed = observed_record(record);
    let diff = route_diff(&observed, &desired);
    if !diff.content_changed && !diff.proxied_changed && !diff.ttl_changed {
        return DnsRouteVerification {
            state: DnsRouteVerificationState::Matched,
            code: "dns_route.matched",
            reason: "route_matches_desired_state",
            hint: "Route is converged.",
            desired,
            observed: Some(observed),
            conflicting_record_ids: Vec::new(),
            diff: Some(diff),
        };
    }

    DnsRouteVerification {
        state: DnsRouteVerificationState::Mismatch,
        code: "dns_route.route_mismatch",
        reason: "observed_route_differs_from_desired_state",
        hint: "Run route reconciliation to converge hostname target/proxied/ttl settings.",
        desired,
        observed: Some(observed),
        conflicting_record_ids: Vec::new(),
        diff: Some(diff),
    }
}

fn desired_from_request(request: &DnsRecordUpsertRequest) -> DnsRouteDesired {
    DnsRouteDesired {
        hostname: request.hostname.trim().to_ascii_lowercase(),
        target: request.target.trim().to_ascii_lowercase(),
        proxied: request.proxied,
        ttl: normalize_ttl(request.ttl),
    }
}

fn observed_record(record: &DnsRecord) -> DnsRouteObserved {
    DnsRouteObserved {
        record_id: record.id.clone(),
        hostname: record.name.trim().to_ascii_lowercase(),
        target: record.content.trim().to_ascii_lowercase(),
        proxied: record.proxied,
        ttl: normalize_ttl(record.ttl),
    }
}

fn matching_cname_records<'a>(records: &'a [DnsRecord], hostname: &str) -> Vec<&'a DnsRecord> {
    records
        .iter()
        .filter(|record| {
            record.record_type.eq_ignore_ascii_case("CNAME")
                && record.name.trim().eq_ignore_ascii_case(hostname)
        })
        .collect()
}

fn route_diff(observed: &DnsRouteObserved, desired: &DnsRouteDesired) -> DnsRouteDiff {
    DnsRouteDiff {
        content_changed: !observed.target.eq_ignore_ascii_case(&desired.target),
        proxied_changed: observed.proxied != desired.proxied,
        ttl_changed: observed.ttl != desired.ttl,
    }
}

fn normalize_ttl(value: Option<u32>) -> Option<u32> {
    value.filter(|ttl| *ttl > 0)
}

#[cfg(test)]
mod tests {
    use super::{
        DnsRouteAction, DnsRouteVerificationState, plan_dns_route_reconciliation, verify_dns_route,
    };
    use crate::cloudflare::{DnsRecord, DnsRecordUpsertRequest};

    fn desired() -> DnsRecordUpsertRequest {
        DnsRecordUpsertRequest {
            hostname: "preview.example.com".to_string(),
            target: "tunnel.cfargotunnel.com".to_string(),
            proxied: Some(true),
            ttl: Some(1),
        }
    }

    #[test]
    fn plan_create_when_route_missing() {
        let plan = plan_dns_route_reconciliation(&[], &desired()).expect("plan");
        assert_eq!(plan.action, DnsRouteAction::Create);
        assert_eq!(plan.reason, "no_existing_route");
    }

    #[test]
    fn plan_noop_when_route_matches() {
        let records = vec![DnsRecord {
            id: "rec-1".to_string(),
            name: "preview.example.com".to_string(),
            record_type: "CNAME".to_string(),
            content: "tunnel.cfargotunnel.com".to_string(),
            proxied: Some(true),
            ttl: Some(1),
        }];
        let plan = plan_dns_route_reconciliation(&records, &desired()).expect("plan");
        assert_eq!(plan.action, DnsRouteAction::Noop);
        assert_eq!(plan.reason, "already_converged");
    }

    #[test]
    fn plan_update_when_route_mismatch_detected() {
        let records = vec![DnsRecord {
            id: "rec-1".to_string(),
            name: "preview.example.com".to_string(),
            record_type: "CNAME".to_string(),
            content: "old.cfargotunnel.com".to_string(),
            proxied: Some(false),
            ttl: Some(300),
        }];
        let plan = plan_dns_route_reconciliation(&records, &desired()).expect("plan");
        assert_eq!(plan.action, DnsRouteAction::Update);
        assert!(plan.diff.content_changed);
        assert!(plan.diff.proxied_changed);
        assert!(plan.diff.ttl_changed);
    }

    #[test]
    fn fails_closed_on_duplicate_cname_records() {
        let records = vec![
            DnsRecord {
                id: "rec-1".to_string(),
                name: "preview.example.com".to_string(),
                record_type: "CNAME".to_string(),
                content: "a.cfargotunnel.com".to_string(),
                proxied: Some(true),
                ttl: Some(1),
            },
            DnsRecord {
                id: "rec-2".to_string(),
                name: "preview.example.com".to_string(),
                record_type: "CNAME".to_string(),
                content: "b.cfargotunnel.com".to_string(),
                proxied: Some(true),
                ttl: Some(1),
            },
        ];
        let conflict = plan_dns_route_reconciliation(&records, &desired())
            .expect_err("duplicate records should fail");
        assert_eq!(conflict.code, "dns_route.conflict_multiple_records");
        assert_eq!(conflict.conflicting_record_ids.len(), 2);
    }

    #[test]
    fn verify_reports_mismatch() {
        let records = vec![DnsRecord {
            id: "rec-1".to_string(),
            name: "preview.example.com".to_string(),
            record_type: "CNAME".to_string(),
            content: "old.cfargotunnel.com".to_string(),
            proxied: Some(true),
            ttl: Some(1),
        }];
        let verification = verify_dns_route(&records, &desired());
        assert_eq!(verification.state, DnsRouteVerificationState::Mismatch);
        assert_eq!(verification.code, "dns_route.route_mismatch");
    }
}
