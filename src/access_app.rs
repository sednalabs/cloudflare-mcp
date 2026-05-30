use serde::Serialize;

use crate::cloudflare::AccessApplication;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessAppAction {
    Create,
    Update,
    Noop,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessAppDesired {
    pub hostname: String,
    pub app_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessAppDiff {
    pub name_changed: bool,
    pub from_name: Option<String>,
    pub to_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessAppUpsertPlan {
    pub action: AccessAppAction,
    pub desired: AccessAppDesired,
    pub existing_app: Option<AccessApplication>,
    pub hostname_match_count: usize,
    pub matching_app_ids: Vec<String>,
    pub diff: AccessAppDiff,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessAppConflict {
    pub code: &'static str,
    pub message: String,
    pub hint: &'static str,
    pub desired: AccessAppDesired,
    pub conflicting_app_ids: Vec<String>,
    pub conflicting_app_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessAppValidationError {
    pub code: &'static str,
    pub message: String,
    pub hint: &'static str,
    pub desired: AccessAppDesired,
    pub observed_hostname_match_count: usize,
    pub observed_app_ids: Vec<String>,
    pub observed_app_names: Vec<String>,
}

pub fn plan_access_app_upsert(
    apps: &[AccessApplication],
    hostname: &str,
    app_name: &str,
) -> Result<AccessAppUpsertPlan, AccessAppConflict> {
    let desired = desired(hostname, app_name);
    let matches = matching_apps_for_hostname(apps, &desired.hostname);
    if matches.len() > 1 {
        return Err(AccessAppConflict {
            code: "access_app.duplicate_hostname_conflict",
            message: format!(
                "multiple Access apps match hostname {:?}; upsert is ambiguous",
                desired.hostname
            ),
            hint: "Delete or consolidate duplicate Access apps for hostname before retrying.",
            conflicting_app_ids: matches.iter().map(|app| app.id.clone()).collect(),
            conflicting_app_names: matches.iter().map(|app| app.name.clone()).collect(),
            desired,
        });
    }

    let existing = matches.into_iter().next();
    let (action, diff) = match existing.as_ref() {
        None => (
            AccessAppAction::Create,
            AccessAppDiff {
                name_changed: true,
                from_name: None,
                to_name: desired.app_name.clone(),
            },
        ),
        Some(existing) if existing.name == desired.app_name => (
            AccessAppAction::Noop,
            AccessAppDiff {
                name_changed: false,
                from_name: Some(existing.name.clone()),
                to_name: desired.app_name.clone(),
            },
        ),
        Some(existing) => (
            AccessAppAction::Update,
            AccessAppDiff {
                name_changed: true,
                from_name: Some(existing.name.clone()),
                to_name: desired.app_name.clone(),
            },
        ),
    };

    let matching_app_ids = existing
        .as_ref()
        .map(|app| vec![app.id.clone()])
        .unwrap_or_default();
    Ok(AccessAppUpsertPlan {
        action,
        desired,
        existing_app: existing.cloned(),
        hostname_match_count: matching_app_ids.len(),
        matching_app_ids,
        diff,
    })
}

pub fn validate_access_app_readback(
    apps: &[AccessApplication],
    hostname: &str,
    app_name: &str,
) -> Result<AccessApplication, AccessAppValidationError> {
    let desired = desired(hostname, app_name);
    let hostname_matches = matching_apps_for_hostname(apps, &desired.hostname);
    let desired_matches = hostname_matches
        .iter()
        .filter(|app| app.name == desired.app_name)
        .cloned()
        .collect::<Vec<_>>();

    if desired_matches.len() == 1 {
        return Ok(desired_matches[0].clone());
    }
    if hostname_matches.len() > 1 {
        return Err(AccessAppValidationError {
            code: "access_app.readback_duplicate_hostname_conflict",
            message: format!(
                "readback found multiple apps for hostname {:?}; expected one",
                desired.hostname
            ),
            hint: "Reconcile duplicate Access apps for hostname before retrying.",
            desired,
            observed_hostname_match_count: hostname_matches.len(),
            observed_app_ids: hostname_matches.iter().map(|app| app.id.clone()).collect(),
            observed_app_names: hostname_matches
                .iter()
                .map(|app| app.name.clone())
                .collect(),
        });
    }
    if hostname_matches.is_empty() {
        return Err(AccessAppValidationError {
            code: "access_app.readback_missing_app",
            message: format!(
                "readback did not find Access app for hostname {:?}",
                desired.hostname
            ),
            hint: "Retry upsert and verify Access app permissions for this account.",
            desired,
            observed_hostname_match_count: 0,
            observed_app_ids: Vec::new(),
            observed_app_names: Vec::new(),
        });
    }

    Err(AccessAppValidationError {
        code: "access_app.readback_name_mismatch",
        message: format!(
            "readback found hostname match but expected app_name {:?}",
            desired.app_name
        ),
        hint: "Update app_name or reconcile existing Access app naming.",
        desired,
        observed_hostname_match_count: hostname_matches.len(),
        observed_app_ids: hostname_matches.iter().map(|app| app.id.clone()).collect(),
        observed_app_names: hostname_matches
            .iter()
            .map(|app| app.name.clone())
            .collect(),
    })
}

fn desired(hostname: &str, app_name: &str) -> AccessAppDesired {
    AccessAppDesired {
        hostname: hostname.trim().to_ascii_lowercase(),
        app_name: app_name.trim().to_string(),
    }
}

fn matching_apps_for_hostname<'a>(
    apps: &'a [AccessApplication],
    hostname: &str,
) -> Vec<&'a AccessApplication> {
    apps.iter()
        .filter(|app| {
            app.domain
                .as_deref()
                .map(|domain| domain.trim().eq_ignore_ascii_case(hostname))
                .unwrap_or(false)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{AccessAppAction, plan_access_app_upsert, validate_access_app_readback};
    use crate::cloudflare::AccessApplication;

    fn app(id: &str, name: &str, domain: &str) -> AccessApplication {
        AccessApplication {
            id: id.to_string(),
            name: name.to_string(),
            domain: Some(domain.to_string()),
            aud: None,
        }
    }

    #[test]
    fn plans_create_when_no_existing_app_matches_hostname() {
        let plan = plan_access_app_upsert(&[], "preview.example.com", "preview-app").expect("plan");
        assert_eq!(plan.action, AccessAppAction::Create);
    }

    #[test]
    fn plans_noop_when_existing_matches_hostname_and_name() {
        let plan = plan_access_app_upsert(
            &[app("a1", "preview-app", "preview.example.com")],
            "preview.example.com",
            "preview-app",
        )
        .expect("plan");
        assert_eq!(plan.action, AccessAppAction::Noop);
        assert!(!plan.diff.name_changed);
    }

    #[test]
    fn plans_update_when_existing_name_differs() {
        let plan = plan_access_app_upsert(
            &[app("a1", "old-name", "preview.example.com")],
            "preview.example.com",
            "preview-app",
        )
        .expect("plan");
        assert_eq!(plan.action, AccessAppAction::Update);
        assert!(plan.diff.name_changed);
    }

    #[test]
    fn fails_closed_on_duplicate_hostname_matches() {
        let conflict = plan_access_app_upsert(
            &[
                app("a1", "preview-app", "preview.example.com"),
                app("a2", "preview-app-2", "preview.example.com"),
            ],
            "preview.example.com",
            "preview-app",
        )
        .expect_err("duplicate hostnames should conflict");
        assert_eq!(conflict.code, "access_app.duplicate_hostname_conflict");
        assert_eq!(conflict.conflicting_app_ids.len(), 2);
    }

    #[test]
    fn readback_detects_name_mismatch() {
        let err = validate_access_app_readback(
            &[app("a1", "old-name", "preview.example.com")],
            "preview.example.com",
            "preview-app",
        )
        .expect_err("name mismatch should fail");
        assert_eq!(err.code, "access_app.readback_name_mismatch");
    }
}
