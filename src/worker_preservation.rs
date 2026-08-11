use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::cloudflare::model::{WorkerSchedule, WorkerSettings};
use crate::cloudflare::{AdapterError, CloudflareClient};

#[derive(Debug, Clone)]
pub(crate) struct WorkerPreservationSnapshot {
    canonical_settings: Value,
    schedule_crons: Vec<String>,
    settings_sha256: String,
    schedules_sha256: String,
    binding_descriptors: Vec<Value>,
    setting_keys: Vec<String>,
    main_module: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct WorkerPreservationError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) hint: &'static str,
}

#[derive(Debug, Clone)]
pub(crate) enum WorkerPreservationReadError {
    Provider {
        product: &'static str,
        error: AdapterError,
    },
    Invalid(WorkerPreservationError),
}

impl WorkerPreservationReadError {
    pub(crate) fn payload(&self) -> Value {
        match self {
            Self::Provider { product, error } => json!({
                "code": "workers.upload_preservation_read_failed",
                "message": format!("Worker {product} could not be read for preservation proof"),
                "hint": "Verify the exact Worker target and read permission, then rerun the guarded dry-run.",
                "readback_error": error.payload(),
            }),
            Self::Invalid(error) => error.payload(),
        }
    }
}

pub(crate) async fn read_worker_preservation(
    client: &CloudflareClient,
    account_id: &str,
    script_name: &str,
) -> Result<WorkerPreservationSnapshot, WorkerPreservationReadError> {
    let settings = client
        .get_worker_settings(account_id, script_name)
        .await
        .map_err(|error| WorkerPreservationReadError::Provider {
            product: "settings and bindings",
            error,
        })?;
    let schedules = client
        .get_worker_schedules(account_id, script_name)
        .await
        .map_err(|error| WorkerPreservationReadError::Provider {
            product: "schedules",
            error,
        })?;
    WorkerPreservationSnapshot::from_readback(&settings, &schedules)
        .map_err(WorkerPreservationReadError::Invalid)
}

impl WorkerPreservationError {
    fn new(code: &'static str, message: impl Into<String>, hint: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            hint,
        }
    }

    pub(crate) fn payload(&self) -> Value {
        json!({
            "code": self.code,
            "message": self.message,
            "hint": self.hint,
        })
    }
}

impl WorkerPreservationSnapshot {
    pub(crate) fn from_readback(
        settings: &WorkerSettings,
        schedules: &[WorkerSchedule],
    ) -> Result<Self, WorkerPreservationError> {
        let bindings = settings.bindings.as_deref().ok_or_else(|| {
            WorkerPreservationError::new(
                "workers.upload_preservation_bindings_absent",
                "Worker settings readback omitted the bindings array",
                "Do not upload until Cloudflare returns a complete Worker settings readback.",
            )
        })?;
        let mut binding_names = BTreeSet::new();
        let mut binding_descriptors = Vec::with_capacity(bindings.len());
        for (index, binding) in bindings.iter().enumerate() {
            let object = binding.as_object().ok_or_else(|| {
                WorkerPreservationError::new(
                    "workers.upload_preservation_binding_invalid",
                    format!("Worker binding at index {index} was not an object"),
                    "Do not upload until every binding has an unambiguous name and type.",
                )
            })?;
            let name = required_binding_string(object, "name", index)?;
            let binding_type = required_binding_string(object, "type", index)?;
            if !binding_names.insert(name.to_string()) {
                return Err(WorkerPreservationError::new(
                    "workers.upload_preservation_binding_ambiguous",
                    format!("Worker settings returned duplicate binding name {name}"),
                    "Do not upload until the Worker binding inventory is unambiguous.",
                ));
            }
            binding_descriptors.push(json!({
                "name": name,
                "type": binding_type,
            }));
        }
        binding_descriptors.sort_by(|left, right| {
            left["name"]
                .as_str()
                .cmp(&right["name"].as_str())
                .then_with(|| left["type"].as_str().cmp(&right["type"].as_str()))
        });

        let mut schedule_crons = Vec::with_capacity(schedules.len());
        let mut unique_crons = BTreeSet::new();
        for (index, schedule) in schedules.iter().enumerate() {
            let cron = schedule.cron.trim();
            if cron.is_empty() {
                return Err(WorkerPreservationError::new(
                    "workers.upload_preservation_schedule_invalid",
                    format!("Worker schedule at index {index} had an empty cron expression"),
                    "Do not upload until the Worker schedule inventory is canonical.",
                ));
            }
            if !unique_crons.insert(cron.to_string()) {
                return Err(WorkerPreservationError::new(
                    "workers.upload_preservation_schedule_ambiguous",
                    format!("Worker schedules returned duplicate cron expression {cron}"),
                    "Do not upload until the Worker schedule inventory is unambiguous.",
                ));
            }
            schedule_crons.push(cron.to_string());
        }
        schedule_crons.sort();

        let settings_value = serde_json::to_value(settings).map_err(|err| {
            WorkerPreservationError::new(
                "workers.upload_preservation_settings_invalid",
                format!("Worker settings could not be normalized: {err}"),
                "Do not upload until Worker settings can be normalized for comparison.",
            )
        })?;
        let canonical_settings = canonicalize_json(settings_value);
        let settings_sha256 = stable_json_sha256(&canonical_settings)?;
        let schedules_sha256 = stable_json_sha256(&schedule_crons)?;
        let setting_keys = canonical_settings
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .filter(|(_, value)| !value.is_null())
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(Self {
            canonical_settings,
            schedule_crons,
            settings_sha256,
            schedules_sha256,
            binding_descriptors,
            setting_keys,
            main_module: settings
                .main_module
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        })
    }

    pub(crate) fn validate_requested_metadata(
        &self,
        metadata: &Value,
    ) -> Result<(), WorkerPreservationError> {
        let Some(metadata) = metadata.as_object() else {
            return Err(WorkerPreservationError::new(
                "workers.upload_preservation_metadata_invalid",
                "Worker module metadata was not an object",
                "Use object metadata and retry the guarded dry-run.",
            ));
        };
        let settings = self.canonical_settings.as_object().ok_or_else(|| {
            WorkerPreservationError::new(
                "workers.upload_preservation_settings_invalid",
                "Worker settings readback was not an object",
                "Do not upload until Worker settings can be normalized for comparison.",
            )
        })?;
        for (key, requested) in metadata {
            if matches!(
                key.as_str(),
                "main_module" | "body_part" | "parts" | "bindings"
            ) {
                continue;
            }
            let Some(current) = settings.get(key) else {
                return Err(WorkerPreservationError::new(
                    "workers.upload_preservation_metadata_unproven",
                    format!("Upload metadata key {key} was absent from current settings readback"),
                    "For an existing Worker, omit unproven metadata changes or use the settings tool separately.",
                ));
            };
            if canonicalize_json(requested.clone()) != *current {
                return Err(WorkerPreservationError::new(
                    "workers.upload_preservation_metadata_change_denied",
                    format!("Upload metadata key {key} differs from current Worker settings"),
                    "Use workers_upload_script for code-only updates; change settings in a separate guarded operation.",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_requested_main_module(
        &self,
        requested: Option<&str>,
    ) -> Result<(), WorkerPreservationError> {
        let Some(current) = self.main_module.as_deref() else {
            return Ok(());
        };
        if requested.is_some_and(|requested| requested.trim() != current) {
            return Err(WorkerPreservationError::new(
                "workers.upload_preservation_main_module_change_denied",
                "Requested main_module differs from the existing Worker setting",
                "Use the existing main module for a code-only update or change settings separately.",
            ));
        }
        Ok(())
    }

    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.settings_sha256 == other.settings_sha256
            && self.schedules_sha256 == other.schedules_sha256
    }

    pub(crate) fn main_module_reported(&self) -> bool {
        self.main_module.is_some()
    }

    pub(crate) fn token_binding(&self) -> Value {
        json!({
            "settings_sha256": self.settings_sha256,
            "schedules_sha256": self.schedules_sha256,
        })
    }

    pub(crate) fn public_summary(&self) -> Value {
        json!({
            "settings_sha256": self.settings_sha256,
            "schedules_sha256": self.schedules_sha256,
            "setting_keys": self.setting_keys,
            "bindings": self.binding_descriptors,
            "binding_count": self.binding_descriptors.len(),
            "schedule_crons": self.schedule_crons,
            "schedule_count": self.schedule_crons.len(),
            "main_module_reported": self.main_module.is_some(),
            "secret_values_included": false,
        })
    }
}

fn required_binding_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<&'a str, WorkerPreservationError> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match value {
        Some(value) => Ok(value),
        None => Err(WorkerPreservationError::new(
            "workers.upload_preservation_binding_invalid",
            format!("Worker binding at index {index} omitted a canonical {field}"),
            "Do not upload until every binding has an unambiguous name and type.",
        )),
    }
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted = object
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        other => other,
    }
}

fn stable_json_sha256<T: Serialize>(value: &T) -> Result<String, WorkerPreservationError> {
    let bytes = serde_json::to_vec(value).map_err(|err| {
        WorkerPreservationError::new(
            "workers.upload_preservation_digest_failed",
            format!("Worker preservation state could not be serialized: {err}"),
            "Do not upload until the preservation state can be hashed deterministically.",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> WorkerSettings {
        serde_json::from_value(json!({
            "main_module": null,
            "compatibility_date": "2026-08-11",
            "bindings": [
                {"type": "d1", "name": "DB", "id": "db-1"},
                {"type": "secret_text", "name": "TOKEN"}
            ],
            "observability": {"enabled": true, "logs": {"enabled": true}}
        }))
        .expect("settings")
    }

    #[test]
    fn summary_preserves_d1_and_secret_shape_without_values() {
        let snapshot = WorkerPreservationSnapshot::from_readback(
            &settings(),
            &[WorkerSchedule {
                cron: "*/5 * * * *".to_string(),
                created_on: Some("2026-08-11T00:00:00Z".to_string()),
                modified_on: None,
            }],
        )
        .expect("snapshot");
        let summary = snapshot.public_summary();
        assert_eq!(summary["binding_count"], json!(2));
        assert_eq!(summary["bindings"][0], json!({"name": "DB", "type": "d1"}));
        assert_eq!(
            summary["bindings"][1],
            json!({"name": "TOKEN", "type": "secret_text"})
        );
        assert_eq!(summary["schedule_crons"], json!(["*/5 * * * *"]));
        assert_eq!(summary["secret_values_included"], json!(false));
        let serialized = summary.to_string();
        assert!(!serialized.contains("db-1"));
        assert!(!serialized.contains("secret-value"));
    }

    #[test]
    fn rejects_missing_and_ambiguous_binding_readback() {
        let absent = serde_json::from_value::<WorkerSettings>(json!({
            "main_module": null
        }))
        .expect("settings");
        assert_eq!(
            WorkerPreservationSnapshot::from_readback(&absent, &[])
                .expect_err("missing bindings")
                .code,
            "workers.upload_preservation_bindings_absent"
        );
        let duplicate = serde_json::from_value::<WorkerSettings>(json!({
            "bindings": [
                {"type": "d1", "name": "DB"},
                {"type": "secret_text", "name": "DB"}
            ]
        }))
        .expect("settings");
        assert_eq!(
            WorkerPreservationSnapshot::from_readback(&duplicate, &[])
                .expect_err("duplicate bindings")
                .code,
            "workers.upload_preservation_binding_ambiguous"
        );
    }

    #[test]
    fn schedule_timestamps_do_not_change_preservation_identity() {
        let before = WorkerPreservationSnapshot::from_readback(
            &settings(),
            &[WorkerSchedule {
                cron: "*/5 * * * *".to_string(),
                created_on: Some("before".to_string()),
                modified_on: None,
            }],
        )
        .expect("before");
        let after = WorkerPreservationSnapshot::from_readback(
            &settings(),
            &[WorkerSchedule {
                cron: "*/5 * * * *".to_string(),
                created_on: Some("after".to_string()),
                modified_on: Some("after".to_string()),
            }],
        )
        .expect("after");
        assert!(before.matches(&after));
    }

    #[test]
    fn binding_transport_metadata_does_not_compare_redacted_provider_fields() {
        let snapshot = WorkerPreservationSnapshot::from_readback(&settings(), &[])
            .expect("preservation snapshot");

        snapshot
            .validate_requested_metadata(&json!({
                "main_module": "index.js",
                "bindings": [
                    {"type": "d1", "name": "DB"},
                    {"type": "secret_text", "name": "TOKEN", "text": "upload-only-secret"}
                ],
                "parts": ["index.js"],
                "compatibility_date": "2026-08-11"
            }))
            .expect("binding and parts transport metadata must not compare redacted readback");
    }

    #[test]
    fn non_transport_metadata_change_remains_denied() {
        let snapshot = WorkerPreservationSnapshot::from_readback(&settings(), &[])
            .expect("preservation snapshot");

        let error = snapshot
            .validate_requested_metadata(&json!({"compatibility_date": "2026-08-12"}))
            .expect_err("settings change must remain separate");
        assert_eq!(
            error.code,
            "workers.upload_preservation_metadata_change_denied"
        );
    }

    #[test]
    fn schedule_whitespace_is_normalized_for_preservation_identity() {
        let canonical = WorkerPreservationSnapshot::from_readback(
            &settings(),
            &[WorkerSchedule {
                cron: "*/5 * * * *".to_string(),
                created_on: None,
                modified_on: None,
            }],
        )
        .expect("canonical schedule");
        let padded = WorkerPreservationSnapshot::from_readback(
            &settings(),
            &[WorkerSchedule {
                cron: "  */5 * * * *  ".to_string(),
                created_on: None,
                modified_on: None,
            }],
        )
        .expect("padded schedule");

        assert!(canonical.matches(&padded));
        assert_eq!(
            padded.public_summary()["schedule_crons"],
            json!(["*/5 * * * *"])
        );
    }
}
