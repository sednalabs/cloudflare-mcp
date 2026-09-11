use serde_json::{Map, Value};

const REDACTED_SECRET_VALUE: &str = "<redacted-secret>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PagesProjectUpdateInputError {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
    pub(crate) hint: &'static str,
    pub(crate) field: String,
    pub(crate) actual_shape: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NormalizedPagesProjectUpdateSettings {
    pub(crate) settings: Value,
    pub(crate) normalized_from_json_string: bool,
}

pub(crate) fn normalize_pages_project_update_settings(
    input: Option<Value>,
) -> Result<NormalizedPagesProjectUpdateSettings, PagesProjectUpdateInputError> {
    let Some(input) = input else {
        return Err(input_error(
            "pages_project_update.missing_settings",
            "Pages project update requires a settings object.",
            "Pass one non-empty JSON object; do not replay an entire project GET response.",
            "settings",
            None,
        ));
    };

    let (settings, normalized_from_json_string) = match input {
        Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(input_error(
                    "pages_project_update.empty_settings",
                    "Pages project update settings must not be empty.",
                    "Pass one non-empty JSON object; omit settings that are not changing.",
                    "settings",
                    None,
                ));
            }
            let parsed = serde_json::from_str(trimmed).map_err(|_| {
                input_error(
                    "pages_project_update.invalid_settings_json",
                    "Pages project update settings JSON could not be parsed.",
                    "Pass settings as a JSON object or an escaped JSON object string.",
                    "settings",
                    Some("string"),
                )
            })?;
            (parsed, true)
        }
        value => (value, false),
    };

    let Some(object) = settings.as_object() else {
        return Err(input_error(
            "pages_project_update.invalid_settings_shape",
            "Pages project update settings must be a JSON object.",
            "Pass a non-empty object, not a scalar, array, or null.",
            "settings",
            Some(json_shape(&settings)),
        ));
    };
    if object.is_empty() {
        return Err(input_error(
            "pages_project_update.empty_settings",
            "Pages project update settings must not be empty.",
            "Pass one non-empty JSON object; omit settings that are not changing.",
            "settings",
            None,
        ));
    }

    validate_environment_variables(object)?;
    Ok(NormalizedPagesProjectUpdateSettings {
        settings,
        normalized_from_json_string,
    })
}

pub(crate) fn redact_pages_project_update_settings(settings: &Value) -> Value {
    let mut redacted = settings.clone();
    redact_secret_text_values(&mut redacted);
    redacted
}

fn validate_environment_variables(
    settings: &Map<String, Value>,
) -> Result<(), PagesProjectUpdateInputError> {
    validate_environment_variable_map(settings.get("env_vars"), "env_vars")?;
    let Some(deployment_configs) = settings.get("deployment_configs") else {
        return Ok(());
    };
    let Some(deployment_configs) = deployment_configs.as_object() else {
        return Err(input_error(
            "pages_project_update.invalid_deployment_configs_shape",
            "deployment_configs must be a JSON object when supplied.",
            "Pass an object keyed by the Pages deployment environment.",
            "deployment_configs",
            Some(json_shape(deployment_configs)),
        ));
    };
    for (environment, config) in deployment_configs {
        let Some(config) = config.as_object() else {
            return Err(input_error(
                "pages_project_update.invalid_deployment_config_shape",
                "A Pages deployment configuration must be a JSON object.",
                "Pass an object containing only the deployment settings that are changing.",
                &format!("deployment_configs.{environment}"),
                Some(json_shape(config)),
            ));
        };
        validate_environment_variable_map(
            config.get("env_vars"),
            &format!("deployment_configs.{environment}.env_vars"),
        )?;
    }
    Ok(())
}

fn validate_environment_variable_map(
    env_vars: Option<&Value>,
    field: &str,
) -> Result<(), PagesProjectUpdateInputError> {
    let Some(env_vars) = env_vars else {
        return Ok(());
    };
    if env_vars.is_null() {
        return Ok(());
    }
    let Some(env_vars) = env_vars.as_object() else {
        return Err(input_error(
            "pages_project_update.invalid_env_vars_shape",
            "Pages environment variables must be an object or null.",
            "Pass an object of exact variable changes; use null only where the Pages API documents deletion.",
            field,
            Some(json_shape(env_vars)),
        ));
    };
    for (name, entry) in env_vars {
        if entry.is_null() {
            continue;
        }
        let Some(entry) = entry.as_object() else {
            return Err(input_error(
                "pages_project_update.invalid_env_var_shape",
                "Each Pages environment variable must be an object or null.",
                "Pass an exact variable object, or null to delete that variable.",
                &format!("{field}.{name}"),
                Some(json_shape(entry)),
            ));
        };
        if entry.get("type").and_then(Value::as_str) != Some("secret_text") {
            continue;
        }
        let Some(value) = entry.get("value").and_then(Value::as_str) else {
            return Err(input_error(
                "pages_project_update.secret_value_required",
                "A Pages secret_text update requires an exact non-empty secret value.",
                "Set the exact replacement value, omit an unchanged secret, or use null to delete that variable.",
                &format!("{field}.{name}"),
                None,
            ));
        };
        if value.trim().is_empty() {
            return Err(input_error(
                "pages_project_update.secret_value_required",
                "A Pages secret_text update requires an exact non-empty secret value.",
                "Set the exact replacement value, omit an unchanged secret, or use null to delete that variable.",
                &format!("{field}.{name}"),
                None,
            ));
        }
        if is_obviously_masked_secret(value) {
            return Err(input_error(
                "pages_project_update.masked_secret_value",
                "A masked Pages secret_text value cannot be used as a replacement.",
                "Set the exact replacement value, omit an unchanged secret, or use null to delete that variable.",
                &format!("{field}.{name}"),
                None,
            ));
        }
    }
    Ok(())
}

fn redact_secret_text_values(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                redact_secret_text_values(value);
            }
        }
        Value::Object(values) => {
            if values.get("type").and_then(Value::as_str) == Some("secret_text") {
                values.insert(
                    "value".to_string(),
                    Value::String(REDACTED_SECRET_VALUE.into()),
                );
            }
            for value in values.values_mut() {
                redact_secret_text_values(value);
            }
        }
        _ => {}
    }
}

fn is_obviously_masked_secret(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && (value.chars().all(|character| character == '*')
            || matches!(
                value.to_ascii_lowercase().as_str(),
                "redacted"
                    | "masked"
                    | "<redacted>"
                    | "<masked>"
                    | "[redacted]"
                    | "[masked]"
                    | REDACTED_SECRET_VALUE
            ))
}

fn json_shape(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn input_error(
    code: &'static str,
    message: &'static str,
    hint: &'static str,
    field: &str,
    actual_shape: Option<&'static str>,
) -> PagesProjectUpdateInputError {
    PagesProjectUpdateInputError {
        code,
        message,
        hint,
        field: field.to_string(),
        actual_shape,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{normalize_pages_project_update_settings, redact_pages_project_update_settings};

    #[test]
    fn accepts_exact_secret_values_and_explicit_null_deletions() {
        let normalized = normalize_pages_project_update_settings(Some(json!({
            "deployment_configs": {
                "production": {
                    "env_vars": {
                        "NEW_SECRET": {"type": "secret_text", "value": "known-value"},
                        "OLD_SECRET": null,
                    }
                }
            }
        })))
        .expect("valid Pages update");
        assert!(!normalized.normalized_from_json_string);
    }

    #[test]
    fn rejects_empty_and_masked_secret_replacements() {
        for value in ["", "********", "<redacted>"] {
            let error = normalize_pages_project_update_settings(Some(json!({
                "deployment_configs": {
                    "production": {
                        "env_vars": {"SECRET": {"type": "secret_text", "value": value}}
                    }
                }
            })))
            .expect_err("unsafe secret input");
            assert!(error.code.starts_with("pages_project_update."));
        }
    }

    #[test]
    fn redacts_secret_values_without_round_tripping_unmentioned_settings() {
        let settings = json!({
            "deployment_configs": {
                "production": {
                    "env_vars": {
                        "SECRET": {"type": "secret_text", "value": "known-value"},
                        "PLAIN": {"type": "plain_text", "value": "visible"}
                    }
                }
            }
        });
        let redacted = redact_pages_project_update_settings(&settings);
        assert_eq!(
            redacted["deployment_configs"]["production"]["env_vars"]["SECRET"]["value"],
            json!("<redacted-secret>")
        );
        assert!(redacted["deployment_configs"]["preview"].is_null());
    }
}
