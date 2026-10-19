//! Ruleset response -> entrypoint PUT projection and complete-state verification.
//! Rule IDs are supported PUT fields; the ruleset's top-level ID is not.

use serde_json::{Map, Value, json};

const RULE_FIELDS: &[&str] = &[
    "id",
    "ref",
    "action",
    "action_parameters",
    "description",
    "enabled",
    "expression",
    "logging",
    "ratelimit",
    "exposed_credential_check",
];
const RULE_RESPONSE_FIELDS: &[&str] = &["version", "last_updated", "categories"];
const RULESET_FIELDS: &[&str] = &[
    "id",
    "name",
    "kind",
    "phase",
    "version",
    "last_updated",
    "description",
    "rules",
];

/// Unknown fields fail closed rather than silently deleting future configuration.
/// Nested action parameters and rate-limit/logging configuration remain intact.
pub(crate) fn write_body(ruleset: &Value) -> Result<Value, &'static str> {
    let object = ruleset.as_object().ok_or("ruleset")?;
    if object
        .keys()
        .any(|key| !RULESET_FIELDS.contains(&key.as_str()))
    {
        return Err("ruleset.unsupported_fields");
    }
    for field in ["id", "name", "kind", "phase", "version"] {
        if !object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err("ruleset.identity");
        }
    }
    let rules = object
        .get("rules")
        .and_then(Value::as_array)
        .ok_or("rules")?;
    let mut projected = Vec::with_capacity(rules.len());
    let mut ids = std::collections::BTreeSet::new();
    let mut refs = std::collections::BTreeSet::new();
    for rule in rules {
        let rule = rule.as_object().ok_or("rules[]")?;
        if rule.keys().any(|key| {
            !RULE_FIELDS.contains(&key.as_str()) && !RULE_RESPONSE_FIELDS.contains(&key.as_str())
        }) {
            return Err("rules[].unsupported_fields");
        }
        for field in ["action", "expression"] {
            if !rule
                .get(field)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
            {
                return Err("rules[].action_or_expression");
            }
        }
        for (field, seen) in [("id", &mut ids), ("ref", &mut refs)] {
            if let Some(value) = rule.get(field) {
                let value = value
                    .as_str()
                    .filter(|value| !value.trim().is_empty())
                    .ok_or("rules[].identity")?;
                if !seen.insert(value) {
                    return Err("rules[].duplicate_identity");
                }
            }
        }
        if rule
            .get("description")
            .is_some_and(|value| !value.is_string())
            || rule.get("enabled").is_some_and(|value| !value.is_boolean())
        {
            return Err("rules[].description_or_enabled");
        }
        for field in [
            "action_parameters",
            "logging",
            "ratelimit",
            "exposed_credential_check",
        ] {
            if rule.get(field).is_some_and(|value| !value.is_object()) {
                return Err("rules[].configuration");
            }
        }
        projected.push(Value::Object(
            rule.iter()
                .filter(|(key, _)| RULE_FIELDS.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        ));
    }
    let mut body = Map::new();
    body.insert("rules".to_string(), Value::Array(projected));
    if let Some(description) = object.get("description") {
        if !description.is_string() {
            return Err("description");
        }
        body.insert("description".to_string(), description.clone());
    }
    Ok(Value::Object(body))
}

/// Compare all writable fields and rule order, plus immutable target identity.
/// Only documented generated ID/ref defaults for newly added rules are ignored.
pub(crate) fn verify_readback(
    current: &Value,
    expected_body: &Value,
    readback: &Value,
) -> Result<(), &'static str> {
    for field in ["id", "name", "kind", "phase"] {
        if current.get(field) != readback.get(field) {
            return Err("ruleset.identity");
        }
    }
    let mut actual = write_body(readback)?;
    let expected_rules = expected_body["rules"].as_array().ok_or("rules")?;
    let actual_rules = actual["rules"].as_array_mut().ok_or("rules")?;
    if actual_rules.len() != expected_rules.len() {
        return Err("rules.length");
    }
    for (expected, actual) in expected_rules.iter().zip(actual_rules) {
        let actual = actual.as_object_mut().ok_or("rules[]")?;
        if expected.get("id").is_none() {
            let id = actual
                .remove("id")
                .filter(|value| value.as_str().is_some_and(|id| !id.is_empty()))
                .ok_or("rules[].id")?;
            if expected.get("ref").is_none() && actual.get("ref") == Some(&id) {
                actual.remove("ref");
            }
        }
    }
    if expected_body.get("description").is_none() && actual.get("description") == Some(&json!("")) {
        actual
            .as_object_mut()
            .ok_or("ruleset")?
            .remove("description");
    }
    if &actual != expected_body {
        return Err("ruleset.writable_fields_or_order");
    }
    Ok(())
}
