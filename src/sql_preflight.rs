use std::collections::BTreeSet;

use serde_json::{Value, json};

pub(crate) fn validate_sql_against_schema(sql: &str, schema: &Value, product: &str) -> Value {
    let available_tables = schema_object_names(schema);
    let available_columns = schema_column_names(schema);
    let referenced_tables = referenced_sql_tables(sql);
    let referenced_columns = referenced_sql_columns(sql);
    let missing_tables = referenced_tables
        .iter()
        .filter(|name| !available_tables.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    if !missing_tables.is_empty() {
        return json!({
            "ok": false,
            "error": {
                "code": format!("{product}.table_not_application_schema"),
                "category": "not_application_schema",
                "message": format!("Query references table or dataset not present in application schema metadata: {}", missing_tables.join(", ")),
                "hint": "Use the schema metadata returned by this tool and choose an application table, dataset, or view that is present.",
                "missing_tables": missing_tables,
            },
            "referenced_tables": referenced_tables,
            "referenced_columns": referenced_columns,
            "validation_confidence": "heuristic",
        });
    }
    let missing_columns = referenced_columns
        .iter()
        .filter(|name| !available_columns.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    if !missing_columns.is_empty() {
        return json!({
            "ok": false,
            "error": {
                "code": format!("{product}.column_not_found"),
                "category": "column_does_not_exist",
                "message": format!("Query references column not present in application schema metadata: {}", missing_columns.join(", ")),
                "hint": "Use a column from the returned schema. For derived view columns, check object_type=view rows in schema.columns.",
                "missing_columns": missing_columns,
            },
            "referenced_tables": referenced_tables,
            "referenced_columns": referenced_columns,
            "validation_confidence": "heuristic",
        });
    }
    let view_names = schema
        .get("objects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|object| object.get("type").and_then(Value::as_str) == Some("view"))
        .filter_map(|object| object.get("name").and_then(Value::as_str))
        .map(normalize_sql_identifier)
        .collect::<BTreeSet<_>>();
    let expensive_view_references = referenced_tables
        .iter()
        .filter(|name| view_names.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    json!({
        "ok": true,
        "referenced_tables": referenced_tables,
        "referenced_columns": referenced_columns,
        "validation_confidence": "heuristic",
        "warnings": if expensive_view_references.is_empty() {
            Value::Array(Vec::new())
        } else {
            json!([{
                "code": format!("{product}.view_may_be_expensive"),
                "message": "Query references one or more views; inspect query_plan when available before executing against large datasets.",
                "views": expensive_view_references,
            }])
        },
    })
}

pub(crate) fn analytics_engine_schema_hints(dataset_readback: Option<Value>) -> Value {
    let columns = analytics_engine_columns();
    let objects = dataset_readback
        .as_ref()
        .map(analytics_engine_dataset_objects)
        .unwrap_or_default();
    json!({
        "schema_version": "workers_analytics_engine_sql_v1",
        "source": "cloudflare_workers_analytics_engine_sql_api",
        "objects": objects,
        "columns": columns,
        "blob_mapping": {
            "columns": (1..=20).map(|index| format!("blob{index}")).collect::<Vec<_>>(),
            "type": "string",
            "meaning": "application-defined dimensions written through writeDataPoint blobs",
        },
        "double_mapping": {
            "columns": (1..=20).map(|index| format!("double{index}")).collect::<Vec<_>>(),
            "type": "double",
            "meaning": "application-defined numeric values written through writeDataPoint doubles",
        },
        "index_mapping": {
            "columns": ["index1"],
            "type": "string",
            "meaning": "application-defined sampling key written through writeDataPoint indexes",
        },
        "sampling": {
            "sample_interval_column": "_sample_interval",
            "count_hint": "Use SUM(_sample_interval) instead of COUNT() for sampled-aware counts.",
        },
        "fidelity": {
            "mode": "template",
            "limitations": [
                "application-specific meanings for blob, double, and index fields are not available from Cloudflare SQL metadata",
                "dataset existence comes from SHOW TABLES when readback is enabled",
            ],
        },
    })
}

fn schema_object_names(schema: &Value) -> BTreeSet<String> {
    schema
        .get("objects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|object| object.get("name").and_then(Value::as_str))
        .map(normalize_sql_identifier)
        .collect()
}

fn schema_column_names(schema: &Value) -> BTreeSet<String> {
    schema
        .get("columns")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|column| column.get("column_name").and_then(Value::as_str))
        .map(normalize_sql_identifier)
        .collect()
}

fn referenced_sql_tables(sql: &str) -> Vec<String> {
    let tokens = sql_identifier_tokens(sql);
    let mut tables = BTreeSet::new();
    for window in tokens.windows(2) {
        if matches!(window[0].as_str(), "from" | "join") {
            tables.insert(window[1].clone());
        }
    }
    tables.into_iter().collect()
}

fn referenced_sql_columns(sql: &str) -> Vec<String> {
    let mut columns = BTreeSet::new();
    let tokens = sql_identifier_tokens(sql);
    let keywords = sql_validation_keywords();
    let table_refs = referenced_sql_tables(sql)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let aliases = tokens
        .windows(2)
        .filter(|window| window[0] == "as")
        .map(|window| window[1].clone())
        .collect::<BTreeSet<_>>();
    for (index, token) in tokens.iter().enumerate() {
        if index > 0 && tokens[index - 1] == "as" {
            continue;
        }
        if keywords.contains(token.as_str())
            || table_refs.contains(token)
            || aliases.contains(token)
        {
            continue;
        }
        if token.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        columns.insert(token.clone());
    }
    columns.into_iter().collect()
}

fn sql_identifier_tokens(sql: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = sql.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(ch) = chars.next() {
        if let Some(quote_ch) = quote {
            if ch == quote_ch {
                if chars.peek() == Some(&quote_ch) {
                    let _ = chars.next();
                } else {
                    quote = None;
                }
            }
            continue;
        }
        match ch {
            '\'' | '"' | '`' => {
                if !current.is_empty() {
                    tokens.push(normalize_sql_identifier(&current));
                    current.clear();
                }
                quote = Some(ch);
            }
            ch if ch.is_ascii_alphanumeric() || ch == '_' => current.push(ch),
            _ => {
                if !current.is_empty() {
                    tokens.push(normalize_sql_identifier(&current));
                    current.clear();
                }
            }
        }
    }
    if !current.is_empty() {
        tokens.push(normalize_sql_identifier(&current));
    }
    tokens
}

fn normalize_sql_identifier(value: &str) -> String {
    value
        .trim_matches(|ch| ch == '"' || ch == '`' || ch == '[' || ch == ']')
        .to_ascii_lowercase()
}

fn sql_validation_keywords() -> BTreeSet<&'static str> {
    [
        "select", "from", "where", "join", "inner", "left", "right", "full", "outer", "on", "as",
        "and", "or", "not", "null", "is", "in", "between", "like", "glob", "group", "by", "order",
        "having", "limit", "offset", "desc", "asc", "case", "when", "then", "else", "end", "cast",
        "count", "sum", "avg", "min", "max", "date", "datetime", "now", "interval", "day", "hour",
        "minute", "second", "format", "json", "explain", "query", "plan",
    ]
    .into_iter()
    .collect()
}

fn analytics_engine_columns() -> Vec<Value> {
    let mut columns = vec![
        json!({"table_name": "*", "object_type": "dataset", "column_name": "dataset", "column_type": "string", "derived": false, "source": "cloudflare_documented_schema"}),
        json!({"table_name": "*", "object_type": "dataset", "column_name": "timestamp", "column_type": "DateTime", "derived": false, "source": "cloudflare_documented_schema"}),
        json!({"table_name": "*", "object_type": "dataset", "column_name": "_sample_interval", "column_type": "integer", "derived": false, "source": "cloudflare_documented_schema"}),
        json!({"table_name": "*", "object_type": "dataset", "column_name": "index1", "column_type": "string", "derived": false, "source": "cloudflare_documented_schema"}),
    ];
    for index in 1..=20 {
        columns.push(json!({"table_name": "*", "object_type": "dataset", "column_name": format!("blob{index}"), "column_type": "string", "derived": false, "source": "cloudflare_documented_schema"}));
    }
    for index in 1..=20 {
        columns.push(json!({"table_name": "*", "object_type": "dataset", "column_name": format!("double{index}"), "column_type": "double", "derived": false, "source": "cloudflare_documented_schema"}));
    }
    columns
}

fn analytics_engine_dataset_objects(result: &Value) -> Vec<Value> {
    analytics_engine_result_rows(result)
        .into_iter()
        .filter_map(|row| {
            let name = row
                .get("name")
                .or_else(|| row.get("dataset"))
                .or_else(|| row.get("table"))
                .or_else(|| row.get("table_name"))
                .and_then(Value::as_str)?;
            Some(json!({
                "type": "dataset",
                "name": name,
                "tbl_name": name,
                "sql": null,
            }))
        })
        .collect()
}

fn analytics_engine_result_rows(result: &Value) -> Vec<Value> {
    result
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| {
            result
                .get("result")
                .and_then(|result| result.get("data"))
                .and_then(Value::as_array)
                .cloned()
        })
        .unwrap_or_default()
}
