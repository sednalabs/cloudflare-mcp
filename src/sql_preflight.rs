use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

pub(crate) fn validate_sql_against_schema(sql: &str, schema: &Value, product: &str) -> Value {
    let available_tables = schema_object_names(schema);
    let available_columns = schema_column_names(schema);
    let referenced_tables = referenced_sql_tables(sql);
    let referenced_columns = referenced_sql_columns(sql);
    let referenced_functions = referenced_sql_functions(sql);
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
            "referenced_functions": referenced_functions,
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
            "referenced_functions": referenced_functions,
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
        "referenced_functions": referenced_functions,
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
    let tokens = sql_tokens(sql);
    let cte_names = sql_cte_names(sql);
    let mut tables = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        let SqlToken::Identifier(keyword) = token else {
            continue;
        };
        if !matches!(keyword.as_str(), "from" | "join") {
            continue;
        }
        match tokens.get(index + 1) {
            Some(SqlToken::Identifier(schema_name))
                if matches!(tokens.get(index + 2), Some(SqlToken::Symbol('.'))) =>
            {
                let Some(SqlToken::Identifier(name)) = tokens.get(index + 3) else {
                    continue;
                };
                let _ = schema_name;
                tables.insert(name.clone());
            }
            Some(SqlToken::Identifier(name)) => {
                if matches!(tokens.get(index + 2), Some(SqlToken::Symbol('('))) {
                    continue;
                }
                if cte_names.contains(name) {
                    continue;
                }
                tables.insert(name.clone());
            }
            Some(SqlToken::Symbol('(')) | None => {}
            Some(SqlToken::Symbol(_)) => {}
        }
    }
    tables.into_iter().collect()
}

fn referenced_sql_columns(sql: &str) -> Vec<String> {
    let mut columns = BTreeSet::new();
    let tokens = sql_tokens(sql);
    let keywords = sql_validation_keywords();
    let function_names = referenced_sql_functions(sql)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let table_refs = referenced_sql_tables(sql)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let cte_definitions = sql_cte_definitions(sql);
    let cte_names = cte_definitions.keys().cloned().collect::<BTreeSet<_>>();
    let aliases = sql_aliases(sql);
    let virtual_source_aliases = sql_virtual_source_aliases(sql);
    for (index, token) in tokens.iter().enumerate() {
        let SqlToken::Identifier(token) = token else {
            continue;
        };
        if matches!(
            previous_sql_token(&tokens, index, 1),
            Some(SqlToken::Identifier(previous)) if previous == "as"
        ) {
            continue;
        }
        if matches!(tokens.get(index + 1), Some(SqlToken::Symbol('.')))
            && is_cte_source_qualifier_at(&tokens, index, &cte_definitions)
        {
            continue;
        }
        if matches!(tokens.get(index + 1), Some(SqlToken::Symbol('.')))
            && is_schema_qualifier_at(&tokens, index, &table_refs)
        {
            continue;
        }
        if matches!(tokens.get(index + 1), Some(SqlToken::Symbol('.')))
            && is_known_sql_qualifier_at(
                &tokens,
                index,
                &table_refs,
                &aliases,
                &virtual_source_aliases,
            )
        {
            continue;
        }
        if matches!(
            (
                previous_sql_token(&tokens, index, 2),
                previous_sql_token(&tokens, index, 1)
            ),
            (Some(SqlToken::Identifier(qualifier)), Some(SqlToken::Symbol('.')))
                if virtual_source_aliases.contains(qualifier)
        ) {
            continue;
        }
        if keywords.contains(token.as_str())
            || is_table_reference_name_at(&tokens, index, &table_refs)
            || is_source_alias_declaration_at(&tokens, index, &aliases)
            || is_select_alias_reference_at(&tokens, index)
            || is_function_name_at(&tokens, index, &function_names)
            || is_virtual_output_column_at(&tokens, index)
            || is_cte_output_column_at(&tokens, index, &cte_definitions)
            || (cte_names.contains(token) && is_source_identifier_at(&tokens, index))
            || (cte_names.contains(token) && is_cte_definition_identifier_at(&tokens, index))
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

fn previous_sql_token(tokens: &[SqlToken], index: usize, offset: usize) -> Option<&SqlToken> {
    index
        .checked_sub(offset)
        .and_then(|previous| tokens.get(previous))
}

fn is_source_identifier_at(tokens: &[SqlToken], index: usize) -> bool {
    matches!(
        previous_sql_token(tokens, index, 1),
        Some(SqlToken::Identifier(keyword)) if matches!(keyword.as_str(), "from" | "join")
    )
}

fn is_table_reference_name_at(
    tokens: &[SqlToken],
    index: usize,
    table_refs: &BTreeSet<String>,
) -> bool {
    let Some(SqlToken::Identifier(name)) = tokens.get(index) else {
        return false;
    };
    if !table_refs.contains(name) {
        return false;
    }
    matches!(
        previous_sql_token(tokens, index, 1),
        Some(SqlToken::Identifier(keyword)) if matches!(keyword.as_str(), "from" | "join")
    ) || matches!(
        (
            previous_sql_token(tokens, index, 3),
            previous_sql_token(tokens, index, 1)
        ),
        (Some(SqlToken::Identifier(keyword)), Some(SqlToken::Symbol('.')))
            if matches!(keyword.as_str(), "from" | "join")
    )
}

fn is_source_alias_declaration_at(
    tokens: &[SqlToken],
    index: usize,
    aliases: &BTreeSet<String>,
) -> bool {
    let Some(SqlToken::Identifier(name)) = tokens.get(index) else {
        return false;
    };
    if !aliases.contains(name) {
        return false;
    }
    if matches!(
        previous_sql_token(tokens, index, 1),
        Some(SqlToken::Identifier(keyword)) if keyword == "as"
    ) {
        return true;
    }
    if matches!(
        previous_sql_token(tokens, index, 2),
        Some(SqlToken::Identifier(keyword)) if matches!(keyword.as_str(), "from" | "join")
    ) {
        return true;
    }
    if matches!(
        (
            previous_sql_token(tokens, index, 4),
            previous_sql_token(tokens, index, 2)
        ),
        (Some(SqlToken::Identifier(keyword)), Some(SqlToken::Symbol('.')))
            if matches!(keyword.as_str(), "from" | "join")
    ) {
        return true;
    }
    if !matches!(
        previous_sql_token(tokens, index, 1),
        Some(SqlToken::Symbol(')'))
    ) {
        return false;
    }
    let Some(open_index) = matching_open_paren_before(tokens, index.saturating_sub(1)) else {
        return false;
    };
    matches!(
        previous_sql_token(tokens, open_index, 1),
        Some(SqlToken::Identifier(keyword)) if matches!(keyword.as_str(), "from" | "join")
    ) || matches!(
        previous_sql_token(tokens, open_index, 2),
        Some(SqlToken::Identifier(keyword)) if matches!(keyword.as_str(), "from" | "join")
    )
}

fn matching_open_paren_before(tokens: &[SqlToken], close_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().take(close_index + 1).rev() {
        match token {
            SqlToken::Symbol(')') => depth += 1,
            SqlToken::Symbol('(') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
    }
    None
}

fn is_select_alias_reference_at(tokens: &[SqlToken], index: usize) -> bool {
    let Some(SqlToken::Identifier(name)) = tokens.get(index) else {
        return false;
    };
    let (start, end) = sql_enclosing_query_bounds(tokens, index);
    let block = &tokens[start..end];
    let local_index = index.saturating_sub(start);
    let keywords = sql_validation_keywords();
    let select_aliases = sql_select_list_tokens(block)
        .map(sql_select_aliases_in_tokens)
        .unwrap_or_default()
        .into_iter()
        .filter(|alias| !keywords.contains(alias.as_str()))
        .collect::<BTreeSet<_>>();
    select_aliases.contains(name)
        && matches!(
            top_level_clause_before(block, local_index).as_deref(),
            Some("group" | "order" | "having")
        )
}

fn top_level_clause_before(tokens: &[SqlToken], index: usize) -> Option<String> {
    let mut depth = 0usize;
    let mut clause = None;
    for token in tokens.iter().take(index) {
        match token {
            SqlToken::Symbol('(') => {
                depth += 1;
                continue;
            }
            SqlToken::Symbol(')') => {
                depth = depth.saturating_sub(1);
                continue;
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
        if depth != 0 {
            continue;
        }
        let SqlToken::Identifier(keyword) = token else {
            continue;
        };
        if matches!(
            keyword.as_str(),
            "select" | "from" | "where" | "group" | "having" | "order" | "limit" | "offset"
        ) {
            clause = Some(keyword.clone());
        }
    }
    clause
}

fn is_schema_qualifier_at(
    tokens: &[SqlToken],
    index: usize,
    table_refs: &BTreeSet<String>,
) -> bool {
    matches!(
        (
            previous_sql_token(tokens, index, 1),
            tokens.get(index + 2)
        ),
        (Some(SqlToken::Identifier(keyword)), Some(SqlToken::Identifier(table)))
            if matches!(keyword.as_str(), "from" | "join") && table_refs.contains(table)
    )
}

fn is_function_name_at(
    tokens: &[SqlToken],
    index: usize,
    function_names: &BTreeSet<String>,
) -> bool {
    matches!(
        (tokens.get(index), tokens.get(index + 1)),
        (Some(SqlToken::Identifier(name)), Some(SqlToken::Symbol('(')))
            if function_names.contains(name)
    )
}

fn is_cte_definition_identifier_at(tokens: &[SqlToken], index: usize) -> bool {
    let mut cursor = match tokens.first() {
        Some(SqlToken::Identifier(keyword)) if keyword == "with" => 1,
        _ => return false,
    };
    if matches!(tokens.get(cursor), Some(SqlToken::Identifier(keyword)) if keyword == "recursive") {
        cursor += 1;
    }

    loop {
        if cursor == index {
            return true;
        }
        if !matches!(tokens.get(cursor), Some(SqlToken::Identifier(_))) {
            return false;
        }
        cursor += 1;

        if matches!(tokens.get(cursor), Some(SqlToken::Symbol('('))) {
            let Some(after_columns) = skip_parenthesized_tokens(tokens, cursor) else {
                return false;
            };
            cursor = after_columns;
        }
        if !matches!(tokens.get(cursor), Some(SqlToken::Identifier(keyword)) if keyword == "as") {
            return false;
        }
        cursor += 1;
        if matches!(tokens.get(cursor), Some(SqlToken::Identifier(keyword)) if keyword == "materialized")
        {
            cursor += 1;
        } else if matches!(tokens.get(cursor), Some(SqlToken::Identifier(keyword)) if keyword == "not")
            && matches!(tokens.get(cursor + 1), Some(SqlToken::Identifier(keyword)) if keyword == "materialized")
        {
            cursor += 2;
        }
        if !matches!(tokens.get(cursor), Some(SqlToken::Symbol('('))) {
            return false;
        }
        let Some(after_body) = skip_parenthesized_tokens(tokens, cursor) else {
            return false;
        };
        cursor = after_body;
        if matches!(tokens.get(cursor), Some(SqlToken::Symbol(','))) {
            cursor += 1;
            continue;
        }
        return false;
    }
}

fn is_known_sql_qualifier_at(
    tokens: &[SqlToken],
    index: usize,
    table_refs: &BTreeSet<String>,
    aliases: &BTreeSet<String>,
    virtual_source_aliases: &BTreeSet<String>,
) -> bool {
    let Some(SqlToken::Identifier(token)) = tokens.get(index) else {
        return false;
    };
    table_refs.contains(token) || aliases.contains(token) || virtual_source_aliases.contains(token)
}

fn is_cte_source_qualifier_at(
    tokens: &[SqlToken],
    index: usize,
    definitions: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    let Some(SqlToken::Identifier(name)) = tokens.get(index) else {
        return false;
    };
    let (start, end) = sql_enclosing_query_bounds(tokens, index);
    let block = &tokens[start..end];
    let (source_names, _) = sql_cte_source_outputs_in_tokens(block, definitions);
    source_names.contains(name)
}

fn is_cte_output_column_at(
    tokens: &[SqlToken],
    index: usize,
    definitions: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    let Some(SqlToken::Identifier(name)) = tokens.get(index) else {
        return false;
    };
    let (start, end) = sql_enclosing_query_bounds(tokens, index);
    let block = &tokens[start..end];
    let local_index = index.saturating_sub(start);
    let (source_names, output_columns) = sql_cte_source_outputs_in_tokens(block, definitions);
    if !output_columns.contains(name) {
        return false;
    }
    let qualified_by_cte_source = matches!(
        (
            previous_sql_token(block, local_index, 2),
            previous_sql_token(block, local_index, 1)
        ),
        (Some(SqlToken::Identifier(qualifier)), Some(SqlToken::Symbol('.')))
            if source_names.contains(qualifier)
    );
    let unqualified = !matches!(
        previous_sql_token(block, local_index, 1),
        Some(SqlToken::Symbol('.'))
    );
    qualified_by_cte_source || unqualified
}

fn sql_cte_source_outputs_in_tokens(
    tokens: &[SqlToken],
    definitions: &BTreeMap<String, BTreeSet<String>>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let keywords = sql_validation_keywords();
    let mut source_names = BTreeSet::new();
    let mut output_columns = BTreeSet::new();
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            SqlToken::Symbol('(') => {
                depth += 1;
                continue;
            }
            SqlToken::Symbol(')') => {
                depth = depth.saturating_sub(1);
                continue;
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
        if depth != 0 {
            continue;
        }
        let SqlToken::Identifier(keyword) = token else {
            continue;
        };
        if !matches!(keyword.as_str(), "from" | "join") {
            continue;
        }
        let Some(SqlToken::Identifier(name)) = tokens.get(index + 1) else {
            continue;
        };
        if matches!(tokens.get(index + 2), Some(SqlToken::Symbol('.'))) {
            continue;
        }
        let Some(columns) = definitions.get(name) else {
            continue;
        };
        source_names.insert(name.clone());
        output_columns.extend(columns.iter().cloned());
        if let Some((alias, _)) = sql_source_alias_after(tokens, index, &keywords) {
            source_names.insert(alias);
        }
    }
    (source_names, output_columns)
}

fn is_virtual_output_column_at(tokens: &[SqlToken], index: usize) -> bool {
    let Some(SqlToken::Identifier(name)) = tokens.get(index) else {
        return false;
    };
    let (start, end) = sql_enclosing_query_bounds(tokens, index);
    let block = &tokens[start..end];
    let local_index = index.saturating_sub(start);
    let virtual_columns = sql_virtual_output_columns_in_tokens(block);
    if !virtual_columns.contains(name) {
        return false;
    }
    let virtual_source_aliases = sql_virtual_source_aliases_in_tokens(block);
    let qualified_by_virtual_source = matches!(
        (
            previous_sql_token(block, local_index, 2),
            previous_sql_token(block, local_index, 1)
        ),
        (Some(SqlToken::Identifier(qualifier)), Some(SqlToken::Symbol('.')))
            if virtual_source_aliases.contains(qualifier)
    );
    let unqualified = !matches!(
        previous_sql_token(block, local_index, 1),
        Some(SqlToken::Symbol('.'))
    );
    qualified_by_virtual_source || unqualified
}

fn sql_enclosing_query_bounds(tokens: &[SqlToken], index: usize) -> (usize, usize) {
    let mut stack = Vec::new();
    for (cursor, token) in tokens.iter().enumerate().take(index) {
        match token {
            SqlToken::Symbol('(') => stack.push(cursor),
            SqlToken::Symbol(')') => {
                let _ = stack.pop();
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
    }
    for open_index in stack.into_iter().rev() {
        let Some(close_after) = skip_parenthesized_tokens(tokens, open_index) else {
            continue;
        };
        let close_index = close_after.saturating_sub(1);
        if sql_tokens_have_top_level_select(&tokens[open_index + 1..close_index]) {
            return (open_index + 1, close_index);
        }
    }
    (0, tokens.len())
}

fn sql_tokens_have_top_level_select(tokens: &[SqlToken]) -> bool {
    let mut depth = 0usize;
    for token in tokens {
        match token {
            SqlToken::Symbol('(') => {
                depth += 1;
                continue;
            }
            SqlToken::Symbol(')') => {
                depth = depth.saturating_sub(1);
                continue;
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
        if depth == 0 && matches!(token, SqlToken::Identifier(keyword) if keyword == "select") {
            return true;
        }
    }
    false
}

fn referenced_sql_functions(sql: &str) -> Vec<String> {
    sql_function_names(sql).into_iter().collect()
}

fn sql_aliases(sql: &str) -> BTreeSet<String> {
    let tokens = sql_tokens(sql);
    let keywords = sql_validation_keywords();
    let mut aliases = BTreeSet::new();

    let explicit_aliases = sql_select_aliases_in_tokens(&tokens)
        .into_iter()
        .filter(|alias| !keywords.contains(alias.as_str()));
    aliases.extend(explicit_aliases);

    for (index, token) in tokens.iter().enumerate() {
        let SqlToken::Identifier(keyword) = token else {
            continue;
        };
        if !matches!(keyword.as_str(), "from" | "join") {
            continue;
        }
        let Some((alias, _)) = sql_source_alias_after(&tokens, index, &keywords) else {
            continue;
        };
        aliases.insert(alias);
    }

    aliases
}

fn sql_virtual_source_aliases(sql: &str) -> BTreeSet<String> {
    let tokens = sql_tokens(sql);
    let mut aliases = sql_referenced_cte_names(sql);
    aliases.extend(sql_virtual_source_aliases_in_tokens(&tokens));
    aliases
}

fn sql_virtual_output_columns_in_tokens(tokens: &[SqlToken]) -> BTreeSet<String> {
    let mut columns = sql_table_valued_output_columns_in_tokens(tokens);
    columns.extend(sql_derived_source_output_columns_in_tokens(tokens));
    columns
}

fn sql_table_valued_output_columns_in_tokens(tokens: &[SqlToken]) -> BTreeSet<String> {
    let mut columns = BTreeSet::new();
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            SqlToken::Symbol('(') => {
                depth += 1;
                continue;
            }
            SqlToken::Symbol(')') => {
                depth = depth.saturating_sub(1);
                continue;
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
        if depth != 0 {
            continue;
        }
        let SqlToken::Identifier(keyword) = token else {
            continue;
        };
        if !matches!(keyword.as_str(), "from" | "join") {
            continue;
        }
        let Some(SqlToken::Identifier(function_name)) = tokens.get(index + 1) else {
            continue;
        };
        if !matches!(tokens.get(index + 2), Some(SqlToken::Symbol('('))) {
            continue;
        }
        if matches!(function_name.as_str(), "json_each" | "json_tree") {
            columns.extend(
                sqlite_json_table_column_names()
                    .into_iter()
                    .map(str::to_string),
            );
        }
    }
    columns
}

fn sql_derived_source_output_columns_in_tokens(tokens: &[SqlToken]) -> BTreeSet<String> {
    let mut columns = BTreeSet::new();
    let mut depth = 0usize;
    let mut index = 0usize;
    while index < tokens.len() {
        match &tokens[index] {
            SqlToken::Symbol('(') => {
                depth += 1;
                index += 1;
                continue;
            }
            SqlToken::Symbol(')') => {
                depth = depth.saturating_sub(1);
                index += 1;
                continue;
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
        if depth == 0
            && matches!(
                &tokens[index],
                SqlToken::Identifier(keyword) if matches!(keyword.as_str(), "from" | "join")
            )
            && matches!(tokens.get(index + 1), Some(SqlToken::Symbol('(')))
        {
            if let Some(after_body) = skip_parenthesized_tokens(tokens, index + 1) {
                columns.extend(sql_select_output_columns_in_tokens(
                    &tokens[index + 2..after_body.saturating_sub(1)],
                ));
                index = after_body;
                continue;
            }
        }
        index += 1;
    }
    columns
}

fn sql_virtual_source_aliases_in_tokens(tokens: &[SqlToken]) -> BTreeSet<String> {
    let keywords = sql_validation_keywords();
    let mut aliases = BTreeSet::new();
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            SqlToken::Symbol('(') => {
                depth += 1;
                continue;
            }
            SqlToken::Symbol(')') => {
                depth = depth.saturating_sub(1);
                continue;
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
        if depth != 0 {
            continue;
        }
        let SqlToken::Identifier(keyword) = token else {
            continue;
        };
        if !matches!(keyword.as_str(), "from" | "join") {
            continue;
        }
        if let (Some(SqlToken::Identifier(function_name)), Some(SqlToken::Symbol('('))) =
            (tokens.get(index + 1), tokens.get(index + 2))
        {
            if matches!(function_name.as_str(), "json_each" | "json_tree") {
                aliases.insert(function_name.clone());
            }
        }
        let Some((alias, virtual_source)) = sql_source_alias_after(tokens, index, &keywords) else {
            continue;
        };
        if virtual_source {
            aliases.insert(alias);
        }
    }
    aliases
}

fn sqlite_json_table_column_names() -> [&'static str; 10] {
    [
        "key", "value", "type", "atom", "id", "parent", "fullkey", "path", "json", "root",
    ]
}

fn sql_source_alias_after(
    tokens: &[SqlToken],
    keyword_index: usize,
    keywords: &BTreeSet<&'static str>,
) -> Option<(String, bool)> {
    let mut index = keyword_index + 1;
    let virtual_source = match (tokens.get(index), tokens.get(index + 1)) {
        (Some(SqlToken::Symbol('(')), _) => {
            index = skip_parenthesized_tokens(tokens, index)?;
            true
        }
        (Some(SqlToken::Identifier(_)), Some(SqlToken::Symbol('.'))) => {
            let Some(SqlToken::Identifier(_)) = tokens.get(index + 2) else {
                return None;
            };
            index += 3;
            false
        }
        (Some(SqlToken::Identifier(_)), Some(SqlToken::Symbol('('))) => {
            index = skip_parenthesized_tokens(tokens, index + 1)?;
            true
        }
        (Some(SqlToken::Identifier(_)), _) => {
            index += 1;
            false
        }
        _ => return None,
    };

    if matches!(tokens.get(index), Some(SqlToken::Identifier(keyword)) if keyword == "as") {
        index += 1;
    }

    let Some(SqlToken::Identifier(alias)) = tokens.get(index) else {
        return None;
    };
    if keywords.contains(alias.as_str()) {
        return None;
    }
    Some((alias.clone(), virtual_source))
}

fn sql_cte_names(sql: &str) -> BTreeSet<String> {
    sql_cte_definitions(sql).into_keys().collect()
}

fn sql_referenced_cte_names(sql: &str) -> BTreeSet<String> {
    let definitions = sql_cte_definitions(sql);
    if definitions.is_empty() {
        return BTreeSet::new();
    }
    let tokens = sql_tokens(sql);
    let mut names = BTreeSet::new();
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            SqlToken::Symbol('(') => {
                depth += 1;
                continue;
            }
            SqlToken::Symbol(')') => {
                depth = depth.saturating_sub(1);
                continue;
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
        if depth != 0 {
            continue;
        }
        let SqlToken::Identifier(keyword) = token else {
            continue;
        };
        if !matches!(keyword.as_str(), "from" | "join") {
            continue;
        }
        let Some(SqlToken::Identifier(name)) = tokens.get(index + 1) else {
            continue;
        };
        if definitions.contains_key(name) {
            names.insert(name.clone());
        }
    }
    names
}

fn sql_cte_definitions(sql: &str) -> BTreeMap<String, BTreeSet<String>> {
    let tokens = sql_tokens(sql);
    let mut definitions = BTreeMap::new();
    let mut index = match tokens.first() {
        Some(SqlToken::Identifier(keyword)) if keyword == "with" => 1,
        _ => return definitions,
    };
    if matches!(tokens.get(index), Some(SqlToken::Identifier(keyword)) if keyword == "recursive") {
        index += 1;
    }

    loop {
        let Some(SqlToken::Identifier(name)) = tokens.get(index) else {
            break;
        };
        let name = name.clone();
        index += 1;

        let mut output_columns = BTreeSet::new();
        if matches!(tokens.get(index), Some(SqlToken::Symbol('('))) {
            let Some(after_columns) = skip_parenthesized_tokens(&tokens, index) else {
                break;
            };
            for token in &tokens[index + 1..after_columns.saturating_sub(1)] {
                if let SqlToken::Identifier(column) = token {
                    output_columns.insert(column.clone());
                }
            }
            index = after_columns;
        }
        if !matches!(tokens.get(index), Some(SqlToken::Identifier(keyword)) if keyword == "as") {
            break;
        }
        index += 1;
        if matches!(tokens.get(index), Some(SqlToken::Identifier(keyword)) if keyword == "materialized")
        {
            index += 1;
        } else if matches!(tokens.get(index), Some(SqlToken::Identifier(keyword)) if keyword == "not")
            && matches!(tokens.get(index + 1), Some(SqlToken::Identifier(keyword)) if keyword == "materialized")
        {
            index += 2;
        }
        if !matches!(tokens.get(index), Some(SqlToken::Symbol('('))) {
            break;
        }
        let Some(after_body) = skip_parenthesized_tokens(&tokens, index) else {
            break;
        };
        if output_columns.is_empty() {
            output_columns.extend(sql_select_output_columns_in_tokens(
                &tokens[index + 1..after_body - 1],
            ));
        }
        definitions.insert(name, output_columns);
        index = after_body;

        if matches!(tokens.get(index), Some(SqlToken::Symbol(','))) {
            index += 1;
            continue;
        }
        break;
    }

    definitions
}

fn sql_select_aliases_in_tokens(tokens: &[SqlToken]) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    let mut depth = 0usize;
    for window in tokens.windows(2) {
        match &window[0] {
            SqlToken::Symbol('(') => {
                depth += 1;
                continue;
            }
            SqlToken::Symbol(')') => {
                depth = depth.saturating_sub(1);
                continue;
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
        if depth != 0 {
            continue;
        }
        if let (SqlToken::Identifier(keyword), SqlToken::Identifier(alias)) =
            (&window[0], &window[1])
        {
            if keyword == "as" {
                aliases.insert(alias.clone());
            }
        }
    }
    aliases
}

fn sql_select_output_columns_in_tokens(tokens: &[SqlToken]) -> BTreeSet<String> {
    let mut output_columns = sql_select_aliases_in_tokens(tokens);
    let virtual_columns = sql_virtual_output_columns_in_tokens(tokens);
    if virtual_columns.is_empty() {
        return output_columns;
    }

    let Some(select_tokens) = sql_select_list_tokens(tokens) else {
        return output_columns;
    };
    let keywords = sql_validation_keywords();
    let virtual_source_aliases = sql_virtual_source_aliases_in_tokens(tokens);
    for (index, token) in select_tokens.iter().enumerate() {
        let SqlToken::Identifier(name) = token else {
            continue;
        };
        if keywords.contains(name.as_str())
            || output_columns.contains(name)
            || name.chars().all(|ch| ch.is_ascii_digit())
            || matches!(select_tokens.get(index + 1), Some(SqlToken::Symbol('.')))
            || !select_item_is_plain_identifier(select_tokens, index)
        {
            continue;
        }
        let qualified_by_virtual_source = matches!(
            (
                previous_sql_token(select_tokens, index, 2),
                previous_sql_token(select_tokens, index, 1)
            ),
            (Some(SqlToken::Identifier(qualifier)), Some(SqlToken::Symbol('.')))
                if virtual_source_aliases.contains(qualifier)
        );
        let unqualified = !matches!(
            previous_sql_token(select_tokens, index, 1),
            Some(SqlToken::Symbol('.'))
        );
        if virtual_columns.contains(name) && (qualified_by_virtual_source || unqualified) {
            output_columns.insert(name.clone());
        }
    }

    output_columns
}

fn select_item_is_plain_identifier(tokens: &[SqlToken], index: usize) -> bool {
    let (mut start, mut end) = select_item_bounds(tokens, index);
    while matches!(
        tokens.get(start),
        Some(SqlToken::Identifier(keyword)) if matches!(keyword.as_str(), "distinct" | "all")
    ) {
        start += 1;
    }
    while select_item_has_wrapping_parentheses(tokens, start, end) {
        start += 1;
        end = end.saturating_sub(1);
    }
    let item = &tokens[start..end];
    match item {
        [SqlToken::Identifier(_)] => index == start,
        [
            SqlToken::Identifier(_),
            SqlToken::Symbol('.'),
            SqlToken::Identifier(_),
        ] => index == start + 2,
        _ => false,
    }
}

fn select_item_has_wrapping_parentheses(tokens: &[SqlToken], start: usize, end: usize) -> bool {
    if end <= start + 1
        || !matches!(tokens.get(start), Some(SqlToken::Symbol('(')))
        || !matches!(tokens.get(end - 1), Some(SqlToken::Symbol(')')))
    {
        return false;
    }
    let mut depth = 0usize;
    for (offset, token) in tokens[start..end].iter().enumerate() {
        match token {
            SqlToken::Symbol('(') => depth += 1,
            SqlToken::Symbol(')') => {
                depth = depth.saturating_sub(1);
                if depth == 0 && offset != end - start - 1 {
                    return false;
                }
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
    }
    depth == 0
}

fn select_item_bounds(tokens: &[SqlToken], index: usize) -> (usize, usize) {
    let mut depth = 0usize;
    let mut start = 0usize;
    for cursor in 0..index {
        match &tokens[cursor] {
            SqlToken::Symbol('(') => depth += 1,
            SqlToken::Symbol(')') => depth = depth.saturating_sub(1),
            SqlToken::Symbol(',') if depth == 0 => start = cursor + 1,
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
    }

    depth = 0;
    let mut end = tokens.len();
    for (cursor, token) in tokens.iter().enumerate().skip(index + 1) {
        match token {
            SqlToken::Symbol('(') => depth += 1,
            SqlToken::Symbol(')') => depth = depth.saturating_sub(1),
            SqlToken::Symbol(',') if depth == 0 => {
                end = cursor;
                break;
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
    }
    (start, end)
}

fn sql_select_list_tokens(tokens: &[SqlToken]) -> Option<&[SqlToken]> {
    let mut depth = 0usize;
    let mut select_start = None;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            SqlToken::Symbol('(') => {
                depth += 1;
                continue;
            }
            SqlToken::Symbol(')') => {
                depth = depth.saturating_sub(1);
                continue;
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
        if depth != 0 {
            continue;
        }
        let SqlToken::Identifier(keyword) = token else {
            continue;
        };
        if keyword == "select" && select_start.is_none() {
            select_start = Some(index + 1);
            continue;
        }
        if keyword == "from" {
            if let Some(start) = select_start {
                return Some(&tokens[start..index]);
            }
        }
    }
    select_start.map(|start| &tokens[start..])
}

fn skip_parenthesized_tokens(tokens: &[SqlToken], open_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open_index) {
        match token {
            SqlToken::Symbol('(') => depth += 1,
            SqlToken::Symbol(')') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            SqlToken::Identifier(_) | SqlToken::Symbol(_) => {}
        }
    }
    None
}

fn sql_function_names(sql: &str) -> BTreeSet<String> {
    let tokens = sql_tokens(sql);
    let keywords = sql_validation_keywords();
    tokens
        .windows(2)
        .filter_map(|window| match (&window[0], &window[1]) {
            (SqlToken::Identifier(name), SqlToken::Symbol('('))
                if !keywords.contains(name.as_str()) =>
            {
                Some(name.clone())
            }
            _ => None,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SqlToken {
    Identifier(String),
    Symbol(char),
}

fn sql_tokens(sql: &str) -> Vec<SqlToken> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = sql.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' => {
                push_identifier_token(&mut tokens, &mut current);
                skip_quoted_literal(&mut chars, '\'');
            }
            '"' | '`' => {
                push_identifier_token(&mut tokens, &mut current);
                let identifier = read_quoted_identifier(&mut chars, ch);
                if !identifier.is_empty() {
                    tokens.push(SqlToken::Identifier(normalize_sql_identifier(&identifier)));
                }
            }
            '[' => {
                push_identifier_token(&mut tokens, &mut current);
                let identifier = read_bracket_identifier(&mut chars);
                if !identifier.is_empty() {
                    tokens.push(SqlToken::Identifier(normalize_sql_identifier(&identifier)));
                }
            }
            '-' if chars.peek() == Some(&'-') => {
                let _ = chars.next();
                push_identifier_token(&mut tokens, &mut current);
                skip_line_comment(&mut chars);
            }
            '/' if chars.peek() == Some(&'*') => {
                let _ = chars.next();
                push_identifier_token(&mut tokens, &mut current);
                skip_block_comment(&mut chars);
            }
            '(' | ')' | ',' | '.' => {
                push_identifier_token(&mut tokens, &mut current);
                tokens.push(SqlToken::Symbol(ch));
            }
            ch if ch.is_ascii_alphanumeric() || ch == '_' => current.push(ch),
            _ => {
                if !current.is_empty() {
                    push_identifier_token(&mut tokens, &mut current);
                }
            }
        }
    }
    push_identifier_token(&mut tokens, &mut current);
    tokens
}

fn push_identifier_token(tokens: &mut Vec<SqlToken>, current: &mut String) {
    if current.is_empty() {
        return;
    }
    tokens.push(SqlToken::Identifier(normalize_sql_identifier(current)));
    current.clear();
}

fn skip_quoted_literal<I>(chars: &mut std::iter::Peekable<I>, quote: char)
where
    I: Iterator<Item = char>,
{
    while let Some(ch) = chars.next() {
        if ch == quote {
            if chars.peek() == Some(&quote) {
                let _ = chars.next();
            } else {
                break;
            }
        }
    }
}

fn read_quoted_identifier<I>(chars: &mut std::iter::Peekable<I>, quote: char) -> String
where
    I: Iterator<Item = char>,
{
    let mut value = String::new();
    while let Some(ch) = chars.next() {
        if ch == quote {
            if chars.peek() == Some(&quote) {
                value.push(quote);
                let _ = chars.next();
            } else {
                break;
            }
        } else {
            value.push(ch);
        }
    }
    value
}

fn read_bracket_identifier<I>(chars: &mut std::iter::Peekable<I>) -> String
where
    I: Iterator<Item = char>,
{
    let mut value = String::new();
    while let Some(ch) = chars.next() {
        if ch == ']' {
            if chars.peek() == Some(&']') {
                value.push(']');
                let _ = chars.next();
            } else {
                break;
            }
        } else {
            value.push(ch);
        }
    }
    value
}

fn skip_line_comment<I>(chars: &mut std::iter::Peekable<I>)
where
    I: Iterator<Item = char>,
{
    for ch in chars.by_ref() {
        if ch == '\n' {
            break;
        }
    }
}

fn skip_block_comment<I>(chars: &mut std::iter::Peekable<I>)
where
    I: Iterator<Item = char>,
{
    let mut previous = '\0';
    for ch in chars.by_ref() {
        if previous == '*' && ch == '/' {
            break;
        }
        previous = ch;
    }
}

fn normalize_sql_identifier(value: &str) -> String {
    value
        .trim_matches(|ch| ch == '"' || ch == '`' || ch == '[' || ch == ']')
        .to_ascii_lowercase()
}

fn sql_validation_keywords() -> BTreeSet<&'static str> {
    [
        "select",
        "from",
        "where",
        "join",
        "inner",
        "left",
        "right",
        "full",
        "outer",
        "on",
        "as",
        "and",
        "or",
        "not",
        "null",
        "is",
        "in",
        "between",
        "like",
        "glob",
        "group",
        "by",
        "order",
        "having",
        "limit",
        "offset",
        "desc",
        "asc",
        "case",
        "when",
        "then",
        "else",
        "end",
        "cast",
        "count",
        "sum",
        "avg",
        "min",
        "max",
        "date",
        "datetime",
        "now",
        "interval",
        "day",
        "hour",
        "minute",
        "second",
        "format",
        "json",
        "explain",
        "query",
        "plan",
        "true",
        "false",
        "exists",
        "distinct",
        "with",
        "recursive",
        "materialized",
        "union",
        "all",
        "over",
        "partition",
        "range",
        "rows",
        "preceding",
        "following",
        "current",
        "row",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_quoted_identifiers_and_ignores_comments_and_literals() {
        let schema = json!({
            "objects": [{"type": "table", "name": "User Events"}],
            "columns": [
                {"column_name": "Event Name"},
                {"column_name": "created_at"}
            ]
        });

        let validation = validate_sql_against_schema(
            r#"
            SELECT "Event Name" AS event_name
            FROM "User Events"
            WHERE [created_at] >= 'literal_missing_column'
            -- missing_table missing_column
            /* another_missing_table another_missing_column */
            "#,
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["user events"]));
        assert_eq!(
            validation["referenced_columns"],
            json!(["created_at", "event name"])
        );
    }

    #[test]
    fn table_valued_function_names_are_not_application_tables() {
        let tables =
            referenced_sql_tables("SELECT value FROM json_each(payload) WHERE value IS NOT NULL");
        let functions = referenced_sql_functions(
            "SELECT value FROM json_each(payload) WHERE value IS NOT NULL",
        );

        assert_eq!(tables, Vec::<String>::new());
        assert_eq!(functions, vec!["json_each".to_string()]);
    }

    #[test]
    fn table_valued_function_aliases_do_not_become_columns() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "payload"}]
        });

        let validation = validate_sql_against_schema(
            "SELECT item.value FROM users JOIN json_each(users.payload) item ON true WHERE item.value IS NOT NULL",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["users"]));
        assert_eq!(validation["referenced_columns"], json!(["payload"]));
        assert_eq!(validation["referenced_functions"], json!(["json_each"]));
    }

    #[test]
    fn derived_table_aliases_do_not_become_columns() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "id"}]
        });

        let validation = validate_sql_against_schema(
            "SELECT sub.id FROM (SELECT id FROM users) AS sub WHERE sub.id > 0",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["users"]));
        assert_eq!(validation["referenced_columns"], json!(["id"]));
    }

    #[test]
    fn bracket_identifiers_support_escaped_closing_brackets() {
        let schema = json!({
            "objects": [{"type": "table", "name": "odd] table"}],
            "columns": [{"column_name": "odd] column"}]
        });

        let validation =
            validate_sql_against_schema("SELECT [odd]] column] FROM [odd]] table]", &schema, "d1");

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["odd] table"]));
        assert_eq!(validation["referenced_columns"], json!(["odd] column"]));
    }

    #[test]
    fn cte_names_do_not_become_missing_application_tables() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "id"}]
        });

        let validation = validate_sql_against_schema(
            "WITH cte AS (SELECT id FROM users) SELECT cte.id FROM cte WHERE cte.id > 0",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["users"]));
        assert_eq!(validation["referenced_columns"], json!(["id"]));
    }

    #[test]
    fn cte_names_are_still_checked_when_used_as_bare_columns() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "id"}]
        });

        let validation = validate_sql_against_schema(
            "WITH cte AS (SELECT id FROM users) SELECT cte FROM users",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(false));
        assert_eq!(validation["error"]["code"], json!("d1.column_not_found"));
        assert_eq!(validation["error"]["missing_columns"], json!(["cte"]));
    }

    #[test]
    fn cte_names_are_not_hidden_when_aliased_as_select_expressions() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "id"}]
        });

        let validation = validate_sql_against_schema(
            "WITH cte AS (SELECT id FROM users) SELECT cte AS alias FROM users",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(false));
        assert_eq!(validation["error"]["code"], json!("d1.column_not_found"));
        assert_eq!(validation["error"]["missing_columns"], json!(["cte"]));
    }

    #[test]
    fn cte_qualifiers_are_invalid_when_cte_is_not_a_source() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "id"}]
        });

        let validation = validate_sql_against_schema(
            "WITH cte AS (SELECT id FROM users) SELECT cte.id FROM users",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(false));
        assert_eq!(validation["error"]["code"], json!("d1.column_not_found"));
        assert_eq!(validation["error"]["missing_columns"], json!(["cte"]));
    }

    #[test]
    fn cte_materialization_hints_still_parse_cte_names() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "id"}]
        });

        let validation = validate_sql_against_schema(
            "WITH cte AS MATERIALIZED (SELECT id FROM users) SELECT cte.id FROM cte",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["users"]));
        assert_eq!(validation["referenced_columns"], json!(["id"]));
    }

    #[test]
    fn cte_declared_output_columns_are_not_application_columns() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "id"}]
        });

        let validation = validate_sql_against_schema(
            "WITH cte(col) AS (SELECT id FROM users) SELECT col FROM cte",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["users"]));
        assert_eq!(validation["referenced_columns"], json!(["id"]));
    }

    #[test]
    fn cte_body_aliases_are_not_application_columns_when_selected_from_cte() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "id"}]
        });

        let validation = validate_sql_against_schema(
            "WITH cte AS (SELECT id AS total FROM users) SELECT total FROM cte",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["users"]));
        assert_eq!(validation["referenced_columns"], json!(["id"]));
    }

    #[test]
    fn cte_body_virtual_outputs_are_not_application_columns_when_selected_from_cte() {
        let schema = json!({
            "objects": [],
            "columns": [{"column_name": "payload"}]
        });

        let validation = validate_sql_against_schema(
            "WITH cte AS (SELECT value FROM json_each(payload)) SELECT value FROM cte",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!([]));
        assert_eq!(validation["referenced_columns"], json!(["payload"]));
        assert_eq!(validation["referenced_functions"], json!(["json_each"]));
    }

    #[test]
    fn nested_subqueries_can_read_cte_output_columns() {
        let schema = json!({
            "objects": [],
            "columns": [{"column_name": "payload"}]
        });

        let validation = validate_sql_against_schema(
            "WITH cte AS (SELECT value FROM json_each(payload)) SELECT 1 WHERE EXISTS (SELECT cte.value FROM cte)",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!([]));
        assert_eq!(validation["referenced_columns"], json!(["payload"]));
        assert_eq!(validation["referenced_functions"], json!(["json_each"]));
    }

    #[test]
    fn cte_body_distinct_virtual_outputs_keep_their_raw_name() {
        let schema = json!({
            "objects": [],
            "columns": [{"column_name": "payload"}]
        });

        let validation = validate_sql_against_schema(
            "WITH cte AS (SELECT DISTINCT value FROM json_each(payload)) SELECT value FROM cte",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!([]));
        assert_eq!(validation["referenced_columns"], json!(["payload"]));
        assert_eq!(validation["referenced_functions"], json!(["json_each"]));
    }

    #[test]
    fn aliased_virtual_projection_does_not_export_raw_virtual_name() {
        let schema = json!({
            "objects": [],
            "columns": [{"column_name": "payload"}]
        });

        let validation = validate_sql_against_schema(
            "SELECT value FROM (SELECT value AS x FROM json_each(payload)) sub",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(false));
        assert_eq!(validation["error"]["code"], json!("d1.column_not_found"));
        assert_eq!(validation["error"]["missing_columns"], json!(["value"]));
        assert_eq!(
            validation["referenced_columns"],
            json!(["payload", "value"])
        );
    }

    #[test]
    fn unused_cte_outputs_do_not_hide_unrelated_missing_columns() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "payload"}]
        });

        let validation = validate_sql_against_schema(
            "WITH unused AS (SELECT value AS leaked FROM json_each(payload)) SELECT leaked FROM users",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(false));
        assert_eq!(validation["error"]["code"], json!("d1.column_not_found"));
        assert_eq!(validation["error"]["missing_columns"], json!(["leaked"]));
        assert_eq!(
            validation["referenced_columns"],
            json!(["leaked", "payload"])
        );
    }

    #[test]
    fn function_names_are_checked_as_columns_when_not_call_sites() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "payload"}]
        });

        let validation = validate_sql_against_schema(
            "SELECT coalesce FROM users WHERE coalesce(payload, '') IS NOT NULL",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(false));
        assert_eq!(validation["error"]["code"], json!("d1.column_not_found"));
        assert_eq!(validation["error"]["missing_columns"], json!(["coalesce"]));
        assert_eq!(
            validation["referenced_columns"],
            json!(["coalesce", "payload"])
        );
        assert_eq!(validation["referenced_functions"], json!(["coalesce"]));
    }

    #[test]
    fn table_names_are_checked_as_columns_when_not_source_references() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "id"}]
        });

        let validation = validate_sql_against_schema("SELECT users FROM users", &schema, "d1");

        assert_eq!(validation["ok"], json!(false));
        assert_eq!(validation["error"]["code"], json!("d1.column_not_found"));
        assert_eq!(validation["error"]["missing_columns"], json!(["users"]));
    }

    #[test]
    fn source_aliases_do_not_hide_same_named_select_columns() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "payload"}]
        });

        let validation = validate_sql_against_schema("SELECT id FROM users AS id", &schema, "d1");

        assert_eq!(validation["ok"], json!(false));
        assert_eq!(validation["error"]["code"], json!("d1.column_not_found"));
        assert_eq!(validation["error"]["missing_columns"], json!(["id"]));
    }

    #[test]
    fn select_aliases_are_allowed_in_group_and_order_clauses() {
        let schema = json!({
            "objects": [{"type": "table", "name": "events"}],
            "columns": [
                {"column_name": "payload"},
                {"column_name": "timestamp"}
            ]
        });

        let validation = validate_sql_against_schema(
            "SELECT coalesce(payload, 'unknown') AS route, max(timestamp) AS last_seen FROM events GROUP BY route ORDER BY last_seen DESC",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["events"]));
        assert_eq!(
            validation["referenced_columns"],
            json!(["payload", "timestamp"])
        );
        assert_eq!(validation["referenced_functions"], json!(["coalesce"]));
    }

    #[test]
    fn nested_select_aliases_are_allowed_in_order_clauses() {
        let schema = json!({
            "objects": [{"type": "table", "name": "orders"}],
            "columns": [{"column_name": "amount"}]
        });

        let validation = validate_sql_against_schema(
            "SELECT * FROM (SELECT amount AS total FROM orders ORDER BY total) sub",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["orders"]));
        assert_eq!(validation["referenced_columns"], json!(["amount"]));
    }

    #[test]
    fn derived_table_output_aliases_are_not_application_columns() {
        let schema = json!({
            "objects": [{"type": "table", "name": "orders"}],
            "columns": [{"column_name": "amount"}]
        });

        let validation = validate_sql_against_schema(
            "SELECT total FROM (SELECT sum(amount) AS total FROM orders) sub",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["orders"]));
        assert_eq!(validation["referenced_columns"], json!(["amount"]));
    }

    #[test]
    fn json_each_in_subquery_does_not_hide_outer_missing_columns() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "payload"}]
        });

        let validation = validate_sql_against_schema(
            "SELECT id FROM users WHERE EXISTS (SELECT 1 FROM json_each(users.payload))",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(false));
        assert_eq!(validation["error"]["code"], json!("d1.column_not_found"));
        assert_eq!(validation["error"]["missing_columns"], json!(["id"]));
    }

    #[test]
    fn unaliased_json_each_output_columns_are_not_application_columns() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "payload"}]
        });

        let validation = validate_sql_against_schema(
            "SELECT value FROM json_each(payload) WHERE value IS NOT NULL",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_columns"], json!(["payload"]));
        assert_eq!(validation["referenced_functions"], json!(["json_each"]));
    }

    #[test]
    fn top_level_json_each_outputs_work_with_application_table_sources() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "payload"}]
        });

        let validation = validate_sql_against_schema(
            "SELECT value FROM users JOIN json_each(users.payload) item ON true",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["users"]));
        assert_eq!(validation["referenced_columns"], json!(["payload"]));
        assert_eq!(validation["referenced_functions"], json!(["json_each"]));
    }

    #[test]
    fn dotted_sqlite_sources_use_the_object_name_not_schema_qualifier() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "id"}]
        });

        let validation = validate_sql_against_schema(
            "SELECT u.id FROM main.users AS u WHERE u.id > 0",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["users"]));
        assert_eq!(validation["referenced_columns"], json!(["id"]));
    }

    #[test]
    fn dotted_sqlite_sources_are_not_hidden_by_same_named_ctes() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "id"}]
        });

        let validation = validate_sql_against_schema(
            "WITH users AS (SELECT 1 AS id) SELECT id FROM main.users",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["users"]));
        assert_eq!(validation["referenced_columns"], json!(["id"]));
    }

    #[test]
    fn dotted_sqlite_sources_are_not_hidden_by_schema_named_ctes() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "id"}]
        });

        let validation = validate_sql_against_schema(
            "WITH main AS (SELECT 1 AS id) SELECT id FROM main.users",
            &schema,
            "d1",
        );

        assert_eq!(validation["ok"], json!(true));
        assert_eq!(validation["referenced_tables"], json!(["users"]));
        assert_eq!(validation["referenced_columns"], json!(["id"]));
    }

    #[test]
    fn dotted_select_expressions_do_not_hide_bad_qualifiers() {
        let schema = json!({
            "objects": [{"type": "table", "name": "users"}],
            "columns": [{"column_name": "id"}]
        });

        let validation =
            validate_sql_against_schema("SELECT bogus.users FROM users", &schema, "d1");

        assert_eq!(validation["ok"], json!(false));
        assert_eq!(validation["error"]["code"], json!("d1.column_not_found"));
        assert_eq!(
            validation["error"]["missing_columns"],
            json!(["bogus", "users"])
        );
    }
}
