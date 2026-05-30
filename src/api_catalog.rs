use std::borrow::Cow;
use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CATALOG_JSON: &str = include_str!("../spec/cloudflare_api_catalog.v1.json");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiCatalog {
    pub schema: String,
    pub source: ApiCatalogSource,
    pub operation_count: usize,
    pub operations: Vec<ApiOperation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiCatalogSource {
    pub url: String,
    pub etag: Option<String>,
    pub sha256: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiOperation {
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub tag: String,
    pub summary: Option<String>,
    #[serde(default)]
    pub deprecated: bool,
    pub scope: ApiScope,
    pub risk: ApiRisk,
    #[serde(default)]
    pub path_params: Vec<String>,
    #[serde(default)]
    pub query_params: Vec<String>,
    #[serde(default)]
    pub required_query_params: Vec<String>,
    #[serde(default)]
    pub has_request_body: bool,
    pub preferred_tool: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiScope {
    Account,
    Zone,
    User,
    Organization,
    Global,
    Mixed,
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiRisk {
    Read,
    Mutating,
    HighRisk,
    DeniedByDefault,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiCatalogStatus {
    pub schema: String,
    pub source: ApiCatalogSource,
    pub operation_count: usize,
    pub method_counts: BTreeMap<String, usize>,
    pub risk_counts: BTreeMap<String, usize>,
    pub scope_counts: BTreeMap<String, usize>,
    pub curated_preferred_tools: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiOperationSearchResult {
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub tag: String,
    pub summary: Option<String>,
    pub deprecated: bool,
    pub scope: ApiScope,
    pub risk: ApiRisk,
    pub preferred_tool: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ApiOperationSearch<'a> {
    pub query: Option<&'a str>,
    pub tag: Option<&'a str>,
    pub method: Option<&'a str>,
    pub scope: Option<ApiScope>,
    pub risk: Option<ApiRisk>,
    pub include_deprecated: bool,
    pub limit: usize,
}

pub fn catalog() -> &'static ApiCatalog {
    static CATALOG: std::sync::OnceLock<ApiCatalog> = std::sync::OnceLock::new();
    CATALOG.get_or_init(|| {
        let catalog: ApiCatalog =
            serde_json::from_str(CATALOG_JSON).expect("valid Cloudflare API catalog");
        assert_eq!(
            catalog.operation_count,
            catalog.operations.len(),
            "Cloudflare API catalog operation_count must match operations"
        );
        catalog
    })
}

pub fn status() -> ApiCatalogStatus {
    let catalog = catalog();
    let mut method_counts = BTreeMap::new();
    let mut risk_counts = BTreeMap::new();
    let mut scope_counts = BTreeMap::new();
    let mut curated_preferred_tools: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for operation in &catalog.operations {
        *method_counts.entry(operation.method.clone()).or_insert(0) += 1;
        *risk_counts
            .entry(format!("{:?}", operation.risk).to_ascii_lowercase())
            .or_insert(0) += 1;
        *scope_counts
            .entry(format!("{:?}", operation.scope).to_ascii_lowercase())
            .or_insert(0) += 1;
        if let Some(tool) = &operation.preferred_tool {
            curated_preferred_tools
                .entry(tool.clone())
                .or_default()
                .push(operation.operation_id.clone());
        }
    }

    ApiCatalogStatus {
        schema: catalog.schema.clone(),
        source: catalog.source.clone(),
        operation_count: catalog.operation_count,
        method_counts,
        risk_counts,
        scope_counts,
        curated_preferred_tools,
    }
}

pub fn find_operation(operation_id: &str) -> Option<&'static ApiOperation> {
    catalog()
        .operations
        .iter()
        .find(|operation| operation.operation_id == operation_id)
}

pub fn search_operations(filter: ApiOperationSearch<'_>) -> Vec<ApiOperationSearchResult> {
    let limit = filter.limit.clamp(1, 100);
    let mut query_terms = filter
        .query
        .map(split_terms)
        .unwrap_or_default()
        .into_iter()
        .flat_map(expanded_query_terms)
        .map(|term| term.to_ascii_lowercase())
        .collect::<Vec<_>>();
    query_terms.sort();
    query_terms.dedup();
    let tag = filter.tag.map(|tag| tag.to_ascii_lowercase());
    let method = filter.method.map(|method| method.to_ascii_uppercase());

    let mut scored = catalog()
        .operations
        .iter()
        .filter(|operation| filter.include_deprecated || !operation.deprecated)
        .filter(|operation| {
            method
                .as_ref()
                .is_none_or(|method| operation.method.eq_ignore_ascii_case(method))
        })
        .filter(|operation| filter.scope.is_none_or(|scope| operation.scope == scope))
        .filter(|operation| filter.risk.is_none_or(|risk| operation.risk == risk))
        .filter(|operation| {
            tag.as_ref().is_none_or(|tag| {
                operation.tag.to_ascii_lowercase().contains(tag)
                    || operation.path.to_ascii_lowercase().contains(tag)
            })
        })
        .filter_map(|operation| {
            let haystack = operation_search_text(operation);
            if query_terms.is_empty() {
                return Some((0usize, operation));
            }
            let mut score = 0usize;
            let mut matched_terms = 0usize;
            for term in &query_terms {
                if !haystack.contains(term) {
                    continue;
                }
                matched_terms += 1;
                if operation.operation_id.to_ascii_lowercase().contains(term) {
                    score += 8;
                }
                if operation.tag.to_ascii_lowercase().contains(term) {
                    score += 4;
                }
                if operation.path.to_ascii_lowercase().contains(term) {
                    score += 3;
                }
                if operation
                    .summary
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(term)
                {
                    score += 2;
                }
            }
            if matched_terms == 0 {
                return None;
            }
            score += matched_terms * 16;
            Some((usize::MAX - score, operation))
        })
        .collect::<Vec<_>>();

    scored.sort_by(|(a_score, a), (b_score, b)| {
        a_score
            .cmp(b_score)
            .then_with(|| a.tag.cmp(&b.tag))
            .then_with(|| a.operation_id.cmp(&b.operation_id))
    });

    scored
        .into_iter()
        .take(limit)
        .map(|(_, operation)| ApiOperationSearchResult {
            operation_id: operation.operation_id.clone(),
            method: operation.method.clone(),
            path: operation.path.clone(),
            tag: operation.tag.clone(),
            summary: operation.summary.clone(),
            deprecated: operation.deprecated,
            scope: operation.scope,
            risk: operation.risk,
            preferred_tool: operation.preferred_tool.clone(),
        })
        .collect()
}

pub fn operation_detail(operation: &ApiOperation) -> Value {
    json!({
        "operation_id": operation.operation_id,
        "method": operation.method,
        "path": operation.path,
        "tag": operation.tag,
        "summary": operation.summary,
        "deprecated": operation.deprecated,
        "scope": operation.scope,
        "risk": operation.risk,
        "path_params": operation.path_params,
        "query_params": operation.query_params,
        "required_query_params": operation.required_query_params,
        "has_request_body": operation.has_request_body,
        "preferred_tool": operation.preferred_tool,
        "executor": if operation.method.eq_ignore_ascii_case("GET") { "api_read" } else { "api_mutate" },
        "call_template": {
            "operation_id": operation.operation_id,
            "path_params": template_params(&operation.path_params),
            "query": {},
            "body": operation.has_request_body.then_some(json!({})),
            "dry_run": (!operation.method.eq_ignore_ascii_case("GET")).then_some(true),
        }
    })
}

pub fn render_path(
    operation: &ApiOperation,
    path_params: &BTreeMap<String, String>,
    default_account_id: Option<&str>,
    default_zone_id: Option<&str>,
) -> Result<String, ApiCatalogError> {
    let mut rendered = operation.path.clone();
    for name in &operation.path_params {
        let value = path_params
            .get(name)
            .map(String::as_str)
            .or_else(|| default_param(name, default_account_id, default_zone_id))
            .ok_or_else(|| ApiCatalogError::MissingPathParam(name.clone()))?;
        if value.trim().is_empty() {
            return Err(ApiCatalogError::MissingPathParam(name.clone()));
        }
        rendered = rendered.replace(&format!("{{{name}}}"), &encode_path_segment(value));
    }
    Ok(rendered)
}

pub fn validate_required_query(
    operation: &ApiOperation,
    query: &BTreeMap<String, Value>,
) -> Result<(), ApiCatalogError> {
    for name in &operation.required_query_params {
        match query.get(name) {
            Some(Value::Null) | None => {
                return Err(ApiCatalogError::MissingQueryParam(name.clone()));
            }
            Some(Value::String(value)) if value.trim().is_empty() => {
                return Err(ApiCatalogError::MissingQueryParam(name.clone()));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

pub fn query_pairs(
    query: &BTreeMap<String, Value>,
) -> Result<Vec<(String, String)>, ApiCatalogError> {
    let mut pairs = Vec::new();
    for (name, value) in query {
        append_query_value(&mut pairs, name, value)?;
    }
    Ok(pairs)
}

pub fn mutation_confirmation_token(
    operation: &ApiOperation,
    path: &str,
    body: &Option<Value>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(operation.operation_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(operation.method.as_bytes());
    hasher.update(b"\n");
    hasher.update(path.as_bytes());
    hasher.update(b"\n");
    if let Some(body) = body {
        hasher.update(serde_json::to_vec(body).unwrap_or_default());
    }
    format!("cf-api-{}", hex_prefix(hasher.finalize().as_slice(), 16))
}

pub fn operation_allowed_by_default(operation: &ApiOperation) -> bool {
    operation.risk != ApiRisk::DeniedByDefault
}

fn split_terms(query: &str) -> Vec<&str> {
    query
        .split(|ch: char| ch.is_whitespace() || ch == '_' || ch == '-' || ch == '/' || ch == '.')
        .map(str::trim)
        .filter(|term| !term.is_empty())
        .collect()
}

fn expanded_query_terms(term: &str) -> Vec<String> {
    let term = term.trim();
    let mut terms = vec![term.to_string()];
    if term.len() > 3 && term.ends_with('s') {
        terms.push(term.trim_end_matches('s').to_string());
    }
    terms
}

fn operation_search_text(operation: &ApiOperation) -> String {
    format!(
        "{} {} {} {} {}",
        operation.operation_id,
        operation.method,
        operation.path,
        operation.tag,
        operation.summary.as_deref().unwrap_or_default()
    )
    .to_ascii_lowercase()
}

fn template_params(names: &[String]) -> BTreeMap<String, String> {
    names
        .iter()
        .map(|name| (name.clone(), format!("<{name}>")))
        .collect()
}

fn default_param<'a>(
    name: &str,
    default_account_id: Option<&'a str>,
    default_zone_id: Option<&'a str>,
) -> Option<&'a str> {
    match name {
        "account_id" => default_account_id,
        "zone_id" => default_zone_id,
        _ => None,
    }
}

fn encode_path_segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn append_query_value(
    pairs: &mut Vec<(String, String)>,
    name: &str,
    value: &Value,
) -> Result<(), ApiCatalogError> {
    match value {
        Value::Null => {}
        Value::Bool(value) => pairs.push((name.to_string(), value.to_string())),
        Value::Number(value) => pairs.push((name.to_string(), value.to_string())),
        Value::String(value) => pairs.push((name.to_string(), value.clone())),
        Value::Array(values) => {
            for value in values {
                append_query_value(pairs, name, value)?;
            }
        }
        Value::Object(_) => return Err(ApiCatalogError::InvalidQueryParam(name.to_string())),
    }
    Ok(())
}

fn hex_prefix(bytes: &[u8], len: usize) -> String {
    bytes
        .iter()
        .flat_map(|byte| {
            let hi = byte >> 4;
            let lo = byte & 0x0f;
            [hex_char(hi), hex_char(lo)]
        })
        .take(len)
        .collect()
}

fn hex_char(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '0',
    }
}

pub fn parse_scope(value: Option<&str>) -> Result<Option<ApiScope>, ApiCatalogError> {
    parse_enum(
        value,
        "scope",
        &[
            ("account", ApiScope::Account),
            ("zone", ApiScope::Zone),
            ("user", ApiScope::User),
            ("organization", ApiScope::Organization),
            ("global", ApiScope::Global),
            ("mixed", ApiScope::Mixed),
            ("unknown", ApiScope::Unknown),
        ],
    )
}

pub fn parse_risk(value: Option<&str>) -> Result<Option<ApiRisk>, ApiCatalogError> {
    parse_enum(
        value,
        "risk",
        &[
            ("read", ApiRisk::Read),
            ("mutating", ApiRisk::Mutating),
            ("high_risk", ApiRisk::HighRisk),
            ("denied_by_default", ApiRisk::DeniedByDefault),
        ],
    )
}

fn parse_enum<T: Copy>(
    value: Option<&str>,
    name: &'static str,
    allowed: &[(&'static str, T)],
) -> Result<Option<T>, ApiCatalogError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    allowed
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(value))
        .map(|(_, parsed)| Some(*parsed))
        .ok_or_else(|| {
            let allowed_values = allowed
                .iter()
                .map(|(value, _)| *value)
                .collect::<Vec<_>>()
                .join(", ");
            let mut message = String::from(name);
            message.push_str(" must be one of ");
            message.push_str(&allowed_values);
            ApiCatalogError::InvalidFilter(message)
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiCatalogError {
    OperationNotFound(String),
    MissingPathParam(String),
    MissingQueryParam(String),
    InvalidQueryParam(String),
    InvalidFilter(String),
    MethodMismatch {
        expected: Cow<'static, str>,
        actual: String,
    },
    DeniedByDefault(String),
}

impl ApiCatalogError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::OperationNotFound(_) => "api_catalog.operation_not_found",
            Self::MissingPathParam(_) => "api_catalog.missing_path_param",
            Self::MissingQueryParam(_) => "api_catalog.missing_query_param",
            Self::InvalidQueryParam(_) => "api_catalog.invalid_query_param",
            Self::InvalidFilter(_) => "api_catalog.invalid_filter",
            Self::MethodMismatch { .. } => "api_catalog.method_mismatch",
            Self::DeniedByDefault(_) => "api_catalog.denied_by_default",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::OperationNotFound(id) => format!("Cloudflare API operation '{id}' was not found"),
            Self::MissingPathParam(name) => format!("missing required path parameter '{name}'"),
            Self::MissingQueryParam(name) => format!("missing required query parameter '{name}'"),
            Self::InvalidQueryParam(name) => {
                format!("query parameter '{name}' must be scalar or array of scalars")
            }
            Self::InvalidFilter(message) => message.clone(),
            Self::MethodMismatch { expected, actual } => {
                format!("operation uses method {actual}; expected {expected}")
            }
            Self::DeniedByDefault(id) => {
                format!("operation '{id}' is denied by default by the generic API executor")
            }
        }
    }

    pub fn hint(&self) -> &'static str {
        match self {
            Self::OperationNotFound(_) => {
                "Call api_find_operations to discover valid operation_id values."
            }
            Self::MissingPathParam(_) => {
                "Pass the path parameter explicitly, or configure the matching account/zone default when supported."
            }
            Self::MissingQueryParam(_) => {
                "Pass all required query parameters from api_get_operation."
            }
            Self::InvalidQueryParam(_) => {
                "Use string, number, boolean, null, or arrays of those scalar values."
            }
            Self::InvalidFilter(_) => "Use the documented filter names and values.",
            Self::MethodMismatch { .. } => {
                "Use api_read for GET operations and api_mutate for POST/PUT/PATCH/DELETE operations."
            }
            Self::DeniedByDefault(_) => {
                "Use a curated safe tool when available, or explicitly allow this operation in a future policy profile."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn catalog_loads_with_unique_operation_ids() {
        let catalog = catalog();
        assert!(catalog.operation_count > 1000);
        let mut ids = BTreeSet::new();
        for operation in &catalog.operations {
            assert!(
                ids.insert(&operation.operation_id),
                "duplicate operation id"
            );
        }
    }

    #[test]
    fn search_finds_dns_records_and_prefers_curated_tool() {
        let results = search_operations(ApiOperationSearch {
            query: Some("list dns records"),
            limit: 10,
            ..ApiOperationSearch::default()
        });
        assert!(results.iter().any(|result| {
            result.operation_id == "dns-records-for-a-zone-list-dns-records"
                && result.preferred_tool.as_deref() == Some("list_dns_records")
        }));
    }

    #[test]
    fn search_tolerates_extra_natural_language_terms() {
        let results = search_operations(ApiOperationSearch {
            query: Some("token api create user tokens wrangler api token"),
            limit: 20,
            ..ApiOperationSearch::default()
        });
        assert!(results.iter().any(|result| {
            result.operation_id == "account-api-tokens-create-token"
                && result.method == "POST"
                && result.risk == ApiRisk::DeniedByDefault
        }));
    }

    #[test]
    fn render_path_uses_defaults_for_account_and_zone() {
        let operation = ApiOperation {
            operation_id: "test".to_string(),
            method: "GET".to_string(),
            path: "/zones/{zone_id}/dns_records".to_string(),
            tag: "DNS".to_string(),
            summary: None,
            deprecated: false,
            scope: ApiScope::Zone,
            risk: ApiRisk::Read,
            path_params: vec!["zone_id".to_string()],
            query_params: Vec::new(),
            required_query_params: Vec::new(),
            has_request_body: false,
            preferred_tool: None,
        };
        assert_eq!(
            render_path(&operation, &BTreeMap::new(), None, Some("zone-1")).unwrap(),
            "/zones/zone-1/dns_records"
        );
    }

    #[test]
    fn confirmation_token_is_stable() {
        let operation = find_operation("accounts-list-accounts").expect("operation");
        let first = mutation_confirmation_token(operation, "/accounts", &None);
        let second = mutation_confirmation_token(operation, "/accounts", &None);
        assert_eq!(first, second);
        assert!(first.starts_with("cf-api-"));
    }
}
