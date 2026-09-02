//! Conservative exact D1 DML statement classification.
//!
//! This is deliberately a closed lexical recognizer, not a general SQL parser.
//! It accepts one bounded statement whose target is one unquoted canonical
//! lowercase relation identity and rejects comments, quoted identifiers,
//! qualified targets, CTEs, and unrecognized compound forms.

use serde::Serialize;

use crate::d1_execute_write::D1WriteStatementKind;
use crate::d1_reserved_relation_graph::D1WriteOperationForm;

const MAX_SQL_BYTES: usize = 1024 * 1024;
const MAX_RELATION_BYTES: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1ClassifiedDml {
    pub(crate) statement_kind: D1WriteStatementKind,
    pub(crate) form: D1WriteOperationForm,
    pub(crate) relation: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlClassifierClassification {
    Empty,
    TooLarge,
    MultipleStatements,
    CommentOrQuotedIdentityUnsupported,
    UnsupportedStatement,
    TargetMissing,
    TargetInvalid,
    CompoundFormUnsupported,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1DmlClassifierError {
    pub(crate) code: &'static str,
    pub(crate) classification: D1DmlClassifierClassification,
    pub(crate) message: &'static str,
}

pub(crate) fn classify_d1_dml(sql: &str) -> Result<D1ClassifiedDml, D1DmlClassifierError> {
    if sql.is_empty() || sql.trim().is_empty() {
        return Err(error(
            D1DmlClassifierClassification::Empty,
            "D1 DML SQL was empty",
        ));
    }
    if sql.len() > MAX_SQL_BYTES {
        return Err(error(
            D1DmlClassifierClassification::TooLarge,
            "D1 DML SQL exceeded the exact classifier byte cap",
        ));
    }
    if sql.contains("--")
        || sql.contains("/*")
        || sql.contains("*/")
        || sql.contains('"')
        || sql.contains('`')
        || sql.contains('[')
        || sql.contains(']')
    {
        return Err(error(
            D1DmlClassifierClassification::CommentOrQuotedIdentityUnsupported,
            "comments and quoted identifiers are outside the closed D1 DML contract",
        ));
    }
    let trimmed = sql.trim();
    let body = trimmed.strip_suffix(';').unwrap_or(trimmed).trim_end();
    if body.contains(';') {
        return Err(error(
            D1DmlClassifierClassification::MultipleStatements,
            "exactly one D1 DML statement is required",
        ));
    }
    let tokens = body.split_whitespace().collect::<Vec<_>>();
    let first = tokens
        .first()
        .map(|value| value.to_ascii_uppercase())
        .ok_or_else(|| error(D1DmlClassifierClassification::Empty, "D1 DML SQL was empty"))?;
    let (kind, form, relation_index) = match first.as_str() {
        "INSERT" => {
            if upper(&tokens, 1) == Some("OR")
                && upper(&tokens, 2) == Some("REPLACE")
                && upper(&tokens, 3) == Some("INTO")
            {
                (
                    D1WriteStatementKind::Insert,
                    D1WriteOperationForm::InsertOrReplace,
                    4,
                )
            } else if upper(&tokens, 1) == Some("INTO") {
                let form = if contains_upsert_do_update(body) {
                    D1WriteOperationForm::UpsertDoUpdate
                } else {
                    D1WriteOperationForm::Insert
                };
                (D1WriteStatementKind::Insert, form, 2)
            } else {
                return Err(error(
                    D1DmlClassifierClassification::CompoundFormUnsupported,
                    "INSERT form was outside the closed D1 DML contract",
                ));
            }
        }
        "REPLACE" if upper(&tokens, 1) == Some("INTO") => (
            D1WriteStatementKind::Replace,
            D1WriteOperationForm::Replace,
            2,
        ),
        "UPDATE" => {
            if upper(&tokens, 1) == Some("OR") && upper(&tokens, 2) == Some("REPLACE") {
                (
                    D1WriteStatementKind::Update,
                    D1WriteOperationForm::UpdateOrReplace,
                    3,
                )
            } else {
                (
                    D1WriteStatementKind::Update,
                    D1WriteOperationForm::Update,
                    1,
                )
            }
        }
        "DELETE" if upper(&tokens, 1) == Some("FROM") => (
            D1WriteStatementKind::Delete,
            D1WriteOperationForm::Delete,
            2,
        ),
        "INSERT" | "UPDATE" | "DELETE" | "REPLACE" => {
            return Err(error(
                D1DmlClassifierClassification::CompoundFormUnsupported,
                "DML form was outside the closed contract",
            ));
        }
        _ => {
            return Err(error(
                D1DmlClassifierClassification::UnsupportedStatement,
                "D1 write SQL must be one supported INSERT, UPDATE, DELETE, or REPLACE form",
            ));
        }
    };
    let raw = tokens.get(relation_index).ok_or_else(|| {
        error(
            D1DmlClassifierClassification::TargetMissing,
            "D1 DML target relation was absent",
        )
    })?;
    if raw.contains('(')
        && !matches!(
            kind,
            D1WriteStatementKind::Insert | D1WriteStatementKind::Replace
        )
    {
        return Err(error(
            D1DmlClassifierClassification::TargetInvalid,
            "D1 DML target relation used unsupported attached syntax",
        ));
    }
    let relation = raw.split_once('(').map_or(*raw, |(relation, _)| relation);
    if !valid_relation(relation) {
        return Err(error(
            D1DmlClassifierClassification::TargetInvalid,
            "D1 DML target was not one canonical lowercase unqualified relation",
        ));
    }
    Ok(D1ClassifiedDml {
        statement_kind: kind,
        form,
        relation: relation.to_string(),
    })
}

fn upper<'a>(tokens: &'a [&str], index: usize) -> Option<&'static str> {
    match tokens
        .get(index)
        .map(|value| value.to_ascii_uppercase())?
        .as_str()
    {
        "OR" => Some("OR"),
        "REPLACE" => Some("REPLACE"),
        "INTO" => Some("INTO"),
        "FROM" => Some("FROM"),
        _ => None,
    }
}

fn contains_upsert_do_update(sql: &str) -> bool {
    let upper = sql.to_ascii_uppercase();
    upper.contains(" ON CONFLICT") && upper.contains(" DO UPDATE")
}

fn valid_relation(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_RELATION_BYTES
        && !value.contains('.')
        && value.to_ascii_lowercase() == value
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn error(
    classification: D1DmlClassifierClassification,
    message: &'static str,
) -> D1DmlClassifierError {
    D1DmlClassifierError {
        code: "d1.execute_write_classifier_denied",
        classification,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_closed_forms_and_relations() {
        let cases = [
            (
                "INSERT INTO stories(id) VALUES (?)",
                D1WriteOperationForm::Insert,
                "stories",
            ),
            (
                "INSERT OR REPLACE INTO stories (id) VALUES (?)",
                D1WriteOperationForm::InsertOrReplace,
                "stories",
            ),
            (
                "INSERT INTO stories(id) VALUES (?) ON CONFLICT(id) DO UPDATE SET id=?",
                D1WriteOperationForm::UpsertDoUpdate,
                "stories",
            ),
            (
                "UPDATE OR REPLACE stories SET id=?",
                D1WriteOperationForm::UpdateOrReplace,
                "stories",
            ),
            (
                "DELETE FROM stories WHERE id=?",
                D1WriteOperationForm::Delete,
                "stories",
            ),
            (
                "REPLACE INTO stories(id) VALUES (?)",
                D1WriteOperationForm::Replace,
                "stories",
            ),
        ];
        for (sql, form, relation) in cases {
            let classified = classify_d1_dml(sql).expect(sql);
            assert_eq!(classified.form, form);
            assert_eq!(classified.relation, relation);
        }
    }

    #[test]
    fn denies_ambiguous_or_noncanonical_targets() {
        for sql in [
            "WITH x AS (SELECT 1) UPDATE stories SET id=1",
            "UPDATE main.stories SET id=1",
            "UPDATE Stories SET id=1",
            "UPDATE \"stories\" SET id=1",
            "UPDATE stories SET id=1; DELETE FROM stories",
        ] {
            assert!(classify_d1_dml(sql).is_err(), "{sql}");
        }
    }
}
