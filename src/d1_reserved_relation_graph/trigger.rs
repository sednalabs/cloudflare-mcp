use super::lexer::{
    Token, ensure_balanced, identifier, is_word, require_word, tokenize, unsupported_definition,
};
use super::{D1ReservedRelationGraphError, WriteOperation};

const MAX_TRIGGER_STATEMENTS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TriggerTiming {
    Before,
    After,
    InsteadOf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TriggerEffect {
    pub(super) relation: String,
    pub(super) operations: Vec<WriteOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Trigger {
    pub(super) parent: String,
    pub(super) timing: TriggerTiming,
    pub(super) operation: WriteOperation,
    pub(super) effects: Vec<TriggerEffect>,
}

pub(super) fn parse_trigger(
    expected_name: &str,
    expected_parent: &str,
    sql: &str,
) -> Result<Trigger, D1ReservedRelationGraphError> {
    let mut tokens = tokenize(sql)?;
    if tokens.last() == Some(&Token::Symbol(';')) {
        tokens.pop();
    }
    if tokens.is_empty() {
        return Err(unsupported_definition());
    }
    let mut cursor = 0usize;
    require_word(&tokens, &mut cursor, "create")?;
    require_word(&tokens, &mut cursor, "trigger")?;
    if is_word(tokens.get(cursor), "if") {
        require_word(&tokens, &mut cursor, "if")?;
        require_word(&tokens, &mut cursor, "not")?;
        require_word(&tokens, &mut cursor, "exists")?;
    }
    let (name, next) = identifier(&tokens, cursor)?;
    if name != expected_name || tokens.get(next) == Some(&Token::Symbol('.')) {
        return Err(unsupported_definition());
    }
    cursor = next;
    let timing = if is_word(tokens.get(cursor), "before") {
        cursor += 1;
        TriggerTiming::Before
    } else if is_word(tokens.get(cursor), "after") {
        cursor += 1;
        TriggerTiming::After
    } else if is_word(tokens.get(cursor), "instead") {
        cursor += 1;
        require_word(&tokens, &mut cursor, "of")?;
        TriggerTiming::InsteadOf
    } else {
        TriggerTiming::Before
    };
    let operation = if is_word(tokens.get(cursor), "insert") {
        cursor += 1;
        WriteOperation::Insert
    } else if is_word(tokens.get(cursor), "update") {
        cursor += 1;
        if is_word(tokens.get(cursor), "of") {
            cursor += 1;
            let mut columns = 0usize;
            loop {
                let (_, next) = identifier(&tokens, cursor)?;
                columns += 1;
                cursor = next;
                if tokens.get(cursor) == Some(&Token::Symbol(',')) {
                    cursor += 1;
                } else {
                    break;
                }
            }
            if columns == 0 {
                return Err(unsupported_definition());
            }
        }
        WriteOperation::Update
    } else if is_word(tokens.get(cursor), "delete") {
        cursor += 1;
        WriteOperation::Delete
    } else {
        return Err(unsupported_definition());
    };
    require_word(&tokens, &mut cursor, "on")?;
    let (parent, next) = identifier(&tokens, cursor)?;
    if parent != expected_parent || tokens.get(next) == Some(&Token::Symbol('.')) {
        return Err(unsupported_definition());
    }
    cursor = next;
    if is_word(tokens.get(cursor), "for") {
        require_word(&tokens, &mut cursor, "for")?;
        require_word(&tokens, &mut cursor, "each")?;
        require_word(&tokens, &mut cursor, "row")?;
    }
    let begin = top_level_word(&tokens, cursor, "begin").ok_or_else(unsupported_definition)?;
    if cursor < begin {
        require_word(&tokens, &mut cursor, "when")?;
        if cursor == begin {
            return Err(unsupported_definition());
        }
        ensure_balanced(&tokens[cursor..begin])?;
        cursor = begin;
    }
    if cursor != begin {
        return Err(unsupported_definition());
    }
    let end = tokens
        .len()
        .checked_sub(1)
        .ok_or_else(unsupported_definition)?;
    if !is_word(tokens.get(begin), "begin") || !is_word(tokens.get(end), "end") || begin + 1 >= end
    {
        return Err(unsupported_definition());
    }
    let statements = split_body(&tokens[begin + 1..end])?;
    let mut effects = Vec::new();
    for statement in statements {
        if is_word(statement.first(), "select") {
            ensure_balanced(statement)?;
            continue;
        }
        effects.push(parse_dml(statement)?);
    }
    Ok(Trigger {
        parent,
        timing,
        operation,
        effects,
    })
}

fn split_body(tokens: &[Token]) -> Result<Vec<&[Token]>, D1ReservedRelationGraphError> {
    let mut statements = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0usize;
    let mut case_depth = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Symbol('(') => {
                paren_depth = paren_depth
                    .checked_add(1)
                    .ok_or_else(unsupported_definition)?;
            }
            Token::Symbol(')') => {
                paren_depth = paren_depth
                    .checked_sub(1)
                    .ok_or_else(unsupported_definition)?;
            }
            Token::Word(word) if word.eq_ignore_ascii_case("case") => {
                case_depth = case_depth
                    .checked_add(1)
                    .ok_or_else(unsupported_definition)?;
            }
            Token::Word(word) if word.eq_ignore_ascii_case("end") && case_depth > 0 => {
                case_depth -= 1;
            }
            Token::Symbol(';') if paren_depth == 0 && case_depth == 0 => {
                if start == index {
                    return Err(unsupported_definition());
                }
                statements.push(&tokens[start..index]);
                start = index + 1;
            }
            _ => {}
        }
        if statements.len() > MAX_TRIGGER_STATEMENTS {
            return Err(unsupported_definition());
        }
    }
    if paren_depth != 0 || case_depth != 0 {
        return Err(unsupported_definition());
    }
    if start < tokens.len() {
        statements.push(&tokens[start..]);
    }
    if statements.is_empty() || statements.len() > MAX_TRIGGER_STATEMENTS {
        return Err(unsupported_definition());
    }
    Ok(statements)
}

fn parse_dml(tokens: &[Token]) -> Result<TriggerEffect, D1ReservedRelationGraphError> {
    ensure_balanced(tokens)?;
    let mut cursor = 0usize;
    let mut operations = Vec::new();
    let replace;
    if is_word(tokens.get(cursor), "insert") {
        operations.push(WriteOperation::Insert);
        cursor += 1;
        replace = parse_conflict(tokens, &mut cursor)?;
        require_word(tokens, &mut cursor, "into")?;
    } else if is_word(tokens.get(cursor), "replace") {
        operations.push(WriteOperation::Insert);
        replace = true;
        cursor += 1;
        require_word(tokens, &mut cursor, "into")?;
    } else if is_word(tokens.get(cursor), "update") {
        operations.push(WriteOperation::Update);
        cursor += 1;
        replace = parse_conflict(tokens, &mut cursor)?;
    } else if is_word(tokens.get(cursor), "delete") {
        operations.push(WriteOperation::Delete);
        cursor += 1;
        replace = false;
        require_word(tokens, &mut cursor, "from")?;
    } else {
        return Err(unsupported_definition());
    }
    let (relation, next) = identifier(tokens, cursor)?;
    if tokens.get(next) == Some(&Token::Symbol('.')) {
        return Err(unsupported_definition());
    }
    if replace {
        operations.push(WriteOperation::Delete);
    }
    if operations.contains(&WriteOperation::Insert)
        && tokens
            .windows(2)
            .any(|window| is_word(window.first(), "do") && is_word(window.get(1), "update"))
    {
        operations.push(WriteOperation::Update);
    }
    operations.sort();
    operations.dedup();
    Ok(TriggerEffect {
        relation,
        operations,
    })
}

fn parse_conflict(
    tokens: &[Token],
    cursor: &mut usize,
) -> Result<bool, D1ReservedRelationGraphError> {
    if !is_word(tokens.get(*cursor), "or") {
        return Ok(false);
    }
    *cursor += 1;
    let Some(Token::Word(mode)) = tokens.get(*cursor) else {
        return Err(unsupported_definition());
    };
    if !matches!(
        mode.to_ascii_lowercase().as_str(),
        "rollback" | "abort" | "fail" | "ignore" | "replace"
    ) {
        return Err(unsupported_definition());
    }
    *cursor += 1;
    Ok(mode.eq_ignore_ascii_case("replace"))
}

fn top_level_word(tokens: &[Token], start: usize, expected: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token {
            Token::Symbol('(') => depth = depth.checked_add(1)?,
            Token::Symbol(')') => depth = depth.checked_sub(1)?,
            _ if depth == 0 && is_word(Some(token), expected) => return Some(index),
            _ => {}
        }
    }
    None
}
