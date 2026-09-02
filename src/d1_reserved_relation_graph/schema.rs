use super::lexer::{
    Token, ensure_balanced, identifier, is_word, require_word, tokenize, trim_terminal_semicolon,
    unsupported_definition,
};
use super::{D1ReservedRelationGraphError, WriteOperation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RelationKind {
    Table,
    View,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ForeignKeyAction {
    NoAction,
    Restrict,
    SetNull,
    SetDefault,
    Cascade,
}

impl ForeignKeyAction {
    pub(super) fn child_operation(self, parent: WriteOperation) -> Option<WriteOperation> {
        match (self, parent) {
            (Self::Cascade, WriteOperation::Delete) => Some(WriteOperation::Delete),
            (
                Self::Cascade | Self::SetNull | Self::SetDefault,
                WriteOperation::Update | WriteOperation::Delete,
            ) => Some(WriteOperation::Update),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ForeignKey {
    pub(super) parent: String,
    pub(super) on_delete: ForeignKeyAction,
    pub(super) on_update: ForeignKeyAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RelationSchema {
    pub(super) kind: RelationKind,
    pub(super) autoincrement: bool,
    pub(super) foreign_keys: Vec<ForeignKey>,
}

pub(super) fn parse_relation(
    kind: RelationKind,
    expected_name: &str,
    sql: &str,
) -> Result<RelationSchema, D1ReservedRelationGraphError> {
    let tokens = trim_terminal_semicolon(tokenize(sql)?)?;
    let mut cursor = 0usize;
    require_word(&tokens, &mut cursor, "create")?;
    match kind {
        RelationKind::Table => require_word(&tokens, &mut cursor, "table")?,
        RelationKind::View => require_word(&tokens, &mut cursor, "view")?,
    }
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

    if kind == RelationKind::View {
        require_word(&tokens, &mut cursor, "as")?;
        if !matches!(
            tokens.get(cursor),
            Some(Token::Word(word))
                if word.eq_ignore_ascii_case("select") || word.eq_ignore_ascii_case("with")
        ) {
            return Err(unsupported_definition());
        }
        ensure_balanced(&tokens[cursor..])?;
        return Ok(RelationSchema {
            kind,
            autoincrement: false,
            foreign_keys: Vec::new(),
        });
    }

    if tokens.get(cursor) != Some(&Token::Symbol('(')) {
        return Err(unsupported_definition());
    }
    let (segments, after_body) = table_segments(&tokens, cursor)?;
    validate_table_options(&tokens[after_body..])?;
    let autoincrement = segments.iter().any(|segment| {
        segment
            .iter()
            .any(|token| is_word(Some(token), "autoincrement"))
    });
    let mut foreign_keys = Vec::new();
    for segment in segments {
        let references = segment
            .iter()
            .enumerate()
            .filter_map(|(index, token)| is_word(Some(token), "references").then_some(index))
            .collect::<Vec<_>>();
        if references.len() > 1 {
            return Err(unsupported_definition());
        }
        if let Some(reference) = references.first().copied() {
            foreign_keys.push(parse_foreign_key(segment, reference)?);
        }
    }
    Ok(RelationSchema {
        kind,
        autoincrement,
        foreign_keys,
    })
}

fn table_segments(
    tokens: &[Token],
    opening: usize,
) -> Result<(Vec<&[Token]>, usize), D1ReservedRelationGraphError> {
    let mut segments = Vec::new();
    let mut depth = 1usize;
    let mut start = opening + 1;
    for (index, token) in tokens.iter().enumerate().skip(opening + 1) {
        match token {
            Token::Symbol('(') => {
                depth = depth.checked_add(1).ok_or_else(unsupported_definition)?;
            }
            Token::Symbol(')') => {
                depth = depth.checked_sub(1).ok_or_else(unsupported_definition)?;
                if depth == 0 {
                    if start == index {
                        return Err(unsupported_definition());
                    }
                    segments.push(&tokens[start..index]);
                    return Ok((segments, index + 1));
                }
            }
            Token::Symbol(',') if depth == 1 => {
                if start == index {
                    return Err(unsupported_definition());
                }
                segments.push(&tokens[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    Err(unsupported_definition())
}

fn validate_table_options(tokens: &[Token]) -> Result<(), D1ReservedRelationGraphError> {
    let mut cursor = 0usize;
    let mut strict = false;
    let mut without_rowid = false;
    while cursor < tokens.len() {
        if is_word(tokens.get(cursor), "strict") && !strict {
            strict = true;
            cursor += 1;
        } else if is_word(tokens.get(cursor), "without")
            && is_word(tokens.get(cursor + 1), "rowid")
            && !without_rowid
        {
            without_rowid = true;
            cursor += 2;
        } else {
            return Err(unsupported_definition());
        }
        if cursor == tokens.len() {
            return Ok(());
        }
        if tokens.get(cursor) != Some(&Token::Symbol(',')) || cursor + 1 == tokens.len() {
            return Err(unsupported_definition());
        }
        cursor += 1;
    }
    Ok(())
}

fn parse_foreign_key(
    segment: &[Token],
    reference: usize,
) -> Result<ForeignKey, D1ReservedRelationGraphError> {
    let (parent, mut cursor) = identifier(segment, reference + 1)?;
    if segment.get(cursor) == Some(&Token::Symbol('.')) {
        return Err(unsupported_definition());
    }
    if segment.get(cursor) == Some(&Token::Symbol('(')) {
        cursor = consume_identifier_list(segment, cursor)?;
    }

    let mut on_delete = ForeignKeyAction::NoAction;
    let mut on_update = ForeignKeyAction::NoAction;
    let mut delete_seen = false;
    let mut update_seen = false;
    while cursor < segment.len() {
        if is_word(segment.get(cursor), "on")
            && (is_word(segment.get(cursor + 1), "delete")
                || is_word(segment.get(cursor + 1), "update"))
        {
            let is_delete = is_word(segment.get(cursor + 1), "delete");
            if (is_delete && delete_seen) || (!is_delete && update_seen) {
                return Err(unsupported_definition());
            }
            let (action, consumed) = parse_action(&segment[cursor + 2..])?;
            if is_delete {
                delete_seen = true;
                on_delete = action;
            } else {
                update_seen = true;
                on_update = action;
            }
            cursor += 2 + consumed;
        } else if is_word(segment.get(cursor), "match") {
            let (_, next) = identifier(segment, cursor + 1)?;
            cursor = next;
        } else if is_word(segment.get(cursor), "not")
            && is_word(segment.get(cursor + 1), "deferrable")
        {
            cursor += 2;
        } else if is_word(segment.get(cursor), "deferrable") {
            cursor += 1;
            if is_word(segment.get(cursor), "initially") {
                cursor += 1;
                if !is_word(segment.get(cursor), "deferred")
                    && !is_word(segment.get(cursor), "immediate")
                {
                    return Err(unsupported_definition());
                }
                cursor += 1;
            }
        } else {
            // Other column constraints are irrelevant to write reachability.
            // They remain lexed and balanced; a later REFERENCES or mutating
            // ON action was counted above and therefore cannot hide here.
            cursor += 1;
        }
    }
    Ok(ForeignKey {
        parent,
        on_delete,
        on_update,
    })
}

fn consume_identifier_list(
    tokens: &[Token],
    opening: usize,
) -> Result<usize, D1ReservedRelationGraphError> {
    let mut cursor = opening + 1;
    loop {
        let (_, next) = identifier(tokens, cursor)?;
        cursor = next;
        match tokens.get(cursor) {
            Some(Token::Symbol(',')) => cursor += 1,
            Some(Token::Symbol(')')) => return Ok(cursor + 1),
            _ => return Err(unsupported_definition()),
        }
    }
}

fn parse_action(
    tokens: &[Token],
) -> Result<(ForeignKeyAction, usize), D1ReservedRelationGraphError> {
    if is_word(tokens.first(), "cascade") {
        Ok((ForeignKeyAction::Cascade, 1))
    } else if is_word(tokens.first(), "restrict") {
        Ok((ForeignKeyAction::Restrict, 1))
    } else if is_word(tokens.first(), "no") && is_word(tokens.get(1), "action") {
        Ok((ForeignKeyAction::NoAction, 2))
    } else if is_word(tokens.first(), "set") && is_word(tokens.get(1), "null") {
        Ok((ForeignKeyAction::SetNull, 2))
    } else if is_word(tokens.first(), "set") && is_word(tokens.get(1), "default") {
        Ok((ForeignKeyAction::SetDefault, 2))
    } else {
        Err(unsupported_definition())
    }
}
