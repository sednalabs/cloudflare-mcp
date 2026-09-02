use super::{D1ReservedRelationGraphClassification, D1ReservedRelationGraphError, graph_error};

pub(super) const MAX_DEFINITION_BYTES: usize = 512 * 1024;
const MAX_TOKENS: usize = 32_768;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Token {
    Word(String),
    Identifier(String),
    StringLiteral,
    Symbol(char),
}

pub(super) fn tokenize(sql: &str) -> Result<Vec<Token>, D1ReservedRelationGraphError> {
    if sql.is_empty() || sql.len() > MAX_DEFINITION_BYTES || !sql.is_ascii() {
        return Err(unsupported_definition());
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Normal,
        SingleQuote,
        DoubleQuote,
        Backtick,
        Bracket,
        LineComment,
        BlockComment,
    }

    let bytes = sql.as_bytes();
    let mut mode = Mode::Normal;
    let mut tokens = Vec::new();
    let mut current = Vec::new();
    let mut quoted = Vec::new();
    let mut index = 0usize;
    let flush_word = |current: &mut Vec<u8>, tokens: &mut Vec<Token>| {
        if !current.is_empty() {
            tokens.push(Token::Word(
                String::from_utf8(current.clone()).expect("ASCII token"),
            ));
            current.clear();
        }
    };

    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match mode {
            Mode::Normal => match (byte, next) {
                (b'-', Some(b'-')) => {
                    flush_word(&mut current, &mut tokens);
                    mode = Mode::LineComment;
                    index += 1;
                }
                (b'/', Some(b'*')) => {
                    flush_word(&mut current, &mut tokens);
                    mode = Mode::BlockComment;
                    index += 1;
                }
                (b'\'', _) => {
                    flush_word(&mut current, &mut tokens);
                    quoted.clear();
                    mode = Mode::SingleQuote;
                }
                (b'"', _) => {
                    flush_word(&mut current, &mut tokens);
                    quoted.clear();
                    mode = Mode::DoubleQuote;
                }
                (b'`', _) => {
                    flush_word(&mut current, &mut tokens);
                    quoted.clear();
                    mode = Mode::Backtick;
                }
                (b'[', _) => {
                    flush_word(&mut current, &mut tokens);
                    quoted.clear();
                    mode = Mode::Bracket;
                }
                _ if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$') => {
                    current.push(byte);
                }
                _ if byte.is_ascii_whitespace() => flush_word(&mut current, &mut tokens),
                _ if byte.is_ascii_punctuation() => {
                    flush_word(&mut current, &mut tokens);
                    tokens.push(Token::Symbol(byte as char));
                }
                _ => return Err(unsupported_definition()),
            },
            Mode::SingleQuote => {
                if byte == b'\'' {
                    if next == Some(b'\'') {
                        quoted.push(b'\'');
                        index += 1;
                    } else {
                        tokens.push(Token::StringLiteral);
                        mode = Mode::Normal;
                    }
                } else {
                    quoted.push(byte);
                }
            }
            Mode::DoubleQuote | Mode::Backtick => {
                let delimiter = if mode == Mode::DoubleQuote {
                    b'"'
                } else {
                    b'`'
                };
                if byte == delimiter {
                    if next == Some(delimiter) {
                        quoted.push(delimiter);
                        index += 1;
                    } else {
                        tokens.push(Token::Identifier(
                            String::from_utf8(quoted.clone())
                                .map_err(|_| unsupported_definition())?,
                        ));
                        mode = Mode::Normal;
                    }
                } else {
                    quoted.push(byte);
                }
            }
            Mode::Bracket => {
                if byte == b']' {
                    if next == Some(b']') {
                        quoted.push(b']');
                        index += 1;
                    } else {
                        tokens.push(Token::Identifier(
                            String::from_utf8(quoted.clone())
                                .map_err(|_| unsupported_definition())?,
                        ));
                        mode = Mode::Normal;
                    }
                } else {
                    quoted.push(byte);
                }
            }
            Mode::LineComment => {
                if matches!(byte, b'\n' | b'\r') {
                    mode = Mode::Normal;
                }
            }
            Mode::BlockComment => {
                if byte == b'*' && next == Some(b'/') {
                    mode = Mode::Normal;
                    index += 1;
                }
            }
        }
        if tokens.len() > MAX_TOKENS {
            return Err(graph_error(
                D1ReservedRelationGraphClassification::GraphLimitExceeded,
                "catalog definition exceeded the closed token bound",
            ));
        }
        index += 1;
    }

    if !matches!(mode, Mode::Normal | Mode::LineComment) {
        return Err(unsupported_definition());
    }
    flush_word(&mut current, &mut tokens);
    if tokens.is_empty() || tokens.len() > MAX_TOKENS {
        return Err(unsupported_definition());
    }
    Ok(tokens)
}

pub(super) fn trim_terminal_semicolon(
    mut tokens: Vec<Token>,
) -> Result<Vec<Token>, D1ReservedRelationGraphError> {
    if tokens.last() == Some(&Token::Symbol(';')) {
        tokens.pop();
    }
    if tokens.is_empty() || tokens.iter().any(|token| token == &Token::Symbol(';')) {
        return Err(unsupported_definition());
    }
    Ok(tokens)
}

pub(super) fn is_word(token: Option<&Token>, expected: &str) -> bool {
    matches!(token, Some(Token::Word(word)) if word.eq_ignore_ascii_case(expected))
}

pub(super) fn require_word(
    tokens: &[Token],
    cursor: &mut usize,
    expected: &str,
) -> Result<(), D1ReservedRelationGraphError> {
    if !is_word(tokens.get(*cursor), expected) {
        return Err(unsupported_definition());
    }
    *cursor += 1;
    Ok(())
}

pub(super) fn identifier(
    tokens: &[Token],
    cursor: usize,
) -> Result<(String, usize), D1ReservedRelationGraphError> {
    let value = match tokens.get(cursor) {
        Some(Token::Word(value) | Token::Identifier(value)) => value,
        _ => return Err(unsupported_definition()),
    };
    if value.is_empty()
        || value.len() > 255
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(unsupported_definition());
    }
    Ok((value.to_ascii_lowercase(), cursor + 1))
}

pub(super) fn ensure_balanced(tokens: &[Token]) -> Result<(), D1ReservedRelationGraphError> {
    let mut depth = 0usize;
    for token in tokens {
        match token {
            Token::Symbol('(') => {
                depth = depth.checked_add(1).ok_or_else(unsupported_definition)?;
            }
            Token::Symbol(')') => {
                depth = depth.checked_sub(1).ok_or_else(unsupported_definition)?;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(unsupported_definition());
    }
    Ok(())
}

pub(super) fn unsupported_definition() -> D1ReservedRelationGraphError {
    graph_error(
        D1ReservedRelationGraphClassification::CatalogDefinitionUnsupported,
        "catalog definition was outside the closed reserved-relation grammar",
    )
}
