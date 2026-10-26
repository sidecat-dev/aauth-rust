//! Strict JSON for documents and parameters.
//!
//! Numbers stay the sender's spelling. Object members reject duplicates.
//! Nesting is bounded by `MAX_DEPTH`.
//! Callers that need wire bytes keep the exact value slice.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
use serde_json::value::RawValue;

use crate::error::Error;

/// Implementation limit on open arrays and objects, counted from the outermost
/// value of the bytes being parsed.
///
/// This is a stack-safety resource policy, not an R3 protocol rule. It matches
/// serde_json's default recursion limit: 127 nested levels parse, and the
/// 128th opening bracket is refused before its contents are read.
const MAX_DEPTH: usize = 128;

/// One JSON value. Numbers are the original literal, not floating point.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

pub(crate) struct RawMember {
    pub name: String,
    pub raw: Vec<u8>,
}

pub(crate) fn parse_json(data: &[u8]) -> Result<Json, Error> {
    let mut parser = Parser::new(data)?;
    parser.skip_ws();
    let value = parser.parse_value()?;
    parser.finish()?;
    Ok(value)
}

pub(crate) fn parse_raw_object(data: &[u8]) -> Result<Vec<RawMember>, Error> {
    let mut parser = Parser::new(data)?;
    parser.skip_ws();
    if parser.peek() != Some(b'{') {
        return Err(Error::new("expected JSON object"));
    }
    parser.enter()?;
    let mut members = Vec::new();
    let mut seen = BTreeSet::new();
    parser.skip_ws();
    if parser.peek() == Some(b'}') {
        parser.bump();
        parser.finish()?;
        return Ok(members);
    }
    loop {
        parser.skip_ws();
        let name = parser.parse_string()?;
        if !seen.insert(name.clone()) {
            return Err(Error::new(format!("duplicate member \"{name}\"")));
        }
        parser.skip_ws();
        if parser.peek() != Some(b':') {
            return Err(Error::new("expected ':' after object member name"));
        }
        parser.bump();
        parser.skip_ws();
        let start = parser.index;
        parser.parse_value()?;
        let raw = parser.data[start..parser.index].to_vec();
        members.push(RawMember { name, raw });
        parser.skip_ws();
        match parser.peek() {
            Some(b',') => parser.bump(),
            Some(b'}') => {
                parser.bump();
                break;
            }
            _ => return Err(Error::new("invalid JSON object")),
        }
    }
    parser.finish()?;
    Ok(members)
}

pub(crate) fn raw_array_elements(data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut parser = Parser::new(data)?;
    parser.skip_ws();
    if parser.peek() != Some(b'[') {
        return Err(Error::new("expected JSON array"));
    }
    parser.enter()?;
    let mut elements = Vec::new();
    parser.skip_ws();
    if parser.peek() == Some(b']') {
        parser.bump();
        parser.finish()?;
        return Ok(elements);
    }
    loop {
        parser.skip_ws();
        let start = parser.index;
        parser.parse_value()?;
        elements.push(parser.data[start..parser.index].to_vec());
        parser.skip_ws();
        match parser.peek() {
            Some(b',') => parser.bump(),
            Some(b']') => {
                parser.bump();
                break;
            }
            _ => return Err(Error::new("invalid JSON array")),
        }
    }
    parser.finish()?;
    Ok(elements)
}

pub(crate) fn expect_json_string(data: &[u8]) -> Result<String, Error> {
    match parse_json(data)? {
        Json::String(text) => Ok(text),
        _ => Err(Error::new("expected JSON string")),
    }
}

pub(crate) fn json_equal(left: &Json, right: &Json) -> bool {
    match (left, right) {
        (Json::Null, Json::Null) => true,
        (Json::Bool(left), Json::Bool(right)) => left == right,
        (Json::String(left), Json::String(right)) => left == right,
        (Json::Number(left), Json::Number(right)) => numbers_equal(left, right),
        (Json::Array(left), Json::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right.iter())
                    .all(|(left, right)| json_equal(left, right))
        }
        (Json::Object(left), Json::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(name, value)| {
                    right
                        .iter()
                        .find(|(other, _)| other == name)
                        .is_some_and(|(_, other)| json_equal(value, other))
                })
        }
        _ => false,
    }
}

pub(crate) fn compact_json(value: &Json) -> Vec<u8> {
    let mut out = Vec::new();
    write_json(&mut out, value);
    out
}

pub(crate) fn push_key(out: &mut Vec<u8>, key: &str) {
    push_string(out, key);
    out.push(b':');
}

pub(crate) fn push_optional_string(out: &mut Vec<u8>, key: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    out.push(b',');
    push_key(out, key);
    push_string(out, value);
}

pub(crate) fn push_string(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br#"\\"#),
            '\u{0008}' => out.extend_from_slice(br#"\b"#),
            '\u{000c}' => out.extend_from_slice(br#"\f"#),
            '\n' => out.extend_from_slice(br#"\n"#),
            '\r' => out.extend_from_slice(br#"\r"#),
            '\t' => out.extend_from_slice(br#"\t"#),
            c if (c as u32) < 0x20 => {
                let code = c as u32;
                out.extend_from_slice(format!("\\u{code:04x}").as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

pub(crate) fn decode_strict_object(
    data: &[u8],
    allowed: &[&str],
    mut handle: impl FnMut(&str, &[u8]) -> Result<(), Error>,
) -> Result<BTreeSet<String>, Error> {
    let members = parse_raw_object(data)?;
    let mut seen = BTreeSet::new();
    for member in members {
        if !allowed.contains(&member.name.as_str()) {
            return Err(Error::new(format!("unknown member \"{}\"", member.name)));
        }
        seen.insert(member.name.clone());
        handle(&member.name, &member.raw)
            .map_err(|err| Error::wrap(format!("member \"{}\"", member.name), err))?;
    }
    Ok(seen)
}

pub(crate) fn serialize_exact<S: Serializer>(
    bytes: &[u8],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let text = std::str::from_utf8(bytes).map_err(serde::ser::Error::custom)?;
    RawValue::from_string(text.to_owned())
        .map_err(serde::ser::Error::custom)?
        .serialize(serializer)
}

pub(crate) fn refuse_deserialize<'de, T, D>(deserializer: D, message: &str) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let _ignored = serde_json::Value::deserialize(deserializer)?;
    Err(serde::de::Error::custom(message))
}

fn write_json(out: &mut Vec<u8>, value: &Json) {
    match value {
        Json::Null => out.extend_from_slice(b"null"),
        Json::Bool(true) => out.extend_from_slice(b"true"),
        Json::Bool(false) => out.extend_from_slice(b"false"),
        Json::Number(literal) => out.extend_from_slice(literal.as_bytes()),
        Json::String(text) => push_string(out, text),
        Json::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json(out, item);
            }
            out.push(b']');
        }
        Json::Object(members) => {
            let mut ordered = members.clone();
            ordered.sort_by(|left, right| left.0.cmp(&right.0));
            out.push(b'{');
            for (index, (name, value)) in ordered.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                push_string(out, name);
                out.push(b':');
                write_json(out, value);
            }
            out.push(b'}');
        }
    }
}

fn numbers_equal(left: &str, right: &str) -> bool {
    match (normalize_number(left), normalize_number(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Normalized {
    negative: bool,
    digits: String,
    exponent: Big,
}

impl Normalized {
    fn zero() -> Self {
        Self {
            negative: false,
            digits: "0".to_owned(),
            exponent: Big::zero(),
        }
    }
}

fn normalize_number(source: &str) -> Option<Normalized> {
    let (coefficient, exponent_text) = match source.find(['e', 'E']) {
        Some(index) => (&source[..index], Some(&source[index + 1..])),
        None => (source, None),
    };
    let mut exponent = match exponent_text {
        Some(text) => Big::parse(text)?,
        None => Big::zero(),
    };
    let negative = coefficient.starts_with('-');
    let coefficient = coefficient.strip_prefix('-').unwrap_or(coefficient);
    let joined;
    let (body, fraction_digits) = if let Some(dot) = coefficient.find('.') {
        joined = format!("{}{}", &coefficient[..dot], &coefficient[dot + 1..]);
        (joined.as_str(), coefficient.len() - dot - 1)
    } else {
        (coefficient, 0)
    };
    let trimmed = body.trim_start_matches('0');
    if trimmed.is_empty() {
        return Some(Normalized::zero());
    }
    exponent = exponent.sub(&Big::from_usize(fraction_digits));
    let trailing = trimmed.len() - trimmed.trim_end_matches('0').len();
    let digits = if trailing == 0 {
        trimmed.to_owned()
    } else {
        exponent = exponent.add(&Big::from_usize(trailing));
        trimmed[..trimmed.len() - trailing].to_owned()
    };
    Some(Normalized {
        negative,
        digits,
        exponent,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Big {
    negative: bool,
    digits: String,
}

impl Big {
    fn zero() -> Self {
        Self {
            negative: false,
            digits: "0".to_owned(),
        }
    }

    fn from_usize(value: usize) -> Self {
        Self {
            negative: false,
            digits: value.to_string(),
        }
    }

    fn parse(input: &str) -> Option<Self> {
        let (negative, digits) = if let Some(rest) = input.strip_prefix('+') {
            (false, rest)
        } else if let Some(rest) = input.strip_prefix('-') {
            (true, rest)
        } else {
            (false, input)
        };
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let trimmed = digits.trim_start_matches('0');
        if trimmed.is_empty() {
            return Some(Self::zero());
        }
        Some(Self {
            negative,
            digits: trimmed.to_owned(),
        })
    }

    fn add(&self, other: &Self) -> Self {
        if self.negative == other.negative {
            let digits = add_abs(&self.digits, &other.digits);
            if digits == "0" {
                Self::zero()
            } else {
                Self {
                    negative: self.negative,
                    digits,
                }
            }
        } else {
            self.difference(other)
        }
    }

    fn sub(&self, other: &Self) -> Self {
        let flipped = Self {
            negative: !other.negative && other.digits != "0",
            digits: other.digits.clone(),
        };
        if other.digits == "0" {
            return self.clone();
        }
        self.add(&flipped)
    }

    fn difference(&self, other: &Self) -> Self {
        match cmp_abs(&self.digits, &other.digits) {
            Ordering::Equal => Self::zero(),
            Ordering::Greater => Self {
                negative: self.negative,
                digits: sub_abs(&self.digits, &other.digits),
            },
            Ordering::Less => Self {
                negative: other.negative,
                digits: sub_abs(&other.digits, &self.digits),
            },
        }
    }
}

fn cmp_abs(left: &str, right: &str) -> Ordering {
    match left.len().cmp(&right.len()) {
        Ordering::Equal => left.cmp(right),
        other => other,
    }
}

fn add_abs(left: &str, right: &str) -> String {
    let a = left.as_bytes();
    let b = right.as_bytes();
    let mut carry = 0u16;
    let mut out = Vec::new();
    let mut i = a.len();
    let mut j = b.len();
    while i > 0 || j > 0 || carry > 0 {
        let da = if i > 0 {
            i -= 1;
            u16::from(a[i] - b'0')
        } else {
            0
        };
        let db = if j > 0 {
            j -= 1;
            u16::from(b[j] - b'0')
        } else {
            0
        };
        let sum = da + db + carry;
        out.push(char::from(b'0' + u8::try_from(sum % 10).unwrap_or(0)));
        carry = sum / 10;
    }
    if out.is_empty() {
        return "0".to_owned();
    }
    out.iter().rev().collect()
}

fn sub_abs(left: &str, right: &str) -> String {
    let a = left.as_bytes();
    let b = right.as_bytes();
    let mut borrow = 0i16;
    let mut out = vec![b'0'; a.len()];
    for index in (0..a.len()).rev() {
        let da = i16::from(a[index] - b'0');
        let b_index = index as isize - (a.len() as isize - b.len() as isize);
        let db = if b_index >= 0 {
            i16::from(b[b_index as usize] - b'0')
        } else {
            0
        };
        let mut diff = da - db - borrow;
        if diff < 0 {
            diff += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[index] = b'0' + u8::try_from(diff).unwrap_or(0);
    }
    let text = String::from_utf8_lossy(&out);
    let trimmed = text.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}

struct Parser<'a> {
    data: &'a [u8],
    index: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8]) -> Result<Self, Error> {
        if std::str::from_utf8(data).is_err() {
            return Err(Error::new("JSON must be valid UTF-8"));
        }
        Ok(Self {
            data,
            index: 0,
            depth: 0,
        })
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.index).copied()
    }

    fn bump(&mut self) {
        self.index += 1;
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    /// Consume an opening bracket, refusing it when it would reach `MAX_DEPTH`.
    fn enter(&mut self) -> Result<(), Error> {
        self.depth += 1;
        if self.depth >= MAX_DEPTH {
            return Err(Error::new("JSON nesting exceeds the depth limit"));
        }
        self.bump();
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    fn finish(&mut self) -> Result<(), Error> {
        self.skip_ws();
        if self.index != self.data.len() {
            Err(Error::new("unexpected trailing JSON value"))
        } else {
            Ok(())
        }
    }

    fn parse_value(&mut self) -> Result<Json, Error> {
        match self.peek() {
            Some(b'n') => self.consume_literal(b"null", Json::Null),
            Some(b't') => self.consume_literal(b"true", Json::Bool(true)),
            Some(b'f') => self.consume_literal(b"false", Json::Bool(false)),
            Some(b'"') => Ok(Json::String(self.parse_string()?)),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(Error::new("invalid JSON value")),
        }
    }

    fn consume_literal(&mut self, literal: &[u8], value: Json) -> Result<Json, Error> {
        let end = self.index + literal.len();
        if self.data.get(self.index..end) != Some(literal) {
            return Err(Error::new("invalid JSON value"));
        }
        if self
            .data
            .get(end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(Error::new("invalid JSON value"));
        }
        self.index = end;
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Json, Error> {
        let start = self.index;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.peek() {
            Some(b'0') => self.bump(),
            Some(b'1'..=b'9') => {
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.bump();
                }
            }
            _ => return Err(Error::new("invalid JSON number")),
        }
        if self.peek() == Some(b'.') {
            self.bump();
            let mut digits = 0;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.bump();
                digits += 1;
            }
            if digits == 0 {
                return Err(Error::new("invalid JSON number"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            let mut digits = 0;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.bump();
                digits += 1;
            }
            if digits == 0 {
                return Err(Error::new("invalid JSON number"));
            }
        }
        let literal = std::str::from_utf8(&self.data[start..self.index])
            .map_err(|_| Error::new("invalid JSON number"))?;
        Ok(Json::Number(literal.to_owned()))
    }

    fn parse_string(&mut self) -> Result<String, Error> {
        if self.peek() != Some(b'"') {
            return Err(Error::new("expected JSON string"));
        }
        self.bump();
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(Error::new("unterminated JSON string")),
                Some(b'"') => {
                    self.bump();
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.bump();
                    let Some(escaped) = self.peek() else {
                        return Err(Error::new("unterminated JSON string"));
                    };
                    self.bump();
                    match escaped {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.read_unicode_escape()?),
                        _ => return Err(Error::new("invalid JSON string escape")),
                    }
                }
                Some(0x00..=0x1F) => return Err(Error::new("invalid JSON string")),
                Some(_) => out.push(self.next_char()?),
            }
        }
    }

    fn read_unicode_escape(&mut self) -> Result<char, Error> {
        let unit = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&unit) {
            if self.peek() != Some(b'\\') {
                return Err(Error::new("invalid JSON surrogate"));
            }
            self.bump();
            if self.peek() != Some(b'u') {
                return Err(Error::new("invalid JSON surrogate"));
            }
            self.bump();
            let low = self.read_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(Error::new("invalid JSON surrogate"));
            }
            let code = 0x10000 + (((unit - 0xD800) << 10) | (low - 0xDC00));
            return char::from_u32(code).ok_or_else(|| Error::new("invalid JSON surrogate"));
        }
        if (0xDC00..=0xDFFF).contains(&unit) {
            return Err(Error::new("invalid JSON surrogate"));
        }
        char::from_u32(unit).ok_or_else(|| Error::new("invalid JSON string"))
    }

    fn read_hex4(&mut self) -> Result<u32, Error> {
        let mut value = 0u32;
        for _ in 0..4 {
            let Some(byte) = self.peek() else {
                return Err(Error::new("invalid JSON string escape"));
            };
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                b'A'..=b'F' => u32::from(byte - b'A') + 10,
                _ => return Err(Error::new("invalid JSON string escape")),
            };
            self.bump();
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn next_char(&mut self) -> Result<char, Error> {
        let rest = std::str::from_utf8(&self.data[self.index..])
            .map_err(|_| Error::new("JSON must be valid UTF-8"))?;
        let ch = rest
            .chars()
            .next()
            .ok_or_else(|| Error::new("unterminated JSON string"))?;
        self.index += ch.len_utf8();
        Ok(ch)
    }

    fn parse_object(&mut self) -> Result<Json, Error> {
        self.enter()?;
        let mut members = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.bump();
            self.leave();
            return Ok(Json::Object(members));
        }
        loop {
            self.skip_ws();
            let name = self.parse_string()?;
            if members.iter().any(|(existing, _)| existing == &name) {
                return Err(Error::new(format!("duplicate member \"{name}\"")));
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(Error::new("expected ':' after object member name"));
            }
            self.bump();
            self.skip_ws();
            let value = self.parse_value()?;
            members.push((name, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b'}') => {
                    self.bump();
                    self.leave();
                    return Ok(Json::Object(members));
                }
                _ => return Err(Error::new("invalid JSON object")),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Json, Error> {
        self.enter()?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.bump();
            self.leave();
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b']') => {
                    self.bump();
                    self.leave();
                    return Ok(Json::Array(items));
                }
                _ => return Err(Error::new("invalid JSON array")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Json, json_equal, parse_json};

    fn parsed(text: &str) -> Json {
        parse_json(text.as_bytes()).expect("json")
    }

    #[test]
    fn numbers_match_without_floating_point() {
        let pairs = [
            ("1", "1.0", true),
            ("1.00", "1", true),
            ("2e0", "2", true),
            ("1e1000000", "10e999999", true),
            ("-0", "0e999999999999999999", true),
            ("0", "0.0", true),
            ("9007199254740992", "9007199254740993", false),
            ("1.0000000000000000000000000001", "1", false),
            ("1e1000000", "1e999999", false),
        ];
        for (left, right, matches) in pairs {
            assert_eq!(
                json_equal(&parsed(left), &parsed(right)),
                matches,
                "{left} vs {right}"
            );
        }
        assert!(json_equal(&parsed(r#""a""#), &parsed(r#""\u0061""#)));
        assert!(parse_json(br#"{"x":1,"\u0078":2}"#).is_err());
        assert!(parse_json(br#"{"a":1,"a":2}"#).is_err());
    }
}
