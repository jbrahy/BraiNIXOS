//! A small, total JSON reader.
//!
//! Three of the converter's four inputs are JSON — the safetensors header, the
//! model `config.json`, and the tokenizer's `vocab.json` — and the workspace
//! vendors its crates.io mirror, so pulling in a JSON crate means vendoring and
//! re-checksumming the tree for a host tool. This reader is deliberately
//! minimal: it parses the JSON grammar and nothing else, it never panics, and
//! object members keep their file order so a caller can iterate them.

use std::collections::BTreeMap;
use std::fmt;

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// Any JSON number, held as `f64`.
    Number(f64),
    /// A string, with every escape already resolved.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object. Members keep their file order.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// The member named `key`, if this is an object that has one.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Object(members) => members
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// This value as an `f64`, if it is a number.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(value) => Some(*value),
            _ => None,
        }
    }

    /// This value as a `usize`, if it is a non-negative integral number.
    pub fn as_usize(&self) -> Option<usize> {
        let value = self.as_f64()?;
        if value < 0.0 || value.fract() != 0.0 {
            return None;
        }
        Some(value as usize)
    }

    /// This value as a `bool`, if it is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// This value as a string slice, if it is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// This value as a slice of values, if it is an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    /// This value's members, if it is an object.
    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Self::Object(members) => Some(members),
            _ => None,
        }
    }

    /// The object's members as a map, for lookup-heavy callers.
    pub fn to_map(&self) -> Option<BTreeMap<&str, &Value>> {
        Some(
            self.as_object()?
                .iter()
                .map(|(name, value)| (name.as_str(), value))
                .collect(),
        )
    }
}

/// A parse failure, with the byte offset at which it was detected.
#[derive(Debug)]
pub struct ParseError {
    /// What went wrong.
    pub reason: &'static str,
    /// Byte offset into the input.
    pub offset: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at byte {}", self.reason, self.offset)
    }
}

impl std::error::Error for ParseError {}

/// Parses a complete JSON document.
pub fn parse(input: &[u8]) -> Result<Value, ParseError> {
    let mut parser = Parser {
        input,
        position: 0,
    };
    parser.skip_whitespace();
    let value = parser.value()?;
    parser.skip_whitespace();
    if parser.position != input.len() {
        return Err(parser.error("trailing bytes after document"));
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Parser<'a> {
    fn error(&self, reason: &'static str) -> ParseError {
        ParseError {
            reason,
            offset: self.position,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position += 1;
        Some(byte)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn expect(&mut self, byte: u8, reason: &'static str) -> Result<(), ParseError> {
        if self.peek() == Some(byte) {
            self.position += 1;
            Ok(())
        } else {
            Err(self.error(reason))
        }
    }

    fn literal(&mut self, text: &str) -> bool {
        let end = self.position + text.len();
        if self.input.get(self.position..end) == Some(text.as_bytes()) {
            self.position = end;
            true
        } else {
            false
        }
    }

    fn value(&mut self) -> Result<Value, ParseError> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') if self.literal("true") => Ok(Value::Bool(true)),
            Some(b'f') if self.literal("false") => Ok(Value::Bool(false)),
            Some(b'n') if self.literal("null") => Ok(Value::Null),
            Some(_) => self.number(),
            None => Err(self.error("unexpected end of input")),
        }
    }

    fn object(&mut self) -> Result<Value, ParseError> {
        self.expect(b'{', "expected '{'")?;
        let mut members = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.position += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_whitespace();
            let key = self.string()?;
            self.skip_whitespace();
            self.expect(b':', "expected ':' after member name")?;
            self.skip_whitespace();
            let value = self.value()?;
            members.push((key, value));
            self.skip_whitespace();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => return Ok(Value::Object(members)),
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self) -> Result<Value, ParseError> {
        self.expect(b'[', "expected '['")?;
        let mut values = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.position += 1;
            return Ok(Value::Array(values));
        }
        loop {
            self.skip_whitespace();
            values.push(self.value()?);
            self.skip_whitespace();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => return Ok(Value::Array(values)),
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"', "expected '\"'")?;
        let mut out = String::new();
        loop {
            let byte = self.bump().ok_or_else(|| self.error("unterminated string"))?;
            match byte {
                b'"' => return Ok(out),
                b'\\' => self.escape(&mut out)?,
                _ => {
                    // Copy the whole UTF-8 sequence this byte begins.
                    let width = utf8_width(byte);
                    let start = self.position - 1;
                    let end = start + width;
                    let raw = self
                        .input
                        .get(start..end)
                        .ok_or_else(|| self.error("truncated UTF-8 sequence"))?;
                    let text = std::str::from_utf8(raw)
                        .map_err(|_| self.error("invalid UTF-8 in string"))?;
                    out.push_str(text);
                    self.position = end;
                }
            }
        }
    }

    fn escape(&mut self, out: &mut String) -> Result<(), ParseError> {
        let byte = self.bump().ok_or_else(|| self.error("unterminated escape"))?;
        let resolved = match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{0008}',
            b'f' => '\u{000C}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.unicode_escape(out),
            _ => return Err(self.error("unrecognized escape")),
        };
        out.push(resolved);
        Ok(())
    }

    fn unicode_escape(&mut self, out: &mut String) -> Result<(), ParseError> {
        let first = self.hex4()?;
        let code = if (0xD800..0xDC00).contains(&first) {
            if !self.literal("\\u") {
                return Err(self.error("lone high surrogate"));
            }
            let second = self.hex4()?;
            if !(0xDC00..0xE000).contains(&second) {
                return Err(self.error("high surrogate not followed by a low one"));
            }
            0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
        } else {
            first
        };
        out.push(char::from_u32(code).ok_or_else(|| self.error("escape is not a scalar value"))?);
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let end = self.position + 4;
        let raw = self
            .input
            .get(self.position..end)
            .ok_or_else(|| self.error("truncated \\u escape"))?;
        let text = std::str::from_utf8(raw).map_err(|_| self.error("bad \\u escape"))?;
        let value = u32::from_str_radix(text, 16).map_err(|_| self.error("bad \\u escape"))?;
        self.position = end;
        Ok(value)
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        while matches!(
            self.peek(),
            Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
        ) {
            self.position += 1;
        }
        let raw = self
            .input
            .get(start..self.position)
            .ok_or_else(|| self.error("bad number"))?;
        let text = std::str::from_utf8(raw).map_err(|_| self.error("bad number"))?;
        let value: f64 = text.parse().map_err(|_| ParseError {
            reason: "bad number",
            offset: start,
        })?;
        Ok(Value::Number(value))
    }
}

fn utf8_width(lead: u8) -> usize {
    match lead {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_shapes_the_converter_reads() {
        let document =
            parse(r#"{"a":[1,2.5,-3e2],"b":{"c":true,"d":null},"e":"xé😀é😀"}"#.as_bytes())
                .expect("parse");
        assert_eq!(document.get("a").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(
            document.get("a").unwrap().as_array().unwrap()[2].as_f64(),
            Some(-300.0)
        );
        assert_eq!(
            document.get("b").unwrap().get("c").unwrap().as_bool(),
            Some(true)
        );
        assert_eq!(document.get("e").unwrap().as_str(), Some("xé😀é😀"));
    }

    #[test]
    fn member_order_is_preserved() {
        let document = parse(br#"{"z":1,"a":2}"#).expect("parse");
        let members = document.as_object().unwrap();
        assert_eq!(members[0].0, "z");
        assert_eq!(members[1].0, "a");
    }
}
