// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::io::Read;

use krsm::AsyncRuntimeError;

/// These could be waiting for literals or waiting for other basic BNF terms
///
/// The `usize` field of these reasons are used to store an index, asserting
/// where the literals/strings must show up in the parser input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum JsonParserYieldReason {
    LiteralArrayStart(usize),
    LiteralArrayEnd(usize),
    LiteralObjectStart(usize),
    LiteralObjectEnd(usize),
    LiteralStringStart(usize),
    LiteralStringEnd(usize),
    LiteralColon(usize),
    LiteralComma(usize),
    LiteralPeriod(usize),
    LiteralTrue(usize),
    LiteralFalse(usize),
    LiteralNull(usize),
    LiteralSlash(usize),
    LiteralHexEscapeChar(usize),
    RegexCharAnyExceptQuoteOrSlash(usize),
    RegexEscapedCharAfterSlash(usize),
    RegexCharExponent(usize),
    RegexCharInHex(usize),
    RegexCharInDigit(usize),
    RegexCharNumberSign(usize),
    RegexCharWhitespace(usize),
    // Note: empty string doesn't have a index here: Technically every index can have an empty string
    EmptyString,
}

type JsonParserYieldResponse = String;

type AsyncRuntime = krsm::AsyncRuntime<JsonParserYieldReason, JsonParserYieldResponse>;

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum Json {
    Object(HashMap<String, Json>),
    Array(Vec<Json>),
    Number(String),
    String(String),
    Boolean(bool),
    Null,
}

/// This is a state machine that is written in the exact same way as a BNF grammar.
///
/// The following rules must be followed when wrting async code:
///
/// * List the futures `futures_lite::future::or` in the exact order of shortcircuit
/// * Make sure every future in `futures_lite::future::or` has at least one `await`
/// * Use EmptyString as an escape hatch when there is nothing to await on
struct JsonParser<'a> {
    runtime: &'a AsyncRuntime,

    // The current offset of the char to read upon next yield
    offset: RefCell<usize>,
}

type JResult<T> = Result<T, krsm::AsyncRuntimeError>;

impl<'a> JsonParser<'a> {
    fn new(runtime: &'a AsyncRuntime) -> Self {
        Self {
            runtime,
            offset: RefCell::new(0),
        }
    }

    async fn parse(&self) -> JResult<Json> {
        self.parse_element().await
    }

    /// <value> ::= <object> | <array> | <string> | <number> | <boolean> | <null>
    async fn parse_value(&self) -> JResult<Json> {
        futures_lite::future::or(
            futures_lite::future::or(
                self.parse_object(),
                futures_lite::future::or(self.parse_array(), self.parse_string_value()),
            ),
            futures_lite::future::or(
                self.parse_number(),
                futures_lite::future::or(self.parse_boolean(), self.parse_null()),
            ),
        )
        .await
    }

    /// <object> ::= "{" <whitespaces> "}" | "{" <members> "}"
    async fn parse_object(&self) -> JResult<Json> {
        let curr_offset = *self.offset.borrow();
        self.runtime
            .new_pending_future(JsonParserYieldReason::LiteralObjectStart(curr_offset))
            .await?;
        let result = futures_lite::future::or(
            async { Ok(Json::Object(Box::pin(self.parse_members()).await?)) },
            async {
                self.parse_whitespaces().await?;
                Ok(Json::Object(HashMap::default()))
            },
        )
        .await?;

        let curr_offset2 = *self.offset.borrow();
        self.runtime
            .new_pending_future(JsonParserYieldReason::LiteralObjectEnd(curr_offset2))
            .await?;
        Ok(result)
    }

    /// <members> ::= <member> | <member> "," <members>
    async fn parse_members(&self) -> JResult<HashMap<String, Json>> {
        let (key, value) = self.parse_member().await?;
        let mut map = futures_lite::future::or(
            async {
                let curr_offset = *self.offset.borrow();
                self.runtime
                    .new_pending_future(JsonParserYieldReason::LiteralComma(curr_offset))
                    .await?;
                Box::pin(self.parse_members()).await
            },
            async {
                self.runtime
                    .new_pending_future(JsonParserYieldReason::EmptyString)
                    .await?;
                Ok(HashMap::new())
            },
        )
        .await?;
        map.insert(key, value);
        Ok(map)
    }

    /// <member> ::= <whitespaces> <string> <whitespaces> ":" <value>
    async fn parse_member(&self) -> JResult<(String, Json)> {
        self.parse_whitespaces().await?;
        let key = self.parse_string().await?;
        self.parse_whitespaces().await?;
        let curr_offset = *self.offset.borrow();
        self.runtime
            .new_pending_future(JsonParserYieldReason::LiteralColon(curr_offset))
            .await?;
        let value = self.parse_element().await?;
        Ok((key, value))
    }

    /// <array> ::= "[" <whitespaces> "]" | "[" <elements> "]"
    async fn parse_array(&self) -> JResult<Json> {
        let curr_offset = *self.offset.borrow();
        self.runtime
            .new_pending_future(JsonParserYieldReason::LiteralArrayStart(curr_offset))
            .await?;
        let result = futures_lite::future::or(
            async { Ok(Json::Array(self.parse_elements().await?)) },
            async {
                self.parse_whitespaces().await?;
                Ok(Json::Array(Vec::default()))
            },
        )
        .await?;

        let curr_offset2 = *self.offset.borrow();
        self.runtime
            .new_pending_future(JsonParserYieldReason::LiteralArrayEnd(curr_offset2))
            .await?;
        Ok(result)
    }

    /// wrapper of parse_elements_reversed
    async fn parse_elements(&self) -> JResult<Vec<Json>> {
        let mut list = self.parse_elements_reversed().await?;
        list.reverse();
        Ok(list)
    }

    /// <elements> ::= <element> | <element> "," <elements>
    async fn parse_elements_reversed(&self) -> JResult<Vec<Json>> {
        let item = self.parse_element().await?;
        let mut list = futures_lite::future::or(
            async {
                let curr_offset = *self.offset.borrow();
                self.runtime
                    .new_pending_future(JsonParserYieldReason::LiteralComma(curr_offset))
                    .await?;
                Box::pin(self.parse_elements_reversed()).await
            },
            async {
                self.runtime
                    .new_pending_future(JsonParserYieldReason::EmptyString)
                    .await?;
                Ok(vec![])
            },
        )
        .await?;
        list.push(item);
        Ok(list)
    }

    /// <element> ::= <whitespaces> <value> <whitespaces>
    async fn parse_element(&self) -> JResult<Json> {
        self.parse_whitespaces().await?;
        let value = Box::pin(self.parse_value()).await?;
        self.parse_whitespaces().await?;
        Ok(value)
    }

    /// Wrapper of parse_string (different return type)
    async fn parse_string_value(&self) -> JResult<Json> {
        Ok(Json::String(self.parse_string().await?))
    }

    /// <string> ::= '"' <characters> '"'
    async fn parse_string(&self) -> JResult<String> {
        let curr_offset = *self.offset.borrow();
        self.runtime
            .new_pending_future(JsonParserYieldReason::LiteralStringStart(curr_offset))
            .await?;

        let mut reversed = self.parse_characters_reversed().await?;
        reversed.reverse();
        let result = reversed.into_iter().collect::<String>();

        let curr_offset2 = *self.offset.borrow();
        self.runtime
            .new_pending_future(JsonParserYieldReason::LiteralStringEnd(curr_offset2))
            .await?;
        Ok(result)
    }

    /// <characters> ::= "" | <character> | <character> <characters>
    async fn parse_characters_reversed(&self) -> JResult<Vec<char>> {
        futures_lite::future::or(
            async {
                let char = self.parse_character().await?;
                let mut list = Box::pin(self.parse_characters_reversed()).await?;
                list.push(char);
                Ok(list)
            },
            async {
                self.runtime
                    .new_pending_future(JsonParserYieldReason::EmptyString)
                    .await?;
                Ok(vec![])
            },
        )
        .await
    }

    /// helper function to convert a string to a character
    fn str_to_char(&self, str: &str) -> char {
        str.chars().next().unwrap()
    }

    /// <character> ::= <regex_char_any_except_quote_or_slash> | <literal_slash> <regex_escaped_char_after_slash> | <literal_slash> "u" <hex> <hex> <hex> <hex>
    async fn parse_character(&self) -> JResult<char> {
        let curr_offset = *self.offset.borrow();
        futures_lite::future::or(
            async {
                let str = self
                    .runtime
                    .new_pending_future(JsonParserYieldReason::RegexCharAnyExceptQuoteOrSlash(
                        curr_offset,
                    ))
                    .await?;
                Ok(self.str_to_char(&str))
            },
            futures_lite::future::or(
                async {
                    self.runtime
                        .new_pending_future(JsonParserYieldReason::LiteralSlash(curr_offset))
                        .await?;
                    let str = self
                        .runtime
                        .new_pending_future(JsonParserYieldReason::RegexEscapedCharAfterSlash(
                            curr_offset + 1,
                        ))
                        .await?;
                    let result_str = match str.as_str() {
                        "b" => "\x08".to_string(),
                        "f" => "\x0c".to_string(),
                        "n" => "\n".to_string(),
                        "r" => "\r".to_string(),
                        "t" => "t".to_string(),
                        _ => str,
                    };
                    Ok(self.str_to_char(&result_str))
                },
                async {
                    self.runtime
                        .new_pending_future(JsonParserYieldReason::LiteralSlash(curr_offset))
                        .await?;
                    self.runtime
                        .new_pending_future(JsonParserYieldReason::LiteralHexEscapeChar(
                            curr_offset + 1,
                        ))
                        .await?;
                    let hex1 = self
                        .runtime
                        .new_pending_future(JsonParserYieldReason::RegexCharInHex(curr_offset + 2))
                        .await?;
                    let hex2 = self
                        .runtime
                        .new_pending_future(JsonParserYieldReason::RegexCharInHex(curr_offset + 3))
                        .await?;
                    let hex3 = self
                        .runtime
                        .new_pending_future(JsonParserYieldReason::RegexCharInHex(curr_offset + 4))
                        .await?;
                    let hex4 = self
                        .runtime
                        .new_pending_future(JsonParserYieldReason::RegexCharInHex(curr_offset + 5))
                        .await?;
                    let hex_str = format!("0x{}{}{}{}", hex1, hex2, hex3, hex4);
                    let hex_val = u32::from_str_radix(&hex_str, 16).unwrap();
                    Ok(char::from_u32(hex_val).unwrap())
                },
            ),
        )
        .await
    }

    /// <number> ::= <integer> <fraction> <exponent>
    async fn parse_number(&self) -> JResult<Json> {
        let integer = self.parse_integer().await?;
        let fraction = self.parse_fraction().await?;
        let exponent = self.parse_exponent().await?;
        Ok(Json::Number(format!("{}{}{}", integer, fraction, exponent)))
    }

    /// <integer> ::= <sign> <digits> | <digits>
    async fn parse_integer(&self) -> JResult<String> {
        let curr_offset = *self.offset.borrow();
        let sign = futures_lite::future::or(
            self.runtime
                .new_pending_future(JsonParserYieldReason::RegexCharNumberSign(curr_offset)),
            self.runtime
                .new_pending_future(JsonParserYieldReason::EmptyString),
        )
        .await?;
        let digits = self.parse_digits().await?;
        Ok(format!("{}{}", sign, digits))
    }

    /// <digits> ::= <digit> | <digit> <digits>
    async fn parse_digits(&self) -> JResult<String> {
        let curr_offset = *self.offset.borrow();
        let digit = self
            .runtime
            .new_pending_future(JsonParserYieldReason::RegexCharInDigit(curr_offset))
            .await?;
        futures_lite::future::or(
            async {
                let digits = Box::pin(self.parse_digits()).await?;
                let result = format!("{}{}", digit, digits);
                Ok(result)
            },
            async {
                self.runtime
                    .new_pending_future(JsonParserYieldReason::EmptyString)
                    .await?;
                Ok(digit.clone())
            },
        )
        .await
    }

    /// <fraction> ::= "." <digits> | ""
    async fn parse_fraction(&self) -> JResult<String> {
        let curr_offset = *self.offset.borrow();
        futures_lite::future::or(
            async {
                self.runtime
                    .new_pending_future(JsonParserYieldReason::LiteralPeriod(curr_offset))
                    .await?;
                let digits = self.parse_digits().await?;
                Ok(format!("{}{}", ".", digits))
            },
            async {
                self.runtime
                    .new_pending_future(JsonParserYieldReason::EmptyString)
                    .await
            },
        )
        .await
    }

    /// <exponent> ::= "e" <digits> | "E" <digits> | ""
    async fn parse_exponent(&self) -> JResult<String> {
        let curr_offset = *self.offset.borrow();
        futures_lite::future::or(
            async {
                let exp = self
                    .runtime
                    .new_pending_future(JsonParserYieldReason::RegexCharExponent(curr_offset))
                    .await?;
                let digits = self.parse_digits().await?;
                Ok(format!("{}{}", exp, digits))
            },
            async {
                self.runtime
                    .new_pending_future(JsonParserYieldReason::EmptyString)
                    .await
            },
        )
        .await
    }

    /// <whitespaces> ::= "" | <regex_char_whitespace> <whitespaces>
    async fn parse_whitespaces(&self) -> JResult<()> {
        let curr_offset = *self.offset.borrow();
        futures_lite::future::or(
            async {
                self.runtime
                    .new_pending_future(JsonParserYieldReason::RegexCharWhitespace(curr_offset))
                    .await?;
                Box::pin(self.parse_whitespaces()).await?;
                Ok::<(), AsyncRuntimeError>(())
            },
            async {
                self.runtime
                    .new_pending_future(JsonParserYieldReason::EmptyString)
                    .await?;
                Ok::<(), AsyncRuntimeError>(())
            },
        )
        .await
    }

    /// <boolean> ::= "true" | "false"
    async fn parse_boolean(&self) -> JResult<Json> {
        let curr_offset = *self.offset.borrow();
        futures_lite::future::or(
            async {
                self.runtime
                    .new_pending_future(JsonParserYieldReason::LiteralTrue(curr_offset))
                    .await?;
                Ok(Json::Boolean(true))
            },
            async {
                self.runtime
                    .new_pending_future(JsonParserYieldReason::LiteralFalse(curr_offset))
                    .await?;
                Ok(Json::Boolean(false))
            },
        )
        .await
    }

    /// <null> ::= "null"
    async fn parse_null(&self) -> JResult<Json> {
        let curr_offset = *self.offset.borrow();
        self.runtime
            .new_pending_future(JsonParserYieldReason::LiteralNull(curr_offset))
            .await?;
        Ok(Json::Null)
    }
}

fn run_parser<T, Fut>(full_str: &str, parser: &JsonParser, mut future: Fut) -> Result<T, String>
where
    T: Debug,
    Fut: Future<Output = JResult<T>>,
{
    let mut index = 0;
    let runtime = parser.runtime;
    loop {
        parser.offset.replace(index);
        let result = unsafe { runtime.run_async_step(&mut future) }.unwrap();
        if let Some(result) = result {
            return Ok(result.map_err(|e| format!("Internal error: {:?}", e))?);
        }

        // Async step yielded. Handle the yield reason by checking the type of the next character.
        // And, if there is no more input, return an error.
        if index >= full_str.len() {
            loop {
                let unblock_reason = runtime
                    .check_pending_reasons(|reason| match reason {
                        Some(JsonParserYieldReason::EmptyString) => true,
                        _ => false,
                    })
                    .map_err(|e| format!("Internal error: {:?}", e))?;
                if unblock_reason.is_none() {
                    break;
                } else {
                    println!("Debug, unblocking EmptyString (exit loop)");
                    runtime
                        .unblock_futures(JsonParserYieldReason::EmptyString, "".to_string())
                        .map_err(|e| format!("Internal error: {:?}", e))?;
                    let result = unsafe { runtime.run_async_step(&mut future).unwrap() };
                    println!("EXITLOOP {:?}", &result);
                    if let Some(result) = result {
                        return Ok(result.map_err(|e| format!("Internal error: {:?}", e))?);
                    }
                }
            }
            return Err("Unexpected end of input".to_string());
        }

        let single_char = &full_str[index..index + 1];

        // Decide which future to unblock, with different priorities (normal > lowpri)
        let unblock_reason_normal = runtime
            .check_pending_reasons(|reason| match reason {
                Some(JsonParserYieldReason::LiteralArrayStart(j)) => {
                    single_char == "[" && index == j
                }
                Some(JsonParserYieldReason::LiteralArrayEnd(j)) => single_char == "]" && index == j,
                Some(JsonParserYieldReason::LiteralObjectStart(j)) => {
                    single_char == "{" && index == j
                }
                Some(JsonParserYieldReason::LiteralObjectEnd(j)) => {
                    single_char == "}" && index == j
                }
                Some(JsonParserYieldReason::LiteralStringStart(j)) => {
                    &full_str[index..index + 1] == "\"" && index == j
                }
                Some(JsonParserYieldReason::LiteralStringEnd(j)) => {
                    single_char == "\"" && index == j
                }
                Some(JsonParserYieldReason::LiteralColon(j)) => single_char == ":" && index == j,
                Some(JsonParserYieldReason::LiteralComma(j)) => single_char == "," && index == j,
                Some(JsonParserYieldReason::LiteralPeriod(j)) => single_char == "." && index == j,
                Some(JsonParserYieldReason::LiteralTrue(j)) => {
                    full_str[index..].starts_with("true") && index == j
                }
                Some(JsonParserYieldReason::LiteralFalse(j)) => {
                    full_str[index..].starts_with("false") && index == j
                }
                Some(JsonParserYieldReason::LiteralNull(j)) => {
                    full_str[index..].starts_with("null") && index == j
                }
                Some(JsonParserYieldReason::LiteralSlash(j)) => single_char == "\\" && index == j,
                Some(JsonParserYieldReason::LiteralHexEscapeChar(j)) => {
                    single_char == "u" && index == j
                }
                Some(JsonParserYieldReason::RegexCharAnyExceptQuoteOrSlash(j)) => {
                    single_char != "\"" && single_char != "\\" && index == j
                }
                Some(JsonParserYieldReason::RegexEscapedCharAfterSlash(j)) => {
                    "\"\\/bfnrt".contains(single_char) && index == j
                }
                Some(JsonParserYieldReason::RegexCharExponent(j)) => {
                    (single_char == "e" || single_char == "E") && index == j
                }
                Some(JsonParserYieldReason::RegexCharInHex(j)) => {
                    "0123456789abcdefABCDEF".contains(single_char) && index == j
                }
                Some(JsonParserYieldReason::RegexCharInDigit(j)) => {
                    "0123456789".contains(single_char) && index == j
                }
                Some(JsonParserYieldReason::RegexCharNumberSign(j)) => {
                    "+-".contains(single_char) && index == j
                }
                Some(JsonParserYieldReason::RegexCharWhitespace(j)) => {
                    " \t\n\r".contains(single_char) && index == j
                }
                _ => false,
            })
            .map_err(|e| format!("Internal error: {:?}", e))?;
        let unblock_reason_lowpri = runtime
            .check_pending_reasons(|reason| match reason {
                Some(JsonParserYieldReason::EmptyString) => true,
                _ => false,
            })
            .map_err(|e| format!("Internal error: {:?}", e))?;
        let unblock_reason = unblock_reason_normal.or(unblock_reason_lowpri);

        let Some(unblock_reason) = unblock_reason else {
            return Err(format!("Unexpected character: {}", single_char));
        };

        let mut response = "".to_string();
        if unblock_reason == JsonParserYieldReason::LiteralTrue(index) {
            response = "true".to_string();
            index += 4;
        } else if unblock_reason == JsonParserYieldReason::LiteralFalse(index) {
            response = "false".to_string();
            index += 5;
        } else if unblock_reason == JsonParserYieldReason::LiteralNull(index) {
            response = "null".to_string();
            index += 4;
        } else if unblock_reason != JsonParserYieldReason::EmptyString {
            response = single_char.to_string();
            index += 1;
        }

        // Note: This is technically wrong for LiteralTrue, LiteralFalse, LiteralNull. But it's enough for this example.
        println!("Debug, unblocking {:?}, str {}", unblock_reason, response);
        runtime
            .unblock_futures(unblock_reason, response)
            .map_err(|e| format!("Internal error: {:?}", e))?;
    }
}

fn main() -> std::io::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let runtime = AsyncRuntime::new().unwrap();
    let parser = JsonParser::new(&runtime);
    let future = parser.parse();
    let result = run_parser(&input, &parser, future).unwrap();
    println!("Parsed result: {:?}", result);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_number_parsing() {
        let runtime = AsyncRuntime::new().unwrap();
        let parser = JsonParser::new(&runtime);
        let future = parser.parse_digits();
        let result = run_parser("123", &parser, future).unwrap();
        assert_eq!(result, "123");
    }

    #[test]
    fn test_string_parsing() {
        let runtime = AsyncRuntime::new().unwrap();
        let parser = JsonParser::new(&runtime);
        let future = parser.parse_string();
        let result = run_parser("\"ab\\nc\"", &parser, future).unwrap();
        assert_eq!(result, "ab\nc");
    }

    #[test]
    fn test_string_parsing_confused_with_number() {
        // this test case might fail with parser returning String("123.") instead.
        let runtime = AsyncRuntime::new().unwrap();
        let parser = JsonParser::new(&runtime);
        let future = parser.parse();
        let result = run_parser("\"123.+917\"", &parser, future).unwrap();
        assert_eq!(result, Json::String("123.+917".to_string()));
    }

    #[test]
    fn test_fraction_parsing() {
        let runtime = AsyncRuntime::new().unwrap();
        let parser = JsonParser::new(&runtime);
        let future = parser.parse();
        let result = run_parser("-123.917", &parser, future).unwrap();
        assert_eq!(result, Json::Number("-123.917".to_string()));
    }

    #[test]
    fn test_member_parsing() {
        let runtime = AsyncRuntime::new().unwrap();
        let parser = JsonParser::new(&runtime);
        let future = parser.parse_member();
        let result = run_parser("  \"ab\\nc\":\"d ef\" ", &parser, future).unwrap();
        assert_eq!(
            result,
            ("ab\nc".to_string(), Json::String("d ef".to_string()))
        );
    }

    #[test]
    fn test_object_parsing() {
        let runtime = AsyncRuntime::new().unwrap();
        let parser = JsonParser::new(&runtime);

        let future = parser.parse_object();
        let result = run_parser("{\"name\":\"John\",\"age\":30}", &parser, future).unwrap();
        assert_eq!(
            result,
            Json::Object(HashMap::from([
                ("name".to_string(), Json::String("John".to_string())),
                ("age".to_string(), Json::Number("30".to_string()))
            ]))
        );
    }

    #[test]
    fn test_array_parsing() {
        let runtime = AsyncRuntime::new().unwrap();
        let parser = JsonParser::new(&runtime);

        let future = parser.parse();
        let result = run_parser(" [12  , 3   ] ", &parser, future).unwrap();
        assert_eq!(
            result,
            Json::Array(vec![
                Json::Number("12".to_string()),
                Json::Number("3".to_string())
            ])
        );
    }
}
