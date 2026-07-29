//! Gatus-compatible condition DSL parser and executor.
//!
//! Parses condition strings like `[STATUS] == 200`, `[BODY].path == "value"`,
//! `len([BODY].items) > 0`, `has([BODY].data)`, `pat([STATUS], 2*)`,
//! `any([STATUS], 200, 201)` into an AST and evaluates them against check results.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A parsed condition that can be evaluated against a check result.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DslCondition {
    /// Original condition string.
    pub raw: String,
    /// Parsed condition tree.
    pub expr: ConditionExpr,
}

/// Condition expression AST.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConditionExpr {
    /// `left CMP right` where CMP is ==, !=, <, >, <=, >=
    Compare { left: ValueRef, cmp: Comparator, right: ValueRef },
    /// `len(ref) CMP number`
    Length { of: ValueRef, cmp: Comparator, value: u64 },
    /// `has(ref)` — true if the value exists
    Has { of: ValueRef },
    /// `pat(ref, pattern)` — glob pattern match
    Pattern { of: ValueRef, pattern: String },
    /// `any(ref, v1, v2, ...)` — value matches any of the given values
    AnyOf { of: ValueRef, values: Vec<String> },
}

/// Comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Comparator {
    Equal,
    NotEqual,
    LessThan,
    GreaterThan,
    LessOrEqual,
    GreaterOrEqual,
}

/// A reference to a value from the check result.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "path", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ValueRef {
    /// HTTP status code: `[STATUS]`
    Status,
    /// Response time in ms: `[RESPONSE_TIME]`
    ResponseTime,
    /// Response body (full or JSON path): `[BODY]` or `[BODY].path.sub`
    Body(Option<String>),
    /// DNS RCODE: `[DNS_RCODE]`
    DnsRcode,
    /// Whether connection succeeded: `[CONNECTED]`
    Connected,
    /// Certificate expiration in ms: `[CERTIFICATE_EXPIRATION]`
    CertExpiration,
    /// IP address: `[IP]`
    Ip,
    /// A literal string/number value
    Literal(String),
}

/// Errors during condition parsing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConditionParseError {
    #[error("empty condition string")]
    Empty,
    #[error("unrecognized placeholder: {0}")]
    UnknownPlaceholder(String),
    #[error("unbalanced brackets in: {0}")]
    UnbalancedBrackets(String),
    #[error("invalid condition syntax: {0}")]
    InvalidSyntax(String),
}

impl DslCondition {
    /// Parse a condition string into a `DslCondition`.
    pub fn parse(raw: &str) -> Result<Self, ConditionParseError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(ConditionParseError::Empty);
        }
        let expr = parse_expr(raw)?;
        Ok(Self { raw: raw.to_string(), expr })
    }
}

fn parse_expr(input: &str) -> Result<ConditionExpr, ConditionParseError> {
    let input = input.trim();

    // Check for `has(ref)`
    if let Some(inner) = strip_func_call(input, "has") {
        let of = parse_value_ref(inner.trim())?;
        return Ok(ConditionExpr::Has { of });
    }

    // Check for `len(ref) CMP number`
    if let Some((func_arg, rest)) = strip_func_prefix(input, "len") {
        let of = parse_value_ref(func_arg.trim())?;
        let (cmp, num_str) = parse_comparator_and_number(rest.trim())?;
        let value: u64 = num_str.parse().map_err(|_| {
            ConditionParseError::InvalidSyntax(format!("expected number, got '{num_str}'"))
        })?;
        return Ok(ConditionExpr::Length { of, cmp, value });
    }

    // Check for `pat(ref, pattern)`
    if let Some((arg1, arg2)) = strip_two_arg_func(input, "pat") {
        let of = parse_value_ref(arg1.trim())?;
        let pattern = arg2.trim().trim_matches('"').to_string();
        return Ok(ConditionExpr::Pattern { of, pattern });
    }

    // Check for `any(ref, v1, v2, ...)`
    if let Some(args_str) = strip_func_call(input, "any") {
        let parts: Vec<&str> = args_str.split(',').map(str::trim).collect();
        if parts.len() < 2 {
            return Err(ConditionParseError::InvalidSyntax("any() needs at least 2 args".into()));
        }
        let of = parse_value_ref(parts[0])?;
        let values: Vec<String> =
            parts[1..].iter().map(|s| s.trim_matches('"').to_string()).collect();
        return Ok(ConditionExpr::AnyOf { of, values });
    }

    // Check for `ref CMP value` comparison
    let (left_str, cmp, right_str) = split_comparison(input)?;
    let left = parse_value_ref(left_str.trim())?;
    let right = parse_value_ref(right_str.trim())?;
    Ok(ConditionExpr::Compare { left, cmp, right })
}

fn parse_value_ref(s: &str) -> Result<ValueRef, ConditionParseError> {
    let s = s.trim().trim_matches('"');

    if s == "[STATUS]" {
        return Ok(ValueRef::Status);
    }
    if s == "[RESPONSE_TIME]" {
        return Ok(ValueRef::ResponseTime);
    }
    if s == "[DNS_RCODE]" {
        return Ok(ValueRef::DnsRcode);
    }
    if s == "[CONNECTED]" {
        return Ok(ValueRef::Connected);
    }
    if s == "[CERTIFICATE_EXPIRATION]" {
        return Ok(ValueRef::CertExpiration);
    }
    if s == "[IP]" {
        return Ok(ValueRef::Ip);
    }
    if s == "[BODY]" {
        return Ok(ValueRef::Body(None));
    }
    if let Some(rest) = s.strip_prefix("[BODY]") {
        let path = rest.trim_start_matches('.');
        if path.is_empty() {
            return Ok(ValueRef::Body(None));
        }
        return Ok(ValueRef::Body(Some(path.to_string())));
    }
    // Literal value
    Ok(ValueRef::Literal(s.to_string()))
}

fn split_comparison(input: &str) -> Result<(&str, Comparator, &str), ConditionParseError> {
    for (op_str, op) in [
        ("==", Comparator::Equal),
        ("!=", Comparator::NotEqual),
        ("<=", Comparator::LessOrEqual),
        (">=", Comparator::GreaterOrEqual),
        ("<", Comparator::LessThan),
        (">", Comparator::GreaterThan),
    ] {
        if let Some(pos) = input.find(op_str) {
            let left = &input[..pos];
            let right = &input[pos + op_str.len()..];
            if op_str == "<" && right.starts_with('=') {
                continue;
            }
            if op_str == ">" && right.starts_with('=') {
                continue;
            }
            return Ok((left, op, right));
        }
    }
    Err(ConditionParseError::InvalidSyntax(format!("no comparison operator found in: {input}")))
}

fn parse_comparator_and_number(input: &str) -> Result<(Comparator, &str), ConditionParseError> {
    let input = input.trim();
    for (op_str, op) in [
        ("==", Comparator::Equal),
        ("!=", Comparator::NotEqual),
        ("<=", Comparator::LessOrEqual),
        (">=", Comparator::GreaterOrEqual),
        ("<", Comparator::LessThan),
        (">", Comparator::GreaterThan),
    ] {
        if let Some(rest) = input.strip_prefix(op_str) {
            return Ok((op, rest.trim()));
        }
    }
    Err(ConditionParseError::InvalidSyntax(format!("expected comparator, got: {input}")))
}

fn strip_func_call(input: &str, func_name: &str) -> Option<String> {
    let prefix = format!("{func_name}(");
    (input.starts_with(&prefix) && input.ends_with(')'))
        .then(|| input[prefix.len()..input.len() - 1].to_string())
}

fn strip_func_prefix<'a>(input: &'a str, func_name: &str) -> Option<(&'a str, &'a str)> {
    let prefix = format!("{func_name}(");
    let rest = input.strip_prefix(&prefix)?;
    let paren_pos = rest.find(')')?;
    Some((&rest[..paren_pos], &rest[paren_pos + 1..]))
}

fn strip_two_arg_func<'a>(input: &'a str, func_name: &str) -> Option<(&'a str, &'a str)> {
    let prefix = format!("{func_name}(");
    let rest = input.strip_prefix(&prefix)?;
    let rest = rest.strip_suffix(')')?;
    let comma_pos = rest.find(',')?;
    Some((rest[..comma_pos].trim(), rest[comma_pos + 1..].trim()))
}

/// Evaluate a parsed condition against check result data.
#[derive(Debug)]
pub struct ConditionContext {
    pub status: Option<u16>,
    pub response_time_ms: Option<u64>,
    pub body: Option<serde_json::Value>,
    pub dns_rcode: Option<String>,
    pub connected: Option<bool>,
    pub cert_expiration_ms: Option<u64>,
    pub ip: Option<String>,
}

impl ConditionExpr {
    /// Evaluate this condition against the given context.
    pub fn evaluate(&self, ctx: &ConditionContext) -> bool {
        match self {
            Self::Compare { left, cmp, right } => {
                let lv = resolve_value(left, ctx);
                let rv = resolve_value(right, ctx);
                compare_values(lv.as_deref(), rv.as_deref(), *cmp)
            }
            Self::Length { of, cmp, value } => {
                let v = resolve_value(of, ctx);
                let len = v.map_or(0, |s| s.len() as u64);
                compare_numbers(len, *cmp, *value)
            }
            Self::Has { of } => resolve_value(of, ctx).is_some(),
            Self::Pattern { of, pattern } => {
                let v = resolve_value(of, ctx).unwrap_or_default();
                glob_match(pattern, &v)
            }
            Self::AnyOf { of, values } => {
                let v = resolve_value(of, ctx).unwrap_or_default();
                values.contains(&v)
            }
        }
    }
}

fn resolve_value(v: &ValueRef, ctx: &ConditionContext) -> Option<String> {
    match v {
        ValueRef::Status => ctx.status.map(|s| s.to_string()),
        ValueRef::ResponseTime => ctx.response_time_ms.map(|t| t.to_string()),
        ValueRef::Body(path) => {
            let body = ctx.body.as_ref()?;
            match path {
                None => Some(body.to_string()),
                Some(p) => resolve_json_path_str(body, p),
            }
        }
        ValueRef::DnsRcode => ctx.dns_rcode.clone(),
        ValueRef::Connected => ctx.connected.map(|c| c.to_string()),
        ValueRef::CertExpiration => ctx.cert_expiration_ms.map(|t| t.to_string()),
        ValueRef::Ip => ctx.ip.clone(),
        ValueRef::Literal(s) => Some(s.clone()),
    }
}

fn resolve_json_path_str(val: &serde_json::Value, path: &str) -> Option<String> {
    if let Some(inner) = path.strip_prefix("len(").and_then(|s| s.strip_suffix(')')) {
        let arr = resolve_json_path(val, inner)?;
        return arr.as_array().map(|a| a.len().to_string());
    }
    let v = resolve_json_path(val, path)?;
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => None,
        _ => Some(v.to_string()),
    }
}

fn resolve_json_path<'a>(val: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = val;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

fn compare_values(left: Option<&str>, right: Option<&str>, op: Comparator) -> bool {
    match (left, right) {
        (None, None) => matches!(op, Comparator::Equal),
        (None, Some(_)) | (Some(_), None) => matches!(op, Comparator::NotEqual),
        (Some(l), Some(r)) => {
            if let (Ok(ln), Ok(rn)) = (l.parse::<f64>(), r.parse::<f64>()) {
                return compare_numbers_f64(ln, op, rn);
            }
            match op {
                Comparator::Equal => l == r || glob_match(r, l),
                Comparator::NotEqual => l != r,
                Comparator::LessThan => l < r,
                Comparator::GreaterThan => l > r,
                Comparator::LessOrEqual => l <= r,
                Comparator::GreaterOrEqual => l >= r,
            }
        }
    }
}

#[expect(clippy::missing_const_for_fn)]
fn compare_numbers(left: u64, op: Comparator, right: u64) -> bool {
    match op {
        Comparator::Equal => left == right,
        Comparator::NotEqual => left != right,
        Comparator::LessThan => left < right,
        Comparator::GreaterThan => left > right,
        Comparator::LessOrEqual => left <= right,
        Comparator::GreaterOrEqual => left >= right,
    }
}

fn compare_numbers_f64(left: f64, op: Comparator, right: f64) -> bool {
    match op {
        Comparator::Equal => (left - right).abs() < f64::EPSILON,
        Comparator::NotEqual => (left - right).abs() >= f64::EPSILON,
        Comparator::LessThan => left < right,
        Comparator::GreaterThan => left > right,
        Comparator::LessOrEqual => left <= right,
        Comparator::GreaterOrEqual => left >= right,
    }
}

/// ponytail: glob matching with `*` wildcard, no external dep.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    glob_match_bytes(p, t)
}

fn glob_match_bytes(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_equal() {
        let c = DslCondition::parse("[STATUS] == 200").unwrap();
        assert!(matches!(c.expr, ConditionExpr::Compare { .. }));
    }

    #[test]
    fn parse_response_time() {
        let c = DslCondition::parse("[RESPONSE_TIME] < 500").unwrap();
        assert!(matches!(c.expr, ConditionExpr::Compare { .. }));
    }

    #[test]
    fn parse_body_path() {
        let c = DslCondition::parse(r#"[BODY].status == "healthy""#).unwrap();
        assert!(matches!(c.expr, ConditionExpr::Compare { .. }));
    }

    #[test]
    fn parse_len() {
        let c = DslCondition::parse("len([BODY].items) > 0").unwrap();
        assert!(matches!(c.expr, ConditionExpr::Length { .. }));
    }

    #[test]
    fn parse_has() {
        let c = DslCondition::parse("has([BODY].data)").unwrap();
        assert!(matches!(c.expr, ConditionExpr::Has { .. }));
    }

    #[test]
    fn parse_pat() {
        let c = DslCondition::parse(r#"pat([STATUS], "2*")"#).unwrap();
        assert!(matches!(c.expr, ConditionExpr::Pattern { .. }));
    }

    #[test]
    fn parse_any() {
        let c = DslCondition::parse(r"any([STATUS], 200, 201, 204)").unwrap();
        assert!(matches!(c.expr, ConditionExpr::AnyOf { .. }));
    }

    #[test]
    fn eval_status_equal() {
        let c = DslCondition::parse("[STATUS] == 200").unwrap();
        let ctx = ConditionContext {
            status: Some(200),
            response_time_ms: None,
            body: None,
            dns_rcode: None,
            connected: None,
            cert_expiration_ms: None,
            ip: None,
        };
        assert!(c.expr.evaluate(&ctx));
    }

    #[test]
    fn eval_body_path() {
        let c = DslCondition::parse(r#"[BODY].status == "healthy""#).unwrap();
        let ctx = ConditionContext {
            status: Some(200),
            response_time_ms: None,
            body: Some(serde_json::json!({"status": "healthy"})),
            dns_rcode: None,
            connected: None,
            cert_expiration_ms: None,
            ip: None,
        };
        assert!(c.expr.evaluate(&ctx));
    }

    #[test]
    fn eval_glob() {
        let c = DslCondition::parse(r#"pat([STATUS], "2*")"#).unwrap();
        let ctx = ConditionContext {
            status: Some(200),
            response_time_ms: None,
            body: None,
            dns_rcode: None,
            connected: None,
            cert_expiration_ms: None,
            ip: None,
        };
        assert!(c.expr.evaluate(&ctx));
    }

    #[test]
    fn eval_any() {
        let c = DslCondition::parse(r"any([STATUS], 200, 201, 204)").unwrap();
        let ctx = ConditionContext {
            status: Some(201),
            response_time_ms: None,
            body: None,
            dns_rcode: None,
            connected: None,
            cert_expiration_ms: None,
            ip: None,
        };
        assert!(c.expr.evaluate(&ctx));
    }
}
