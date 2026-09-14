//! Decimal-string ↔ base-units conversion. Exact integer arithmetic only.
//!
//! A wei amount needs up to 256 bits; f64 carries 53. "0.1" ETH does not round-trip through
//! a double, and a wallet that loses a digit here signs the wrong number. Everything below
//! is string manipulation plus U256, and there is no floating point anywhere in this file.

use alloy::primitives::U256;
use serde_json::{json, Value};

/// Fraction digits the bounded rendering keeps. At any plausible ETH price 1e-5 ETH is a
/// few cents, so nothing a user would notice can hide behind the dust marker, and
/// `min(DISPLAY_PLACES, decimals)` generalises the rule to a 6-decimal token.
pub const DISPLAY_PLACES: u8 = 5;

/// Why a typed amount could not be read. Rejection, never truncation: silently dropping a
/// digit changes the number being signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AmountError {
    Empty,
    Negative,
    NotANumber,
    TooManyDecimals { given: usize, allowed: u8 },
    TooLarge,
}

/// Token units as the user typed them → base units. Hex, `1e18`, `1_000` and `1,5` are all
/// refused: `parse_u256_any`'s hex must never be read as a token-unit amount.
pub fn parse_units(input: &str, decimals: u8) -> Result<U256, AmountError> {
    let t = input.trim_matches(|c: char| c.is_ascii_whitespace());
    if t.is_empty() {
        return Err(AmountError::Empty);
    }
    if t.starts_with('-') {
        return Err(AmountError::Negative);
    }
    let mut dots = 0usize;
    for b in t.bytes() {
        match b {
            b'0'..=b'9' => {}
            b'.' => dots += 1,
            _ => return Err(AmountError::NotANumber),
        }
    }
    if dots > 1 {
        return Err(AmountError::NotANumber);
    }
    let (int_part, frac_part) = t.split_once('.').unwrap_or((t, ""));
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(AmountError::NotANumber);
    }
    let allowed = decimals as usize;
    if frac_part.len() > allowed {
        return Err(AmountError::TooManyDecimals { given: frac_part.len(), allowed: decimals });
    }
    let mut digits = String::with_capacity(int_part.len() + allowed);
    digits.push_str(int_part);
    digits.push_str(frac_part);
    for _ in frac_part.len()..allowed {
        digits.push('0');
    }
    U256::from_str_radix(&digits, 10).map_err(|_| AmountError::TooLarge)
}

fn digits_only(raw: &str) -> Option<&str> {
    let t = raw.trim_matches(|c: char| c.is_ascii_whitespace());
    (!t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())).then_some(t)
}

fn strip_leading_zeros(s: &str) -> String {
    let t = s.trim_start_matches('0');
    if t.is_empty() { "0".to_string() } else { t.to_string() }
}

/// Every digit of `raw` base units, in token units. `None` when `raw` is not a decimal
/// integer — the caller renders an em-dash, because "we could not read it" is not "none".
pub fn format_exact(raw: &str, decimals: u8) -> Option<String> {
    let digits = digits_only(raw)?;
    let d = decimals as usize;
    if d == 0 {
        return Some(strip_leading_zeros(digits));
    }
    let mut padded = String::with_capacity(d + 1);
    for _ in digits.len()..d + 1 {
        padded.push('0');
    }
    padded.push_str(digits);
    let split = padded.len() - d;
    let int_part = strip_leading_zeros(&padded[..split]);
    let frac = padded[split..].trim_end_matches('0');
    if frac.is_empty() { Some(int_part) } else { Some(format!("{int_part}.{frac}")) }
}

/// The bounded rendering. Only an exactly-zero amount renders `"0"`; anything below the
/// resolution renders `"<0.00001"`, so a 1-wei balance can never look like an empty account.
/// Truncated, not rounded: a balance shown as more than you hold is worse than one shown as
/// less, and the dust marker covers the case where truncation would have erased a real amount.
pub fn format_display(raw: &str, decimals: u8) -> Option<String> {
    let digits = digits_only(raw)?;
    let v = U256::from_str_radix(digits, 10).ok()?;
    if v.is_zero() {
        return Some("0".to_string());
    }
    let p = DISPLAY_PLACES.min(decimals);
    if p == 0 {
        return Some(v.to_string());
    }
    // An unrepresentable threshold means every nonzero amount is below the resolution.
    let threshold = U256::from(10u8).checked_pow(U256::from(decimals - p));
    if threshold.map(|t| v < t).unwrap_or(true) {
        return Some(format!("<0.{}1", "0".repeat(p as usize - 1)));
    }
    let exact = format_exact(digits, decimals)?;
    let Some((int_part, frac)) = exact.split_once('.') else { return Some(exact) };
    let cut = frac[..frac.len().min(p as usize)].trim_end_matches('0');
    if cut.is_empty() { Some(int_part.to_string()) } else { Some(format!("{int_part}.{cut}")) }
}

/// Add `<key>Display` (bounded) and `<key>Exact` beside an amount, accepting either the hex
/// a node answers or the decimal this wallet stores.
///
/// Absent — never `""`, never `"0"` — when the amount or its decimals cannot be read, so the
/// view shows an em-dash rather than a number the user would take as a fact.
pub fn decorate(v: &mut Value, key: &str, raw: &str, decimals: Option<u8>) {
    let (Some(d), Some(n)) = (decimals, crate::txbuild::parse_u256_any(raw)) else { return };
    let base = n.to_string();
    if let Some(x) = format_display(&base, d) {
        v[format!("{key}Display")] = json!(x);
    }
    if let Some(x) = format_exact(&base, d) {
        v[format!("{key}Exact")] = json!(x);
    }
}

/// Turn a send request's two mutually exclusive amount fields into base units.
///
/// `amount` keeps its old meaning exactly — base units — so no existing caller is rescaled.
/// Both present is refused rather than resolved: they mean different units and only one can
/// be what the caller meant.
pub fn resolve_amount(
    amount: Option<&str>,
    amount_units: Option<&str>,
    decimals: u8,
    symbol: &str,
) -> Result<U256, String> {
    match (amount, amount_units) {
        (Some(_), Some(_)) => Err("send both `amount` and `amountUnits`: they mean different \
                                   units and only one can be what you meant"
            .to_string()),
        (None, None) => Err("no amount".to_string()),
        (Some(a), None) => crate::txbuild::parse_u256_any(a)
            .ok_or_else(|| format!("amount '{a}' is not a number")),
        (None, Some(u)) => parse_units(u, decimals).map_err(|e| describe(&e, u, symbol, decimals)),
    }
}

/// The sentence a human reads. It names the token because "18 decimals" means nothing
/// without one.
fn describe(e: &AmountError, input: &str, symbol: &str, decimals: u8) -> String {
    match e {
        AmountError::TooManyDecimals { given, .. } => {
            format!("{symbol} has {decimals} decimals; that amount has {given}")
        }
        AmountError::Negative => "an amount cannot be negative".to_string(),
        AmountError::NotANumber => {
            format!("'{input}' is not an amount — use digits and at most one decimal point")
        }
        AmountError::Empty => "enter an amount".to_string(),
        AmountError::TooLarge => "that amount is too large".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> U256 {
        U256::from_str_radix(s, 10).unwrap()
    }

    #[test]
    fn parse_units_accepts_every_shape_a_human_types() {
        let cases: &[(&str, u8, &str)] = &[
            ("1", 18, "1000000000000000000"),
            (" 1 ", 18, "1000000000000000000"),
            ("0.1", 18, "100000000000000000"),
            ("1.5", 18, "1500000000000000000"),
            ("0.000000000000000001", 18, "1"),
            ("1.", 18, "1000000000000000000"),
            (".5", 18, "500000000000000000"),
            ("007", 18, "7000000000000000000"),
            ("0", 18, "0"),
            ("0.0", 18, "0"),
            ("0.", 18, "0"),
            (".0", 18, "0"),
            ("1.234567890123456789", 18, "1234567890123456789"),
            ("1.000001", 6, "1000001"),
            ("12", 0, "12"),
        ];
        for (input, decimals, expected) in cases {
            assert_eq!(parse_units(input, *decimals), Ok(u(expected)), "{input:?}");
        }
    }

    #[test]
    fn parse_units_refuses_what_is_not_a_plain_decimal_amount() {
        use AmountError::*;
        let cases: &[(&str, u8, AmountError)] = &[
            ("", 18, Empty),
            ("   ", 18, Empty),
            ("-1", 18, Negative),
            ("-0.5", 18, Negative),
            ("+1", 18, NotANumber),
            // Hex is the one that matters: `parse_u256_any` would have read it as a number.
            ("0x1", 18, NotANumber),
            ("1e18", 18, NotANumber),
            ("1_000", 18, NotANumber),
            ("1,5", 18, NotANumber),
            ("1 5", 18, NotANumber),
            ("abc", 18, NotANumber),
            ("1.2.3", 18, NotANumber),
            (".", 18, NotANumber),
            ("0.1234567890123456789", 18, TooManyDecimals { given: 19, allowed: 18 }),
            ("1.5", 0, TooManyDecimals { given: 1, allowed: 0 }),
        ];
        for (input, decimals, expected) in cases {
            assert_eq!(parse_units(input, *decimals), Err(expected.clone()), "{input:?}");
        }
    }

    #[test]
    fn an_amount_wider_than_256_bits_is_refused_not_wrapped() {
        let huge = "9".repeat(78);
        assert_eq!(parse_units(&huge, 0), Err(AmountError::TooLarge));
        assert_eq!(parse_units(&huge, 18), Err(AmountError::TooLarge));
        // U256::MAX itself still fits, so the boundary is the type's and not an invention.
        let max = U256::MAX.to_string();
        assert_eq!(parse_units(&max, 0), Ok(U256::MAX));
    }

    #[test]
    fn format_exact_keeps_every_digit() {
        let cases: &[(&str, u8, &str)] = &[
            ("1", 18, "0.000000000000000001"),
            ("1000000000000000000", 18, "1"),
            ("1500000000000000000", 18, "1.5"),
            ("0", 18, "0"),
            ("1234567890123456789", 18, "1.234567890123456789"),
            ("100000000000000000", 18, "0.1"),
            ("1000001", 6, "1.000001"),
            ("42", 0, "42"),
            ("007", 0, "7"),
        ];
        for (raw, decimals, expected) in cases {
            assert_eq!(format_exact(raw, *decimals).as_deref(), Some(*expected), "{raw:?}");
        }
        // Unreadable is not zero: the caller renders an em-dash.
        assert_eq!(format_exact("", 18), None);
        assert_eq!(format_exact("0x1f", 18), None);
        assert_eq!(format_exact("1.5", 18), None);
    }

    #[test]
    fn a_value_survives_the_round_trip_through_its_own_rendering() {
        // The test a float implementation cannot pass.
        let values = [
            "0", "1", "9", "10", "999", "1000000000000000000", "1500000000000000000",
            "1234567890123456789", "100000000000000000", "10000000000000", "1000000000000",
            "999999999999999999999999", "1000000000000000000000000000",
            "115792089237316195423570985008687907853269984665640564039457584007913129639",
            "57896044618658097711785492504343953926634992332820282019728792003956564819967",
            "12345678901234567890123456789012345678901234567890",
            "7", "70", "700", "70000000000000000",
        ];
        for v in values {
            let rendered = format_exact(v, 18).unwrap();
            assert_eq!(parse_units(&rendered, 18), Ok(u(v)), "{v} rendered as {rendered}");
        }
    }

    #[test]
    fn only_an_exactly_zero_balance_renders_as_zero() {
        assert_eq!(format_display("0", 18).as_deref(), Some("0"));
        for wei in 1u64..1000 {
            let shown = format_display(&wei.to_string(), 18).unwrap();
            assert_ne!(shown, "0", "{wei} wei must not render as an empty account");
            assert_eq!(shown, "<0.00001");
        }
    }

    #[test]
    fn a_dust_balance_and_an_empty_account_are_distinguishable() {
        assert_ne!(format_display("1", 18), format_display("0", 18));
        assert_eq!(format_display("1", 18).as_deref(), Some("<0.00001"));
    }

    #[test]
    fn the_bounded_rendering_truncates_and_includes_its_own_boundary() {
        let cases: &[(&str, u8, &str)] = &[
            // 10^13 wei is exactly the resolution: included, not dust.
            ("10000000000000", 18, "0.00001"),
            ("9999999999999", 18, "<0.00001"),
            ("1000000000000000000", 18, "1"),
            ("1234567890123456789", 18, "1.23456"),
            ("1500000000000000000", 18, "1.5"),
            ("1000010000000000000", 18, "1.00001"),
            // A sixth place is truncated away, and the amount is far above the resolution,
            // so it renders as a plain "1" rather than a dust marker.
            ("1000001000000000000", 18, "1"),
            ("1000000000001", 6, "1000000"),
            ("42", 0, "42"),
        ];
        for (raw, decimals, expected) in cases {
            assert_eq!(format_display(raw, *decimals).as_deref(), Some(*expected), "{raw:?}");
        }
        assert_eq!(format_display("", 18), None);
        assert_eq!(format_display("0x1", 18), None);
    }

    #[test]
    fn a_token_with_few_decimals_never_shows_a_dust_marker() {
        // p == decimals, so the threshold is 1 and every nonzero amount is representable.
        for raw in ["1", "5", "99", "100"] {
            let shown = format_display(raw, 2).unwrap();
            assert!(!shown.starts_with('<'), "{raw} @2 rendered {shown}");
        }
        assert_eq!(format_display("1", 2).as_deref(), Some("0.01"));
    }

    #[test]
    fn decorate_emits_both_renderings_or_neither() {
        let mut v = json!({});
        decorate(&mut v, "value", "1500000000000000000", Some(18));
        assert_eq!(v["valueDisplay"], json!("1.5"));
        assert_eq!(v["valueExact"], json!("1.5"));

        // A node's hex reaches the same field as this wallet's decimal.
        let mut v = json!({});
        decorate(&mut v, "value", "0x1", Some(18));
        assert_eq!(v["valueDisplay"], json!("<0.00001"));
        assert_eq!(v["valueExact"], json!("0.000000000000000001"));

        // Unknown decimals and an unreadable amount both emit nothing at all.
        let mut v = json!({});
        decorate(&mut v, "value", "1", None);
        decorate(&mut v, "fee", "", Some(18));
        assert_eq!(v, json!({}));
    }

    #[test]
    fn exactly_one_of_amount_and_amount_units_is_accepted() {
        assert_eq!(resolve_amount(Some("1"), None, 18, "ETH"), Ok(U256::from(1)));
        assert_eq!(
            resolve_amount(Some("0x10"), None, 18, "ETH"),
            Ok(U256::from(16)),
            "the base-units field keeps its old meaning exactly, hex included"
        );
        assert_eq!(
            resolve_amount(None, Some("1"), 18, "ETH"),
            Ok(u("1000000000000000000")),
            "amountUnits is token units, amount is base units — they must not agree"
        );
        let both = resolve_amount(Some("1"), Some("1"), 18, "ETH").unwrap_err();
        assert!(both.contains("only one can be what you meant"), "{both}");
        assert_eq!(resolve_amount(None, None, 18, "ETH").unwrap_err(), "no amount");
    }

    #[test]
    fn an_unreadable_typed_amount_is_explained_in_the_tokens_own_terms() {
        let e = resolve_amount(None, Some("0.1234567890123456789"), 18, "ETH").unwrap_err();
        assert_eq!(e, "ETH has 18 decimals; that amount has 19");
        let e = resolve_amount(None, Some("1.5000001"), 6, "USDC").unwrap_err();
        assert_eq!(e, "USDC has 6 decimals; that amount has 7");
        let e = resolve_amount(None, Some("-1"), 18, "ETH").unwrap_err();
        assert_eq!(e, "an amount cannot be negative");
        let e = resolve_amount(None, Some("0x1"), 18, "ETH").unwrap_err();
        assert!(e.contains("is not an amount"), "{e}");
        assert_eq!(resolve_amount(None, Some(""), 18, "ETH").unwrap_err(), "enter an amount");
    }
}
