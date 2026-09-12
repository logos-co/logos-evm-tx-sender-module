//! Offline transaction construction: the unsigned call as the JSON `keystore_module` signs,
//! plus the number parsing every reply shares. No network, no keys. Pure Rust, unit-tested
//! with `cargo test`.

use alloy::primitives::{Address, U256};
use serde_json::{json, Value};

fn u256_hex(v: U256) -> String {
    format!("0x{:x}", v)
}

fn u64_hex(v: u64) -> String {
    format!("0x{v:x}")
}

/// Parse an EVM quantity written either as `0x`-hex or as decimal. Nodes answer hex, this
/// module stores decimal, and both reach the same fields.
///
/// No digits is `None`, never zero: an empty balance means "we could not read it", and
/// answering 0 would turn that into a number the user reads as a fact.
pub fn parse_u256_any(s: &str) -> Option<U256> {
    let t = s.trim();
    let (digits, radix) = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => (h, 16),
        None => (t, 10),
    };
    if digits.is_empty() {
        return None;
    }
    U256::from_str_radix(digits, radix).ok()
}

pub fn parse_u64_any(s: &str) -> Option<u64> {
    parse_u256_any(s).and_then(|v| u64::try_from(v).ok())
}

/// Calldata as the caller gave it, normalised: `0x`-prefixed lowercase hex of whole bytes.
/// An empty or absent field is `"0x"` — a plain transfer's own answer. Odd length or a
/// non-hex digit is refused rather than padded, because the bytes are what gets signed.
pub fn normalize_data(s: Option<&str>) -> Result<String, String> {
    let t = s.unwrap_or("").trim();
    let h = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if h.is_empty() {
        return Ok("0x".into());
    }
    if h.len() % 2 != 0 {
        return Err(format!("calldata has an odd number of hex digits ({})", h.len()));
    }
    if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("calldata is not hexadecimal".into());
    }
    Ok(format!("0x{}", h.to_lowercase()))
}

/// Fee policy for an unsigned transaction.
#[derive(Clone, Debug)]
pub enum Fee {
    Eip1559 { max_fee_per_gas: U256, max_priority_fee_per_gas: U256 },
    Legacy { gas_price: U256 },
}

fn apply_fee(o: &mut serde_json::Map<String, Value>, fee: &Fee) {
    match fee {
        Fee::Eip1559 { max_fee_per_gas, max_priority_fee_per_gas } => {
            o.insert("fee_mode".into(), json!("eip1559"));
            o.insert("max_fee_per_gas".into(), json!(u256_hex(*max_fee_per_gas)));
            o.insert("max_priority_fee_per_gas".into(), json!(u256_hex(*max_priority_fee_per_gas)));
        }
        Fee::Legacy { gas_price } => {
            o.insert("fee_mode".into(), json!("legacy"));
            o.insert("gas_price".into(), json!(u256_hex(*gas_price)));
        }
    }
}

/// Build an unsigned call — any `to`, any `value`, any `data` — as the JSON the keystore
/// signs. A plain transfer is a call with `data: "0x"`.
pub fn unsigned_call_tx(
    to: Address,
    value: U256,
    data: &str,
    nonce: u64,
    gas_limit: u64,
    fee: &Fee,
) -> Value {
    let mut o = serde_json::Map::new();
    o.insert("to".into(), json!(to.to_string()));
    o.insert("value".into(), json!(u256_hex(value)));
    o.insert("nonce".into(), json!(u64_hex(nonce)));
    o.insert("gas_limit".into(), json!(u64_hex(gas_limit)));
    o.insert("data".into(), json!(data));
    apply_fee(&mut o, fee);
    Value::Object(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    const TO: Address = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

    #[test]
    fn a_call_is_the_shape_the_keystore_signs() {
        let fee = Fee::Eip1559 { max_fee_per_gas: U256::from(30), max_priority_fee_per_gas: U256::from(2) };
        let tx = unsigned_call_tx(TO, U256::from(1_000), "0x095ea7b3", 7, 60_000, &fee);
        assert_eq!(tx["to"], json!(TO.to_string()));
        assert_eq!(tx["value"], json!("0x3e8"));
        assert_eq!(tx["nonce"], json!("0x7"));
        assert_eq!(tx["gas_limit"], json!("0xea60"));
        assert_eq!(tx["data"], json!("0x095ea7b3"));
        assert_eq!(tx["fee_mode"], json!("eip1559"));
        assert_eq!(tx["max_fee_per_gas"], json!("0x1e"));
        assert_eq!(tx["max_priority_fee_per_gas"], json!("0x2"));

        let legacy = unsigned_call_tx(TO, U256::ZERO, "0x", 0, 21_000, &Fee::Legacy { gas_price: U256::from(9) });
        assert_eq!(legacy["fee_mode"], json!("legacy"));
        assert_eq!(legacy["gas_price"], json!("0x9"));
        assert!(legacy.get("max_fee_per_gas").is_none());
    }

    #[test]
    fn quantities_parse_from_hex_or_decimal_and_never_from_nothing() {
        assert_eq!(parse_u256_any("0x10"), Some(U256::from(16)));
        assert_eq!(parse_u256_any("16"), Some(U256::from(16)));
        assert_eq!(parse_u256_any(" 0X10 "), Some(U256::from(16)));
        assert_eq!(parse_u256_any(""), None, "no digits is not zero");
        assert_eq!(parse_u256_any("0x"), None);
        assert_eq!(parse_u256_any("nope"), None);
        assert_eq!(parse_u64_any("0xffffffffffffffffff"), None, "too big for a u64");
    }

    #[test]
    fn calldata_is_normalised_or_refused_never_padded() {
        assert_eq!(normalize_data(None).unwrap(), "0x");
        assert_eq!(normalize_data(Some("")).unwrap(), "0x");
        assert_eq!(normalize_data(Some("0x")).unwrap(), "0x");
        assert_eq!(normalize_data(Some("0X095EA7B3")).unwrap(), "0x095ea7b3");
        assert_eq!(normalize_data(Some("095ea7b3")).unwrap(), "0x095ea7b3");
        assert!(normalize_data(Some("0xabc")).unwrap_err().contains("odd"));
        assert!(normalize_data(Some("0xzz")).unwrap_err().contains("not hexadecimal"));
    }
}
