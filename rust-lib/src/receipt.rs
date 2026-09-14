//! What a receipt carries beyond the four numbers `absorb_receipt` used to keep: the
//! transaction's own `to`, and the ERC-20 Transfer logs.
//!
//! An event's `topics[0]` is the full 32-byte keccak of the signature, so recognising one is a
//! FACT rather than a lookup — unlike a 4-byte function selector, which collides and whose
//! public registries are deliberately poisoned. No registry is consulted here and none may be.
//!
//! Pure Rust; `cargo test --no-default-features` covers all of it.

use alloy::primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `keccak256("Transfer(address,address,uint256)")`.
pub const TRANSFER_TOPIC0: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// Transfers kept on one row. The history file is rewritten whole on every edit, so an
/// unbounded array here is a cost every later poll pays.
pub const TRANSFERS_MAX: usize = 8;

/// One decoded ERC-20 Transfer: the on-chain facts and nothing else.
///
/// No symbol, no decimals and no rendered amount, because those are not in the log — they come
/// from the token table at read time, so a token added to it later decorates rows already on
/// disk rather than leaving them frozen at what we knew the day they settled.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct TokenTransfer {
    pub contract: String,
    pub from: String,
    pub to: String,
    /// Base units, decimal. Unscaled: the decimals belong to the token, not to the log.
    pub amount: String,
}

/// EIP-55 for an address that reaches us in whatever casing the node used. A receipt's `to`
/// and a log topic are both lowercase while `TxRecord.to` is checksummed, so the same address
/// rendered twice on one screen looked like two. Anything unparseable comes back untouched:
/// we do not know what it is, and reshaping it would be a guess.
pub fn checksummed(addr: &str) -> String {
    addr.parse::<Address>().map(|a| a.to_string()).unwrap_or_else(|_| addr.to_string())
}

/// The 20-byte address inside an indexed topic — the low 20 of its 32 bytes.
fn topic_address(t: &str) -> Option<String> {
    let h = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"))?;
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(checksummed(&format!("0x{}", &h[24..])))
}

fn topics(log: &Value) -> Vec<&str> {
    log.get("topics")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// One log, if it is an ERC-20 Transfer.
///
/// Three conditions, and the middle one is the one that matters: ERC-721 `Transfer` carries the
/// SAME topic0 with FOUR topics, because its `tokenId` is indexed rather than in `data`. Without
/// the count check an NFT token id renders as an amount.
fn decode_transfer(log: &Value) -> Option<TokenTransfer> {
    let t = topics(log);
    if t.len() != 3 || !t[0].eq_ignore_ascii_case(TRANSFER_TOPIC0) {
        return None;
    }
    let data = log.get("data").and_then(Value::as_str)?;
    let digits = data.strip_prefix("0x").or_else(|| data.strip_prefix("0X"))?;
    if digits.len() != 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(TokenTransfer {
        contract: checksummed(log.get("address").and_then(Value::as_str)?),
        from: topic_address(t[1])?,
        to: topic_address(t[2])?,
        amount: U256::from_str_radix(digits, 16).ok()?.to_string(),
    })
}

/// Every ERC-20 Transfer in `receipt`, `account`'s own first and each group in log order,
/// capped at `TRANSFERS_MAX`. The second value counts what the cap dropped.
///
/// Sorted before it is cut, so the transfer the user themselves made can never be the one
/// truncated away.
pub fn decode_transfers(receipt: &Value, account: &str) -> (Vec<TokenTransfer>, u32) {
    let all: Vec<TokenTransfer> = receipt
        .get("logs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(decode_transfer)
        .collect();
    let (mut kept, theirs): (Vec<_>, Vec<_>) =
        all.into_iter().partition(|t| t.from.eq_ignore_ascii_case(account));
    kept.extend(theirs);
    let more = u32::try_from(kept.len().saturating_sub(TRANSFERS_MAX)).unwrap_or(u32::MAX);
    kept.truncate(TRANSFERS_MAX);
    (kept, more)
}

/// The transaction's OWN `to` — the token contract, for an ERC-20 send. `None` for a contract
/// creation, whose receipt `to` is null; this wallet never makes one.
pub fn receipt_to(receipt: &Value) -> Option<String> {
    receipt.get("to").and_then(Value::as_str).map(checksummed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const WETH: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    const ME: &str = "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199";
    const THEM: &str = "0x0adBc7B2D1A2b7C8E9F0A1b2c3d4e5f60718D3A7";

    /// Lowercase, as a node answers one — which is the whole of F-6: an address read out of a
    /// topic and one the user typed used to reach the same screen spelled two ways.
    fn topic_of(addr: &str) -> String {
        format!("0x000000000000000000000000{}", addr.trim_start_matches("0x").to_lowercase())
    }

    fn word(n: u128) -> String {
        format!("0x{n:064x}")
    }

    fn transfer_log(contract: &str, from: &str, to: &str, amount: u128) -> Value {
        json!({ "address": contract,
                "topics": [TRANSFER_TOPIC0, topic_of(from), topic_of(to)],
                "data": word(amount) })
    }

    #[test]
    fn a_transfer_log_decodes_to_the_facts_it_carries() {
        let r = json!({ "logs": [transfer_log(WETH, ME, THEM, 1_000_000_000_000)] });
        let (t, more) = decode_transfers(&r, ME);
        assert_eq!(more, 0);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].contract, WETH);
        // F-6. EIP-55, not the topic's own lowercase: `TxRecord.to` is checksummed, so the
        // card that exists to reconcile addresses used to print one address two ways.
        assert_eq!((&t[0].from, &t[0].to), (&ME.to_string(), &THEM.to_string()));
        // Decimal, unscaled: the decimals are the token's and are applied at render time.
        assert_eq!(t[0].amount, "1000000000000");
    }

    /// THE DEFECT THIS EXISTS FOR. ERC-721 `Transfer` has the SAME topic0 and four topics,
    /// because `tokenId` is indexed. Read as an ERC-20 log, an NFT id renders as an amount.
    ///
    /// TWO cases, because they are refused by two different conditions and the realistic one
    /// does not exercise the rule: a real ERC-721 log carries EMPTY data, so the data-length
    /// check alone turns it away and the topic COUNT could be dropped with nothing failing.
    #[test]
    fn an_erc721_transfer_is_not_an_amount() {
        let real = json!({ "address": WETH,
                           "topics": [TRANSFER_TOPIC0, topic_of(ME), topic_of(THEM), word(7)],
                           "data": "0x" });
        assert_eq!(decode_transfers(&json!({ "logs": [real] }), ME).0, vec![]);

        // Four topics AND a full word of data: only the topic count can refuse this one, and
        // without it that word — a token id, not an amount — would render as a balance.
        let four = json!({ "address": WETH,
                           "topics": [TRANSFER_TOPIC0, topic_of(ME), topic_of(THEM), word(7)],
                           "data": word(999) });
        assert_eq!(decode_transfers(&json!({ "logs": [four] }), ME).0, vec![],
                   "a fourth topic means the third argument is indexed, so `data` is not it");
    }

    #[test]
    fn only_this_topic0_and_only_a_full_word_of_data() {
        let other = json!({ "address": WETH,
                            "topics": [word(1), topic_of(ME), topic_of(THEM)],
                            "data": word(5) });
        assert_eq!(decode_transfers(&json!({ "logs": [other] }), ME).0, vec![]);

        // A short `data` is not a zero amount, it is a log we did not understand.
        let short = json!({ "address": WETH,
                            "topics": [TRANSFER_TOPIC0, topic_of(ME), topic_of(THEM)],
                            "data": "0x2a" });
        assert_eq!(decode_transfers(&json!({ "logs": [short] }), ME).0, vec![]);

        // And an upper-case topic0 is the same 32 bytes.
        let shouty = json!({ "address": WETH,
                             "topics": [TRANSFER_TOPIC0.to_uppercase(), topic_of(ME), topic_of(THEM)],
                             "data": word(1) });
        assert_eq!(decode_transfers(&json!({ "logs": [shouty] }), ME).0.len(), 1);
    }

    #[test]
    fn a_receipt_with_no_logs_decodes_to_nothing_and_says_nothing_was_dropped() {
        assert_eq!(decode_transfers(&json!({ "status": "0x1" }), ME), (vec![], 0));
        assert_eq!(decode_transfers(&json!({ "logs": [] }), ME), (vec![], 0));
    }

    /// The cap is applied AFTER the sort, so the transfer the user made is never the one it
    /// drops — which is the only one they came to this screen to read.
    #[test]
    fn the_account_s_own_transfer_survives_the_cap() {
        let mut logs: Vec<Value> = (0..TRANSFERS_MAX + 3)
            .map(|i| transfer_log(WETH, THEM, THEM, i as u128))
            .collect();
        logs.push(transfer_log(WETH, ME, THEM, 999));
        let (t, more) = decode_transfers(&json!({ "logs": logs }), ME);
        assert_eq!(t.len(), TRANSFERS_MAX);
        assert_eq!(more, 4, "eleven decoded, eight kept");
        assert_eq!(t[0].amount, "999", "the account's own sorts first");
        // The rest keep log order, which is on-chain order.
        assert_eq!(t[1].amount, "0");
        assert_eq!(t[2].amount, "1");
    }

    #[test]
    fn the_transactions_own_to_is_read_but_a_contract_creation_has_none() {
        assert_eq!(receipt_to(&json!({ "to": WETH })), Some(WETH.to_string()));
        assert_eq!(receipt_to(&json!({ "to": Value::Null })), None);
        assert_eq!(receipt_to(&json!({})), None);
    }

    /// F-6. A node answers `to` and its log topics in lowercase; the recipient the user typed
    /// is stored EIP-55. One casing on the way in, or the same address reads as two.
    #[test]
    fn an_address_is_checksummed_however_the_node_spelled_it() {
        assert_eq!(receipt_to(&json!({ "to": WETH.to_lowercase() })), Some(WETH.to_string()));
        assert_eq!(checksummed(&THEM.to_uppercase().replace("0X", "0x")), THEM);
        assert_eq!(checksummed(WETH), WETH, "already checksummed, and idempotent");

        let r = json!({ "logs": [transfer_log(&WETH.to_lowercase(), ME, THEM, 1)] });
        assert_eq!(decode_transfers(&r, ME).0[0].contract, WETH);

        // Not an address, so not reshaped: we do not know what it is.
        assert_eq!(checksummed("0xdeadbeef"), "0xdeadbeef");
        assert_eq!(checksummed(""), "");
    }
}
