//! What a receipt carries beyond the four numbers `absorb_receipt` used to keep: the
//! transaction's own `to`, the ERC-20 Transfer logs, and the EIP-7708 ether-transfer logs.
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

/// EIP-7708's emitter (EIP-4788's SYSTEM_ADDRESS). From Glamsterdam every nonzero ether transfer
/// logs an ERC-20-shaped Transfer from here: ether moved, and never a token contract.
pub const SYSTEM_ADDRESS: &str = "0xfffffffffffffffffffffffffffffffffffffffe";

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

/// One EIP-7708 ether transfer. Wei, decimal, unscaled like a token amount on disk.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct NativeTransfer {
    pub from: String,
    pub to: String,
    pub amount: String,
}

pub fn is_system_address(addr: &str) -> bool {
    addr.eq_ignore_ascii_case(SYSTEM_ADDRESS)
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

/// A decoded Transfer log: what the emitter says moved.
enum Moved {
    Token(TokenTransfer),
    Native(NativeTransfer),
}

/// One log, if it is a Transfer.
///
/// Three conditions, and the middle one is the one that matters: ERC-721 `Transfer` carries the
/// SAME topic0 with FOUR topics, because its `tokenId` is indexed rather than in `data`. Without
/// the count check an NFT token id renders as an amount. The emitter then decides the kind: the
/// system address logs ether (EIP-7708), anything else is a token contract.
fn decode_log(log: &Value) -> Option<Moved> {
    let t = topics(log);
    if t.len() != 3 || !t[0].eq_ignore_ascii_case(TRANSFER_TOPIC0) {
        return None;
    }
    let data = log.get("data").and_then(Value::as_str)?;
    let digits = data.strip_prefix("0x").or_else(|| data.strip_prefix("0X"))?;
    if digits.len() != 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let emitter = log.get("address").and_then(Value::as_str)?;
    let from = topic_address(t[1])?;
    let to = topic_address(t[2])?;
    let amount = U256::from_str_radix(digits, 16).ok()?.to_string();
    Some(if is_system_address(emitter) {
        Moved::Native(NativeTransfer { from, to, amount })
    } else {
        Moved::Token(TokenTransfer { contract: checksummed(emitter), from, to, amount })
    })
}

fn decode_logs(receipt: &Value) -> impl Iterator<Item = Moved> + '_ {
    receipt.get("logs").and_then(Value::as_array).into_iter().flatten().filter_map(decode_log)
}

/// `own` entries first, each group in log order, capped at `TRANSFERS_MAX`. The second value
/// counts what the cap dropped.
fn own_first<T>(all: Vec<T>, own: impl Fn(&T) -> bool) -> (Vec<T>, u32) {
    let (mut kept, theirs): (Vec<T>, Vec<T>) = all.into_iter().partition(|t| own(t));
    kept.extend(theirs);
    let more = u32::try_from(kept.len().saturating_sub(TRANSFERS_MAX)).unwrap_or(u32::MAX);
    kept.truncate(TRANSFERS_MAX);
    (kept, more)
}

/// Every ERC-20 Transfer in `receipt`, `account`'s own first and each group in log order,
/// capped at `TRANSFERS_MAX`. The second value counts what the cap dropped.
///
/// Sorted before it is cut, so the transfer the user themselves made can never be the one
/// truncated away.
pub fn decode_transfers(receipt: &Value, account: &str) -> (Vec<TokenTransfer>, u32) {
    let all: Vec<TokenTransfer> = decode_logs(receipt)
        .filter_map(|m| match m {
            Moved::Token(t) => Some(t),
            Moved::Native(_) => None,
        })
        .collect();
    own_first(all, |t| t.from.eq_ignore_ascii_case(account))
}

/// Every EIP-7708 ether transfer in `receipt`, capped like the tokens. Those `account` sent OR
/// received sort first: a swap's ether proceeds are the entry the user came to read.
pub fn decode_native_transfers(receipt: &Value, account: &str) -> (Vec<NativeTransfer>, u32) {
    let all: Vec<NativeTransfer> = decode_logs(receipt)
        .filter_map(|m| match m {
            Moved::Native(t) => Some(t),
            Moved::Token(_) => None,
        })
        .collect();
    own_first(all, |t| t.from.eq_ignore_ascii_case(account) || t.to.eq_ignore_ascii_case(account))
}

/// The wei `account` received in `receipt`, summed over EVERY ether-transfer log: the cap
/// bounds the list, never this total. `None` when nothing came in.
pub fn native_received(receipt: &Value, account: &str) -> Option<String> {
    let mut total: Option<U256> = None;
    for m in decode_logs(receipt) {
        if let Moved::Native(t) = m {
            if t.to.eq_ignore_ascii_case(account) {
                let amount = U256::from_str_radix(&t.amount, 10).ok()?;
                total = Some(total.unwrap_or(U256::ZERO).checked_add(amount)?);
            }
        }
    }
    total.map(|t| t.to_string())
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

    /// A REAL receipt, trimmed to what decoding reads: anvil 1.8.1 `--hardfork amsterdam`, a
    /// 0.5 ETH call from account 0 to a contract whose code forwards it straight back.
    fn eip7708_forward_receipt() -> Value {
        json!({ "status": "0x1", "to": "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9", "logs": [
            { "address": "0xfffffffffffffffffffffffffffffffffffffffe",
              "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                         "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                         "0x000000000000000000000000cf7ed3acca5a467e9e704c703e8d87f634fb0fc9"],
              "data": "0x00000000000000000000000000000000000000000000000006f05b59d3b20000" },
            { "address": "0xfffffffffffffffffffffffffffffffffffffffe",
              "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                         "0x000000000000000000000000cf7ed3acca5a467e9e704c703e8d87f634fb0fc9",
                         "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266"],
              "data": "0x00000000000000000000000000000000000000000000000006f05b59d3b20000" }
        ] })
    }

    const ANVIL0: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const FORWARDER: &str = "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9";

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

    /// THE DEFECT THIS EXISTS FOR (EIP-7708). The system address logs ether with the ERC-20
    /// Transfer topic, so reading it as a token made every ETH send a transfer of 0xFfff…FFfE.
    #[test]
    fn an_eip7708_log_is_ether_not_a_token() {
        let r = eip7708_forward_receipt();
        assert_eq!(decode_transfers(&r, ANVIL0), (vec![], 0), "no token moved");

        let (native, more) = decode_native_transfers(&r, ANVIL0);
        assert_eq!(more, 0);
        let half = "500000000000000000".to_string();
        let (me, fwd) = (checksummed(ANVIL0), checksummed(FORWARDER));
        assert_eq!(native, vec![
            NativeTransfer { from: me.clone(), to: fwd.clone(), amount: half.clone() },
            NativeTransfer { from: fwd, to: me, amount: half.clone() },
        ], "the call's own value first, then the internal CALL, in log order");
        assert_eq!(native_received(&r, ANVIL0), Some(half));
    }

    /// A USDC -> ETH swap: tokens and ether interleave in one receipt and split by emitter.
    #[test]
    fn a_swap_receipt_splits_ether_from_tokens_in_log_order() {
        const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        const ROUTER: &str = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45";
        let ether = |from: &str, to: &str, amount: u128| {
            transfer_log(&SYSTEM_ADDRESS.to_uppercase().replace("0X", "0x"), from, to, amount)
        };
        let withdrawal = json!({ "address": WETH, "topics": [word(1), topic_of(ROUTER)],
                                 "data": word(3) });
        let r = json!({ "logs": [
            transfer_log(USDC, ME, THEM, 10_000_000),
            transfer_log(WETH, THEM, ROUTER, 3),
            withdrawal,
            ether(WETH, ROUTER, 3),
            ether(ROUTER, ME, 3),
        ] });
        let (tokens, _) = decode_transfers(&r, ME);
        assert_eq!(tokens.iter().map(|t| t.contract.as_str()).collect::<Vec<_>>(), [USDC, WETH]);
        let (native, _) = decode_native_transfers(&r, ME);
        assert_eq!((native[0].from.as_str(), native[0].to.as_str()), (ROUTER, ME),
                   "what the account received sorts first");
        assert_eq!((native[1].from.as_str(), native[1].to.as_str()), (WETH, ROUTER));
        assert_eq!(native_received(&r, ME).as_deref(), Some("3"));
    }

    /// Only the one shape EIP-7708 defines is ether. A four-topic log or another topic0 from the
    /// system address is a log we do not understand, and it lands in neither list.
    #[test]
    fn a_system_log_of_any_other_shape_is_neither() {
        let four = json!({ "address": SYSTEM_ADDRESS,
                           "topics": [TRANSFER_TOPIC0, topic_of(ME), topic_of(THEM), word(7)],
                           "data": word(9) });
        let other = json!({ "address": SYSTEM_ADDRESS,
                            "topics": [word(1), topic_of(ME), topic_of(THEM)], "data": word(9) });
        let r = json!({ "logs": [four, other] });
        assert_eq!(decode_transfers(&r, ME), (vec![], 0));
        assert_eq!(decode_native_transfers(&r, ME), (vec![], 0));
        assert_eq!(native_received(&r, ME), None);
    }

    /// The EMITTER decides, not the recipient: a token sent to the system address is a token.
    #[test]
    fn a_token_sent_to_the_system_address_is_still_a_token() {
        let r = json!({ "logs": [transfer_log(WETH, ME, SYSTEM_ADDRESS, 5)] });
        let (tokens, _) = decode_transfers(&r, ME);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].contract, WETH);
        assert_eq!(decode_native_transfers(&r, ME), (vec![], 0));
    }

    /// The cap bounds the LIST; the received total is summed over every log, dropped ones too.
    #[test]
    fn the_ether_received_is_summed_whole_and_survives_the_cap() {
        let mut logs: Vec<Value> =
            (0..3).map(|_| transfer_log(SYSTEM_ADDRESS, THEM, WETH, 1)).collect();
        logs.extend((0..TRANSFERS_MAX + 2).map(|_| transfer_log(SYSTEM_ADDRESS, THEM, ME, 10)));
        let r = json!({ "logs": logs });
        let (native, more) = decode_native_transfers(&r, ME);
        assert_eq!((native.len(), more), (TRANSFERS_MAX, 5));
        assert!(native.iter().all(|t| t.to == ME), "the account's own entries are the ones kept");
        assert_eq!(native_received(&r, ME).as_deref(), Some("100"), "ten received, all counted");

        let sent = json!({ "logs": [transfer_log(SYSTEM_ADDRESS, ME, THEM, 10)] });
        assert_eq!(native_received(&sent, ME), None, "nothing came in");
        assert_eq!(native_received(&json!({}), ME), None);
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
