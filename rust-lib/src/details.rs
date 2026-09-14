//! The `get_tx_details` reply: what a receipt never carried, assembled from however many of
//! its two independent legs actually ran.
//!
//! The glue makes the calls; the SHAPE of the answer is decided here, so
//! `cargo test --no-default-features` covers the two rules that matter — either leg may fail
//! alone, and every reply names the transaction it is about.

use serde_json::{json, Value};

use crate::history::TxRecord;
use crate::sweep::GAS_PRICE_UNIT;
use crate::verified;

/// One leg: the fields it filled plus `eth_rpc`'s route label for them, or the node's own
/// words for why it could not.
pub type Leg = Result<(Value, Option<String>), String>;

/// Whether the transaction leg would tell this row anything it does not already store. The
/// calldata joins the two fee fields: a row written before `tx_input` existed learns it here
/// or never, and skipping on the fee fields alone made that unreachable.
pub fn transaction_leg_needed(rec: &TxRecord) -> bool {
    rec.max_priority_fee_per_gas.is_none() || rec.gas_limit.is_none() || rec.tx_input.is_none()
}

/// A refusal that NAMES its transaction. The plain `{ ok, error }` shape does not, and this
/// reply is rendered beside one transaction's own rows — an unattributable message there lands
/// under whichever transaction the user is looking at when it arrives.
pub fn details_refusal(hash: &str, why: &str) -> Value {
    json!({ "ok": false, "hash": hash, "error": why })
}

/// Assemble the reply.
///
/// `transaction` is `None` when the row already stores what that leg would answer and it was
/// never made — not a failure, and it must not read as one. `ok` is true when EITHER leg
/// landed: a timed-out block read must not withhold a priority fee that arrived.
pub fn details_reply(
    hash: &str,
    chain_id: u64,
    fetched_at: u64,
    block: Leg,
    transaction: Option<Leg>,
) -> Value {
    let mut out = json!({ "ok": true, "hash": hash, "chainId": chain_id,
                          "fetchedAt": fetched_at, "gasPriceUnit": GAS_PRICE_UNIT });
    let mut routes: Vec<Option<String>> = Vec::new();
    for (key, err_key, leg) in [
        ("block", "blockError", Some(block)),
        ("transaction", "transactionError", transaction),
    ] {
        match leg {
            Some(Ok((v, route))) => {
                out[key] = v;
                routes.push(route);
            }
            Some(Err(e)) => out[err_key] = json!(e),
            None => {}
        }
    }
    if routes.is_empty() {
        let why = out
            .get("blockError")
            .or_else(|| out.get("transactionError"))
            .and_then(Value::as_str)
            .unwrap_or("nothing could be read")
            .to_string();
        let mut r = details_refusal(hash, &why);
        r["chainId"] = json!(chain_id);
        return r;
    }
    // The weakest label behind anything in this reply. Never `verified`: neither method is
    // proof-backed, so nothing fetched here may wear a verified badge.
    let labels: Vec<Option<&str>> = routes.iter().map(|r| r.as_deref()).collect();
    out["route"] = json!(verified::weakest_route(&labels));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0x9a3c000000000000000000000000000000000000000000000000000000000001";

    fn block() -> Leg {
        Ok((json!({ "number": 25_882_523, "timestamp": 1_756_612_345u64 }), Some("direct".into())))
    }

    fn tx() -> Leg {
        Ok((json!({ "gasLimit": 51_000, "maxPriorityFeePerGas": "1000000000" }),
            Some("proxied".into())))
    }

    #[test]
    fn both_legs_landing_gives_both_halves_and_the_weakest_label_over_them() {
        let v = details_reply(HASH, 1, 1_756_700_000, block(), Some(tx()));
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["hash"], json!(HASH));
        assert_eq!(v["chainId"], json!(1));
        assert_eq!(v["block"]["timestamp"], json!(1_756_612_345u64));
        assert_eq!(v["transaction"]["gasLimit"], json!(51_000));
        assert_eq!(v["gasPriceUnit"], json!("gwei"));
        assert_eq!(v["route"], json!("direct"), "a reply is only as proved as its weakest part");
        assert!(v.get("blockError").is_none() && v.get("transactionError").is_none());
    }

    /// PARTIAL FAILURE IS NORMAL. The two calls are independent, so a block read that timed
    /// out must not withhold a priority fee that landed — and the leg that failed carries its
    /// own reason beside the fields it could not fill.
    #[test]
    fn one_leg_failing_alone_is_still_an_answer() {
        let v = details_reply(HASH, 1, 0, Err("request timed out after 3s".into()), Some(tx()));
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["blockError"], json!("request timed out after 3s"));
        assert_eq!(v["transaction"]["maxPriorityFeePerGas"], json!("1000000000"));
        assert!(v.get("block").is_none(), "no block, not an invented one");

        let v = details_reply(HASH, 1, 0, block(), Some(Err("no such transaction".into())));
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["transactionError"], json!("no such transaction"));
        assert!(v.get("transaction").is_none());
    }

    /// A leg that was never MADE is not a leg that failed: the row already stored what it
    /// would have answered, and reporting an error there would send the user chasing one.
    #[test]
    fn a_skipped_leg_is_neither_a_failure_nor_an_empty_field() {
        let v = details_reply(HASH, 1, 0, block(), None);
        assert_eq!(v["ok"], json!(true));
        assert!(v.get("transaction").is_none());
        assert!(v.get("transactionError").is_none());
        assert_eq!(v["route"], json!("direct"), "only the leg that ran labels the reply");

        // ...and with the only leg that ran having failed, there is nothing to report.
        let v = details_reply(HASH, 1, 0, Err("request timed out after 3s".into()), None);
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["error"], json!("request timed out after 3s"));
    }

    /// EVERY reply names its transaction, refusals included. Without it a message rendered
    /// beside one transaction's rows lands under whichever one is on screen when it arrives.
    #[test]
    fn every_reply_names_the_transaction_it_is_about() {
        let replies = [
            details_reply(HASH, 1, 0, block(), Some(tx())),
            details_reply(HASH, 1, 0, Err("a".into()), Some(tx())),
            details_reply(HASH, 1, 0, Err("a".into()), Some(Err("b".into()))),
            details_reply(HASH, 1, 0, Err("a".into()), None),
            details_refusal(HASH, "no recorded transaction with that hash"),
        ];
        for v in replies {
            assert_eq!(v["hash"], json!(HASH), "{v}");
        }
    }

    /// A row recorded before `tx_input` existed has one way to learn its calldata, and while
    /// the skip asked about the fee fields alone that leg was never made for it again.
    #[test]
    fn a_row_that_never_knew_its_calldata_still_makes_the_transaction_leg() {
        let stored = TxRecord {
            gas_limit: Some(51_000),
            max_priority_fee_per_gas: Some("1000000000".into()),
            tx_input: Some("0x".into()),
            ..Default::default()
        };
        assert!(!transaction_leg_needed(&stored), "the row stores every answer it would bring");
        assert!(transaction_leg_needed(&TxRecord { tx_input: None, ..stored.clone() }));
        assert!(transaction_leg_needed(&TxRecord { gas_limit: None, ..stored }));
    }

    #[test]
    fn both_legs_failing_is_a_refusal_carrying_the_first_reason() {
        let v = details_reply(HASH, 11_155_111, 0, Err("block: timed out".into()),
                              Some(Err("tx: timed out".into())));
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["chainId"], json!(11_155_111));
        assert_eq!(v["error"], json!("block: timed out"));
        assert!(v.get("route").is_none(), "nothing was read, so nothing may be labelled");
    }
}
