//! The parts of an `eth_rpc_module` reply this wallet must not get wrong: the envelope and
//! its route label, the verified-proxy verdict, and how a blocking one is disclosed.
//!
//! `eth_rpc_module` owns the verdict and the label; nothing here invents either. These
//! decisions live outside `glue.rs` so `cargo test --no-default-features` covers them.

use serde_json::{json, Value};

/// What an `eth_rpc` call answered, and how it got the answer.
pub struct Answer {
    pub value: Value,
    /// eth_rpc's own label: `verified` is proof-backed, `proxied` was forwarded to the
    /// proxy's provider on trust, `direct` never touched the proxy. `None` = unlabelled.
    pub route: Option<String>,
}

/// Most replies are `{ ok, result }`, but a broadcast answers `{ ok, hash }` — reading only
/// `result` there loses the hash of a transaction that already moved money. Accept both, and
/// keep `route` beside the value: dropping it makes a fee indistinguishable from a balance.
pub fn unwrap_answer(reply: &str) -> Result<Answer, String> {
    let v: Value = serde_json::from_str(reply).map_err(|e| e.to_string())?;
    if v.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(v
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("eth_rpc call failed")
            .to_string());
    }
    Ok(Answer {
        value: v.get("result").or_else(|| v.get("hash")).cloned().unwrap_or(Value::Null),
        route: v.get("route").and_then(Value::as_str).map(str::to_string),
    })
}

/// The value alone, for the receipt polls whose route no reply reports.
pub fn unwrap_rpc(reply: &str) -> Result<Value, String> {
    unwrap_answer(reply).map(|a| a.value)
}

/// The verdict to use when `eth_rpc` cannot be reached or answers a shape we cannot read.
/// Unknown is treated as bad: defaulting to `off` here is the false assurance in a new costume.
pub fn unknown_verdict(chain_id: u64, why: &str) -> Value {
    json!({
        "ok": false, "error": why, "chainId": chain_id,
        "mode": "unknown", "state": "unhealthy", "usable": false, "blocking": true,
        "message": "The verified-proxy state could not be read.",
        "action": "restart_or_reload", "detail": why,
    })
}

/// A verdict is readable only when it carries BOTH a `state` and a boolean `blocking`.
/// One without the other is not a partly-good verdict, it is a shape we cannot act on.
pub fn readable(v: &Value) -> bool {
    v.get("state").and_then(Value::as_str).is_some()
        && v.get("blocking").and_then(Value::as_bool).is_some()
}

/// `raw` when it is readable, else a blocking unknown verdict carrying `raw`'s own error.
pub fn normalize(chain_id: u64, raw: &Value) -> Value {
    if readable(raw) {
        return raw.clone();
    }
    let why = raw
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("eth_rpc returned no usable verdict");
    unknown_verdict(chain_id, why)
}

/// Whether this verdict closes the gate. Only an explicit `blocking: false` opens it — a
/// verdict that does not say is one we did not understand, and the gate fails closed.
pub fn is_blocking(v: &Value) -> bool {
    v.get("blocking").and_then(Value::as_bool) != Some(false)
}

/// What we call an answer `eth_rpc` did not label. Ranks below every real route.
pub const UNKNOWN_ROUTE: &str = "unknown";

/// How strongly an answer was proved: `verified` (proof-backed) beats `proxied` (forwarded
/// by the proxy on trust) beats `direct` (never touched it) beats unlabelled.
fn rank(label: &str) -> u8 {
    match label {
        "verified" => 3,
        "proxied" => 2,
        "direct" => 1,
        _ => 0,
    }
}

/// The weakest label among `labels` — a reply is only as proved as its least-proved part,
/// so a badge built on this can never over-claim.
pub fn weakest_route(labels: &[Option<&str>]) -> String {
    labels
        .iter()
        .map(|l| l.unwrap_or(UNKNOWN_ROUTE))
        .min_by_key(|l| rank(l))
        .filter(|l| rank(l) > 0)
        .unwrap_or(UNKNOWN_ROUTE)
        .to_string()
}

/// A send the gate is holding: the job's own reply, plus why it did not go out.
///
/// `ok` stays TRUE and the status is untouched. A poller reads `ok: false` as a failed send —
/// it drops the request id and stops polling — and that would orphan a job which is still
/// holding its nonce and can still go out once the proxy is usable again. This says "not
/// yet", in the one shape that keeps the poll coming back.
pub fn held_by_the_gate(reply: &Value, verdict: &Value) -> Value {
    let mut v = reply.clone();
    v["blocked"] = json!(true);
    v["reason"] = json!(verdict
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("the verified proxy is not usable"));
    v["verifiedProxy"] = verdict.clone();
    v
}

/// One chain whose blocking proxy froze rows during a sweep: what it cost, which rows, and
/// the verdict that says why. A row on a NON-active chain is explainable nowhere else —
/// the view's banner is keyed on the active chain and never mentions this one.
pub fn blocked_chain_json(chain_id: u64, network: &str, hashes: &[String], verdict: &Value) -> Value {
    let s = |k: &str| verdict.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    json!({
        "chainId": chain_id,
        "network": network,
        "count": hashes.len(),
        "hashes": hashes,
        "message": s("message"),
        "action": s("action"),
        "verifiedProxy": verdict,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one shape `unknown_verdict` did not check. `state` alone used to open every gated
    /// method, which is the fail-closed rule failing exactly where it exists to hold.
    #[test]
    fn a_verdict_that_does_not_say_it_is_blocking_is_treated_as_blocking() {
        let no_flag = json!({ "ok": true, "chainId": 1, "state": "ready", "usable": true });
        assert!(!readable(&no_flag));
        assert!(is_blocking(&normalize(1, &no_flag)));
        assert_eq!(normalize(1, &no_flag)["state"], json!("unhealthy"));

        // Not a bool either: a string is a shape we did not understand.
        assert!(is_blocking(&normalize(1, &json!({ "state": "ready", "blocking": "false" }))));
        assert!(is_blocking(&json!({})));
    }

    #[test]
    fn only_an_explicit_blocking_false_opens_the_gate() {
        let open = json!({ "state": "ready", "usable": true, "blocking": false });
        assert!(readable(&open));
        assert!(!is_blocking(&open));
        assert_eq!(normalize(1, &open), open, "a readable verdict is passed through whole");

        assert!(is_blocking(&json!({ "state": "unhealthy", "blocking": true })));
    }

    #[test]
    fn an_unreadable_verdict_keeps_the_reason_eth_rpc_gave() {
        let v = normalize(7, &json!({ "ok": false, "error": "no configuration for chain 7" }));
        assert_eq!(v["error"], json!("no configuration for chain 7"));
        assert_eq!(v["detail"], json!("no configuration for chain 7"));
        assert_eq!(v["chainId"], json!(7));
        assert!(is_blocking(&v));
    }

    #[test]
    fn an_envelope_gives_up_both_its_value_and_its_route() {
        // send_raw_transaction answers `{ok, hash}` while every other method answers
        // `{ok, result}`. Reading only `result` loses the hash of a transaction that has
        // already moved money.
        let a = unwrap_answer(r#"{"ok":true,"hash":"0xabc","route":"proxied"}"#).unwrap();
        assert_eq!((a.value, a.route.as_deref()), (json!("0xabc"), Some("proxied")));
        let a = unwrap_answer(r#"{"ok":true,"result":"0x2a","route":"verified"}"#).unwrap();
        assert_eq!((a.value, a.route.as_deref()), (json!("0x2a"), Some("verified")));

        // An eth_rpc that predates the label leaves it absent rather than guessing one.
        assert_eq!(unwrap_answer(r#"{"ok":true,"result":"0x2a"}"#).unwrap().route, None);
        assert_eq!(unwrap_rpc(r#"{"ok":true,"result":"0x2a"}"#).unwrap(), json!("0x2a"));
    }

    #[test]
    fn an_envelope_surfaces_the_inner_error_not_a_generic_one() {
        let e = unwrap_rpc(r#"{"ok":false,"error":"no configuration for chain 7"}"#).unwrap_err();
        assert_eq!(e, "no configuration for chain 7");
        assert!(unwrap_rpc("not json").is_err());
        // A failure carries no route, and nothing may invent one for it.
        assert!(unwrap_answer(r#"{"ok":false,"route":"verified"}"#).is_err());
    }

    #[test]
    fn a_reply_is_only_as_proved_as_its_least_proved_part() {
        assert_eq!(weakest_route(&[Some("verified")]), "verified");
        assert_eq!(weakest_route(&[Some("verified"), Some("proxied")]), "proxied");
        assert_eq!(weakest_route(&[Some("verified"), Some("direct")]), "direct");
        // An unlabelled contributor cannot be badged, so the whole reply cannot be.
        assert_eq!(weakest_route(&[Some("verified"), None]), UNKNOWN_ROUTE);
        assert_eq!(weakest_route(&[Some("nonsense")]), UNKNOWN_ROUTE);
        assert_eq!(weakest_route(&[]), UNKNOWN_ROUTE);
    }

    /// A gate that closes while a human is approving must not read as a failed send: the
    /// transaction never left, the nonce is still reserved, and the next poll can send it.
    #[test]
    fn a_send_the_gate_is_holding_is_still_a_live_send() {
        let job = json!({ "ok": true, "requestId": "snd_1", "status": "awaitingApproval" });
        let verdict = json!({ "state": "unhealthy", "blocking": true, "action": "restart_or_reload",
                              "message": "The verified proxy is not usable." });
        let held = held_by_the_gate(&job, &verdict);
        assert_eq!(held["ok"], json!(true), "`ok: false` is what orphans the job");
        assert_eq!(held["status"], json!("awaitingApproval"), "and what keeps the poll coming");
        assert_eq!(held["requestId"], json!("snd_1"));
        assert_eq!(held["blocked"], json!(true));
        assert_eq!(held["reason"], json!("The verified proxy is not usable."));
        assert_eq!(held["verifiedProxy"], verdict, "the whole verdict, so nothing is re-derived");

        // A verdict with no sentence of its own still says something a view can render.
        let bare = held_by_the_gate(&job, &json!({ "blocking": true }));
        assert!(bare["reason"].as_str().is_some_and(|r| !r.is_empty()));
    }

    #[test]
    fn a_blocked_chain_entry_names_the_frozen_rows_and_carries_the_verdict() {
        let verdict = json!({ "state": "unhealthy", "blocking": true, "action": "restart_or_reload",
                              "message": "The verified proxy is running but not tracking the chain." });
        let e = blocked_chain_json(11_155_111, "Sepolia", &["0xaaa".into(), "0xbbb".into()], &verdict);
        assert_eq!(e["chainId"], json!(11_155_111));
        assert_eq!(e["network"], json!("Sepolia"));
        assert_eq!(e["count"], json!(2));
        assert_eq!(e["hashes"], json!(["0xaaa", "0xbbb"]));
        assert_eq!(e["action"], json!("restart_or_reload"));
        assert!(e["message"].as_str().unwrap().contains("not tracking"));
        assert_eq!(e["verifiedProxy"], verdict, "the whole verdict, so nothing is re-derived");
    }
}
