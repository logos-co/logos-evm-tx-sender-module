//! A failed outbound call as a clause a person can read, beside the code a caller acts on.
//! Pure, so `cargo test --no-default-features` covers the wording.

use std::time::Duration;

use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub code: String,
    pub why: String,
}

impl Failure {
    /// The reply `err` sends on whole: `Couldn't <what>: <why>.`, with the code beside it.
    pub fn reply(&self, what: &str) -> String {
        json!({ "ok": false, "code": self.code, "error": format!("Couldn't {what}: {}.", self.why) }).to_string()
    }
}

/// Who answers a chain's reads: its RPC endpoint, or the verified proxy in front of it.
pub fn endpoint(name: &str, verified: bool) -> String {
    if verified { format!("{name}'s verified proxy") } else { format!("{name}'s RPC endpoint") }
}

/// "8 s", "2.5 s".
pub fn secs(d: Duration) -> String {
    let tenths = (d.as_millis() + 50) / 100;
    if tenths % 10 == 0 { format!("{} s", tenths / 10) } else { format!("{}.{} s", tenths / 10, tenths % 10) }
}

/// The SDK's own failure calling `module`, whose message is the runtime's `{ code, message }`.
/// A timeout is `who` not answering within `within`.
pub fn transport(message: &str, module: &str, who: &str, within: Duration) -> Failure {
    let v: Value = serde_json::from_str(message).unwrap_or(Value::Null);
    let code = v.get("code").and_then(Value::as_str).unwrap_or("transport").to_string();
    if code == "timeout" {
        return Failure { code, why: format!("{who} didn't answer within {}", secs(within)) };
    }
    let detail = v.get("message").and_then(Value::as_str).unwrap_or(message);
    Failure { code, why: format!("{module} could not be asked ({detail})") }
}

/// eth_rpc's refusal `{ ok: false, code, error }`, or `None` for anything else.
pub fn refusal(reply: &str, endpoint: &str, rt: Duration) -> Option<Failure> {
    let v: Value = serde_json::from_str(reply).ok()?;
    if v.get("ok").and_then(Value::as_bool) != Some(false) {
        return None;
    }
    let code = v.get("code").and_then(Value::as_str).unwrap_or("rpc").to_string();
    let why = if code == "timeout" {
        format!("{endpoint} didn't answer within {}", secs(rt))
    } else {
        v.get("error").and_then(Value::as_str).unwrap_or("eth_rpc call failed").to_string()
    };
    Some(Failure { code, why })
}

/// Refused before it started: what was left could not hold one round trip.
pub fn no_time(left: Duration, endpoint: &str, rt: Duration) -> Failure {
    Failure {
        code: "not_enough_time".into(),
        why: format!("only {} of this request's time was left, and {endpoint} is allowed {} per call",
                     secs(left), secs(rt)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINT: &str = "Ethereum's RPC endpoint";

    /// The demo's review dialog, verbatim: the fee pass ran out under the sender.
    #[test]
    fn a_transport_timeout_names_who_did_not_answer() {
        let m = r#"{"code":"timeout","message":"call to 'fee_module.estimate_bundle' timed out after 6000ms","origin":"fee_module"}"#;
        let f = transport(m, "fee_module", "the fee module", Duration::from_secs(6));
        assert_eq!(f.reply("estimate the fee"),
                   r#"{"code":"timeout","error":"Couldn't estimate the fee: the fee module didn't answer within 6 s.","ok":false}"#);
        let other = transport(r#"{"code":"not_loaded","message":"no such module"}"#, "fee_module", "x", Duration::ZERO);
        assert_eq!(other.why, "fee_module could not be asked (no such module)");
    }

    #[test]
    fn eth_rpcs_own_refusal_keeps_its_code_and_its_words() {
        let t = refusal(r#"{"ok":false,"code":"timeout","error":"no answer within 8000ms: x"}"#, ENDPOINT, Duration::from_secs(8));
        assert_eq!(t.unwrap().why, "Ethereum's RPC endpoint didn't answer within 8 s");
        let r = refusal(r#"{"ok":false,"code":"http","error":"http: refused"}"#, ENDPOINT, Duration::from_secs(8)).unwrap();
        assert_eq!((r.code.as_str(), r.why.as_str()), ("http", "http: refused"));
        assert_eq!(refusal(r#"{"ok":true,"result":"0x1"}"#, ENDPOINT, Duration::from_secs(8)), None);
    }

    #[test]
    fn a_refusal_before_the_call_says_what_was_left_and_what_one_call_needs() {
        let f = no_time(Duration::from_millis(1_408), ENDPOINT, Duration::from_secs(8));
        assert_eq!(f.reply("read the nonce"),
                   r#"{"code":"not_enough_time","error":"Couldn't read the nonce: only 1.4 s of this request's time was left, and Ethereum's RPC endpoint is allowed 8 s per call.","ok":false}"#);
        assert_eq!(endpoint("chain 31337", true), "chain 31337's verified proxy");
    }
}
