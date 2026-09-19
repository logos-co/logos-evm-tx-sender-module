//! Where a send LANDS when the verified gate closes between `send` and the poll that would
//! have broadcast it.
//!
//! The window is minutes wide: `send` passes the gate, a human takes their time in the
//! signer, and by the time the poll comes back with signatures the proxy may be unusable or
//! the mode may have flipped to `required`. `advance_send` refuses there — but the refusal is
//! the delicate part, because by then the keystore has handed back signatures over specific
//! nonces, and this module's whole design is a write-ahead record plus held numbers.
//!
//! So the refusal touches the ledger not at all: no claim, no record, no settle. The job
//! stays `awaitingApproval` with its nonces reserved, which is what the tests below name one
//! property at a time — including the one that shows what settling it `Failed` instead
//! would have cost.
//!
//! `glue.rs` is behind the `logos_module` feature and is read as source elsewhere. What is
//! driven here is `SendLedger` itself, which `cargo test` does compile: the refusal is
//! modelled as what it is — the ledger being left alone.

use serde_json::Value;
use tx_sender_module::send::{BroadcastClaim, Leg, SendJob, SendLedger, SendStatus};

const CHAIN: u64 = 1;
const ACC: &str = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
const ID: &str = "snd_1";
/// What the chain reports at `latest`. It does not move: a broadcast that has not mined does
/// not count, which is why a nonce is reserved at all.
const LATEST: u64 = 5;
const NOW: u64 = 1_700_000_000;

fn leg(nonce: u64) -> Leg {
    Leg {
        to: "0xbbbb".into(),
        value: "1".into(),
        data: "0x".into(),
        gas_limit: 21_000,
        nonce,
        label: String::new(),
        meta: Value::Null,
        fee_ceiling_wei: None,
        hash: None,
        left: false,
    }
}

fn job(request_id: &str, nonces: &[u64]) -> SendJob {
    SendJob {
        request_id: request_id.into(),
        handle: "ksh_1".into(),
        receipt: "ksc_1".into(),
        chain_id: CHAIN,
        from: ACC.into(),
        legs: nonces.iter().map(|n| leg(*n)).collect(),
        max_fee: "1".into(),
        max_priority: "1".into(),
        purpose: String::new(),
        origin: String::new(),
        status: SendStatus::AwaitingApproval,
        broadcast: None,
        replaces: None,
    }
}

/// One bundle of `count` calls priced, its nonces reserved and its job committed —
/// `request_send` in full. Answers the numbers it took.
fn requested(l: &SendLedger, request_id: &str, count: usize) -> Vec<u64> {
    let g = l.open(CHAIN, ACC, LATEST, count, None).expect("a claim");
    let nonces = g.claim().nonces.clone();
    g.commit(job(request_id, &nonces));
    nonces
}

/// The state itself, named. All three halves are load-bearing: non-terminal so a poll comes
/// back, unclaimed so `cancel_send` is still open, reserved so nothing else takes the numbers
/// the signatures in hand are over.
#[test]
fn a_send_the_gate_refused_is_still_a_live_send() {
    let l = SendLedger::default();
    assert_eq!(requested(&l, ID, 2), vec![LATEST, LATEST + 1]);

    // The refusal: `advance_send` returns having touched nothing.
    let j = l.get(ID).expect("the job is still there");
    assert_eq!(j.reported_status(NOW), "awaitingApproval");
    assert!(!j.broadcast_started(), "nothing was claimed, so nothing may have left");
    assert!(!j.status.is_terminal(), "a closed gate is not an outcome");
    assert!(!j.is_final(NOW), "so the held reply tells the poller to come back");
    assert_eq!(l.outstanding(CHAIN, ACC), 2, "the numbers the signatures are over stay held");
    assert_eq!(l.live(NOW).len(), 1, "and a consumer still sees it as live");
}

/// Why it must not be reported as a failure, in the only terms that matter. The signatures
/// the keystore handed back are over THESE nonces and the send can still go out on a later
/// poll, so a `Failed` here gives 5 away while a transaction signed at 5 is still waiting.
#[test]
fn failing_the_send_would_hand_its_nonces_to_the_next_one() {
    let l = SendLedger::default();
    assert_eq!(requested(&l, ID, 1), vec![LATEST]);

    let reason = "the verified proxy is not usable".to_string();
    l.settle(ID, SendStatus::Failed { reason }).expect("the job");
    assert_eq!(l.outstanding(CHAIN, ACC), 0, "a failed send lets go of its number");
    assert_eq!(requested(&l, "snd_2", 1), vec![LATEST], "and the next send takes the very same one");
}

/// The resumption. The proxy comes back, the next poll re-reads the approval, re-fetches the
/// signatures and claims the broadcast — on the same numbers, because nothing let go of
/// them. A send started in the meantime queued behind it rather than colliding with it.
#[test]
fn the_next_poll_sends_it_once_the_gate_reopens() {
    let l = SendLedger::default();
    assert_eq!(requested(&l, ID, 2), vec![LATEST, LATEST + 1]);
    assert_eq!(requested(&l, "snd_2", 1), vec![LATEST + 2]);

    let BroadcastClaim::Claimed(t) = l.claim_broadcast(ID, NOW) else {
        panic!("a held send must still be claimable once the gate reopens")
    };
    l.leaving(&t, 0).unwrap();
    l.leaving(&t, 1).unwrap();
    let s = l
        .settle_owned(&t, SendStatus::Broadcast { hash: "0xdead".into(), route: "proxied".into() })
        .expect("the ticket owns this job");
    assert!(s.changed);
    assert_eq!(s.job.nonces(), vec![LATEST, LATEST + 1], "the numbers it was signed at");
    assert_eq!(l.outstanding(CHAIN, ACC), 3, "burnt rather than released, for ever");
}

/// And the way out while it is held. Nothing claimed the broadcast, so cancelling is still
/// open — which is what stops a proxy that never comes back from wedging the account, and is
/// the door a `Failed` would have closed by settling the job behind the user's back.
#[test]
fn a_held_send_can_still_be_cancelled() {
    let l = SendLedger::default();
    assert_eq!(requested(&l, ID, 2), vec![LATEST, LATEST + 1]);

    let j = l.claim_cancel(ID).expect("a send that has not broadcast is cancellable");
    assert_eq!(j.status, SendStatus::Cancelled);
    assert_eq!(l.outstanding(CHAIN, ACC), 0, "and both numbers go back, because nothing left");
}
