//! Aggregate call budgets.
//!
//! A per-call timeout bounds one round-trip. A method that makes eight of them is bounded
//! only by their SUM, which is what the user actually waits. A `Budget` is ONE allowance
//! shared by every call on one entry point.
//!
//! The arithmetic lives here, clock-free, so `cargo test --no-default-features` covers it.

use std::time::{Duration, Instant};

use serde_json::Value;

/// Per-call caps. Reading a dependency's config or its metadata is local work; registering
/// an approval is a signer manager write — 5s is slack, not a working number.
pub const PROBE_BUDGET: Duration = Duration::from_millis(1500);
pub const INIT_BUDGET: Duration = Duration::from_secs(5);

/// One JSON-RPC round trip through `eth_rpc` off the send path, or one signer manager read.
/// This crosses a network, so 3s is a working number rather than slack.
pub const RPC_BUDGET: Duration = Duration::from_secs(3);

/// One round trip on a chain when eth_rpc cannot say: its default `timeoutSecs`.
pub const DEFAULT_ROUND_TRIP: Duration = Duration::from_secs(8);

/// One round trip on a chain, from eth_rpc's `get_chain_config`: the `timeoutSecs` the user
/// set, or `verifiedTimeoutSecs` when its reads go through the verified proxy.
pub fn round_trip(config: &Value) -> Duration {
    let verified = config.get("verifiedProxyMode").and_then(Value::as_str) == Some("required");
    let (key, default) = if verified { ("verifiedTimeoutSecs", 15) } else { ("timeoutSecs", 8) };
    let secs = config.get(key).and_then(Value::as_u64).filter(|s| *s > 0).unwrap_or(default);
    Duration::from_secs(secs.clamp(1, 60))
}

/// The transport for one eth_rpc read on a chain whose round trip is `rt`: all of it, plus
/// the margin eth_rpc's own refusal needs to come home.
pub fn rpc_slice(rt: Duration) -> Duration {
    rt + CALLEE_MARGIN
}

/// The deadline to hand a callee that this caller will wait `transport` for.
///
/// Shorter than the transport bound on purpose. The two clocks start together, so a callee
/// given the SAME budget finishes exactly as the caller stops listening, and its error
/// sentence -- the one naming which endpoint failed and why -- is lost to a bare timeout.
/// The margin buys the reply its trip home.
///
/// None when there is not enough left to be worth bounding: below `MIN_SLICE` the callee
/// would spend its whole allowance failing, so it is better told nothing and left to its own
/// default than handed a deadline it cannot meet.
pub fn callee_deadline(transport: Duration) -> Option<i64> {
    transport
        .checked_sub(CALLEE_MARGIN)
        .filter(|d| *d >= MIN_SLICE)
        .map(|d| d.as_millis() as i64)
}

const CALLEE_MARGIN: Duration = Duration::from_millis(300);

/// The most a send's own outbound work may take on any chain: the verified gate, the chain's
/// config, one `fee_module` bundle estimate, the balance and nonce reads, and registering the
/// approval. Each read gets the chain's own round trip, so a two-leg verified bundle at the
/// default 15 s fits; a caller in a hurry hands over its own `deadlineMs` and this shrinks to it.
pub const SEND_BUDGET: Duration = Duration::from_secs(120);

/// The least `fee_module` spends on one bundle when it has no deadline: its own default.
pub const FEE_BUDGET: Duration = Duration::from_secs(20);

/// What a step still has to do once the one before it is back: round trips on the chain, and
/// local work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct After {
    pub round_trips: u32,
    pub local: Duration,
}

impl After {
    pub fn on(self, rt: Duration) -> Duration {
        rpc_slice(rt) * self.round_trips + self.local
    }
}

impl std::ops::Add for After {
    type Output = After;
    fn add(self, o: After) -> After {
        After { round_trips: self.round_trips + o.round_trips, local: self.local + o.local }
    }
}

/// What a quote does after pricing: the balance and the nonce.
pub const AFTER_PRICING: After = After { round_trips: 2, local: Duration::ZERO };
/// What a send does after its quote: the approval request.
pub const AFTER_QUOTE: After = After { round_trips: 0, local: INIT_BUDGET };

/// The round trips `fee_module` may make on one bundle: the history, a tip, and an estimate
/// and an allowance probe per leg after the first.
pub fn fee_rounds(legs: usize) -> u32 {
    2 * legs as u32 + 1
}

/// The least a fee pass is started on: the history and one estimate per leg, each whole.
pub fn fee_floor(rt: Duration, legs: usize) -> Duration {
    rpc_slice(rt) * (legs as u32 + 1) + CALLEE_MARGIN
}

/// The fee pass gets what `after` leaves of `left`, but never less than its floor, and never
/// more than `fee_module` would use: its own default, grown to the chain's round trip.
pub fn fee_cap(left: Duration, legs: usize, after: Duration, rt: Duration) -> Duration {
    let most = FEE_BUDGET.max(rpc_slice(rt) * fee_rounds(legs)) + CALLEE_MARGIN;
    left.saturating_sub(after).max(fee_floor(rt, legs)).min(most)
}

/// One `live_sends` or ledger read: no call at all, but every entry point takes a budget so
/// the shape stays uniform.
pub const READ_BUDGET: Duration = Duration::from_secs(4);

/// One receipt sweep: up to `SWEEP_MAX` receipts, plus a verdict and a mined-nonce read per
/// distinct chain.
pub const SWEEP_BUDGET: Duration = Duration::from_secs(10);

/// One `tx_details`: the verified gate, the block header and, for a row that does not
/// already store them, the transaction's own fields. A user is waiting on a button for all
/// three, so the gate is INSIDE this — an aggregate that starts after the longest call in
/// the method bounds nothing a user can feel.
pub const DETAILS_BUDGET: Duration = Duration::from_secs(8);

/// One `refresh_tx_status`: the verified gate and one receipt read, both on a button.
pub const REFRESH_BUDGET: Duration = Duration::from_secs(5);

/// Below this a grant buys nothing, and the protocol ABI refuses a sub-millisecond bound
/// outright. The last sliver of an allowance goes on answering, not on one more call.
pub const MIN_SLICE: Duration = Duration::from_millis(50);

/// A shrinking allowance shared by every outbound call on one entry point.
pub struct Budget {
    started: Instant,
    total: Duration,
}

impl Budget {
    pub fn new(total: Duration) -> Self {
        Self { started: Instant::now(), total }
    }

    /// An allowance no larger than `total`, cut to what a caller said it will wait. A
    /// caller's deadline of zero or less is no deadline.
    pub fn bounded_by(total: Duration, deadline_ms: Option<i64>) -> Self {
        let total = match deadline_ms {
            Some(ms) if ms > 0 => total.min(Duration::from_millis(ms as u64)),
            _ => total,
        };
        Self::new(total)
    }

    /// What the next call may spend, or `None` once too little is left to be worth a
    /// round-trip. Charged against real elapsed time, so a call that returned early costs
    /// what it took rather than what it was granted.
    pub fn take(&self, per_call: Duration) -> Option<Duration> {
        slice(self.total, self.started.elapsed(), per_call)
    }

    pub fn left(&self) -> Duration {
        self.total.saturating_sub(self.started.elapsed())
    }

    /// Up to `cap`, but only when at least `min` is left; `Err` is what was left. A read started
    /// on less than the chain's own timeout is cut short by us rather than by the endpoint.
    pub fn take_whole(&self, min: Duration, cap: Duration) -> Result<Duration, Duration> {
        whole(self.total, self.started.elapsed(), min, cap)
    }
}

/// [`Budget::take_whole`], clock-free.
pub fn whole(total: Duration, elapsed: Duration, min: Duration, cap: Duration) -> Result<Duration, Duration> {
    let left = total.saturating_sub(elapsed);
    if left < min.max(MIN_SLICE) {
        return Err(left);
    }
    Ok(left.min(cap))
}

/// The whole policy, clock-free. A grant never exceeds what is left, so the grants of any
/// sequence of calls sum to at most `total`.
pub fn slice(total: Duration, elapsed: Duration, per_call: Duration) -> Option<Duration> {
    let grant = total.checked_sub(elapsed)?.min(per_call);
    (grant >= MIN_SLICE).then_some(grant)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spend every grant in full and report what the caller waited.
    fn walk(total: Duration, calls: &[Duration]) -> Duration {
        let mut spent = Duration::ZERO;
        for cap in calls {
            match slice(total, spent, *cap) {
                Some(g) => spent += g,
                None => break,
            }
        }
        spent
    }

    /// The worst case a sweep presents: a verdict and a mined nonce per chain, then
    /// `SWEEP_MAX` receipts.
    #[test]
    fn a_sweep_is_bounded_by_its_total_and_not_by_the_history_length() {
        let mut calls = vec![PROBE_BUDGET; 3];
        calls.extend([RPC_BUDGET; 3 + crate::sweep::SWEEP_MAX]);
        assert!(calls.iter().sum::<Duration>() > SWEEP_BUDGET, "the aggregate must bind");
        assert!(walk(SWEEP_BUDGET, &calls) <= SWEEP_BUDGET);
    }

    /// A send: the gate, the chain's config, the fee pass, the balance, the nonce, then the
    /// approval request — every read whole, on the default timeouts and both routes.
    #[test]
    fn a_send_whose_every_call_takes_its_full_grant_still_reaches_the_approval() {
        for (rt, legs) in [(8, 1), (8, 2), (15, 1), (15, 2)] {
            let rt = Duration::from_secs(rt);
            let after = (AFTER_PRICING + AFTER_QUOTE).on(rt);
            let fee = fee_cap(SEND_BUDGET - PROBE_BUDGET * 2, legs, after, rt);
            let most = FEE_BUDGET.max(rpc_slice(rt) * fee_rounds(legs)) + CALLEE_MARGIN;
            assert_eq!(fee, most, "{rt:?}, {legs} legs: the fee pass gets all fee_module would use");
            let calls = [PROBE_BUDGET, PROBE_BUDGET, fee, rpc_slice(rt), rpc_slice(rt), INIT_BUDGET];
            assert!(calls.iter().sum::<Duration>() <= SEND_BUDGET, "{rt:?}, {legs} legs");
            assert_eq!(walk(SEND_BUDGET, &calls), calls.iter().sum::<Duration>());
        }
    }

    /// The demo: mainnet at `timeoutSecs: 8`, 2-3 s a call. eth_wallet_backend handed over
    /// 8.7 s, the fee pass got 6 s and the nonce read 1.4 s. Now no read starts short.
    #[test]
    fn a_slow_chain_gets_whole_round_trips_or_a_refusal_up_front() {
        let rt = Duration::from_secs(8);
        let left = Duration::from_millis(8_700) - PROBE_BUDGET;
        assert_eq!(fee_cap(left, 1, AFTER_PRICING.on(rt), rt), fee_floor(rt, 1));
        assert_eq!(whole(Duration::from_millis(8_700), Duration::from_millis(1_500), rpc_slice(rt),
                         fee_floor(rt, 1)), Err(Duration::from_millis(7_200)), "refused, not started");
        assert_eq!(whole(Duration::from_secs(40), Duration::from_secs(33), rt, rpc_slice(rt)),
                   Err(Duration::from_secs(7)), "the nonce read is refused on 7 s");
        assert_eq!(whole(Duration::from_secs(40), Duration::from_secs(31), rt, rpc_slice(rt)),
                   Ok(rpc_slice(rt)));
    }

    #[test]
    fn the_round_trip_is_the_chains_own_timeout_on_the_route_it_takes() {
        use serde_json::json;
        assert_eq!(round_trip(&json!({ "timeoutSecs": 8, "verifiedTimeoutSecs": 15 })), Duration::from_secs(8));
        assert_eq!(round_trip(&json!({ "timeoutSecs": 8, "verifiedTimeoutSecs": 15,
                                       "verifiedProxyMode": "required" })), Duration::from_secs(15));
        assert_eq!(round_trip(&Value::Null), DEFAULT_ROUND_TRIP);
        assert_eq!(round_trip(&json!({ "timeoutSecs": 600 })), Duration::from_secs(60));
    }

    /// The caller's own deadline cuts the allowance and never grows it.
    #[test]
    fn a_callers_deadline_shrinks_the_allowance_and_a_bad_one_is_ignored() {
        let b = Budget::bounded_by(SEND_BUDGET, Some(2_000));
        assert_eq!(b.total, Duration::from_secs(2));
        assert_eq!(Budget::bounded_by(SEND_BUDGET, Some(600_000)).total, SEND_BUDGET);
        assert_eq!(Budget::bounded_by(SEND_BUDGET, Some(0)).total, SEND_BUDGET);
        assert_eq!(Budget::bounded_by(SEND_BUDGET, Some(-5)).total, SEND_BUDGET);
        assert_eq!(Budget::bounded_by(SEND_BUDGET, None).total, SEND_BUDGET);
    }

    /// The gate is INSIDE the aggregate for the two button paths.
    #[test]
    fn a_details_read_is_bounded_across_the_gate_in_front_of_it() {
        let calls = [PROBE_BUDGET, RPC_BUDGET, RPC_BUDGET];
        assert!(walk(DETAILS_BUDGET, &calls) <= DETAILS_BUDGET);
        assert!(calls.iter().sum::<Duration>() <= DETAILS_BUDGET, "the gate must fit too");
        assert!(calls.iter().all(|c| slice(DETAILS_BUDGET, Duration::ZERO, *c).is_some()));
    }

    #[test]
    fn a_refresh_is_bounded_across_the_gate_in_front_of_it() {
        let calls = [PROBE_BUDGET, RPC_BUDGET];
        assert!(walk(REFRESH_BUDGET, &calls) <= REFRESH_BUDGET);
        assert!(calls.iter().sum::<Duration>() <= REFRESH_BUDGET, "the gate must fit too");
        assert!(calls.iter().all(|c| slice(REFRESH_BUDGET, Duration::ZERO, *c).is_some()));
    }

    #[test]
    fn no_ordering_or_number_of_calls_can_outlast_the_total() {
        let mut calls = vec![INIT_BUDGET; 4];
        calls.extend([PROBE_BUDGET; 6]);
        calls.reverse();
        assert!(walk(READ_BUDGET, &calls) <= READ_BUDGET);
        calls.extend(vec![MIN_SLICE; 500]);
        assert!(walk(READ_BUDGET, &calls) <= READ_BUDGET);
    }

    #[test]
    fn a_spent_budget_grants_nothing_so_the_sequence_terminates() {
        let mut spent = Duration::ZERO;
        let mut granted: u128 = 0;
        for _ in 0..10_000 {
            let Some(g) = slice(READ_BUDGET, spent, MIN_SLICE) else { break };
            spent += g;
            granted += 1;
        }
        assert_eq!(granted, READ_BUDGET.as_millis() / MIN_SLICE.as_millis());
        assert_eq!(slice(READ_BUDGET, READ_BUDGET, PROBE_BUDGET), None);
        assert_eq!(slice(READ_BUDGET, READ_BUDGET + PROBE_BUDGET, PROBE_BUDGET), None);
    }

    #[test]
    fn a_grant_never_exceeds_the_per_call_cap_or_what_is_left() {
        assert_eq!(slice(READ_BUDGET, Duration::ZERO, PROBE_BUDGET), Some(PROBE_BUDGET));
        assert_eq!(
            slice(READ_BUDGET, Duration::from_secs(3), INIT_BUDGET),
            Some(Duration::from_secs(1))
        );
        let sliver = READ_BUDGET - Duration::from_millis(10);
        assert_eq!(slice(READ_BUDGET, sliver, PROBE_BUDGET), None);
        assert!(matches!(slice(READ_BUDGET, READ_BUDGET - MIN_SLICE, PROBE_BUDGET),
                         Some(g) if g >= MIN_SLICE));
    }

    #[test]
    fn the_clock_backs_the_allowance() {
        let b = Budget::new(READ_BUDGET);
        assert_eq!(b.take(PROBE_BUDGET), Some(PROBE_BUDGET));
        assert_eq!(Budget::new(Duration::ZERO).take(PROBE_BUDGET), None);
    }

    #[test]
    fn a_callee_is_handed_less_than_the_caller_waits() {
        assert_eq!(callee_deadline(Duration::from_secs(3)), Some(2_700));
        assert_eq!(callee_deadline(Duration::from_millis(340)), None, "not worth bounding");
        assert_eq!(callee_deadline(Duration::from_millis(100)), None);
    }
}
