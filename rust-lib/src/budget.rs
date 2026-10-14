//! Aggregate call budgets.
//!
//! A per-call timeout bounds one round-trip. A method that makes eight of them is bounded
//! only by their SUM, which is what the user actually waits. A `Budget` is ONE allowance
//! shared by every call on one entry point.
//!
//! The arithmetic lives here, clock-free, so `cargo test --no-default-features` covers it.

use std::time::{Duration, Instant};

/// Per-call caps. Reading a dependency's config or its metadata is local work; registering
/// an approval is a signer manager write — 5s is slack, not a working number.
pub const PROBE_BUDGET: Duration = Duration::from_millis(1500);
pub const INIT_BUDGET: Duration = Duration::from_secs(5);

/// One JSON-RPC round trip through `eth_rpc`, one `fee_module` estimate, or one signer
/// manager read. This crosses a network, so 3s is a working number rather than slack.
pub const RPC_BUDGET: Duration = Duration::from_secs(3);

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

/// A send's own outbound work: the verified gate, one `fee_module` bundle estimate, the
/// balance and nonce reads, and registering the approval. Sized so a two-leg bundle through
/// the verified proxy prices (one estimate measured 4.6 s, 2026-10-14); a caller in a hurry
/// hands over its own `deadlineMs` and this shrinks to it.
pub const SEND_BUDGET: Duration = Duration::from_secs(33);

/// The most `fee_module` spends on one bundle: its own default budget.
pub const FEE_BUDGET: Duration = Duration::from_secs(20);
/// What a quote does after pricing: the balance and the nonce.
pub const AFTER_PRICING: Duration = Duration::from_secs(6);
/// What a send does after its quote: the approval request.
pub const AFTER_QUOTE: Duration = INIT_BUDGET;

/// The fee pass gets what `after` leaves of `left`, but never less than a slice per leg
/// plus one (what it had before), and never more than `fee_module` would use.
pub fn fee_cap(left: Duration, legs: usize, after: Duration) -> Duration {
    left.saturating_sub(after).max(RPC_BUDGET * (legs as u32 + 1)).min(FEE_BUDGET)
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

    /// A send: the gate, the fee pass, the balance, the nonce, then the approval request.
    #[test]
    fn a_send_whose_every_call_takes_its_full_grant_still_reaches_the_approval() {
        for legs in [1, 2, crate::send::MAX_LEGS] {
            let fee = fee_cap(SEND_BUDGET - PROBE_BUDGET, legs, AFTER_PRICING + AFTER_QUOTE);
            assert_eq!(fee, FEE_BUDGET, "{legs} legs: the fee pass gets all fee_module would use");
            let calls = [PROBE_BUDGET, fee, RPC_BUDGET, RPC_BUDGET, INIT_BUDGET];
            assert!(calls.iter().sum::<Duration>() <= SEND_BUDGET, "{legs} legs");
            assert_eq!(walk(SEND_BUDGET, &calls), calls.iter().sum::<Duration>());
        }
        assert_eq!(AFTER_PRICING, RPC_BUDGET * 2);
    }

    /// eth_wallet_backend hands over 8.7 s: the fee pass keeps the slice it always had.
    #[test]
    fn a_short_deadline_keeps_the_old_per_leg_slice() {
        let left = Duration::from_millis(8_700) - PROBE_BUDGET;
        assert_eq!(fee_cap(left, 1, AFTER_PRICING), RPC_BUDGET * 2);
        assert_eq!(fee_cap(Duration::from_secs(16), 1, AFTER_PRICING), Duration::from_secs(10));
        assert_eq!(fee_cap(Duration::ZERO, 2, AFTER_PRICING), RPC_BUDGET * 3, "take() still cuts it to what is left");
    }

    /// The caller's own deadline cuts the allowance and never grows it.
    #[test]
    fn a_callers_deadline_shrinks_the_allowance_and_a_bad_one_is_ignored() {
        let b = Budget::bounded_by(SEND_BUDGET, Some(2_000));
        assert_eq!(b.total, Duration::from_secs(2));
        assert_eq!(Budget::bounded_by(SEND_BUDGET, Some(60_000)).total, SEND_BUDGET);
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
