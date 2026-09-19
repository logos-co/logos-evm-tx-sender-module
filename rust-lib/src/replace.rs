//! What a pinned nonce must pay to replace a transaction still pending at that number.
//!
//! Nodes keep a pending transaction unless its replacement pays more on both fee fields, and
//! at least 10% more (geth's default price bump; reth, Nethermind and Erigon agree). A
//! replacement priced at the tier alone is refused whenever the market has not risen 10%.

use alloy::primitives::U256;

use crate::history::{is_unsettled, TxRecord};
use crate::txbuild::parse_u256_any;

/// The highest fee each field offered by any transaction still unsettled at a nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Floor {
    pub max_fee: U256,
    pub max_priority: U256,
}

fn at(rows: &[TxRecord], chain_id: u64, nonce: u64) -> impl Iterator<Item = &TxRecord> {
    rows.iter().filter(move |r| r.chain_id == chain_id && r.nonce == Some(nonce))
}

/// None when nothing this module sent is still pending, or unresolved, at `nonce`.
pub fn floor(rows: &[TxRecord], chain_id: u64, nonce: u64) -> Option<Floor> {
    let wei = |s: &Option<String>| s.as_deref().and_then(parse_u256_any).unwrap_or(U256::ZERO);
    at(rows, chain_id, nonce).filter(|r| is_unsettled(r)).fold(None, |f: Option<Floor>, r| {
        let (fee, tip) = (wei(&r.max_fee_per_gas), wei(&r.max_priority_fee_per_gas));
        Some(match f {
            Some(f) => Floor { max_fee: f.max_fee.max(fee), max_priority: f.max_priority.max(tip) },
            None => Floor { max_fee: fee, max_priority: tip },
        })
    })
}

/// A transaction this module saw mined at `nonce`: that number is used, and a send pinned to
/// it could only fail at broadcast, after the human approved it.
pub fn mined(rows: &[TxRecord], chain_id: u64, nonce: u64) -> Option<&TxRecord> {
    at(rows, chain_id, nonce).find(|r| r.status == "confirmed" || r.status == "failed")
}

/// More than `x`, and at least 10% more.
pub fn bump(x: U256) -> U256 {
    x.saturating_add(x / U256::from(10u8)).saturating_add(U256::from(1u8))
}

/// The fees a pinned send goes out with. A suggested field is raised past the floor; a field
/// the caller set is used as given, and refused when a node would refuse it.
pub fn raise(
    max_fee: U256,
    max_priority: U256,
    set_fee: bool,
    set_tip: bool,
    f: &Floor,
    nonce: u64,
) -> Result<(U256, U256), String> {
    let (need_fee, need_tip) = (bump(f.max_fee), bump(f.max_priority));
    if (set_fee && max_fee < need_fee) || (set_tip && max_priority < need_tip) {
        return Err(format!(
            "nonce {nonce} replaces a transaction still pending at max fee {} wei and priority \
             fee {} wei; nodes keep it unless a replacement offers at least {need_fee} and \
             {need_tip}",
            f.max_fee, f.max_priority
        ));
    }
    let tip = if set_tip { max_priority } else { max_priority.max(need_tip) };
    let fee = if set_fee { max_fee } else { max_fee.max(need_fee).max(tip) };
    if tip > fee {
        return Err(format!(
            "nonce {nonce} replaces a transaction still pending at priority fee {} wei; a \
             replacement must tip at least {need_tip}, more than the max fee set ({fee})",
            f.max_priority
        ));
    }
    Ok((fee, tip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(nonce: u64, status: &str, fee: &str, tip: &str) -> TxRecord {
        TxRecord {
            chain_id: 1,
            nonce: Some(nonce),
            status: status.into(),
            max_fee_per_gas: Some(fee.into()),
            max_priority_fee_per_gas: Some(tip.into()),
            ..Default::default()
        }
    }
    fn u(v: u64) -> U256 {
        U256::from(v)
    }

    // The mainnet case: nonce 40 went out with a zero tip, and the market fee had fallen below
    // its max fee. The tier's pair would have been refused; the raised one clears the rule.
    #[test]
    fn a_suggested_fee_is_raised_past_what_is_pending() {
        let f = floor(&[row(40, "pending", "338658463", "0")], 1, 40).unwrap();
        let (fee, tip) = raise(u(336953631), u(37979581), false, false, &f, 40).unwrap();
        assert_eq!((fee, tip), (u(372524310), u(37979581)));
    }

    #[test]
    fn a_market_already_past_the_floor_is_left_alone() {
        let f = floor(&[row(40, "pending", "1000", "100")], 1, 40).unwrap();
        assert_eq!(raise(u(5000), u(500), false, false, &f, 40).unwrap(), (u(5000), u(500)));
    }

    #[test]
    fn a_tip_floor_above_the_fee_lifts_the_fee_with_it() {
        let f = floor(&[row(40, "pending", "100", "2000")], 1, 40).unwrap();
        assert_eq!(raise(u(1000), u(10), false, false, &f, 40).unwrap(), (u(2201), u(2201)));
    }

    // Every attempt at the number may still be in some mempool: the floor beats all of them.
    #[test]
    fn the_floor_is_the_highest_of_each_field_across_attempts() {
        let rows = [row(40, "pending", "900", "0"), row(40, "unknown", "700", "50"), row(40, "pending", "800", "20")];
        assert_eq!(floor(&rows, 1, 40), Some(Floor { max_fee: u(900), max_priority: u(50) }));
    }

    #[test]
    fn only_what_may_still_be_pending_at_that_nonce_counts() {
        let rows = [row(40, "failed", "9000", "900"), row(41, "pending", "9000", "900")];
        assert_eq!(floor(&rows, 1, 40), None);
        let other_chain = TxRecord { chain_id: 10, ..row(40, "pending", "9000", "900") };
        assert_eq!(floor(&[other_chain], 1, 40), None);
    }

    // A fee the caller set is theirs, so it is refused, not overruled, when a node would
    // refuse it; one that clears the rule goes out as given.
    #[test]
    fn a_fee_the_caller_set_is_refused_rather_than_raised() {
        let f = floor(&[row(40, "pending", "1000", "100")], 1, 40).unwrap();
        let e = raise(u(1050), u(200), true, false, &f, 40).unwrap_err();
        assert!(e.contains("nonce 40") && e.contains("at least 1101 and 111"), "{e}");
        assert!(raise(u(5000), u(105), false, true, &f, 40).is_err());
        assert_eq!(raise(u(1101), u(111), true, true, &f, 40).unwrap(), (u(1101), u(111)));
        let high_tip = floor(&[row(40, "pending", "100", "2000")], 1, 40).unwrap();
        let e = raise(u(1000), u(10), true, false, &high_tip, 40).unwrap_err();
        assert!(e.contains("tip at least 2201, more than the max fee set (1000)"), "{e}");
    }

    #[test]
    fn a_number_this_module_saw_mined_is_named() {
        let rows = [row(40, "confirmed", "1", "1"), row(41, "pending", "1", "1")];
        assert!(mined(&rows, 1, 40).is_some());
        assert!(mined(&rows, 1, 41).is_none());
        assert!(mined(&[row(40, "failed", "1", "1")], 1, 40).is_some(), "a revert still used the number");
    }

    // geth: new >= old * 110 / 100 on both fields, and strictly more than old.
    #[test]
    fn every_bump_clears_the_nodes_rule() {
        for x in [0u64, 1, 9, 10, 11, 99, 100, 101, 999_999, 338_658_463, 50_000_000_000] {
            let b = bump(u(x));
            assert!(b > u(x) && b >= u(x) * u(110) / u(100), "{x} -> {b}");
        }
    }
}
