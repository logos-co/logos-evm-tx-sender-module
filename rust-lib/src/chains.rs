//! Names for the chains this module can label. DECORATION ONLY: a send on a chain absent
//! from this table is made exactly as one on a chain in it — the id is what the request
//! carries — but its rows name no currency, because a figure in a unit we cannot name is a
//! claim we cannot stand behind.
//!
//! There is deliberately no explorer field. Nothing here fetches or opens one, and a live
//! explorer URL is a loaded gun for whoever next adds a "view on explorer" button that would
//! disclose the user's IP together with their address.

/// A chain this module can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chain {
    pub chain_id: u64,
    pub name: &'static str,
    pub native_symbol: &'static str,
}

pub const KNOWN: [Chain; 8] = [
    Chain { chain_id: 1, name: "Ethereum", native_symbol: "ETH" },
    Chain { chain_id: 10, name: "Optimism", native_symbol: "ETH" },
    Chain { chain_id: 8453, name: "Base", native_symbol: "ETH" },
    Chain { chain_id: 17_000, name: "Holesky", native_symbol: "ETH" },
    Chain { chain_id: 31_337, name: "Local", native_symbol: "ETH" },
    Chain { chain_id: 42_161, name: "Arbitrum One", native_symbol: "ETH" },
    Chain { chain_id: 560_048, name: "Hoodi", native_symbol: "ETH" },
    Chain { chain_id: 11_155_111, name: "Sepolia", native_symbol: "ETH" },
];

pub fn by_chain_id(chain_id: u64) -> Option<Chain> {
    KNOWN.into_iter().find(|c| c.chain_id == chain_id)
}

pub fn name(chain_id: u64) -> Option<&'static str> {
    by_chain_id(chain_id).map(|c| c.name)
}

pub fn native_symbol(chain_id: u64) -> Option<&'static str> {
    by_chain_id(chain_id).map(|c| c.native_symbol)
}

/// The unit an error about money on `chain_id` is written in: the chain's own symbol, or
/// a word that says we do not know it rather than a symbol we guessed.
pub fn money_unit(chain_id: u64) -> &'static str {
    native_symbol(chain_id).unwrap_or("(native units)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_known_chains_are_distinct_and_resolvable() {
        let mut ids: Vec<u64> = KNOWN.iter().map(|c| c.chain_id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), KNOWN.len(), "duplicate chain id");
        assert_eq!(name(1), Some("Ethereum"));
        assert_eq!(native_symbol(11_155_111), Some("ETH"));
    }

    #[test]
    fn an_unknown_chain_names_nothing() {
        assert_eq!(name(424_242), None);
        assert_eq!(native_symbol(424_242), None);
        assert_eq!(money_unit(424_242), "(native units)");
        assert_eq!(money_unit(1), "ETH");
    }
}
