//! tx_sender_module — the one transaction sender on the device.
//!
//! Any module may hand it a bundle of calls from one account on one chain. It prices them
//! through `fee_module`, reserves their nonces in the one ledger, asks `keystore_module` for
//! ONE human approval over every leg, broadcasts the signatures in order through
//! `eth_rpc_module`, records each leg BEFORE it leaves, and polls the receipts. It never sees
//! key material and never chooses a chain: the request carries the chain, and the human in
//! the signer decides.
//!
//! Everything below is plain Rust with no Logos runtime and is unit-tested with
//! `cargo test --no-default-features`; the glue lives behind the default `logos_module`
//! feature.

pub mod budget;
pub mod chains;
pub mod details;
pub mod gate;
pub mod history;
pub mod receipt;
pub mod send;
pub mod sweep;
pub mod txbuild;
pub mod units;
pub mod verified;

pub use history::{History, TxRecord};
pub use receipt::TokenTransfer;
pub use send::{Leg, NonceReserver, SendJob, SendLedger, SendStatus};

#[cfg(feature = "logos_module")]
mod glue;
