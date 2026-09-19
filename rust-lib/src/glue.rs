//! Logos module glue for `tx_sender_module`.
//!
//! The builder derives the `.lidl` from the `TxSenderModule` trait below
//! (`codegen.rust = { trait, source: "src/glue.rs" }`). Compiled only with the default
//! `logos_module` feature; `cargo test --no-default-features` exercises the pure cores.
//!
//! `concurrency: "multi"`: every step here is a blocking round-trip through `eth_rpc_module`,
//! `fee_module` or `keystore_module`, so the module opts into concurrent dispatch and one
//! slow call cannot stall the rest. The multi contract makes the generated trait take
//! `&self` + `Send + Sync`, so all state lives behind an `RwLock` — and no lock in this file
//! is ever held across an outbound call.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use alloy::primitives::{Address, U256};
use serde_json::{json, Value};

use crate::budget::{
    callee_deadline, Budget, DETAILS_BUDGET, INIT_BUDGET, PROBE_BUDGET, READ_BUDGET,
    REFRESH_BUDGET, RPC_BUDGET, SEND_BUDGET, SWEEP_BUDGET,
};
use crate::details;
use crate::gate::{self, Gate};
use crate::history::{self, History, TxRecord};
use crate::send::{
    self, BroadcastClaim, Leg, SendJob, SendLedger, SendStatus, MAX_LABEL_BYTES, MAX_LEGS,
    MAX_META_BYTES, MAX_PURPOSE_BYTES,
};
use crate::sweep::{history_reply, SweepOutcome, GAS_PRICE_DECIMALS, SWEEP_MAX};
use crate::txbuild::{self, parse_u256_any, parse_u64_any};
use crate::verified::{self, unwrap_answer, unwrap_rpc, Answer};
use crate::{chains, units};

pub trait TxSenderModule: Send + Sync + 'static {
    /// Price a bundle of calls without doing anything: one `fee_module` bundle estimate,
    /// the account's ether against the value plus the fee ceiling, and the nonce the first
    /// call would take. Reserves nothing and requests no approval, so it is safe on every
    /// keystroke.
    ///
    /// `request_json`: `{ chainId, from, calls: [{ to, value?, data?, gasLimit?, label?,
    /// meta? }], tier?, maxFeePerGas?, maxPriorityFeePerGas?, nonce?, deadlineMs? }`.
    /// `value` is wei, `data` is `0x`-hex calldata (absent for a plain transfer). A call with
    /// no `gasLimit` is estimated through `fee_module` as the chain will find it — an ERC-20
    /// approve in an earlier call is applied to the calls after it — and one the estimator
    /// cannot model must carry its own limit. `nonce` pins a
    /// single call onto a number to REPLACE a transaction that already left. `deadlineMs`
    /// shrinks this method's own allowance to what the caller will wait.
    ///
    /// Returns `{ ok, chainId, from, nonce, legs: [{ to, value, data, gasLimit, gasSource,
    /// label }], maxFeePerGas, maxPriorityFeePerGas, feeSource, feeCeilingWei(+Display/Exact),
    /// maxCostWei(+Display/Exact), assumptions, nativeSymbol?, route, feeRoute }`.
    /// `feeCeilingWei` is the sum of every call's `maxFeePerGas × gasLimit` as `fee_module`
    /// answered it — a ceiling, never a price.
    fn prepare(&self, request_json: String) -> String;

    /// Ask a human to approve a bundle. The same `request_json` as `prepare`, plus `purpose`:
    /// one line the signer shows as the requester's CLAIM, suffixed with the module that
    /// asked as the runtime attested it.
    ///
    /// Reserves one nonce per call under the one ledger, asks `keystore_module` for ONE
    /// approval over every call, and answers `{ ok, pending: true, requestId, handle }` —
    /// **never a transaction hash**. Nothing has been signed or broadcast. `handle` is the
    /// keystore's name for the approval record, for pointing a signer at it. Drive the rest
    /// with `send_status`.
    fn send(&self, request_json: String) -> String;

    /// Advance a pending send and report where it got to. Poll this — there is no
    /// background advancer, so this call IS the broadcast.
    ///
    /// Once the human has approved, this collects the signatures, broadcasts them in call
    /// order — each recorded before it leaves, each exactly once — and stops at the first
    /// that does not land. `{ ok, requestId, handle, status, final, origin, purpose, legs:
    /// [{ to, nonce, label, hash? }], hashes, hash?, route?, reason? }` where `status` is
    /// `awaitingApproval` | `broadcasting` | `stuck` | `broadcast` | `rejected` |
    /// `cancelled` | `failed`. `hashes` are the calls that answered, in order; `hash` is the
    /// last. A `failed` bundle whose earlier calls landed still lists them.
    ///
    /// `final` is when to stop polling: false for `awaitingApproval` and `broadcasting`, true
    /// for every other status, `stuck` included. A refusal is `{ ok: false, error, final }`,
    /// final only for a request id this module does not hold — any other may pass on the next
    /// poll, and a poller that stops on it strands an approved send.
    ///
    /// A reply carrying `blocked: true` is a send being HELD by the verified-proxy gate, not
    /// a failed one: `ok` stays true, the nonces stay reserved, and the next poll sends it
    /// once the proxy is usable.
    fn send_status(&self, request_id: String) -> String;

    /// Withdraw a send that has not been approved yet, releasing its reserved nonces.
    fn cancel_send(&self, request_id: String) -> String;

    /// Every send that could still move and is not stuck: `{ ok, sends: [{ requestId,
    /// handle, chainId, from, status, origin, purpose }] }`. What a consumer that must not
    /// change the ground under a pending approval — a wallet switching networks — asks first.
    fn live_sends(&self) -> String;

    /// Locally recorded transactions for `address`, newest first, on `chain_id` — or on every
    /// chain when it is 0. Only transactions this module broadcast: there is no indexer.
    ///
    /// `{ ok, chainId, address, transactions, stillDue, stillDueAnyChain, unstored,
    /// unresolved, blockedChains, strandedNonces }`. Each row carries its stored fields plus
    /// `stalled`, `unresolved` and `verificationBlocked`; ether figures are decorated at 18
    /// places and gas prices in gwei. A row's `label`, `purpose`, `origin` and `meta` are the
    /// requester's own, returned verbatim — a token amount inside `meta` is the consumer's to
    /// render. Sweeps due receipts first.
    fn history(&self, address: String, chain_id: i64) -> String;

    /// Poll receipts for this address's still-pending transactions, on each row's OWN chain,
    /// and update their stored status. `{ ok, address, polled, changed, blocked,
    /// blockedChains, stillDue }`. `stillDue` is false once no row can move again.
    fn refresh_pending(&self, address: String) -> String;

    /// Re-read one recorded transaction's receipt on ITS OWN chain and update the stored
    /// status. `{ ok, hash, chainId, status, route }`.
    fn refresh_tx_status(&self, address: String, hash_hex: String) -> String;

    /// The transaction- and block-level fields a RECEIPT does not carry, for one recorded
    /// transaction. `{ ok, hash, chainId, route, fetchedAt, gasPriceUnit, block?,
    /// transaction?, blockError?, transactionError? }`; `ok` is true when EITHER leg landed.
    fn tx_details(&self, address: String, hash_hex: String) -> String;

    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
}

pub trait TxSenderModuleEvents {
    /// A pending send changed state — approved, rejected, broadcast or failed.
    fn send_status_changed(&self, request_id: String);
    /// A recorded transaction took a hash or a receipt settled it.
    fn tx_status_changed(&self, hash_hex: String);
    /// A recorded row for `address` appeared or changed with no hash for `tx_status_changed`
    /// to name — a call is written to history BEFORE it is broadcast, and on the arm where
    /// the node returns no hash it never gets one.
    fn history_changed(&self, address: String);
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct TxSenderModuleImpl {
    /// Behind an `Arc` so a caller takes a HANDLE out of the guard and drops it, rather than
    /// borrowing through it. That is what makes holding it across an outbound call
    /// unexpressible: the state a method works on outlives the lock by construction.
    state: RwLock<Option<Arc<State>>>,
    /// Built once with the module and never replaced. `on_context_ready` can be called
    /// again — a re-init installs a fresh `State` — and a second ledger would drop every
    /// reservation at once, including those protecting transactions already on chain.
    sends: Arc<SendLedger>,
    feeds: Feeds,
    /// Which chains may be gated without asking eth_rpc at all. Shared with the listener
    /// thread that keeps it honest; see [`crate::gate`] for why only `off` is ever held.
    gate: Arc<gate::ModeCache>,
}

/// The subscriptions this module keeps open on eth_rpc. Each flag is held for as long as
/// its thread runs, so a feed that ends re-arms on the next read rather than going quiet
/// for the life of the process.
#[derive(Default)]
struct Feeds {
    gate: Arc<AtomicBool>,
    chains: Arc<AtomicBool>,
}

/// Run a subscription's listener thread, releasing `flag` when the feed ends.
fn listen<S: Send + 'static>(flag: Arc<AtomicBool>, sub: S, body: impl FnOnce(S) + Send + 'static) {
    std::thread::spawn(move || {
        body(sub);
        flag.store(false, Ordering::SeqCst);
    });
}

/// How many new subscriptions a lost gate feed takes before giving up and leaving it to the
/// next gated read, which arms one itself. Bounded so a provider that is gone for good is
/// not spun on.
const GATE_REARMS: u32 = 5;
const GATE_REARM_PAUSE: std::time::Duration = std::time::Duration::from_secs(2);

/// One arming of the mode feed: the status watcher first, then the subscription.
///
/// The watcher goes on first because the C side replays the current state synchronously from
/// inside the install, so no arm can fall into the gap ahead of it. `subscribed` is what
/// stops that replay opening the cache before there is a mode subscription for an arm to be
/// about — the status is per TARGET, so a client already armed for the chain-config feed
/// reports `Armed` the instant it is asked. Re-installing after the subscription exists is a
/// second replay and not a second gate: same closure, same flag, one edge.
fn arm_gate(cache: &Arc<gate::ModeCache>) -> Option<logos_rust_sdk::EventSubscription> {
    let subscribed = Arc::new(AtomicBool::new(false));
    let watcher = |cache: Arc<gate::ModeCache>, subscribed: Arc<AtomicBool>| {
        move |s: logos_rust_sdk::SubStatus, _generation: u64| match s {
            // The one edge that opens this cache, and never before there is a feed to open it
            // for. `Lost`, `Held`, `Abandoned` and anything a later protocol adds close it.
            logos_rust_sdk::SubStatus::Armed if subscribed.load(Ordering::Acquire) => {
                cache.feed_live()
            }
            _ => cache.feed_dead(),
        }
    };
    let mut w = modules().eth_rpc_module;
    w.on_subscription_status(watcher(cache.clone(), subscribed.clone())).ok()?;
    // Bound at function scope, so `w` still holds the client when this second proxy asks the
    // cache for it: the cache is weak, and letting the last handle go destroys the client and
    // silently discards the watcher just installed.
    let mut c = modules().eth_rpc_module;
    let Ok(sub) = c.on_verified_proxy_mode_changed() else {
        return None;
    };
    subscribed.store(true, Ordering::Release);
    let _ = w.on_subscription_status(watcher(cache.clone(), subscribed));
    Some(sub)
}

/// Keep the mode feed running for as long as one can be had.
///
/// A stream ENDS: `Abandoned` is terminal, and it wakes its reader rather than parking it
/// for ever, so everything below the loop is reachable. Terminal is terminal — the way back
/// is not a re-arm of this subscription but a NEW one, which is unarmed at creation. Nothing
/// here opens the cache: taking a subscription is not an arm, and every re-subscribe waits
/// on the same single edge in [`arm_gate`] the first one did.
fn gate_feed(cache: &Arc<gate::ModeCache>) {
    for attempt in 0..=GATE_REARMS {
        if attempt > 0 {
            std::thread::sleep(GATE_REARM_PAUSE);
        }
        let Some(sub) = arm_gate(cache) else {
            cache.feed_dead();
            continue;
        };
        for ev in sub {
            let Some(e) =
                eth_rpc_module::EthRpcModuleClient::decode_verified_proxy_mode_changed(&ev)
            else {
                // An event we cannot read is a contract we no longer share, and it names no
                // chain to invalidate. Drop the lot, and do not go back for more of it.
                cache.feed_dead();
                return;
            };
            cache.told(e.chain_id as u64, &e.mode);
        }
        cache.feed_dead();
    }
}

/// Everything a request works on. Each field carries its own lock, taken and released inside
/// itself around local work only — so nothing in this file ever holds one across a call.
struct State {
    history: History,
    /// Shared with the module, not owned here: see `TxSenderModuleImpl::sends`.
    sends: Arc<SendLedger>,
}

fn err(e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": e.to_string() }).to_string()
}

const NO_CONTEXT: &str = "module context not ready";

/// The reply every gated method returns when the proxy is blocking. `error` is the verdict's
/// own sentence, so a consumer renders something actionable with no new wiring.
fn blocked(verdict: &Value) -> Value {
    json!({
        "ok": false,
        "error": verdict.get("message").and_then(Value::as_str)
            .unwrap_or("the verified proxy is not usable"),
        "verifiedProxy": verdict,
    })
}

/// The module that made this call, as the runtime attested it. Recorded on every row and
/// named in the claim line, never trusted for anything else. Empty when the runtime could
/// not say.
fn caller_name() -> String {
    match logos_rust_sdk::current_caller() {
        logos_rust_sdk::LogosCaller::Module { name, .. } => name,
        logos_rust_sdk::LogosCaller::HostAnchor => "host".to_string(),
        logos_rust_sdk::LogosCaller::Derived { parent, leaf } => format!("{parent}/{leaf}"),
        logos_rust_sdk::LogosCaller::Operator { name } => format!("operator:{name}"),
        logos_rust_sdk::LogosCaller::Unknown => String::new(),
    }
}

/// One call, as the caller asked for it.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CallSpec {
    to: String,
    /// Wei, decimal or hex. Absent is zero.
    #[serde(default)]
    value: Option<String>,
    /// `0x`-hex calldata. Absent or empty is a plain transfer.
    #[serde(default)]
    data: Option<String>,
    /// Used verbatim when given. A call that can only be estimated once an earlier one has
    /// landed — a swap behind its approval — has to carry one.
    #[serde(default)]
    gas_limit: Option<String>,
    #[serde(default)]
    label: String,
    /// Stored beside the row and returned with it, verbatim. An object or absent.
    #[serde(default)]
    meta: Value,
}

/// A bundle as the caller asked for it, before any chain lookup.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CallRequest {
    chain_id: u64,
    from: String,
    #[serde(default)]
    purpose: String,
    #[serde(default)]
    calls: Vec<CallSpec>,
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    max_fee_per_gas: Option<String>,
    #[serde(default)]
    max_priority_fee_per_gas: Option<String>,
    /// Pins the ONE call of a single-call bundle onto a number, to replace a transaction that
    /// already left. Refused for a bundle.
    #[serde(default)]
    nonce: Option<u64>,
    /// What the caller will wait, so this module's own allowance never outlives it.
    #[serde(default)]
    deadline_ms: Option<i64>,
}

/// One call, validated and priced.
struct PricedLeg {
    to: Address,
    value: U256,
    data: String,
    gas_limit: u64,
    label: String,
    meta: Value,
    /// This leg's `maxFeePerGas × gasLimit`, decimal wei, as `fee_module` priced it.
    fee_ceiling_wei: Option<String>,
    gas_source: String,
}

/// A priced bundle: what `prepare` reports and what `send` acts on.
struct Quote {
    chain_id: u64,
    from: Address,
    legs: Vec<PricedLeg>,
    /// The number the first call would take, as a preview. `send` reserves the real ones.
    nonce: u64,
    max_fee: U256,
    max_priority: U256,
    fee_source: String,
    /// The weakest route behind the balance and nonce reads. Says nothing about the fee.
    route: String,
    /// `fee_module`'s own reply: the ceiling in wei and in the native unit, and what the
    /// estimate assumed. Copied out, never recomputed here.
    priced: Value,
}

impl Quote {
    fn fee_ceiling_wei(&self) -> Option<U256> {
        self.priced.get("feeCeilingWei").and_then(Value::as_str).and_then(parse_u256_any)
    }

    fn gas_limits(&self) -> Vec<u64> {
        self.legs.iter().map(|l| l.gas_limit).collect()
    }

    fn value_total(&self) -> Option<U256> {
        self.legs.iter().try_fold(U256::ZERO, |a, l| a.checked_add(l.value))
    }
}

/// A call's name in a refusal: its label, or its target.
fn leg_name(i: usize, spec: &CallSpec) -> String {
    if spec.label.trim().is_empty() {
        format!("call {} to {}", i + 1, spec.to.trim())
    } else {
        format!("call {} ({})", i + 1, spec.label.trim())
    }
}

/// Why a bundle stopped at one of its calls, naming which.
fn leg_failure(i: usize, n: usize, reason: &str) -> String {
    format!("call {} of {n} was not completed: {reason}", i + 1)
}

impl TxSenderModuleImpl {
    /// The state, with the guard already dropped — the only lock this file takes. An owned
    /// handle is not a convention to remember: the guard is gone before this returns.
    fn state(&self) -> Result<Arc<State>, String> {
        let guard = self.state.read().map_err(|_| "state lock poisoned".to_string())?;
        guard.clone().ok_or_else(|| NO_CONTEXT.to_string())
    }

    /// Arm the gate feed. Everything the mode cache is allowed to remember rests on this
    /// subscription: it is what turns "verification is off for this chain" from a reading
    /// taken once into a fact someone is obliged to correct.
    ///
    /// Holding the subscription handle is NOT that fact. A subscription taken from
    /// `on_context_ready` is deferred until eth_rpc listens, so the handle exists across a
    /// window in which nobody would tell us the user switched verification ON. Only the
    /// runtime's per-module status channel separates the two, so a runtime without one
    /// latches the cache cold instead and every gated read pays its own probe.
    fn watch_gate(&self) {
        if self.feeds.gate.swap(true, Ordering::SeqCst) {
            return;
        }
        let cache = self.gate.clone();
        if !gate::status_channel(&logos_rust_sdk::protocol_version()) {
            // No one here can say when a subscription arms or dies, and a handle that merely
            // exists is not an arm. Latched for the process, which makes `feed_live` inert.
            cache.no_status_channel();
            eprintln!(
                "tx_sender_module: logos-protocol {} carries no per-module subscription \
                 status channel; the verified-proxy gate reads live on every check",
                logos_rust_sdk::protocol_version()
            );
        }
        listen(self.feeds.gate.clone(), cache, |cache| gate_feed(&cache));
    }

    /// Arm the chain-config feed. Belt and braces for the gate: a config change that did not
    /// move the mode cannot alter a verdict, since `off` is never blocking whatever the
    /// endpoint is — but a chain whose record moved is read live once, to be sure.
    fn watch_chain_config(&self) {
        if self.feeds.chains.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut c = modules().eth_rpc_module;
        let Ok(sub) = c.on_chain_config_changed() else {
            self.feeds.chains.store(false, Ordering::SeqCst);
            return;
        };
        let cache = self.gate.clone();
        listen(self.feeds.chains.clone(), sub, move |sub| {
            for ev in sub {
                if let Some(e) = eth_rpc_module::EthRpcModuleClient::decode_chain_config_changed(&ev)
                {
                    cache.invalidate(e.chain_id as u64);
                }
            }
        });
    }

    /// eth_rpc's verified-proxy verdict for `chain_id`, or a synthetic blocking one when it
    /// cannot be read. Never falls back to `off`, and never unbounded: the probe is a
    /// cross-process hop the protocol answers with a 20s default. A probe the budget cuts
    /// short still refuses — the verdict it returns carries its own reason, so a timeout is
    /// not read as permission and not reported as a freeze.
    fn verified_verdict_within(&self, chain_id: u64, b: &Budget) -> Value {
        let Some(t) = b.take(PROBE_BUDGET) else {
            return verified::unknown_verdict(chain_id, "this read's budget ran out");
        };
        self.watch_gate();
        let ticket = self.gate.ticket();
        let raw = modules().eth_rpc_module.verified_proxy_status_with_timeout(chain_id as i64, t);
        let v = Self::verdict_of(chain_id, raw);
        self.gate.learned(chain_id, v.get("mode").and_then(Value::as_str), ticket);
        v
    }

    fn verdict_of(chain_id: u64, raw: Result<String, impl std::fmt::Debug>) -> Value {
        let raw = match raw {
            Ok(r) => r,
            Err(e) => return verified::unknown_verdict(chain_id, &format!("{e:?}")),
        };
        match serde_json::from_str::<Value>(&raw) {
            Ok(v) => verified::normalize(chain_id, &v),
            Err(e) => verified::unknown_verdict(chain_id, &format!("unreadable verdict: {e}")),
        }
    }

    /// Whether `chain_id` may be read or sent on. `Err` carries the verdict to return to
    /// the caller: with verification required and the proxy not usable, nothing goes out.
    ///
    /// [`Gate::Open`] skips the hop entirely, and only ever for a chain whose mode eth_rpc
    /// has told us is `off` — where its own `blocking` is `mode_required && !usable`, so the
    /// answer cannot depend on the proxy health this would have probed. Every other chain,
    /// and every chain we are not certain about, is read live and refuses on its own.
    ///
    /// Charged to the SAME budget as the calls behind it, so the gate is time the method's
    /// own allowance can see rather than twenty seconds in front of it.
    fn verified_gate_within(&self, chain_id: u64, b: &Budget) -> Result<(), Value> {
        if self.gate.gate(chain_id) == Gate::Open {
            return Ok(());
        }
        Self::gate_of(self.verified_verdict_within(chain_id, b))
    }

    fn gate_of(v: Value) -> Result<(), Value> {
        if verified::is_blocking(&v) {
            Err(v)
        } else {
            Ok(())
        }
    }

    /// Poll due receipts for `address`, each on ITS OWN chain, and update the stored rows.
    /// An `Err` is never a status — the row stays pending and the stamped poll time is the
    /// backoff. The verdict is read once per distinct chain, not once per record.
    /// Rows are collected through History's lock, receipts fetched holding nothing, results
    /// applied back through that lock — which re-reads the file, so the apply is a
    /// compare-and-set rather than a blind write from this snapshot.
    fn sweep(&self, st: &State, address: &str, b: &Budget) -> SweepOutcome {
        let now = history::now_secs();
        let mut out = SweepOutcome::default();
        let mut failures: HashMap<u64, u32> = HashMap::new();
        let mut blocking: HashMap<u64, Option<Value>> = HashMap::new();

        for rec in st.history.pending_due(address, now, SWEEP_MAX) {
            // Two consecutive errors on a chain drop it for the rest of this sweep.
            if failures.get(&rec.chain_id).copied().unwrap_or(0) >= 2 {
                continue;
            }
            // Bounded, unlike the paths that refuse outright: a row this skips is DISCLOSED in
            // `blockedChains` and retried on the next poll, so an expired probe costs one
            // degraded cycle rather than a consumer that shows nothing.
            let gated = blocking.entry(rec.chain_id).or_insert_with(|| {
                let v = self.verified_verdict_within(rec.chain_id, b);
                verified::is_blocking(&v).then_some(v)
            });
            if let Some(verdict) = gated {
                out.blocked
                    .entry(rec.chain_id)
                    .or_insert_with(|| (Vec::new(), verdict.clone()))
                    .0
                    .push(rec.hash.clone());
                continue;
            }
            let Some(t) = b.take(RPC_BUDGET) else { break };
            let receipt = modules()
                .eth_rpc_module
                .get_transaction_receipt_with_timeout(rec.chain_id as i64, &rec.hash, t)
                .map_err(|e| format!("{e:?}"))
                .and_then(|raw| unwrap_rpc(&raw));
            out.polled += 1;
            match receipt {
                Ok(r) => {
                    failures.insert(rec.chain_id, 0);
                    // Counted and announced only where the new status reached DISK. A
                    // subscriber re-reads from there, so a settle claimed over a refused
                    // write is a row the consumer renders as pending for ever.
                    match st.history.apply_receipt(&rec, &r, now) {
                        Ok(true) => {
                            out.changed += 1;
                            out.confirmed |= history::classify_receipt(&r) == "confirmed";
                            emit_tx_status_changed(&rec.hash);
                        }
                        Ok(false) => {}
                        Err(_) => out.unstored += 1,
                    }
                }
                Err(_) => {
                    *failures.entry(rec.chain_id).or_insert(0) += 1;
                    // The backoff stamp alone. A disk that refuses it refuses the status
                    // too, and the row is simply due again on the next sweep.
                    let _ = st.history.apply_receipt(&rec, &Value::Null, now);
                }
            }
        }
        out.still_due = st.history.has_live(address, now);
        out
    }

    /// Validate a bundle and price it: one `fee_module` bundle estimate, the ether against
    /// the value plus the fee ceiling, the nonce from the chain. Pure of side effects —
    /// reserves nothing and requests no approval.
    fn quote(&self, req: &CallRequest, b: &Budget) -> Result<Quote, String> {
        let chain_id = req.chain_id;
        if chain_id == 0 {
            return Err("chainId is required".into());
        }
        let from = req.from.trim().parse::<Address>()
            .map_err(|e| format!("invalid `from` address: {e}"))?;
        if req.calls.is_empty() || req.calls.len() > MAX_LEGS {
            return Err(format!("a send carries between 1 and {MAX_LEGS} calls, not {}", req.calls.len()));
        }
        if req.purpose.len() > MAX_PURPOSE_BYTES {
            return Err(format!("`purpose` is longer than {MAX_PURPOSE_BYTES} bytes"));
        }
        if req.nonce.is_some() && req.calls.len() != 1 {
            return Err("a pinned nonce replaces ONE transaction; a bundle cannot be pinned".into());
        }

        // Validated whole before anything is asked: a refusal must not cost a round trip.
        let mut legs: Vec<PricedLeg> = Vec::with_capacity(req.calls.len());
        for (i, c) in req.calls.iter().enumerate() {
            let name = leg_name(i, c);
            let to = c.to.trim().parse::<Address>()
                .map_err(|e| format!("{name}: invalid `to` address: {e}"))?;
            let value = match c.value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
                Some(v) => parse_u256_any(v).ok_or_else(|| format!("{name}: `value` is not a quantity"))?,
                None => U256::ZERO,
            };
            let data = txbuild::normalize_data(c.data.as_deref()).map_err(|e| format!("{name}: {e}"))?;
            if c.label.len() > MAX_LABEL_BYTES {
                return Err(format!("{name}: `label` is longer than {MAX_LABEL_BYTES} bytes"));
            }
            if !(c.meta.is_null() || c.meta.is_object()) {
                return Err(format!("{name}: `meta` must be an object"));
            }
            if c.meta.to_string().len() > MAX_META_BYTES {
                return Err(format!("{name}: `meta` is larger than {MAX_META_BYTES} bytes"));
            }
            let gas_limit = match c.gas_limit.as_deref().map(str::trim).filter(|g| !g.is_empty()) {
                Some(g) => parse_u64_any(g).filter(|g| *g > 0)
                    .ok_or_else(|| format!("{name}: `gasLimit` is not a positive quantity"))?,
                None => 0,
            };
            legs.push(PricedLeg { to, value, data, gas_limit, label: c.label.trim().to_string(), meta: c.meta.clone(),
                                  fee_ceiling_wei: None, gas_source: String::new() });
        }

        // One fee for the whole bundle and every limit from one `fee_module` pass: each call
        // is estimated as the chain will find it, an earlier approve applied to the calls
        // after it. A caller's own limit is used verbatim.
        let calls_json: Vec<Value> = legs
            .iter()
            .map(|l| {
                let mut c = json!({ "to": l.to.to_string(), "value": format!("0x{:x}", l.value),
                                    "data": l.data, "label": l.label });
                if l.gas_limit > 0 {
                    c["gasLimit"] = json!(l.gas_limit.to_string());
                }
                c
            })
            .collect();
        let mut fee_req = json!({ "from": from.to_string(), "calls": calls_json });
        if let Some(t) = &req.tier { fee_req["tier"] = json!(t); }
        if let Some(v) = &req.max_fee_per_gas { fee_req["maxFeePerGas"] = json!(v); }
        if let Some(v) = &req.max_priority_fee_per_gas { fee_req["maxPriorityFeePerGas"] = json!(v); }
        // One round trip per call plus one for the fee, granted as a single slice.
        let t = b.take(RPC_BUDGET * (legs.len() as u32 + 1)).ok_or("no time left to price the bundle")?;
        if let Some(d) = callee_deadline(t) {
            fee_req["deadlineMs"] = json!(d);
        }
        let raw = modules()
            .fee_module
            .estimate_bundle_with_timeout(chain_id as i64, &fee_req.to_string(), t)
            .map_err(|e| format!("pricing: {e:?}"))?;
        let fee: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        if fee.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(fee.get("error").and_then(Value::as_str).unwrap_or("fee estimation failed").to_string());
        }
        // fee_module emits amounts as decimal strings but `gasLimit` as a JSON number, so
        // every numeric field is read through both forms rather than assuming one.
        let pick = |v: &Value, k: &str| -> Result<U256, String> {
            v.get(k)
                .and_then(|x| match x {
                    Value::String(t) => parse_u256_any(t),
                    Value::Number(n) => n.as_u64().map(U256::from),
                    _ => None,
                })
                .ok_or_else(|| format!("fee_module returned no usable `{k}`"))
        };
        let max_fee = pick(&fee, "maxFeePerGas")?;
        let max_priority = pick(&fee, "maxPriorityFeePerGas")?;
        if max_priority > max_fee {
            return Err("maxPriorityFeePerGas cannot exceed maxFeePerGas".into());
        }
        let fee_source = fee.get("source").and_then(Value::as_str).unwrap_or("unknown").to_string();
        let priced_calls = fee.get("calls").and_then(Value::as_array).cloned().unwrap_or_default();
        if priced_calls.len() != legs.len() {
            return Err(format!("fee_module priced {} calls, not {}", priced_calls.len(), legs.len()));
        }
        for (i, (leg, p)) in legs.iter_mut().zip(priced_calls.iter()).enumerate() {
            let name = leg_name(i, &req.calls[i]);
            let gas = u64::try_from(pick(p, "gasLimit").map_err(|_| {
                format!("fee_module returned no usable `gasLimit` for {name} — refusing rather than guessing one")
            })?)
            .map_err(|_| format!("fee_module returned an implausible `gasLimit` for {name}"))?;
            if gas == 0 {
                return Err(format!("fee_module returned a zero `gasLimit` for {name}"));
            }
            if leg.gas_limit == 0 {
                leg.gas_limit = gas;
            }
            leg.fee_ceiling_wei = p.get("feeCeilingWei").and_then(Value::as_str).map(str::to_string);
            leg.gas_source = p.get("gasSource").and_then(Value::as_str).unwrap_or("unknown").to_string();
        }
        let ceiling = pick(&fee, "feeCeilingWei")?;

        let (balance, balance_route) = self.native_balance(chain_id, &from.to_string(), b)?;
        let value_total = legs.iter().try_fold(U256::ZERO, |a, l| a.checked_add(l.value))
            .ok_or("the values of this bundle overflow")?;
        send::affordable(balance, value_total, ceiling, chains::money_unit(chain_id))?;

        // A caller-supplied nonce came from nothing we can vouch for, so it unlabels the quote.
        let (nonce, nonce_route) = match req.nonce {
            Some(n) => (n, None),
            None => self.chain_nonce(chain_id, &from.to_string(), b)?,
        };
        let route = verified::weakest_route(&[balance_route.as_deref(), nonce_route.as_deref()]);

        Ok(Quote { chain_id, from, legs, nonce, max_fee, max_priority, fee_source, route, priced: fee })
    }

    fn native_balance(
        &self,
        chain_id: u64,
        address: &str,
        b: &Budget,
    ) -> Result<(U256, Option<String>), String> {
        let t = b.take(RPC_BUDGET).ok_or("no time left to read the balance")?;
        let raw = modules()
            .eth_rpc_module
            .get_balance_with_timeout(chain_id as i64, address, t)
            .map_err(|e| format!("{e:?}"))?;
        let a = unwrap_answer(&raw)?;
        let v = a.value.as_str().and_then(parse_u256_any)
            .ok_or_else(|| "could not read the native balance".to_string())?;
        Ok((v, a.route))
    }

    fn chain_nonce(
        &self,
        chain_id: u64,
        address: &str,
        b: &Budget,
    ) -> Result<(u64, Option<String>), String> {
        let t = b.take(RPC_BUDGET).ok_or("no time left to read the nonce")?;
        let raw = modules()
            .eth_rpc_module
            .get_transaction_count_with_timeout(chain_id as i64, address, t)
            .map_err(|e| format!("{e:?}"))?;
        let a = unwrap_answer(&raw)?;
        let v = a.value.as_str().and_then(parse_u64_any)
            .ok_or_else(|| "could not read the account nonce".to_string())?;
        Ok((v, a.route))
    }

    /// The `prepare` reply for a quote.
    fn quote_reply(q: &Quote) -> Value {
        let gas_limits = q.gas_limits();
        let value_total = q.value_total().unwrap_or(U256::ZERO);
        let max_cost = q.fee_ceiling_wei().and_then(|c| send::max_cost_wei(value_total, c)).map(|v| v.to_string());
        let gas_total: u64 = gas_limits.iter().sum();
        let legs: Vec<Value> = q
            .legs
            .iter()
            .map(|l| {
                json!({ "to": l.to.to_string(), "value": l.value.to_string(), "data": l.data,
                        "gasLimit": l.gas_limit, "gasSource": l.gas_source, "label": l.label })
            })
            .collect();
        let mut v = json!({
            "ok": true, "chainId": q.chain_id, "from": q.from.to_string(),
            "nonce": q.nonce, "legs": legs,
            "valueWei": value_total.to_string(),
            "maxFeePerGas": q.max_fee.to_string(),
            "maxPriorityFeePerGas": q.max_priority.to_string(),
            "gasLimit": gas_total,
            "maxCostWei": max_cost,
            // Σ `maxFeePerGas × gasLimit` as fee_module priced it, in wei and in the native
            // unit: a ceiling, never a price. A consumer that presents it as "the fee" is
            // how an overpayment goes unnoticed.
            "feeCeilingWei": q.priced.get("feeCeilingWei").cloned().unwrap_or(Value::Null),
            "feeCeilingWeiDisplay": q.priced.get("feeCeilingWeiDisplay").cloned().unwrap_or(Value::Null),
            "feeCeilingWeiExact": q.priced.get("feeCeilingWeiExact").cloned().unwrap_or(Value::Null),
            // What the estimate took for granted: an earlier call's approve, applied to a
            // later call. Empty when every call was estimated against the chain as it is.
            "assumptions": q.priced.get("assumptions").cloned().unwrap_or_else(|| json!([])),
            "feeSource": q.fee_source,
            // `route` covers the balance and nonce reads only. The fee is fee_module's, which
            // emits no label, so it is never proof-backed whatever `route` says.
            "route": q.route,
            "feeRoute": verified::UNKNOWN_ROUTE,
        });
        if let Some(s) = chains::native_symbol(q.chain_id) {
            v["nativeSymbol"] = json!(s);
        }
        units::decorate(&mut v, "valueWei", &value_total.to_string(), Some(18));
        if let Some(m) = &max_cost {
            units::decorate(&mut v, "maxCostWei", m, Some(18));
        }
        v
    }

    /// Price, commit, then ask for approval — the commit under the ledger's lock rather than
    /// around the call. Two concurrent sends both reach `open` and take disjoint runs of
    /// nonces; every path out short of `commit` hands them back.
    fn request_send(
        &self,
        st: &State,
        req: &CallRequest,
        b: &Budget,
    ) -> Result<(String, String), String> {
        let q = self.quote(req, b)?;
        let origin = caller_name();
        let chain_id = q.chain_id;
        let from = q.from.to_string();

        // `latest` does not count a broadcast-but-unmined transaction and the verified path
        // refuses `pending`, so this reservation is all that stops a clash. The guard owns it
        // from here: every path out short of `commit` hands the numbers back.
        let guard = st.sends.open(chain_id, &from, q.nonce, q.legs.len(), req.nonce)?;
        let nonces = guard.claim().nonces.clone();

        let fee = txbuild::Fee::Eip1559 {
            max_fee_per_gas: q.max_fee,
            max_priority_fee_per_gas: q.max_priority,
        };
        let mut intent_legs = Vec::with_capacity(q.legs.len());
        let mut legs = Vec::with_capacity(q.legs.len());
        for (pl, nonce) in q.legs.iter().zip(nonces.iter()) {
            let tx = txbuild::unsigned_call_tx(pl.to, pl.value, &pl.data, *nonce, pl.gas_limit, &fee);
            intent_legs.push(json!({ "kind": "tx", "chain_id": chain_id, "tx": tx }));
            legs.push(Leg {
                to: pl.to.to_string(),
                value: pl.value.to_string(),
                data: pl.data.clone(),
                gas_limit: pl.gas_limit,
                nonce: *nonce,
                label: pl.label.clone(),
                meta: pl.meta.clone(),
                fee_ceiling_wei: pl.fee_ceiling_wei.clone(),
                hash: None,
                left: false,
            });
        }
        // What a human reads at the moment of approval: the requester's own sentence, and
        // who the runtime says the requester was.
        let purpose = req.purpose.trim().to_string();
        let intent = json!({
            "address": from,
            "purpose": send::claim_line(&purpose, &origin),
            "legs": intent_legs,
        });

        // Bounded: this registers the request, it does not wait for the human. A late deadline
        // costs a stray prompt whose signature is never fetched — no money moves.
        let t = b.take(INIT_BUDGET).ok_or("no time left to request approval")?;
        let raw = modules()
            .keystore_module
            .request_approval_with_timeout(&intent.to_string(), t)
            .map_err(|e| format!("{e:?}"))?;
        let v: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        if v.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(v
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("the keystore refused the approval request")
                .to_string());
        }
        let handle = v.get("handle").and_then(Value::as_str).unwrap_or_default().to_string();
        let receipt = v.get("receipt").and_then(Value::as_str).unwrap_or_default().to_string();

        let job = SendJob {
            request_id: format!("snd_{handle}"),
            handle,
            receipt,
            chain_id,
            from,
            legs,
            max_fee: q.max_fee.to_string(),
            max_priority: q.max_priority.to_string(),
            purpose,
            origin,
            status: SendStatus::AwaitingApproval,
            broadcast: None,
            // Set from the claim by `commit`; a caller does not get to name it.
            replaces: None,
        };
        let request_id = job.request_id.clone();
        let handle = job.handle.clone();
        guard.commit(job);
        Ok((request_id, handle))
    }

    /// Advance one pending send. Outbound calls, none under a lock, and they need no
    /// consistent view of each other: the claim belongs immediately before the first call
    /// that moves money.
    ///
    /// The claim hands back a ticket, and from then on nothing else may settle this job. A
    /// concurrent dispatch that read the job before the claim bounces off it rather than
    /// failing a transaction already on its way to a node. The calls then leave ONE AT A
    /// TIME, each recorded first and each burning its own number the instant its bytes are
    /// about to go, and the first that does not land stops the rest.
    fn advance_send(&self, request_id: &str) -> Result<Value, String> {
        let st = self.state()?;
        let b = Budget::new(SEND_BUDGET);
        let now = history::now_secs();
        let job =
            st.sends.get(request_id).ok_or_else(|| format!("no send with id '{request_id}'"))?;
        if job.status.is_terminal() {
            return Ok(Self::job_reply(&job, now));
        }
        // Another dispatch owns the broadcast. Going on would ask the keystore about a request
        // it has already answered and read the absence of a signature as a failure — settling
        // a transaction that is on its way, and handing its nonce to the next send.
        if job.broadcast_started() {
            return Ok(Self::job_reply(&job, now));
        }

        let t = b.take(RPC_BUDGET).ok_or("no time left to read the approval")?;
        let raw = modules()
            .keystore_module
            .approval_status_with_timeout(&job.handle, &job.receipt, t)
            .map_err(|e| format!("{e:?}"))?;
        let v: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        if v.get("ok").and_then(Value::as_bool) != Some(true) {
            let reason = v
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("the keystore lost this request")
                .to_string();
            return self.settle(&st, request_id, SendStatus::Failed { reason });
        }
        match v.get("state").and_then(Value::as_str).unwrap_or("") {
            // Re-read: a cancel may have landed while the keystore was answering.
            "offered" | "rendered" => {
                return Ok(Self::job_reply(&st.sends.get(request_id).unwrap_or(job), now))
            }
            "settled" => {}
            other => return Err(format!("unknown approval state '{other}'")),
        }
        match v.get("reason").and_then(Value::as_str).unwrap_or("approved") {
            "approved" => {}
            "rejected" => return self.settle(&st, request_id, SendStatus::Rejected),
            r => {
                return self.settle(&st, request_id, SendStatus::Failed { reason: r.to_string() })
            }
        }

        // Approved. Fetching the signatures is a read and is safe to repeat, so it happens
        // BEFORE the claim: a failure here leaves the send exactly as it was, and the next
        // poll tries again.
        let t = b.take(RPC_BUDGET).ok_or("no time left to collect the signatures")?;
        let fetched = modules()
            .keystore_module
            .fetch_result_with_timeout(&job.handle, &job.receipt, t)
            .map_err(|e| format!("{e:?}"))?;
        let fv: Value = serde_json::from_str(&fetched).map_err(|e| e.to_string())?;
        // `signed`, not `results` — the documented key, and the one the keystore emits.
        let signed: Vec<String> = fv
            .get("signed")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        let n = job.legs.len();
        if signed.len() < n {
            let reason = format!("the approval carried {} signature(s) for {n} call(s)", signed.len());
            return self.settle(&st, request_id, SendStatus::Failed { reason });
        }

        // The gate again, as late as a check can be and still be in front of the money: the
        // one `send` passed can close while a human sits in the signer. A refusal touches
        // nothing — no claim, no record, no settle — so the job keeps its nonces and the next
        // poll sends it once the proxy is usable. A closed gate is not a failed send.
        if let Err(v) = self.verified_gate_within(job.chain_id, &b) {
            // Re-read: a cancel may have landed while the probe was out.
            let now_job = st.sends.get(request_id).unwrap_or(job);
            return Ok(verified::held_by_the_gate(&Self::job_reply(&now_job, now), &v));
        }

        // Claim, then for each call: record, burn, broadcast. The ticket is the only key to
        // this job from here on, and it is the whole answer to a broadcast that never
        // returns: the job cannot be settled behind our back, and after STUCK_AFTER_SECS it
        // reports `stuck` rather than wedging.
        let ticket = match st.sends.claim_broadcast(request_id, now) {
            BroadcastClaim::Claimed(t) => t,
            // Another poll is inside the broadcast right now; it will settle the job.
            BroadcastClaim::InFlight(j) | BroadcastClaim::Settled(j) => {
                return Ok(Self::job_reply(&j, now))
            }
            BroadcastClaim::Unknown => {
                return Err(format!("no send with id '{request_id}'"))
            }
        };

        let mut route: Option<String> = None;
        let mut last_hash = String::new();
        for (i, raw_tx) in signed.iter().take(n).enumerate() {
            // WRITE AHEAD. The intent goes first; the outcome only completes it, and a row
            // that cannot be written means no send — `broadcast` takes the proof.
            let recorded = match st.history.record_intent(request_id, i as u32, Self::intent_row(&job, i)) {
                Ok(r) => r,
                Err(reason) => {
                    let reason = leg_failure(i, n, &reason);
                    return self.settle_owned(&st, &ticket, SendStatus::Failed { reason });
                }
            };
            // A row exists from here on and has no hash yet, so `tx_status_changed` cannot
            // name it. A history view learns of it now rather than only if the broadcast answers.
            emit_history_changed(&job.from);

            // The number is burnt the instant its bytes are about to leave, IN MEMORY, which
            // no restart can read — the row above is what a restart reads.
            let Some(leaving) = st.sends.leaving(&ticket, i) else {
                let reason = leg_failure(i, n, "the ledger would not release this call");
                return self.settle_owned(&st, &ticket, SendStatus::Failed { reason });
            };

            let hash = match self.broadcast(&recorded, &leaving, job.chain_id, raw_tx) {
                Ok(a) => match a.value.as_str().map(str::to_string).filter(|h| !h.is_empty()) {
                    Some(h) => {
                        route = Some(verified::fold_route(route.as_deref(), a.route.as_deref()));
                        h
                    }
                    None => {
                        // The transaction may well be on-chain; we simply cannot follow it. The
                        // nonce stays burnt for exactly that reason, and the row stays
                        // `unknown` on disk, so the next process holds it too.
                        let reason =
                            "the node accepted the transaction but returned no hash".to_string();
                        if st.history.leave_unknown(&recorded, &reason) {
                            emit_history_changed(&job.from);
                        }
                        let reason = leg_failure(i, n, &reason);
                        return self.settle_owned(&st, &ticket, SendStatus::Failed { reason });
                    }
                },
                Err(reason) => {
                    if st.history.leave_unknown(&recorded, &reason) {
                        emit_history_changed(&job.from);
                    }
                    let reason = leg_failure(i, n, &reason);
                    return self.settle_owned(&st, &ticket, SendStatus::Failed { reason });
                }
            };

            // The intent becomes an ordinary pollable row. Nothing new is recorded here: the
            // evidence has been on disk since before the transaction left.
            let took_hash = st.history.resolve_broadcast(&recorded, &hash, history::now_secs());
            st.sends.landed(&ticket, i, &hash);
            // Only if the row actually took it: otherwise this names a hash history does not hold.
            if took_hash {
                emit_tx_status_changed(&hash);
            }
            last_hash = hash;
        }

        let _ = modules().keystore_module.ack_result_with_timeout(
            &job.handle,
            &job.receipt,
            RPC_BUDGET,
        );
        let route = route.unwrap_or_else(|| verified::UNKNOWN_ROUTE.to_string());
        self.settle_owned(&st, &ticket, SendStatus::Broadcast { hash: last_hash, route })
    }

    /// The one call that moves money, and the only site allowed to make it. It takes
    /// `Recorded`, which only `History::record_intent` produces, and `Leaving`, which only
    /// `SendLedger::leaving` produces — so broadcasting before the record is written, or on
    /// a number the ledger could still hand to another send, is not something this file can
    /// express. The ordering is a type, not a rule each new path has to remember.
    ///
    /// Deliberately UNBOUNDED, alone among the calls here: a deadline does not stop the
    /// transaction, it only stops us learning its hash.
    fn broadcast(
        &self,
        _recorded: &history::Recorded,
        _leaving: &send::Leaving,
        chain_id: u64,
        raw_tx: &str,
    ) -> Result<Answer, String> {
        modules()
            .eth_rpc_module
            .send_raw_transaction(chain_id as i64, raw_tx)
            .map_err(|e| format!("{e:?}"))
            .and_then(|r| unwrap_answer(&r))
    }

    /// The durable record of one call, as it goes down BEFORE the broadcast. Every field but
    /// the hash is known from the quote the human approved; the hash is what the broadcast
    /// is for, and `record_intent` supplies the status.
    fn intent_row(j: &SendJob, i: usize) -> TxRecord {
        let leg = &j.legs[i];
        TxRecord {
            chain_id: j.chain_id,
            from: j.from.clone(),
            to: leg.to.clone(),
            value: leg.value.clone(),
            kind: if leg.data == "0x" { "native".into() } else { "call".into() },
            timestamp: history::now_secs(),
            leg: i as u32,
            legs: j.legs.len() as u32,
            label: leg.label.clone(),
            purpose: j.purpose.clone(),
            origin: j.origin.clone(),
            meta: leg.meta.clone(),
            nonce: Some(leg.nonce),
            gas_limit: Some(leg.gas_limit),
            max_fee_per_gas: Some(j.max_fee.clone()),
            max_priority_fee_per_gas: Some(j.max_priority.clone()),
            fee_ceiling_wei: leg.fee_ceiling_wei.clone(),
            tx_input: Some(leg.data.clone()),
            // The receipt has not landed yet; the poll fills the rest.
            ..Default::default()
        }
    }

    /// Re-read one row's receipt on its own chain and settle it. Bounded AS A WHOLE, gate
    /// included: this is a button, and an unbounded probe in front of the receipt read is up
    /// to twenty seconds of frozen consumer.
    fn refresh_one(&self, address: &str, hash_hex: &str) -> Result<Value, String> {
        let st = self.state()?;
        // The record's own chain: a consumer switching networks must not send every refresh
        // to the wrong node and re-affirm `pending` forever.
        let rec = st
            .history
            .find(address, hash_hex)
            .ok_or_else(|| format!("no recorded transaction with hash {hash_hex}"))?;
        let b = Budget::new(REFRESH_BUDGET);
        if let Err(v) = self.verified_gate_within(rec.chain_id, &b) {
            return Ok(blocked(&v));
        }
        let t = b.take(RPC_BUDGET).ok_or("no time left to read the receipt")?;
        let raw = modules()
            .eth_rpc_module
            .get_transaction_receipt_with_timeout(rec.chain_id as i64, &rec.hash, t)
            .map_err(|e| format!("{e:?}"))?;
        let Answer { value: receipt, route } = unwrap_answer(&raw)?;
        let status = history::classify_receipt(&receipt);
        // Exactly one of two concurrent refreshes of the same row sees `true` here — the
        // apply compares against what is on disk — so the event is announced once.
        if st.history.apply_receipt(&rec, &receipt, history::now_secs())? {
            emit_tx_status_changed(&rec.hash);
        }
        Ok(json!({ "ok": true, "hash": rec.hash, "chainId": rec.chain_id, "status": status,
                   "route": verified::weakest_route(&[route.as_deref()]) }))
    }

    /// The mined-at time. `eth_getBlockByNumber` has no typed helper on `eth_rpc`, so it goes
    /// through `raw_rpc`; `false` asks for the header rather than every transaction in it.
    fn block_header(
        &self,
        chain_id: u64,
        number: u64,
        b: &Budget,
    ) -> Result<(Value, Option<String>), String> {
        let t = b.take(RPC_BUDGET).ok_or("no time left to read the block")?;
        let params = format!("[\"0x{number:x}\", false]");
        let raw = modules()
            .eth_rpc_module
            .raw_rpc_with_timeout(chain_id as i64, "eth_getBlockByNumber", &params, t)
            .map_err(|e| format!("{e:?}"))?;
        let Answer { value, route } = unwrap_answer(&raw)?;
        let ts = value
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(parse_u64_any)
            .ok_or("the node returned no timestamp for this block")?;
        Ok((json!({ "number": number, "timestamp": ts }), route))
    }

    /// `gas` (the LIMIT the transaction carried), `maxPriorityFeePerGas` and `input`, none of
    /// which a receipt reports. An absent field stays absent: a legacy transaction has no
    /// priority fee, and a zero here would be a figure the chain never carried.
    fn tx_fields(
        &self,
        chain_id: u64,
        hash: &str,
        b: &Budget,
    ) -> Result<(Value, Option<String>), String> {
        let t = b.take(RPC_BUDGET).ok_or("no time left to read the transaction")?;
        let raw = modules()
            .eth_rpc_module
            .get_transaction_by_hash_with_timeout(chain_id as i64, hash, t)
            .map_err(|e| format!("{e:?}"))?;
        let Answer { value, route } = unwrap_answer(&raw)?;
        if value.is_null() {
            return Err("the node does not have this transaction".to_string());
        }
        let mut out = json!({});
        if let Some(g) = value.get("gas").and_then(Value::as_str).and_then(parse_u64_any) {
            out["gasLimit"] = json!(g);
        }
        if let Some(p) =
            value.get("maxPriorityFeePerGas").and_then(Value::as_str).and_then(parse_u256_any)
        {
            let tip = p.to_string();
            out["maxPriorityFeePerGas"] = json!(tip);
            units::decorate(&mut out, "maxPriorityFeePerGas", &tip, Some(GAS_PRICE_DECIMALS));
        }
        if let Some(d) = value.get("input").and_then(Value::as_str) {
            out["input"] = json!(d);
        }
        Ok((out, route))
    }

    /// Fetch what a receipt never carried, for ONE row, on its own chain. Bounded AS A WHOLE,
    /// gate included, for the reason `refresh_one` gives.
    ///
    /// The two legs are independent, so one failing is reported BESIDE the fields it could not
    /// fill rather than failing the other — a timed-out block read must not withhold a priority
    /// fee that landed.
    fn fetch_details(&self, address: &str, hash_hex: &str) -> Result<Value, String> {
        let st = self.state()?;
        let rec = st
            .history
            .find(address, hash_hex)
            .ok_or_else(|| format!("no recorded transaction with hash {hash_hex}"))?;
        let b = Budget::new(DETAILS_BUDGET);
        // The hash goes onto the refusal too: a consumer renders this beside one transaction's
        // own rows, so every reply has to say which transaction it is about.
        if let Err(v) = self.verified_gate_within(rec.chain_id, &b) {
            let mut r = blocked(&v);
            r["hash"] = json!(rec.hash);
            r["chainId"] = json!(rec.chain_id);
            return Ok(r);
        }
        let Some(number) = rec.block_number else {
            return Err("this transaction has no block yet, so there is nothing to read".into());
        };

        // The second leg is SKIPPED, not failed, when the row already stores every answer it
        // would bring: that is what makes this one call for a send recorded by this build.
        let needed = details::transaction_leg_needed(&rec);
        // The block first: it is the gap a user comparing with an explorer notices, so it gets
        // the allowance ahead of a leg that may not even be made.
        let block = self.block_header(rec.chain_id, number, &b);
        let tx = needed.then(|| self.tx_fields(rec.chain_id, &rec.hash, &b));
        Ok(details::details_reply(&rec.hash, rec.chain_id, history::now_secs(), block, tx))
    }

    /// `status` is what the send is DOING, not only what it has settled into: a claimed
    /// broadcast reads `broadcasting`, and one that has not answered reads `stuck`. `final`
    /// says whether a poll can still move it.
    fn job_reply(j: &SendJob, now: u64) -> Value {
        let status = j.reported_status(now);
        let legs: Vec<Value> = j
            .legs
            .iter()
            .map(|l| {
                let mut v = json!({ "to": l.to, "nonce": l.nonce, "label": l.label, "left": l.left });
                if let Some(h) = &l.hash {
                    v["hash"] = json!(h);
                }
                v
            })
            .collect();
        let mut v = json!({ "ok": true, "requestId": j.request_id, "handle": j.handle,
                            "chainId": j.chain_id, "from": j.from,
                            "status": status, "final": j.is_final(now),
                            "origin": j.origin, "purpose": j.purpose,
                            "legs": legs, "hashes": j.hashes() });
        if let Some(h) = j.hashes().last() {
            v["hash"] = json!(h);
        }
        match &j.status {
            SendStatus::Broadcast { hash, route } => {
                v["hash"] = json!(hash);
                v["route"] = json!(route);
            }
            SendStatus::Failed { reason } => v["reason"] = json!(reason),
            _ => {}
        }
        if status == "stuck" {
            v["reason"] = json!(
                "the broadcast has not answered; this send may already be on chain and must \
                 not be sent again"
            );
        }
        v
    }

    /// Settle a job and announce it. The ledger applies the status to the LIVE job and gives
    /// back whatever it now holds, so a status another dispatch settled first is reported
    /// rather than overwritten from this caller's stale copy — and announced only when THIS
    /// call is what moved it, because the reply is a truthful answer to a settle that lost.
    fn settle(&self, st: &State, request_id: &str, status: SendStatus) -> Result<Value, String> {
        let s = st
            .sends
            .settle(request_id, status)
            .ok_or_else(|| format!("no send with id '{request_id}'"))?;
        if s.changed {
            emit_send_status_changed(&s.job.request_id);
        }
        Ok(Self::job_reply(&s.job, history::now_secs()))
    }

    /// The broadcast owner's door — the only settle that lands once a broadcast is claimed.
    fn settle_owned(
        &self,
        st: &State,
        t: &send::BroadcastTicket,
        status: SendStatus,
    ) -> Result<Value, String> {
        let s = st
            .sends
            .settle_owned(t, status)
            .ok_or_else(|| "the send vanished while it was being broadcast".to_string())?;
        if s.changed {
            emit_send_status_changed(&s.job.request_id);
        }
        Ok(Self::job_reply(&s.job, history::now_secs()))
    }
}

impl TxSenderModule for TxSenderModuleImpl {
    fn on_context_ready(&self, ctx: &RustModuleContext) {
        let dir = PathBuf::from(&ctx.instance_persistence_path);
        let history = History::new(dir);

        // The ledger is in-memory and `latest` does not count a broadcast that has not
        // mined, so a restart would hand the next send a number an unsettled transaction is
        // already using. Burn them before any send can reach `state()`.
        let seeded = self.sends.seed_spent(history.unsettled_nonces());
        if seeded > 0 {
            eprintln!("tx_sender_module: {seeded} unsettled nonces carried over from disk");
        }

        if let Ok(mut g) = self.state.write() {
            *g = Some(Arc::new(State { history, sends: self.sends.clone() }));
        }
        // Arm before the first gated read rather than on it: the gate cache may only trust an
        // answer read after its feed existed, so arming late costs a live read per chain.
        self.watch_gate();
        self.watch_chain_config();
    }

    fn prepare(&self, request_json: String) -> String {
        let req: CallRequest = match serde_json::from_str(&request_json) {
            Ok(r) => r,
            Err(e) => return err(format!("invalid request: {e}")),
        };
        let b = Budget::bounded_by(SEND_BUDGET, req.deadline_ms);
        if req.chain_id == 0 {
            return err("chainId is required");
        }
        if let Err(v) = self.verified_gate_within(req.chain_id, &b) {
            return blocked(&v).to_string();
        }
        match self.quote(&req, &b) {
            Ok(q) => Self::quote_reply(&q).to_string(),
            Err(e) => err(e),
        }
    }

    fn send(&self, request_json: String) -> String {
        let req: CallRequest = match serde_json::from_str(&request_json) {
            Ok(r) => r,
            Err(e) => return err(format!("invalid request: {e}")),
        };
        let b = Budget::bounded_by(SEND_BUDGET, req.deadline_ms);
        let st = match self.state() {
            Ok(st) => st,
            Err(e) => return err(e),
        };
        if req.chain_id == 0 {
            return err("chainId is required");
        }
        if let Err(v) = self.verified_gate_within(req.chain_id, &b) {
            return blocked(&v).to_string();
        }
        match self.request_send(&st, &req, &b) {
            // Deliberately no hash: nothing is signed or broadcast until a human approves.
            Ok((id, handle)) => {
                json!({ "ok": true, "pending": true, "requestId": id, "handle": handle })
                    .to_string()
            }
            Err(e) => err(e),
        }
    }

    fn send_status(&self, request_id: String) -> String {
        match self.advance_send(&request_id) {
            Ok(v) => v.to_string(),
            // Read from the ledger, not the sentence: final only for a send it does not hold.
            Err(e) => {
                let st = self.state().ok();
                let fin = send::refusal_is_final(st.as_deref().map(|s| &*s.sends), &request_id);
                json!({ "ok": false, "error": e, "final": fin }).to_string()
            }
        }
    }

    fn cancel_send(&self, request_id: String) -> String {
        // Cancel locally FIRST, under the ledger's lock; telling the keystore is a courtesy
        // whose reply was already discarded. The other order let two cancels release the same
        // nonce twice, or one cancel a send another poll had begun broadcasting.
        match self.state().and_then(|st| {
            let job = st.sends.claim_cancel(&request_id)?;
            let _ = modules().keystore_module.cancel_approval_with_timeout(
                &job.handle,
                &job.receipt,
                RPC_BUDGET,
            );
            emit_send_status_changed(&job.request_id);
            Ok(Self::job_reply(&job, history::now_secs()))
        }) {
            Ok(v) => v.to_string(),
            Err(e) => err(e),
        }
    }

    fn live_sends(&self) -> String {
        let _b = Budget::new(READ_BUDGET);
        let st = match self.state() {
            Ok(st) => st,
            Err(e) => return err(e),
        };
        let now = history::now_secs();
        let sends: Vec<Value> = st
            .sends
            .live(now)
            .iter()
            .map(|j| {
                json!({ "requestId": j.request_id, "handle": j.handle, "chainId": j.chain_id,
                        "from": j.from, "status": j.reported_status(now),
                        "origin": j.origin, "purpose": j.purpose })
            })
            .collect();
        json!({ "ok": true, "sends": sends }).to_string()
    }

    fn history(&self, address: String, chain_id: i64) -> String {
        if chain_id < 0 {
            return err(format!("chain {chain_id} is not a valid chain id"));
        }
        let st = match self.state() {
            Ok(st) => st,
            Err(e) => return err(e),
        };
        let chain_id = chain_id as u64;
        // Rows are derived on read, so one that confirmed while the consumer was closed reads
        // `confirmed` the moment anything asks. The sweep announces that itself, per row: a
        // read must not, or a subscriber drives it round again.
        let swept = self.sweep(&st, &address, &Budget::new(SWEEP_BUDGET));
        let rows = st.history.list(&address);
        let mut v = history_reply(&address, chain_id, &rows, history::now_secs(), &swept);
        // Numbers a duplicate request id stranded: nothing holds them, nothing will hand
        // them back, and every later send queues behind them. Disclosed rather than released,
        // because "nobody holds it" is not evidence a transaction did not leave.
        let stranded: Vec<Value> = st
            .sends
            .stranded()
            .iter()
            .filter(|(c, a, _)| (chain_id == 0 || *c == chain_id) && send::same_account(a, &address))
            .map(|(c, _, n)| json!({ "chainId": c, "nonce": n }))
            .collect();
        v["strandedNonces"] = json!(stranded);
        v.to_string()
    }

    fn refresh_pending(&self, address: String) -> String {
        // Gated per record inside the sweep: a row carries its own chain, so a blocking proxy
        // on one chain must not suppress a due row elsewhere. `blockedChains` says which rows
        // that cost, and why.
        let st = match self.state() {
            Ok(st) => st,
            Err(e) => return err(e),
        };
        let s = self.sweep(&st, &address, &Budget::new(SWEEP_BUDGET));
        json!({ "ok": true, "address": address, "polled": s.polled,
                "changed": s.changed, "blocked": s.blocked_count(),
                "blockedChains": s.blocked_json(), "stillDue": s.still_due })
        .to_string()
    }

    fn refresh_tx_status(&self, address: String, hash_hex: String) -> String {
        match self.refresh_one(&address, &hash_hex) {
            Ok(v) => v.to_string(),
            Err(e) => err(e),
        }
    }

    fn tx_details(&self, address: String, hash_hex: String) -> String {
        match self.fetch_details(&address, &hash_hex) {
            Ok(v) => v.to_string(),
            // Not `err()`: this reply is rendered beside ONE transaction's rows, so even a
            // refusal has to name the hash it is about or it could land under another.
            Err(e) => details::details_refusal(&hash_hex, &e).to_string(),
        }
    }
}

// The registration hook. The generated provider glue DECLARES this symbol and the loader
// resolves it at dlopen; the author owes the definition. Omitting it links cleanly and
// segfaults inside `ensure_ready` at set_context time on macOS (lazy resolution, no hint);
// Linux at least says `undefined symbol: logos_module_install`.
#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<TxSenderModuleImpl>();
}
