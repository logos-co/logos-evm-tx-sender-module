//! The send state machine and nonce reservation — the parts that must be correct without a
//! network. Everything here is pure and unit-tested; `glue.rs` does the I/O around it.
//!
//! A send is a BUNDLE of one or more calls from one account on one chain, approved by a human
//! as one decision and signed under one key derivation. Each leg carries its own nonce, and
//! the ledger reserves them together: two sends racing through `open` take disjoint runs of
//! numbers, and a bundle abandoned before its approval hands every one of them back.
//!
//! The numbers leave one at a time. A leg's nonce is burnt the instant its signed bytes are
//! about to leave — `leaving` is the door, and `broadcast` in the glue demands its proof —
//! so a bundle whose second leg never went out still frees that number, while the first,
//! which may be on chain, is spent for ever.

use std::collections::{BTreeSet, HashMap};

use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::units;

/// The most calls one approval may carry. A bundle is one human decision, and a decision
/// over more than this is not one a human reads.
pub const MAX_LEGS: usize = 8;

/// Where a send has got to. A job is created `AwaitingApproval` and reaches exactly one
/// terminal state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum SendStatus {
    AwaitingApproval,
    /// Every leg approved and handed to the chain. `hash` is the LAST leg's; the legs carry
    /// their own. `route` is how `eth_rpc` got them there: a broadcast is forwarded to a
    /// provider on trust and is never proof-backed.
    Broadcast { hash: String, route: String },
    Rejected,
    Cancelled,
    Failed { reason: String },
}

impl SendStatus {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, SendStatus::AwaitingApproval)
    }

    /// The wire word for this status. One spelling, shared by the reply and the refusals,
    /// so a user is never told a send is `Broadcast { hash: .., route: .. }`.
    pub fn label(&self) -> &'static str {
        match self {
            SendStatus::AwaitingApproval => "awaitingApproval",
            SendStatus::Broadcast { .. } => "broadcast",
            SendStatus::Rejected => "rejected",
            SendStatus::Cancelled => "cancelled",
            SendStatus::Failed { .. } => "failed",
        }
    }
}

/// One call of a bundle: the transaction as the human approved it, and where it got to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Leg {
    pub to: String,
    /// Decimal wei attached to the call.
    pub value: String,
    /// The calldata, `0x`-prefixed. `"0x"` is a plain transfer's own answer.
    pub data: String,
    pub gas_limit: u64,
    pub nonce: u64,
    /// The requester's word for this leg, shown beside it. Never interpreted.
    #[serde(default)]
    pub label: String,
    /// Whatever the requester wants stored beside the row, verbatim. `Null` when none.
    #[serde(default)]
    pub meta: Value,
    /// The hash the broadcast answered with; `None` until it did.
    #[serde(default)]
    pub hash: Option<String>,
    /// Whether this leg's signed bytes may have left the process. Set through `leaving`
    /// immediately before the broadcast and never cleared: it is what burns the nonce.
    #[serde(default)]
    pub left: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendJob {
    pub request_id: String,
    pub handle: String,
    pub receipt: String,
    pub chain_id: u64,
    pub from: String,
    /// In order. Signed in this order, broadcast in this order, one nonce each.
    pub legs: Vec<Leg>,
    /// The fee price every leg was quoted at. Carried because the history row is written
    /// after the approval, by which point the quote is gone and a receipt never repeats these.
    pub max_fee: String,
    #[serde(default)]
    pub max_priority: String,
    /// What the requester claimed the bundle is for, as the keystore showed it.
    #[serde(default)]
    pub purpose: String,
    /// The module that asked, as the runtime attested it. Recorded, never trusted for
    /// anything but naming the row.
    #[serde(default)]
    pub origin: String,
    pub status: SendStatus,
    /// Set before any leg leaves, so a concurrent poll cannot send it twice, and carrying
    /// the ticket that alone may settle the job from then on.
    pub broadcast: Option<Broadcasting>,
    /// What this send replaces, when it deliberately takes another's nonce. Set from the
    /// claim, never by the caller — an undirected share is a collision, not a replacement.
    #[serde(default)]
    pub replaces: Option<Replaces>,
}

/// What a pinned nonce is taking over from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Replaces {
    /// A send this process still holds, by request id: its transaction has begun to leave.
    Send(String),
    /// A send this process never saw. The number is burnt — a previous process signed at it,
    /// or a holder vanished with it — and nothing here holds it, so nothing can hand it
    /// back. Pinning it is the only way an account queued behind it ever moves again.
    Departed,
}

/// An outstanding broadcast: which dispatch owns it, and when it took it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Broadcasting {
    pub ticket: u64,
    pub claimed_at: u64,
}

/// A broadcast whose RPC has not answered in this long is DISCLOSED as `stuck` rather than
/// left reading `awaitingApproval` for ever. The job stays non-terminal and keeps its nonces —
/// we cannot say the transaction is not on chain — but a consumer may stop waiting on it.
pub const STUCK_AFTER_SECS: u64 = 180;

impl SendJob {
    /// Claim the right to broadcast. Returns false if anyone already claimed it.
    fn claim_broadcast(&mut self, ticket: u64, now: u64) -> bool {
        if self.broadcast.is_some() || self.status.is_terminal() {
            return false;
        }
        self.broadcast = Some(Broadcasting { ticket, claimed_at: now });
        true
    }

    pub fn broadcast_started(&self) -> bool {
        self.broadcast.is_some()
    }

    /// Whether this leg's signed transaction may have reached the chain. Monotone: `left`
    /// is never cleared and `Broadcast` is terminal, so nothing ever un-spends a nonce.
    fn leg_spent(&self, i: usize) -> bool {
        self.legs[i].left || matches!(self.status, SendStatus::Broadcast { .. })
    }

    /// Whether a leg's nonce is still its own — while the job can move, and for ever after
    /// the leg may have left.
    fn holds_leg(&self, i: usize) -> bool {
        !self.status.is_terminal() || self.leg_spent(i)
    }

    /// Whether any nonce is still this job's.
    fn holds_nonce(&self) -> bool {
        (0..self.legs.len()).any(|i| self.holds_leg(i))
    }

    /// The legs' nonces, in leg order.
    pub fn nonces(&self) -> Vec<u64> {
        self.legs.iter().map(|l| l.nonce).collect()
    }

    /// The hashes the legs that answered carry, in leg order.
    pub fn hashes(&self) -> Vec<String> {
        self.legs.iter().filter_map(|l| l.hash.clone()).collect()
    }

    /// The claim owns the identity: chain, account, the nonces and what this send replaces.
    /// The caller supplies the payload only, so the one hand-off the ledger cannot audit — a
    /// job given different numbers from its claim — is not expressible. A draft with more
    /// legs than the claim has numbers is cut to the claim: a leg with no number is a leg
    /// nothing was signed at.
    fn from_claim(c: &Claim, mut draft: SendJob) -> SendJob {
        draft.legs.truncate(c.nonces.len());
        for (leg, n) in draft.legs.iter_mut().zip(c.nonces.iter()) {
            leg.nonce = *n;
        }
        SendJob {
            chain_id: c.chain_id,
            from: c.from.clone(),
            replaces: c.replaces.clone(),
            ..draft
        }
    }

    /// A claim whose RPC has not come back within `STUCK_AFTER_SECS`.
    pub fn is_stuck(&self, now: u64) -> bool {
        !self.status.is_terminal()
            && self
                .broadcast
                .is_some_and(|b| now.saturating_sub(b.claimed_at) >= STUCK_AFTER_SECS)
    }

    /// What a caller is told this send is doing. `broadcasting` and `stuck` are not states a
    /// job settles into; they describe a claim still outstanding, and exist so a send whose
    /// signed transaction has left is never reported as `awaitingApproval`.
    pub fn reported_status(&self, now: u64) -> &'static str {
        match (self.status.is_terminal(), self.broadcast.is_some(), self.is_stuck(now)) {
            (true, _, _) | (false, false, _) => self.status.label(),
            (false, true, true) => "stuck",
            (false, true, false) => "broadcasting",
        }
    }
}

/// Nonces handed out but not yet mined.
///
/// Load-bearing rather than a nicety: the verified proxy refuses the `pending` block tag
/// (a light client proves against a header's stateRoot, and pending has none), so the nonce
/// comes from `latest`, which does not count a broadcast-but-unmined transaction. Without
/// this, two sends in quick succession collide and the second is silently lost.
#[derive(Default)]
pub struct NonceReserver {
    accounts: HashMap<(u64, String), AccountNonces>,
}

/// One account's numbers. `spent` is append-only and nothing ever takes anything out of it:
/// a nonce used to sign a transaction that may have reached the chain must never be handed
/// to another send, and a set that only grows makes that structural rather than a rule every
/// release door has to remember.
#[derive(Default)]
struct AccountNonces {
    reserved: BTreeSet<u64>,
    spent: BTreeSet<u64>,
}

fn key(chain_id: u64, address: &str) -> (u64, String) {
    // Lowercased FIRST, so a `0X` prefix is stripped like a `0x` one.
    (chain_id, address.trim().to_lowercase().trim_start_matches("0x").to_string())
}

/// Two spellings of one account. The reserver's own notion of identity, since a nonce is
/// held per (chain, account) and a caller's `0x` or letter case is no part of it.
pub fn same_account(a: &str, b: &str) -> bool {
    key(0, a) == key(0, b)
}

impl NonceReserver {
    /// The next free nonce at or above what the chain reports at `latest`.
    ///
    /// A chain reading frees nothing. `latest` comes from a load-balanced provider and is
    /// monotonic neither across calls nor across a reorg, so dropping reservations below it
    /// hands the next send a number that is already on chain. Numbers below the reading are
    /// stepped over instead; a released one is reused by the scan, so no gap is skipped.
    pub fn reserve(&mut self, chain_id: u64, address: &str, chain_nonce: u64) -> u64 {
        let a = self.accounts.entry(key(chain_id, address)).or_default();
        let mut candidate = chain_nonce;
        while a.reserved.contains(&candidate) || a.spent.contains(&candidate) {
            candidate += 1;
        }
        a.reserved.insert(candidate);
        candidate
    }

    /// Take an exact nonce. False when it is already held or ever spent: pinning a number a
    /// live send is using is the legitimate way to replace a stuck transaction, so such a
    /// claim shares that number rather than owning it — and must never release it.
    pub fn hold(&mut self, chain_id: u64, address: &str, nonce: u64) -> bool {
        let a = self.accounts.entry(key(chain_id, address)).or_default();
        !a.spent.contains(&nonce) && a.reserved.insert(nonce)
    }

    /// This number has been used to sign a transaction that may be leaving. A one-way door,
    /// reached from `sync_nonce` and from `seed_spent` and nowhere else. True when it is new.
    fn mark_spent(&mut self, chain_id: u64, address: &str, nonce: u64) -> bool {
        let a = self.accounts.entry(key(chain_id, address)).or_default();
        a.reserved.insert(nonce);
        a.spent.insert(nonce)
    }

    /// Give a nonce back. Private, because releasing needs two facts this cannot see: that
    /// the holder leaving owned the number, and that nobody else still holds it.
    /// `release_if_unheld` is the only caller.
    fn release(&mut self, chain_id: u64, address: &str, nonce: u64) {
        let k = key(chain_id, address);
        let Some(a) = self.accounts.get_mut(&k) else { return };
        if a.spent.contains(&nonce) {
            return;
        }
        a.reserved.remove(&nonce);
        if a.reserved.is_empty() && a.spent.is_empty() {
            self.accounts.remove(&k);
        }
    }

    /// Test-only: drop a number outright, spent or not. This is the corruption the audit
    /// exists to catch, and `release` deliberately cannot express it.
    #[cfg(test)]
    fn forget(&mut self, chain_id: u64, address: &str, nonce: u64) {
        if let Some(a) = self.accounts.get_mut(&key(chain_id, address)) {
            a.reserved.remove(&nonce);
            a.spent.remove(&nonce);
        }
    }

    fn holds(&self, chain_id: u64, address: &str, nonce: u64) -> bool {
        self.accounts.get(&key(chain_id, address)).is_some_and(|a| a.reserved.contains(&nonce))
    }

    /// Put a number back. `Ledger::audit`'s repair alone — the conservative direction.
    fn reinstate(&mut self, chain_id: u64, address: &str, nonce: u64) {
        self.accounts.entry(key(chain_id, address)).or_default().reserved.insert(nonce);
    }

    pub fn outstanding(&self, chain_id: u64, address: &str) -> usize {
        self.accounts.get(&key(chain_id, address)).map(|a| a.reserved.len()).unwrap_or(0)
    }
}

pub use gate::SendLedger;

/// The choke point. `Ledger` is reachable from nowhere but `SendLedger::lock`, and that
/// guard audits the invariant as it is released — so a new door cannot forget the check,
/// and one that tried to skip it would have to name a field this module does not export.
mod gate {
    use std::ops::{Deref, DerefMut};
    use std::sync::{Mutex, MutexGuard};

    use super::Ledger;

    /// Every in-flight send and the nonces they hold — under ONE lock, because
    /// `concurrency: "multi"` really does run these at once. Two locks could not express
    /// "reserve these nonces AND record the send" as one decision. The outbound calls happen
    /// after the critical section, holding nothing.
    #[derive(Default)]
    pub struct SendLedger {
        inner: Mutex<Ledger>,
    }

    impl SendLedger {
        /// The only route to the ledger, for every door. A panic cannot leave a half-applied
        /// ledger — every mutation is a few field writes — and refusing every send for the
        /// rest of the process is worse than carrying on.
        pub(super) fn lock(&self) -> Audited<'_> {
            Audited(self.inner.lock().unwrap_or_else(|e| e.into_inner()))
        }

        /// Test-only: drop a reservation without auditing, so that what a door's OWN audit
        /// catches can be measured. The only other use of `inner` in the program.
        #[cfg(test)]
        pub(super) fn unreserve_behind_the_ledgers_back(&self, chain: u64, addr: &str, n: u64) {
            let mut l = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            l.nonces.forget(chain, addr, n);
        }
    }

    /// A borrow of the ledger that audits when it is released.
    pub(super) struct Audited<'a>(MutexGuard<'a, Ledger>);

    impl Deref for Audited<'_> {
        type Target = Ledger;
        fn deref(&self) -> &Ledger {
            &self.0
        }
    }

    impl DerefMut for Audited<'_> {
        fn deref_mut(&mut self) -> &mut Ledger {
            &mut self.0
        }
    }

    impl Drop for Audited<'_> {
        fn drop(&mut self) {
            self.0.audit();
        }
    }
}

#[derive(Default)]
struct Ledger {
    jobs: HashMap<String, SendJob>,
    claims: HashMap<u64, Claim>,
    nonces: NonceReserver,
    last_claim: u64,
    last_ticket: u64,
    /// Nonces left reserved by a job that was overwritten before it could let go. Recorded,
    /// never acted on: "nobody holds this, so free it" is the exact reasoning that hands out
    /// a number already on chain. A leak is an availability fault to disclose.
    stranded: Vec<(u64, String, u64)>,
}

impl Ledger {
    /// The invariant, as data. Two properties, both computable from the ledger alone:
    ///
    /// * containment — every nonce a claim, a live job or a leg that may have reached the
    ///   chain holds is still reserved. This is "a nonce that may be on chain is never handed
    ///   to another send" in a form a machine can check.
    /// * uniqueness — at most one holder of a number is not an explicit replacement.
    ///
    /// The converse of containment is deliberately NOT checked. A reservation nobody holds
    /// costs a gap; asserting it away is the reasoning that releases an on-chain nonce.
    fn violations(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut accounts: HashMap<(u64, String), Vec<(u64, bool, String)>> = HashMap::new();
        for c in self.claims.values() {
            let who = format!("claim {}", c.id);
            for n in &c.nonces {
                accounts.entry(key(c.chain_id, &c.from)).or_default().push((
                    *n,
                    c.replaces.is_none(),
                    who.clone(),
                ));
            }
        }
        for j in self.jobs.values() {
            let counts = !j.status.is_terminal() && j.replaces.is_none();
            for (i, leg) in j.legs.iter().enumerate() {
                if !j.holds_leg(i) {
                    continue;
                }
                accounts.entry(key(j.chain_id, &j.from)).or_default().push((
                    leg.nonce,
                    counts,
                    j.request_id.clone(),
                ));
            }
        }
        for (k, holders) in &accounts {
            for (nonce, _, who) in holders {
                if !self.nonces.holds(k.0, &k.1, *nonce) {
                    out.push(format!("{who} holds nonce {nonce} on {}/{} unreserved", k.0, k.1));
                }
            }
            for (nonce, _, who) in holders.iter().filter(|(_, counts, _)| *counts) {
                let rivals = holders
                    .iter()
                    .filter(|(n, counts, w)| *n == *nonce && *counts && w != who)
                    .count();
                if rivals > 0 {
                    out.push(format!("{who} shares nonce {nonce} with {rivals} other holders"));
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Run as `Audited` is released, which is every door in and out of this ledger. A module
    /// that panics in its send path is its own failure mode, so a violation in release
    /// re-reserves the missing numbers — the direction that costs a gap rather than a
    /// collision — and says so. Tests and debug builds panic instead.
    fn audit(&mut self) {
        let faults = self.violations();
        if faults.is_empty() {
            return;
        }
        let mut repairs: Vec<(u64, String, u64)> = Vec::new();
        for c in self.claims.values() {
            repairs.extend(c.nonces.iter().map(|n| (c.chain_id, c.from.clone(), *n)));
        }
        for j in self.jobs.values() {
            for (i, leg) in j.legs.iter().enumerate() {
                if j.holds_leg(i) {
                    repairs.push((j.chain_id, j.from.clone(), leg.nonce));
                }
            }
        }
        for (chain_id, from, nonce) in repairs {
            self.nonces.reinstate(chain_id, &from, nonce);
        }
        let why = faults.join("; ");
        // Panicking again while unwinding aborts the process, so a test that is already
        // failing gets the repair and the message rather than a hard stop.
        if cfg!(debug_assertions) && !std::thread::panicking() {
            panic!("send ledger invariant violated: {why}");
        }
        eprintln!("tx_sender_module: send ledger invariant violated and repaired: {why}");
    }
}

/// A send that has been priced and has reserved its nonces, but whose approval request has
/// not come back yet. It has no request id — the keystore's handle supplies that.
#[derive(Clone, Debug)]
pub struct Claim {
    pub id: u64,
    pub chain_id: u64,
    pub from: String,
    /// One per leg, in leg order.
    pub nonces: Vec<u64>,
    /// What this claim replaces, when it shares another's nonce. `None` means this claim is
    /// the only holder — the ledger refuses a pin that would share a number with a send
    /// which has not broadcast, because that is a collision and not a replacement.
    pub replaces: Option<Replaces>,
}

impl Claim {
    /// The first leg's number.
    pub fn nonce(&self) -> u64 {
        self.nonces[0]
    }
}

/// Proof that this dispatch owns the broadcast. Deliberately not `Clone`: while it is
/// outstanding nothing else may settle the job — the rule `claim_cancel` enforces at the
/// cancel door, extended to every door.
pub struct BroadcastTicket {
    request_id: String,
    ticket: u64,
}

/// Proof that one leg's nonce is burnt. `SendLedger::leaving` is the only constructor and
/// the glue's `broadcast` demands it, so bytes cannot leave on a number the ledger could
/// still hand to another send.
#[derive(Debug)]
pub struct Leaving {
    request_id: String,
    leg: usize,
}

impl Leaving {
    pub fn leg(&self) -> usize {
        self.leg
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

/// What asking for the right to broadcast answered.
pub enum BroadcastClaim {
    /// This caller owns the broadcast and must settle the job through its ticket.
    Claimed(BroadcastTicket),
    /// Another dispatch is broadcasting it right now.
    InFlight(SendJob),
    /// Already terminal — rejected, cancelled, failed or broadcast.
    Settled(SendJob),
    Unknown,
}

impl SendLedger {
    /// Open a claim for a send of `count` legs on `chain_id`.
    ///
    /// Under one lock: reserve the numbers and record the claim. Unpinned legs take the next
    /// free numbers at or above `chain_nonce`, one each, so two bundles racing here take
    /// disjoint runs. A pin names ONE transaction to replace and is refused for a bundle.
    pub fn open(
        &self,
        chain_id: u64,
        from: &str,
        chain_nonce: u64,
        count: usize,
        pinned: Option<u64>,
    ) -> Result<ClaimGuard<'_>, String> {
        if count == 0 || count > MAX_LEGS {
            return Err(format!("a send carries between 1 and {MAX_LEGS} calls, not {count}"));
        }
        let mut l = self.lock();
        let (nonces, replaces) = match pinned {
            Some(n) if count == 1 => (vec![n], pin(&mut l, chain_id, from, n)?),
            Some(_) => {
                return Err("a pinned nonce replaces ONE transaction; a bundle cannot be pinned"
                    .into())
            }
            None => {
                let mut nonces = Vec::with_capacity(count);
                for _ in 0..count {
                    nonces.push(l.nonces.reserve(chain_id, from, chain_nonce));
                }
                (nonces, None)
            }
        };
        l.last_claim += 1;
        let claim = Claim { id: l.last_claim, chain_id, from: from.to_string(), nonces, replaces };
        l.claims.insert(claim.id, claim.clone());
        Ok(ClaimGuard { ledger: self, claim: Some(claim) })
    }

    fn commit(&self, c: &Claim, job: SendJob) {
        let mut l = self.lock();
        l.claims.remove(&c.id);
        let job = SendJob::from_claim(c, job);
        // A repeated request id overwrites a LIVE job: nothing burns its numbers and no
        // holder is left to release them, so they stay reserved for the life of the process.
        // Saying so is the whole remedy — releasing them is what must not happen.
        if let Some(prev) = l.jobs.insert(job.request_id.clone(), job) {
            if prev.holds_nonce() {
                eprintln!(
                    "tx_sender_module: send {} was replaced by another with the same id; \
                     nonces {:?} on chain {} are now held by nobody and stay reserved",
                    prev.request_id,
                    prev.nonces(),
                    prev.chain_id
                );
                for n in prev.nonces() {
                    l.stranded.push((prev.chain_id, prev.from.clone(), n));
                }
            }
        }
    }

    fn abandon(&self, c: &Claim) {
        let mut l = self.lock();
        l.claims.remove(&c.id);
        for n in &c.nonces {
            release_if_unheld(&mut l, c.chain_id, &c.from, *n);
        }
    }

    pub fn get(&self, request_id: &str) -> Option<SendJob> {
        self.lock().jobs.get(request_id).cloned()
    }

    /// Every job that could still move and is not stuck — what a consumer that must not
    /// change the ground under a pending approval asks before it does.
    pub fn live(&self, now: u64) -> Vec<SendJob> {
        let l = self.lock();
        let mut out: Vec<SendJob> = l
            .jobs
            .values()
            .filter(|j| !j.status.is_terminal() && !j.is_stuck(now))
            .cloned()
            .collect();
        out.sort_by(|a, b| a.request_id.cmp(&b.request_id));
        out
    }

    /// Apply a terminal status to the LIVE job. A job another dispatch already settled comes
    /// back untouched — the first terminal state wins — and so does one whose broadcast is
    /// claimed: past that point only the ticket holder may settle it.
    pub fn settle(&self, request_id: &str, status: SendStatus) -> Option<Settled> {
        settle_locked(&mut self.lock(), request_id, status, None)
    }

    /// Settle the job this ticket owns. The only door open once a broadcast is claimed.
    pub fn settle_owned(&self, t: &BroadcastTicket, status: SendStatus) -> Option<Settled> {
        settle_locked(&mut self.lock(), &t.request_id, status, Some(t.ticket))
    }

    /// Claim the right to broadcast. Taken immediately before the first leg leaves and
    /// nowhere earlier: a claim held across a call that does not move money wedges the send
    /// if that call fails, because nothing ever releases it. Burns nothing yet — a leg's
    /// number is burnt by `leaving`, the moment its own bytes are about to go.
    pub fn claim_broadcast(&self, request_id: &str, now: u64) -> BroadcastClaim {
        let mut l = self.lock();
        let ticket = l.last_ticket + 1;
        let Some(job) = l.jobs.get_mut(request_id) else { return BroadcastClaim::Unknown };
        if job.status.is_terminal() {
            return BroadcastClaim::Settled(job.clone());
        }
        if !job.claim_broadcast(ticket, now) {
            return BroadcastClaim::InFlight(job.clone());
        }
        l.last_ticket = ticket;
        BroadcastClaim::Claimed(BroadcastTicket { request_id: request_id.to_string(), ticket })
    }

    /// One leg's signed bytes are about to leave. Burns its number here rather than at the
    /// settle: between the two the outcome is unknown, and that is the window a job settling
    /// `Failed` used to hand its nonce to the next send through. `None` when the ticket does
    /// not own the job or the leg does not exist — and then nothing may be sent.
    pub fn leaving(&self, t: &BroadcastTicket, leg: usize) -> Option<Leaving> {
        let mut l = self.lock();
        let job = l.jobs.get_mut(&t.request_id)?;
        if job.broadcast.map(|b| b.ticket) != Some(t.ticket) || leg >= job.legs.len() {
            return None;
        }
        job.legs[leg].left = true;
        sync_nonce(&mut l, &t.request_id);
        Some(Leaving { request_id: t.request_id.clone(), leg })
    }

    /// The broadcast answered: the leg takes its hash. Only the ticket holder, only for a
    /// leg that left. Answers whether the job now holds it.
    pub fn landed(&self, t: &BroadcastTicket, leg: usize, hash: &str) -> bool {
        let mut l = self.lock();
        let Some(job) = l.jobs.get_mut(&t.request_id) else { return false };
        if job.broadcast.map(|b| b.ticket) != Some(t.ticket) {
            return false;
        }
        match job.legs.get_mut(leg) {
            Some(l) if l.left => {
                l.hash = Some(hash.to_string());
                true
            }
            _ => false,
        }
    }

    /// Cancel and hand back the settled job. Refused once the broadcast is claimed: that
    /// transaction may already be on its way, and releasing its nonce then hands the next
    /// send the very nonce it is using.
    pub fn claim_cancel(&self, request_id: &str) -> Result<SendJob, String> {
        let mut l = self.lock();
        let job = l
            .jobs
            .get(request_id)
            .ok_or_else(|| format!("no send with id '{request_id}'"))?;
        if job.status.is_terminal() {
            return Err(format!(
                "this send is already {} and cannot be cancelled",
                job.status.label()
            ));
        }
        if job.broadcast_started() {
            return Err("this send is being broadcast and can no longer be cancelled".into());
        }
        // Unconditionally a move: the two guards above are exactly the paths on which
        // `settle_locked` writes nothing, so this door's caller always has something to say.
        settle_locked(&mut l, request_id, SendStatus::Cancelled, None)
            .map(|s| s.job)
            .ok_or_else(|| format!("no send with id '{request_id}'"))
    }

    /// Burn what a previous process signed at. This ledger is in-memory and `latest` does not
    /// count a broadcast that has not mined, so without it a restart hands the next send a
    /// number a pending transaction is already using. A row that has since mined costs
    /// nothing — it sits below every later `latest`, where `reserve` starts looking — and
    /// seeding too much costs a gap where too little costs a collision. Answers what was new.
    pub fn seed_spent(&self, rows: impl IntoIterator<Item = (u64, String, u64)>) -> usize {
        let mut l = self.lock();
        let mut fresh = 0;
        for (chain_id, from, nonce) in rows {
            fresh += usize::from(l.nonces.mark_spent(chain_id, &from, nonce));
        }
        fresh
    }

    /// Nonces held for an account, claims included. The measure the tests assert on.
    pub fn outstanding(&self, chain_id: u64, address: &str) -> usize {
        self.lock().nonces.outstanding(chain_id, address)
    }

    /// Nonces reserved for a job that no longer exists, because another send took its id.
    /// Disclosed so a user can see why an account has queued and pin the number to get it
    /// moving; never released here, for the reason on `Ledger::stranded`.
    pub fn stranded(&self) -> Vec<(u64, String, u64)> {
        self.lock().stranded.clone()
    }

    /// The invariant, for the tests that assert on it directly rather than through the panic
    /// `audit` raises — including the one that shows the checker itself can fail.
    #[cfg(test)]
    fn faults(&self) -> Vec<String> {
        self.lock().violations()
    }
}

/// What a settle did: whatever the ledger holds NOW, and whether this call is what moved it.
/// Two of `settle_locked`'s three answers write nothing — an outsider settling a claimed
/// broadcast, and a settle arriving after a terminal status — and both must still report the
/// job, because that reply is what tells a stale caller the truth. Only `changed` may be
/// announced.
#[derive(Clone, Debug)]
pub struct Settled {
    pub job: SendJob,
    pub changed: bool,
}

impl Settled {
    fn unmoved(job: &SendJob) -> Self {
        Self { job: job.clone(), changed: false }
    }
}

/// Apply `status` to the live job. `ticket` is the broadcast owner's proof, `None` every
/// other door.
///
/// Three rules, all about a transaction that may already be on chain: once a broadcast is
/// claimed only its owner may settle the job; from that moment a leg that left never hands
/// its nonce back; and a ticketed hash corrects even a terminal status, because losing it
/// loses the user's only handle on money in flight.
fn settle_locked(
    l: &mut Ledger,
    request_id: &str,
    status: SendStatus,
    ticket: Option<u64>,
) -> Option<Settled> {
    let is_broadcast = matches!(status, SendStatus::Broadcast { .. });
    let out = {
        let job = l.jobs.get_mut(request_id)?;
        let owner = job.broadcast.map(|b| b.ticket);
        if owner.is_some() && owner != ticket {
            return Some(Settled::unmoved(job));
        }
        let correcting = is_broadcast
            && ticket.is_some()
            && !matches!(job.status, SendStatus::Broadcast { .. });
        if job.status.is_terminal() && !correcting {
            return Some(Settled::unmoved(job));
        }
        // Read before the write: re-affirming a status the job already holds moves nothing,
        // and an event for it is a subscriber re-reading what it was already told.
        let changed = job.status != status;
        job.status = status;
        Settled { job: job.clone(), changed }
    };
    // The new status is already written, so this job counts itself out of `held` for every
    // leg it can let go of — and counts itself in for ever for every leg that left.
    sync_nonce(l, request_id);
    Some(out)
}

/// Take the nonce a caller pinned.
///
/// A free number is simply reserved. One another send is holding is shared ONLY when that
/// send's leg has begun to leave: replacing a stuck transaction is what pinning is for, and
/// the claim then names what it replaces. Sharing with a send that has not left yet is not
/// a replacement — it is the collision an unpinned send a microsecond earlier would cause —
/// and it is refused rather than papered over.
///
/// A number nothing here holds is the escape, and it must not be refused. Seeding burns what
/// a previous process signed at, so after a restart every unsettled row's nonce is spent and
/// held by no job at all; a pin was then refused, and since an unmined nonce blocks every
/// later send behind it, the account was wedged with no way out. That number is exactly the
/// one a replacement must reuse.
fn pin(l: &mut Ledger, chain_id: u64, from: &str, n: u64) -> Result<Option<Replaces>, String> {
    if l.nonces.hold(chain_id, from, n) {
        return Ok(None);
    }
    let k = key(chain_id, from);
    let refuse = format!(
        "nonce {n} is already held by a send that has not been broadcast; a nonce may only \
         be pinned to replace a transaction that has already left"
    );
    if l.claims.values().any(|c| key(c.chain_id, &c.from) == k && c.nonces.contains(&n)) {
        return Err(refuse);
    }
    let mut replaces = None;
    for j in l.jobs.values().filter(|j| key(j.chain_id, &j.from) == k) {
        for (i, _) in j.legs.iter().enumerate().filter(|(_, leg)| leg.nonce == n) {
            match (j.leg_spent(i), j.holds_leg(i)) {
                (true, _) => replaces = Some(Replaces::Send(j.request_id.clone())),
                (false, true) => return Err(refuse),
                (false, false) => {}
            }
        }
    }
    if let Some(r) = replaces {
        return Ok(Some(r));
    }
    // Nothing live holds it, and it is not free. Reserved without a holder is the one place
    // this reads the converse of containment, and it reads it conservatively: the claim TAKES
    // the number rather than freeing it, so a transaction that may be on chain is replaced
    // and never merely forgotten.
    l.nonces.reinstate(chain_id, from, n);
    Ok(Some(Replaces::Departed))
}

/// The one writer of a job's numbers, and the reason the two halves of `leg_spent` cannot
/// disagree: the same predicate chooses between the one-way burn and the release. A leg
/// that left, or a job reaching `Broadcast` through any door, burns its number.
fn sync_nonce(l: &mut Ledger, request_id: &str) {
    let Some(j) = l.jobs.get(request_id) else { return };
    let (chain_id, from) = (j.chain_id, j.from.clone());
    let legs: Vec<(u64, bool)> = (0..j.legs.len()).map(|i| (j.legs[i].nonce, j.leg_spent(i))).collect();
    for (nonce, spent) in legs {
        if spent {
            l.nonces.mark_spent(chain_id, &from, nonce);
        } else {
            release_if_unheld(l, chain_id, &from, nonce);
        }
    }
}

/// Release `nonce` only if no claim and no job still holds it. The single shrinking path:
/// `NonceReserver::release` is private behind this, and refuses a spent number even here.
///
/// Ownership is recomputed rather than carried. A flag copied at a hand-off is exactly what
/// `commit` dropped when a claim became a job, and there is now no such flag to drop. The
/// departing holder counts itself out by being removed, or by having its status written,
/// before this is called.
fn release_if_unheld(l: &mut Ledger, chain_id: u64, from: &str, nonce: u64) {
    if held(l, &key(chain_id, from)).contains(&nonce) {
        return;
    }
    l.nonces.release(chain_id, from, nonce);
}

/// Every nonce still held for one account: a claim, a live job, or a leg that may have
/// reached the chain.
fn held(l: &Ledger, k: &(u64, String)) -> BTreeSet<u64> {
    let claims = l
        .claims
        .values()
        .filter(|c| key(c.chain_id, &c.from) == *k)
        .flat_map(|c| c.nonces.iter().copied());
    let jobs = l.jobs.values().filter(|j| key(j.chain_id, &j.from) == *k).flat_map(|j| {
        j.legs.iter().enumerate().filter(|(i, _)| j.holds_leg(*i)).map(|(_, leg)| leg.nonce)
    });
    claims.chain(jobs).collect()
}

/// A claim that releases itself. Every failure between the reservation and the approval —
/// including a `?` on an IPC error — must give the numbers back, and a `Drop` is the only
/// form of that which a new early return cannot forget.
pub struct ClaimGuard<'a> {
    ledger: &'a SendLedger,
    claim: Option<Claim>,
}

impl std::fmt::Debug for ClaimGuard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimGuard").field("claim", &self.claim).finish()
    }
}

impl ClaimGuard<'_> {
    pub fn claim(&self) -> &Claim {
        self.claim.as_ref().expect("a claim is live until it is committed")
    }

    /// The approval landed: the claim becomes a job and keeps its numbers.
    pub fn commit(mut self, job: SendJob) {
        if let Some(c) = self.claim.take() {
            self.ledger.commit(&c, job);
        }
    }
}

impl Drop for ClaimGuard<'_> {
    fn drop(&mut self) {
        if let Some(c) = self.claim.take() {
            self.ledger.abandon(&c);
        }
    }
}

/// The worst-case cost of a bundle: the value moved plus every leg's fee ceiling.
///
/// `max_fee_per_gas` is a ceiling, not a price — the user is never charged more, so this is
/// what their balance must cover for every leg to be includable.
pub fn max_cost_wei(value_wei: U256, gas_limits: &[u64], max_fee_per_gas: U256) -> Option<U256> {
    let gas: u64 = gas_limits.iter().try_fold(0u64, |a, g| a.checked_add(*g))?;
    let fee = max_fee_per_gas.checked_mul(U256::from(gas))?;
    value_wei.checked_add(fee)
}

/// Whether `balance` covers the ether a bundle needs: every leg's `value` plus every leg's
/// fee ceiling. A token moved by a call is not ether and is not checked here — that is the
/// requester's own knowledge.
///
/// The message is in whole `symbol` units and exact to the last digit: an error about money
/// must not round, and a user cannot act on a figure in wei.
pub fn affordable(
    balance_wei: U256,
    value_wei: U256,
    gas_limits: &[u64],
    max_fee_per_gas: U256,
    symbol: &str,
) -> Result<(), String> {
    let Some(total) = max_cost_wei(value_wei, gas_limits, max_fee_per_gas) else {
        return Err("fee calculation overflowed".into());
    };
    if balance_wei < total {
        let need = eth(total);
        let have = eth(balance_wei);
        return Err(format!(
            "insufficient funds: this send needs {need} {symbol} (the value plus the fee \
             ceiling of every call), and the account holds {have} {symbol}"
        ));
    }
    Ok(())
}

fn eth(v: U256) -> String {
    units::format_exact(&v.to_string(), 18).unwrap_or_else(|| v.to_string())
}

/// Largest `purpose` a requester may claim, in bytes. The keystore shows the whole line.
pub const MAX_PURPOSE_BYTES: usize = 256;
/// Largest `label` a leg may carry.
pub const MAX_LABEL_BYTES: usize = 120;
/// Largest `meta` a leg may carry, serialized. Stored verbatim on the row and returned with
/// it, so a large one is paid on every history read.
pub const MAX_META_BYTES: usize = 4096;

/// The line the keystore shows as the requester's claim: what was asked for, and who asked.
///
/// The keystore attests the requester, and every send crosses it as THIS module — so the
/// module that actually asked is named here, as the runtime attested it to us. It goes
/// AFTER the purpose so a consumer's own wording opens the line and can be compared
/// character for character against the keystore's reading below it.
pub fn claim_line(purpose: &str, origin: &str) -> String {
    let purpose = purpose.trim();
    let who = if origin.is_empty() { "an unnamed caller" } else { origin };
    if purpose.is_empty() {
        format!("A transaction [asked by {who}]")
    } else {
        format!("{purpose} [asked by {who}]")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{mpsc, Barrier, Mutex};

    use super::*;

    /// The request id a `replaces` names, or None when it names a send this process never
    /// saw. Every assertion below is about the id.
    fn names(r: &Option<Replaces>) -> Option<&str> {
        match r {
            Some(Replaces::Send(id)) => Some(id),
            _ => None,
        }
    }

    fn leg(nonce: u64) -> Leg {
        Leg {
            to: "0xbbbb".into(),
            value: "1".into(),
            data: "0x".into(),
            gas_limit: 21_000,
            nonce,
            label: String::new(),
            meta: Value::Null,
            hash: None,
            left: false,
        }
    }

    fn job() -> SendJob {
        SendJob {
            request_id: "req_1".into(),
            handle: "ksh_1".into(),
            receipt: "ksc_1".into(),
            chain_id: 1,
            from: "0xaaaa".into(),
            legs: vec![leg(7)],
            max_fee: "1".into(),
            max_priority: "1".into(),
            purpose: String::new(),
            origin: String::new(),
            status: SendStatus::AwaitingApproval,
            broadcast: None,
            replaces: None,
        }
    }

    fn job_with(n: usize) -> SendJob {
        SendJob { legs: (0..n as u64).map(leg).collect(), ..job() }
    }

    /// Open a one-leg claim the way `send` does.
    fn open(l: &SendLedger, chain_id: u64, chain_nonce: u64) -> ClaimGuard<'_> {
        l.open(chain_id, "0xaaaa", chain_nonce, 1, None).unwrap()
    }

    fn open_n(l: &SendLedger, chain_nonce: u64, count: usize) -> ClaimGuard<'_> {
        l.open(1, "0xaaaa", chain_nonce, count, None).unwrap()
    }

    fn bcast(hash: &str) -> SendStatus {
        SendStatus::Broadcast { hash: hash.into(), route: "proxied".into() }
    }

    /// What the claim owner does when every leg has left and the last answered with a hash.
    fn broadcast(l: &SendLedger, t: &BroadcastTicket, hash: &str) -> SendJob {
        l.settle_owned(t, bcast(hash)).unwrap().job
    }

    fn committed(l: &SendLedger, request_id: &str, nonce: u64) {
        let g = open(l, 1, nonce);
        g.commit(SendJob { request_id: request_id.into(), ..job() });
    }

    fn committed_n(l: &SendLedger, request_id: &str, nonce: u64, count: usize) {
        let g = open_n(l, nonce, count);
        g.commit(SendJob { request_id: request_id.into(), ..job_with(count) });
    }

    /// Two sends racing through `open`. The old shape reserved the nonce under one lock and
    /// recorded the send under another, with an approval request in between.
    #[test]
    fn concurrent_sends_never_share_a_nonce_and_never_lose_one() {
        let l = SendLedger::default();
        let start = Barrier::new(8);
        let nonces: Vec<u64> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        start.wait();
                        // Every thread reads the SAME chain nonce: `latest` does not count a
                        // send that has not been mined, which is the case this exists for.
                        let g = open(&l, 1, 5);
                        let n = g.claim().nonce();
                        g.commit(SendJob { request_id: format!("snd_{n}"), ..job() });
                        n
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        let mut sorted = nonces.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 8, "two sends took the same nonce: {nonces:?}");
        assert_eq!(sorted, (5..13).collect::<Vec<_>>(), "and they are consecutive");
        assert_eq!(l.outstanding(1, "0xaaaa"), 8, "each send still holds its own");

        for n in &sorted {
            l.settle(&format!("snd_{n}"), SendStatus::Cancelled);
        }
        assert_eq!(l.outstanding(1, "0xaaaa"), 0, "and every one comes back");
    }

    /// A bundle takes a RUN of numbers under the one lock, so two bundles racing take
    /// disjoint runs and a single send racing them lands beside both rather than inside one.
    #[test]
    fn concurrent_bundles_take_disjoint_runs_of_nonces() {
        let l = &SendLedger::default();
        let start = &Barrier::new(6);
        let runs: Vec<Vec<u64>> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..6usize)
                .map(|t| {
                    s.spawn(move || {
                        start.wait();
                        let count = if t % 2 == 0 { 3 } else { 1 };
                        let g = open_n(l, 5, count);
                        let run = g.claim().nonces.clone();
                        g.commit(SendJob { request_id: format!("snd_{t}"), ..job_with(count) });
                        run
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let mut all: Vec<u64> = runs.iter().flatten().copied().collect();
        all.sort_unstable();
        let n = all.len();
        all.dedup();
        assert_eq!(all.len(), n, "two sends shared a number: {runs:?}");
        assert_eq!(all, (5..17).collect::<Vec<_>>(), "twelve numbers, no gap: {runs:?}");
        for run in &runs {
            let consecutive = run.windows(2).all(|w| w[1] == w[0] + 1);
            assert!(consecutive, "a bundle's legs are consecutive: {run:?}");
        }
        assert_eq!(l.outstanding(1, "0xaaaa"), 12);
    }

    /// The leak the old `send` had: the nonce was reserved and then five `?`s could return
    /// without giving it back — an unparseable reply, an IPC error, a keystore refusal.
    #[test]
    fn a_claim_that_never_reaches_commit_gives_its_nonces_back() {
        let l = SendLedger::default();
        fn fails_after_reserving(l: &SendLedger) -> Result<(), String> {
            let _guard = open_n(l, 5, 3);
            Err("the keystore refused the approval request".into())
        }
        assert!(fails_after_reserving(&l).is_err());
        assert_eq!(l.outstanding(1, "0xaaaa"), 0, "the guard released all three on the way out");
        // And the next send gets that very nonce rather than skipping past it.
        assert_eq!(open(&l, 1, 5).claim().nonce(), 5);
    }

    #[test]
    fn a_committed_claim_keeps_its_nonces_until_the_send_settles() {
        let l = SendLedger::default();
        committed_n(&l, "snd_1", 5, 2);
        assert_eq!(l.outstanding(1, "0xaaaa"), 2);
        assert_eq!(open(&l, 1, 5).claim().nonce(), 7, "the next send must not reuse either");

        l.settle("snd_1", SendStatus::Rejected);
        assert_eq!(l.outstanding(1, "0xaaaa"), 0, "a rejected send hands both back");
    }

    #[test]
    fn a_broadcast_send_keeps_its_nonce_but_a_settled_one_does_not() {
        for (status, left) in [
            (SendStatus::Broadcast { hash: "0xdead".into(), route: "proxied".into() }, 1),
            (SendStatus::Cancelled, 0),
            (SendStatus::Failed { reason: "no signature".into() }, 0),
        ] {
            let l = SendLedger::default();
            committed(&l, "snd_1", 5);
            l.settle("snd_1", status);
            assert_eq!(l.outstanding(1, "0xaaaa"), left, "a broadcast nonce is spent, not free");
        }
    }

    /// THE BUNDLE RULE. A leg that left keeps its number for ever; a leg that never left
    /// gives its number back when the bundle fails — a burnt number nothing was sent at is
    /// a gap, and a gap stops every later send from the account.
    #[test]
    fn a_bundle_that_failed_after_its_first_leg_left_frees_only_the_legs_that_did_not() {
        let l = SendLedger::default();
        committed_n(&l, "snd_1", 5, 3);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_1", 0) else { panic!() };
        assert_eq!(l.outstanding(1, "0xaaaa"), 3, "a claim burns nothing by itself");

        let first = l.leaving(&t, 0).expect("the ticket owns leg 0");
        assert_eq!((first.request_id(), first.leg()), ("snd_1", 0));
        assert!(l.landed(&t, 0, "0xdead0"));
        // Leg 1 answers with an error; legs 2 never goes out.
        let _second = l.leaving(&t, 1).expect("the ticket owns leg 1");
        l.settle_owned(&t, SendStatus::Failed { reason: "leg 2 of 3: connection reset".into() });

        assert_eq!(l.outstanding(1, "0xaaaa"), 2, "5 and 6 may be on chain; 7 never left");
        assert_eq!(open(&l, 1, 5).claim().nonce(), 7, "so 7 is the next number, not 8");
        let j = l.get("snd_1").unwrap();
        assert_eq!(j.hashes(), vec!["0xdead0".to_string()], "the hash that landed is kept");
        assert!(j.legs[0].left && j.legs[1].left && !j.legs[2].left);
    }

    /// Only the ticket holder may mark a leg as leaving, and only a leg the job has.
    #[test]
    fn only_the_broadcast_owner_can_burn_a_leg_and_only_a_real_one() {
        let l = SendLedger::default();
        committed_n(&l, "snd_1", 5, 2);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_1", 0) else { panic!() };
        assert!(l.leaving(&t, 2).is_none(), "there is no leg 2");
        assert_eq!(l.outstanding(1, "0xaaaa"), 2);

        committed_n(&l, "snd_2", 9, 1);
        let BroadcastClaim::Claimed(t2) = l.claim_broadcast("snd_2", 0) else { panic!() };
        // A landed hash needs a leg that left, and a ticket for one job says nothing about
        // another.
        assert!(!l.landed(&t2, 0, "0xnope"), "a hash cannot land on a leg that has not left");
        assert!(!l.landed(&t, 0, "0xnope"), "nor on another job's leg");
        assert!(l.leaving(&t2, 0).is_some());
        assert!(l.landed(&t2, 0, "0xok"));
        assert_eq!(l.get("snd_2").unwrap().hashes(), vec!["0xok".to_string()]);
        drop(t);
    }

    /// A pin shares a number rather than owning it, so abandoning it must not hand back a
    /// number the send it replaces is still using.
    #[test]
    fn an_abandoned_replacement_never_releases_the_nonce_it_shares() {
        let l = SendLedger::default();
        committed(&l, "snd_1", 5);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_1", 0) else { panic!() };
        l.leaving(&t, 0).unwrap();
        assert_eq!(l.outstanding(1, "0xaaaa"), 1);
        {
            let g = l.open(1, "0xaaaa", 5, 1, Some(5)).unwrap();
            assert_eq!(g.claim().nonce(), 5, "the caller's number is used verbatim");
            assert_eq!(names(&g.claim().replaces), Some("snd_1"), "naming what it replaces");
        }
        assert_eq!(l.outstanding(1, "0xaaaa"), 1, "the broadcast send still holds nonce 5");
        assert_eq!(open(&l, 1, 5).claim().nonce(), 6, "and 5 is never handed out a second time");
    }

    /// A pin names ONE transaction to replace. A bundle pinned to it would put its second
    /// leg on a number nobody chose.
    #[test]
    fn a_bundle_cannot_be_pinned() {
        let l = SendLedger::default();
        let e = l.open(1, "0xaaaa", 5, 2, Some(5)).unwrap_err();
        assert!(e.contains("cannot be pinned"), "{e}");
        assert_eq!(l.outstanding(1, "0xaaaa"), 0, "and the refusal reserved nothing");
        assert!(l.open(1, "0xaaaa", 5, 0, None).is_err(), "nor may a send carry no call");
        assert!(l.open(1, "0xaaaa", 5, MAX_LEGS + 1, None).is_err());
        assert!(l.open(1, "0xaaaa", 5, MAX_LEGS, None).is_ok());
    }

    #[test]
    fn only_one_of_many_concurrent_polls_may_broadcast() {
        let l = SendLedger::default();
        committed(&l, "snd_1", 5);
        let start = Barrier::new(8);
        let claimed = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        start.wait();
                        matches!(l.claim_broadcast("snd_1", 0), BroadcastClaim::Claimed(_))
                    })
                })
                .collect();
            handles.into_iter().filter_map(|h| h.join().unwrap().then_some(())).count()
        });
        assert_eq!(claimed, 1, "the same signed transaction must not be sent twice");
    }

    /// The pair that moves money twice if it is not one critical section: a poll claiming the
    /// broadcast while a cancel releases the nonce and calls the send finished.
    #[test]
    fn a_cancel_and_a_broadcast_cannot_both_win() {
        let l = SendLedger::default();
        committed(&l, "snd_1", 5);
        assert!(matches!(l.claim_broadcast("snd_1", 0), BroadcastClaim::Claimed(_)));
        let e = l.claim_cancel("snd_1").unwrap_err();
        assert_eq!(e, "this send is being broadcast and can no longer be cancelled");
        assert_eq!(l.outstanding(1, "0xaaaa"), 1, "the nonce is not handed back mid-flight");

        // And the other order: the cancel gets there first, so the poll finds it settled.
        let l = SendLedger::default();
        committed(&l, "snd_2", 5);
        assert_eq!(l.claim_cancel("snd_2").unwrap().status, SendStatus::Cancelled);
        assert!(matches!(l.claim_broadcast("snd_2", 0), BroadcastClaim::Settled(_)));
        assert_eq!(l.outstanding(1, "0xaaaa"), 0);
        assert_eq!(
            l.claim_cancel("snd_2").unwrap_err(),
            "this send is already cancelled and cannot be cancelled"
        );
    }

    /// `settle` used to write back a clone read before the call, which could undo a status
    /// another dispatch had already applied.
    #[test]
    fn the_first_terminal_state_wins_and_a_stale_caller_is_told_the_truth() {
        let l = SendLedger::default();
        committed(&l, "snd_1", 5);
        assert_eq!(l.settle("snd_1", SendStatus::Rejected).unwrap().job.status, SendStatus::Rejected);
        let late = l
            .settle("snd_1", SendStatus::Failed { reason: "the keystore lost it".into() })
            .unwrap()
            .job;
        assert_eq!(late.status, SendStatus::Rejected, "the reply reports what actually happened");
        assert_eq!(l.outstanding(1, "0xaaaa"), 0, "and the nonce is released exactly once");
        assert!(l.settle("snd_missing", SendStatus::Cancelled).is_none());
    }

    /// A settle that moved nothing is not a state change. `settle_locked` answers with the
    /// live job on three paths and writes on only one of them, and announcing on `Some`
    /// alone made `send_status_changed` mean "someone tried" — which is the one thing an
    /// event may not mean.
    #[test]
    fn a_settle_onto_a_terminal_status_moved_nothing_and_is_not_announced() {
        let l = SendLedger::default();
        committed(&l, "snd_1", 5);
        let moved = l.settle("snd_1", SendStatus::Rejected).unwrap();
        assert!(moved.changed, "awaitingApproval -> rejected is a move, and is announced");

        let again = l.settle("snd_1", SendStatus::Rejected).unwrap();
        assert_eq!(again.job.status, SendStatus::Rejected, "the reply still tells the truth");
        assert!(!again.changed, "but the second settle wrote nothing to announce");
    }

    /// The other unmoved path, and the one that never even reaches the terminal check: past
    /// a claimed broadcast every settle but the ticket holder's is refused outright.
    #[test]
    fn a_settle_the_broadcast_owner_refused_is_not_announced() {
        let l = SendLedger::default();
        committed(&l, "snd_1", 5);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_1", 0) else { panic!() };

        let outsider = l.settle("snd_1", SendStatus::Cancelled).unwrap();
        assert_eq!(outsider.job.status, SendStatus::AwaitingApproval, "it is not theirs");
        assert!(!outsider.changed, "and nothing moved, so nothing is announced");

        // The owner's own door still moves it, so the check cannot pass by never announcing.
        assert!(l.settle_owned(&t, bcast("0xdead")).unwrap().changed);
    }

    /// A concurrent dispatch could otherwise call a broadcast in flight `Failed`, hand its
    /// nonce to the next send, and leave the real hash with nowhere to land.
    #[test]
    fn a_settle_and_a_broadcast_cannot_both_win() {
        let l = SendLedger::default();
        committed(&l, "snd_1", 5);
        let BroadcastClaim::Claimed(ticket) = l.claim_broadcast("snd_1", 0) else {
            panic!("the first claim wins")
        };
        l.leaving(&ticket, 0).unwrap();

        // The exact call a second dispatch makes when its `fetch_result` came back empty
        // because the first had already acked it.
        let reason = "the approval carried no signature".to_string();
        let refused = l.settle("snd_1", SendStatus::Failed { reason }).unwrap().job;
        assert_eq!(refused.status, SendStatus::AwaitingApproval, "an outsider may not settle it");
        assert_eq!(refused.reported_status(0), "broadcasting", "and is told what it really is");
        assert_eq!(l.outstanding(1, "0xaaaa"), 1, "the nonce is not handed back mid-flight");

        // A cancel is refused for the same reason, and the owner's hash still lands.
        assert_eq!(
            l.claim_cancel("snd_1").unwrap_err(),
            "this send is being broadcast and can no longer be cancelled"
        );
        let done = broadcast(&l, &ticket, "0xdead");
        assert_eq!(done.status, bcast("0xdead"), "the hash is not dropped");
        assert_eq!(l.outstanding(1, "0xaaaa"), 1, "a broadcast nonce is spent, not free");
    }

    /// The same interleaving on real threads. A owns the broadcast and is still inside the
    /// UNBOUNDED `send_raw_transaction`; B is a concurrent dispatch — `concurrency: "multi"`
    /// really does run these at once — that finds no signature, or a keystore that restarted
    /// mid-broadcast and answers `ok:false`. Both land on the same `settle`, and both must
    /// bounce off the claim.
    #[test]
    fn a_concurrent_dispatch_cannot_fail_a_broadcast_that_is_in_flight() {
        let l = &SendLedger::default();
        committed(l, "snd_1", 5);
        let (claimed_tx, claimed_rx) = mpsc::channel();
        let (b_done_tx, b_done_rx) = mpsc::channel();

        let (settled, seen, mid) = std::thread::scope(|s| {
            let a = s.spawn(move || {
                let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_1", 0) else {
                    panic!("A owns the broadcast")
                };
                l.leaving(&t, 0).unwrap();
                claimed_tx.send(()).unwrap();
                // The signed transaction is away. B runs entirely inside this window.
                b_done_rx.recv().unwrap();
                broadcast(l, &t, "0xdead")
            });
            let b = s.spawn(move || {
                claimed_rx.recv().unwrap();
                let reason = "the approval carried no signature".to_string();
                let seen = l.settle("snd_1", SendStatus::Failed { reason }).unwrap().job;
                let mid = l.outstanding(1, "0xaaaa");
                b_done_tx.send(()).unwrap();
                (seen, mid)
            });
            let (seen, mid) = b.join().unwrap();
            (a.join().unwrap(), seen, mid)
        });

        assert_eq!(mid, 1, "the nonce was handed back while the broadcast was in flight");
        assert_eq!(seen.reported_status(0), "broadcasting", "B is told the truth, not `failed`");
        assert_eq!(settled.status, bcast("0xdead"), "and A's hash survived B");
        assert_eq!(l.get("snd_1").unwrap().status, bcast("0xdead"), "the ledger agrees");
        assert_eq!(l.outstanding(1, "0xaaaa"), 1);
    }

    /// Eight concurrent dispatches against one claimed broadcast: none may move it.
    #[test]
    fn no_number_of_concurrent_dispatches_can_settle_a_claimed_broadcast() {
        let l = SendLedger::default();
        committed(&l, "snd_1", 5);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_1", 0) else { panic!() };
        l.leaving(&t, 0).unwrap();
        let start = Barrier::new(8);
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    start.wait();
                    l.settle("snd_1", SendStatus::Failed { reason: "lost it".into() });
                    l.settle("snd_1", SendStatus::Rejected);
                    let _ = l.claim_cancel("snd_1");
                });
            }
        });
        assert_eq!(l.get("snd_1").unwrap().status, SendStatus::AwaitingApproval);
        assert_eq!(l.outstanding(1, "0xaaaa"), 1, "and its nonce was never handed back");
        assert_eq!(broadcast(&l, &t, "0xdead").status, bcast("0xdead"));
    }

    /// A hash is the user's only handle on money in flight, so it wins even against a status
    /// that got there first — the owner's own, when the node answered twice.
    #[test]
    fn a_real_hash_corrects_a_terminal_status_and_keeps_the_nonce() {
        let l = SendLedger::default();
        committed(&l, "snd_1", 5);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_1", 0) else { panic!() };
        l.leaving(&t, 0).unwrap();
        let reason = "the node accepted the transaction but returned no hash".to_string();
        l.settle_owned(&t, SendStatus::Failed { reason }).unwrap();
        assert_eq!(l.outstanding(1, "0xaaaa"), 1, "a nonce that left is never handed back");

        assert_eq!(broadcast(&l, &t, "0xdead").status, bcast("0xdead"), "the hash corrects it");
        assert_eq!(l.outstanding(1, "0xaaaa"), 1, "and the corrected send still holds its nonce");
        // Only a hash may do that. Nothing walks a terminal status back the other way.
        assert_eq!(l.settle_owned(&t, SendStatus::Cancelled).unwrap().job.status, bcast("0xdead"));
    }

    /// A claim taken and then dropped before any leg left — the record would not write —
    /// hands every number back: nothing is on the wire, and a burnt number nothing was sent
    /// at would stop the account.
    #[test]
    fn a_failure_between_the_claim_and_the_first_leg_leaving_frees_the_numbers() {
        let l = SendLedger::default();
        committed_n(&l, "snd_1", 5, 2);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_1", 0) else { panic!() };
        let reason = "this transaction could not be recorded, so it was not sent".to_string();
        l.settle_owned(&t, SendStatus::Failed { reason }).unwrap();
        assert_eq!(l.outstanding(1, "0xaaaa"), 0, "nothing left, so nothing stays burnt");
        assert_eq!(open(&l, 1, 5).claim().nonce(), 5);
    }

    /// The latch. `send_raw_transaction` is deliberately unbounded, so a broadcast can simply
    /// never return; the fix is not a deadline on the call — that would only stop us learning
    /// the hash — but a deadline on the CLAIM, after which the job says so and stops counting
    /// as live. It never becomes terminal and never releases a leg that left: the
    /// transaction may be on chain, and only the broadcast itself can say.
    #[test]
    fn a_broadcast_that_never_returns_is_disclosed_and_stops_counting_as_live() {
        let l = SendLedger::default();
        committed(&l, "snd_1", 5);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_1", 100) else { panic!() };
        l.leaving(&t, 0).unwrap();
        let live = l.get("snd_1").unwrap();

        assert_eq!(live.reported_status(100), "broadcasting", "never `awaitingApproval`");
        assert_eq!(l.live(100).len(), 1, "a send in flight is live");

        let late = 100 + STUCK_AFTER_SECS;
        assert_eq!(live.reported_status(late - 1), "broadcasting", "the deadline is not early");
        assert_eq!(live.reported_status(late), "stuck");
        assert!(l.live(late).is_empty(), "a stuck send stops holding a consumer's ground");
        assert_eq!(l.outstanding(1, "0xaaaa"), 1, "but its nonce is still spent");
        assert!(l.claim_cancel("snd_1").is_err(), "and it is still nobody else's to settle");
        assert_eq!(l.settle("snd_1", SendStatus::Rejected).unwrap().job.reported_status(late), "stuck");

        // Recovery: the broadcast finally answers, hours late, and its hash still lands.
        assert_eq!(broadcast(&l, &t, "0xdead").reported_status(late), "broadcast");
    }

    /// A send still waiting on a human is NOT stuck, however long it waits: nothing has left,
    /// and it stays live for as long as the human takes.
    #[test]
    fn an_unclaimed_send_never_goes_stuck_however_long_the_human_takes() {
        let l = SendLedger::default();
        committed(&l, "snd_1", 5);
        let late = 10 * STUCK_AFTER_SECS;
        assert_eq!(l.get("snd_1").unwrap().reported_status(late), "awaitingApproval");
        assert_eq!(l.live(late).len(), 1, "an unapproved send is still live");
        assert_eq!(l.claim_cancel("snd_1").unwrap().status, SendStatus::Cancelled);
        assert!(l.live(late).is_empty());
    }

    /// A pinned nonce short-circuited past the reserver once, so a concurrent unpinned send
    /// could reserve the very same number.
    #[test]
    fn a_pinned_nonce_is_reserved_against_a_concurrent_unpinned_send() {
        let l = SendLedger::default();
        let pin = l.open(1, "0xaaaa", 5, 1, Some(5)).unwrap();
        assert_eq!(pin.claim().nonce(), 5);
        assert_eq!(l.outstanding(1, "0xaaaa"), 1, "a pin holds its number like any other");

        let other = open(&l, 1, 5);
        assert_eq!(other.claim().nonce(), 6, "the next send must not take it too");
        assert_eq!(l.outstanding(1, "0xaaaa"), 2);
        drop(pin);
        assert_eq!(l.outstanding(1, "0xaaaa"), 1, "a pin it owned it gives back");
        drop(other);
        assert_eq!(l.outstanding(1, "0xaaaa"), 0);
    }

    /// The same, on real threads: one pin, then seven unpinned sends racing for the rest.
    #[test]
    fn a_pin_and_a_burst_of_unpinned_sends_never_share_a_nonce() {
        let l = SendLedger::default();
        let g = l.open(1, "0xaaaa", 5, 1, Some(5)).unwrap();
        assert_eq!(g.claim().nonce(), 5);
        g.commit(SendJob { request_id: "snd_pin".into(), ..job() });

        let start = Barrier::new(7);
        let mut nonces: Vec<u64> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..7)
                .map(|_| {
                    s.spawn(|| {
                        start.wait();
                        let g = open(&l, 1, 5);
                        let n = g.claim().nonce();
                        g.commit(SendJob { request_id: format!("snd_{n}"), ..job() });
                        n
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        nonces.push(5);
        nonces.sort_unstable();
        nonces.dedup();
        assert_eq!(nonces, (5..13).collect::<Vec<_>>(), "an unpinned send took the pinned nonce");
    }

    #[test]
    fn holding_an_exact_nonce_says_whether_this_caller_owns_it() {
        let mut r = NonceReserver::default();
        assert!(r.hold(1, "0xa", 9), "a free number is taken");
        assert!(!r.hold(1, "0xA", 9), "one a live send holds is shared, not owned");
        assert_eq!(r.reserve(1, "0xa", 9), 10, "and an unpinned send steps over it");
    }

    #[test]
    fn broadcast_can_be_claimed_exactly_once() {
        let mut j = job();
        assert!(j.claim_broadcast(1, 0), "the first claim wins");
        assert!(!j.claim_broadcast(2, 0), "a concurrent poll must not broadcast again");
        assert_eq!(j.broadcast.unwrap().ticket, 1, "and the loser does not steal the ticket");
    }

    #[test]
    fn a_settled_job_can_never_be_broadcast() {
        let mut j = job();
        j.status = SendStatus::Rejected;
        assert!(!j.claim_broadcast(1, 0));

        let mut j = job();
        j.status = SendStatus::Broadcast { hash: "0xdead".into(), route: "proxied".into() };
        assert!(!j.claim_broadcast(1, 0));
    }

    #[test]
    fn consecutive_sends_get_consecutive_nonces_from_the_same_chain_view() {
        let mut r = NonceReserver::default();
        // The chain still reports 5 for the second send: `latest` does not count the first,
        // which is exactly the case this exists for.
        assert_eq!(r.reserve(1, "0xAbC", 5), 5);
        assert_eq!(r.reserve(1, "0xabc", 5), 6);
        assert_eq!(r.reserve(1, "0xABC", 5), 7);
        assert_eq!(r.outstanding(1, "abc"), 3, "the address key is case- and prefix-insensitive");
    }

    #[test]
    fn a_released_nonce_is_handed_out_again() {
        let mut r = NonceReserver::default();
        assert_eq!(r.reserve(1, "0xa", 5), 5);
        assert_eq!(r.reserve(1, "0xa", 5), 6);
        r.release(1, "0xa", 5);
        assert_eq!(r.reserve(1, "0xa", 5), 5, "the gap is reused, not skipped");
    }

    /// `latest` comes from a load-balanced provider, so it moves backwards between calls
    /// and across a reorg: it may say where to start looking and never what to hand back.
    /// Dropping everything below it is what freed an on-chain nonce.
    #[test]
    fn a_chain_reading_says_where_to_start_and_never_what_to_free() {
        let mut r = NonceReserver::default();
        r.reserve(1, "0xa", 5);
        r.reserve(1, "0xa", 5);
        // Both mined; the chain now reports 7. The old shape dropped 5 and 6 here.
        assert_eq!(r.reserve(1, "0xa", 7), 7);
        assert_eq!(r.outstanding(1, "0xa"), 3, "a reading frees nothing");
        assert_eq!(r.reserve(1, "0xa", 5), 8, "and a node a block behind is stepped over");
    }

    #[test]
    fn reservations_do_not_leak_across_chains_or_accounts() {
        let mut r = NonceReserver::default();
        assert_eq!(r.reserve(1, "0xa", 5), 5);
        assert_eq!(r.reserve(11_155_111, "0xa", 5), 5, "a different chain is a different account");
        assert_eq!(r.reserve(1, "0xb", 5), 5, "a different account is independent");
        assert_eq!(r.reserve(1, "0XA", 5), 6, "an upper-case prefix is the same account");
        assert!(same_account(" 0XABC ", "0xabc"));
    }

    #[test]
    fn max_cost_is_the_value_plus_every_legs_fee_ceiling() {
        let c = max_cost_wei(U256::from(1000), &[21_000, 50_000], U256::from(2)).unwrap();
        assert_eq!(c, U256::from(1000 + 142_000));
        assert!(max_cost_wei(U256::MAX, &[21_000], U256::MAX).is_none(), "overflow must not wrap");
        assert!(max_cost_wei(U256::ZERO, &[u64::MAX, 1], U256::from(1)).is_none());
    }

    #[test]
    fn the_insufficient_funds_message_names_both_numbers() {
        let e = affordable(U256::from(1), U256::from(10), &[21_000], U256::from(1), "ETH")
            .unwrap_err();
        assert!(e.contains("insufficient funds"), "{e}");
        assert!(e.contains("0.00000000000002101") && e.contains("0.000000000000000001"), "{e}");
        assert!(e.contains("ETH"), "{e}");
        assert!(affordable(U256::from(21_010), U256::from(10), &[21_000], U256::from(1), "ETH").is_ok());
    }

    #[test]
    fn an_error_about_money_is_never_denominated_in_wei() {
        // "need 9351928362001 wei" is a number the user cannot act on.
        let e = affordable(U256::from(1), U256::from(1), &[21_000], U256::from(445_329_922u64), "ETH")
            .unwrap_err();
        assert!(!e.contains(" wei"), "{e}");
        assert!(e.contains("0.000009351928362001"), "{e}");
    }

    #[test]
    fn the_claim_line_opens_with_the_purpose_and_names_who_asked() {
        assert_eq!(
            claim_line("Send 1 ETH from A to B", "eth_wallet_backend"),
            "Send 1 ETH from A to B [asked by eth_wallet_backend]"
        );
        assert_eq!(claim_line("  ", "uniswap_ui"), "A transaction [asked by uniswap_ui]");
        assert_eq!(claim_line("x", ""), "x [asked by an unnamed caller]");
    }

    // ---- The invariant itself, asserted over histories rather than over interleavings ----
    //
    // Every test above names one race and closes one door. Rounds of that each missed the
    // next door, so these assert the property instead:
    //
    //   INV-1  every nonce a claim, a live job or a leg that may have reached the chain holds
    //          is still reserved — "a nonce that may be on chain is never handed to another
    //          send", in a form a machine can check;
    //   INV-2  at most one holder of a number is not an explicit replacement;
    //   money  no two sends that LEFT ever carried the same nonce, unless the later one named
    //          the earlier as the transaction it replaces. Logged outside the ledger, so a
    //          change of the ledger's representation cannot make it vacuous;
    //   live   a history in which nothing ever left ends with nothing reserved. Without
    //          this, "never release anything" satisfies all three above.

    const ACC: &str = "0xaaaa";

    /// A terminal status a driven step can apply.
    #[derive(Clone, Copy, Debug)]
    enum Term {
        Rejected,
        Failed,
        Broadcast,
    }

    impl Term {
        fn status(self) -> SendStatus {
            match self {
                Term::Rejected => SendStatus::Rejected,
                Term::Failed => SendStatus::Failed { reason: "no signature".into() },
                Term::Broadcast => bcast("0xdead"),
            }
        }
    }

    /// One step. Every op is total: one that does not apply to the ledger as it stands is a
    /// no-op, so no sequence has to be filtered and the enumeration below is exhaustive.
    #[derive(Clone, Copy, Debug)]
    enum Op {
        /// The chain reading, one leg. Drawn from a deliberately non-monotonic set: two nodes
        /// at different heights and a reorg all show up here as the reading moving backwards.
        Open(u64),
        /// A two-leg bundle.
        OpenTwo(u64),
        Pin(u64),
        Abandon,
        Commit,
        Claim(usize),
        /// The next leg of job i that has not left, leaves.
        Leave(usize),
        /// Claim job i and let its first leg leave at once — the shape a poll takes when the
        /// record writes and the RPC is issued in one go.
        ClaimLeave(usize),
        Settle(usize, Term),
        SettleOwned(usize, Term),
    }

    const ALPHABET: &[Op] = &[
        Op::Open(4),
        Op::Open(5),
        Op::OpenTwo(6),
        Op::Pin(5),
        Op::Abandon,
        Op::Commit,
        Op::Claim(0),
        Op::Claim(1),
        Op::Leave(0),
        Op::Leave(1),
        Op::Settle(0, Term::Rejected),
        Op::Settle(1, Term::Failed),
        Op::SettleOwned(0, Term::Broadcast),
        Op::SettleOwned(0, Term::Failed),
    ];

    /// Drives one ledger, and keeps the one record the ledger's own shape cannot make
    /// vacuous: which sends LEFT on each number, in order.
    struct Drive<'a> {
        l: &'a SendLedger,
        guards: Vec<ClaimGuard<'a>>,
        jobs: Vec<String>,
        tickets: HashMap<String, BroadcastTicket>,
        left: HashMap<u64, Vec<String>>,
        next: usize,
    }

    impl<'a> Drive<'a> {
        fn new(l: &'a SendLedger) -> Self {
            Drive {
                l,
                guards: Vec::new(),
                jobs: Vec::new(),
                tickets: HashMap::new(),
                left: HashMap::new(),
                next: 0,
            }
        }

        fn pick(&self, i: usize) -> Option<String> {
            (!self.jobs.is_empty()).then(|| self.jobs[i % self.jobs.len()].clone())
        }

        fn leave(&mut self, i: usize) {
            let Some(id) = self.pick(i) else { return };
            let Some(t) = self.tickets.get(&id) else { return };
            let Some(j) = self.l.get(&id) else { return };
            let Some(k) = j.legs.iter().position(|l| !l.left) else { return };
            if self.l.leaving(t, k).is_some() {
                self.note_left(&id, j.legs[k].nonce);
            }
        }

        fn note_left(&mut self, id: &str, nonce: u64) {
            let who = self.left.entry(nonce).or_default();
            if !who.iter().any(|w| w == id) {
                who.push(id.to_string());
            }
        }

        fn step(&mut self, op: Op) {
            match op {
                Op::Open(cn) => {
                    if let Ok(g) = self.l.open(1, ACC, cn, 1, None) {
                        self.guards.push(g);
                    }
                }
                Op::OpenTwo(cn) => {
                    if let Ok(g) = self.l.open(1, ACC, cn, 2, None) {
                        self.guards.push(g);
                    }
                }
                // A refused pin is a legal outcome, and the one the replacement rule turns on.
                Op::Pin(n) => {
                    if let Ok(g) = self.l.open(1, ACC, 5, 1, Some(n)) {
                        self.guards.push(g);
                    }
                }
                Op::Abandon => {
                    if !self.guards.is_empty() {
                        drop(self.guards.remove(0));
                    }
                }
                Op::Commit => {
                    if self.guards.is_empty() {
                        return;
                    }
                    let g = self.guards.remove(0);
                    let count = g.claim().nonces.len();
                    self.next += 1;
                    let id = format!("snd_{}", self.next);
                    g.commit(SendJob { request_id: id.clone(), ..job_with(count) });
                    self.jobs.push(id);
                }
                Op::Claim(i) => {
                    let Some(id) = self.pick(i) else { return };
                    if let BroadcastClaim::Claimed(t) = self.l.claim_broadcast(&id, 0) {
                        self.tickets.insert(id, t);
                    }
                }
                Op::Leave(i) => self.leave(i),
                Op::ClaimLeave(i) => {
                    self.step(Op::Claim(i));
                    self.leave(i);
                }
                Op::Settle(i, term) => {
                    if let Some(id) = self.pick(i) {
                        self.l.settle(&id, term.status());
                    }
                }
                Op::SettleOwned(i, term) => {
                    let Some(id) = self.pick(i) else { return };
                    let Some(t) = self.tickets.get(&id) else { return };
                    let before = self.l.get(&id);
                    if let Some(s) = self.l.settle_owned(t, term.status()) {
                        // A `Broadcast` written by the owner asserts every leg left, so the
                        // side log records them as such.
                        if s.changed && matches!(s.job.status, SendStatus::Broadcast { .. }) {
                            if let Some(b) = before {
                                for n in b.nonces() {
                                    self.note_left(&id, n);
                                }
                            }
                        }
                    }
                }
            }
        }

        /// INV-1 and INV-2 out of the ledger, and the money property out of the side log.
        fn check(&self, trace: &[Op]) {
            let faults = self.l.faults();
            assert!(faults.is_empty(), "{trace:?}: {faults:?}");
            for (nonce, who) in &self.left {
                for (i, later) in who.iter().enumerate().skip(1) {
                    let says = self.l.get(later).and_then(|j| j.replaces);
                    assert!(
                        names(&says).is_some_and(|x| who[..i].iter().any(|w| w == x)),
                        "{trace:?}: {later} left on nonce {nonce} after {:?} without naming \
                         the transaction it replaces (it says {says:?})",
                        &who[..i]
                    );
                }
            }
        }

        /// The anti-degenerate check. Containment alone is satisfied by never releasing
        /// anything, so a history in which nothing ever left must end holding nothing.
        fn liveness(&mut self, trace: &[Op]) {
            self.guards.clear();
            let settled =
                self.jobs.iter().all(|id| self.l.get(id).is_some_and(|j| j.status.is_terminal()));
            if self.left.is_empty() && settled {
                assert_eq!(
                    self.l.outstanding(1, ACC),
                    0,
                    "{trace:?}: a nonce nothing ever broadcast was never handed back"
                );
            }
        }
    }

    /// Tier 0. An invariant checker nobody has seen fail is not known to work.
    #[test]
    fn the_checker_sees_a_nonce_that_is_held_but_not_reserved() {
        let mut l = Ledger::default();
        // A live job whose number the reserver has let go.
        l.jobs.insert("snd_1".into(), SendJob { request_id: "snd_1".into(), legs: vec![leg(5)], ..job() });
        let faults = l.violations();
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(faults[0].contains("holds nonce 5") && faults[0].contains("unreserved"),
                "{faults:?}");

        l.nonces.hold(1, ACC, 5);
        assert!(l.violations().is_empty(), "and it is quiet once the number is reserved");
    }

    /// Tier 0, INV-2. Sharing is legal only when the later holder names the earlier.
    #[test]
    fn the_checker_sees_two_unnamed_holders_of_one_number() {
        let mut l = Ledger::default();
        for id in ["snd_a", "snd_b"] {
            l.jobs.insert(id.into(), SendJob { request_id: id.into(), legs: vec![leg(5)], ..job() });
        }
        l.nonces.hold(1, ACC, 5);
        let faults = l.violations();
        assert_eq!(faults.len(), 2, "one per unnamed holder: {faults:?}");
        assert!(faults.iter().all(|f| f.contains("shares nonce 5")), "{faults:?}");

        l.jobs.get_mut("snd_b").unwrap().replaces = Some(Replaces::Send("snd_a".into()));
        assert!(l.violations().is_empty(), "a named replacement is the legal way to share");
    }

    /// The checker over a bundle: every leg of a live job is held, and one unreserved leg
    /// is a fault on its own.
    #[test]
    fn the_checker_sees_every_leg_of_a_bundle() {
        let mut l = Ledger::default();
        l.jobs.insert("snd_1".into(), SendJob { request_id: "snd_1".into(), ..job_with(3) });
        l.nonces.hold(1, ACC, 0);
        l.nonces.hold(1, ACC, 2);
        let faults = l.violations();
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(faults[0].contains("holds nonce 1"), "{faults:?}");
        l.nonces.hold(1, ACC, 1);
        assert!(l.violations().is_empty());
    }

    /// The audit's INSTALLATION, not the checker. Corrupt the reserver behind the ledger's
    /// back, then simply USE the ledger: the release is what has to notice, and what has to
    /// put the number back.
    #[test]
    fn using_the_ledger_at_all_audits_it_and_repairs_what_is_missing() {
        let l = SendLedger::default();
        committed(&l, "snd_1", 5);
        l.unreserve_behind_the_ledgers_back(1, ACC, 5);

        // A read door that holds nothing and mutates nothing. In a debug build the audit
        // says so by panicking, which is the only way a test can see that it ran at all.
        let used = std::panic::AssertUnwindSafe(|| drop(l.get("snd_1")));
        assert!(std::panic::catch_unwind(used).is_err(), "releasing the ledger did not audit");
        assert_eq!(l.outstanding(1, ACC), 1, "the repair is the conservative direction");
    }

    /// Tier 0. In release a violation is repaired and disclosed; a test build stops dead, so
    /// a future edit that breaks the invariant cannot ship green.
    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn a_violated_invariant_stops_a_test_build() {
        let mut l = Ledger::default();
        l.jobs.insert("snd_1".into(), SendJob { request_id: "snd_1".into(), legs: vec![leg(5)], ..job() });
        l.audit();
    }

    /// Every history of length <= `depth` over `alphabet`, asserting the invariant after
    /// every step. Answers how many it ran and the most sends that ever left on one number —
    /// an enumeration that never reaches the interesting state proves nothing, so both are
    /// asserted by the callers.
    fn enumerate(alphabet: &[Op], depth: u32) -> (u64, usize) {
        let n = alphabet.len() as u64;
        let (mut total, mut shared) = (0u64, 0usize);
        for len in 1..=depth {
            for code in 0..n.pow(len) {
                let mut c = code;
                let seq: Vec<Op> = (0..len)
                    .map(|_| {
                        let op = alphabet[(c % n) as usize];
                        c /= n;
                        op
                    })
                    .collect();
                let l = SendLedger::default();
                let mut d = Drive::new(&l);
                for k in 0..seq.len() {
                    d.step(seq[k]);
                    d.check(&seq[..=k]);
                }
                d.liveness(&seq);
                shared = shared.max(d.left.values().map(Vec::len).max().unwrap_or(0));
                total += 1;
            }
        }
        (total, shared)
    }

    /// Tier 1. Over half a million histories over the whole alphabet. This is the test that
    /// is supposed to close the NEXT door rather than the last one.
    #[test]
    fn the_invariant_holds_over_every_short_history() {
        let (total, _) = enumerate(ALPHABET, 5);
        assert_eq!(total, 579_194, "the enumeration collapsed");
    }

    /// Tier 1, deeper but narrower. Two sends leaving on the SAME number — the replacement
    /// flow, and the only shape in which the money property has anything to say — takes
    /// several steps to reach, which the pass above cannot afford over fourteen ops.
    #[test]
    fn the_invariant_holds_over_every_replacement_history() {
        const REPLACEMENT: &[Op] = &[
            Op::Open(5),
            Op::Pin(5),
            Op::Commit,
            Op::ClaimLeave(0),
            Op::ClaimLeave(1),
            Op::SettleOwned(0, Term::Broadcast),
            Op::Settle(1, Term::Rejected),
        ];
        let (total, shared) = enumerate(REPLACEMENT, 6);
        assert_eq!(total, 137_256, "the enumeration collapsed");
        assert!(shared >= 2, "no history ever got two sends onto one nonce: nothing was tested");
    }

    /// Tier 1, the bundle shape: legs leaving one at a time, some never leaving, under every
    /// order of settles.
    #[test]
    fn the_invariant_holds_over_every_bundle_history() {
        const BUNDLE: &[Op] = &[
            Op::OpenTwo(5),
            Op::Open(5),
            Op::Commit,
            Op::Claim(0),
            Op::Leave(0),
            Op::SettleOwned(0, Term::Failed),
            Op::SettleOwned(0, Term::Broadcast),
            Op::Abandon,
        ];
        let (total, _) = enumerate(BUNDLE, 6);
        assert_eq!(total, 299_592, "the enumeration collapsed");
    }

    /// Tier 2. The same property under any schedule rather than one named interleaving.
    #[test]
    fn the_invariant_holds_under_concurrent_dispatch() {
        let l = &SendLedger::default();
        let left: &Mutex<HashMap<u64, Vec<String>>> = &Mutex::new(HashMap::new());
        let start = &Barrier::new(8);
        std::thread::scope(|s| {
            for t in 0..8u64 {
                s.spawn(move || {
                    let mut rng = t.wrapping_mul(7919) + 1;
                    let mut roll = move |m: u64| {
                        rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                        (rng >> 33) % m
                    };
                    start.wait();
                    for k in 0..24u64 {
                        let id = format!("snd_{t}_{k}");
                        let pinned = (roll(4) == 0).then_some(5);
                        let count = if pinned.is_some() { 1 } else { 1 + roll(2) as usize };
                        let Ok(g) = l.open(1, ACC, 4 + roll(4), count, pinned) else { continue };
                        if roll(5) == 0 {
                            continue; // abandoned on the way out
                        }
                        g.commit(SendJob { request_id: id.clone(), ..job_with(count) });
                        if roll(3) == 0 {
                            l.settle(&id, SendStatus::Rejected);
                        } else if let BroadcastClaim::Claimed(tk) = l.claim_broadcast(&id, 0) {
                            let j = l.get(&id).expect("a job that was just claimed");
                            // Some legs leave, some do not.
                            let leave = 1 + roll(count as u64) as usize;
                            for i in 0..leave {
                                if l.leaving(&tk, i).is_some() {
                                    left.lock().unwrap().entry(j.legs[i].nonce).or_default().push(id.clone());
                                }
                            }
                            // Half the broadcasts answer with a hash; the rest come back an
                            // error, which is UNKNOWN, not proof of non-delivery.
                            let out = match roll(2) {
                                0 if leave == count => bcast("0xdead"),
                                _ => SendStatus::Failed { reason: "no answer".into() },
                            };
                            l.settle_owned(&tk, out);
                        }
                        assert!(l.faults().is_empty(), "{:?}", l.faults());
                    }
                });
            }
        });
        assert!(l.faults().is_empty(), "{:?}", l.faults());
        // The ids are logged outside the ledger's lock, so their ORDER is not the ledger's.
        // What IS the ledger's own fact is the set — of the sends that left on one number,
        // exactly one may be unnamed, and every other must name one of them.
        let log = left.lock().unwrap();
        assert!(!log.is_empty(), "no send ever left: nothing was tested");
        for (nonce, who) in log.iter() {
            let says: Vec<Option<String>> = who
                .iter()
                .map(|id| l.get(id).and_then(|j| names(&j.replaces).map(str::to_string)))
                .collect();
            let unnamed = says.iter().filter(|s| s.is_none()).count();
            assert_eq!(unnamed, 1, "nonce {nonce}: {who:?} left on it, naming {says:?}");
            for named in says.iter().flatten() {
                assert!(who.contains(named), "nonce {nonce}: {named} is not one of {who:?}");
            }
        }
    }

    /// Tier 3. The chain reading as a property rather than as one scenario: whatever order
    /// a load-balanced provider answers in, no number a send has left on comes back. This
    /// covers a reorg for free — a legitimately backwards reading is just another draw.
    #[test]
    fn no_reading_however_shuffled_hands_back_a_nonce_that_left() {
        let l = SendLedger::default();
        let mut spent: BTreeSet<u64> = BTreeSet::new();
        for (i, reading) in [5u64, 7, 4, 6, 5, 8, 4, 7, 6, 5].into_iter().enumerate() {
            let g = l.open(1, ACC, reading, 1, None).unwrap();
            let n = g.claim().nonce();
            assert!(!spent.contains(&n), "reading {reading} handed back on-chain nonce {n}");
            let id = format!("snd_{i}");
            g.commit(SendJob { request_id: id.clone(), ..job() });
            if i % 2 == 0 {
                let BroadcastClaim::Claimed(t) = l.claim_broadcast(&id, 0) else { panic!() };
                l.leaving(&t, 0).unwrap();
                spent.insert(n);
                // Every other one comes back an error: the transaction may well be on chain.
                let out = match i % 4 {
                    0 => bcast("0xdead"),
                    _ => SendStatus::Failed { reason: "the node did not answer".into() },
                };
                l.settle_owned(&t, out);
            } else {
                l.settle(&id, SendStatus::Rejected);
            }
            assert!(l.faults().is_empty(), "{:?}", l.faults());
        }
    }

    /// A number that reached the chain survives another job's rejection — both variants: the
    /// transaction settled on chain, and the transaction still in flight.
    #[test]
    fn a_nonce_that_reached_the_chain_survives_another_jobs_rejection() {
        let l = SendLedger::default();
        committed(&l, "snd_a", 5);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_a", 0) else { panic!() };
        l.leaving(&t, 0).unwrap();
        broadcast(&l, &t, "0xdead");

        let g = l.open(1, ACC, 5, 1, Some(5)).unwrap();
        assert_eq!(names(&g.claim().replaces), Some("snd_a"), "a pin names what it replaces");
        g.commit(SendJob { request_id: "snd_b".into(), ..job() });
        l.settle("snd_b", SendStatus::Rejected);
        assert_eq!(l.outstanding(1, ACC), 1, "B's rejection freed a nonce that is on chain");
        assert_eq!(open(&l, 1, 5).claim().nonce(), 6, "so C must never be handed 5");

        // A is still inside the broadcast — left, unsettled — and B fails.
        let l = SendLedger::default();
        committed(&l, "snd_a", 5);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_a", 0) else { panic!() };
        l.leaving(&t, 0).unwrap();
        let g = l.open(1, ACC, 5, 1, Some(5)).unwrap();
        g.commit(SendJob { request_id: "snd_b".into(), ..job() });
        l.settle("snd_b", SendStatus::Failed { reason: "no signature".into() });
        assert_eq!(l.outstanding(1, ACC), 1, "B's failure freed a nonce still in flight");
        assert_eq!(open(&l, 1, 5).claim().nonce(), 6);
    }

    /// A node that had already counted the transaction used to free the very nonce it was
    /// mined at, and a node a block behind then handed that number to the next send.
    #[test]
    fn a_nonce_that_reached_the_chain_survives_a_stale_chain_reading() {
        let l = SendLedger::default();
        committed(&l, "snd_a", 5);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_a", 0) else { panic!() };
        l.leaving(&t, 0).unwrap();
        broadcast(&l, &t, "0xdead");

        // A node that has already counted 0xdead answers 6.
        let g = open(&l, 1, 6);
        assert_eq!(g.claim().nonce(), 6);
        g.commit(SendJob { request_id: "snd_b".into(), ..job() });
        // A node one block behind answers 5.
        assert_eq!(open(&l, 1, 5).claim().nonce(), 7, "a lagging node freed an on-chain nonce");
        assert_eq!(l.outstanding(1, ACC), 2, "5 is on chain and 6 is B's; that third is gone");
    }

    // ---- The invariant's INSTALLATION, rather than the checker ----
    //
    // The audit runs in `Audited::drop`, the only way to reach a `Ledger`, so a door cannot
    // omit it. Each test below takes a reservation away behind the ledger's back and drives
    // ONE door, which must see it on the way out — delete the audit and every one goes quiet.

    /// One live send holding nonce 5, correctly reserved.
    fn witnessed() -> SendLedger {
        let l = SendLedger::default();
        committed(&l, "snd_witness", 5);
        l
    }

    /// Take 5 away from the reserver without auditing — INV-1 is now violated, and the next
    /// door to release its guard is the one under test.
    fn derail(l: &SendLedger) {
        l.unreserve_behind_the_ledgers_back(1, ACC, 5);
    }

    const VIOLATED: &str = "send ledger invariant violated";

    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn the_open_door_audits() {
        let l = witnessed();
        derail(&l);
        let _ = l.open(1, ACC, 9, 1, None);
    }

    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn the_commit_door_audits() {
        let l = witnessed();
        let g = open(&l, 1, 9);
        derail(&l);
        g.commit(SendJob { request_id: "snd_door".into(), ..job() });
    }

    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn the_abandon_door_audits() {
        let l = witnessed();
        let g = open(&l, 1, 9);
        derail(&l);
        drop(g);
    }

    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn the_claim_broadcast_door_audits() {
        let l = witnessed();
        committed(&l, "snd_door", 9);
        derail(&l);
        l.claim_broadcast("snd_door", 0);
    }

    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn the_leaving_door_audits() {
        let l = witnessed();
        committed(&l, "snd_door", 9);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_door", 0) else {
            unreachable!("the first claim wins")
        };
        derail(&l);
        let _ = l.leaving(&t, 0);
    }

    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn the_landed_door_audits() {
        let l = witnessed();
        committed(&l, "snd_door", 9);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_door", 0) else {
            unreachable!("the first claim wins")
        };
        l.leaving(&t, 0);
        derail(&l);
        let _ = l.landed(&t, 0, "0xdead");
    }

    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn the_settle_door_audits() {
        let l = witnessed();
        committed(&l, "snd_door", 9);
        derail(&l);
        l.settle("snd_door", SendStatus::Rejected);
    }

    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn the_settle_owned_door_audits() {
        let l = witnessed();
        committed(&l, "snd_door", 9);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_door", 0) else {
            unreachable!("the first claim wins")
        };
        derail(&l);
        l.settle_owned(&t, bcast("0xdead"));
    }

    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn the_cancel_door_audits() {
        let l = witnessed();
        committed(&l, "snd_door", 9);
        derail(&l);
        let _ = l.claim_cancel("snd_door");
    }

    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn the_live_door_audits() {
        let l = witnessed();
        derail(&l);
        let _ = l.live(0);
    }

    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn the_seed_door_audits() {
        let l = witnessed();
        derail(&l);
        l.seed_spent([(1, ACC.to_string(), 9)]);
    }

    /// The read doors too: they take the same guard, so they carry the same check.
    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn the_read_doors_audit() {
        let l = witnessed();
        derail(&l);
        let _ = l.get("snd_witness");
    }

    #[test]
    #[should_panic(expected = "send ledger invariant violated")]
    fn the_outstanding_door_audits() {
        let l = witnessed();
        derail(&l);
        let _ = l.outstanding(1, ACC);
    }

    /// And the negative: an intact ledger says nothing, so the tests above are measuring the
    /// corruption and not merely the fact that a door was called.
    #[test]
    fn an_intact_ledger_passes_every_door_in_silence() {
        let l = witnessed();
        committed(&l, "snd_door", 9);
        let _ = l.open(1, ACC, 20, 1, None);
        let _ = l.live(0);
        let _ = l.get("snd_witness");
        l.seed_spent([(1, ACC.to_string(), 30)]);
        assert!(l.faults().is_empty(), "{VIOLATED} on a ledger nobody touched: {:?}", l.faults());
    }

    // ---- The ledger does not survive the process, so it is seeded from what does ----

    /// A seeded number is SPENT, not merely reserved: a reservation can be released and a
    /// pending transaction's number never may be.
    #[test]
    fn a_seeded_nonce_is_burnt_rather_than_reserved() {
        let l = SendLedger::default();
        assert_eq!(l.seed_spent([(1, ACC.to_string(), 5), (1, ACC.to_string(), 5)]), 1, "once");
        assert_eq!(open(&l, 1, 5).claim().nonce(), 6, "a pending transaction still owns 5");
        assert_eq!(l.outstanding(1, ACC), 1, "and the abandoned claim gave 6 back, not 5");
        // Per account, like every other number here.
        assert_eq!(open(&l, 11_155_111, 5).claim().nonce(), 5, "another chain is untouched");
    }

    /// End to end over the real on-disk history. Process 1 broadcasts at 5 and dies; the
    /// persisted row is all process 2 has, and `latest` still answers 5 because the
    /// transaction has not mined. Without the seed the second process signs at 5 too.
    #[test]
    fn a_new_process_does_not_sign_at_a_nonce_a_pending_row_is_using() {
        use crate::history::{History, TxRecord};
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let row = |hash: &str, status: &str, nonce: Option<u64>| TxRecord {
            hash: hash.into(),
            chain_id: 1,
            from: ACC.into(),
            status: status.into(),
            nonce,
            ..Default::default()
        };
        h.add(ACC, row("0xdead5", "pending", Some(5)));
        // Mined: `latest` counts it, so `reserve` starts above it and seeding it buys nothing.
        h.add(ACC, row("0xdead4", "confirmed", Some(4)));
        // Written before the field existed: there is nothing to protect with.
        h.add(ACC, row("0xold", "pending", None));

        let shipped = SendLedger::default();
        assert_eq!(shipped.open(1, ACC, 5, 1, None).unwrap().claim().nonce(), 5,
                   "the collision this fixes: a fresh process hands out 5 again");

        let l = SendLedger::default();
        assert_eq!(l.seed_spent(h.unsettled_nonces()), 1, "the pending row alone is carried over");
        assert_eq!(open(&l, 1, 5).claim().nonce(), 6, "0xdead5 may be mined at 5 at any moment");
    }

    // ---- one predicate decides both halves of `leg_spent` ----

    /// A settle that wrote `Broadcast` with no ticket used to leave the job spent and the
    /// reserver's set empty. The number was then protected only by the job staying in
    /// `jobs` — and the map has exactly one eviction, a duplicate request id.
    #[test]
    fn a_broadcast_written_without_a_ticket_still_burns_its_number() {
        let l = SendLedger::default();
        committed(&l, "snd_a", 5);
        l.settle("snd_a", bcast("0xdead"));

        let g = l.open(1, ACC, 5, 1, Some(5)).unwrap();
        assert_eq!(names(&g.claim().replaces), Some("snd_a"), "a pin names what it replaces");
        g.commit(SendJob { request_id: "snd_a".into(), ..job() });
        l.settle("snd_a", SendStatus::Rejected);

        assert_eq!(l.outstanding(1, ACC), 1, "5 may be on chain and must stay burnt");
        assert_eq!(open(&l, 1, 5).claim().nonce(), 6, "so the next send is never handed 5");
    }

    /// The same eviction against a properly claimed broadcast. Once the job is gone the
    /// reserver's `spent` set is the ONLY record that the number left, which is what makes
    /// `release`'s refusal to free a spent number load-bearing rather than defence in depth.
    #[test]
    fn an_evicted_broadcast_job_leaves_its_number_burnt_behind_it() {
        let l = SendLedger::default();
        committed(&l, "snd_a", 5);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_a", 0) else {
            unreachable!("the first claim wins")
        };
        l.leaving(&t, 0).unwrap();
        broadcast(&l, &t, "0xdead");

        let g = l.open(1, ACC, 5, 1, Some(5)).unwrap();
        g.commit(SendJob { request_id: "snd_a".into(), ..job() });
        l.settle("snd_a", SendStatus::Rejected);

        assert_eq!(l.outstanding(1, ACC), 1, "the eviction lost the job; `spent` is what is left");
        assert_eq!(open(&l, 1, 5).claim().nonce(), 6);
    }

    /// `open` used a pinned number whatever `hold` answered, so it could not tell a deliberate
    /// replacement from an unpinned send that took the number a microsecond earlier. Only a
    /// leg that has begun to leave may be replaced.
    #[test]
    fn two_live_sends_never_share_a_number_unless_one_names_the_other() {
        let l = SendLedger::default();
        committed(&l, "snd_a", 5);
        let Err(e) = l.open(1, ACC, 5, 1, Some(5)) else {
            panic!("a pin may not take the number a send that has not left is using")
        };
        assert!(e.contains("has not been broadcast"), "{e}");
        assert_eq!(l.outstanding(1, ACC), 1, "and the refused pin reserved nothing");

        // A claim is protected the same way: it is a send about to be shown to a human.
        let other = open(&l, 1, 5);
        assert_eq!(other.claim().nonce(), 6);
        assert!(l.open(1, ACC, 5, 1, Some(6)).is_err(), "nor may a pin take a claim's");

        // A claimed-but-not-left send is still not replaceable: nothing has left yet.
        assert!(matches!(l.claim_broadcast("snd_a", 0), BroadcastClaim::Claimed(_)));
        assert!(l.open(1, ACC, 5, 1, Some(5)).is_err(), "a claim is not a departure");
    }

    /// Once a leg has left, the same pin is the documented replacement.
    #[test]
    fn a_leg_that_left_can_be_replaced_by_a_pin() {
        let l = SendLedger::default();
        committed_n(&l, "snd_a", 5, 2);
        let BroadcastClaim::Claimed(t) = l.claim_broadcast("snd_a", 0) else { panic!() };
        l.leaving(&t, 0).unwrap();
        let g = l.open(1, ACC, 5, 1, Some(5)).unwrap();
        assert_eq!(names(&g.claim().replaces), Some("snd_a"));
        // The second leg has not left, and may not be replaced.
        drop(g);
        assert!(l.open(1, ACC, 5, 1, Some(6)).is_err(), "leg 2 has not left");
    }

    /// THE WEDGE. Seeding closed the only escape a dropped transaction had: a number burnt by
    /// a row that will never mine stays burnt across every restart, and since a gap stops
    /// every later send from mining too, the account queues behind it for good. The escape is
    /// to pin that number on a replacement — and after a restart no job holds it, which is
    /// exactly the case `pin` used to refuse.
    #[test]
    fn a_nonce_carried_over_from_a_dead_process_can_still_be_pinned() {
        let l = SendLedger::default();
        assert_eq!(l.seed_spent([(1, ACC.to_string(), 5)]), 1);
        assert_eq!(open(&l, 1, 5).claim().nonce(), 6, "an unpinned send steps over it");

        let g = l.open(1, ACC, 5, 1, Some(5)).expect("the documented escape must work");
        assert_eq!(g.claim().nonce(), 5);
        assert_eq!(g.claim().replaces, Some(Replaces::Departed), "it replaces what left");
        g.commit(SendJob { request_id: "snd_new".into(), ..job() });

        // It is a replacement, not a release: nobody else is handed 5, and the pin cannot be
        // repeated while the replacement itself has not left.
        assert_eq!(open(&l, 1, 5).claim().nonce(), 6);
        assert!(l.open(1, ACC, 5, 1, Some(5)).is_err(), "the replacement is not spent");
        assert!(l.faults().is_empty(), "{:?}", l.faults());
    }

    /// A repeated request id overwrites a live job. Nothing burns its numbers and no holder
    /// is left to release them, so they are reserved for the life of the process — an
    /// availability bug, and the ledger says so rather than reasoning its way to a release.
    #[test]
    fn a_duplicate_request_id_strands_its_nonces_and_reports_them() {
        let l = SendLedger::default();
        committed_n(&l, "snd_1", 5, 2);
        assert_eq!(l.outstanding(1, ACC), 2);
        assert!(l.stranded().is_empty());

        committed(&l, "snd_1", 7);
        assert_eq!(l.stranded(), vec![(1, ACC.to_string(), 5), (1, ACC.to_string(), 6)],
                   "the leak is disclosed, both numbers");
        assert_eq!(l.outstanding(1, ACC), 3, "and 5 and 6 are still reserved, held by nobody");
        // The converse of containment stays unchecked: an unheld reservation is not a fault.
        assert!(l.faults().is_empty(), "{:?}", l.faults());

        // Nothing here frees them, and the way out is the same one a restart uses.
        let g = l.open(1, ACC, 6, 1, Some(5)).expect("a stranded number can be pinned");
        assert_eq!((g.claim().nonce(), g.claim().replaces.clone()), (5, Some(Replaces::Departed)));
    }

    /// `from_claim` cuts a draft with more legs than numbers: a leg with no number is a leg
    /// nothing was signed at, and it must not carry a number of its own invention.
    #[test]
    fn a_job_takes_exactly_the_claims_numbers() {
        let l = SendLedger::default();
        let g = open_n(&l, 5, 2);
        let nonces = g.claim().nonces.clone();
        g.commit(SendJob { request_id: "snd_1".into(), ..job_with(3) });
        let j = l.get("snd_1").unwrap();
        assert_eq!(j.nonces(), nonces);
        assert_eq!(j.legs.len(), 2, "the third leg had no number and is gone");
        assert!(l.faults().is_empty(), "{:?}", l.faults());
    }
}
