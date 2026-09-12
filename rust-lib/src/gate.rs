//! The one fact this wallet is willing to remember about another module's gate.
//!
//! Every gated method used to ask `eth_rpc_module.verified_proxy_status` again, and that call
//! is a cross-process hop that has frozen this wallet before. `eth_rpc` now announces mode
//! changes, so the answer can be remembered — but a gate cache that goes stale in the open
//! direction is a wallet showing chain data while verification is actually blocking, which is
//! the failure the gate exists to prevent.
//!
//! So only ONE value is ever stored: "this chain's verified-proxy mode is `off`". eth_rpc
//! computes `blocking = mode_required && !usable`, so an `off` chain is never blocking, for
//! any proxy health, ever. A `required` chain is never cached at all — its verdict turns on
//! live proxy health, which no event covers — so the health probe is never skipped where it
//! decides anything. The cache can therefore only be wrong about a mode that moved off ->
//! required without us hearing, and [`ModeCache`] is built so that every such window ends in
//! [`Gate::Ask`]:
//!
//! * nothing is trusted until the subscription is actually ARMED. Holding a subscription
//!   handle is not that: the first arm is deferred whenever the provider is not yet
//!   listening, which is exactly the case a module subscribing from `on_context_ready` is
//!   in. Only the runtime's per-module status channel says when it happened, so a runtime
//!   without one ([`status_channel`]) never opens this cache at all;
//! * going live, and losing the feed, both bump the generation and drop what is held, so a
//!   read already in flight cannot land its answer afterwards;
//! * an event applies under the same lock that stamps the generation, so a read that raced it
//!   is rejected rather than allowed to overwrite the newer fact;
//! * a mode that is not exactly `off` — `required`, `unknown`, a value a future eth_rpc
//!   invents — removes the entry.
//!
//! A miss is not a refusal: it falls through to the live read, which refuses on its own if it
//! cannot be answered. Refusing outright on a cold cache would fail every wallet at startup.
//!
//! What arms it is `PluginProxy::on_subscription_status` reporting `SubStatus::Armed` while a
//! mode subscription exists. That is ONE edge, in `glue.rs::arm_gate`, and a re-subscribe
//! after a dead feed goes back through it rather than around it — a new subscription is
//! unarmed at creation, so "the re-subscribe worked" opens nothing. A runtime with no status
//! channel latches the cache cold instead, and there every gated read pays its own probe.

use std::collections::HashSet;
use std::sync::Mutex;

/// eth_rpc's word for a gate that is not enforcing anything. The only mode worth caching.
pub const MODE_OFF: &str = "off";

/// Whether `protocol_version` has the per-module subscription status channel this cache is
/// built on (logos-protocol 0.9). Below it the SDK's watcher installs and never fires, so a
/// cache waiting on `Armed` would wait forever: the caller must latch it cold instead.
pub fn status_channel(protocol_version: &str) -> bool {
    let mut it = protocol_version.split('.');
    let major: u32 = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let minor: u32 = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    (major, minor) >= (0, 9)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Gate {
    /// Verification is off for this chain and we are still being told about changes.
    Open,
    /// Everything else. Read the verdict from eth_rpc.
    Ask,
}

#[derive(Default)]
struct Inner {
    /// Bumped by every event and every change of feed state. A read carries a ticket cut
    /// before it went out, and lands only if nothing has moved since.
    generation: u64,
    /// Whether the mode subscription is established. False = trust nothing.
    live: bool,
    /// Latched by [`ModeCache::no_status_channel`]: nothing may make this cache live again
    /// for the rest of the process.
    cold: bool,
    off: HashSet<u64>,
}

/// Chains known to have verification switched off, for as long as we are being told.
#[derive(Default)]
pub struct ModeCache {
    inner: Mutex<Inner>,
}

impl ModeCache {
    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        // Poisoning means a panic left the set half-written; an empty one is the safe reading.
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => {
                let mut g = p.into_inner();
                g.live = false;
                g.off.clear();
                g
            }
        };
        f(&mut g)
    }

    /// The subscription ARMED. Bumps the generation so a read issued while the feed was still
    /// dark cannot be trusted retroactively — a mode change in that window was announced to
    /// nobody. Refused outright once [`Self::no_status_channel`] has latched.
    pub fn feed_live(&self) {
        self.with(|i| {
            i.generation += 1;
            i.live = !i.cold;
            i.off.clear();
        });
    }

    /// This runtime has no [`status_channel`], so no one can say when the subscription arms
    /// or dies. Latched cold for the process: every gated read then pays its own live probe,
    /// which is what it paid before this cache existed.
    pub fn no_status_channel(&self) {
        self.with(|i| {
            i.generation += 1;
            i.cold = true;
            i.live = false;
            i.off.clear();
        });
    }

    /// Whether the cold latch has taken: past it nothing can make this cache live again.
    pub fn latched_cold(&self) -> bool {
        self.with(|i| i.cold)
    }

    /// The subscription ended or could not be built. Everything held is now unverifiable.
    pub fn feed_dead(&self) {
        self.with(|i| {
            i.generation += 1;
            i.live = false;
            i.off.clear();
        });
    }

    pub fn gate(&self, chain_id: u64) -> Gate {
        self.with(|i| if i.live && i.off.contains(&chain_id) { Gate::Open } else { Gate::Ask })
    }

    /// Cut before an outbound read goes out; hand it back to [`Self::learned`].
    pub fn ticket(&self) -> u64 {
        self.with(|i| i.generation)
    }

    /// What a live read said this chain's mode was. Dropped whole if anything moved while the
    /// read was in flight: the event that moved it is newer than this answer.
    pub fn learned(&self, chain_id: u64, mode: Option<&str>, ticket: u64) {
        self.with(|i| {
            if !i.live || i.generation != ticket {
                return;
            }
            Self::apply(i, chain_id, mode);
        });
    }

    /// `verified_proxy_mode_changed`. Authoritative, and always newer than any read in flight.
    pub fn told(&self, chain_id: u64, mode: &str) {
        self.with(|i| {
            i.generation += 1;
            Self::apply(i, chain_id, Some(mode));
        });
    }

    /// `chain_config_changed`, which does not carry the mode. Costs one live read; the two
    /// events arrive on independent subscriptions, so this must be safe in either order —
    /// and it is, because it only ever moves a chain towards [`Gate::Ask`].
    pub fn invalidate(&self, chain_id: u64) {
        self.with(|i| {
            i.generation += 1;
            i.off.remove(&chain_id);
        });
    }

    fn apply(i: &mut Inner, chain_id: u64, mode: Option<&str>) {
        if mode == Some(MODE_OFF) {
            i.off.insert(chain_id);
        } else {
            i.off.remove(&chain_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: an `off` chain stops costing an IPC hop, and only an `off` chain does.
    #[test]
    fn only_a_mode_that_is_off_is_ever_remembered() {
        let c = ModeCache::default();
        c.feed_live();
        for m in ["required", "unknown", "Off", "", "disabled"] {
            c.told(1, m);
            assert_eq!(c.gate(1), Gate::Ask, "mode {m:?} must not open the gate");
        }
        c.told(1, MODE_OFF);
        assert_eq!(c.gate(1), Gate::Open);
        // Per chain: chain 1 being off says nothing about chain 10.
        assert_eq!(c.gate(10), Gate::Ask);
    }

    /// The direction that matters. Verification being switched ON must never be missed.
    #[test]
    fn switching_verification_on_closes_the_gate_at_once() {
        let c = ModeCache::default();
        c.feed_live();
        c.told(1, MODE_OFF);
        c.told(1, "required");
        assert_eq!(c.gate(1), Gate::Ask, "a required chain is read live, every time");
    }

    #[test]
    fn nothing_is_trusted_before_the_subscription_is_live() {
        let c = ModeCache::default();
        // A read that answered `off` before the feed existed: no one would tell us it moved.
        let t = c.ticket();
        c.learned(1, Some(MODE_OFF), t);
        assert_eq!(c.gate(1), Gate::Ask);

        // Nor may it land afterwards — arming is not retroactive over the window it missed.
        c.feed_live();
        c.learned(1, Some(MODE_OFF), t);
        assert_eq!(c.gate(1), Gate::Ask);
    }

    /// The lost update: a read answers `off`, the mode flips to `required` while it is in
    /// flight, and the read then writes its stale answer over the event's.
    #[test]
    fn a_read_cannot_land_over_an_event_that_overtook_it() {
        let c = ModeCache::default();
        c.feed_live();
        let t = c.ticket();
        c.told(1, "required");
        c.learned(1, Some(MODE_OFF), t);
        assert_eq!(c.gate(1), Gate::Ask);

        // A ticket cut after the event is current again, and does open the gate.
        let t = c.ticket();
        c.learned(1, Some(MODE_OFF), t);
        assert_eq!(c.gate(1), Gate::Open);
    }

    /// Losing the feed is the case that decides whether this cache is safe to hold at all:
    /// past that point nothing will tell us the user switched verification on.
    #[test]
    fn losing_the_feed_drops_everything_it_was_holding() {
        let c = ModeCache::default();
        c.feed_live();
        c.told(1, MODE_OFF);
        c.told(10, MODE_OFF);
        c.feed_dead();
        assert_eq!(c.gate(1), Gate::Ask);
        assert_eq!(c.gate(10), Gate::Ask);

        // And a read still in flight over the gap cannot refill it.
        let t = c.ticket();
        c.learned(1, Some(MODE_OFF), t);
        assert_eq!(c.gate(1), Gate::Ask);

        // Re-arming starts cold rather than resuming: the gap was unwatched.
        c.feed_live();
        assert_eq!(c.gate(1), Gate::Ask);
    }

    /// A config change carries no mode, so it can only remove — which makes it safe to
    /// process in either order against the mode event that accompanies it.
    #[test]
    fn a_config_change_only_ever_moves_a_chain_towards_asking() {
        let c = ModeCache::default();
        c.feed_live();
        c.told(1, MODE_OFF);

        // eth_rpc's own order: config first, then the mode.
        c.invalidate(1);
        c.told(1, MODE_OFF);
        assert_eq!(c.gate(1), Gate::Open);

        // Reordered by two independent subscriptions: one extra live read, same verdict.
        c.told(1, MODE_OFF);
        c.invalidate(1);
        assert_eq!(c.gate(1), Gate::Ask);

        // A removed chain reports `off`, and off is off — eth_rpc answers exactly that.
        c.told(1, MODE_OFF);
        assert_eq!(c.gate(1), Gate::Open);
    }

    /// The degradation that decides whether the fallback is a fallback or a dead wallet:
    /// a runtime with no status channel can never open the cache, and cannot be talked into
    /// it afterwards by a stray `feed_live` from a subscription handle that merely exists.
    #[test]
    fn a_runtime_without_the_status_channel_latches_the_cache_cold() {
        let c = ModeCache::default();
        assert!(!c.latched_cold());
        c.no_status_channel();
        assert!(c.latched_cold(), "and it is readable, which is what glue.rs is checked on");
        c.feed_live();
        c.told(1, MODE_OFF);
        assert_eq!(c.gate(1), Gate::Ask, "no status channel means no cached answer, ever");
        // Nor through the read path: an answer that lands cold is still an answer nobody
        // is obliged to correct.
        c.learned(1, Some(MODE_OFF), c.ticket());
        assert_eq!(c.gate(1), Gate::Ask);
    }

    #[test]
    fn the_status_channel_arrived_in_protocol_0_9() {
        for v in ["0.9", "0.9.1", "0.10.0", "1.0.0"] {
            assert!(status_channel(v), "{v} has the status channel");
        }
        for v in ["0.8", "0.8.9", "", "nonsense", "0"] {
            assert!(!status_channel(v), "{v} has no status channel");
        }
    }

    #[test]
    fn an_unreadable_verdict_never_opens_the_gate() {
        let c = ModeCache::default();
        c.feed_live();
        c.told(1, MODE_OFF);
        // What `verified::unknown_verdict` carries when eth_rpc could not be read at all.
        c.learned(1, Some("unknown"), c.ticket());
        assert_eq!(c.gate(1), Gate::Ask);
        // And a verdict with no mode field at all.
        c.told(1, MODE_OFF);
        c.learned(1, None, c.ticket());
        assert_eq!(c.gate(1), Gate::Ask);
    }
}
