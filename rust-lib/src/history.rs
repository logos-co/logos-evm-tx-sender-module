//! Local transaction history — the record of the transactions THIS module broadcast, which is
//! the only history available without an indexer. One JSON file per account address under
//! `<dir>/history/<address>.json`. Pure Rust, unit-tested with `cargo test`.
//!
//! A row is written BEFORE its transaction leaves, as an `unknown` intent, and completed by
//! the outcome. That order is the whole point: the record is what a restarted process reads
//! to know which nonces are already spoken for, so writing it after the broadcast leaves a
//! window — the entire RPC — in which a crash loses a number that has left. See
//! `record_intent`. A row that reaches a hash becomes `pending` and is moved on by a receipt
//! poll; the schedule and the classification live here, not in the glue, so both are
//! testable without the runtime.
//!
//! A bundle writes one row PER LEG, each just before its own leg leaves, keyed by the send's
//! request id and the leg's index. Every row carries the requester's `label`, `meta` and
//! `purpose` verbatim, and the attested `origin` that asked for it.
//!
//! The module dispatches concurrently (`concurrency: "multi"`), so every read-modify-write
//! runs under one lock and every write lands by rename — a reader never sees a half file,
//! and an unreadable one is never overwritten with a shorter list.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::receipt::{self, TokenTransfer};
use crate::txbuild::parse_u256_any;

/// A transaction record.
///
/// Everything past `last_polled_at` is optional and skipped when absent: a history file
/// written by an earlier build still loads, and an absent field renders as an em-dash
/// rather than as a zero the user would read as a fact.
///
/// `default` at the container, not the field: a row written before a field existed must
/// load, and one failed row must not take every other row in the file down with it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct TxRecord {
    /// Empty until the broadcast answers. An intent row has no hash — that is what the
    /// broadcast is for — so nothing may key off it before then.
    pub hash: String,
    pub chain_id: u64,
    pub from: String,
    /// The transaction's own `to`: the contract called, or the recipient of a plain transfer.
    pub to: String,
    /// wei attached to the call, as a decimal/hex string.
    pub value: String,
    /// "native" for a plain transfer (no calldata), "call" for anything carrying calldata.
    /// Rows an earlier build wrote as "erc20" still load and are read as calls.
    pub kind: String,
    /// "unknown" | "pending" | "confirmed" | "failed". `unknown` is an intent whose outcome
    /// never came back: not pending (there is no hash to poll) and not failed (the
    /// transaction may be on chain). Its nonce stays spoken for until a human resolves it.
    pub status: String,
    /// Epoch seconds of the BROADCAST, not of the block — a receipt carries no time.
    pub timestamp: u64,
    /// Epoch seconds of the last receipt poll; 0 = never polled.
    #[serde(default)]
    pub last_polled_at: u64,

    /// The send that wrote this row ahead of its broadcast. It is how the outcome finds the
    /// row again, since there is no hash yet, and it names the send in a disclosure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Which leg of that send this row is, from 0, and how many the send had.
    #[serde(default)]
    pub leg: u32,
    #[serde(default = "one")]
    pub legs: u32,
    /// The requester's word for this leg. Never interpreted here.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// What the requester claimed the whole send was for — the same line the signer showed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub purpose: String,
    /// The module that asked for the send, as the runtime attested it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub origin: String,
    /// Whatever the requester wanted stored beside the row, verbatim.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub meta: Value,
    /// Why an `unknown` row is still unknown; absent while its broadcast is in flight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_reason: Option<String>,

    // Known at broadcast, from the quote the user approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<String>,
    /// The tip the send offered. Not in any receipt, so a row written before this existed can
    /// only learn it from the transaction itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<String>,
    /// `max_fee_per_gas × gas_limit` — the ceiling the user was quoted, shown while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_ceiling_wei: Option<String>,
    /// The transaction's OWN `data` — the bytes the human approved. `"0x"` is a native
    /// transfer's own answer and is stored as one; absent means a row written before this
    /// field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_input: Option<String>,

    // Filled from the receipt that settled the row. `None` means the node did not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_gas_price: Option<String>,
    /// `gas_used × effective_gas_price`, computed here because a JS `+` on two wei strings
    /// loses precision above 2^53.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_wei: Option<String>,
    /// `value + fee_wei` — the ether that LEFT the account. CONFIRMED rows only: a failed
    /// transaction moved the fee alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_wei: Option<String>,
    /// The `to` the RECEIPT reports. Descriptive only: identity still keys off `from` and
    /// `hash`, never off this. Its presence is also the marker that a receipt was absorbed
    /// by a build carrying these fields, which is what offers an older row a backfill.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_to: Option<String>,
    /// ERC-20 Transfer logs decoded from the receipt, this account's own first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transfers: Vec<TokenTransfer>,
    /// Transfer logs past `TRANSFERS_MAX`. Absent means the cap dropped none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfers_more: Option<u32>,
}

fn one() -> u32 {
    1
}

impl TxRecord {
    /// Copy the receipt's own numbers onto the row and derive the two totals. Idempotent,
    /// so re-applying a receipt backfills a row recorded before these fields existed.
    fn absorb_receipt(&mut self, receipt: &Value) {
        let q = |k: &str| receipt.get(k).and_then(Value::as_str).and_then(parse_u256_any);

        self.block_number = q("blockNumber").and_then(|v| u64::try_from(v).ok());
        let used = q("gasUsed");
        let price = q("effectiveGasPrice");
        self.gas_used = used.map(|v| v.to_string());
        self.effective_gas_price = price.map(|v| v.to_string());
        let fee = used.zip(price).and_then(|(u, p)| u.checked_mul(p));
        self.fee_wei = fee.map(|v| v.to_string());
        // A FAILED transaction moved the fee and nothing else, and the fee field already
        // carries that number — a total equal to it is the same figure under a name that says
        // the amount left too. So a failure has no total, and a view says so in words.
        self.total_wei = match (classify_receipt(receipt), fee) {
            ("confirmed", Some(f)) => {
                parse_u256_any(&self.value).and_then(|v| v.checked_add(f)).map(|t| t.to_string())
            }
            _ => None,
        };

        // The rest of the receipt. `tx_to` never overwrites `to`: they are two readings of
        // one fact and a consumer may label them apart.
        self.tx_to = receipt::receipt_to(receipt);
        let (transfers, more) = receipt::decode_transfers(receipt, &self.from);
        self.transfers = transfers;
        self.transfers_more = (more > 0).then_some(more);
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// "pending" | "confirmed" | "failed". A JSON-null receipt means "not mined yet",
/// which is not an answer and not an error.
pub fn classify_receipt(receipt: &Value) -> &'static str {
    match receipt.get("status").and_then(Value::as_str) {
        Some("0x1") => "confirmed",
        Some(_) => "failed",
        None => "pending",
    }
}

/// Seconds to wait before the next receipt poll for a record `age` seconds old.
/// None means stop polling and leave the row `pending` — never invent a status the
/// view cannot render.
pub fn poll_interval_secs(age: u64) -> Option<u64> {
    match age {
        0..=30 => Some(3),
        31..=300 => Some(15),
        301..=3600 => Some(60),
        _ => None,
    }
}

/// Whether another poll could still change this row. False for a settled row and for one
/// past the give-up horizon — the two cases where a caller's timer has nothing left to do.
pub fn is_live(r: &TxRecord, now: u64) -> bool {
    r.status == "pending" && poll_interval_secs(now.saturating_sub(r.timestamp)).is_some()
}

/// A row we broadcast, polled for the whole horizon, and never saw a receipt for. It is not
/// confirmed, not failed and not still coming: we simply stopped asking, and say so.
pub fn is_stalled(r: &TxRecord, now: u64) -> bool {
    r.status == "pending" && poll_interval_secs(now.saturating_sub(r.timestamp)).is_none()
}

/// An intent whose outcome never came back. We cannot say the transaction left and we
/// cannot say it did not, so we say neither and keep the number it was signed at.
pub fn is_unresolved(r: &TxRecord) -> bool {
    r.status == "unknown"
}

/// A row whose transaction may be on chain: still pending, or an intent with no outcome.
/// Its nonce is not free, and this is what a restart reads to know that.
pub fn is_unsettled(r: &TxRecord) -> bool {
    r.status == "pending" || is_unresolved(r)
}

/// Why a history file did not load. Only one of the two is safe to recover from.
enum ReadFailure {
    Unreadable,
    NotHistory,
}

/// What one stored-row update did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wrote {
    /// The merged list is on disk.
    Landed,
    /// Nothing matched, so nothing was written.
    Untouched,
    /// The rows could not be read, or could not be written: the change is NOT durable.
    Failed,
}

/// A stored entry: a row we understand, or bytes we do not. An entry that does not parse
/// costs itself alone — it is carried through every write untouched, so one corrupt entry
/// can neither hide the file's other transactions nor be deleted by the next write.
enum Row {
    Rec(TxRecord),
    Opaque(Value),
}

impl Row {
    fn rec(&self) -> Option<&TxRecord> {
        match self {
            Row::Rec(r) => Some(r),
            Row::Opaque(_) => None,
        }
    }
}

/// A row serializes as itself, so an entry we could not parse goes back exactly as it came.
impl Serialize for Row {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Row::Rec(r) => r.serialize(s),
            Row::Opaque(v) => v.serialize(s),
        }
    }
}

/// One JSON array into rows. `None` only when the bytes are not an array at all — that is
/// the whole file being wrong, which is the one case worth moving aside.
fn parse_rows(txt: &str) -> Option<Vec<Row>> {
    let entries: Vec<Value> = serde_json::from_str(txt).ok()?;
    Some(
        entries
            .into_iter()
            .map(|v| match TxRecord::deserialize(&v) {
                Ok(r) => Row::Rec(r),
                Err(_) => Row::Opaque(v),
            })
            .collect(),
    )
}

fn read_rows(p: &std::path::Path) -> Vec<Row> {
    std::fs::read_to_string(p).ok().and_then(|t| parse_rows(&t)).unwrap_or_default()
}

/// The file-name key for an account: an optional `0x` stripped and lowercased, so the same
/// account resolves regardless of prefix or case in the caller's address.
fn file_key(address: &str) -> String {
    let a = address.trim();
    a.strip_prefix("0x").or_else(|| a.strip_prefix("0X")).unwrap_or(a).to_lowercase()
}

/// Proof that one leg's intent is on disk.
///
/// Its fields are private and `History::record_intent` is the only constructor, so a
/// broadcast that takes one cannot happen before the record does — the ordering is a type
/// and not something each new path has to remember.
#[derive(Debug)]
pub struct Recorded {
    address: String,
    request_id: String,
    leg: u32,
}

impl Recorded {
    pub fn leg(&self) -> u32 {
        self.leg
    }

    /// The row this proof was written for, and only while it is still awaiting an outcome:
    /// a settled row is somebody else's, and a second outcome must not walk one back.
    fn owns(&self, r: &TxRecord) -> bool {
        is_unresolved(r)
            && r.request_id.as_deref() == Some(self.request_id.as_str())
            && r.leg == self.leg
    }
}

/// Per-address history store rooted at a persistence directory.
pub struct History {
    dir: PathBuf,
    /// Serializes read-modify-write across concurrent dispatch. Process-local: the file is
    /// this module's, and the rename below is what makes another reader's view consistent.
    gate: Mutex<()>,
}

impl History {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, gate: Mutex::new(()) }
    }

    fn path(&self, address: &str) -> PathBuf {
        self.dir.join("history").join(format!("{}.json", file_key(address)))
    }

    /// The stored entries. An error is never "this account has no transactions": the two
    /// kinds are kept apart because only one of them is safe to recover from. Entries are
    /// parsed one at a time, because a single unparseable row used to cost the whole file —
    /// every transaction in it, and with them every nonce a restart reads back.
    fn read(&self, address: &str) -> Result<Vec<Row>, ReadFailure> {
        match std::fs::read_to_string(self.path(address)) {
            Ok(txt) => parse_rows(&txt).ok_or(ReadFailure::NotHistory),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(_) => Err(ReadFailure::Unreadable),
        }
    }

    /// Sidecars beside the account file, holding rows written while that file could not be
    /// read. They are ordinary history files under a name every sweep here already reads.
    fn orphans(&self, address: &str) -> Vec<PathBuf> {
        let prefix = format!("{}.orphan-", file_key(address));
        let Ok(entries) = std::fs::read_dir(self.dir.join("history")) else { return Vec::new() };
        let mut out: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
                name.starts_with(&prefix) && name.ends_with(".json")
            })
            .collect();
        out.sort();
        out
    }

    /// The account file cannot be read, so this row cannot be merged into it — and dropping
    /// it is how a broadcast ends up recorded nowhere while its nonce is handed to the next
    /// send. It goes beside the file instead, where every reader here finds it.
    fn write_orphan(&self, address: &str, record: &TxRecord) -> bool {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = self.dir.join("history");
        let _ = std::fs::create_dir_all(&dir);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let p = dir.join(format!(
            "{}.orphan-{}.{n}.json",
            file_key(address),
            std::process::id()
        ));
        let Ok(txt) = serde_json::to_string_pretty(&[record]) else { return false };
        write_then_rename(&p.with_extension("tmp"), &p, &txt)
    }

    /// Fold stranded sidecars back into the account file now that it reads again. Answers
    /// the files to delete once the merged list has LANDED — deleting them any earlier
    /// loses exactly the rows they exist to keep.
    fn adopt_orphans(&self, address: &str, rows: &mut Vec<Row>) -> Vec<PathBuf> {
        let files = self.orphans(address);
        for p in &files {
            rows.extend(read_rows(p));
        }
        files
    }

    /// Move bytes that are not a history aside rather than over them. A file truncated by
    /// an older build must not wedge the module, and the user's transactions are not ours
    /// to delete — they stay next to the new file, under a name that says what happened.
    fn quarantine(&self, address: &str) -> bool {
        let p = self.path(address);
        let aside = p.with_extension(format!("json.unreadable-{}", now_secs()));
        std::fs::rename(&p, &aside).is_ok()
    }

    /// Write by rename, so a concurrent reader sees either the old file or the new one and
    /// never the truncated middle of a `write`.
    fn write(&self, address: &str, rows: &[Row]) -> bool {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let p = self.path(address);
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let Ok(txt) = serde_json::to_string_pretty(rows) else { return false };
        let tmp = p.with_extension(format!(
            "{}.{}.tmp",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        write_then_rename(&tmp, &p, &txt)
    }

    /// Every row for `address`, newest first: the account file plus any sidecar a write
    /// stranded beside it while the file could not be read. Legs of one send keep their
    /// order within the same second.
    pub fn list(&self, address: &str) -> Vec<TxRecord> {
        let _g = self.gate.lock();
        let mut rows: Vec<TxRecord> =
            self.read(address).unwrap_or_default().iter().filter_map(|r| r.rec().cloned()).collect();
        for p in self.orphans(address) {
            rows.extend(read_rows(&p).iter().filter_map(|r| r.rec().cloned()));
        }
        rows.sort_by(|a, b| b.timestamp.cmp(&a.timestamp).then(b.leg.cmp(&a.leg)));
        rows
    }

    /// Prepend a record (newest first). `false` means the row is on disk NOWHERE, and a
    /// caller about to move money must read that as a refusal.
    ///
    /// Never writes over a history it could not read: replacing one with a one-element
    /// array would destroy an account's transactions to record a single row.
    pub fn add(&self, address: &str, record: TxRecord) -> bool {
        let _g = self.gate.lock();
        let mut rows = match self.read(address) {
            Ok(r) => r,
            // A transient read error may be gone next time, so the file is left alone — but
            // the ROW is not dropped: unreadable is not empty, and it is not a licence to
            // forget a transaction. It goes into a sidecar the readers here already sweep.
            Err(ReadFailure::Unreadable) => return self.write_orphan(address, &record),
            Err(ReadFailure::NotHistory) if self.quarantine(address) => Vec::new(),
            Err(ReadFailure::NotHistory) => return false,
        };
        let adopted = self.adopt_orphans(address, &mut rows);
        rows.insert(0, Row::Rec(record));
        self.landed(address, &rows, adopted)
    }

    /// Write the merged list and, only once it is there, drop the sidecars it absorbed.
    fn landed(&self, address: &str, rows: &[Row], adopted: Vec<PathBuf>) -> bool {
        let ok = self.write(address, rows);
        if ok {
            for p in adopted {
                let _ = std::fs::remove_file(p);
            }
        }
        ok
    }

    /// Read, mutate, write — the shape every update here takes. `f` answers whether it
    /// changed the row; a pass that changed nothing writes nothing.
    ///
    /// The answer is three-valued because a bool cannot carry it: "nothing matched" and "the
    /// disk refused the write" are both `false`, and only one of them may ever be announced.
    fn edit(&self, address: &str, mut f: impl FnMut(&mut TxRecord) -> bool) -> Wrote {
        let _g = self.gate.lock();
        let Ok(mut rows) = self.read(address) else { return Wrote::Failed };
        let adopted = self.adopt_orphans(address, &mut rows);
        let mut touched = false;
        for r in rows.iter_mut() {
            if let Row::Rec(rec) = r {
                touched |= f(rec);
            }
        }
        if !touched {
            return Wrote::Untouched;
        }
        if self.landed(address, &rows, adopted) {
            Wrote::Landed
        } else {
            Wrote::Failed
        }
    }

    /// Write one leg's intent to broadcast, BEFORE its signed transaction leaves.
    ///
    /// The row carries no hash — that is what the broadcast is for — and is `unknown`. What
    /// it does carry is (chain, from, nonce), which is everything a restarted process needs
    /// to keep the number burnt. `Err` means the row reached neither the account file nor a
    /// sidecar, and then nothing may be sent: `Recorded` is the only key to the broadcast.
    pub fn record_intent(
        &self,
        request_id: &str,
        leg: u32,
        mut record: TxRecord,
    ) -> Result<Recorded, String> {
        record.request_id = Some(request_id.to_string());
        record.leg = leg;
        record.status = "unknown".into();
        record.hash = String::new();
        let address = record.from.clone();
        if !self.add(&address, record) {
            return Err("this transaction could not be recorded, so it was not sent".into());
        }
        Ok(Recorded { address, request_id: request_id.to_string(), leg })
    }

    /// The broadcast answered with a hash: the intent becomes an ordinary pollable row. The
    /// poll clock starts here rather than at the intent, so the schedule is unchanged.
    pub fn resolve_broadcast(&self, r: &Recorded, hash: &str, now: u64) -> bool {
        self.edit(&r.address, |rec| {
            if !r.owns(rec) {
                return false;
            }
            rec.hash = hash.to_string();
            rec.status = "pending".into();
            rec.timestamp = now;
            true
        }) == Wrote::Landed
    }

    /// The broadcast did not answer with a hash. The row STAYS `unknown` — an error is not
    /// proof the transaction did not leave — and records why, so the number it holds can be
    /// disclosed with the reason it is held.
    pub fn leave_unknown(&self, r: &Recorded, reason: &str) -> bool {
        self.edit(&r.address, |rec| {
            if !r.owns(rec) {
                return false;
            }
            rec.unknown_reason = Some(reason.to_string());
            true
        }) == Wrote::Landed
    }

    /// One record by (address, hash). None when nothing matches. An empty hash matches
    /// nothing: an intent row has none, and it is not every caller's row.
    pub fn find(&self, address: &str, hash: &str) -> Option<TxRecord> {
        if hash.is_empty() {
            return None;
        }
        self.list(address).into_iter().find(|r| r.hash.eq_ignore_ascii_case(hash))
    }

    /// Pending records due for a receipt poll, newest first, at most `limit`.
    pub fn pending_due(&self, address: &str, now: u64, limit: usize) -> Vec<TxRecord> {
        self.list(address)
            .into_iter()
            .filter(|r| r.status == "pending" && is_due(r, now))
            .take(limit)
            .collect()
    }

    /// Every (chain, account, nonce) an UNSETTLED row was signed at — pending ones, and
    /// intents whose outcome never came back. The directory IS the account list: a fresh
    /// process has no other memory of which addresses this module has sent from. EVERY file
    /// in it is tried — a `.tmp` a crashed rename left behind, or a sidecar written while
    /// the account file could not be read, can hold the very row the real file is missing,
    /// and a number not seeded is a collision.
    pub fn unsettled_nonces(&self) -> Vec<(u64, String, u64)> {
        let _g = self.gate.lock();
        let Ok(entries) = std::fs::read_dir(self.dir.join("history")) else { return Vec::new() };
        let mut out = Vec::new();
        for e in entries.flatten() {
            let rows = read_rows(&e.path());
            let due = rows.iter().filter_map(Row::rec).filter(|r| is_unsettled(r));
            out.extend(due.filter_map(|r| Some((r.chain_id, r.from.clone(), r.nonce?))));
        }
        out.sort();
        out.dedup();
        out
    }

    /// Whether any row for `address` could still be moved by a later poll. This is what a
    /// caller's poll timer should stop on; a row past the horizon keeps it running forever.
    pub fn has_live(&self, address: &str, now: u64) -> bool {
        self.list(address).iter().any(|r| is_live(r, now))
    }

    /// Apply a receipt to one record, keyed off the RECORD's own `from` and `hash`, never
    /// the receipt's. Always stamps `last_polled_at`, so an unanswered poll still backs off.
    ///
    /// `Ok(true)` is a stored status that moved AND reached disk — the only outcome a caller
    /// may announce. `Err` is a row the disk refused: the receipt is not recorded, the row
    /// stays as it was, and the next sweep polls it again. Reporting that as a settle is how
    /// a subscriber gets told to re-read a row that still says `pending`.
    pub fn apply_receipt(
        &self,
        record: &TxRecord,
        receipt: &Value,
        now: u64,
    ) -> Result<bool, String> {
        if record.hash.is_empty() {
            return Ok(false);
        }
        let status = classify_receipt(receipt);
        let mut changed = false;
        let wrote = self.edit(&record.from, |r| {
            if !r.hash.eq_ignore_ascii_case(&record.hash) {
                return false;
            }
            r.last_polled_at = now;
            if status != "pending" {
                changed |= r.status != status;
                r.status = status.to_string();
                r.absorb_receipt(receipt);
            }
            true
        });
        match wrote {
            Wrote::Landed => Ok(changed),
            // The row is no longer in the store. Nothing moved and nothing failed here.
            Wrote::Untouched => Ok(false),
            Wrote::Failed => Err(format!(
                "the receipt for {} could not be written to this account's history",
                record.hash
            )),
        }
    }
}

/// Write `txt` to `tmp`, then move it onto `p`. Cleans up on EITHER failure: a write that
/// fails after creating the file leaves one behind, and those accumulate forever.
pub(crate) fn write_then_rename(tmp: &std::path::Path, p: &std::path::Path, txt: &str) -> bool {
    let ok = std::fs::write(tmp, txt).is_ok() && std::fs::rename(tmp, p).is_ok();
    if !ok {
        let _ = std::fs::remove_file(tmp);
    }
    ok
}

fn is_due(r: &TxRecord, now: u64) -> bool {
    poll_interval_secs(now.saturating_sub(r.timestamp))
        .is_some_and(|iv| now >= r.last_polled_at.saturating_add(iv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(hash: &str) -> TxRecord {
        TxRecord {
            hash: hash.into(),
            chain_id: 1,
            from: "0xaaaa".into(),
            to: "0xbbbb".into(),
            value: "0x1".into(),
            kind: "native".into(),
            status: "pending".into(),
            timestamp: 123,
            ..Default::default()
        }
    }

    fn pending_on(chain_id: u64, hash: &str) -> TxRecord {
        TxRecord {
            chain_id,
            hash: hash.into(),
            from: "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266".into(),
            timestamp: 999_990,
            ..rec(hash)
        }
    }

    /// A receipt the store REFUSED is not a settle: a read-only or full history directory
    /// must not report a confirmation the file never took.
    #[test]
    fn a_receipt_the_store_refused_is_not_a_change() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        h.add(addr, TxRecord { from: addr.into(), ..rec("0xdead") });
        let row = h.find(addr, "0xdead").unwrap();

        let hist = dir.path().join("history");
        let was = std::fs::metadata(&hist).unwrap().permissions();
        let mut ro = was.clone();
        ro.set_readonly(true);
        std::fs::set_permissions(&hist, ro).unwrap();
        let out = h.apply_receipt(&row, &json!({"status": "0x1"}), 200);
        // Restored before the assertions, or the failure takes the tempdir's cleanup with it.
        std::fs::set_permissions(&hist, was).unwrap();

        assert!(out.is_err(), "a receipt the disk refused was reported as a settle: {out:?}");
        assert_eq!(h.find(addr, "0xdead").unwrap().status, "pending", "the row is unmoved");
        assert_eq!(h.pending_due(addr, 200, 8).len(), 1, "and is due again on the next sweep");
    }

    #[test]
    fn add_list_find_persist() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        assert!(h.list(addr).is_empty());
        h.add(addr, TxRecord { from: addr.into(), ..rec("0xdead") });
        h.add(addr, TxRecord { from: addr.into(), ..rec("0xbeef") });
        let list = h.list(addr);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].hash, "0xbeef"); // newest first

        let dead = h.find(addr, "0xDEAD").unwrap(); // case-insensitive
        assert!(h.apply_receipt(&dead, &json!({"status": "0x1"}), 42).unwrap());
        assert!(h.find(addr, "0xmissing").is_none());

        // reopen — persisted + status updated
        let h2 = History::new(dir.path().to_path_buf());
        assert_eq!(h2.find(addr, "0xdead").unwrap().status, "confirmed");

        // address key is normalized: stored under 0x-checksummed, found via bare hex
        let bare = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        assert_eq!(h2.list(bare).len(), 2);
    }

    #[test]
    fn a_history_file_written_before_the_optional_fields_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("history").join("aaaa.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            r#"[{"hash":"0x1","chainId":1,"from":"0xaaaa","to":"0xbbbb","value":"0x1",
                 "kind":"erc20","status":"pending","timestamp":5}]"#,
        )
        .unwrap();
        let h = History::new(dir.path().to_path_buf());
        let r = &h.list("0xaaaa")[0];
        assert_eq!(r.last_polled_at, 0);
        // Every field added since is absent, not zero: the view must show an em-dash.
        assert_eq!((r.nonce, r.gas_limit, r.block_number), (None, None, None));
        assert_eq!((&r.fee_wei, &r.total_wei, &r.max_fee_per_gas), (&None, &None, &None));
        assert_eq!((r.leg, r.legs), (0, 1), "a row from before bundles is its send's only leg");
        assert!(r.label.is_empty() && r.origin.is_empty() && r.meta.is_null());
        assert_eq!(r.kind, "erc20", "an old kind is kept as written");
    }

    /// `"0x"` and absent are different answers — one is a plain transfer's own calldata, the
    /// other a row that never knew — and the file has to keep them apart across a reload.
    #[test]
    fn a_row_round_trips_its_calldata_and_the_absence_of_it() {
        let native = TxRecord { tx_input: Some("0x".into()), ..rec("0x1") };
        let txt = serde_json::to_string(&native).unwrap();
        assert!(txt.contains(r#""txInput":"0x""#), "{txt}");
        assert_eq!(serde_json::from_str::<TxRecord>(&txt).unwrap(), native);

        let txt = serde_json::to_string(&rec("0x2")).unwrap();
        assert!(!txt.contains("txInput"), "an unknown calldata writes no key: {txt}");
        assert_eq!(serde_json::from_str::<TxRecord>(&txt).unwrap().tx_input, None);
    }

    /// What a requester stores beside a row comes back exactly as it went in, and a row
    /// with none of it writes none of it.
    #[test]
    fn a_row_round_trips_the_requesters_own_fields() {
        let full = TxRecord {
            label: "Approve USDC for Uniswap".into(),
            purpose: "Swap 1 ETH for at least 2990 USDC".into(),
            origin: "uniswap_ui".into(),
            meta: json!({ "kind": "approve", "token": "0xA0b8", "amount": "1000000" }),
            leg: 1,
            legs: 2,
            ..rec("0x3")
        };
        let txt = serde_json::to_string(&full).unwrap();
        assert_eq!(serde_json::from_str::<TxRecord>(&txt).unwrap(), full);
        assert!(txt.contains(r#""origin":"uniswap_ui""#) && txt.contains(r#""leg":1"#), "{txt}");

        let bare = serde_json::to_string(&rec("0x4")).unwrap();
        for k in ["label", "purpose", "origin", "meta"] {
            assert!(!bare.contains(&format!("\"{k}\"")), "an absent {k} writes no key: {bare}");
        }
    }

    #[test]
    fn concurrent_writers_never_lose_a_row_and_a_reader_never_sees_a_truncated_file() {
        let dir = tempfile::tempdir().unwrap();
        let h = &History::new(dir.path().to_path_buf());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        h.add(addr, TxRecord { from: addr.into(), ..rec("0xseed") });

        // `concurrency: "multi"` really does run these at once: a history read sweeps while
        // refresh_pending sweeps and a broadcast adds.
        std::thread::scope(|s| {
            for t in 0..4 {
                s.spawn(move || {
                    for i in 0..25 {
                        let hash = format!("0x{t}_{i}");
                        h.add(addr, TxRecord { from: addr.into(), ..rec(&hash) });
                    }
                });
            }
            s.spawn(move || {
                let mut seen = 1;
                for _ in 0..1500 {
                    let n = h.list(addr).len();
                    assert!(n >= seen, "the reader saw history shrink from {seen} to {n}");
                    seen = n;
                }
            });
        });
        assert_eq!(h.list(addr).len(), 101, "every add survived");
    }

    /// Two sweeps racing on the same row must settle it once and announce it once.
    #[test]
    fn two_concurrent_appliers_of_the_same_receipt_settle_it_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let h = &History::new(dir.path().to_path_buf());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        h.add(addr, TxRecord { from: addr.into(), ..rec("0xrace") });

        // Every thread holds the SAME snapshot, taken before any of them applied.
        let snapshot = &h.find(addr, "0xrace").unwrap();
        let confirmed = &json!({ "status": "0x1", "blockNumber": "0x10" });
        let announced = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| s.spawn(move || h.apply_receipt(snapshot, confirmed, 1_000)))
                .collect();
            handles
                .into_iter()
                .filter_map(|t| t.join().unwrap().expect("the write landed").then_some(()))
                .count()
        });
        assert_eq!(announced, 1, "only the applier that moved the status may emit the event");
        assert_eq!(h.find(addr, "0xrace").unwrap().status, "confirmed");
    }

    /// A snapshot taken before a row settled must not walk it backwards.
    #[test]
    fn a_stale_snapshot_cannot_undo_a_status_that_already_landed() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        h.add(addr, TxRecord { from: addr.into(), ..rec("0xstale") });
        let snapshot = h.find(addr, "0xstale").unwrap();

        assert!(h.apply_receipt(&snapshot, &json!({ "status": "0x1" }), 1_000).unwrap());
        // The same pending row, applied late: a null receipt is "not mined yet", never a
        // status, so it stamps the poll and leaves `confirmed` alone.
        assert!(!h.apply_receipt(&snapshot, &Value::Null, 2_000).unwrap());
        let row = h.find(addr, "0xstale").unwrap();
        assert_eq!((row.status.as_str(), row.last_polled_at), ("confirmed", 2_000));
    }

    #[test]
    fn a_history_file_that_cannot_be_read_is_moved_aside_not_written_over() {
        // Exactly what an older build's truncating write leaves behind on a crash.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("history").join("aaaa.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "[{\"hash\": truncated").unwrap();

        let h = History::new(dir.path().to_path_buf());
        assert!(h.list("0xaaaa").is_empty(), "unreadable reads as empty");
        h.add("0xaaaa", rec("0xnew"));

        // The module keeps recording, and the bytes it could not read still exist.
        assert_eq!(h.list("0xaaaa").len(), 1);
        let kept: Vec<_> = std::fs::read_dir(p.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
            .filter(|t| t == "[{\"hash\": truncated")
            .collect();
        assert_eq!(kept.len(), 1, "the unreadable history was deleted, not set aside");
    }

    #[test]
    fn a_write_that_never_lands_leaves_no_tmp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("aaaa.7.0.tmp");

        // Rename fails: the target is a directory. The tmp file exists by then.
        let target = dir.path().join("occupied");
        std::fs::create_dir(&target).unwrap();
        assert!(!write_then_rename(&tmp, &target, "[]"));
        assert!(!tmp.exists(), "the tmp file outlived a failed rename");

        // And the path that used to leak: the file is created, the write itself fails.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&tmp, "stale").unwrap();
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o444)).unwrap();
            assert!(!write_then_rename(&tmp, &dir.path().join("out.json"), "[]"));
            assert!(!tmp.exists(), "the tmp file outlived a failed write");
        }
    }

    #[test]
    fn a_receipt_classifies_into_exactly_the_three_statuses_the_view_can_render() {
        assert_eq!(classify_receipt(&Value::Null), "pending");
        assert_eq!(classify_receipt(&json!({})), "pending");
        assert_eq!(classify_receipt(&json!({"status": "0x1"})), "confirmed");
        assert_eq!(classify_receipt(&json!({"status": "0x0"})), "failed");
    }

    #[test]
    fn a_mined_receipt_confirms_the_row_it_belongs_to_regardless_of_the_chain_asked_about() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        h.add(addr, pending_on(1, "0xaaa"));
        h.add(addr, pending_on(11155111, "0xbbb"));
        let now = 1_000_000;

        let due = h.pending_due(addr, now, 8);
        assert_eq!(due.len(), 2, "each row carries its own chain");

        // A receipt with NO `from` must still land: the record's own `from` is the key.
        let one = due.iter().find(|r| r.chain_id == 1).unwrap();
        assert!(h.apply_receipt(one, &json!({"status": "0x1"}), now).unwrap());
        assert_eq!(h.list(addr).iter().find(|r| r.chain_id == 1).unwrap().status, "confirmed");

        // A null receipt is not an answer: still pending, and last_polled_at moved so it backs off.
        let two = due.iter().find(|r| r.chain_id == 11155111).unwrap();
        assert!(!h.apply_receipt(two, &Value::Null, now).unwrap());
        let after = h.list(addr).into_iter().find(|r| r.chain_id == 11155111).unwrap();
        assert_eq!(after.status, "pending");
        assert_eq!(after.last_polled_at, now);
        assert!(h.pending_due(addr, now + 1, 8).is_empty(), "backed off");

        // And the sweep terminates.
        assert_eq!(poll_interval_secs(4000), None);
    }

    #[test]
    fn a_row_past_the_give_up_horizon_is_stalled_and_leaves_nothing_due() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        h.add(addr, pending_on(1, "0xold"));
        let now = 999_990 + 3601;

        let old = h.find(addr, "0xold").unwrap();
        assert!(h.pending_due(addr, now, 8).is_empty(), "we stopped asking");
        assert!(!h.has_live(addr, now), "and a poll timer has nothing left to catch");
        assert!(is_stalled(&old, now));
        assert_eq!(old.status, "pending", "never a status the chain did not give us");

        // One fresh row is enough to keep the timer running.
        h.add(addr, TxRecord { timestamp: now, ..pending_on(1, "0xnew") });
        assert!(h.has_live(addr, now));
        assert!(!is_stalled(&h.find(addr, "0xnew").unwrap(), now));

        // A settled row is neither live nor stalled.
        let fresh = h.find(addr, "0xnew").unwrap();
        h.apply_receipt(&fresh, &json!({"status": "0x1"}), now).unwrap();
        let done = h.find(addr, "0xnew").unwrap();
        assert!(!is_live(&done, now) && !is_stalled(&done, now));
    }

    #[test]
    fn a_receipt_records_the_fee_the_detail_screen_shows() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        h.add(addr, TxRecord { value: "1000".into(), ..pending_on(1, "0xaaa") });

        let r = h.find(addr, "0xaaa").unwrap();
        let receipt = json!({ "status": "0x1", "blockNumber": "0x4d2",
                              "gasUsed": "0x5208", "effectiveGasPrice": "0x3b9aca00" });
        assert!(h.apply_receipt(&r, &receipt, 42).unwrap());

        let got = h.find(addr, "0xaaa").unwrap();
        assert_eq!(got.block_number, Some(1234));
        assert_eq!(got.gas_used.as_deref(), Some("21000"));
        assert_eq!(got.effective_gas_price.as_deref(), Some("1000000000"));
        assert_eq!(got.fee_wei.as_deref(), Some("21000000000000"));
        assert_eq!(got.total_wei.as_deref(), Some("21000000001000"), "value plus fee");
    }

    /// The rest of the receipt is recorded too, and neither field may touch `to`.
    #[test]
    fn a_receipt_also_records_where_the_transaction_went_and_what_moved() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        let weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
        let them = "0x0adBc7B2D1A2b7C8E9F0A1b2c3d4e5f60718D3A7";
        h.add(addr, TxRecord { from: addr.into(), to: weth.into(), kind: "call".into(),
                               value: "0".into(), ..pending_on(1, "0xaaa") });

        // Lowercase, as a node answers one.
        let topic = |a: &str| {
            format!("0x000000000000000000000000{}", a.trim_start_matches("0x").to_lowercase())
        };
        let receipt = json!({ "status": "0x1", "blockNumber": "0x4d2", "to": weth.to_lowercase(),
                              "logs": [{ "address": weth,
                                         "topics": [crate::receipt::TRANSFER_TOPIC0,
                                                    topic(addr), topic(them)],
                                         "data": format!("0x{:064x}", 1_000_000_000_000u64) }] });
        let r = h.find(addr, "0xaaa").unwrap();
        assert!(h.apply_receipt(&r, &receipt, 42).unwrap());

        let got = h.find(addr, "0xaaa").unwrap();
        assert_eq!(got.tx_to.as_deref(), Some(weth), "the receipt's own target, checksummed");
        assert_eq!(got.to, weth, "and the stored target is UNTOUCHED");
        assert_eq!(got.transfers.len(), 1);
        assert_eq!(got.transfers[0].amount, "1000000000000");
        assert_eq!(got.transfers_more, None, "nothing was dropped, so nothing is claimed");
    }

    /// A REVERTED transaction moved the fee and left the value where it was, so a `failed`
    /// row has no total — money that never moved must not be reported as having left.
    #[test]
    fn a_failed_transaction_has_no_total_because_only_its_fee_left_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        h.add(addr, TxRecord { value: "10000000000000".into(), ..pending_on(1, "0xaaa") });
        h.add(addr, TxRecord { value: "10000000000000".into(), ..pending_on(1, "0xbbb") });

        let receipt = |status: &str| json!({ "status": status, "blockNumber": "0x4d2",
                                             "gasUsed": "0x5208",
                                             "effectiveGasPrice": "0x3b9aca00" });
        let a = h.find(addr, "0xaaa").unwrap();
        assert!(h.apply_receipt(&a, &receipt("0x0"), 42).unwrap());
        let got = h.find(addr, "0xaaa").unwrap();
        assert_eq!(got.status, "failed");
        assert_eq!(got.fee_wei.as_deref(), Some("21000000000000"), "the fee still left");
        assert_eq!(got.total_wei, None, "and nothing else did, so there is no total");

        // The control, on the same numbers: it is the STATUS that decides, not the arithmetic.
        let b = h.find(addr, "0xbbb").unwrap();
        assert!(h.apply_receipt(&b, &receipt("0x1"), 42).unwrap());
        let got = h.find(addr, "0xbbb").unwrap();
        assert_eq!(got.total_wei.as_deref(), Some("31000000000000"), "value plus fee");
    }

    /// `absorb_receipt` is idempotent by design, which is what lets a re-poll BACKFILL a row
    /// that settled under a build carrying none of these fields.
    #[test]
    fn re_polling_a_settled_row_backfills_the_fields_it_was_recorded_without() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        let weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
        h.add(addr, TxRecord { from: addr.into(), ..pending_on(1, "0xaaa") });

        let bare = json!({ "status": "0x1", "blockNumber": "0x1" });
        let r = h.find(addr, "0xaaa").unwrap();
        assert!(h.apply_receipt(&r, &bare, 42).unwrap());
        assert_eq!(h.find(addr, "0xaaa").unwrap().tx_to, None);

        // The status does not change again, so `apply_receipt` answers false — and the row
        // still absorbs. A view keyed on the return value would never see the backfill.
        let full = json!({ "status": "0x1", "blockNumber": "0x1", "to": weth });
        let r = h.find(addr, "0xaaa").unwrap();
        assert!(!h.apply_receipt(&r, &full, 43).unwrap());
        assert_eq!(h.find(addr, "0xaaa").unwrap().tx_to.as_deref(), Some(weth));
    }

    #[test]
    fn a_receipt_that_omits_the_gas_price_leaves_the_fee_unknown_rather_than_zero() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        h.add(addr, TxRecord { value: "1000".into(), ..pending_on(1, "0xaaa") });
        // A call with no value: its total is the fee alone, and it is still ether.
        h.add(addr, TxRecord { kind: "call".into(), value: "0".into(), ..pending_on(1, "0xbbb") });

        let legacy = json!({ "status": "0x1", "blockNumber": "0x1", "gasUsed": "0x5208" });
        let a = h.find(addr, "0xaaa").unwrap();
        h.apply_receipt(&a, &legacy, 42).unwrap();
        let got = h.find(addr, "0xaaa").unwrap();
        assert_eq!(got.gas_used.as_deref(), Some("21000"));
        assert_eq!((got.effective_gas_price, got.fee_wei, got.total_wei), (None, None, None));

        let full = json!({ "status": "0x1", "blockNumber": "0x1",
                           "gasUsed": "0x5208", "effectiveGasPrice": "0x1" });
        let b = h.find(addr, "0xbbb").unwrap();
        h.apply_receipt(&b, &full, 42).unwrap();
        let got = h.find(addr, "0xbbb").unwrap();
        assert_eq!(got.fee_wei.as_deref(), Some("21000"), "the fee is still wei");
        assert_eq!(got.total_wei.as_deref(), Some("21000"), "a valueless call cost its fee");
    }

    /// A restarted process has no ledger and no account list — only these files — so this
    /// sweeps every one of them and answers what the last process signed at.
    #[test]
    fn the_unsettled_nonces_are_gathered_across_every_account_file() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let a = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        let b = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
        let row = |from: &str, chain: u64, hash: &str, status: &str, nonce: Option<u64>| TxRecord {
            chain_id: chain,
            from: from.into(),
            status: status.into(),
            nonce,
            ..rec(hash)
        };
        h.add(a, row(a, 1, "0xa5", "pending", Some(5)));
        h.add(a, row(a, 1, "0xa4", "confirmed", Some(4)));
        h.add(a, row(a, 11_155_111, "0xa9", "pending", Some(9)));
        h.add(a, row(a, 1, "0xold", "pending", None));
        h.add(b, row(b, 1, "0xb7", "pending", Some(7)));
        // A write that landed and whose rename did not: the row it holds is not in any
        // history file, and it is exactly the one a restart must not hand out again.
        let orphan = serde_json::to_string(&[row(b, 1, "0xb11", "pending", Some(11))]).unwrap();
        std::fs::write(dir.path().join("history/lost.1.2.tmp"), orphan).unwrap();
        // Bytes that are not a history contribute nothing rather than failing the sweep.
        std::fs::write(dir.path().join("history/aaaa.json.unreadable-1"), "not json").unwrap();

        let mut want = vec![
            (1, a.to_string(), 5),
            (11_155_111, a.to_string(), 9),
            (1, b.to_string(), 7),
            (1, b.to_string(), 11),
        ];
        want.sort();
        assert_eq!(h.unsettled_nonces(), want, "a mined row and a nonce-less row are skipped");
    }

    #[test]
    fn the_poll_schedule_backs_off_and_then_gives_up() {
        assert_eq!(poll_interval_secs(0), Some(3));
        assert_eq!(poll_interval_secs(30), Some(3));
        assert_eq!(poll_interval_secs(31), Some(15));
        assert_eq!(poll_interval_secs(300), Some(15));
        assert_eq!(poll_interval_secs(301), Some(60));
        assert_eq!(poll_interval_secs(3600), Some(60));
        assert_eq!(poll_interval_secs(3601), None);
    }

    /// The record used to be written AFTER `send_raw_transaction` returned, so the whole RPC
    /// was a window in which a crash lost a number that had already left. The intent goes
    /// down first, and a process that never comes back still leaves it behind.
    #[test]
    fn an_intent_is_on_disk_before_the_broadcast_and_outlives_the_process() {
        let dir = tempfile::tempdir().unwrap();
        let addr = "0xaaaa";
        let h = History::new(dir.path().to_path_buf());
        let intent = TxRecord { nonce: Some(5), ..rec("") };
        let proof = h.record_intent("snd_1", 0, intent).expect("the intent must land");

        // Nothing has been broadcast yet and the number is already on disk, for anyone.
        let restarted = History::new(dir.path().to_path_buf());
        assert_eq!(restarted.unsettled_nonces(), vec![(1, addr.to_string(), 5)]);
        let row = restarted.list(addr).remove(0);
        assert_eq!((row.status.as_str(), row.hash.as_str()), ("unknown", ""));
        assert!(is_unresolved(&row) && is_unsettled(&row));

        // And it is not a pending row wearing another name: there is no hash to poll, so no
        // sweep asks after it, no timer waits on it and it never becomes `stalled`.
        assert!(restarted.pending_due(addr, 1_000, 8).is_empty());
        assert!(!restarted.has_live(addr, 1_000));
        assert!(!is_live(&row, 1_000) && !is_stalled(&row, 1_000_000));
        assert!(!restarted.apply_receipt(&row, &json!({"status": "0x1"}), 1_000).unwrap());

        // The hash completes the row rather than adding one — the evidence was already there.
        assert!(h.resolve_broadcast(&proof, "0xdead", 1_000));
        assert_eq!(h.list(addr).len(), 1);
        let row = h.find(addr, "0xdead").unwrap();
        assert_eq!((row.status.as_str(), row.nonce), ("pending", Some(5)));
        assert!(is_live(&row, 1_000) && !is_unresolved(&row));
    }

    /// Two legs of one send share a request id and are two rows. An outcome for one leg
    /// must reach that leg's row alone.
    #[test]
    fn each_leg_of_a_bundle_is_its_own_row_and_takes_its_own_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let addr = "0xaaaa";
        let h = History::new(dir.path().to_path_buf());
        let leg0 = h.record_intent("snd_1", 0, TxRecord { nonce: Some(5), legs: 2, ..rec("") }).unwrap();
        let leg1 = h.record_intent("snd_1", 1, TxRecord { nonce: Some(6), legs: 2, ..rec("") }).unwrap();
        assert_eq!((leg0.leg(), leg1.leg()), (0, 1));
        assert_eq!(h.unsettled_nonces(), vec![(1, addr.to_string(), 5), (1, addr.to_string(), 6)]);

        assert!(h.resolve_broadcast(&leg1, "0xdead6", 1_000), "leg 1 lands");
        let rows = h.list(addr);
        let unknown: Vec<&TxRecord> = rows.iter().filter(|r| is_unresolved(r)).collect();
        assert_eq!(unknown.len(), 1, "leg 0 is still unresolved: {rows:?}");
        assert_eq!((unknown[0].leg, unknown[0].nonce), (0, Some(5)));
        assert_eq!(h.find(addr, "0xdead6").unwrap().leg, 1);

        assert!(h.leave_unknown(&leg0, "connection reset"));
        let rows = h.list(addr);
        let stuck = rows.iter().find(|r| r.leg == 0).unwrap();
        assert_eq!(stuck.unknown_reason.as_deref(), Some("connection reset"));
        assert_eq!(h.find(addr, "0xdead6").unwrap().unknown_reason, None, "leg 1 untouched");
    }

    /// A broadcast that fails is not a broadcast that did not happen: the node may have
    /// taken the transaction and failed to say so. The row STAYS unknown, so the next process
    /// holds the number too.
    #[test]
    fn a_broadcast_that_never_answered_keeps_its_number_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let addr = "0xaaaa";
        let h = History::new(dir.path().to_path_buf());
        let proof = h.record_intent("snd_1", 0, TxRecord { nonce: Some(5), ..rec("") }).unwrap();
        assert!(h.leave_unknown(&proof, "the node accepted the transaction but returned no hash"));

        let restarted = History::new(dir.path().to_path_buf());
        assert_eq!(restarted.unsettled_nonces(), vec![(1, addr.to_string(), 5)]);
        let row = restarted.list(addr).remove(0);
        assert_eq!(row.status, "unknown");
        assert!(row.unknown_reason.unwrap().contains("returned no hash"), "the user is told why");

        // One outcome per intent: a second cannot walk a settled row back.
        assert!(h.resolve_broadcast(&proof, "0xdead", 5));
        assert!(!h.leave_unknown(&proof, "a late error"), "the row is no longer unresolved");
        assert_eq!(h.find(addr, "0xdead").unwrap().status, "pending");
    }

    /// ONE entry an older build wrote — or one that is not a row at all — must cost that
    /// entry alone, not every nonce in the file.
    #[test]
    fn one_entry_that_does_not_parse_costs_that_entry_and_not_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("history").join("aaaa.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            r#"[{"hash":"0x5","chainId":1,"from":"0xaaaa","value":"0x1","kind":"native",
                 "status":"pending","timestamp":5,"nonce":5},
                {"hash":"0x6","chainId":1,"from":"0xaaaa","to":"0xbbbb","value":"0x1",
                 "kind":"native","status":"pending","timestamp":6,"nonce":6},
                "this is not a transaction"]"#,
        )
        .unwrap();

        let h = History::new(dir.path().to_path_buf());
        let want = vec![(1, "0xaaaa".to_string(), 5), (1, "0xaaaa".to_string(), 6)];
        assert_eq!(h.unsettled_nonces(), want, "one bad entry used to cost both numbers");
        assert_eq!(h.list("0xaaaa").len(), 2);
        assert_eq!(h.find("0xaaaa", "0x5").unwrap().to, "", "an absent field is absent, not fatal");

        // And what we could not read is not ours to delete: it survives the next write.
        assert!(h.add("0xaaaa", rec("0x7")));
        let txt = std::fs::read_to_string(&p).unwrap();
        assert!(txt.contains("this is not a transaction"), "the write dropped it: {txt}");
        assert_eq!(h.list("0xaaaa").len(), 3);
    }

    /// `add` used to give up WITHOUT writing when the file could not be read, so a broadcast
    /// was recorded nowhere and the next process handed its number out.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_account_file_does_not_swallow_the_record() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let addr = "0xaaaa";
        let h = History::new(dir.path().to_path_buf());
        assert!(h.add(addr, rec("0xold")));

        // There, and unopenable: neither absent nor corrupt, the one case worth retrying.
        let p = dir.path().join("history").join("aaaa.json");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();

        let proof = h
            .record_intent("snd_1", 0, TxRecord { nonce: Some(5), ..rec("") })
            .expect("the row must reach disk somewhere, or the send must not happen");
        assert_eq!(
            History::new(dir.path().to_path_buf()).unsettled_nonces(),
            vec![(1, addr.to_string(), 5)],
            "a restart must still see the number"
        );
        // The outcome cannot reach a row the file does not hold, and the row stays unknown —
        // the direction that keeps the number rather than losing it.
        assert!(!h.resolve_broadcast(&proof, "0xdead", 10));
        assert_eq!(h.list(addr)[0].status, "unknown");

        // Once the file reads again the stranded row is folded back in and the sidecar goes.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(h.add(addr, rec("0xlater")));
        assert!(h.orphans(addr).is_empty(), "the sidecar outlived its adoption");
        assert_eq!(h.list(addr).len(), 3);
        assert!(h.resolve_broadcast(&proof, "0xdead", 10), "and the outcome lands after all");
        assert_eq!(h.find(addr, "0xdead").unwrap().nonce, Some(5));
    }

    /// `Recorded` is the only key to the broadcast, so a row that reached neither the
    /// account file nor a sidecar has to be an `Err`.
    #[cfg(unix)]
    #[test]
    fn an_intent_that_reached_no_disk_at_all_is_refused_and_not_reported_as_written() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let hdir = dir.path().join("history");
        std::fs::create_dir_all(&hdir).unwrap();
        // Readable and listable, so `read` answers "no such file" rather than "unreadable",
        // and every write below fails: the account file and the sidecar alike.
        std::fs::set_permissions(&hdir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let h = History::new(dir.path().to_path_buf());
        assert!(!h.add("0xaaaa", rec("0xnope")), "a write that never landed is not a write");
        let e = h.record_intent("snd_1", 0, TxRecord { nonce: Some(5), ..rec("") }).unwrap_err();
        assert!(e.contains("was not sent"), "{e}");
        assert!(h.unsettled_nonces().is_empty(), "and nothing on disk claims otherwise");

        std::fs::set_permissions(&hdir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn a_settled_row_is_never_re_polled_and_the_sweep_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        for i in 0..5 {
            h.add(addr, pending_on(1, &format!("0x{i}")));
        }
        let now = 1_000_000;
        assert_eq!(h.pending_due(addr, now, 3).len(), 3, "capped at the limit");

        let confirmed = h.pending_due(addr, now, 1).remove(0);
        assert!(h.apply_receipt(&confirmed, &json!({"status": "0x1"}), now).unwrap());
        // Re-applying the same receipt is not a change, so nothing re-emits.
        assert!(!h.apply_receipt(&confirmed, &json!({"status": "0x1"}), now + 1).unwrap());
        assert_eq!(h.pending_due(addr, now + 100, 8).len(), 4);
    }
}
