//! Local transaction history — the record of the transactions THIS module broadcast, which is
//! the only history available without an indexer. One file per account under `<dir>/history/`,
//! sealed under that account's `history` key from the signer manager and named by an HMAC of
//! its address under it. An account whose key hasn't come is neither read nor written. Pure
//! Rust, unit-tested with `cargo test`.
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

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use logos_signer_interface::wallets::{self, DataKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::receipt::{self, NativeTransfer, TokenTransfer};
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
    /// "unknown" | "pending" | "confirmed" | "failed" | "replaced". `unknown` is an intent
    /// whose outcome never came back: not pending (there is no hash to poll) and not failed
    /// (the transaction may be on chain). Its nonce stays spoken for until a human resolves
    /// it. `replaced` was never mined: another transaction took its nonce.
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
    /// EIP-7708 ether-transfer logs, kept apart so the system address is never read as a token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_transfers: Vec<NativeTransfer>,
    /// Ether-transfer logs past `TRANSFERS_MAX`. Absent means the cap dropped none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_transfers_more: Option<u32>,
    /// Wei the account received in ether-transfer logs, summed over all of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_received_wei: Option<String>,
    /// The mined row that took a `replaced` row's nonce. Absent when a transaction this
    /// history does not hold took it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_by: Option<String>,
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
        let (native, more) = receipt::decode_native_transfers(receipt, &self.from);
        self.native_transfers = native;
        self.native_transfers_more = (more > 0).then_some(more);
        self.native_received_wei = receipt::native_received(receipt, &self.from);
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

/// An account as one string, `0x` and lowercase hex, whatever prefix or case the caller wrote.
pub fn account_id(address: &str) -> String {
    let a = address.trim();
    format!("0x{}", a.strip_prefix("0x").or_else(|| a.strip_prefix("0X")).unwrap_or(a).to_lowercase())
}

/// The account's file name under `key`: HMAC-SHA256 of its lowercase address, as hex.
fn file_name(key: &DataKey, address: &str) -> Option<String> {
    let raw = Zeroizing::new(hex::decode(key.key.expose().trim()).ok()?);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&raw).ok()?;
    mac.update(account_id(address).as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// A box's associated data: the file it was sealed for, so none opens under another name.
fn aad(file: &str) -> String {
    format!("history/{file}")
}

/// The file a staged write (`<file>.<pid>.<n>.tmp`) lands as; any other name is its own.
fn landing(name: &str) -> &str {
    name.find(".json").map_or(name, |i| &name[..i + ".json".len()])
}

/// One box's rows. A box of another generation is left alone rather than moved aside: it
/// opens once its own key is asked for.
fn unseal_rows(key: &DataKey, txt: &str, file: &str) -> Result<Vec<Row>, ReadFailure> {
    match wallets::generation(txt) {
        Ok(g) if g == key.generation => {}
        Ok(_) => return Err(ReadFailure::Unreadable),
        Err(_) => return Err(ReadFailure::NotHistory),
    }
    let plain = wallets::open(key, txt, &aad(file)).map_err(|_| ReadFailure::NotHistory)?;
    std::str::from_utf8(&plain).ok().and_then(parse_rows).ok_or(ReadFailure::NotHistory)
}

fn seal_rows(key: &DataKey, rows: &[impl Serialize], file: &str) -> Option<String> {
    let plain = Zeroizing::new(serde_json::to_vec(rows).ok()?);
    wallets::seal(key, &plain, &aad(file)).ok()
}

fn read_rows(key: &DataKey, p: &Path) -> Vec<Row> {
    let file = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    std::fs::read_to_string(p)
        .ok()
        .and_then(|t| unseal_rows(key, &t, landing(file)).ok())
        .unwrap_or_default()
}

const LOCKED: &str = "this account's wallet is locked: unlock it in the Signer app";

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

/// An open account: its wallet's key for this module's history, and the name it gives the file.
#[derive(Clone)]
struct Open {
    key: DataKey,
    name: String,
}

impl Open {
    fn file(&self) -> String {
        format!("{}.json", self.name)
    }
}

/// What `History::open` takes for one account: its wallet's current key, and the older ones
/// its files may still be sealed under.
pub struct AccountKeys {
    pub current: DataKey,
    pub older: Vec<DataKey>,
}

/// Why an account's history is closed: what the signer manager last answered for its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Closed {
    /// Not answered yet.
    Asking,
    /// Its wallet is locked.
    Locked,
    /// Any other refusal, in the manager's words.
    Refused(String),
}

impl Closed {
    /// The refusal a call on the account answers with.
    pub fn reply(&self) -> Value {
        let (code, error) = match self {
            Closed::Locked => ("locked", "This account's wallet is locked. Unlock it in the Signer app, then try again.".to_string()),
            Closed::Asking => ("unavailable", "This account's history isn't open yet: its key is still being asked for. Try again in a moment.".to_string()),
            Closed::Refused(why) => {
                let why = why.trim().trim_start_matches("data_key:").trim();
                // A device wallet lists its accounts only once unlocked: "no signer lists" may be that.
                ("unavailable", format!("This account's history isn't open yet ({why}). If its wallet is locked, unlock it in the Signer app, then try again."))
            }
        };
        serde_json::json!({ "ok": false, "code": code, "error": error })
    }

    /// A lock waits for the unlock to be announced; anything else is asked again at the next call.
    pub fn ask_again(&self) -> bool {
        *self != Closed::Locked
    }
}

/// Per-account history store rooted at a persistence directory.
pub struct History {
    dir: PathBuf,
    /// Serializes read-modify-write across concurrent dispatch, and holds the open accounts'
    /// keys. Process-local: the file is this module's, and the rename below is what makes
    /// another reader's view consistent.
    gate: Mutex<HashMap<String, Open>>,
    /// Accounts a caller named, so their keys are asked for too. Memory only.
    known: Mutex<BTreeSet<String>>,
    /// Why each closed account is closed, once the manager answered. Memory only.
    closed: Mutex<HashMap<String, Closed>>,
}

impl History {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            gate: Mutex::new(HashMap::new()),
            known: Mutex::new(BTreeSet::new()),
            closed: Mutex::new(HashMap::new()),
        }
    }

    fn closed(&self) -> MutexGuard<'_, HashMap<String, Closed>> {
        self.closed.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Open>> {
        self.gate.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn hdir(&self) -> PathBuf {
        self.dir.join("history")
    }

    fn at(&self, file: &str) -> PathBuf {
        self.hdir().join(file)
    }

    /// The history directory, made 0700 when it has to be made.
    fn ensure_dir(&self) -> std::io::Result<()> {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(self.hdir())
    }

    /// Where a write of `file` is staged before its rename, under a name that says which file.
    fn staged(&self, file: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        self.at(&format!("{file}.{}.{n}.tmp", std::process::id()))
    }

    /// Every file named for `name`: the account file, its sidecars, staged writes, bytes set aside.
    fn files_of(&self, name: &str) -> Vec<(PathBuf, String)> {
        let prefix = format!("{name}.");
        let Ok(entries) = std::fs::read_dir(self.hdir()) else { return Vec::new() };
        let mut out: Vec<(PathBuf, String)> = entries
            .flatten()
            .filter_map(|e| {
                let file = e.file_name().into_string().ok()?;
                file.starts_with(&prefix).then(|| (e.path(), file))
            })
            .collect();
        out.sort();
        out
    }

    /// The stored entries. An error is never "this account has no transactions": the two
    /// kinds are kept apart because only one of them is safe to recover from. Entries are
    /// parsed one at a time, because a single unparseable row used to cost the whole file —
    /// every transaction in it, and with them every nonce a restart reads back.
    fn read(&self, open: &Open) -> Result<Vec<Row>, ReadFailure> {
        let file = open.file();
        match std::fs::read_to_string(self.at(&file)) {
            Ok(txt) => unseal_rows(&open.key, &txt, &file),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(_) => Err(ReadFailure::Unreadable),
        }
    }

    /// Sidecars beside the account file, holding rows written while that file could not be
    /// read. They are ordinary history files under a name every sweep here already reads.
    fn orphans(&self, open: &Open) -> Vec<PathBuf> {
        let prefix = format!("{}.orphan-", open.name);
        self.files_of(&open.name)
            .into_iter()
            .filter(|(_, file)| file.starts_with(&prefix) && file.ends_with(".json"))
            .map(|(p, _)| p)
            .collect()
    }

    /// The account file cannot be read, so this row cannot be merged into it — and dropping
    /// it is how a broadcast ends up recorded nowhere while its nonce is handed to the next
    /// send. It goes beside the file instead, where every reader here finds it.
    fn write_orphan(&self, open: &Open, record: &TxRecord) -> bool {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let _ = self.ensure_dir();
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let file = format!("{}.orphan-{}.{n}.json", open.name, std::process::id());
        let Some(txt) = seal_rows(&open.key, &[record], &file) else { return false };
        write_then_rename(&self.staged(&file), &self.at(&file), &txt)
    }

    /// Fold stranded sidecars back into the account file now that it reads again. Answers
    /// the files to delete once the merged list has LANDED — deleting them any earlier
    /// loses exactly the rows they exist to keep.
    fn adopt_orphans(&self, open: &Open, rows: &mut Vec<Row>) -> Vec<PathBuf> {
        let files = self.orphans(open);
        for p in &files {
            rows.extend(read_rows(&open.key, p));
        }
        files
    }

    /// Move bytes that are not a history aside rather than over them. A file truncated by
    /// an older build must not wedge the module, and the user's transactions are not ours
    /// to delete — they stay next to the new file, under a name that says what happened.
    fn quarantine(&self, open: &Open) -> bool {
        let p = self.at(&open.file());
        let aside = p.with_extension(format!("json.unreadable-{}", now_secs()));
        std::fs::rename(&p, &aside).is_ok()
    }

    /// Write by rename, so a concurrent reader sees either the old file or the new one and
    /// never the truncated middle of a `write`.
    fn write(&self, open: &Open, rows: &[Row]) -> bool {
        let _ = self.ensure_dir();
        let file = open.file();
        let Some(txt) = seal_rows(&open.key, rows, &file) else { return false };
        write_then_rename(&self.staged(&file), &self.at(&file), &txt)
    }

    /// Every row for `address`, newest first: the account file plus any sidecar a write
    /// stranded beside it while the file could not be read. Legs of one send keep their
    /// order within the same second. Nothing while the account is locked.
    pub fn list(&self, address: &str) -> Vec<TxRecord> {
        let g = self.lock();
        let Some(open) = g.get(&account_id(address)) else { return Vec::new() };
        let mut rows: Vec<TxRecord> =
            self.read(open).unwrap_or_default().iter().filter_map(|r| r.rec().cloned()).collect();
        for p in self.orphans(open) {
            rows.extend(read_rows(&open.key, &p).iter().filter_map(|r| r.rec().cloned()));
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
        let g = self.lock();
        let Some(open) = g.get(&account_id(address)) else { return false };
        let mut rows = match self.read(open) {
            Ok(r) => r,
            // A transient read error may be gone next time, so the file is left alone — but
            // the ROW is not dropped: unreadable is not empty, and it is not a licence to
            // forget a transaction. It goes into a sidecar the readers here already sweep.
            Err(ReadFailure::Unreadable) => return self.write_orphan(open, &record),
            Err(ReadFailure::NotHistory) if self.quarantine(open) => Vec::new(),
            Err(ReadFailure::NotHistory) => return false,
        };
        let adopted = self.adopt_orphans(open, &mut rows);
        rows.insert(0, Row::Rec(record));
        self.landed(open, &rows, adopted)
    }

    /// Write the merged list and, only once it is there, drop the sidecars it absorbed.
    fn landed(&self, open: &Open, rows: &[Row], adopted: Vec<PathBuf>) -> bool {
        let ok = self.write(open, rows);
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
        let g = self.lock();
        let Some(open) = g.get(&account_id(address)) else { return Wrote::Failed };
        let Ok(mut rows) = self.read(open) else { return Wrote::Failed };
        let adopted = self.adopt_orphans(open, &mut rows);
        let mut touched = false;
        for r in rows.iter_mut() {
            if let Row::Rec(rec) = r {
                touched |= f(rec);
            }
        }
        if !touched {
            return Wrote::Untouched;
        }
        if self.landed(open, &rows, adopted) {
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
        if !self.is_open(&address) {
            return Err(format!("{LOCKED}, so this transaction was not sent"));
        }
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

    /// Every (chain, account, nonce) an UNSETTLED row of `address` was signed at — pending
    /// ones, and intents whose outcome never came back — in EVERY file its keys name. A `.tmp`
    /// a crashed rename left behind, or a sidecar, can hold the very row the account file is
    /// missing, and a number not seeded is a collision. Read before the account opens.
    pub fn unsettled_nonces(&self, address: &str, keys: &AccountKeys) -> Vec<(u64, String, u64)> {
        let g = self.lock();
        let mut out = Vec::new();
        for key in Self::keys_for(&g, address, keys) {
            let Some(name) = file_name(&key, address) else { continue };
            for (p, file) in self.files_of(&name) {
                if file.contains(".unreadable-") {
                    continue;
                }
                let rows = read_rows(&key, &p);
                let due = rows.iter().filter_map(Row::rec).filter(|r| is_unsettled(r));
                out.extend(due.filter_map(|r| Some((r.chain_id, r.from.clone(), r.nonce?))));
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// The keys an account's files may be sealed under, newest first: `keys`, and the one it
    /// is open under now.
    fn keys_for(open: &HashMap<String, Open>, address: &str, keys: &AccountKeys) -> Vec<DataKey> {
        let mut out = vec![keys.current.clone()];
        out.extend(keys.older.iter().cloned());
        out.extend(open.get(&account_id(address)).map(|o| o.key.clone()));
        out.sort_by(|a, b| b.generation.cmp(&a.generation));
        out.dedup_by_key(|k| k.generation);
        out
    }

    /// The generations below `current` a box here was sealed at, but the one `address` is open
    /// under. No name says whose a box is, so `open` needs each one's key to find its files.
    pub fn wanted(&self, address: &str, current: &DataKey) -> Vec<u32> {
        let g = self.lock();
        let held = g.get(&account_id(address)).map(|o| o.key.generation);
        let Ok(entries) = std::fs::read_dir(self.hdir()) else { return Vec::new() };
        let mut out: Vec<u32> = entries
            .flatten()
            .filter(|e| !e.file_name().to_string_lossy().contains(".unreadable-"))
            .filter_map(|e| wallets::generation(&std::fs::read_to_string(e.path()).ok()?).ok())
            .filter(|n| *n < current.generation && Some(*n) != held)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Open `address` under its wallet's current key. Files an older key named are sealed
    /// again under the current one and its name; if one can't be, the account stays closed.
    pub fn open(&self, address: &str, keys: AccountKeys) -> Result<(), String> {
        let mut g = self.lock();
        let id = account_id(address);
        let name = file_name(&keys.current, address).ok_or("the history key is not 32 bytes of hex")?;
        self.ensure_dir().map_err(|e| format!("the history directory: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(self.hdir(), std::fs::Permissions::from_mode(0o700));
        }
        let older = Self::keys_for(&g, address, &keys);
        for key in older.iter().filter(|k| k.generation != keys.current.generation) {
            let Some(old) = file_name(key, address) else { continue };
            for (p, file) in self.files_of(&old) {
                let target = format!("{name}{}", &file[old.len()..]);
                if let Err(e) = self.migrate(key, &keys.current, &p, &file, &target) {
                    // Some files may have moved: the old name no longer holds the whole history.
                    g.remove(&id);
                    return Err(e);
                }
            }
        }
        self.closed().remove(&id);
        g.insert(id, Open { key: keys.current, name });
        Ok(())
    }

    /// What the manager answered for a closed account's key.
    pub fn refused(&self, address: &str, why: Closed) {
        self.closed().insert(account_id(address), why);
    }

    /// Why `address` is closed; `Asking` until the manager answered.
    pub fn why_closed(&self, address: &str) -> Closed {
        self.closed().get(&account_id(address)).cloned().unwrap_or(Closed::Asking)
    }

    /// One file an older key named, sealed again under `to` as `target`. A target already
    /// there is a move that landed before a crash, so only the source goes.
    fn migrate(&self, from: &DataKey, to: &DataKey, p: &Path, file: &str, target: &str) -> Result<(), String> {
        let fail = |e: std::io::Error| format!("history/{file}: {e}");
        let dest = self.at(target);
        if dest.exists() {
            return std::fs::remove_file(p).map_err(fail);
        }
        if file.contains(".unreadable-") {
            return std::fs::rename(p, &dest).map_err(fail);
        }
        let txt = std::fs::read_to_string(p).map_err(fail)?;
        let Ok(plain) = wallets::open(from, &txt, &aad(landing(file))) else {
            // Bytes the old key doesn't open are set aside under the new name, not dropped.
            let aside = self.at(&format!("{target}.unreadable-{}", now_secs()));
            return std::fs::rename(p, aside).map_err(fail);
        };
        let boxed = wallets::seal(to, &plain, &aad(landing(target))).map_err(|e| e.to_string())?;
        if !write_then_rename(&self.staged(target), &dest, &boxed) {
            return Err(format!("history/{target} could not be written"));
        }
        std::fs::remove_file(p).map_err(fail)
    }

    /// Forget an account's key: its history is neither read nor written until it opens again.
    pub fn close(&self, address: &str) -> bool {
        self.lock().remove(&account_id(address)).is_some()
    }

    /// Forget every key, as a lock of the wallets asks. Answers the accounts that closed.
    pub fn close_all(&self) -> Vec<String> {
        let ids: Vec<String> = self.lock().drain().map(|(id, _)| id).collect();
        self.closed().extend(ids.iter().map(|id| (id.clone(), Closed::Locked)));
        ids
    }

    pub fn is_open(&self, address: &str) -> bool {
        self.lock().contains_key(&account_id(address))
    }

    /// The generation of the key `address` is open under.
    pub fn generation(&self, address: &str) -> Option<u32> {
        self.lock().get(&account_id(address)).map(|o| o.key.generation)
    }

    /// The account file, while the account is open.
    pub fn file(&self, address: &str) -> Option<PathBuf> {
        self.lock().get(&account_id(address)).map(|o| self.at(&o.file()))
    }

    /// Remember an account a caller named, to ask its key for. True the first time.
    pub fn note(&self, address: &str) -> bool {
        self.known.lock().unwrap_or_else(|e| e.into_inner()).insert(account_id(address))
    }

    pub fn known(&self) -> Vec<String> {
        self.known.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
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

impl History {
    /// Settle as `replaced` every pending row of `address` whose nonce a mined row of the
    /// same chain holds: that number is spent, so the row can never be mined. Local; returns
    /// the hashes that moved and reached disk. A row an earlier chain read settled with no
    /// winner is given its name here.
    pub fn settle_superseded(&self, address: &str) -> Result<Vec<String>, String> {
        let mined: HashMap<(u64, u64), String> = self.list(address).into_iter()
            .filter(|r| r.status == "confirmed" || r.status == "failed")
            .filter_map(|r| Some(((r.chain_id, r.nonce?), r.hash)))
            .collect();
        if mined.is_empty() {
            return Ok(Vec::new());
        }
        let mut moved = Vec::new();
        let wrote = self.edit(address, |r| {
            let Some(winner) = r.nonce.and_then(|n| mined.get(&(r.chain_id, n))) else { return false };
            let settle = r.status == "pending" && !r.hash.eq_ignore_ascii_case(winner);
            let name = r.status == "replaced" && r.replaced_by.is_none();
            if settle {
                moved.push(r.hash.clone());
            }
            if settle || name {
                r.status = "replaced".into();
                r.replaced_by = Some(winner.clone());
            }
            settle || name
        });
        match wrote {
            Wrote::Failed => Err(format!("{} replaced rows could not be written", moved.len())),
            _ => Ok(moved),
        }
    }

    /// Settle one pending row as `replaced` by a transaction this history does not hold: the
    /// chain mined past its nonce while its own receipt is still missing. Stamps the poll.
    pub fn settle_replaced(&self, record: &TxRecord, now: u64) -> Result<bool, String> {
        let mut changed = false;
        let wrote = self.edit(&record.from, |r| {
            if !r.hash.eq_ignore_ascii_case(&record.hash) || r.status != "pending" {
                return false;
            }
            r.last_polled_at = now;
            r.status = "replaced".into();
            changed = true;
            true
        });
        match wrote {
            Wrote::Failed => Err(format!("{} could not be settled as replaced", record.hash)),
            _ => Ok(changed),
        }
    }
}

/// Write `txt` to `tmp`, 0600 from creation, then move it onto `p`. Cleans up on EITHER
/// failure: a write that fails after creating the file leaves one behind, and those
/// accumulate forever.
pub(crate) fn write_then_rename(tmp: &Path, p: &Path, txt: &str) -> bool {
    let ok = write_private(tmp, txt.as_bytes()).is_ok() && std::fs::rename(tmp, p).is_ok();
    if !ok {
        let _ = std::fs::remove_file(tmp);
    }
    ok
}

fn write_private(p: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(p)?.write_all(bytes)
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

    const ACCOUNTS: [&str; 3] = [
        "0xaaaa",
        "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266",
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    ];

    fn key(byte: u8, generation: u32) -> DataKey {
        DataKey { key: logos_signer_interface::Secret::new(hex::encode([byte; 32])), generation }
    }

    fn keys(current: &DataKey) -> AccountKeys {
        AccountKeys { current: current.clone(), older: Vec::new() }
    }

    /// A store over `dir` with every account these tests use open under the test key.
    fn store(dir: &Path) -> History {
        let h = History::new(dir.to_path_buf());
        for a in ACCOUNTS {
            h.open(a, keys(&key(1, 0))).unwrap();
        }
        h
    }

    /// What a restart seeds for `addr`, under the test key.
    fn carried(h: &History, addr: &str) -> Vec<(u64, String, u64)> {
        h.unsettled_nonces(addr, &keys(&key(1, 0)))
    }

    /// `plain` sealed as `addr`'s account file under the test key, as an earlier write left it.
    fn plant(dir: &Path, addr: &str, plain: &str) -> PathBuf {
        let file = format!("{}.json", file_name(&key(1, 0), addr).unwrap());
        let p = dir.join("history").join(&file);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, wallets::seal(&key(1, 0), plain.as_bytes(), &aad(&file)).unwrap()).unwrap();
        p
    }

    fn unseal(p: &Path, k: &DataKey) -> String {
        let file = p.file_name().unwrap().to_str().unwrap();
        let txt = std::fs::read_to_string(p).unwrap();
        String::from_utf8(wallets::open(k, &txt, &aad(landing(file))).unwrap().to_vec()).unwrap()
    }

    /// Every file in the history directory, by name.
    fn files(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        std::fs::read_dir(dir.join("history"))
            .unwrap()
            .flatten()
            .map(|e| (e.file_name().into_string().unwrap(), std::fs::read(e.path()).unwrap()))
            .collect()
    }

    /// A receipt the store REFUSED is not a settle: a read-only or full history directory
    /// must not report a confirmation the file never took.
    #[test]
    fn a_receipt_the_store_refused_is_not_a_change() {
        let dir = tempfile::tempdir().unwrap();
        let h = store(dir.path());
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
        let h = store(dir.path());
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
        let h2 = store(dir.path());
        assert_eq!(h2.find(addr, "0xdead").unwrap().status, "confirmed");

        // address key is normalized: stored under 0x-checksummed, found via bare hex
        let bare = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        assert_eq!(h2.list(bare).len(), 2);
    }

    #[test]
    fn a_history_file_written_before_the_optional_fields_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        plant(
            dir.path(),
            "0xaaaa",
            r#"[{"hash":"0x1","chainId":1,"from":"0xaaaa","to":"0xbbbb","value":"0x1",
                 "kind":"erc20","status":"pending","timestamp":5}]"#,
        );
        let h = store(dir.path());
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
        let h = &store(dir.path());
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
        let h = &store(dir.path());
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
        let h = store(dir.path());
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
        // Exactly what an older build's truncating write leaves behind on a crash, in a box;
        // and, for the other account, bytes that are no box at all.
        let dir = tempfile::tempdir().unwrap();
        let truncated = std::fs::read_to_string(plant(dir.path(), "0xaaaa", "[{\"hash\": truncated")).unwrap();
        let b = ACCOUNTS[1];
        std::fs::write(plant(dir.path(), b, "[]"), "not a box").unwrap();

        let h = store(dir.path());
        for (addr, bytes) in [("0xaaaa", truncated.as_str()), (b, "not a box")] {
            assert!(h.list(addr).is_empty(), "unreadable reads as empty");
            h.add(addr, TxRecord { from: addr.into(), ..rec("0xnew") });

            // The module keeps recording, and the bytes it could not read still exist.
            assert_eq!(h.list(addr).len(), 1);
            let kept = files(dir.path()).into_values().filter(|t| t == bytes.as_bytes()).count();
            assert_eq!(kept, 1, "the unreadable history was deleted, not set aside");
        }
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
    fn a_row_whose_nonce_a_mined_row_holds_is_replaced_by_it() {
        let dir = tempfile::tempdir().unwrap();
        let h = store(dir.path());
        let a = "0xaaaa";
        let at = |hash: &str, chain: u64, nonce: u64, status: &str| TxRecord {
            chain_id: chain, nonce: Some(nonce), status: status.into(), ..rec(hash)
        };
        h.add(a, at("0x40a", 1, 40, "pending"));
        h.add(a, at("0x40b", 1, 40, "confirmed"));
        h.add(a, at("0x41", 1, 41, "pending"));
        h.add(a, at("0x40op", 10, 40, "pending"));
        h.add(a, at("0x39", 1, 39, "replaced"));
        h.add(a, at("0x39b", 1, 39, "failed"));

        assert_eq!(h.settle_superseded(a).unwrap(), ["0x40a"]);
        let row = |hash: &str| h.find(a, hash).unwrap();
        assert_eq!((row("0x40a").status.as_str(), row("0x40a").replaced_by.as_deref()), ("replaced", Some("0x40b")));
        assert_eq!(row("0x40b").status, "confirmed", "the winner is untouched");
        assert_eq!(row("0x41").status, "pending", "a later number is not spent");
        assert_eq!(row("0x40op").status, "pending", "nonce 40 on another chain is another number");
        assert_eq!(row("0x39").replaced_by.as_deref(), Some("0x39b"), "a failed row spent it too, and is named");
        assert!(h.settle_superseded(a).unwrap().is_empty(), "idempotent");
    }

    #[test]
    fn a_row_the_chain_mined_past_is_replaced_by_nobody_it_holds() {
        let dir = tempfile::tempdir().unwrap();
        let h = store(dir.path());
        h.add("0xaaaa", TxRecord { nonce: Some(7), ..rec("0x07") });
        let row = h.find("0xaaaa", "0x07").unwrap();
        assert!(h.settle_replaced(&row, 500).unwrap());
        let after = h.find("0xaaaa", "0x07").unwrap();
        assert_eq!((after.status.as_str(), after.replaced_by.as_deref(), after.last_polled_at), ("replaced", None, 500));
        assert!(!h.settle_replaced(&row, 600).unwrap(), "a settled row stays as it is");
        assert!(!is_unsettled(&after) && !is_live(&after, 500) && !is_stalled(&after, 99_999));
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
        let h = store(dir.path());
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
        let h = store(dir.path());
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
        let h = store(dir.path());
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
        let h = store(dir.path());
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

    /// EIP-7708: the system address's Transfer logs are ether. They land in their own list,
    /// never among the tokens, and what came back to the account is totalled.
    #[test]
    fn a_receipt_s_ether_transfers_are_stored_apart_from_its_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let h = store(dir.path());
        let addr = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        let weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
        let router = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45";
        h.add(addr, TxRecord { from: addr.into(), to: router.into(), kind: "call".into(),
                               value: "0".into(), ..pending_on(1, "0xaaa") });

        let topic = |a: &str| {
            format!("0x000000000000000000000000{}", a.trim_start_matches("0x").to_lowercase())
        };
        let log = |emitter: &str, from: &str, to: &str, amount: u64| {
            json!({ "address": emitter,
                    "topics": [crate::receipt::TRANSFER_TOPIC0, topic(from), topic(to)],
                    "data": format!("0x{amount:064x}") })
        };
        let system = crate::receipt::SYSTEM_ADDRESS;
        let receipt = json!({ "status": "0x1", "blockNumber": "0x4d2", "to": router,
                              "logs": [log(weth, addr, router, 7),
                                       log(system, weth, router, 5),
                                       log(system, router, addr, 5)] });
        let r = h.find(addr, "0xaaa").unwrap();
        assert!(h.apply_receipt(&r, &receipt, 42).unwrap());

        let got = h.find(addr, "0xaaa").unwrap();
        assert_eq!(got.transfers.len(), 1, "one token moved: {:?}", got.transfers);
        assert_eq!(got.transfers[0].contract, weth);
        assert_eq!(got.native_transfers.len(), 2);
        let back = &got.native_transfers[0];
        assert_eq!((back.from.clone(), back.to.clone()),
                   (router.to_string(), crate::receipt::checksummed(addr)),
                   "what came back to the account sorts first");
        assert_eq!(got.native_transfers_more, None);
        assert_eq!(got.native_received_wei.as_deref(), Some("5"));
    }

    /// The new fields are optional on disk: a row written before them loads, and a row with
    /// no ether logs writes no key for them.
    #[test]
    fn a_row_round_trips_its_ether_transfers_and_an_older_row_loads_without_them() {
        let row = TxRecord {
            native_transfers: vec![NativeTransfer { from: "0xaaaa".into(), to: "0xbbbb".into(),
                                                    amount: "5".into() }],
            native_transfers_more: Some(2),
            native_received_wei: Some("5".into()),
            ..rec("0x5")
        };
        let txt = serde_json::to_string(&row).unwrap();
        let list = r#""nativeTransfers":[{"from":"0xaaaa","to":"0xbbbb","amount":"5"}]"#;
        assert!(txt.contains(list), "{txt}");
        assert!(txt.contains(r#""nativeTransfersMore":2"#), "{txt}");
        assert!(txt.contains(r#""nativeReceivedWei":"5""#), "{txt}");
        assert_eq!(serde_json::from_str::<TxRecord>(&txt).unwrap(), row);

        let bare = serde_json::to_string(&rec("0x6")).unwrap();
        for k in ["nativeTransfers", "nativeTransfersMore", "nativeReceivedWei"] {
            assert!(!bare.contains(k), "an absent {k} writes no key: {bare}");
        }
        let old: TxRecord = serde_json::from_str(r#"{"hash":"0x7","chainId":1,"from":"0xaaaa",
            "to":"0xbbbb","value":"1","kind":"native","status":"confirmed","timestamp":1,
            "transfers":[{"contract":"0xcc","from":"0xaaaa","to":"0xbbbb","amount":"1"}]}"#)
            .unwrap();
        assert_eq!((old.native_transfers.len(), old.native_received_wei), (0, None));
        assert_eq!(old.transfers.len(), 1);
    }

    /// A REVERTED transaction moved the fee and left the value where it was, so a `failed`
    /// row has no total — money that never moved must not be reported as having left.
    #[test]
    fn a_failed_transaction_has_no_total_because_only_its_fee_left_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let h = store(dir.path());
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
        let h = store(dir.path());
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
        let h = store(dir.path());
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

    /// A restarted process has no ledger — only these files — so this sweeps every file an
    /// account's key names and answers what the last process signed at.
    #[test]
    fn the_unsettled_nonces_are_gathered_across_every_file_of_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let h = store(dir.path());
        let a = "0xF39fd6E51Aad88f6f4CE6Ab8827279cFFfB92266";
        let b = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
        let name = |addr: &str| file_name(&key(1, 0), addr).unwrap();
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
        let staged = format!("{}.json.1.2.tmp", name(b));
        let lost = [row(b, 1, "0xb11", "pending", Some(11))];
        std::fs::write(h.at(&staged), seal_rows(&key(1, 0), &lost, landing(&staged)).unwrap()).unwrap();
        // Bytes that are not a history contribute nothing rather than failing the sweep.
        std::fs::write(h.at(&format!("{}.json.unreadable-1", name(a))), "not json").unwrap();

        let mut want = vec![(1, a.to_string(), 5), (11_155_111, a.to_string(), 9)];
        want.sort();
        assert_eq!(carried(&h, a), want, "a mined row and a nonce-less row are skipped");
        assert_eq!(carried(&h, b), vec![(1, b.to_string(), 7), (1, b.to_string(), 11)]);
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
        let h = store(dir.path());
        let intent = TxRecord { nonce: Some(5), ..rec("") };
        let proof = h.record_intent("snd_1", 0, intent).expect("the intent must land");

        // Nothing has been broadcast yet and the number is already on disk, for anyone.
        let restarted = store(dir.path());
        assert_eq!(carried(&restarted, addr), vec![(1, addr.to_string(), 5)]);
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
        let h = store(dir.path());
        let leg0 = h.record_intent("snd_1", 0, TxRecord { nonce: Some(5), legs: 2, ..rec("") }).unwrap();
        let leg1 = h.record_intent("snd_1", 1, TxRecord { nonce: Some(6), legs: 2, ..rec("") }).unwrap();
        assert_eq!((leg0.leg(), leg1.leg()), (0, 1));
        assert_eq!(carried(&h, addr), vec![(1, addr.to_string(), 5), (1, addr.to_string(), 6)]);

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
        let h = store(dir.path());
        let proof = h.record_intent("snd_1", 0, TxRecord { nonce: Some(5), ..rec("") }).unwrap();
        assert!(h.leave_unknown(&proof, "the node accepted the transaction but returned no hash"));

        let restarted = store(dir.path());
        assert_eq!(carried(&restarted, addr), vec![(1, addr.to_string(), 5)]);
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
        let p = plant(
            dir.path(),
            "0xaaaa",
            r#"[{"hash":"0x5","chainId":1,"from":"0xaaaa","value":"0x1","kind":"native",
                 "status":"pending","timestamp":5,"nonce":5},
                {"hash":"0x6","chainId":1,"from":"0xaaaa","to":"0xbbbb","value":"0x1",
                 "kind":"native","status":"pending","timestamp":6,"nonce":6},
                "this is not a transaction"]"#,
        );

        let h = store(dir.path());
        let want = vec![(1, "0xaaaa".to_string(), 5), (1, "0xaaaa".to_string(), 6)];
        assert_eq!(carried(&h, "0xaaaa"), want, "one bad entry used to cost both numbers");
        assert_eq!(h.list("0xaaaa").len(), 2);
        assert_eq!(h.find("0xaaaa", "0x5").unwrap().to, "", "an absent field is absent, not fatal");

        // And what we could not read is not ours to delete: it survives the next write.
        assert!(h.add("0xaaaa", rec("0x7")));
        let txt = unseal(&p, &key(1, 0));
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
        let h = store(dir.path());
        assert!(h.add(addr, rec("0xold")));

        // There, and unopenable: neither absent nor corrupt, the one case worth retrying.
        let p = h.file(addr).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();

        let proof = h
            .record_intent("snd_1", 0, TxRecord { nonce: Some(5), ..rec("") })
            .expect("the row must reach disk somewhere, or the send must not happen");
        assert_eq!(
            carried(&History::new(dir.path().to_path_buf()), addr),
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
        assert!(h.orphans(&h.lock()[&account_id(addr)]).is_empty(), "the sidecar outlived its adoption");
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
        let h = store(dir.path());
        // Readable and listable, so `read` answers "no such file" rather than "unreadable",
        // and every write below fails: the account file and the sidecar alike.
        std::fs::set_permissions(&hdir, std::fs::Permissions::from_mode(0o555)).unwrap();

        assert!(!h.add("0xaaaa", rec("0xnope")), "a write that never landed is not a write");
        let e = h.record_intent("snd_1", 0, TxRecord { nonce: Some(5), ..rec("") }).unwrap_err();
        assert!(e.contains("was not sent"), "{e}");
        assert!(carried(&h, "0xaaaa").is_empty(), "and nothing on disk claims otherwise");

        std::fs::set_permissions(&hdir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn a_settled_row_is_never_re_polled_and_the_sweep_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let h = store(dir.path());
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

    /// Until its wallet's key comes, an account's history is not read and nothing is written
    /// for it, the intent a send needs included.
    #[test]
    fn a_locked_account_is_neither_read_nor_written() {
        let dir = tempfile::tempdir().unwrap();
        let addr = "0xaaaa";
        assert!(store(dir.path()).add(addr, TxRecord { nonce: Some(5), ..rec("0x1") }));
        let before = files(dir.path());

        let h = History::new(dir.path().to_path_buf());
        assert!(!h.is_open(addr));
        assert!(h.list(addr).is_empty() && h.find(addr, "0x1").is_none(), "nothing is read");
        assert!(!h.add(addr, rec("0x2")), "nothing is written");
        let e = h.record_intent("snd_1", 0, TxRecord { nonce: Some(6), ..rec("") }).unwrap_err();
        assert!(e.contains("locked") && e.contains("Signer app") && e.contains("not sent"), "{e}");
        assert!(h.apply_receipt(&rec("0x1"), &json!({"status": "0x1"}), 9).is_err());
        assert!(h.settle_superseded(addr).unwrap().is_empty());
        assert_eq!(files(dir.path()), before, "the directory is as it was");

        h.open(addr, keys(&key(1, 0))).unwrap();
        assert_eq!(h.list(addr)[0].hash, "0x1", "its key opens it, and the row was there all along");
        assert_eq!(h.close_all(), vec![account_id(addr)]);
        assert!(h.list(addr).is_empty() && !h.add(addr, rec("0x3")), "and a lock closes it again");
    }

    /// Only the manager's `locked` reads as a locked wallet; any other refusal says what the
    /// manager said and is asked again.
    #[test]
    fn a_closed_account_says_why_it_is_closed() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::new(dir.path().to_path_buf());
        let addr = "0x8FD7aaaa";
        assert_eq!(h.why_closed(addr), Closed::Asking);
        h.refused(addr, Closed::Refused("data_key: this account's wallet isn't known yet".into()));
        let why = h.why_closed(&addr.to_lowercase());
        let r = why.reply();
        assert_eq!(r["code"], "unavailable");
        assert_eq!(r["error"], "This account's history isn't open yet (this account's wallet isn't known yet). If its wallet is locked, unlock it in the Signer app, then try again.");
        assert!(why.ask_again() && Closed::Asking.ask_again());
        assert!(!Closed::Asking.reply()["error"].as_str().unwrap().contains("locked"));

        h.open(addr, keys(&key(1, 0))).unwrap();
        assert_eq!(h.why_closed(addr), Closed::Asking, "opening forgets the refusal");
        h.close_all();
        let locked = h.why_closed(addr);
        assert_eq!(locked, Closed::Locked, "a lock of the wallets is a lock");
        assert_eq!(locked.reply()["code"], "locked");
        assert!(locked.reply()["error"].as_str().unwrap().contains("Signer app"));
        assert!(!locked.ask_again(), "the unlock is announced");
    }

    /// The name is the key's, and so is the box: another key finds nothing, and a box moved
    /// under another account's name doesn't open there.
    #[test]
    fn a_reopened_store_reads_only_with_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = ("0xaaaa", ACCOUNTS[1]);
        let h = store(dir.path());
        assert!(h.add(a, rec("0x1")));
        let theirs = h.file(b).unwrap();
        std::fs::copy(h.file(a).unwrap(), &theirs).unwrap();
        assert!(h.list(b).is_empty(), "a's box under b's name doesn't open");

        let other = History::new(dir.path().to_path_buf());
        other.open(a, keys(&key(2, 0))).unwrap();
        assert!(other.list(a).is_empty(), "another key names another file and opens nothing");
        assert!(other.unsettled_nonces(a, &keys(&key(2, 0))).is_empty());

        let right = History::new(dir.path().to_path_buf());
        right.open(a, keys(&key(1, 0))).unwrap();
        assert_eq!(right.list(a)[0].hash, "0x1");
    }

    /// No file says whose rows it holds: not by its name, and not in its bytes. Files are 0600
    /// in a 0700 directory.
    #[test]
    fn the_history_directory_holds_no_address_in_any_name_or_content() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (ACCOUNTS[1], ACCOUNTS[2]);
        let h = store(dir.path());
        let intent = TxRecord { from: a.into(), to: b.into(), nonce: Some(5), ..rec("") };
        let proof = h.record_intent("snd_1", 0, intent).unwrap();
        assert!(h.resolve_broadcast(&proof, "0xdead", 10));
        assert!(h.add(b, TxRecord { from: b.into(), to: a.into(), ..rec("0xb1") }));
        #[cfg(unix)]
        {
            // A sidecar too, written while the account file couldn't be read.
            use std::os::unix::fs::PermissionsExt;
            let p = h.file(a).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
            assert!(h.add(a, TxRecord { from: a.into(), ..rec("0xa2") }));
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let all = files(dir.path());
        assert!(all.len() >= 2, "{:?}", all.keys());
        for (name, bytes) in &all {
            let (name, txt) = (name.to_lowercase(), String::from_utf8_lossy(bytes).to_lowercase());
            for addr in [a, b, "0xbbbb"] {
                let bare = addr.trim_start_matches("0x").to_lowercase();
                assert!(!name.contains(&bare), "{name} names {addr}");
                assert!(!txt.contains(&bare), "{name} holds {addr}");
            }
            assert!(name.len() >= 32 + ".json".len() && name.ends_with(".json"), "{name}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir.path().join("history")), 0o700);
            for name in all.keys() {
                assert_eq!(mode(&dir.path().join("history").join(name)), 0o600, "{name}");
            }
        }
    }

    /// A key change renames the file and seals it again: the box's own generation is asked
    /// for, its number is carried over, and from then on the current key alone opens it.
    #[test]
    fn a_new_key_generation_seals_the_history_again_under_it() {
        let dir = tempfile::tempdir().unwrap();
        let (addr, other) = (ACCOUNTS[1], ACCOUNTS[2]);
        let (k0, k1) = (key(1, 0), key(7, 1));
        let h = store(dir.path());
        h.record_intent("snd_1", 0, TxRecord { from: addr.into(), nonce: Some(5), ..rec("") }).unwrap();
        assert!(h.add(other, TxRecord { from: other.into(), ..rec("0xo") }));
        let (old, theirs) = (h.file(addr).unwrap(), h.file(other).unwrap());

        let next = History::new(dir.path().to_path_buf());
        assert_eq!(next.wanted(addr, &k1), vec![0], "the box's generation is the key to ask for");
        let both = || AccountKeys { current: k1.clone(), older: vec![k0.clone()] };
        assert_eq!(next.unsettled_nonces(addr, &both()), vec![(1, addr.to_string(), 5)]);
        next.open(addr, both()).unwrap();
        let new = next.file(addr).unwrap();
        assert!(new != old && !old.exists(), "the name moves with the key");
        let txt = std::fs::read_to_string(&new).unwrap();
        assert_eq!(wallets::generation(&txt).unwrap(), 1, "sealed again under the current one");
        assert_eq!(next.list(addr)[0].nonce, Some(5));
        assert!(theirs.exists(), "another account's box is left where it is");

        let later = History::new(dir.path().to_path_buf());
        later.open(addr, keys(&k1)).unwrap();
        assert_eq!(later.generation(addr), Some(1));
        assert_eq!(later.list(addr)[0].nonce, Some(5));
    }

    /// An account open while its key changes moves its files with the key it already holds.
    #[test]
    fn an_open_account_moves_to_a_new_key_with_the_one_it_holds() {
        let dir = tempfile::tempdir().unwrap();
        let addr = "0xaaaa";
        let h = store(dir.path());
        assert!(h.add(addr, rec("0x1")));
        let old = h.file(addr).unwrap();

        assert!(h.wanted(addr, &key(7, 1)).is_empty(), "the key it holds is the one its files need");
        h.open(addr, keys(&key(7, 1))).unwrap();
        assert!(!old.exists());
        assert_eq!((h.list(addr).len(), h.generation(addr)), (1, Some(1)));
    }

    /// A crash after a moved file landed and before the old one went leaves both. The next
    /// open takes the moved one and drops the copy rather than reading the rows twice.
    #[test]
    fn a_move_that_landed_before_a_crash_is_not_made_twice() {
        let dir = tempfile::tempdir().unwrap();
        let addr = "0xaaaa";
        let (k0, k1) = (key(1, 0), key(7, 1));
        let h = store(dir.path());
        assert!(h.add(addr, rec("0x1")));
        let old = h.file(addr).unwrap();
        let saved = std::fs::read(&old).unwrap();
        h.open(addr, keys(&k1)).unwrap();
        std::fs::write(&old, saved).unwrap();

        let next = History::new(dir.path().to_path_buf());
        next.open(addr, AccountKeys { current: k1, older: vec![k0] }).unwrap();
        assert!(!old.exists());
        assert_eq!(next.list(addr).len(), 1, "one row, not two");
    }
}
