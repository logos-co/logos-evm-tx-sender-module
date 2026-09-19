//! A source-shape guard on `glue.rs`: no outbound call is made under a lock, every call is
//! bounded or argued for, the record goes down before the bytes leave, and the broadcast
//! settles through its ticket.
//!
//! `glue.rs` is behind the `logos_module` feature and `--no-default-features` cannot compile
//! it, so it is read as text. That is a BUILD constraint and not a law. Two rules keep these
//! honest:
//!
//! 1. A `contains` over a region asserts that SOME line in the region matches; the property
//!    is about the line on ONE path. Every check below pins the site, not the vocabulary.
//! 2. Every check ships with the mutant it is meant to kill, and the mutant test asserts the
//!    check REJECTS it — so the check's discriminating power is itself under test.
//!
//! Sections 6 and 7 read `send.rs`, which IS compiled here. Its behaviour is asserted in its
//! own module; what is read as text is the SHAPE the compiler has no opinion about — which
//! function a rule is installed in, and how many there are.

use std::collections::BTreeSet;

const GLUE: &str = include_str!("../src/glue.rs");
const SEND: &str = include_str!("../src/send.rs");

/// The file with comments and string literals blanked out, byte offsets preserved. Brace
/// counting and call-site scanning must not be fooled by a `{` inside a `json!` string.
fn code_only(src: &str) -> String {
    let mut out: Vec<u8> = src.as_bytes().to_vec();
    let b = src.as_bytes();
    let (mut i, mut in_str, mut in_line_comment) = (0usize, false, false);
    while i < b.len() {
        match (in_str, in_line_comment, b[i]) {
            (false, false, b'"') => in_str = true,
            (false, false, b'/') if b.get(i + 1) == Some(&b'/') => {
                in_line_comment = true;
                out[i] = b' ';
            }
            (true, _, b'\\') => {
                out[i] = b' ';
                out[i + 1] = b' ';
                i += 2;
                continue;
            }
            (true, _, b'"') => in_str = false,
            (_, true, b'\n') => in_line_comment = false,
            (true, _, _) => out[i] = b' ',
            (_, true, _) => out[i] = b' ',
            _ => {}
        }
        i += 1;
    }
    String::from_utf8(out).expect("blanking replaces bytes one for one")
}

fn line_of(src: &str, at: usize) -> usize {
    src[..at].matches('\n').count() + 1
}

/// The file above its own test module. A check about installation sites must not count the
/// tests that drive them.
fn non_test(code: &str) -> &str {
    match code.find("mod tests") {
        Some(at) => &code[..at],
        None => code,
    }
}

fn no_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn sites(hay: &str, needle: &str) -> Vec<usize> {
    let (mut out, mut from) = (Vec::new(), 0);
    while let Some(rel) = hay[from..].find(needle) {
        out.push(from + rel);
        from += rel + needle.len();
    }
    out
}

/// The end of the block opened after `from` — its matching close brace.
fn block_end(code: &str, from: usize) -> usize {
    let open = from + code[from..].find('{').expect("a block to close");
    let mut depth = 0i32;
    for (k, c) in code[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return open + k;
                }
            }
            _ => {}
        }
    }
    code.len()
}

/// The end of the call expression starting at `from` — its matching close paren.
fn call_end(code: &str, from: usize) -> usize {
    let open = from + code[from..].find('(').expect("a call to close");
    let mut depth = 0i32;
    for (k, c) in code[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return open + k + 1;
                }
            }
            _ => {}
        }
    }
    code.len()
}

/// One `fn` in the file: its name, its signature span and its body span. A trait method with
/// no body is skipped — its `;` arrives before any `{`, so it opens no scope.
struct Func {
    name: String,
    sig: (usize, usize),
    body: (usize, usize),
}

fn functions(code: &str) -> Vec<Func> {
    let mut out = Vec::new();
    for at in sites(code, "fn ") {
        if at > 0 && code.as_bytes()[at - 1].is_ascii_alphanumeric() {
            continue;
        }
        let rest = &code[at + 3..];
        let name: String =
            rest.trim_start().chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        if name.is_empty() {
            continue;
        }
        let after_params = call_end(code, at);
        let Some(rel) = code[after_params..].find(['{', ';']) else { continue };
        if code.as_bytes()[after_params + rel] == b';' {
            continue; // a declaration, not a definition
        }
        let open = after_params + rel;
        out.push(Func { name, sig: (at, open), body: (open, block_end(code, open)) });
    }
    out
}

/// Every body under `name`. All of them, not the first: a trait's empty default definition
/// sits above the impl that does the work, and picking one is how a check reads the wrong one.
fn bodies_of<'a>(fns: &[Func], code: &'a str, name: &str) -> Vec<&'a str> {
    let out: Vec<&str> =
        fns.iter().filter(|f| f.name == name).map(|f| &code[f.body.0..f.body.1]).collect();
    assert!(!out.is_empty(), "no fn {name}");
    out
}

/// The innermost function containing `at`.
fn enclosing_fn(fns: &[Func], at: usize) -> String {
    fns.iter()
        .filter(|f| f.body.0 <= at && at < f.body.1)
        .min_by_key(|f| f.body.1 - f.body.0)
        .map(|f| f.name.clone())
        .unwrap_or_else(|| "<top level>".into())
}

/// Where each lock is taken, and how far its guard can still be held.
///
/// Two shapes, and the difference matters: `let g = X.lock();` binds the guard for the rest
/// of the enclosing block, while `if let Ok(g) = X.write() { .. }` binds it for that block
/// alone. Charging the first shape's span to the second reports a call made after the guard
/// was dropped, which is how a check gets weakened instead of fixed.
fn guard_scopes(code: &str) -> Vec<(usize, usize)> {
    let mut scopes = Vec::new();
    for pat in [".read()", ".write()", ".lock()"] {
        for at in sites(code, pat) {
            let Some(rel) = code[at..].find(['{', ';']) else { continue };
            let end = if code.as_bytes()[at + rel] == b'{' {
                block_end(code, at)
            } else {
                let mut depth = 0i32;
                let mut end = code.len();
                for (k, c) in code[at..].char_indices() {
                    match c {
                        '{' => depth += 1,
                        '}' if depth == 0 => {
                            end = at + k;
                            break;
                        }
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                end
            };
            scopes.push((at, end));
        }
    }
    scopes
}

/// Every method of the glue that reaches `modules()`, directly or through another of its own
/// methods. A scan for the literal token cannot see `self.verified_gate_within(..)`,
/// `self.quote(..)` or `self.chain_nonce(..)` — each an IPC round trip one level down, and
/// each invisible to the check that was supposed to keep calls out of a lock scope.
fn reaches_modules(code: &str, fns: &[Func]) -> BTreeSet<String> {
    let mut reaching: BTreeSet<String> = fns
        .iter()
        .filter(|f| code[f.body.0..f.body.1].contains("modules()"))
        .map(|f| f.name.clone())
        .collect();
    loop {
        let mut grew = false;
        for f in fns {
            if reaching.contains(&f.name) {
                continue;
            }
            let body = &code[f.body.0..f.body.1];
            if reaching.iter().any(|r| calls(body, r)) {
                reaching.insert(f.name.clone());
                grew = true;
            }
        }
        if !grew {
            return reaching;
        }
    }
}

fn calls(body: &str, name: &str) -> bool {
    body.contains(&format!("self.{name}(")) || body.contains(&format!("Self::{name}("))
}

/// A copy of the source with one regression applied, for the mutant tests.
fn mutate(src: &str, from: &str, to: &str) -> String {
    assert_eq!(src.matches(from).count(), 1, "the mutation target moved: {from}");
    src.replacen(from, to, 1)
}

// ---------------------------------------------------------------------------------------
// 1. The success path settles through its ticket.
// ---------------------------------------------------------------------------------------

/// `advance_send` from the broadcast claim to the end of the function.
fn claim_tail(code: &str) -> (usize, String) {
    let at = code.find("fn advance_send").expect("advance_send is where a send is broadcast");
    let end = block_end(code, at);
    let claim =
        at + code[at..end].find("claim_broadcast(").expect("the broadcast is claimed in there");
    (claim, code[claim..end].to_string())
}

const OWNED: &str = "self.settle_owned(&st, &ticket";

/// How many of them there are. Five: the record that would not write, the ledger that would
/// not release the leg, the answer with no hash, the broadcast that errored, and the one
/// that lands the hashes.
const OWNED_SITES: usize = 5;

/// Past the claim the ticket is the only key to the job — and the site that matters is the
/// one that lands the HASH. The others are failure arms, so `tail.contains(OWNED)` is
/// satisfied by them alone: deleting the success site and replying by hand builds clean, runs
/// green, and in production latches the job at `broadcasting` for the life of the process.
fn check_settles_through_the_ticket(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let (claim, tail) = claim_tail(&code);
    if let Some(rel) = tail.find("self.settle(") {
        return Err(format!(
            "glue.rs:{} settles by request id after claiming the broadcast. Past the claim \
             the ticket is the only key: `self.settle_owned(&st, &ticket, ..)`.",
            line_of(src, claim + rel)
        ));
    }
    let found = sites(&tail, OWNED);
    if found.len() != OWNED_SITES {
        return Err(format!(
            "advance_send has {} settles through the ticket, not the {OWNED_SITES} this \
             pins: the four failure arms and the one that lands the hashes. Lines {:?}.",
            found.len(),
            found.iter().map(|s| line_of(src, claim + s)).collect::<Vec<_>>()
        ));
    }
    let last = found[OWNED_SITES - 1];
    if !tail[last..].starts_with(&format!("{OWNED}, SendStatus::Broadcast")) {
        return Err("the last settle through the ticket is not the one carrying the hash".into());
    }
    if tail[..last].contains("SendStatus::Broadcast") {
        return Err("a hash is settled before the end of advance_send; the success path must \
                    be the function's last act"
            .into());
    }
    if !tail[call_end(&tail, last)..].trim().is_empty() {
        return Err("advance_send does something after landing the hash; the reply the caller \
                    gets must be the one the ledger produced"
            .into());
    }
    Ok(())
}

#[test]
fn the_broadcast_success_path_settles_through_its_ticket() {
    check_settles_through_the_ticket(GLUE).unwrap();
}

/// A ticketless `Broadcast` settle added ANYWHERE else — a receipt poller, a new door — walks
/// past the tail scan. A hash means the signed transaction left, which only the ticket holder
/// is in a position to know, so the rule is about the file and not about one function.
fn check_no_ticketless_broadcast(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let fns = functions(&code);
    for at in sites(&code, "self.settle(") {
        if code[at..call_end(&code, at)].contains("SendStatus::Broadcast") {
            return Err(format!(
                "glue.rs:{} settles a Broadcast by request id, in `{}`. Only the ticket \
                 holder knows a transaction left: use `settle_owned`.",
                line_of(src, at),
                enclosing_fn(&fns, at)
            ));
        }
    }
    for at in sites(&code, ".sends.settle(") {
        let who = enclosing_fn(&fns, at);
        if who != "settle" {
            return Err(format!(
                "glue.rs:{} reaches the ledger's ticketless settle from `{who}`. One door, \
                 so a new caller cannot quietly become a second.",
                line_of(src, at)
            ));
        }
    }
    Ok(())
}

#[test]
fn no_broadcast_is_ever_settled_by_request_id() {
    check_no_ticketless_broadcast(GLUE).unwrap();
}

/// `refresh_one` learns a hash from a receipt and settles the send with it. It is nowhere
/// near `advance_send`, which is exactly why the tail scan could not see it.
#[test]
fn a_ticketless_broadcast_settle_anywhere_in_the_file_is_caught() {
    let mutant = mutate(
        GLUE,
        "        let status = history::classify_receipt(&receipt);",
        "        let status = history::classify_receipt(&receipt);\n        let _ = \
         self.settle(&st, hash_hex, SendStatus::Broadcast { hash: rec.hash.clone(), route: \
         \"proxied\".into() });",
    );
    let e = check_no_ticketless_broadcast(&mutant).unwrap_err();
    assert!(e.contains("in `refresh_one`"), "{e}");
    assert!(
        check_settles_through_the_ticket(&mutant).is_ok(),
        "the tail scan is supposed to miss this — that it does is the whole finding"
    );
}

/// Delete the site that lands the hashes, reply by hand. The check must reject it — and the
/// region `contains` it replaces would not have.
#[test]
fn deleting_the_site_that_lands_the_hash_is_caught() {
    let mutant = mutate(
        GLUE,
        "self.settle_owned(&st, &ticket, SendStatus::Broadcast { hash: last_hash, route })",
        "Ok(Self::job_reply(&job, now))",
    );
    let e = check_settles_through_the_ticket(&mutant).unwrap_err();
    assert!(e.contains("not the 5 this pins"), "{e}");

    let (_, tail) = claim_tail(&code_only(&mutant));
    assert!(
        tail.contains(OWNED),
        "the region `contains` this replaces would have rejected the mutant after all — the \
         failure arms are supposed to keep it green, which is the whole finding"
    );
}

/// And the other half: a hash landed early, with work after it.
#[test]
fn settling_the_hash_before_the_end_of_advance_send_is_caught() {
    let mutant = mutate(
        GLUE,
        "        let route = route.unwrap_or_else(|| verified::UNKNOWN_ROUTE.to_string());\n        \
         self.settle_owned(&st, &ticket, SendStatus::Broadcast { hash: last_hash, route })",
        "        let route = route.unwrap_or_else(|| verified::UNKNOWN_ROUTE.to_string());\n        \
         let out = self.settle_owned(&st, &ticket, SendStatus::Broadcast { hash: last_hash, \
         route });\n        emit_history_changed(&job.from);\n        out",
    );
    let e = check_settles_through_the_ticket(&mutant).unwrap_err();
    assert!(e.contains("does something after landing the hash"), "{e}");
}

// ---------------------------------------------------------------------------------------
// 2. No outbound call shares a scope with a lock guard.
// ---------------------------------------------------------------------------------------

fn check_no_call_under_a_lock(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let fns = functions(&code);
    let reaching = reaches_modules(&code, &fns);
    let scopes = guard_scopes(&code);
    if scopes.is_empty() {
        return Err("the scan found no locks at all — it has stopped working".into());
    }
    for (at, end) in scopes {
        let scope = &code[at..end];
        let culprit = scope
            .contains("modules()")
            .then(|| "modules()".to_string())
            .or_else(|| reaching.iter().find(|r| calls(scope, r)).map(|r| format!("self.{r}()")));
        if let Some(culprit) = culprit {
            return Err(format!(
                "glue.rs:{} takes a lock and calls {culprit} while it is still held. Copy \
                 what you need out of the state, drop the guard, THEN call.",
                line_of(src, at)
            ));
        }
    }
    Ok(())
}

#[test]
fn no_outbound_call_shares_a_scope_with_a_lock_guard() {
    check_no_call_under_a_lock(GLUE).unwrap();
}

/// The weakness the transitive scan removes: an IPC call reached through one of the glue's
/// own methods is not the token `modules()`, and the check that looked for that token saw
/// nothing at all.
#[test]
fn an_outbound_call_reached_through_a_helper_is_caught() {
    let mutant = mutate(
        GLUE,
        "guard.clone().ok_or_else(|| NO_CONTEXT.to_string())",
        "let _ = self.verified_gate_within(1, b);\n        guard.clone().ok_or_else(|| NO_CONTEXT.to_string())",
    );
    let e = check_no_call_under_a_lock(&mutant).unwrap_err();
    assert!(e.contains("self.verified_gate_within()"), "{e}");

    let code = code_only(&mutant);
    assert!(
        guard_scopes(&code).into_iter().all(|(a, e)| !code[a..e].contains("modules()")),
        "the literal-token scan this replaces would have rejected the mutant after all"
    );
}

// ---------------------------------------------------------------------------------------
// 3. The glue takes exactly the two locks that are argued for, in the two named places.
// ---------------------------------------------------------------------------------------

/// A COUNT is not a location: `taken.len() == 2` is satisfied by any two locks anywhere.
fn check_lock_sites(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let fns = functions(&code);
    let mut taken: Vec<String> =
        guard_scopes(&code).into_iter().map(|(at, _)| enclosing_fn(&fns, at)).collect();
    taken.sort();
    if taken != ["on_context_ready", "state"] {
        return Err(format!(
            "glue.rs should take exactly two locks — `state()` reading the handle and \
             `on_context_ready` installing it. Found them in {taken:?}. Every other lock \
             belongs inside `History` or `SendLedger`, taken around local work and released \
             before anything is called."
        ));
    }
    if code.contains("with_state") {
        return Err("`with_state(|st| ...)` is back: it reads as `borrow the state` and means \
                    `hold a read lock across whatever the closure does`"
            .into());
    }
    // Whitespace-stripped, so splitting the signature over lines is not a failure. A `&State`
    // borrowed through the guard would keep the guard alive for as long as the caller uses it.
    let sig = no_ws(&code[fns.iter().find(|f| f.name == "state").expect("fn state").sig.0..]);
    if !sig.starts_with("fnstate(&self)->Result<Arc<State>,String>") {
        return Err("`state()` must hand back an owned handle".into());
    }
    Ok(())
}

#[test]
fn the_glue_takes_no_lock_except_the_one_that_hands_back_a_handle() {
    check_lock_sites(GLUE).unwrap();
}

#[test]
fn a_third_lock_anywhere_else_is_caught_even_where_a_count_would_balance() {
    // The count stays at two: one of the argued-for locks goes, two appear in the send path.
    let mutant = mutate(
        GLUE,
        "        let st = self.state()?;\n        let b = Budget::new(SEND_BUDGET);\n        let now = history::now_secs();",
        "        let st = self.state()?;\n        let _a = self.state.read();\n        let b = Budget::new(SEND_BUDGET);\n        let now = history::now_secs();",
    );
    let e = check_lock_sites(&mutant).unwrap_err();
    assert!(e.contains("advance_send"), "{e}");
}

#[test]
fn handing_back_a_borrow_instead_of_a_handle_is_caught() {
    let mutant =
        mutate(GLUE, "fn state(&self) -> Result<Arc<State>, String> {", "fn state(&self) -> Result<&State, String> {");
    let e = check_lock_sites(&mutant).unwrap_err();
    assert!(e.contains("owned handle"), "{e}");
}

// ---------------------------------------------------------------------------------------
// 4. Every outbound call is bounded, or argued for.
// ---------------------------------------------------------------------------------------

/// Every outbound call carries a deadline, except these — each one a decision, not an
/// oversight. A new unbounded call fails this test and has to be argued for here.
const DELIBERATELY_UNBOUNDED: &[(&str, &str, &str)] = &[
    // The one call that moves money. A deadline does not stop the transaction, it only stops
    // us learning its hash.
    ("eth_rpc_module", "send_raw_transaction", "a broadcast with an unknown outcome is worse"),
    // Not a call at all: it arms an `EventSubscription` and the generated client emits no
    // bounded twin for one. A deadline on arming would be a deadline on the SUBSCRIPTION,
    // which is meant to outlive every call this module makes.
    ("eth_rpc_module", "on_verified_proxy_mode_changed", "a subscription has no bounded twin"),
    // Neither is the status watcher: it installs a callback and returns, and the C side
    // replays the current state from inside the call rather than waiting on the provider.
    ("eth_rpc_module", "on_subscription_status", "installs a callback; nothing is dispatched"),
    ("eth_rpc_module", "on_chain_config_changed", "a subscription has no bounded twin"),
];

fn check_calls_are_bounded(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let mut unbounded: Vec<(String, String, usize)> = Vec::new();
    for at in sites(&code, "modules()") {
        let rest = &code[at + "modules()".len()..];
        let mut parts = rest.split('.').skip(1).map(|p| {
            p.trim_start().chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect()
        });
        let (dep, method): (String, String) =
            (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
        if !method.ends_with("_with_timeout") {
            unbounded.push((dep, method, line_of(src, at)));
        }
    }
    for (dep, method, line) in &unbounded {
        if !DELIBERATELY_UNBOUNDED.iter().any(|(d, m, _)| d == dep && m == method) {
            return Err(format!(
                "glue.rs:{line} calls {dep}.{method} with no deadline. Give it one from \
                 `budget.rs`, or add it to DELIBERATELY_UNBOUNDED with the reason."
            ));
        }
    }
    // And the list must not outlive its entries, or it becomes a place to hide things.
    for (dep, method, why) in DELIBERATELY_UNBOUNDED {
        if !unbounded.iter().any(|(d, m, _)| d == dep && m == method) {
            return Err(format!(
                "{dep}.{method} is listed as unbounded ({why}) but the glue no longer calls it"
            ));
        }
    }
    Ok(())
}

#[test]
fn every_outbound_call_is_bounded_except_the_ones_argued_for_here() {
    check_calls_are_bounded(GLUE).unwrap();
}

#[test]
fn a_new_unbounded_call_is_caught() {
    let mutant = mutate(
        GLUE,
        ".get_transaction_count_with_timeout(chain_id as i64, address, t)",
        ".get_transaction_count(chain_id as i64, address)",
    );
    let e = check_calls_are_bounded(&mutant).unwrap_err();
    assert!(e.contains("eth_rpc_module.get_transaction_count with no deadline"), "{e}");
}

#[test]
fn an_entry_the_glue_no_longer_calls_is_caught() {
    let mutant = mutate(
        GLUE,
        ".send_raw_transaction(chain_id as i64, raw_tx)",
        ".send_raw_transaction_with_timeout(chain_id as i64, raw_tx, RPC_BUDGET)",
    );
    let e = check_calls_are_bounded(&mutant).unwrap_err();
    assert!(e.contains("no longer calls it"), "{e}");
}

/// A fee estimate is a call across a network too, and there is one per leg.
#[test]
fn an_unbounded_fee_estimate_is_caught() {
    let mutant = mutate(
        GLUE,
        ".estimate_bundle_with_timeout(chain_id as i64, &fee_req.to_string(), t)",
        ".estimate_bundle(chain_id as i64, &fee_req.to_string())",
    );
    let e = check_calls_are_bounded(&mutant).unwrap_err();
    assert!(e.contains("fee_module.estimate_bundle with no deadline"), "{e}");
}

// ---------------------------------------------------------------------------------------
// 5. The send ledger is built once, with the module.
// ---------------------------------------------------------------------------------------

/// `on_context_ready` can be called again, and it installs a fresh `State`. A fresh
/// `SendLedger` with it discards every reservation at once — including the ones protecting
/// transactions already on chain — without breaking a single rule inside the ledger. The
/// guard belongs at the construction site, where the reserver cannot see.
fn check_ledger_built_once(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let fns = functions(&code);
    if bodies_of(&fns, &code, "on_context_ready").iter().any(|b| b.contains("SendLedger")) {
        return Err("on_context_ready builds a SendLedger. A re-init would drop every \
                    reservation, on-chain ones included; clone the module's handle instead."
            .into());
    }
    let at = code.find("struct TxSenderModuleImpl").ok_or("the module struct")?;
    if !no_ws(&code[at..block_end(&code, at)]).contains("sends:Arc<SendLedger>") {
        return Err("the module must own the ledger, so nothing per-context can replace it".into());
    }
    Ok(())
}

#[test]
fn the_send_ledger_outlives_a_second_on_context_ready() {
    check_ledger_built_once(GLUE).unwrap();
}

#[test]
fn rebuilding_the_ledger_on_re_init_is_caught() {
    let mutant = mutate(
        GLUE,
        "sends: self.sends.clone()",
        "sends: Arc::new(SendLedger::default())",
    );
    let e = check_ledger_built_once(&mutant).unwrap_err();
    assert!(e.contains("builds a SendLedger"), "{e}");
}

// ---------------------------------------------------------------------------------------
// 6. The reserver is seeded from the durable evidence, before anything can ask it.
// ---------------------------------------------------------------------------------------

/// `SendLedger` is in-memory, and `latest` does not count a broadcast that has not mined, so
/// a fresh process hands the next send a number a pending row is already using. This pins
/// the read of the persisted nonces.
fn check_the_reserver_is_seeded(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let fns = functions(&code);
    let bodies = bodies_of(&fns, &code, "on_context_ready");
    let body = bodies
        .iter()
        .find(|b| b.contains("instance_persistence_path"))
        .ok_or("on_context_ready no longer opens the persistence directory")?;
    let seed = body.find("sends.seed_spent(").ok_or(
        "on_context_ready does not seed the reserver from history. The ledger does not \
         survive the process: without this a restart signs at a nonce a pending transaction \
         is already using, and the user is told the first send was made.",
    )?;
    let install = body.find("self.state.write()").ok_or("the state is no longer installed")?;
    if seed > install {
        return Err("the reserver is seeded after the state is installed. A send dispatched \
                    between the two reaches `state()` and gets an unprotected nonce."
            .into());
    }
    Ok(())
}

#[test]
fn the_reserver_is_seeded_from_history_before_the_state_is_reachable() {
    check_the_reserver_is_seeded(GLUE).unwrap();
}

#[test]
fn dropping_the_seed_is_caught() {
    let mutant = mutate(GLUE, "let seeded = self.sends.seed_spent(history.unsettled_nonces());", "let seeded = 0;");
    let e = check_the_reserver_is_seeded(&mutant).unwrap_err();
    assert!(e.contains("does not seed the reserver"), "{e}");
}

#[test]
fn seeding_after_the_state_is_installed_is_caught() {
    let mutant = mutate(
        GLUE,
        "        let seeded = self.sends.seed_spent(history.unsettled_nonces());",
        "        let pending = history.unsettled_nonces();",
    );
    let mutant = mutate(
        &mutant,
        "        // Arm before the first gated read",
        "        let seeded = self.sends.seed_spent(pending);\n        // Arm before the first gated read",
    );
    let e = check_the_reserver_is_seeded(&mutant).unwrap_err();
    assert!(e.contains("seeded after the state is installed"), "{e}");
}

// ---------------------------------------------------------------------------------------
// 7. The ledger's invariant check has exactly one installation, and one way in.
// ---------------------------------------------------------------------------------------

/// Hand-placed `l.audit()` calls can be deleted with the suite still green, because tests
/// drive the CHECKER and never its installation. The audit runs in `Audited::drop`, so a
/// door cannot omit it; this keeps it there.
fn check_the_audit_is_installed_once(src: &str) -> Result<(), String> {
    let full = code_only(src);
    let code = non_test(&full);
    let fns = functions(code);
    let calls = sites(code, ".audit()");
    let who: Vec<String> = calls.iter().map(|&a| enclosing_fn(&fns, a)).collect();
    if who != ["drop"] {
        return Err(format!(
            "send.rs installs the invariant check in {who:?}. It belongs in `Audited::drop` \
             alone: hand-placed calls are what a mutation pass deleted without a single \
             failure."
        ));
    }
    let at = code.find("impl Drop for Audited").ok_or("Audited must audit as it is released")?;
    if !(at < calls[0] && calls[0] < block_end(code, at)) {
        return Err(format!("send.rs:{} audits outside Audited::drop", line_of(src, calls[0])));
    }
    Ok(())
}

/// A guard that audits is worth nothing if a door can go round it. `SendLedger.inner` is
/// private to `mod gate`, so a bypass is a compile error rather than a review question —
/// this pins the two uses that live inside `gate` itself.
fn check_the_ledger_has_one_way_in(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let fns = functions(&code);
    let mut who: Vec<String> =
        sites(&code, "self.inner").into_iter().map(|a| enclosing_fn(&fns, a)).collect();
    who.sort();
    if who != ["lock", "unreserve_behind_the_ledgers_back"] {
        return Err(format!(
            "the ledger's mutex is reached from {who:?}. Only `lock`, whose guard audits, \
             and the test-only corruption door may name it; anything else is a door that \
             skips the check."
        ));
    }
    Ok(())
}

/// `SendJob::leg_spent` decides both the burn and the release, in ONE writer, so the two
/// halves cannot disagree.
fn check_the_burn_is_single_sourced(src: &str) -> Result<(), String> {
    let full = code_only(src);
    let code = non_test(&full);
    let fns = functions(code);
    let mut who: Vec<String> =
        sites(code, ".mark_spent(").into_iter().map(|a| enclosing_fn(&fns, a)).collect();
    who.sort();
    if who != ["seed_spent", "sync_nonce"] {
        return Err(format!(
            "a nonce is burnt from {who:?}. `sync_nonce` is the one place a job's numbers \
             are written — `SendJob::leg_spent` decides the burn and the release together — \
             and `seed_spent` carries what a previous process signed at."
        ));
    }
    Ok(())
}

/// A leg's `left` is the fact the burn turns on, so it has exactly one writer: `leaving`,
/// the ticket holder's door.
fn check_leaving_has_one_writer(src: &str) -> Result<(), String> {
    let full = code_only(src);
    let code = non_test(&full);
    let fns = functions(code);
    let mut who: Vec<String> =
        sites(code, ".left = true").into_iter().map(|a| enclosing_fn(&fns, a)).collect();
    who.sort();
    if who != ["leaving"] {
        return Err(format!(
            "a leg is marked as having left from {who:?}. `leaving` is the one door, and it \
             demands the broadcast ticket."
        ));
    }
    Ok(())
}

#[test]
fn the_ledgers_invariant_check_cannot_be_omitted() {
    check_the_audit_is_installed_once(SEND).unwrap();
    check_the_ledger_has_one_way_in(SEND).unwrap();
    check_the_burn_is_single_sourced(SEND).unwrap();
    check_leaving_has_one_writer(SEND).unwrap();
}

#[test]
fn deleting_the_audit_from_the_guard_is_caught() {
    let mutant = mutate(
        SEND,
        "        fn drop(&mut self) {\n            self.0.audit();\n        }",
        "        fn drop(&mut self) {}",
    );
    let e = check_the_audit_is_installed_once(&mutant).unwrap_err();
    assert!(e.contains("installs the invariant check in []"), "{e}");
}

#[test]
fn a_second_unaudited_way_into_the_ledger_is_caught() {
    let mutant = mutate(
        SEND,
        "    /// A borrow of the ledger that audits when it is released.",
        "    impl SendLedger {\n        pub(super) fn unaudited(&self) -> MutexGuard<'_, Ledger> \
         {\n            self.inner.lock().unwrap()\n        }\n    }\n\n    /// A borrow of the \
         ledger that audits when it is released.",
    );
    let e = check_the_ledger_has_one_way_in(&mutant).unwrap_err();
    assert!(e.contains("\"unaudited\""), "{e}");
}

#[test]
fn burning_a_nonce_outside_the_one_writer_is_caught() {
    let mutant = mutate(
        SEND,
        "        job.legs[leg].left = true;\n        sync_nonce(&mut l, &t.request_id);",
        "        job.legs[leg].left = true;\n        let n = job.legs[leg].nonce;\n        let (c, f) = (job.chain_id, job.from.clone());\n        l.nonces.mark_spent(c, &f, n);",
    );
    let e = check_the_burn_is_single_sourced(&mutant).unwrap_err();
    assert!(e.contains("\"leaving\""), "{e}");
}

#[test]
fn marking_a_leg_as_left_outside_the_ticketed_door_is_caught() {
    let mutant = mutate(
        SEND,
        "        l.last_ticket = ticket;\n        BroadcastClaim::Claimed(",
        "        l.last_ticket = ticket;\n        job.legs[0].left = true;\n        BroadcastClaim::Claimed(",
    );
    let e = check_leaving_has_one_writer(&mutant).unwrap_err();
    assert!(e.contains("\"claim_broadcast\""), "{e}");
}

// ---------------------------------------------------------------------------------------
// 8. The record goes down, and the number is burnt, before each leg leaves.
// ---------------------------------------------------------------------------------------

/// The order in which named markers appear in a region. A count says a marker is present;
/// this says where — and every rule below is about which side of the broadcast a write is on.
fn order<'a>(region: &str, markers: &[&'a str]) -> Vec<&'a str> {
    let mut out: Vec<(usize, &str)> = Vec::new();
    // Distinct: the wanted order repeats markers, and scanning one twice reports its sites
    // twice — a sequence that never matches anything and a check that always fails.
    for m in markers.iter().copied().collect::<BTreeSet<_>>() {
        out.extend(sites(region, m).into_iter().map(|a| (a, m)));
    }
    out.sort();
    out.into_iter().map(|(_, m)| m).collect()
}

const BROADCAST_ORDER: &[&str] = &[
    "st.history.record_intent(",
    "SendStatus::Failed",
    "st.sends.leaving(",
    "SendStatus::Failed",
    "self.broadcast(",
    "st.history.leave_unknown(",
    "SendStatus::Failed",
    "st.history.leave_unknown(",
    "SendStatus::Failed",
    "st.history.resolve_broadcast(",
    "SendStatus::Broadcast",
];

/// The durable record used to be written AFTER the broadcast returned, and on the failure
/// path not at all: a crash inside the RPC, or an early return, left a nonce that had left
/// with nothing on disk, and the next process handed that number to another send.
///
/// Two halves. `broadcast` takes `Recorded`, which only `History::record_intent` produces,
/// and `Leaving`, which only `SendLedger::leaving` produces — so sending before writing, or
/// on a number the ledger could still hand out, is a compile error rather than a review
/// question. And the send path is pinned in order, because a proof obtained after the bytes
/// leave would satisfy the type and none of the intent.
fn check_the_record_precedes_the_broadcast(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let fns = functions(&code);
    let who: Vec<String> =
        sites(&code, ".send_raw_transaction(").into_iter().map(|a| enclosing_fn(&fns, a)).collect();
    if who != ["broadcast"] {
        return Err(format!(
            "glue.rs sends a raw transaction from {who:?}. The one call that moves money \
             belongs in `broadcast` alone, whose `Recorded` argument is what makes \
             broadcasting before the record is written unexpressible."
        ));
    }
    let f = fns.iter().find(|f| f.name == "broadcast").ok_or("fn broadcast")?;
    let sig = no_ws(&code[f.sig.0..f.sig.1]);
    if !sig.contains("&history::Recorded") {
        return Err("`broadcast` no longer takes the `Recorded` proof, so writing the record \
                    first is back to being a rule every new path has to remember"
            .into());
    }
    if !sig.contains("&send::Leaving") {
        return Err("`broadcast` no longer takes the `Leaving` proof, so burning the number \
                    first is back to being a rule every new path has to remember"
            .into());
    }
    let (_, tail) = claim_tail(&code);
    let seen = order(&tail, BROADCAST_ORDER);
    if seen != BROADCAST_ORDER {
        return Err(format!(
            "the send path runs {seen:?}. It must run {BROADCAST_ORDER:?}: record the leg, \
             refuse the send if it did not land, burn the number, broadcast, and leave the \
             row unknown on every arm that did not get a hash."
        ));
    }
    Ok(())
}

#[test]
fn the_intent_is_on_disk_before_the_transaction_leaves() {
    check_the_record_precedes_the_broadcast(GLUE).unwrap();
}

#[test]
fn broadcasting_without_writing_the_record_first_is_caught() {
    let mutant = mutate(
        GLUE,
        "let recorded = match st.history.record_intent(request_id, i as u32, Self::intent_row(&job, i)) {\n                Ok(r) => r,\n                Err(reason) => {\n                    let reason = leg_failure(i, n, &reason);\n                    return self.settle_owned(&st, &ticket, SendStatus::Failed { reason });\n                }\n            };",
        "let recorded = Self::proof();",
    );
    let e = check_the_record_precedes_the_broadcast(&mutant).unwrap_err();
    assert!(e.contains("the send path runs"), "{e}");
}

/// The subtler one: the record is still written, just not first. A `contains` for
/// `record_intent` anywhere in the function would have called it green.
#[test]
fn recording_the_intent_after_the_broadcast_is_caught() {
    let mutant = mutate(
        GLUE,
        "let recorded = match st.history.record_intent(request_id, i as u32, Self::intent_row(&job, i)) {\n                Ok(r) => r,\n                Err(reason) => {\n                    let reason = leg_failure(i, n, &reason);\n                    return self.settle_owned(&st, &ticket, SendStatus::Failed { reason });\n                }\n            };",
        "let recorded = Self::proof();",
    );
    let mutant = mutate(
        &mutant,
        "let took_hash = st.history.resolve_broadcast(",
        "let _ = st.history.record_intent(request_id, i as u32, Self::intent_row(&job, i));\n            \
         let took_hash = st.history.resolve_broadcast(",
    );
    let e = check_the_record_precedes_the_broadcast(&mutant).unwrap_err();
    assert!(e.contains("the send path runs"), "{e}");
    assert!(
        mutant.contains("record_intent"),
        "the mutant still records — that a `contains` would pass it is the whole finding"
    );
}

#[test]
fn a_broadcast_that_does_not_demand_the_proofs_is_caught() {
    let mutant = mutate(GLUE, "_recorded: &history::Recorded,", "_recorded: &str,");
    let e = check_the_record_precedes_the_broadcast(&mutant).unwrap_err();
    assert!(e.contains("no longer takes the `Recorded` proof"), "{e}");
    let mutant = mutate(GLUE, "_leaving: &send::Leaving,", "_leaving: usize,");
    let e = check_the_record_precedes_the_broadcast(&mutant).unwrap_err();
    assert!(e.contains("no longer takes the `Leaving` proof"), "{e}");
}

/// A broadcast that errors must leave the row `unknown` on disk before it settles the job:
/// without this the send is recorded nowhere and the next process, seeing no row, hands the
/// number straight out.
#[test]
fn a_failure_arm_that_does_not_leave_the_row_unknown_is_caught() {
    let mutant = mutate(
        GLUE,
        "                Err(reason) => {\n                    if st.history.leave_unknown(&recorded, &reason) {\n                        emit_history_changed(&job.from);\n                    }\n",
        "                Err(reason) => {\n",
    );
    let e = check_the_record_precedes_the_broadcast(&mutant).unwrap_err();
    assert!(e.contains("the send path runs"), "{e}");
}

/// The number burnt AFTER the bytes left is a window in which another send can take it.
#[test]
fn burning_the_number_after_the_broadcast_is_caught() {
    let mutant = mutate(
        GLUE,
        "            let Some(leaving) = st.sends.leaving(&ticket, i) else {\n                let reason = leg_failure(i, n, \"the ledger would not release this call\");\n                return self.settle_owned(&st, &ticket, SendStatus::Failed { reason });\n            };\n",
        "            let leaving = Self::departure(i);\n",
    );
    let mutant = mutate(
        &mutant,
        "            let took_hash = st.history.resolve_broadcast(",
        "            let _ = st.sends.leaving(&ticket, i);\n            let took_hash = st.history.resolve_broadcast(",
    );
    let e = check_the_record_precedes_the_broadcast(&mutant).unwrap_err();
    assert!(e.contains("the send path runs"), "{e}");
}

// ---------------------------------------------------------------------------------------
// 9. A gated path a BUTTON drives is bounded across its gate.
// ---------------------------------------------------------------------------------------

/// `refresh_one` and `fetch_details` are each one click, and each must run the BOUNDED gate
/// inside the allowance meant to cover the method — otherwise the view's own deadline
/// expires first and blames a backend that had answered nothing yet.
const ON_A_BUTTON: &[(&str, &str)] =
    &[("refresh_one", "REFRESH_BUDGET"), ("fetch_details", "DETAILS_BUDGET")];

/// The last argument of the call starting at `at`.
fn last_arg(body: &str, at: usize) -> String {
    let open = at + body[at..].find('(').expect("a call to close");
    let args = &body[open + 1..call_end(body, at) - 1];
    let (mut depth, mut cut) = (0i32, 0usize);
    for (k, c) in args.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => cut = k + 1,
            _ => {}
        }
    }
    args[cut..].trim().to_string()
}

fn check_button_paths_are_bounded(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let fns = functions(&code);
    for (name, budget) in ON_A_BUTTON {
        for body in bodies_of(&fns, &code, name) {
            let gate = body.find("verified_gate").ok_or(format!("`{name}` no longer gates"))?;
            let taken = body
                .find(&format!("Budget::new({budget})"))
                .ok_or(format!("`{name}` no longer takes a {budget}"))?;
            if taken > gate {
                return Err(format!(
                    "`{name}` takes its {budget} AFTER the gate, so the gate is outside the \
                     allowance and the method is bounded by nothing a user can feel."
                ));
            }
            if body[gate..].starts_with("verified_gate(") {
                return Err(format!(
                    "`{name}` uses the unbounded gate. On a button that is up to 20s of \
                     frozen view — use `verified_gate_within` charged to the budget above."
                ));
            }
            for at in sites(body, "_with_timeout(") {
                let arg = last_arg(body, at);
                if arg.ends_with("_BUDGET") {
                    return Err(format!(
                        "`{name}` bounds a call with {arg} rather than a grant off its \
                         budget, so the method is bounded by its call COUNT again."
                    ));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn a_path_a_button_drives_is_bounded_across_its_gate() {
    check_button_paths_are_bounded(GLUE).unwrap();
}

#[test]
fn the_unbounded_gate_on_a_button_path_is_caught() {
    let mutant = mutate(
        GLUE,
        "self.verified_gate_within(rec.chain_id, &b) {\n            return Ok(blocked(&v));",
        "self.verified_gate(rec.chain_id) {\n            return Ok(blocked(&v));",
    );
    let e = check_button_paths_are_bounded(&mutant).unwrap_err();
    assert!(e.contains("uses the unbounded gate"), "{e}");
}

/// The subtler one: the gate is bounded, but the allowance is taken out after it — so it
/// charges the gate nothing and covers only the legs.
#[test]
fn a_budget_taken_after_the_gate_is_caught() {
    let mutant = mutate(
        GLUE,
        "        let b = Budget::new(DETAILS_BUDGET);\n        // The hash goes onto",
        "        // The hash goes onto",
    );
    let mutant = mutate(
        &mutant,
        "        let Some(number) = rec.block_number else {",
        "        let b = Budget::new(DETAILS_BUDGET);\n        let Some(number) = rec.block_number else {",
    );
    let e = check_button_paths_are_bounded(&mutant).unwrap_err();
    assert!(e.contains("AFTER the gate"), "{e}");
}

#[test]
fn a_call_bounded_by_a_constant_rather_than_the_budget_is_caught() {
    // Twelve spaces: the same call in `sweep` is nested one level deeper, and it is bounded
    // by the sweep's own allowance rather than by this one.
    let mutant = mutate(
        GLUE,
        "\n            .get_transaction_receipt_with_timeout(rec.chain_id as i64, &rec.hash, t)",
        "\n            .get_transaction_receipt_with_timeout(rec.chain_id as i64, &rec.hash, RPC_BUDGET)",
    );
    let e = check_button_paths_are_bounded(&mutant).unwrap_err();
    assert!(e.contains("rather than a grant off its"), "{e}");
}

// ---------------------------------------------------------------------------------------
// 10. Every gated path is bounded across its gate.
// ---------------------------------------------------------------------------------------

/// Every gate site runs the bounded probe INSIDE the method's own allowance. `prepare` and
/// `send` open theirs with `bounded_by`, so a caller's deadline can shrink it.
const GATED: &[(&str, &str)] = &[
    ("prepare", "SEND_BUDGET"),
    ("send", "SEND_BUDGET"),
    ("advance_send", "SEND_BUDGET"),
    ("refresh_one", "REFRESH_BUDGET"),
    ("fetch_details", "DETAILS_BUDGET"),
];

fn check_gated_paths_are_bounded(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let fns = functions(&code);
    for call in ["self.verified_gate(", "self.verified_verdict("] {
        if let Some(at) = sites(&code, call).first() {
            return Err(format!(
                "glue.rs:{} calls the unbounded `{call}`, which the protocol ABI answers with \
                 its 20s default. Take a Budget and spend the gate out of it.",
                line_of(src, *at)
            ));
        }
    }
    for (name, budget) in GATED {
        for body in bodies_of(&fns, &code, name) {
            let gate = body
                .find("verified_gate_within")
                .or_else(|| body.find("verified_verdict_within"))
                .ok_or_else(|| format!("`{name}` no longer gates"))?;
            let taken = body
                .find(&format!("Budget::new({budget})"))
                .or_else(|| body.find(&format!("Budget::bounded_by({budget}")))
                .ok_or_else(|| format!("`{name}` no longer takes a {budget}"))?;
            if taken > gate {
                return Err(format!(
                    "`{name}` takes its {budget} AFTER the gate, so the gate is outside the \
                     allowance and the method is bounded by nothing a user can feel."
                ));
            }
        }
    }
    Ok(())
}

#[test]
fn every_gated_path_takes_its_allowance_before_the_gate() {
    check_gated_paths_are_bounded(GLUE).unwrap();
}

#[test]
fn a_gate_site_left_on_the_unbounded_probe_is_caught() {
    let mutant = mutate(
        GLUE,
        "        if let Err(v) = self.verified_gate_within(req.chain_id, &b) {\n            return blocked(&v).to_string();\n        }\n        match self.quote(&req, &b) {",
        "        if let Err(v) = self.verified_gate(req.chain_id) {\n            return blocked(&v).to_string();\n        }\n        match self.quote(&req, &b) {",
    );
    let e = check_gated_paths_are_bounded(&mutant).unwrap_err();
    assert!(e.contains("calls the unbounded"), "{e}");
}

/// The gate is bounded, but by an allowance opened after it — so it charges the gate nothing
/// and covers only what follows.
#[test]
fn an_allowance_opened_after_the_gate_is_caught() {
    let mutant = mutate(
        GLUE,
        "        let b = Budget::bounded_by(SEND_BUDGET, req.deadline_ms);\n        if req.chain_id == 0 {\n            return err(\"chainId is required\");\n        }\n        if let Err(v) = self.verified_gate_within(req.chain_id, &b) {\n            return blocked(&v).to_string();\n        }\n        match self.quote(&req, &b) {",
        "        if let Err(v) = self.verified_gate_within(req.chain_id, &Budget::new(READ_BUDGET)) {\n            return blocked(&v).to_string();\n        }\n        let b = Budget::bounded_by(SEND_BUDGET, req.deadline_ms);\n        match self.quote(&req, &b) {",
    );
    let e = check_gated_paths_are_bounded(&mutant).unwrap_err();
    assert!(e.contains("AFTER the gate"), "{e}");
}

/// The read BEHIND the gate: the balance read is one call, and "one call" was once the
/// argument for leaving it at the protocol default.
#[test]
fn the_read_behind_the_gate_is_bounded_too() {
    let mutant = mutate(
        GLUE,
        ".get_balance_with_timeout(chain_id as i64, address, t)",
        ".get_balance(chain_id as i64, address)",
    );
    let e = check_calls_are_bounded(&mutant).unwrap_err();
    assert!(e.contains("eth_rpc_module.get_balance with no deadline"), "{e}");
}

// ---------------------------------------------------------------------------------------
// 11. Nothing broadcasts through a gate that has closed.
// ---------------------------------------------------------------------------------------

/// `send` passes the gate and the job then sits `awaitingApproval` while a human decides —
/// seconds to minutes. If the proxy goes unusable in there, or the mode flips to `required`,
/// the poll that finally broadcasts must re-check, as late as a check can be and still be in
/// front of the money. And its refusal touches NOTHING: no claim, no record, no settle, so
/// the job stays `awaitingApproval` with its nonces reserved and the next poll resumes it.
fn check_the_broadcast_is_gated(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let fns = functions(&code);
    let body = bodies_of(&fns, &code, "advance_send")[0];
    let gate = body.find("verified_gate_within").ok_or(
        "`advance_send` reaches `broadcast` with no verified gate. The gate `send` passed can \
         close while a human is approving, and this is the poll that moves the money.",
    )?;
    let claim = body.find("claim_broadcast").ok_or("`advance_send` no longer claims the broadcast")?;
    if gate > claim {
        return Err("`advance_send` gates AFTER the broadcast is claimed, so the claim is \
                    taken on a route the gate would refuse."
            .into());
    }
    let arm = &body[gate..block_end(body, gate)];
    for (touch, why) in [
        ("claim_broadcast", "claims the broadcast"),
        ("record_intent", "writes the write-ahead record"),
        ("settle", "settles the job"),
    ] {
        if arm.contains(touch) {
            return Err(format!(
                "the refusal arm {why}. A closed gate is not a failed send — the transaction \
                 never left — so the job keeps its nonces and stays resumable."
            ));
        }
    }
    if arm.contains("blocked(") {
        return Err("the refusal answers `ok: false`, which a poller reads as a failed send: \
                    it drops the request id and orphans a job still holding its nonces. \
                    `held_by_the_gate` is the shape that keeps the poll coming back."
            .into());
    }
    if !arm.contains("job_reply") {
        return Err("the refusal does not answer with the job as it stands, so a poller cannot \
                    tell a held send from a lost one"
            .into());
    }
    Ok(())
}

#[test]
fn the_broadcast_is_gated_and_a_refusal_leaves_the_send_resumable() {
    check_the_broadcast_is_gated(GLUE).unwrap();
}

#[test]
fn an_ungated_broadcast_is_caught() {
    let mutant = mutate(GLUE, "self.verified_gate_within(job.chain_id, &b)", "Ok::<(), Value>(())");
    let e = check_the_broadcast_is_gated(&mutant).unwrap_err();
    assert!(e.contains("no verified gate"), "{e}");
}

/// The gate present but behind the claim: the job is unsettleable by anyone but the ticket
/// holder before anything asks whether the send may go out at all.
#[test]
fn a_gate_taken_after_the_claim_is_caught() {
    const ARM: &str = "if let Err(v) = self.verified_gate_within(job.chain_id, &b) {\n            // Re-read: a cancel may have landed while the probe was out.\n            let now_job = st.sends.get(request_id).unwrap_or(job);\n            return Ok(verified::held_by_the_gate(&Self::job_reply(&now_job, now), &v));\n        }\n";
    let mutant = mutate(GLUE, ARM, "");
    let mutant = mutate(&mutant, "        let mut route: Option<String> = None;", &format!("        {ARM}\n        let mut route: Option<String> = None;"));
    let e = check_the_broadcast_is_gated(&mutant).unwrap_err();
    assert!(e.contains("AFTER the broadcast is claimed"), "{e}");
}

/// The refusal that corrupts the ledger: a closed gate reported as a failed send.
#[test]
fn a_refusal_that_fails_the_send_is_caught() {
    let mutant = mutate(
        GLUE,
        "            let now_job = st.sends.get(request_id).unwrap_or(job);\n            return Ok(verified::held_by_the_gate(&Self::job_reply(&now_job, now), &v));",
        "            let reason = \"the verified proxy is not usable\".to_string();\n            return self.settle(&st, request_id, SendStatus::Failed { reason });",
    );
    let e = check_the_broadcast_is_gated(&mutant).unwrap_err();
    assert!(e.contains("settles the job"), "{e}");
}

/// And the refusal that orphans it: `ok: false` stops the poll, so the job is left
/// non-terminal, holding its nonces, with nothing left driving it.
#[test]
fn a_refusal_that_reads_as_a_failure_is_caught() {
    let mutant = mutate(
        GLUE,
        "            let now_job = st.sends.get(request_id).unwrap_or(job);\n            return Ok(verified::held_by_the_gate(&Self::job_reply(&now_job, now), &v));",
        "            return Ok(blocked(&v));",
    );
    let e = check_the_broadcast_is_gated(&mutant).unwrap_err();
    assert!(e.contains("orphans a job"), "{e}");
}

// ---------------------------------------------------------------------------------------
// 12. Every leg is broadcast in order, and the first that does not land stops the rest.
// ---------------------------------------------------------------------------------------

/// A bundle's legs are signed at consecutive nonces, so the second is dead on arrival if
/// the first never lands. The loop must return from every failure arm rather than carry on
/// to the next leg.
fn check_the_bundle_stops_at_the_first_failure(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let (_, tail) = claim_tail(&code);
    let Some(loop_at) = tail.find("for (i, raw_tx) in signed.iter().take(n).enumerate()") else {
        return Err("advance_send no longer walks the signatures in order".into());
    };
    let body = &tail[loop_at..block_end(&tail, loop_at)];
    // Every settle inside the loop is a failure arm, and every one of them returns.
    for at in sites(body, OWNED) {
        let stmt = &body[at.saturating_sub(40)..at];
        if !stmt.contains("return ") {
            return Err(format!(
                "a failure arm inside the leg loop settles the job and carries on to the next \
                 leg: `{}`",
                body[at..].lines().next().unwrap_or_default().trim()
            ));
        }
    }
    if body.contains("SendStatus::Broadcast") {
        return Err("the bundle is settled `broadcast` inside the loop, before every leg has left"
            .into());
    }
    Ok(())
}

#[test]
fn the_first_leg_that_does_not_land_stops_the_bundle() {
    check_the_bundle_stops_at_the_first_failure(GLUE).unwrap();
}

#[test]
fn a_failure_arm_that_carries_on_to_the_next_leg_is_caught() {
    let mutant = mutate(
        GLUE,
        "                Err(reason) => {\n                    let reason = leg_failure(i, n, &reason);\n                    return self.settle_owned(&st, &ticket, SendStatus::Failed { reason });\n                }\n            };",
        "                Err(reason) => {\n                    let reason = leg_failure(i, n, &reason);\n                    let _ = self.settle_owned(&st, &ticket, SendStatus::Failed { reason });\n                    continue;\n                }\n            };",
    );
    let e = check_the_bundle_stops_at_the_first_failure(&mutant).unwrap_err();
    assert!(e.contains("carries on to the next"), "{e}");
}

// ---------------------------------------------------------------------------------------
// 13. A pinned nonce is priced past what it replaces, before the ether is checked.
// ---------------------------------------------------------------------------------------

/// `quote` refuses a number it saw mined, raises or refuses the fees against what is pending
/// there, and only then reads the balance: the ether check must cover the fees that go out.
fn check_replacement_is_priced_first(src: &str) -> Result<(), String> {
    let code = code_only(src);
    let fns = functions(&code);
    let body = bodies_of(&fns, &code, "quote")[0];
    let at = |needle: &str| body.find(needle).ok_or_else(|| format!("`quote` never calls {needle}"));
    let order = [at("replace::mined(")?, at("replace::floor(")?, at("replace::raise(")?, at("self.reprice(")?];
    let balance = at("self.native_balance(")?;
    if order.windows(2).any(|w| w[0] > w[1]) || order[3] > balance {
        return Err("`quote` reads the balance before the replacement is priced, so the ether \
                    check covers fees that are not the ones that go out"
            .into());
    }
    Ok(())
}

#[test]
fn a_pinned_nonce_is_priced_past_what_it_replaces_before_the_ether_check() {
    check_replacement_is_priced_first(GLUE).unwrap();
}

#[test]
fn a_replacement_priced_at_the_tier_alone_is_caught() {
    let mutant = mutate(
        GLUE,
        "replace::raise(max_fee, max_priority, set_fee, set_tip, &floor, n)?",
        "(max_fee, max_priority)",
    );
    let e = check_replacement_is_priced_first(&mutant).unwrap_err();
    assert!(e.contains("never calls replace::raise("), "{e}");
}

#[test]
fn pinning_a_number_already_mined_unchecked_is_caught() {
    let mutant = mutate(GLUE, "replace::mined(&rows, chain_id, n)", "None::<&TxRecord>");
    let e = check_replacement_is_priced_first(&mutant).unwrap_err();
    assert!(e.contains("never calls replace::mined("), "{e}");
}

#[test]
fn a_balance_read_ahead_of_the_replacement_is_caught() {
    let mutant = mutate(
        GLUE,
        "        let mut replaces = None;\n",
        "        let early = self.native_balance(chain_id, &from.to_string(), b)?;\n        let mut replaces = None;\n",
    );
    let e = check_replacement_is_priced_first(&mutant).unwrap_err();
    assert!(e.contains("reads the balance before the replacement is priced"), "{e}");
}
