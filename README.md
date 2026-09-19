# tx_sender_module

The one EVM transaction sender on the device.

Any module — a wallet, a swap app, a bridge, anything that wants a transaction to leave an
account the keystore holds — hands this module a **bundle** of calls from one account on one
chain. It prices them through `fee_module`, reserves their nonces in the one ledger, asks
`keystore_module` for **one** human approval over every call, broadcasts the signatures in
order through `eth_rpc_module`, records each call **before** it leaves, and polls the
receipts. A dapp app depends on this module and nothing else to move money.

There is one of these per device for the same reason there is one keystore: two senders
both read the account's nonce at `latest` — the verified proxy refuses the `pending` tag —
so a wallet send awaiting approval and a swap from the same account would collide silently,
and one of the two transactions would be lost.

## What this module is not allowed to do

- **It never sees key material.** Signatures are requested from `keystore_module` and
  authorised by a human in `evm_signer_ui` (or `evm_signer_cli`). `fetch_result` hands the
  signed bytes back to this module alone, because it holds the receipt the keystore issued.
- **It never chooses a chain.** Every request carries its `chainId`. There is no active
  network here — a wallet has one, a bridge has two, and neither is this module's business.
- **It never interprets a call.** `data` is bytes the human approves; `label`, `purpose` and
  `meta` are the requester's own words, stored verbatim and returned verbatim. A token
  amount inside `meta` is the consumer's to render.
- **It never reads the caller for anything but a name.** The runtime attests which module
  asked; that name goes onto the claim line the signer shows and onto every history row as
  `origin`. Nothing is gated on it.
- **It never fetches a price, opens an explorer, or reads a chain it was not asked about.**

## The contract

Every reply is `{ ok: true, … }` or `{ ok: false, error }`. Numbers cross as decimal strings
unless a field is documented as hex; `gasLimit` is a JSON number.

### `prepare(request_json)` — price without doing anything

```json
{ "chainId": 1, "from": "0x…",
  "calls": [ { "to": "0x…", "value": "0x0", "data": "0x095ea7b3…",
               "label": "Approve USDC", "meta": { "kind": "approve", "amount": "1000000" } },
             { "to": "0x…", "value": "0x0", "data": "0x5ae401dc…", "label": "Swap" } ],
  "tier": "normal", "maxFeePerGas": "…", "maxPriorityFeePerGas": "…",
  "nonce": 7, "deadlineMs": 12000 }
```

- 1 to 8 calls. `value` is wei (absent = 0); `data` is `0x`-hex calldata (absent = a plain
  transfer). `label` ≤ 120 bytes, `meta` an object ≤ 4 KiB, `purpose` ≤ 256 bytes.
- **One fee for the bundle, one estimate for the bundle.** `fee_module` prices every call
  in one pass and sets `maxFeePerGas` and `maxPriorityFeePerGas` for all of them; every
  ceiling is that fee times each call's limit. `tier`, or an explicit pair, overrules the
  suggestion.
- **A call behind an ERC-20 `approve` is estimated with that approval applied.** The
  estimator models an earlier call's `approve(spender, amount)` as a state override on the
  token's allowance slot, so a swap behind its approval gets a real limit and a USDT-style
  reset-then-set is estimated with the reset in place. A call whose own `gasLimit` is given
  is taken as given. A call that depends on any other earlier effect must carry one; a
  failed estimate on a limitless call refuses the bundle naming the call. The reply's
  `assumptions` list what the estimate took for granted.
- `nonce` pins a **single** call onto a number to replace a transaction that already left. A
  bundle cannot be pinned. A node keeps the pending transaction unless its replacement pays
  more on both fee fields, and at least 10% more, so a suggested fee is raised past whatever
  this module still has pending at that number, and the reply names it under `replaces`. A fee
  the caller set is used as given, or refused if a node would refuse it. A number this module
  saw mined is refused outright: a send pinned to it could only fail after the approval.
- `deadlineMs` shrinks this method's own allowance (18 s) to what the caller will wait, so
  the reply's error sentence comes home rather than a bare transport timeout.

Reply: `{ ok, chainId, from, nonce, legs: [{ to, value, data, gasLimit, gasSource, label }],
valueWei(+Display/Exact), maxFeePerGas, maxPriorityFeePerGas, gasLimit, feeCeilingWei(+…),
maxCostWei(+…), assumptions, nativeSymbol?, replaces?, feeSource, route, feeRoute }`. `feeCeilingWei`
is Σ `maxFeePerGas × gasLimit` as `fee_module` answered it, wei and native unit alike — a
ceiling, never a price; `gasSource` is `given`, `estimated` or `simulated`. The ether check is `value` plus
that ceiling against the account's balance; a token the calls move is the requester's own
knowledge and is not checked here. Reserves nothing; safe on every keystroke.

### `send(request_json)` — ask a human

The same request plus `purpose`, one line. Reserves one nonce per call under the ledger,
registers one keystore approval whose legs are the calls in order, and answers
`{ ok, pending: true, requestId, handle }` — **never a hash**. The signer shows

```
Requested by: tx_sender_module
Purpose (claimed by the requester): <purpose> [asked by <origin>]
Account: 0x…
2 item(s) to sign:
  [1] Transaction on chain 1  To: … Nonce: … Selector: 0x095ea7b3 Data: 0x…
  [2] Transaction on chain 1  To: … Nonce: … Selector: 0x04e45aaf Data: 0x…
```

`handle` is the keystore's name for the record: a `ui_qml` app hands it to the signer with
`logos.request("evm.signing.approve", { handle })`. `origin` is the module the runtime says
asked — the wallet backend, the swap app — so the human sees who, beneath a requester that is
always this module.

### `send_status(request_id)` — the broadcast

Poll it. There is no background advancer: the first poll after the approval collects every
signature, then for each call **in order** writes the row, burns the nonce, broadcasts,
and takes the hash. The first call that does not land stops the rest: its row stays
`unknown` with the node's reason, its nonce stays burnt, and the calls after it — never
sent — hand their numbers back.

`{ ok, requestId, handle, chainId, from, status, final, origin, purpose, legs: [{ to, nonce,
label, hash?, left }], hashes, hash?, route?, reason? }` with `status` one of
`awaitingApproval`, `broadcasting`, `stuck`, `broadcast`, `rejected`, `cancelled`, `failed`.
A reply carrying `blocked: true` is a send **held** by the verified-proxy gate, not a failed
one: the nonces stay reserved and the next poll sends it once the proxy is usable.

**Poll until `final` is true.** It is false while the send is `awaitingApproval` (held or
not) or `broadcasting`, and true for every other status — `stuck` included, because no poll
can move a broadcast that has not answered. A refusal is `{ ok: false, error, final }`, and
it is final only when this module holds no send with that id. Every other refusal — a
budget spent, a keystore hop that failed — may pass on the next poll: a consumer that stops
on `ok: false` leaves an approved send that is never broadcast.

### `cancel_send(request_id)` · `live_sends()`

Withdraw a send nobody has approved yet; its nonces come back, and the reply is the send as
`send_status` reports it, `cancelled` and final. Refused once the broadcast is claimed: the
poll says how that send ends. `live_sends` lists every send that could still move and is not
stuck, which is every send whose `final` is false: what a wallet asks before switching
networks.

### `history(address, chain_id)` · `refresh_pending` · `refresh_tx_status` · `tx_details`

The transactions this module broadcast for `address` on `chain_id` (0 = every chain),
newest first, one row per call. Rows carry the requester's `label`, `purpose`, `origin`,
`meta`, `leg`/`legs`, the approved fee fields, the receipt fields, and decoration: ether at
18 places, gas prices in gwei, EIP-55 addresses, ERC-20 `Transfer` logs decoded to the raw
integer. **No token is ever scaled here**: a consumer that knows the contract decorates the
transfer or the `meta` it stored. `unresolved` names every row whose outcome never came
back and the nonce it is holding; `strandedNonces` the numbers a duplicate request id
leaked. `history` and `refresh_pending` sweep due receipts on each row's own chain; the
other two are one row on demand.

### Events

`send_status_changed(requestId)`, `tx_status_changed(hash)`, `history_changed(address)` —
announced on a change, after the write, never on a read.

## How a dapp sends

```
uniswap_module.build_swap(…)                 → calls (approve?, swap)
tx_sender_module.prepare({ chainId, from, calls, tier })   → fee figures for the screen,
                                               the swap estimated behind its approval
tx_sender_module.send({ …, purpose })        → { requestId, handle }
logos.request("evm.signing.approve", { handle })           → the signer takes the password
tx_sender_module.send_status(requestId)      → poll every ~1.5 s until "final": true
tx_sender_module.history(from, chainId)      → the rows, with your meta back
```

The wallet backend is the same kind of consumer: a plain transfer is a one-call bundle with
`meta.kind = "native" | "erc20"`.

## Nonces

The ledger is in memory and seeded at startup from every unsettled row on disk. A claim
holds its numbers until the approval is registered, then the job holds them; a leg's number
is **burnt** the instant its bytes are about to leave and never released; a leg that never
left hands its number back when the bundle settles. The invariant — every held number is
reserved, at most one holder of a number is not an explicit replacement — is audited on
every release of the ledger's lock and enumerated over half a million short histories in
`send.rs`. A number a dead process left behind can be pinned by the next one; the
`unresolved` entries tell the user which.

## Building and testing

```bash
cargo test --no-default-features --manifest-path rust-lib/Cargo.toml   # pure cores + guards
nix build .#default                                                    # the module
nix build .#install                                                    # staged for logoscore
doctests/run.sh                                                        # Anvil, headless, two-call bundle
```

The five files under `rust-lib/tests/` read `glue.rs` as text and pin its shape: no call
under a lock, every call bounded or argued for, the record before the bytes, the burn before
the broadcast, the ticket as the only key past the claim, the first failed leg stopping the
rest. Each ships with the mutant it rejects. `doctests/headless-bundle.test.yaml` drives a
two-call bundle end to end on a local Anvil with nothing but `logosctl`.

History files live under this module's instance directory; a wallet that recorded its own
rows before this module existed does not migrate them.
