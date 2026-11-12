# Forward: a long-running public testnet, and what comes after

Working notes (2026-11-12). The aim: a simple, long-running test
deployment on which people use lichen from a phone or a laptop, pay
realistic fees, and can provoke every kind of dispute on demand. Then
the research question of what the L2 should become (smart contracts or
shielded notes).

## Status (2026-11-12)

Done first, at the user's request, for dogfooding on a phone (the app
itself is lichen-gui's, kept out of this repo):

- an Android app (Tauri) and a Mac app over the wallet library; a
  contract opened from each, and payments between a phone and a Mac;
- the hub and sequencer behind TLS: `https://thimbly.org/lichen/<network>/`
  `{hub,sequencer}` (Caddy on babilonia's relay, proxying to lichen-hub);
  Mutinynet live, signet's node syncing (its services need coins);
- in the wallet library: `Wallet::opening` (an opening's steps, typed, for
  a front end), `Wallet::unacknowledged` (an app acknowledges by itself),
  the anchors checked kept in the wallet's file (56 s to 3.5 s a run);
- in the app: an opening shown as steps, a phone-first page, presets with
  pinned keys, backup and restore through the file picker.

Next, in the order below: fees (step 1), disputes on demand (step 2), the
tower and addresses (step 3).

## 1. Fees, user-chosen duration, transparent only

One guest change; new guest ids and a redeploy of lichen-hub (contract
1007 stays on `lichen:v0.4.4`).

- **Liquidity fee per unit time.** The hub quotes a rate per year (ppm
  of the liquidity a year; 0.1% for 6 months is 2,000 ppm/yr). The fee is
  `liquidity × rate × duration / year`, paid upfront from the deposit, as
  `fee_ppm` is now. No refund for leaving early.
- **The user picks the duration.** It's already a per-contract
  parameter; today the hub fixes it at `default_duration` (a week). The
  wallet asks for one between the network's minimum (raise Mutinynet's
  from a day to a week) and the hub's maximum; `/info` carries the rate
  and both bounds. Check: anything relative (CSV) derived from the
  duration must stay within 65,535 blocks: about 22 days on Mutinynet,
  so 6 months there must be absolute heights only.
- **A fee per transaction, burned.** A transaction's outputs may sum to
  less than its inputs, and the difference is burned. Burning is the
  hub's revenue exactly: it issues the tokens, so a burned token is a
  liability gone. No fee output, no hub account on the L2.
  - guest: `Unbalanced` becomes inputs ≥ outputs;
  - sequencer policy, not a guest rule: at least 10 sats (tunable with
    no new guest), advertised in `/info`;
  - the wallet adds it to every send;
  - acks need none (they're bounded by paid spends); mints and exit
    records are the hub's.
- **Transparent only.** A deployment flag: the sequencer refuses
  shielded spends, `/info` says so, and the wallet hides the shielded
  address and sends. The shielded code stays.
- Docs: USE_A_WALLET (fees, duration), RUN_A_HUB (the rate, the
  minimum fee, the flag), and the smoke test.

## 2. Disputes on demand

The switches exist (`refuse_folds`, `forge_assertions`, `hold_defaults`,
`opening_fault`) but are global, for the whole hub. Make them per
contract and the user's to ask for:

- `POST /misbehave {cid, mode}`, signed by the contract's user key, on
  test networks only (the hub already asserts that). Nobody can make the
  hub cheat someone else.
- Modes, one for each ending in the main paper's Table 1, plus the
  stall:
  1. refuse my cooperative withdrawal: I exit, and the hub concedes;
  2. ignore my claim: never answered;
  3. contest my true claim with a forged proof: Kim's path, 4 txs;
  4. the sequencer won't sequence my acknowledgment: a stall, not a
     theft.
- The user's side: the wallet can make a **false** claim (a note paid
  away), so that the hub's real proof runs. About 18 minutes of CPU on
  lichen-hub (827 s + 268 s): rate-limited.
- The requested modes are public (in `/info` or `GET /misbehave/<cid>`),
  so anyone can see the cheating was asked for.
- A wallet command for each (and later a panel in the app); an explainer
  page: what each mode exercises and what the user should see on chain.

## 3. The sender's liveness, and addresses

The receiver needn't be online now: the sequencer's state is public, and
Bob's wallet finds his notes whenever he looks. The **sender** must be:
she acknowledges once the anchor after her payment is the margin deep
(about 20 minutes on Mutinynet, an hour on mainnet), and until then the
payment is soft and her change locked. A phone can't be relied on for
that.

- **Delegated acknowledgment.** `ak` is a one-time key per spend, so
  Alice can hand its secret to a tower (anyone, or her own always-on
  box) without handing over any funds. The tower acks when the anchor is
  deep and it has checked the data, as her wallet would. Its only extra
  power is to ack blind, before the data is served; colluding with the
  operator, that puts this payment's change at risk, nothing else.
  **To verify** before building: that bound, against the claim's need
  for positions (`E`'s contents).
- Option: hand `ak` to the payee instead, who wants the payment to count;
  for a payment with no change, Alice risks nothing.
- **One tower:** the same service watches her contracts for disputes
  (the keyless tower: it holds no keys that move funds). The phone
  wallet depends on it (step 4).
- **Addresses:** bech32m, with a network prefix and the deployment id
  (no paying into the wrong deployment); a payment request (amount,
  memo) as a URI and a QR code.

## 4. The wallet app (Tauri: desktop and Android)

One Tauri 2 project: the wallet library in Rust, an HTML/JS UI with a
mobile layout. macOS, Linux and Windows desktop apps, and an Android APK
(sideloaded; no store). iOS later: it needs a Mac with Xcode and an Apple
developer account to reach testers.

- **First, a build test:** `cargo build --target aarch64-linux-android
  -p lichen-wallet` with the NDK. The tree looks portable: no RISC Zero,
  no OpenSSL (rustls with ring, which builds for Android with the NDK),
  the rest pure Rust. Trim `bitcoincore-rpc` from the wallet's tree.
- **Opening on the phone itself.** Garbling is 9.5 s for 78 instances on
  the laptop (about 1.2 s an instance on one core: blake3 and BN254
  arithmetic, both fine on ARM); a flagship phone perhaps 15–25 s, a
  mid-range one 30–60 s (to measure). The 243 MB upload is what takes
  time: 50 s at 40 Mbit/s up, 3 minutes at 10. So:
  - a resumable upload in the background, per instance (each kept
    instance is already its own POST), preferably on Wi-Fi;
  - perhaps keep fewer instances for the same 40 bits:

    | kept | garbled | upload | garbling |
    |---|---|---|---|
    | 10 (today) | 78 | 243 MB | 1× |
    | 8 | 124 | 194 MB | 1.6× |
    | 6 | 307 | 146 MB | 3.9× |

  - and look at what makes up an instance's 24 MB (AND ciphertexts, DRE
    entries) for a cut. The ciphertexts don't compress.
- **Contracts move between devices.** After opening, Alice keeps a seed
  and the contract's record and pre-signed transactions: kilobytes. An
  export/import, by file or QR, is the backup and restore too. One device
  active at a time (two sending at once just has one refused).
- **The hub and sequencer behind TLS** (Caddy): Android refuses
  cleartext HTTP by default.
- **Paying the deposit** from another wallet app: a BIP21 URI and QR.
- Screens: setup (hub, fee quote for a chosen duration, deposit),
  balance, send, receive (QR), withdraw, exit, the dispute modes of
  step 2, the tower.
- **Where it lives:** lichen-gui is local by the user's choice; an app
  for public testers belongs in lichen or its own public repo (the
  user's call).

## 5. Smart contracts or shielded notes (research, in parallel)

The question is the exit model more than the proving. Lichen's guarantee
is per owner: "these notes are mine at A*", refuted or paid, up to her
cap. Value inside a contract (a pool, an escrow) belongs to no one key:
Plasma's "unowned state", and why it never had general contracts
(Buterin, "Exit games for EVM validiums: the return of Plasma", 2023).

| | apps | the exit model | proving |
|---|---|---|---|
| EVM (revm in the chain guest, as Zeth in RISC Zero) | the most: Solidity, tooling | owned balances, yes; value in contracts only while the L2 is live, unless contracts map their holdings to owners | 10–50× today's payment (guess), so a GPU a height |
| eUTXO scripts (notes with spending predicates; Nervos CKB's RISC-V VM) | fewer, harder to write | yes: state stays owned, a shared note claimable by its script's parties | modest |
| shielded notes (built) | privacy | yes | the client proves |

A research note (docs/CONTRACTS_PLAN.md) answering:

1. what an exit of contract-held value is under each model, and what the
   hub's cap means for it;
2. measured cycles in our guest, on lichen-vps (short runs): a revm ERC20
   transfer and a swap, against the 0.84M of a payment and its
   acknowledgment today;
3. the precedents: Zeth, RSP, Kailua for EVM in a zkVM; CKB and
   Cardano for eUTXO; Intmax2 for a stateless design.

Transparent first is the right base either way: EVM would replace the
ledger, eUTXO extend it.

## Order

1 → 2 → 3 → 4, with 5 alongside. Step 4's build test can go early: it
says whether Tauri on Android is straightforward before 3 is designed
around it.
