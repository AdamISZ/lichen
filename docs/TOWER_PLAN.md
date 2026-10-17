# A turnkey tower: plan

2026-10-17. The next step after the per-move windows. Background, the
business side and the general pattern: ln-gap's
`docs/planning/TURNKEY_TOWER.md` (2026-10-12, local notes); the paper's
Watchtowers section.

## What it is

Alice's own instance of her dispute, on a machine she rents (an x86
VPS), started when the hub refuses a withdrawal and torn down after.
Not a service watching on her behalf: only Alice starts a dispute (the
hub refuses and challenges, it never claims), so nothing needs watching
until she asks.

It does everything after the refusal: the proof, the dispute, the
liveness. A machine that can prove (a STARK, then the Groth16 wrap on
x86) is already more than a typical user's setup, so the tower carries
it rather than leaving it to her:

1. builds the withdrawal statement's input from the sequencer's public
   state (her return's note, its path, the signed root: what `lichen
   withdraw-input` prints);
2. proves it and wraps the proof (ln-gap's `lngap-r0 claim`: 446k
   cycles, about 2.5 min and 4.8 GB on a 12-core x86 laptop, the wrap
   about 2 min more);
3. runs her side of the search (the traced verifier, a few minutes);
4. escalates, publishes her input, and answers each of the hub's moves
   within her window `w_A`, through any read challenge, to the payout.

What Alice does on her own device: the return of `b` on the L2 (her L2
key signs it, and it never leaves her device), the cooperative attempt
the hub refuses, and the export of the package below.

## Chain access: two Esplora endpoints, confirmed moves only

A cold-started node can't sync within a dispute, and a turnkey box
shouldn't carry one. The wallet already reads Bitcoin through Esplora
(`Chain::esplora`, `--esplora`), and that is the tower's backend, with
two independent endpoints instead of one, under these rules:

- **Answer only a move confirmed in a block, as both endpoints report it**
  (the same block, the same wtxid). A link's txid doesn't commit to its
  witness, where the move is, so a lying explorer colluding with the hub
  could show a move the hub signed but never broadcast. Had the tower
  answered it, the hub would hold Alice's signature on that answer and,
  once it posts its real move and she answers that, two of her
  signatures under one key: `equiv_d`, and the hub takes the contract. A
  move in a block with proof of work, seen the same by two explorers,
  can't be faked that way. (The wallet today waits for confirmation, but
  as one Esplora reports it.)
- **Broadcast to both.** A premature timeout is rejected by the network,
  so reading heights from the higher-reporting endpoint costs at most a
  retry.
- **Find spends with Esplora's outspends**, rather than inferring "spent,
  not by the link" as the wallet does now.
- **Alarm** when the endpoints disagree (heights apart by more than a
  few blocks, a transaction one has and the other hasn't a block later),
  or when a window is running out.
- **Poll within public rate limits.**

Later, and only if wanted: a BIP157/158 light client (compact block
filters, e.g. the `kyoto` crate) syncing headers from a checkpoint (the
contract's funding block: a few hundred headers), which would leave
nothing to believe but proof of work.

## The activation package

What Alice's wallet exports once the hub has refused:

| item | why | secret? |
|---|---|---|
| the contract record (the pre-signed set, both parties' signatures) | every link and terminal | no |
| the statement's id; her return's note index and amount `b` | to build the input and prove | no (the ledger is public) |
| the sequencer's URL | the note's path and the signed root | no |
| her input-word secrets, except `b`'s; her signature on `b` | to sign the escalation and `inputs` | yes: this contract's only |
| her move secrets (depths 3, 5, …, `m`), her hop secrets | to sign each move | yes: this contract's only |
| the fee budget's key | the terminals' fee inputs (and, with the TODO below, the links' bumps) | yes: bounded by the budget |
| the two endpoints | | no |

Her signature on `b` (a one-time signature, deterministic) goes instead
of `b`'s key, so the tower can't claim a different amount; any other
word it signed wrongly would only fail the claim. Each one-time secret
is its own hash (`SHA256("lngap-seed/" + "{contract_seed}/move/{d}/{f}")`,
and `/input/{j}`, `/hop/{k}`), so exporting them one by one exposes
nothing else: no change to the derivation, and existing contracts can be
delegated.

The tower stops at the payout. Her bit outputs and the reserves wait `δ`
for her own key (`alice_bit_i`, `alice_reserve`), and nothing races her
for them unless she signed two values of `b`, which the tower can't. She
sweeps when she is back.

### TODO: fee bumps need their own key

`Wallet::post` signs each link's fee child with
`contract_keys(nonce).payment`, the key that also sweeps her winnings.
Until links get a separate anchor key (`PartyPubKeys` gains it in
ln-gap's `lngap_channel`, `anchor_tree` uses it, the opening exchanges
it; contracts opened after), the package holds no `payment` key and the
tower posts each link at its floor (1 sat/vB, out of the contract): enough
on the test networks, not under congestion. Terminals already take their
fee from the budget's key.

### What a compromised tower can do

Sign a wrong move (the hub disproves it), sign two values (`equiv_d`,
the hub takes it), go silent (a timeout), spend the fee budget, read
her return's details (public anyway). Every loss is the hub's gain,
bounded by this contract; anything but silence is attributable, since
the honest moves are a function of public data.

## Redundancy

Honest moves are deterministic (one-time signatures, the 2-of-2
signatures made at the opening), so her laptop and a tower, or two
towers, can run at once: whichever acts first, the other finds the same
link on chain (the wallet already checks a posted link is "the move
replayed"). The confirmed-only rule keeps this safe across explorers.
Proving isn't deterministic in its bytes, but only one claim reaches
the chain: the escalation, after which every instance reads it.

## Packaging

- One x86 image: the `lichen` wallet, BitVMX's verifier ELF, ln-gap's
  `lngap-r0` with RISC Zero's prover, and the Groth16 wrap. The wrap
  runs RISC Zero's prover image today, so the container needs the
  host's Docker socket, or that prover's binaries bundled (better).
- `lichen tower --package <file> --esplora <url>,<url>`, its state on a
  volume: the claim once proved, the position in the search (the trace
  can be recomputed).
- A one-click launch on a VPS: a cloud-init script that installs Docker,
  pulls the image and starts it with the package (pasted, or fetched
  encrypted).
- Notifications: progress and alarms to Alice (a webhook, ntfy).
- Size: 8 GB of memory at least (the proof's 4.8 GB, the wrap's few);
  proving and the traced run to measure on a small VPS.

## Phases

1. **Done (2026-10-17).** The dispute loop is now an engine
   (`lichen_wallet::engine`) over a `Signer` (the wallet's derived
   secrets, or a package's) and a `Store` (the wallet's contract, or a
   state file beside the package); `Wallet::dispute` drives it and
   sweeps a win. `lichen export-dispute <cid> --out <file>`, `lichen tower
   --package <file>` (no wallet), `lichen sweep-dispute <cid>
   --tower-state <file>`. Test `crates/hub/tests/tower.rs`: refused,
   exported (no payment key, no key for `b`'s word), the tower plays a
   whole search at its floors and proves, resumes to the payout, the
   wallet sweeps. The package is 2.3 MB on the mock, nearly all of it the
   record's pre-signed signatures.

   The plan as written: **a headless dispute from a package, with a ready claim.**
   `lichen export-dispute <cid>` and `lichen tower <package>`: the
   wallet's dispute loop without the wallet. Test on regtest (mock
   statement): the wallet returns `b` and is refused, exports, stops;
   the tower escalates and plays to the payout; the wallet sweeps.
2. **Proving in the tower:** the input from the sequencer, `lngap-r0
   claim` (the STARK and the wrap), on x86. Test: the Groth16 statement
   end to end on a Linux box, from the package alone.
3. **Done (2026-10-17).** `Chain::esploras(&[urls])` (`lichen_chain::
   Endpoints`), the wallet's `--esplora a,b`: confirmed only when every
   server says so in the same block (else an error), a transaction read
   only if every server that has it gives the same wtxid (else none, and
   an alarm), spent only when all agree, the highest height, broadcast to
   all; disagreements printed as `chain: ALARM`. Test (`chain/tests/
   esplora.rs`, two_servers_neither_trusted_alone): a proxy in front of
   electrs serving a funding with another witness (read as unknown), or
   placing it in another block (confirmation refused). Not yet: outspends
   to find a spender (the engine still infers "spent, not by the link").

   The plan as written: **two Esplora endpoints** with the rules above. Test: a stub endpoint
   serving a move the hub signed but didn't broadcast is ignored;
   endpoints that disagree raise the alarm.
4. **The image and the one-click launch;** a Mutinynet trial: the laptop
   is refused, exports and closes, a VPS proves and plays to the end.
5. Later: the separate anchor key (the TODO above); the BIP157 client;
   the business side (insurance, a contingent fee: the notes).

## Open questions

- Endpoints: on Mutinynet the trial may name mutinynet.com twice (the
  rules are exercised, not the independence); mempool.space and
  blockstream.info for signet and testnet4.
- The middle tier: the tower proves and computes, she signs each move
  from her phone. Viable only if `w_A` is long against how often a phone
  wakes.
- Delivering the package: a file, an encrypted blob through a relay, a
  QR code.
- The VPS's size and cost for the proof and the wrap; whether the wrap
  is better rented separately (stateless, trustless) when the tower runs
  on something small.
