# Payments and acknowledgments

How a payment moves on lichen's L2, and why it counts only once its
sender acknowledges it, against an anchor fixed on Bitcoin. With
Bob's payment of 10,000 to Alice on Mutinynet (2026-11-11). The design
and its reasoning are docs/HUB_PROVES_PLAN.md, "Data availability".

## A payment

The L2 is a ledger of notes. A transparent note is an owner's key, a
value and a memo; a shielded one is a commitment to them, opened only to
its owner ([SHIELDED.md](../SHIELDED.md)). A payment spends notes,
each signed by its owner (or, if shielded, proved by the sender's
device), and creates new notes of the same total: one for the payee, and
the sender's change. The sequencer checks it and applies it at once,
then seals the new state into a signed root every few seconds. Its
chain prover proves each sealed height valid
([pipeline.md](pipeline.md)), and it anchors its history on Bitcoin: a
chain of its own transactions, each committing to a hash of the roots up
to a height.

```sh
lichen send <Alice's address> 10000
lichen ack --wait
```

## Why a spend needs the sender's word

An exit judges a claim at an anchored state ([exit.md](exit.md)):
"these notes are mine and unspent at `A*`". The root of each anchor is on
Bitcoin, but the data under it isn't. So an operator could anchor a busy
block and serve none of its data. Every sender in it would then be
stuck:

- **her inputs:** if the anchor holds her payment, they're spent, and a
  claim of them is false;
- **her outputs:** if it doesn't, they don't exist, and a claim of them
  is false.

She can't tell which, and at `T_close` whatever she can't claim defaults
to the hub: the operator's motive. No better data structure fixes this
(a member of any accumulator needs data about the others' changes to
prove membership). What fixes it is an order: inclusion first, which
changes nothing yet; then the sender's signature, given only once she
holds her data, which makes the spend count.

## The rules

**Every spend names a one-time key `ak`,** the sender's, for that spend
only (derived from her wallet's key and the spend's first nullifier, so
unlinkable). Transactions the hub signs (its mints, its exit records)
acknowledge themselves.

**A sealed spend is pending.** It spends its inputs and appends its
outputs, but the outputs are **locked**: no one spends them, the
sender's change included, until the spend is acknowledged.

**The sender acknowledges against an anchor.** Once an anchor at or above
the spend's height is recorded on the L2, which the sequencer does only
once it is the margin deep on Bitcoin (20 blocks on Mutinynet), her
wallet checks:

- the anchor on Bitcoin, from its own view of the chain;
- the sequencer's state, against the roots it signed;
- that the roots from her spend's block to the anchor hash-chain to the
  history the anchor commits.

Then it signs the **acknowledgment**, `H("lichen/ack" ‖ txid ‖ a ‖
hist_a)` under `ak`, naming the anchor's height `a` and its history
`hist_a`, and sends it to the sequencer. The sequencer applies it: the
spend counts, and its outputs unlock.

**An exit can void a pending spend.** If the sender claims the inputs of
a spend she hasn't acknowledged, the exit record that pays her voids it:
its outputs locked for good, a later acknowledgment refused. And the
sequencer refuses to acknowledge a spend whose inputs a request on
Bitcoin claims: the earlier of an exit and an acknowledgment wins.

**The chain guest enforces all of it,** in the spent set: each spend's
pending entry, each output's lock, each acknowledgment, each void and
each anchor's history, under keys of their own.

## Bob's payment, on Mutinynet

Bob had received 30,000 from Alice. He paid Alice 10,000 of it, just
after the sequencer had broadcast an anchor, so his payment waited for
the next one: the worst case, two anchors.

| block | time (UTC) | what |
|---|---|---|
| 3,580,067 | 02:20:21 | Bob sends 10,000 to Alice: sealed at once, its two outputs (Alice's 10,000, his change of 20,000) locked |
| 3,580,068 | | [anchor 37](https://mutinynet.com/tx/1f5f8f27313e727616f7e7cad4233479bc6448d1e17bae163f02357225494ed2) confirms, broadcast just before his payment was sealed: it doesn't hold it |
| 3,580,087 | 02:30:25 | anchor 37 is 20 deep: the sequencer records it, and sends [anchor 43](https://mutinynet.com/tx/5bdd93d58879578523c30a8ec22834312801275864db84edbc52971b8aa119cc), which holds Bob's payment |
| 3,580,088 | | anchor 43 confirms (269 vB, fee 540) |
| 3,580,106 | 02:40:41 | anchor 43 is the margin deep and recorded; Bob's wallet checks it and acknowledges; the sequencer applies it: his payment counts, and both outputs unlock |

**39 blocks, 20 minutes,** from sending to firm. A payment sealed just
before an anchor's broadcast waits one margin instead: Cleo's payment to
Bob in the same run, sent at 02:20:02, was acknowledged at block
3,580,087, 21 blocks and 10 minutes later. On mainnet, with a margin of
6 blocks and anchors every few blocks, that is about one to two hours.

Alice's wallet shows the note as soon as the payment is sealed, but as
locked until Bob acknowledges: `lichen balance` counts locked notes,
and a spend or a claim takes only unlocked ones.

## Who is protected, and how

| collusion | what they try | what happens |
|---|---|---|
| the operator, against Alice | anchor her payment and withhold its data | she never acknowledges; the payment counts for nothing, and her inputs stay hers to claim. A stall, not a theft |
| Alice and the operator, against Bob | the operator never sequences her acknowledgment, and she claims her inputs | the exit record voids her payment, and Bob's note with it. Bob never counted the payment: it wasn't acknowledged |
| Alice and Bob, against the hub | she gives her acknowledgment to Bob alone, and claims her inputs | the hub can't refute her claim, and pays; its exit record voids the payment, so Bob's claim of his note fails as voided. The hub pays once |
| Alice, against the hub | she claims her inputs through one contract and her acknowledged change through another | her acknowledgment, posted in the one, is the hub's evidence that the inputs are spent, against the other |

**A payee who waits for the acknowledgment to be sequenced is safe
against any collusion.** It is sequenced only once its anchor is the
margin deep, and from then no exit can void the spend. Before that he
holds a soft payment: the sequencer's word, then Alice's acknowledgment,
which leaves him trusting that she and the operator don't collude.

## What it costs

- **Time.** A payment is firm, and spendable onward, once its anchor is
  the margin deep and the acknowledgment sequenced: 10 to 20 minutes on Mutinynet, as
  Bob's and Cleo's were.
  On mainnet, with a margin of 6 blocks, about an hour. There are no
  fast onward transfers in this version: softer finality (spends of
  locked outputs that count only if their parents do, as with
  unconfirmed Bitcoin outputs) is for later.
- **Presence.** The sender is online until the anchor after her payment
  is the margin deep. If she goes away first, her payment waits; it
  counts for nothing, her inputs stay claimable, and she acknowledges on
  her return.
- **Proving.** An acknowledgment is about one BIP340 signature in the
  chain guest, some 260k cycles, and a few accesses of the spent set. A
  payment and its acknowledgment cost about 0.84M cycles of the chain's
  proof, one segment.
- **On chain:** nothing in normal operation. An exit that claims a
  locked note carries the acknowledgment in `request`'s witness: under
  20 vB.

## Shielded payments

A shielded spend names `ak` as a public input of its proof, and is
acknowledged the same way. Its proof is made on the sender's device:
Sara's shield of 90,000 sats into a shielded note took **3.0 s** on a
Mac (14.6k cycles); a payment of two inputs and two outputs takes 23 to
110 s. A shielded input's lock is the wallet's and the sequencer's to
keep, since its position is private.
