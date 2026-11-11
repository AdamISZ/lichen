# Shielded transfers

An example L2 for lichen: payments whose amounts
and parties are hidden, Zcash-style, with every block proved valid so
that a withdrawal enforced on Bitcoin rests on a history anyone can
check. It is a demonstration that lichen's contracts work under a
private L2. It is not a production system.

## What it is

The sequencer's ledger holds two kinds of note in one Merkle tree:

- **transparent notes**, whose owner and amount are public: the hub's
  mints (your deposit's tokens), and any you pay or keep transparent;
- **shielded notes**: only a hash of each is public. The owner and the
  amount are inside it.

A deposit's life on the L2:

```
Bitcoin deposit ──▶ mint (transparent, to you)
                      │ shield
                      ▼
                 shielded note ──send──▶ shielded notes of others ──send──▶ …
                      │
                      ▼
            a claim of your notes, shielded or not: withdraw
            cooperatively, or exit on Bitcoin
```

The wallet's commands are `shield <amount>`, `unshield <amount>`, `send
<shielded address> <amount>` and `balance`, which shows both kinds. `address --shielded` prints your shielded address (`lichen
--help` lists them all).

Three kinds of proof, all RISC Zero:

| proof | made by | when | shows |
|---|---|---|---|
| spend | the sender, on their own machine | every shielded transaction | the notes spent exist, are yours, and are unspent; the amounts balance. The sequencer checks it without learning the notes |
| chain | the sequencer's prover | every sealed height | this block is valid, and so was the history before it |
| the hub's statement | the hub | only when a user's exit claim is false | the claim is false at the anchored state it is judged at, under a root the chain proof ends at; wrapped in Groth16 for BABE on Bitcoin |

The chain proof is what makes a shielded ledger safe for everyone. With
transparent notes anyone can audit the sequencer. With shielded ones
nobody can, so instead every block is proved valid, each proof
verifying the one before. The hub's proof that an exit claim is false
must stand on the chain proof at the claim's state, so it can't show a
spend that never happened; and a user's exit is judged against a
history proved valid, so no one can claim a note that no one paid for.
How these proofs are made: [the pipeline](explainers/pipeline.md).

## Privacy

**Hidden from everyone, the sequencer and the hub included:**

- who pays whom, and how much, inside the pool;
- your balance;
- which note a spend uses: a spend reveals a nullifier, which can't be
  linked to the note's commitment without the owner's key. So whoever
  paid you can't see when you spend what they sent.

Your wallet learns about payments by downloading every new shielded
output and trying to decrypt each one, and it builds its own Merkle
paths. It never asks the sequencer about a note, so it doesn't reveal
which notes are yours.

**Public:**

- **Where money enters and leaves.** Shielding spends your mint
  transparently, so the amount shielded is linked to your deposit. A
  withdrawal or an exit of shielded notes opens them to the hub (an
  exit, to everyone, on Bitcoin): their positions, values and the keys
  that derive their nullifiers, so the hub can check they are yours and
  unspent. Your spend key stays secret, and so do your other notes, but
  whoever sent you a claimed note can then see when you spent the notes
  that key derives, so the wallet moves to a fresh shielded address
  after an exit. Privacy comes from what happens in between. Shield and
  withdraw different amounts, at different times, among other users'
  payments, or the two ends can be matched by amount and timing.
- **A transaction's shape:** how many notes it spends and creates. For
  example, whether a payment has change.
- **Timing and network metadata, to the sequencer:** when each
  transaction arrives, and from which address. There is no Tor or mixnet
  integration.

The cryptography: notes are SHA-256 commitments with a random trapdoor,
so a commitment hides its owner and value even from someone who knows
the owner's address; the new note's amount and trapdoor go to its
recipient encrypted (ECDH, ChaCha20-Poly1305), and the recipient learns
the amount, not who sent it. An owner is a hash of three keys: a spend
key, used only inside the spend proof; a nullifier key, which derives
the notes' nullifiers; and an exit key, which signs exit claims and
nothing else (docs/HUB_PROVES_PLAN.md, "Shielded notes"). RISC Zero aims for perfect
zero knowledge but hasn't proved it, so treat the proofs' hiding as a
strong expectation, not a theorem.

## Using it

**Your machine.** The wallet proves each shielded spend locally, with
`--spend-prover`: `lichen-r0` built natively (`r0/`), or the prover in
Docker through `r0/spend-prover.sh`. Natively on a Mac a shield of one
note took 3.0 s on Mutinynet (2026-11-11). Measured earlier, in Docker
on an 8-core Apple-silicon Mac:

| action | proving |
|---|---|
| shield | about 6 s |
| pay someone (one note in, payment and change out) | about 13 s |
| a payment from three notes | about 30 s |

A payment's proof needs about 1.5 GB of memory; one from several notes
needs more. Add the sequencer's seal interval (5 s by
default) before the recipient sees the payment. A proof is made against
a recent state of the ledger (one of the last 64 sealed roots), so a
slow machine has minutes to get it in, not seconds.

**The sequencer** verifies each spend proof as it arrives (fast), and
seals as before: every few seconds it signs the new root. Its chain
prover runs alongside, one height after another, behind the seals: on
the same Mac, about 1 to 2.5 minutes a height for small blocks (one or
two transactions), roughly half a minute more per transaction. A
machine proving continuously keeps up with on the order of a hundred
transactions an hour: plenty for a demonstration, far short of a busy
payment system. Running it: [RUN_A_HUB.md](RUN_A_HUB.md), its
`chain-prover` service.

**What the lag means.** A payment is final when it is sealed, as on
transparent lichen, if you trust the sequencer: a proof shows a history
is valid, not that it is the only one the sequencer signed. Without
trusting it, a payment is final once its height is anchored on Bitcoin
and buried (below). So you needn't wait for the prover before
treating a payment as received. Signing two histories can't go unseen,
though, by anyone who looks: your wallet keeps every root it checks and
stops, writing the evidence beside itself, if it's ever shown a
different root at a height it has seen; the hub does the same before
folding. To compare with others, `lichen roots` prints yours and
`lichen compare-roots <file or sequencer URL>` checks theirs against
them; `lichen check-equivocation <file>` checks evidence, which anyone
with the sequencer's key can do. The chain proof guards the hub, and
through its collateral everyone, against notes nobody paid for. An
honest sequencer checks every spend before accepting it, so its blocks
always prove; for it the lag is only a delay. It falls on the hub: to
prove a false exit claim false, it needs the chain proof at the claim's
state, within its window. A user's withdrawal or exit doesn't wait for
it. If transactions keep arriving faster than one machine proves them,
the lag grows. The remedy is faster proving: on an RTX 4090 a height
proved in 1.4 to 2.3 s, against 18 to 62 s on a Mac's CPU. Here each
height is proved from the last in one step, so the work can't yet be
shared among machines; proving blocks in parallel and chaining them
after would allow it.

**Anchoring on Bitcoin.** A sequencer could sign two histories that
split at some height, each valid: pay someone in one and claim the same
money through a contract in the other. So the sequencer anchors its history on
Bitcoin ([RUN_A_HUB.md](RUN_A_HUB.md) runs it): it keeps
one output, the seal, and each anchor transaction spends it, makes the
next, and commits a hash of the whole history up to a sealed height. An
output can be spent only once, so only one history is ever anchored;
each anchor is recorded on the L2 and checked by the chain proof, so a
history forked from the anchored one can hold none after the fork. An
exit claim is judged at the last anchor at least a margin of blocks
before its request (20 on Mutinynet), and the hub's proof shows
`request` under blocks whose work is at least the contract's (its
checkpoint's difficulty). Every spend counts only once its sender
acknowledges it against an anchor the margin deep
([payments](explainers/payments.md)).

`lichen balance` shows how final what you hold is: firm (anchored the
margin deep, and acknowledged by its sender), anchored, sealed only, or
locked, waiting for its sender's acknowledgment. The wallet doesn't take the
sequencer's word for the anchors: it checks each on Bitcoin, from the
genesis seal on, against the history it computes from the roots it has
checked.

What it costs: an anchor of about 270 vB per Bitcoin block at most, and
only when something has changed; a payment is firm once its anchor is
the margin deep and its acknowledgment sequenced, minutes on Mutinynet
and about an hour on mainnet. On regtest and Mutinynet the proof of
work is negligible (Mutinynet is a signet: its blocks are authorized by
a signature), so there they show how it works, not its security.

**A cooperative withdrawal**: a claim of your notes, shielded or not,
which the hub checks against its ledger and records on the L2, then the
fold, which pays you on Bitcoin in one transaction
([the explainer](explainers/cooperative.md)). You prove nothing for it.

## The bad case: an exit

If the hub won't fold, or the operator stops or vanishes, you exit on
Bitcoin: your claim of your notes, shielded ones by their openings and
your exit key's signature. You prove nothing: the hub must prove the
claim false within its window (2 hours on Mutinynet), or a timeout pays
you; a false proof you challenge yourself, within a day
([the exit](explainers/exit.md)). On Mutinynet, Sara's exit of a
shielded note of 90,000 sats, with a transparent 9,000, was paid by
timeout 2 hours after her request; her `request` was 59 vB larger than a
transparent claim's, for the note's opening and her keys.

## Limits

- **Liveness.** A sequencer that stops proving, sealing or anchoring
  stops payments, but not exits: your wallet keeps the notes and paths
  an exit needs as it reads the ledger, and an exit needs neither the
  sequencer nor the hub. Withheld data can stall payments, not take
  funds, since a spend counts only once its sender, holding her data,
  acknowledges it.
- **A shielded input's lock is the wallet's to keep.** An output locked
  until its spend is acknowledged is checked by position, and a shielded
  input's position is private, so the chain proof can't check its lock;
  the wallet and the sequencer do.
- **At most 13 shielded notes in a claim,** which `request`'s witness
  holds; the wallet leaves out its smallest notes beyond them.
- **Hardware signers aren't supported.** The right to spend a shielded
  note is knowledge of a key inside the proof, not a signature a device
  could make.
- **Each new version of a guest program is a new deployment.** The
  contracts pin the hub's guest's image id, and through it the chain and
  spend guests', so contracts opened under one build can't be disputed
  with another.
- **Demonstration code.** Unaudited, on a test network, with toy sizes.
