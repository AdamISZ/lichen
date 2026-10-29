# Shielded transfers

An example L2 for lichen: payments whose amounts
and parties are hidden, Zcash-style, with every block proved valid so
that a withdrawal enforced on Bitcoin rests on a history anyone can
check. It is a demonstration that lichen's contracts work under a
private L2. It is not a production system.

## What it is

The sequencer's ledger holds two kinds of note in one Merkle tree:

- **transparent notes**, whose owner and amount are public: the hub's
  mints (your deposit's tokens) and returns to the hub (a withdrawal's
  first step);
- **shielded notes**: only a hash of each is public. The owner and the
  amount are inside it.

A deposit's life on the L2:

```
Bitcoin deposit ──▶ mint (transparent, to you)
                      │ shield
                      ▼
                 shielded note ──send──▶ shielded notes of others ──send──▶ …
                      │ return
                      ▼
                 return to the hub (transparent: amount b, the contract's memo)
                      │
                      ▼
            withdraw cooperatively, or by dispute on Bitcoin
```

The wallet's commands are `shield <amount>`, `send <shielded address>
<amount>`, `return <amount> <contract>` and `balance`, which shows both
kinds. `address --shielded` prints your shielded address (`lichen
--help` lists them all).

Three kinds of proof, all RISC Zero:

| proof | made by | when | shows |
|---|---|---|---|
| spend | the sender, on their own machine | every shielded transaction | the notes spent exist, are yours, and are unspent; the amounts balance. The sequencer checks it without learning the notes |
| chain | the sequencer's prover | every sealed height | this block is valid, and so was the history before it |
| withdrawal | the user (or their tower) | only when the hub refuses a withdrawal | the return is in the ledger, under a root the chain proof ends at; wrapped in Groth16 for the contract's verification gadget on Bitcoin (BABE, or BitVMX) |

The chain proof is what makes a shielded ledger safe for the hub. With
transparent notes anyone can audit the sequencer. With shielded ones
nobody can, so instead every block is proved valid, each proof
verifying the one before. A withdrawal disputed on Bitcoin must carry
the chain proof at its height, so nobody can win a dispute with a note
that no one paid for, the sequencer included. The hub holds a
cooperative withdrawal to the same standard: before folding, it checks
the withdrawal statement itself, with the chain proof, so it pays out
only what you could have won by dispute.

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
  transparently, so the amount shielded is linked to your deposit.
  A return shows its amount and its contract, since the withdrawal on
  Bitcoin needs them; these are public on Bitcoin anyway. Privacy comes
  from what happens in between. Shield and return different amounts, at
  different times, among other users' payments, or the two ends can be
  matched by amount and timing.
- **A transaction's shape:** how many notes it spends and creates. For
  example, whether a payment has change.
- **Timing and network metadata, to the sequencer:** when each
  transaction arrives, and from which address. There is no Tor or mixnet
  integration.

The cryptography: notes are SHA-256 commitments; the new note's amount
goes to its recipient encrypted (ECDH, ChaCha20-Poly1305), and the
recipient learns the amount, not who sent it. RISC Zero aims for perfect
zero knowledge but hasn't proved it, so treat the proofs' hiding as a
strong expectation, not a theorem.

## Using it

**Your machine.** The wallet proves each shielded spend locally, with
`--spend-prover r0/spend-prover.sh`. That runs the prover in Docker
(`docker build -f r0/Dockerfile -t lichen-r0 .`, once). On a Mac it is
always in Docker; on Linux it can also run natively. Measured on an
8-core Apple-silicon Mac:

| action | proving |
|---|---|
| shield | about 6 s |
| pay someone (one note in, payment and change out) | about 13 s |
| return to the hub, from one note | about 15 s |
| return to the hub, from three notes | about 30 s |

A payment's proof needs about 1.5 GB of memory; a return from
several notes needs more. Add the sequencer's seal interval (5 s by
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
payment system. Running it: [RUN_A_SEQUENCER.md](RUN_A_SEQUENCER.md).

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
always prove; for it the lag is only a delay. That delay falls on
withdrawals, cooperative or disputed: each needs the chain proof at its
return's height, so it waits for the prover to get there. If
transactions keep arriving faster than one machine proves them, the
lag grows and so does every withdrawal's wait. The remedy is on the
sequencer's side, not the user's: faster proving (a GPU). Here each
height is proved from the last in one step, so the work can't yet be
shared among machines; proving blocks in parallel and chaining them
after would allow it.

**Anchoring on Bitcoin.** A sequencer could sign two histories that
split at some height, each valid: pay someone in one and return the same
money to the hub in the other. So the sequencer anchors its history on
Bitcoin ([RUN_A_SEQUENCER.md](RUN_A_SEQUENCER.md) runs it): it keeps
one output, the seal, and each anchor transaction spends it, makes the
next, and commits a hash of the whole history up to a sealed height. An
output can be spent only once, so only one history is ever anchored;
each anchor is recorded on the L2 and checked by the chain proof, so a
history forked from the anchored one can hold none after the fork. A
withdrawal, cooperative or disputed, is of a return under an anchored
root, with blocks on top of the anchor's whose work is at least ten
blocks' at the difficulty when the contract opened (its checkpoint).
Forging one means mining a branch of Bitcoin that long.

`lichen balance` shows how final what you hold is: final (anchored,
ten blocks deep), anchored, or sealed only. The wallet doesn't take the
sequencer's word for the anchors: it checks each on Bitcoin, from the
genesis seal on, against the history it computes from the roots it has
checked.

What it costs: an anchor of about 270 vB per Bitcoin block at most, and
only when something has changed; a withdrawal waits for the next anchor
and ten blocks on it, about two hours with 10-minute blocks (on
Mutinynet, minutes). On regtest and Mutinynet the proof of work is
negligible (Mutinynet is a signet: its blocks are authorized by a
signature), so there they show how it works, not its security.

**A cooperative withdrawal**: return to the hub, ask it to fold, and it
pays you on Bitcoin in one transaction. You prove nothing for it. The
hub checks the withdrawal statement natively, in milliseconds, against
the sequencer's chain proof carrying your return's anchor and the blocks
on it. So `withdraw` waits for the anchor, the chain proof and the
blocks; it says what it's waiting for.

## The bad case: a refused withdrawal

If the hub won't fold, you enforce the withdrawal on Bitcoin. Your
wallet proves the withdrawal statement under the sequencer's chain
proof and wraps it in Groth16, and the contract's verification gadget
checks it on Bitcoin. Under BABE you first request the amount on chain
and the hub responds by signing it too; then you prove, since the proof
covers that signature: about 11 minutes and the wrap 4, on a 4-vCPU x86
Linux machine, with until shortly before the contract closes to do it.
Under BitVMX you prove first (about 6 minutes and the wrap 4.5), and the
proof is the input of BitVMX's dispute game. The wrap runs only on x86,
so on a Mac it has to happen elsewhere (a Mac proves BitVMX's unwrapped
part in about 75 s).

You don't have to stay online for it. A **tower** is a machine you rent
for one dispute. You hand it a package (`lichen export-dispute`), never
your wallet's key. Under BABE you prove first, and the package holds
your signatures and the fee budget's key: the tower asserts your proof
and answers a challenge, and at worst stays silent. Under BitVMX it
holds that contract's one-time secrets and its fee budget's key, and
proves, escalates and answers each of the hub's moves; at worst it can
lose that one dispute, not take your money. Either stops at the payout,
which you sweep from your own device later.

What it takes ([RUN_A_TOWER.md](RUN_A_TOWER.md) has the setup):

- **A machine.** x86-64 Linux with Docker; 15 GB of disk. Under BABE
  it only waits for blocks, and holds the contract's kept garbled
  circuits (about 240 MB). Under BitVMX it proves: 4 vCPUs and 16 GB of
  memory (the wrap uses about 8), all cores busy for about 10 minutes at
  the start.
- **Time.** Under BABE, if the hub doesn't challenge, `success` pays
  you once its window passes (on Mutinynet 240 blocks, two hours); if it
  challenges, the tower answers within minutes. Under BitVMX, if the hub
  never answers, you are paid by timeout once its window passes: on Mutinynet (30-second blocks, a 10-minute window)
  well under an hour from the tower's start; with 10-minute blocks
  (a one-hour window), a few hours. If the hub plays the whole search,
  there are 21 rounds of moves. In a Mutinynet trial against a hub
  disputing a true claim, the tower took 75 minutes from its start to
  the payout: 10 proving, 5 to compute and escalate, 16 for the search,
  and the rest waiting out the hub's last window. The payout is yours
  to sweep 40 blocks later. With 10-minute blocks each move waits for a
  confirmation, and the hub may use its full hour for each choice:
  expect several hours, up to about a day.
- **Money.** Rent for that long: at on-demand cloud prices, a few
  dollars for such a machine for a day. On chain, the escalation's large
  transactions are paid from the contract, out of the hub's reserve.
  Your fee budget, set aside when you opened the contract (30,000 sats
  on Mutinynet), pays the small ones, and what's left of it comes back
  to you.

## Limits

- **Liveness.** Every withdrawal, cooperative or disputed, needs the
  sequencer's chain proof at its height. A sequencer that stops
  proving, or stops serving the proofs, stops withdrawals, just as one
  that stopped signing roots would. Your wallet keeps a return's signed
  root, path and chain proof once the sequencer has them, so a
  sequencer that stops after that can't stop that withdrawal. The ledger's data lives with the
  sequencer; data availability is out of scope.
- **Hardware signers aren't supported.** The right to spend a shielded
  note is knowledge of a key inside the proof, not a signature a device
  could make.
- **Each new version of a guest program is a new deployment.** The
  contracts pin the withdrawal guest's image id, so contracts opened
  under one build can't be disputed with another.
- **Demonstration code.** Unaudited, on a test network, with toy sizes.
