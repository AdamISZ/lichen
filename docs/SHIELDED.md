# Shielded transfers

An example L2 for lichen, on branch `shielded`: payments whose amounts
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
| withdrawal | the user (or their tower) | only when the hub refuses a withdrawal | the return is in the ledger, under a root the chain proof ends at; wrapped in Groth16 for BitVMX's verifier on Bitcoin |

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
transparent lichen: you trust the sequencer for that, not the chain
proof (a proof shows a history is valid, not that it is the only one
the sequencer signed). So you needn't wait for the prover before
treating a payment as received. The chain proof guards the hub, and
through its collateral everyone, against notes nobody paid for. An
honest sequencer checks every spend before accepting it, so its blocks
always prove; for it the lag is only a delay. That delay falls on
withdrawals, cooperative or disputed: each needs the chain proof at its
return's height, so it waits for the prover to get there. If
transactions keep arriving faster than one machine proves them, the
lag grows and so does every withdrawal's wait. The remedy is faster
proving (a GPU) or more machines, not anything a user does.

**A cooperative withdrawal**: return to the hub, ask it to fold, and it
pays you on Bitcoin in one transaction. You prove nothing for it. The
hub checks the withdrawal statement natively, in milliseconds, against
the sequencer's chain proof at your return's height. So `withdraw` may
wait a few minutes for the sequencer to prove that height; it says so
while it waits.

## The bad case: a refused withdrawal

If the hub won't fold, you enforce the withdrawal on Bitcoin. Your
wallet (or a tower, below) proves the withdrawal statement under the
sequencer's chain proof, wraps it in Groth16, and plays BitVMX's
dispute game with that as its input. Proving takes about 6 minutes and
the wrap 4.5, on a 4-vCPU x86 Linux machine. The wrap runs only on x86,
so on a Mac it has to happen elsewhere. A Mac proves the unwrapped part
in about 75 s.

You don't have to stay online for it. A **tower** is a machine you rent
for one dispute. You hand it a package (`lichen export-dispute`) holding
that contract's one-time secrets and its fee budget's key, but never
your wallet's key. At worst a tower can lose that one dispute; it can't
take your money. It proves, escalates, answers each of the hub's moves,
and stops at the payout, which you sweep from your own device later.

What it takes ([RUN_A_TOWER.md](RUN_A_TOWER.md) has the setup):

- **A machine.** x86-64 Linux with Docker; 4 vCPUs, 16 GB of memory
  (the wrap uses about 8), 15 GB of disk. All cores are busy for about
  10 minutes at the start; after that it mostly waits for blocks.
- **Time.** If the hub never answers, you are paid by timeout once its
  window passes: on Mutinynet (30-second blocks, a 10-minute window)
  well under an hour from the tower's start; with 10-minute blocks
  (a one-hour window), a few hours. If the hub plays the whole search,
  there are 21 rounds of moves. On Mutinynet, with prompt answers, that
  took about 13 minutes. With 10-minute blocks each move waits for a
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
  that stopped signing roots would. The ledger's data lives with the
  sequencer; data availability is out of scope.
- **Hardware signers aren't supported.** The right to spend a shielded
  note is knowledge of a key inside the proof, not a signature a device
  could make.
- **Each new version of a guest program is a new deployment.** The
  contracts pin the withdrawal guest's image id, so contracts opened
  under one build can't be disputed with another.
- **Demonstration code.** Unaudited, on a test network, with toy sizes.
