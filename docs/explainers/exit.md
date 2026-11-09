# Exiting against a hostile operator

How a user leaves when the operator, running both the hub and the
sequencer, wants her money: she claims her notes, and the hub must
prove her claim false, or pay. She proves nothing. Built (`lichen exit`,
a `hub-proves` contract) and played on regtest on the mock statement;
not yet on real proofs or on Mutinynet. The design and its working
notes are docs/HUB_PROVES_PLAN.md.

## The problem

In a cooperative withdrawal, Alice returns her tokens to the hub on the
L2, and the hub folds the contract. If the hub and the sequencer are one
operator, it profits from not doing that: whatever isn't withdrawn by
`T_close` goes to the hub. So it might:

- censor her return;
- stop sealing the L2 to Bitcoin;
- withhold the data she would need to prove anything;
- or simply vanish.

## The idea: she claims, the hub proves

Alice posts a claim on Bitcoin: "these notes are mine, unspent, and
worth `b`." Everything that could make the claim false is in data the
operator holds, since it runs the L2. So the burden is the operator's:
the hub has a window, `w_H`, to prove the claim false. If it can't, or
doesn't try, her timeout pays her `b`.

An honest exit is two transactions, and her wallet runs no prover.

## Her claim

**What it says.** Each note by its position in the L2's commitment tree
and its opening (owner, value, memo, `rho`: 80 bytes), and one signature
per owner key on the claim's fingerprint `E`. Her `request` carries it
in its witness, beside her one-time signatures on `b` and on `E`. Script
can't check the claim's bytes, so the hub's statement checks they hash
to the `E` she signed.

**When it's judged.** At `A*`: the last anchor confirmed at least a
margin of blocks before her `request`'s block (6 on regtest, 20 on
Mutinynet). The margin is for censorship. If the operator holds a
payment of hers unsequenced, she sees at the tip that it isn't
included and claims its inputs; an anchor slipped in while her `request`
confirms doesn't count.

**What her wallet claims.** Its notes in `A*`'s tree, unspent, the
largest first, up to the contract's cap: so it waits, once her notes are
anchored, until that anchor is the margin deep. After a return to the
contract it claims the notes the return spent, `b` at most the return's
value. With the sequencer gone, it claims from the notes it kept as it
read the L2.

## The hub's statement

"The claim posted in `request` is false", on one of five grounds:

| ground | shown by |
|---|---|
| malformed | the claim doesn't parse, doesn't hash to her `E`, or repeats a note |
| not hers | a note's owner signed none of the claim's signatures |
| too much | the notes are worth less than `b` |
| not live | at `A*`, the leaf at a note's position isn't its commitment, or its nullifier is spent |
| a second claim | the note's owner signed a claim of it through another contract |

A spend that doesn't count: her own return of at least `b` to this
contract (the hub holds those tokens), and this contract's own exit
record.

The hub shows `A*` is the last anchor before the cutoff by the first
spend of its seal output, confirmed after it: anchors spend the seal one
after another, and Bitcoin allows one spend. The statement reads
`request` from Bitcoin, in a block with the contract's work on it.

## On chain

```
request (Alice: b, E, the claim)
 ├─ request_timeout (after w_H)      → Alice: b
 └─ assert (the hub: its proof)
     ├─ success (after Δ2)           → the hub: the contract
     └─ challenge_assert (Alice)
         ├─ wrongly_challenged_k     → the hub (its proof was valid)
         └─ failure (after Δ1)       → Alice: b
```

It is BABE's game with the roles swapped. At opening, Alice garbles the
instances for the hub's statement and commits to them; the hub keeps a
few, which she uploads (23 MB each), and checks the rest. If the hub
asserts, her wallet checks the proof natively. A false one she
challenges, revealing its input labels; the hub can answer only with a
valid proof, by opening one of her instances. On regtest `request` is
about 2.1 kvB, `assert` 7,725 vB, her `challenge_assert` 20,717 vB.

**After a claim that holds,** the hub holds its notes (the sequencer
refuses their spends) and records the exit on the L2, which retires
them.

## A run on regtest

Seven exits on the mock statement (the hub decides its statement
natively and asserts the mock's proof), in a deployment anchoring on
regtest, blocks every 150 ms. The hub refuses every cooperative
withdrawal (`hp_exit.rs`).

| | what happens | outcome |
|---|---|---|
| E | an honest claim: the hub finds no ground, records the exit | `request_timeout` pays her |
| S | a stale claim, after a payment anchored before the cutoff | the hub asserts the note spent at `A*`; her wallet finds the proof valid and concedes |
| C | the same, challenged anyway | the hub opens one of her instances and answers; it takes the contract |
| Q | one note claimed through two contracts at once | each is asserted false as the other's second claim |
| K | a lying hub asserts a false proof against an honest claim | she challenges; it can't answer; `failure` pays her |
| R | an exit after a return the hub wouldn't fold | her own return isn't a spend against the contract; she is paid |
| G | the hub and the sequencer gone | she claims from the notes kept; `request_timeout` pays her |

## What a hostile operator can try

| the operator | what happens |
|---|---|
| censors her return | she exits, claiming the notes the return spent |
| stops sealing, or vanishes | she claims what was anchored; no assertion, the timeout pays her |
| holds a payment of hers, and anchors it once she has claimed | past the cutoff: it doesn't count |
| asserts a false proof | she challenges, and `failure` pays her |
| claims her notes through its own contract | it can't: only she signs |
| anchors a spend of hers, then withholds its data | she may lose the notes that spend touched: see Limits |

## Limits

- **Not yet on real proofs.** The hub's statement is checked natively;
  its guest, the real statement, is next.
- **Transparent notes only, at most 8 a claim.** Shielded notes are
  planned (docs/HUB_PROVES_PLAN.md, "Shielded notes"), and the limit is
  an exit record's.
- **Data availability.** Money at rest is safe: only her keys spend her
  notes. A spend in flight when the operator turns can lose the notes
  it spends: if the operator anchors it and withholds the data, she
  can't tell whether to claim its inputs or its outputs.
- **No tower.** Her challenge reveals her dealing's secrets, so a tower
  can't play it keyless. She has to challenge only a lying hub, and her
  window for it is long (a day on Mutinynet).
- **Her opening uploads** the instances the hub keeps: ten of 23 MB at
  real parameters.
- **Mass exit.** Each exit is a dispute competing for block space, and a
  hub that asserts falsely against everyone forces each user's 20.7 kvB
  challenge.
