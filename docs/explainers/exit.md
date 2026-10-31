# Exiting against a hostile operator

How a user leaves when the operator, running both the hub and the
sequencer, wants her money: she claims her notes from a state already
anchored on Bitcoin, and the operator may answer only with something
that really happened. Built (`lichen exit`), and played on regtest on
BABE's mock statement; not yet on real proofs or on Mutinynet. This note
is about the proofs, and how they ride on BABE's dispute.

## The problem

In today's withdrawal, Alice returns her tokens to the hub on the L2,
and then proves that return on Bitcoin. That needs the sequencer to
include her return. If the hub and the sequencer are one operator, it
profits from not including it: whatever isn't withdrawn by `T_close`
goes to the hub. So it might:

- censor her return;
- stop sealing the L2 to Bitcoin;
- withhold the data she needs to prove anything;
- or simply vanish.

Each of these blocks a withdrawal that starts with a return. The exit
doesn't start with one.

## The idea: claim from the past, answer with something real

Alice claims from a state of the L2 that's already anchored on Bitcoin:
"at state `S`, these notes of mine were unspent; pay me `b`." She can
make that claim with no help from the operator. She needs only data she
already holds.

The operator gets one answer, a **counter**, on one of two grounds:

- **a later spend:** one of those notes was spent at an anchored state
  after `S`, and that state was final on Bitcoin when she claimed;
- **a second claim:** she signed a claim of one of those notes through
  another of her contracts too.

Those are the only ways a claim from the past can be wrong, and each
points to something only Alice could have done.

![the two proofs](img/exit-proofs.svg)

## Alice's claim

**Her exit kit.** For an anchored state `S`, the sequencer serves each
note's part of a kit (`/kit/<height>/<index>/<nullifier>`): the note's
path in the commitment tree `T_S`, and its nullifier's absence from the
spent set `N_S`. Her wallet checks both against the root the sequencer
signed at that height. With the chain receipt at `S` (the sequencer's
recursive proof that every L2 block up to `S` was valid), that's all she
needs. A kit never goes stale: the tree only grows, and a nullifier
absent from `N_S` stays absent from `N_S`.

**The claim.** Her wallet claims her notes in the latest anchored state,
the largest first, up to the contract's cap `V_max`. It computes the
claim's fingerprint

```
E = H(c ‖ O_D ‖ b ‖ h_S ‖ SR_S ‖ nullifiers)
```

over the contract `c`, its deposit coin `O_D`, the amount, the state and
the notes, and each note's owner signs `E`. The deposit coin names the
contract on Bitcoin: the contract's funding is the only transaction that
can spend it, and `request` the only one spending the funding's output.

**Posted, not just proved.** Her `request` carries the claim in its
witness: `h_S`, `SR_S`, each note's opening and its owner's signature
on `E`. At most 1,169 bytes, in fifteen items of 80 bytes (Bitcoin Core
relays no larger tapscript item). It's there so that the operator can
search for the notes, and cite the signatures against her if she claims
them twice. Her proof checks that `request` posted exactly this claim,
so she can't post junk and prove something else.

**The proof** is the claim branch of her statement (below): her notes
in `T_S` and unspent in `N_S`, `S` anchored with the contract's work on
its anchor block, `request` in a block with that work on it too, and
`b ≤ Σ`. RISC Zero proves it as a STARK, and the STARK is wrapped in
Groth16.

## The hub's counter

**A later spend.** A note's nullifier enters the spent set in only two
ways:

- **a spend,** which needs the note's keys. The chain proof checks every
  spend's authority, so the operator can't sign one for her;
- **an exit record,** which the operator posts after a claim to retire
  its notes on the L2. A record must carry the owners' signatures on the
  claim, which the chain guest checks. Without that rule, the operator
  could post a record with Alice's nullifiers, taken from her request,
  and counter her with it.

The counter cites a spend at a state `S′` after `S`, in the one anchored
history, and:

- **only if final when she claimed:** `S′`'s anchor confirmed in or
  before `request`'s block. Otherwise any transaction she signed and the
  operator holds would be a counter in waiting, sequenced after she
  committed to her claim;
- **not her own return to this contract,** of at least `b`: she tries
  the cooperative way first, and the operator still holds that signed
  return. If the return is sequenced, the hub has her tokens, and the
  contract still pays once;
- **another contract's exit record counts whenever anchored:** it needs
  her signature on a claim through that contract.

![a counter needs a real insertion after S](img/exit-heights.svg)

**A second claim.** The counter may also cite her signed claim of one of
the notes through another contract, from that contract's `request`. Only
she can sign it, and an honest wallet claims a note through one contract
only. This one needs no anchoring, so the hub can cite it as soon as the
other `request` is on chain, which matters: under BABE the hub responds
before Alice proves, so two requests in one block would otherwise both
be paid.

**The proof** is the counter guest's: the claim's `E` from what it
hashes, and either the spend in `S′` (the nullifier's leaf in the spent
set says how it was spent: a spend, a return, an exit record), with
`S′`'s history passing through `S` and `request` in its block, or the
other claim's signature. Its journal is `D ‖ E`, so it answers this
contract's claim and no other. Wrapped in Groth16, its points, 128
bytes, are the counter `K`.

## On chain

BABE's dispute keeps its shape. What the exit adds rides on its first
two transactions:

![request, the two responses, and the statement's branches](img/exit-graph.svg)

- **`request`:** Alice signs `b`, as for any dispute, and `E` under a
  second one-time key, and posts her claim beside them.
- **`respond`,** within `w_H`: the hub signs `b` again, and `E`, in one
  of two leaves of the same transaction. The plain leaf signs `E` under
  one key. The countering leaf signs it under another, and signs `K`
  itself, 259 digits. Script checks the hub's `E` digit for digit
  against Alice's (her signature's digits feed the hub's signature check
  directly), so the hub can't answer some other claim. Which key signed
  `E` tells her statement which leaf ran.
- **`assert`:** Alice's proof of her statement, before `T_A`. Her
  statement is fixed when the contract opens, with the journal
  `c ‖ D ‖ H(pk_H ‖ O_D)`: her contract, its `D`, and the hub's keys for
  `respond` with the deposit coin. She wins on any of three branches:

| branch | holds when |
|---|---|
| return | the hub signed `b`, and a return of `b` to the contract is anchored: a refused withdrawal, as before the exit |
| claim | the hub signed `b` and `E` in the plain leaf, and her claim holds |
| failed counter | the hub signed `E` and `K` in the countering leaf, and `K` isn't a counter for her `D ‖ E` |

A true counter leaves her no branch: she can't assert, and from `T_A`
the contract is the hub's. A false one pays her through the third
branch. That branch's proof checks a Groth16 proof inside RISC Zero,
56.3 million cycles in 58 segments (about an hour on a laptop's CPU,
about a minute on a CUDA GPU, estimated from measured segments), and
needs no secret of hers: anyone can prove it for her. It has days to
run, since her deadline is `T_A`, near the contract's end.

The rest is BABE's: a false assertion is challenged, a true one pays
her `b` and the reserves after `Δ2`, and a hub that never responds lets
her `request_timeout` pay her.

## After a claim

With no counter, the hub responds plainly, then:

- **holds** the claimed notes: the sequencer refuses their spends;
- **records the exit on the L2:** the claim, as posted, with the owners'
  signatures, retires its notes. Another claim of them, through another
  contract, then meets that record, as well as her signature.

## A run on regtest

Four exits on BABE's mock statement (a proof anyone can make; the hub
and the wallet decide each claim's truth natively, as the guests would),
in a deployment anchoring its history on regtest, blocks every 150 ms.
The hub refuses every cooperative withdrawal.

| | what Alice does | what happens |
|---|---|---|
| E | claims her note from the latest anchored state | the hub has no counter: it responds plainly, holds the note and records the exit. She proves her claim, and `success` pays her 375,719 sats (`b` 200,000 in bits, the reserves, the fee budget's rest) |
| S | prepares her claim, pays Bob, and once the payment is anchored claims the old note anyway | the hub counters with the spend, anchored before her request: she has no branch |
| Q | claims the same note through two contracts, one request after the other | the second is countered by the first's signed claim; the first is paid |
| K | claims honestly; the hub, misbehaving, counters with a `K` that isn't one | she proves it false, and is paid |

Both counters were also built as the counter guest's real input and
checked natively before the hub posted them. On regtest under standard
policy `request` is 2,373 vB with the largest claim, and `respond`
4,480 vB plain or 12,255 vB countering.

## What a hostile operator can try

| the operator | what happens |
|---|---|
| censors her return | she exits from her kit; the return can't be used against her |
| stops sealing | her kit's `S` is already anchored |
| withholds data, with no spend of hers since her kit | her last kit still works |
| holds a transaction she signed, and seals it after her claim | past the cutoff: not a counter |
| seals a spend of hers, then withholds its new notes' data | she loses: the data-availability gap, see Limits |
| vanishes | no response: `request_timeout` pays her |
| responds, then waits | she proves and asserts; the gadget pays her |
| counters with something false | she proves it false, and is paid |
| forges an insertion | it can't: a spend needs her keys, an exit record her signature |
| cites a copy of her claim through another contract | it can't make one: only she signs |
| counters with her own return | excluded |

## Limits

- **Not yet on real proofs.** The guests are built and checked against
  real receipts, but the exit hasn't been played with real proofs on
  chain.
- **Transparent notes only.** A shielded note's owner proves her
  authority by knowing its key inside the proof, so there's nothing to
  post or cite: the exit claims a wallet's transparent notes. Shielded
  addresses will gain an owner key for this.
- **No towers yet.** A tower plays a return's dispute without her keys
  because she signs her proof ahead. An exit's proof depends on how the
  hub responds, so it can't be signed ahead.
- **A request commits its notes.** Once claimed through a contract, a
  note can't be claimed through another, even if the first claim fails.
- **Exits are disputes.** Hours, and fees, against the fold's 193 vB,
  unless the operator folds.
- **Data availability: the one substantial gap.** The exit is safe
  exactly when Alice can read the anchored data she needs. In the
  consolidation attack, she merges her covered notes into one new note;
  the operator seals that and withholds the new note's data: the old
  notes are countered, and the new one has no kit. The planned remedy
  is the sender's acknowledgment: a spend can counter her only once she
  has signed that she holds its data, its outputs locked until then.
- **Whole notes.** A claim spends whole notes. Alice claims everything
  up to `V_max`, and above the cap the claimed notes' excess is
  forfeit.
- **Mass exit.** A hostile operator can refuse every user at once. Each
  exit is one dispute, competing for block space, and `w_H` is longer
  (two hours on Mutinynet) so that the hub can prove a counter.
