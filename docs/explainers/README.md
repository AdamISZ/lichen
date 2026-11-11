# Explainers

How lichen's contracts work, from real runs: on Mutinynet (2026-11-11,
the hub-proves deployment), with every transaction linked to its
explorer, and on regtest where a run needed a real prover's timings.
For the idea without the details, start with [the 1,000-foot
view](../1000-ft-view.md).

## For anyone

- [Why the hub may print tokens](minting.md): conceptual. A hub that
  can mint without limit still can't touch a covered balance; a
  sports-car story, then the details.

## A contract, from opening to exit

- [Opening a contract](opening.md): the terms, the deposit, the
  cut-and-choose in which Alice garbles 78 instances of the hub's
  statement and uploads the 10 it keeps, the pre-signed transactions,
  and the funding swapped for the mint.
- [Payments and acknowledgments](payments.md): an L2 payment, and why it
  counts only once its sender acknowledges it against an anchor on
  Bitcoin: what that protects, and how long it takes.
- [A cooperative withdrawal](cooperative.md): Alice claims her notes,
  the hub records the claim on the L2 and folds the contract at once.
- [Exiting against a hostile operator](exit.md): when the hub won't
  fold, Alice posts the same claim on Bitcoin and proves nothing. The
  hub must prove the claim false, or her timeout pays her. Every ending,
  played on Mutinynet: a true claim paid, a stale claim proved false
  (a real proof, made on the hub's server), a valid proof challenged
  anyway, a lying hub refuted, and a shielded note's exit.
- [How a timeout pays out](payout.md): how one pre-signed transaction
  pays Alice exactly her claim in the contract's units, and the hub the
  rest. A toy example, then a Mutinynet payout down to the witness.

## For engineers

- [From a Rust program to a check on Bitcoin](pipeline.md): the three
  statements proved (a user's shielded spend, the sequencer's chain, the
  hub's statement that a claim is false), the STARK and its Groth16
  wrap, and how BABE checks the hub's proof on Bitcoin with the roles
  swapped. Proving times on a Mac, an x86 server and a GPU.

The explainers of the earlier designs (the withdrawal by return and its
disputes, under BitVMX and under BABE, with the walkthroughs of
Mutinynet's Tests A to C) were removed with those designs; they are in
the history, the last time in commit `40159b6`.

"Anchor" means two things in these notes. A dispute's links carry
330-sat **anchor outputs**, which a child spends to pay the fee. The
sequencer also **anchors** the L2's history on Bitcoin: a chain of its
own transactions, each committing to a root of the L2's state.

The diagrams are SVG, drawn by the scripts in `img/` (Python, standard
library only, sharing `img/svg.py`); rerun a script after changing its
numbers.
