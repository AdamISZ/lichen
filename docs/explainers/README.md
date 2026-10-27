# Explainers

How lichen's contracts work, from real runs. For the idea without the
details, start with [the 1,000-foot view](../1000-ft-view.md).

- [Why the hub may print tokens](minting.md): conceptual, for anyone.
  A hub that can mint without limit still can't touch a covered
  balance; a sports-car story, then the details.
- [From a Rust program to one step on Bitcoin](pipeline.md): for
  engineers. How a withdrawal is proved in RISC Zero, wrapped in Groth16,
  checked by BitVMX's verifier, and searched on chain if the hub refuses.
- [Opening a contract](opening.md): Test B's contract on Mutinynet,
  from the deposit to the mint. The terms, the deposit address, the 141
  transactions both sides pre-sign, and why the order is safe.
- [A cooperative withdrawal](cooperative.md): the simplest case on
  Mutinynet. A deposit, an L2 payment, and a fold of 193 vB. Where the
  money goes, and what happens to the tokens left on the L2.
- [A withdrawal when the hub disappears](hub-absent.md): a dispute on
  Mutinynet, transaction by transaction. What each one does, its size,
  and who pays for it.
- [A withdrawal when the hub comes back](hub-returns.md): the same
  dispute, with the hub restarted after the escalation. What it rebuilds
  from the chain, why it concedes, and the fixes from Test B on chain.
- [When Alice lies](lie-caught.md): two false claims on Mutinynet,
  each played to the end. The search lands on the lie: an exit code
  disproved in one step, and a read disproved by a 66-hop path back
  478 million steps. What it cost, and who paid.
- [Exiting against a hostile operator](exit.md): a design, not built.
  How a user exits from anchored state when the operator censors, stops
  sealing or vanishes: her exit proof, the operator's counter proof,
  and the verification gadget, kept abstract, used in one of two
  places on chain.
- [How a dispute pays out](payout.md): how one pre-signed transaction
  pays Alice exactly `b`, in bits, and the hub the rest. A toy example,
  then Test B's payout traced down to the witness.

"Anchor" means two things in these notes. A dispute's links carry
330-sat **anchor outputs**, which a child spends to pay the fee. A
sequencer may also **anchor** the L2's history on Bitcoin: a chain of
its own transactions, each committing to a root of the L2's state.

The diagrams are SVG, drawn by the scripts in `img/` (Python, standard
library only); rerun a script after changing its numbers.
