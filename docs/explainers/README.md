# Explainers

How lichen's contracts work, from real runs.

- [Why the hub may print tokens](minting.md): conceptual, for anyone.
  A hub that can mint without limit still can't touch a covered
  balance; a sports-car story, then the details.
- [A cooperative withdrawal](cooperative.md): the simplest case on
  Mutinynet. A deposit, an L2 payment, and a fold of 193 vB. Where the
  money goes, and what happens to the tokens left on the L2.
- [A withdrawal when the hub disappears](hub-absent.md): a dispute on
  Mutinynet, transaction by transaction. What each one does, its size,
  and who pays for it.

The diagrams are SVG, drawn by the scripts in `img/` (Python, standard
library only); rerun a script after changing its numbers.
