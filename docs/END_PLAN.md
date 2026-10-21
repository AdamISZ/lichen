# The L2's end and the exit: plan

2026-10-21, branch `anchor`. After anchoring (ANCHOR_PLAN.md); its
"later, not now" freeze, worked out.

## The problem

Every withdrawal is a return the sequencer must seal and anchor. A
sequencer that stops stops them all, and whatever isn't withdrawn by
`T_close` goes to the hub by the contract's default. So a user's money
is only as safe as the sequencer is alive, and the hub profits from its
death.

Censorship (a live sequencer refusing your return) is not this plan's;
it would need a forced-inclusion proof feeding the same exit (below).
Data availability is a known unknown here: named where the exit needs
it, not solved.

## The principle

- The sequencer must anchor at least every `N` blocks. A seal left
  unspent that long may be spent by anyone; Bitcoin's consensus
  enforces the wait (CSV).
- Any spend of the seal that isn't an anchor ends the L2, by
  definition and for good.
- After the end, a withdrawal no longer proves "you gave the hub `b`"
  but "you hold `b`": your contract's backed notes, unspent in the final
  state. The contract pays it as before; only the statement changes.

## The rule

> Once the current seal is spent by anything but an anchor, the L2 has
> ended. Its final state is the one its last anchor committed. Heights
> sealed after it never happened, and no later root is valid for
> anything. It can't be revived: a new seal chain is a new genesis, so a
> new deployment. What remains is to pay out the final state: each
> contract once, its backed notes and its unpaid returns, up to its cap.

Bitcoin enforces most of it. An anchor must spend the current seal, and
the end spent it, so no anchor can follow; the chain guest refuses a
record of anything else. Withdrawals need anchored roots, and exits need
the end. The software does the rest: the sequencer stops, the hub opens
no contracts and folds only exits and anchored returns, and wallets stop
sending.

It keeps the finality levels' meaning. A final note (anchored, 10 deep)
is in the final state unless its owner spent it later. A payment only
sealed after the last anchor is undone: the payer's notes are unspent in
the final state, so they back the payer's exit, not the receiver's.
That is what "sealed: trust the sequencer" meant.

## Definitions

- **Anchor**: a spend of the current seal whose seal input has BIP68
  disabled (nSequence bit 31 set; the anchorer's `0xfffffffd` already
  is), output 0 the seal script, output 1 `"lichen" ‖ at ‖ hist_at`. As
  now, plus the nSequence rule.
- **The end**: any other spend of the current seal, transaction `X`.
- **The final anchor** `A_k`: the anchor whose seal `X` spends. **The
  final state**: what it commits: height `h_k`, root `SR_k` (tree `T_k`,
  nullifiers `N_k`).
- **Backed notes** of contract `c`: notes owned by the exit owners the
  contract pins, shielded notes of owner `O_c = H("lichen/owner" ‖
  nk_c)` and transparent notes of key `K_c`, both derived by the wallet
  for that contract; and the returns to the hub with memo `c` (owed,
  never paid). Up to the contract's cap.
- **Unbacked**: everything else: notes of other owners, value above a
  cap, notes of users with no contract. At the end the hub keeps it.

## The seal

P2TR: internal key the sequencer's `P`; one leaf, `<N>
OP_CHECKSEQUENCEVERIFY` (anyone, `N` blocks after the seal confirmed;
the leaf leaves `N` on the stack, true). Output key `Q = P +
H_TapTweak(P ‖ leaf)·G`. Anchors are key-path spends with the tweaked
key.

The leaf needs nSequence to hold a lock of at least `N`, so a leaf spend
can never be an anchor. Without that rule anyone could keep a dead L2
"alive" by re-anchoring its last history through the leaf every `N`
blocks. The hub, which takes the default's windfall, would have reason
to.

No curve arithmetic in the guests. `Q` is a constant of the deployment:
the genesis anchor state carries it in place of the sequencer's key,
and `D` commits it. Wallets and hub check `Q = tweak(P, N)` natively
when they join or open. `N` is in no guest, since Bitcoin enforces it.
The seal's 1,000 sats pay the end's fee.

Today's seal (`OP_1 <P>`, untweaked, no leaf) can't end: a new
deployment.

## The heartbeat

The sequencer anchors at least every `B ≤ N/2` blocks, even with nothing
new: an anchor of the last anchor's record height. Today it skips when
nothing changed. It fee-bumps (RBF) an anchor still unconfirmed after a
few blocks, so a fee spike costs it money, not its L2. Cost: 270 vB per
`B` blocks, three anchors a day on mainnet at `B = 48`.

From `a + N`, a late anchor and an end can race, and whichever confirms
wins. A late anchor is an anchor, and the L2 lives.

## What the exit proves, and what it reads from Bitcoin

The exit is a second mode of the withdrawal guest: one image id, so the
contract, its scripts and the dispute don't change. The journal is the
same, `b ‖ c ‖ D`.

| input | from | shows |
|---|---|---|
| `D`'s preimage: deployment, genesis seal, `W`, `Q`, `O_c`, `K_c` | the contract | which L2; which owners back this contract |
| a chain receipt at some height `H ≥ h_k` | the L2: the sequencer's, or proved by anyone from the block inputs | a valid history from genesis; its last recorded anchor `A_j` (seal, block) and `hist_H` |
| the anchors `A_{j+1..k}` not yet recorded: each transaction, Merkle path, `hist_{at−1}` and the roots `at..H` | Bitcoin (transactions, paths); the L2's signed roots (the wallet has them) | each spends the last seal and commits this history (`check_anchor`, as the chain guest would record it). The last gives `h_k` and `SR_k` |
| the end `X`, its Merkle path | Bitcoin | it spends `A_k`'s seal and isn't an anchor |
| headers from `A_j`'s block, through each named block, then at least `W` of work on `X`'s | Bitcoin (any node) | all on one chain, with 10 blocks' work after the end |
| each backed note's opening (with `nk_c`, or `K_c`'s signature on `c ‖ D`), its path in `T_k`, its nullifier's non-membership in `N_k`; each unpaid return's path in `T_k` | the wallet (secrets); the L2's data (paths) | the claimant holds `Σ`, unspent in the final state |

It accepts if all of that checks, the notes are distinct, and `b ≤ Σ`.
A claim may be partial, so a wallet claims `min(Σ, cap)`.

**Why each piece is on Bitcoin.**

- **The anchors past the receipt's last record.** The last anchor is
  almost never recorded: its record goes in a later height, and a
  sequencer that stops doesn't seal one.
- **The end.** `X` is the unique spend of `A_k`'s seal, so every exit
  lands on the same final state. No claimant can pick an earlier
  anchor and call it final, which is what would let two exits pay one
  note.
- **The work after the end,** so that the end isn't a cheap fork.

The receipt may be past `h_k`: heights sealed after the last anchor,
proved but void. Its `hist` commits everything to `h_k` anyway, and
`check_anchor` hashes forward to it. No signature on `SR_k` is needed,
because the anchor commits it.

**Cost**, estimated. Per note, 16 hashes for the tree and 256
compressions for the non-membership. Per header, a double SHA-256: about
180 headers on mainnet, 350 on Mutinynet. Gap anchors cost what anchor
records do. In all, about the withdrawal's 392k cycles plus a few
hundred thousand: one segment, 75–150 s on the Mac.

## No double payment

- **Across contracts:** a note backs only the contract whose owner it
  has, and the hub refuses a contract whose `O_c` or `K_c` it already
  backs. Without that, one note could exit through two contracts, and
  nothing on Bitcoin would link the two claims.
- **Within a contract:** it pays once. The fold or the dispute closes
  it.
- **Exits and returns:** a return anchored before the end spent its
  notes, so it counts as a return, never as its notes. A contract with
  both claims both in one exit. The return counts by membership in
  `T_k` alone: owed whether or not the hub has since spent the returned
  note.

## The hub's books at the end

The chain proof conserves value, so the final state's notes sum to the
deposits less the returns. Across its contracts the hub nets out:

- a contract whose backed notes exceed its deposit is paid from the
  hub's reserve;
- one whose notes fall short returns the rest to the hub by the
  default.

It keeps what is unbacked. An honest hub checks an exit natively (the
end on its own node, the notes) and folds it. A hostile hub disputes it,
as now.

## Timing

The exit's escalation must confirm by `T_close`; after that the hub may
broadcast the default. Counting from the last anchor's confirmation at
block `a`:

| term | for |
|---|---|
| `N` | the seal's wait |
| `f` | the end confirming: anyone's transaction, through fee spikes and pinning |
| 10 | `W` on top of the end |
| `P` | the exit proof, the wrap, the trace; the hub's answer to a fold |
| `e` | the escalation confirming |

`Δ = N + f + 10 + P + e`. The hatch protects a contract whenever its
last anchor confirms by `T_close − Δ`.

The sequencer can stop at any time, so the wallet must withdraw or roll
the contract over by `T_close − Δ − ℓ`, with `ℓ` its return's anchoring
latency (a block or two). After that, a sequencer that stops may leave
too little time. On top of `Δ` comes the user's own liveness `U`: the
wallet or a tower online to see the end and act. That is the user's
choice, as in Lightning.

Proposed values (blocks):

| network | block time | `N` | `B` | `f` | `P` | `e` | `Δ` | contract life | covered |
|---|---|---|---|---|---|---|---|---|---|
| regtest | — | 20 | 5 | 2 | 10 | 2 | 44 | 1,000 | 96% |
| Mutinynet | 30 s | 240 (2 h) | 80 | 20 | 120 (1 h) | 20 | 410 (3.4 h) | 20,160 (a week) | 98% |
| signet, mainnet | 10 min | 144 (a day) | 48 | 12 (2 h) | 6 (1 h) | 6 | 178 (30 h) | 1,008 (a week) | 82% |
| | | | | | | | | 4,320 (a month) | 96% |

"Covered" is the share of a contract's life during which a stopped
sequencer still leaves time to exit, before `U`. Adding a day's `U` on
mainnet takes a week's contract to 68% and a month's to 93%. So mainnet
contracts should live about a month.

Why these values:

- **`N`** trades the sequencer's slack (a day of fee spikes or
  downtime on mainnet) against the window at the end of a contract.
- **`f`**: the end is about 150 vB, paid from 1,000 sats (about 7
  sat/vB). In a spike it needs a child from the wallet.
- **`P`** is measured: in the Mutinynet trial the tower escalated 15
  minutes after starting (proof 405 s, wrap 263 s). Added to that: the
  chain receipts for heights the sequencer hadn't proved when it
  stopped (a minute or three each), and starting a tower.
- **`e`**: one hour.

For the Mutinynet trial, a shorter `N` (60, half an hour) so the end
fits in a session.

**Mass exit.** At the end every contract exits at once. With an honest
hub these are folds (205 vB each). With a hostile one, every escalation
must confirm by its own `T_close`. Contracts opened at different times
spread those deadlines, but `e` must cover all escalations whose
`T_close` falls together. The windows' congestion table covers the
moves after an escalation; the escalation's deadline is absolute. This
is a known risk at scale.

## Not this plan

- **Censorship.** Post the return on Bitcoin; an anchor more than `K`
  blocks later whose history doesn't hold it proves censorship (the
  history would carry the forced transactions it processed: a
  non-membership proof). That would feed this exit, for that contract
  alone.
- **Data availability.** The exit needs:
  - a chain receipt at a height of at least `h_k`, or the block inputs
    to prove one;
  - the roots;
  - each note's path in `T_k` and its nullifier's non-membership in
    `N_k`.

  All of these are L2 data. Availability is graded: the wallet's own
  sync, mirrors, the hub, Bitcoin.
- **Sabotage.** A sequencer could spend its seal with an anchor-shaped
  transaction committing a history nobody can prove (garbage, or a fork
  it won't serve), then stop. No exit can pass that anchor, and the L2
  is stuck, as today. Blunt sabotage, any spend that isn't anchor-shaped,
  is simply the end, and exits work. A remedy (a bond, or a counter-proof
  by the hub) comes later.
- **Bitcoin censorship** of anchors or of the end is outside, as
  everywhere.

## Steps

1. **The seal.** The leaf; `Deployment` gains `N` and `Q`; anchors
   signed with the tweaked key; `parse_tx` reads nSequence; the chain
   guest refuses an anchor whose seal input has BIP68 enabled; the anchor
   state carries `Q`. A new chain guest.
2. **The heartbeat** and fee bumps in the anchorer.
3. **The exit owners.** `D = H("lichen/contract" ‖ deployment ‖ genesis
   seal ‖ W ‖ Q ‖ O_c ‖ K_c)`. The hub refuses an owner it already
   backs. The wallet:
   - derives `nk_c` and `K_c` per contract;
   - receives to `O_c` and claims the mint there;
   - keeps its backed notes few (consolidating);
   - shows backed and unbacked, and `T_close − Δ`.
4. **The exit mode** of the withdrawal statement (`lichen-withdraw`),
   native first (the mock statement), then the guest. A new withdrawal
   guest.
5. **The end, seen.**
   - Wallet, hub, sequencer and l2 see it (`Event::Ended`).
   - `lichen end` sends anyone's end.
   - The hub stops opening and folds exits it has checked.
   - `lichen exit <contract>` folds, or disputes if refused.
   - The tower's package carries the exit's material.
6. **Tests.**
   - Regtest:
     - the sequencer stopped, `N` mined, the end, exits folded (mock);
     - an exit disputed;
     - a sealed-only payment undone;
     - a late anchor racing the end;
     - a leaf spend shaped as an anchor, refused as one;
     - an end too shallow;
     - a repeated owner refused at opening.
   - Groth16: an exit proved and disputed.
   - Mutinynet: stop the sequencer; the end; Alice folds; Bob disputes
     against a `HOSTILE` hub.
7. **Docs.** SHIELDED.md's Limits and CODE.md. The README is the user's.
