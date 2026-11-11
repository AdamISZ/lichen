# Exiting against a hostile operator

How a user leaves when the operator, running both the hub and the
sequencer, wants her money: she claims her notes on Bitcoin, and the hub
must prove her claim false, or pay. She proves nothing. Played on
Mutinynet (2026-11-11) on the real statement: every ending of the
dispute, with the hub's proofs made on its own server. The design and
its working notes are docs/HUB_PROVES_PLAN.md.

## The problem

In a cooperative withdrawal, Alice claims her notes and the hub folds
the contract ([cooperative.md](cooperative.md)). If the hub and the
sequencer are one operator, it profits from not doing that: whatever
isn't withdrawn by `T_close` goes to the hub. So it might:

- refuse the fold, or not answer;
- censor her payments, or stop sealing the L2;
- withhold the data she would need to prove anything;
- or simply vanish.

## The idea: she claims, the hub proves

Alice posts a claim on Bitcoin: "these notes are mine, unspent, and
worth `b`." Everything that could make the claim false is in data the
operator holds, since it runs the L2. So the burden is the operator's:
the hub has a window, `w_H` (2 hours on Mutinynet), to prove the claim
false. If it can't, or doesn't try, her timeout pays her `b` and both
reserves.

An honest exit is two transactions, and her wallet runs no prover.

## Her claim

**What it says.** Her notes, transparent ones by their positions in the
L2's commitment tree, shielded ones by their positions and openings; the
acknowledgments of her own spends whose outputs she claims while they're
still locked ([payments.md](payments.md)); and one signature per owner
key (a shielded owner's by its exit key) on the claim's fingerprint `E`,
which binds the claim to this contract and to `b`. Her `request` carries
it in its witness, at most 1,200 bytes, beside her one-time signatures on
`b` and on `E`. Script can't check the claim's bytes, so the hub's
statement checks they hash to the `E` she signed.

**When it's judged.** At `A*`: the last anchor confirmed at least a
margin of blocks before her `request`'s block (20 on Mutinynet, 6 on
mainnet). The margin is for censorship. If the operator holds a payment
of hers unsequenced, she sees at the tip that it isn't included and
claims its inputs; an anchor slipped in while her `request` confirms
doesn't count.

**What her wallet claims.** Its notes in `A*`'s tree, unspent, the
largest first, up to the contract's cap and the witness's room (64
notes, 13 of them shielded). So once her notes are anchored, it waits
until that anchor is the margin deep. A withdrawal the hub recorded but
didn't fold is exited with that same claim. With the sequencer gone, it
claims from the notes it kept as it read the L2.

## The hub's statement

"The claim posted in `request` is false", on one of these grounds:

| ground | shown by |
|---|---|
| malformed | the claim doesn't parse, doesn't hash to her `E`, repeats a note, or `b` exceeds the cap |
| not hers | a note's owner signed none of the claim's signatures |
| too much | the notes are worth less than `b` |
| not a note | at `A*`, the leaf at a note's position isn't its commitment |
| spent | at `A*`, its nullifier is spent by a spend that counts: the hub's, or one its sender acknowledged |
| locked | at `A*`, it's an output of a spend not acknowledged, and the claim carries no acknowledgment |
| voided | at `A*`, it's an output of a spend an exit record voided |
| a second claim | the note's owner signed a claim of it through another contract |

The hub shows `A*` is the last anchor before the cutoff by the first
spend of its seal output, confirmed after it: anchors spend the seal one
after another, and Bitcoin allows one spend. The statement reads
`request` from Bitcoin, in a block with the contract's work on it, and
the state at `A*` from the sequencer's chain receipt there. The hub
decides it natively, in milliseconds, and proves it only if it holds
([pipeline.md](pipeline.md)).

## On chain

```
request (Alice: b, E, the claim)
 ├─ request_timeout (after w_H)      → Alice: b and both reserves
 └─ assert (the hub: its proof)
     ├─ success (after Δ2)           → the hub: the contract
     └─ challenge_assert (Alice)
         ├─ wrongly_challenged_k     → the hub (its proof was valid)
         └─ failure (after Δ1)       → Alice: b and both reserves
```

It is BABE's game with the roles swapped ([pipeline.md](pipeline.md#4-the-check-on-bitcoin-under-babe)).
At opening Alice garbled the instances for the hub's statement; the hub
kept 10 and checked the rest ([opening.md](opening.md)). If the hub
asserts, her wallet checks the proof natively. A valid one means her
claim was false, and she concedes. A false one she challenges,
revealing its input labels; the hub can answer only with a valid proof,
by opening one of her instances. On Mutinynet the windows are `w_H` 240
blocks (2 hours), `Δ2` 2,880 (a day), `Δ1` 240.

**After a claim that holds,** the hub holds its notes (the sequencer
refuses their spends, and the acknowledgment of a spend of them) and
records the exit on the L2, which retires them.

## The runs, on Mutinynet

Six contracts opened on one deployment (2026-11-11), each with a deposit
of 100,000 and 100,000 of liquidity: a cap of 199,155, 255 units of 781.

| wallet | contract | the claim | how it ended | on chain |
|---|---|---|---|---|
| Erin | 1002 | true | the hub found no ground; `request_timeout` paid her after 2 hours | 2.7 kvB |
| Sara | 1005 | true, of a shielded note and a transparent one | the same | 2.8 kvB |
| Sam | 1003 | stale: its note paid away and acknowledged | the hub proved it false on its server and asserted 54 minutes after `request`; his wallet conceded | 9.9 kvB, then `success` a day later |
| Cleo | 1001 | stale, as Sam's | the hub asserted; she challenged anyway; the hub answered in two blocks | 30.8 kvB |
| Kim | 1004 | true, against a hub restarted hostile | the hub asserted a forged proof; she challenged; no instance opened; `failure` pays her | 30.6 kvB, and `failure` |

Alice and Olga withdrew cooperatively instead ([cooperative.md](cooperative.md)).

### Erin: a true claim, paid

Erin opened contract 1002, acknowledged her mint's move to her key,
and exited at once, claiming her one note of 99,000: 126 units, 98,406
sats (the claim is in whole units, and the 594 above them stay with the
hub). The hub never refused anything: an exit needs no refusal first.

| block | time (UTC) | what |
|---|---|---|
| 3,580,073 | 02:22 | [request](https://mutinynet.com/tx/834b657fd68f8694690754cd544dec58d1de4b1552ef3561df86cd750e09ea07): 2,135 vB, its floor 2,384 sats out of the contract |
| | 02:23 | the hub holds her note: the sequencer refuses its spends |
| | by 02:29 | `request`'s block has the contract's work on it; the hub decides natively: the claim holds. It asserts nothing, and records the exit on the L2, retiring the note |
| 3,580,314 | 04:27 | after `w_H` (240 blocks), [request_timeout](https://mutinynet.com/tx/2eb4200a19ec65b82b024b787df44a0843511adb4a9ec28b8e636c988d4579d3) pays her: her 126 units in bit outputs, and both reserves less the floor (565 vB; its fee, 568, from her fee budget) |
| 3,580,315 | 04:27 | the hub [collects](https://mutinynet.com/tx/69fa312f732e2e5dc50d8f4e812b777929ba2e53b683b2868923630b2c8f9815) the bit outputs whose bits are 0 |
| 3,580,355 | 04:48 | after `δ` (40 blocks), her wallet [sweeps](https://mutinynet.com/tx/6136d1d26f545c3719ca7174b87e99098d00a57032f3f7df9960e21ad49c9b41) her outputs, with her fee budget's rest, to her payout address: 174,833 sats |

[payout.md](payout.md#part-2-erins-exit-traced) traces the payout to
its witness bytes. **Two transactions of the contract's, 2,700 vB,** and
her sweep. Her wallet ran no prover, and needed neither the hub nor the
sequencer after its request: it waited 2 hours and 20 minutes.

Of her deposit's 151,000 she got back 174,833 on Bitcoin: her 98,406,
her reserve, the hub's reserve less the floor (29,102), and the rest of
her fee budget. The hub, for not answering a true claim, lost its
reserve.

### Sam: a stale claim, proved false

Sam did as Cleo did, without the challenge: his claim of his 99,000
note was prepared and kept, the note paid to Bob and the payment
acknowledged, and once its anchor was past the margin he posted the
stale claim. The hub proved it false on its own server, and his wallet,
finding the proof valid, conceded.

| block | time (UTC) | what |
|---|---|---|
| 3,580,133 | 02:53 | [request](https://mutinynet.com/tx/f4736bd5073f2ba4598835938edd335ff49fd137baa0d9ee808c2820fa7f30c3): 126 units, 2,143 vB |
| | 02:54 | the hub holds the claimed note: the sequencer refuses its spends from now on |
| | 02:59 | it mints itself a sat, for an anchor after the cutoff to show `A*` the last before it |
| | 03:01 | it decides natively: note 10 was spent at `A*` (L2 height 47). It waits for the chain receipt at height 51, where `A*`'s anchor is recorded |
| | 03:36 | the receipt: the hub proves |
| 3,580,237 | 03:47 | proved in 526.0 s (1.65M cycles, two segments), wrapped in 119.3 s: [assert](https://mutinynet.com/tx/4d866a54b8ba0ba272b44fb45c7fc484aa36e9ad947effd305abb024e282d05f), 7,725 vB. His wallet checks the proof natively, finds it valid, and concedes |
| 3,583,117 | | from here, after `Δ2` (2,880 blocks, a day), `success` takes the contract: the hub posts it |

From request to assertion: 104 blocks, 54 minutes, of the 240 the hub
had. Of that, 35 minutes waited for the chain prover and 11 were
proving and wrapping.

### Cleo: a valid proof, challenged anyway

Cleo opened contract 1001, prepared her claim of her 99,000-sat note
(`lichen exit --claim-only`, which keeps it unposted), then paid the
whole note to Bob and acknowledged the payment. Once its anchor was
past the margin, she posted the old claim anyway, set to challenge
whatever the hub asserted (`--challenge-anyway`, a trial switch).

| block | time (UTC) | what |
|---|---|---|
| 3,580,114 | 02:44 | [request](https://mutinynet.com/tx/9c5aac46d1b87abb48f1e4f765625ae16fd1bf99837272862275ed0b5dcc798d): 126 units, 2,144 vB, its floor 2,384 sats out of the contract |
| | 02:49 | no anchor yet spends `A*`'s seal after the cutoff: the hub mints itself a sat, so that the sequencer seals and anchors |
| | 02:51 | the hub decides natively: note 4 was spent at `A*` (L2 height 43), by her acknowledged payment. It waits for the chain prover to reach height 47, where `A*`'s anchor is recorded |
| | 03:22 | the chain receipt at 47: the hub proves (`lichen-hp-prover`) |
| | 03:33 | proved in 520.6 s (1.62M cycles, two segments) and wrapped in 128.4 s |
| 3,580,209 | 03:33 | [assert](https://mutinynet.com/tx/02a7c46a36e3e982034e3f6817fece105770f36606aefd429aa32505334f2619): 7,725 vB |
| 3,580,210 | 03:33 | her wallet checks the proof: valid. It challenges anyway: [challenge_assert](https://mutinynet.com/tx/26b534239e7ac0ae37701672fe5eda32aec2f3a7a25e5e0eb07b4ca4e69fd26f), 20,717 vB |
| 3,580,212 | 03:34 | the hub reads the secrets, evaluates its kept instances, unmasks a `msg` and posts [wrongly_challenged](https://mutinynet.com/tx/84b578529e07d6e2d697bab806362deb3b77e0dec719c81abd46b5177aef7a0c): 262 vB. The contract is the hub's |

The three links paid their floors out of the contract, 30,826 sats,
and carried a 330-sat anchor output each: 31,816 in all, exactly `r_H`,
the reserve the hub sized for the deepest dispute. The rest, 219,155,
is `V_max + r_A`: the hub took the contract, Cleo's deposit and reserve
with it. Her claim was false: she had already paid its note to Bob. A wallet doesn't
challenge a valid proof: this one did only because the trial told it
to.

**Where the time went:** 31 minutes waiting for the sequencer's chain
prover to reach the height the proof needs, and 11 minutes proving and
wrapping, on lichen-hub, a 16-vCPU x86 server. The prover was behind
because the trial had made a burst of heights; it proved each in 75 to
157 s. Both fit easily in `w_H`, 240 blocks, about 2 hours.

### Kim: a lying hub

For Kim's exit the hub was restarted hostile (`HOSTILE`, a trial
setting): it asserts a forged proof against every claim, true ones
too. Kim's claim of her 99,000 note was true.

| block | time (UTC) | what |
|---|---|---|
| 3,580,268 | 04:03 | [request](https://mutinynet.com/tx/57083622707a73f4fa01398f26514af6c3c86ec0c6f0e0d3976e79aa34dc93dc): 126 units, 2,144 vB |
| 3,580,299 | 04:19 | the hub [asserts](https://mutinynet.com/tx/687df0a23e154bda71747c2d3abe32860bb29cc6858e21a104f47f8a5e7dcf03) a forged proof, 7,725 vB. Her wallet checks it natively: it doesn't verify |
| 3,580,301 | 04:21 | [challenge_assert](https://mutinynet.com/tx/09002f935223a51d7c217b43282e4ccd7916c02b1133fa436978f7371a3c7a76), 20,717 vB: her secrets for the digits of the point the hub signed. The hub evaluates its ten kept instances on them: none opens, as none can on a false proof |
| 3,580,541 | | from here, after `Δ1` (240 blocks), `failure` pays Kim `b` and both reserves, less the floors |

The hub lost the contract for asserting a proof it couldn't stand
behind. The links' floors, 2,384 + 7,725 + 20,717 sats and their
anchors, come out of the reserves Kim is paid, which is to say out of
the hub's: she gets her `b` and her own reserve whole.

### Sara: a shielded note

Sara shielded 90,000 of her 99,000, a proof of 3.0 s on a Mac, and
acknowledged it; then she exited, claiming both her notes: the shielded
90,000 and the transparent 9,000 left. A shielded note's claim carries
its opening (position, value, `rho` and trapdoor, 76 bytes) and once her
keys but the spend key (`auth`, `nk` and the exit key `x`), and her exit
key signs `E`: her `request` was 2,194 vB, 59 more than Erin's.

| block | time (UTC) | what |
|---|---|---|
| 3,580,081 | 02:26 | [request](https://mutinynet.com/tx/8134062a5b2b41197c6405bc24cfd54ff3094176226d94d16c56f8fd95f412c6): 126 units, 2,194 vB |
| | by 02:31 | the hub decides: each note's leaf is its commitment at `A*`, its nullifier (now computable from the posted `nk`) unspent, the exit key signed. It holds, and the hub records the exit, retiring both nullifiers |
| 3,580,322 | 04:31 | [request_timeout](https://mutinynet.com/tx/9784787a4e62bb18c1c7a6bcc691dfa299e2971a8f75f3a1a57f69864e6363dc) pays her, 565 vB |
| 3,580,363 | 04:52 | her [sweep](https://mutinynet.com/tx/55a99371945f419acc0928424f51aae0ada10c18db8b7b2de247890e29b201fd): 174,825 sats, 2,283 vB |

Revealing `nk` and the trapdoors lets anyone link her claimed notes'
nullifiers to them, and the senders of notes under the same keys to
learn when she spent them: so after an exit her wallet moves to a fresh
shielded address. Her spend key stays hers: nobody can spend with what
the claim reveals.

## On regtest

The rest of the dispute's cases, played on regtest by `hp_exit.rs` and
`shielded_exit.rs` (blocks every 150 ms, the mock statement: the hub
decides natively and asserts a toy circuit's proof) and by `hp_real.rs`
on the real circuit:

| | what happens | outcome |
|---|---|---|
| Q | one note claimed through two contracts at once | each is asserted false as the other's second claim; the double claimer loses both |
| R | an exit after a withdrawal the hub recorded but didn't fold | the contract's own exit record isn't a spend against it: paid |
| G | the hub and the sequencer gone | she claims from the notes kept; `request_timeout` pays her |
| U | a payment never acknowledged, its input claimed | paid; the exit record voids the payment, and the payee's note stays locked for good |
| W | a payment acknowledged, the acknowledgment withheld by the operator | her locked change claimed, carrying her acknowledgment: paid, the payee's note unlocked |
| real | a stale claim on the real circuit (`hp_real.rs`), the hub proving on a 4-vCPU x86 server | proved in 827 s and wrapped in 268 s; asserted; the exit 1,143 s from request to concession |

## What a hostile operator can try

| the operator | what happens |
|---|---|
| refuses the fold | she exits with the same claim, and is paid |
| stops sealing, or vanishes | she claims what was anchored; no assertion, the timeout pays her |
| holds a payment of hers, and anchors it once she has claimed | past the cutoff: it doesn't count |
| anchors a payment of hers, then withholds its data | she never acknowledged it, so it doesn't count: she claims its inputs |
| asserts a false proof | she challenges, and `failure` pays her |
| claims her notes through its own contract | it can't: only she signs |

## Limits

- **The hub must prove within `w_H`.** It proves only false claims, once
  a contract, and a liar loses the contract. But a coordinated wave of
  false claims could outrun its prover: each one it fails to answer is
  paid. On lichen-hub one proof took about 11 minutes with its wrap; on a
  GPU the proving
  is seconds and the Groth16 wrap the rest
  ([pipeline.md](pipeline.md)).
- **No tower.** Her challenge reveals her dealing's secrets, so a tower
  would have to be trusted. She has to challenge only a lying hub, and
  her window for it is long (a day on Mutinynet).
- **Her opening uploads** the instances the hub keeps: 239 MiB at real
  parameters.
- **Mass exit.** Each exit is a dispute competing for block space, and a
  hub that asserts falsely against everyone forces each user's 20.7 kvB
  challenge, paid from the contract.
