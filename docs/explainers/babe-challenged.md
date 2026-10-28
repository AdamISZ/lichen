# A BABE dispute: a true claim, challenged

A walkthrough of one real dispute on Mutinynet (2026-10-29), played on
BABE, lichen's second verification gadget (branch `gadget`;
[BABE_GADGET_PLAN.md](../BABE_GADGET_PLAN.md), the design note
`papers/lichen-babe-v0.1.6`). Alice withdraws 300,000 sats from contract
1000 with a real RISC Zero proof. The hub is hostile: it refuses every
cooperative withdrawal and challenges every claim, true ones too. So the
dispute runs to its longest honest ending: the hub challenges a valid
proof, and Alice answers. Every transaction is linked to the Mutinynet
explorer; sizes and fees are as mined.

| # | transaction | block | size | fee | paid by |
|---|---|---|---|---|---|
| | [deposit](https://mutinynet.com/tx/370ed7f27d271438203d7ececa88bfb9fd3695049501fd6e50c0067bc2bc6fbd) | 3,543,216 | 269 vB | 540 | Alice's payer wallet |
| | [funding](https://mutinynet.com/tx/ac6d2230fbd79d9e1c724d82e35b3ec52acdf55083c1502c41c17fa086d6ce72) | 3,543,218 | 362 vB | 2,000 | half each |
| 1 | [request](https://mutinynet.com/tx/fc6c4f8031a784878d70dcf0ff5f5697974a482a615bf4fdcdbe31558e8b5ed7) | 3,543,234 | 449 vB | 458 | the contract (the loser's reserve) |
| 2 | [respond](https://mutinynet.com/tx/f3b64aae6ad4aab05145e5e3d755a28a6942ce40bd0021ce17fcbb64348d1b11) | 3,543,235 | 759 vB | 761 | the contract |
| 3 | [assert](https://mutinynet.com/tx/3b9e22671325c54fe140ff61d17bef4dc2f4e1ab78c3068c52377750f29649a4) | 3,543,266 | 7,725 vB | 7,725 | the contract |
| 4 | [challenge_assert](https://mutinynet.com/tx/74ba41262c89163683c43007762179fced23fc28f97af23b7658b73a839c02e5) | 3,543,267 | 20,717 vB | 20,717 | the contract |
| | [fee coin](https://mutinynet.com/tx/524486657799dc239962da45a239a4ae61d2fce58f97770fada1ad68c921b4d7) | 3,543,271 | 154 vB | 160 | Alice's fee budget |
| 5 | [wrongly_challenged_0](https://mutinynet.com/tx/2535dae6798f0114659287bb79096ad89fa8a95c45a481cf7353889cdde3cc4a) | 3,543,272 | 821 vB | 823 | Alice's fee budget |
| | [the hub collects](https://mutinynet.com/tx/8f57fafe7cfb3166b21ada8c6f82b6060762416c2aa5007c15024607781e269c) | 3,543,273 | 2,725 vB | 2,727 | what it swept |
| | [Alice's sweep](https://mutinynet.com/tx/f914c7c176597a7a6f0a7ec1be96a834aa7bd63516d5b48dc27792d1ef3786b4) | 3,543,312 | 1,737 vB | 1,739 | what it swept |

The dispute is transactions 1 to 5: **30,471 vB, 30,484 sats in fees**,
two thirds of it the hub's challenge. From `request` to Alice's answer
took 19.5 minutes, 15 of them her proving. For comparison, the BitVMX
disputes on Mutinynet were 23,051 vB with the hub absent
([hub-absent.md](hub-absent.md)), and 100,000 to 200,000 vB for a lie
caught by the search ([lie-caught.md](lie-caught.md)).

## BABE in one paragraph

At opening the hub encrypts a random `msg` so that only a valid proof of
the withdrawal for this contract can decrypt it: a witness encryption,
built as a garbled circuit. In a dispute Alice publishes part of her
proof (π1) on chain. If the hub thinks it false, it challenges, and the
challenge, by construction, reveals the garbled circuit's input labels
for the π1 she posted. With them Alice evaluates the circuit and
decrypts. A valid proof yields `msg`; she posts it, and a hashlock pays
her. A false proof yields nothing, and the hub's `failure` takes the
contract after `Δ1`. No verifier runs on chain, and none is searched:
the verifier is inside the garbled circuit, which never goes on chain.
A cut-and-choose at opening keeps the hub's garbling honest.

## The contract

| term | value | meaning |
|---|---|---|
| `V_max` | 2,097,151 | the cap: a withdrawal is `b < 2^21` sats |
| `D` | 400,000 | Alice's deposit, minted to her as tokens on the L2 |
| `r_A` | 20,000 | Alice's reserve |
| `r_H` | 41,943 | the hub's reserve, 2% of the cap: at least the floors of the longest dispute, 30,981 |
| `low_bits` | 9 | on the dispute path, bits of `b` below 2^9 get no output |
| `T_close` | 3,563,376 | a week after opening |
| `to_self_delay` | 10 blocks | `request` waits this long after funding |
| `w_H` | 40 blocks | the hub's window to `respond` (20 minutes) |
| `T_A` | 3,563,016 | the deadline for Alice's `assert`: `T_close` less the other windows |
| `Δ2` | 240 blocks | the hub's window to challenge (2 hours) |
| `Δ1` | 80 blocks | Alice's window to answer a challenge (40 minutes) |
| `δ` | 40 blocks | the bit and reserve outputs' wait |
| statement | `babe` | a RISC Zero receipt of the BABE guest, wrapped in Groth16 |

The statement's public input is the journal `c ‖ D ‖ H(pk_H)`: the memo
`c` (1000, the contract's number), the contract's id `D` (its deployment
and the anchor checkpoint both sides checked at opening), and the hash
of a one-time key of the hub's for `b`. All three are known at opening,
so the hub can encrypt before anyone proves anything. `b` is not in it:
the proof shows instead that the hub signed `b` with that key, as it
does in `respond` (below). One journal serves every amount.

The contract output holds `V_max + r_A + r_H` = 2,159,094 sats. The
hub's reserve is small next to BitVMX's (197,356 at a cap of 2^16):
BABE's longest dispute has four links, not dozens.

## Opening: the cut-and-choose

Opening is where BABE does its heavy work, once per contract.

1. **The hub deals.** It builds 78 instances, each a garbled circuit
   computing `r·π1` and a ciphertext of its own `msg` under the
   statement for this journal: 24 MB each, 9.5 s for all 78. It
   commits to each by hash. The circuits' input labels are reached
   through secrets shared across the instances: for each 2-bit digit
   of π1 and each of its four values, a polynomial `f` of degree 68,
   committed coefficient by coefficient. Instance `i` gets `f(i)`.
2. **Alice chooses** 10 instances to keep; the hub opens the other 68:
   their seeds and their shares. Alice rebuilds each opened instance
   from its seed, checks its hash, and checks its shares lie on the
   committed polynomials. A hub that garbled dishonestly is caught,
   unless every bad instance is among the 10 she keeps: odds of 1 in
   C(78, 10), about 2^40.
3. **She downloads the 10 kept instances** (243 MB), checks each
   against its hash, and checks that each `wrongly_challenged_k` locks
   to SHA-256 of that instance's `msg`.
4. **She hands over her keys and pre-signatures:** a one-time key for
   `b`; a Lamport key for π1, with four hashes for each of its 254
   digits; and 1,016 adaptor pre-signatures on `challenge_assert`, one
   per digit and value, each adapted to the point `f(0)·G` of that
   digit and value's polynomial. Then both sides sign the dispute's 19
   pre-signed transactions. Alice keeps her signatures on the ten
   `wrongly_challenged_k` to herself (see 5).

**The deposit and the funding.** Alice paid 451,000 = `D` + `r_A` + a
fee budget of 30,000 + her half of the funding fee, from a wallet of
her own, to a deposit address whose 2-of-2 leaf the funding spends. The
hub added two of its coins. The funding's outputs are the contract
(2,159,094), Alice's fee budget (30,000) and the hub's change.

## Off chain: the return, refused

Alice returns 300,000 tokens to the hub on the L2, memo 1000, and asks
for a cooperative withdrawal. Her wallet first waits for the return's
height to be anchored on Bitcoin and proved valid by the sequencer's
chain prover (7 minutes 44 seconds), so that it holds what a dispute
needs. The hub refuses.

## 1. `request`: Alice signs `b`

[fc6c4f80…](https://mutinynet.com/tx/fc6c4f8031a784878d70dcf0ff5f5697974a482a615bf4fdcdbe31558e8b5ed7)
· 449 vB · fee 458 · block 3,543,234

It spends the contract output by its `request` leaf: 2-of-2
pre-signed, after `to_self_delay`, and Alice's one-time Winternitz
signature on `b` = 300,000 (8 digits of 4 bits, 2 of checksum). The
witness has 24 elements, the script 817 bytes.

Its outputs are the requested output and Alice's 330-sat anchor. The
requested output has two leaves:

- **`respond`:** the hub's move, after a block;
- **`request_timeout`:** after `w_H`, Alice's payout of `b`. A hub that
  never responds loses the withdrawal.

## 2. `respond`: the hub signs the same `b`

[f3b64aae…](https://mutinynet.com/tx/f3b64aae6ad4aab05145e5e3d755a28a6942ce40bd0021ce17fcbb64348d1b11)
· 759 vB · fee 761 · block 3,543,235

The hub signs `b` with its one-time key, a Winternitz key over SHA-256.
The script verifies both signatures and checks, digit by digit, that
they sign the same value. So the hub can't sign another `b`, and
signing is mechanical: an honest hub signs whatever Alice requested,
and a dishonest one can only let `request_timeout` pay her.

The output's leaves:

- **`assert`:** Alice's proof, after a block;
- **`respond_timeout`:** the hub's, from `T_A` (an absolute lock), if
  she never asserts.

## Off chain: the proof

The hub's signature on `b` is part of what Alice proves, so she can only
prove now. Her wallet reads it from `respond`, checks it under the hub's
key, writes it out for the prover, and stops: the proof is due by `T_A`,
19,781 blocks (about a week) away. On a 4-core x86 machine the BABE guest
proved the withdrawal and the hub's signature in 640 s (476,418
cycles), and RISC Zero's Groth16 wrap took 254 s.

The proof is three curve points: π1 and π3 on G1, π2 on G2. Only π1 goes
through the garbled circuit.

## 3. `assert`: π1, signed

[3b9e2267…](https://mutinynet.com/tx/3b9e22671325c54fe140ff61d17bef4dc2f4e1ab78c3068c52377750f29649a4)
· 7,725 vB · fee 7,725 · block 3,543,266

π1's coordinates are 508 bits. Alice signs them under her Lamport key
in 2-bit digits: 254 preimages, 20 bytes each, one of the four for each
digit. π2 (64 bytes) and π3 (32 bytes) ride along unsigned, so that the
hub can check the whole proof from the chain. The witness has 260
elements; the script, 24,713 bytes, hashes each preimage and finds it
among the digit's four hashes.

The output's leaves:

- **`challenge_assert`:** the hub's challenge, after a block;
- **`success`:** Alice's payout of `b`, after `Δ2`.

The hub checks the proof natively, in milliseconds. It is valid: an
honest hub lets `success` pay Alice after two hours. This hub
challenges anyway.

## 4. `challenge_assert`: the hub reveals π1's secrets

[74ba4126…](https://mutinynet.com/tx/74ba41262c89163683c43007762179fced23fc28f97af23b7658b73a839c02e5)
· 20,717 vB · fee 20,717 · block 3,543,267

For each of the 254 digits the leaf takes Alice's preimage, copied from
`assert`, which selects one of four keys, and a signature under that
key. The only signature the hub can make is the completion of Alice's
adaptor pre-signature for that digit and value, and completing it takes
the secret `f(0)` of the value she asserted. Posting the completion
hands her the secret: the difference between the two signatures. The
witness has 512 elements, 508 of them the reveal; the script is 60,272
bytes.

**Why 2-bit digits.** A tapscript's witness may hold 1,000 elements.
Bit by bit the reveal would be 1,016 elements and the leaf's own
signatures, too many; two bits at a time, 508.

The output's leaves:

- **`wrongly_challenged_0` to `_9`:** one per kept instance, 2-of-2
  and SHA-256 of that instance's `msg`, after a block;
- **`failure`:** the hub's, after `Δ1`.

## Off chain: opening a kept instance

Alice's wallet reads the challenge's 254 secrets. For each kept
instance `i`, each digit's polynomial now has 69 known points (the 68
opened shares and `f(0)`), enough for its degree 68: she interpolates
`f(i)`, the instance's input secret, and through the instance's table
its input labels for π1. She evaluates the garbled circuit (528,000 AND
gates) to `r·π1`, and with π2 and π3 decrypts the ciphertext. Instance
9, the first she kept, gave a `msg` whose SHA-256 is its hashlock.

A false proof decrypts to nothing, in every instance: then no
`wrongly_challenged` can be posted, and `failure` takes the contract.
A kept instance garbled wrongly would fail too, and she would try the
next.

## 5. `wrongly_challenged_0`: Alice's answer

[2535dae6…](https://mutinynet.com/tx/2535dae6798f0114659287bb79096ad89fa8a95c45a481cf7353889cdde3cc4a)
· 821 vB · fee 823 · block 3,543,272

It spends the challenged output by `wrongly_challenged_0`. The witness
is small: both signatures, `msg` (32 bytes), and a 109-byte script. A
[fee coin](https://mutinynet.com/tx/524486657799dc239962da45a239a4ae61d2fce58f97770fada1ad68c921b4d7)
of exactly the fee, split off Alice's budget, is its second input. It
was mined five blocks after the challenge, well inside `Δ1`'s 80.

**Why Alice keeps her signature on it from the hub.** The hub knows
every `msg`. With both signatures it could post `wrongly_challenged`
itself, padded with its own inputs into a large transaction at a low
fee rate, and pin it there. Alice's own broadcast would then have to
beat that transaction's whole fee, and if the pinned one didn't
confirm within `Δ1`, the hub's `failure` would win. So her signature
goes only to her own towers (below).

**Why it is TRUC (version 3).** A tower holding her signature, if run by
the hub, could still pin it. TRUC caps the transaction at 10,000 vB,
which bounds what an honest broadcaster must outbid. A TRUC transaction
can't spend an unconfirmed ordinary one, so the fee coin confirmed
first.

Its outputs are the payout, as BitVMX's ([payout.md](payout.md)):

- **12 bit outputs, 2^9 to 2^20.** Alice owns those whose bit is set in
  her signed `b`. 300,000 is 2^18 + 2^15 + 2^12 + 2^9 + 480, so hers are
  262,144, 32,768, 4,096 and 512: 299,520. The low 480 is rounding.
- **The reserve output, 30,962:** `r_A + r_H` less the four links'
  floors (29,661) and anchors (1,320). Alice's, after `δ`.
- **511 to the hub:** bits 0 to 8 of the cap.

## The sweeps

**The hub** collected its eight bit outputs (those clear in `b`) the
next block,
[8f57fafe…](https://mutinynet.com/tx/8f57fafe7cfb3166b21ada8c6f82b6060762416c2aa5007c15024607781e269c):
1,797,120 less a 2,727 fee. Each input shows Alice's signature on `b`
again, which settles the bit.

**Alice** swept after `δ`,
[f914c7c1…](https://mutinynet.com/tx/f914c7c176597a7a6f0a7ec1be96a834aa7bd63516d5b48dc27792d1ef3786b4):
her four bit outputs, the reserve output, her two links' anchors, and
the rest of her fee budget, **358,260 sats** to her payout address.

## Where the money went

| | sats |
|---|---|
| Alice paid in (the deposit) | 451,000 |
| Alice received at her payout address | 358,260 |
| still hers: tokens on the L2 (400,000 minted, 300,000 returned) | 100,000 |
| the hub put in (the funding, less its change) | 1,740,094 |
| the hub received: its bit outputs, less the fee, and 511 | 1,794,904 |
| the hub's: two anchors, unspent | 660 |
| fees in all: the floors 29,661, the fee coins 320, the answer 823, the sweeps 4,466, the funding 2,000 | 37,270 |

For her 300,000 returned tokens Alice got `b` rounded down, 299,520,
her reserve, 20,000, and what was left of the hub's reserve after the
floors and anchors, 10,962. The hub got back its share of the cap less
`b`. Challenging a true claim cost it its reserve, 41,943.

The 100,000 tokens Alice kept on the L2 are ordinary tokens, but the
dispute closed contract 1000, so no contract of hers covers them now:
the same position as [Alice's 5,000](cooperative.md#alices-5000) after a
fold, with the same remedy, a new contract.

## The other endings

Played on regtest through the same hub and wallet, not on Mutinynet:
the first two on a real proof (`crates/hub/tests/babe_risc0.rs`), the
others on the mock statement (`babe.rs`, `babe_resume.rs`):

| ending | what happens | who is paid |
|---|---|---|
| no challenge | the hub checks the proof and waits; `success` after `Δ2` | Alice, `b` |
| a false proof | the hub challenges; no kept instance opens; `failure` after `Δ1` | the hub, everything |
| the hub gone | no `respond`; `request_timeout` after `w_H` | Alice, `b` |
| Alice gone | no `assert`; `respond_timeout` from `T_A` | the hub, everything |

A wallet can stop and resume anywhere in the dispute: what is on chain
is replayed.

## A tower holds no keys

Alice's own moves are `request` and `assert`, and nothing presses her
on them: `T_A` was a week away. Her one move inside a window is the
answer, and it takes no key: her signature on `wrongly_challenged` was
made at opening, and `msg` comes from the chain, the kept instances and
the proof. So she can hand the dispute to a tower with signatures alone
([RUN_A_TOWER.md](../RUN_A_TOWER.md#under-babe)): on `b`, on π1, and on
`wrongly_challenged`. A tower can't sign a second `b` or a second π1,
and the worst it can do is stay silent. Several can run at once, run by
strangers. Under BitVMX a tower holds her move keys, and one that signs
a move two ways loses her the dispute.

## Compared with BitVMX

| | BitVMX (Mutinynet) | BABE (this run) |
|---|---|---|
| opening | 141 to 169 pre-signed transactions | 19 pre-signed; 243 MB of kept instances to download |
| the longest dispute | dozens of links; 100,000 to 200,000 vB | four links and the answer; 30,471 vB |
| the longest dispute's floors, which the hub's reserve must cover | 197,356 (a cap of 2^16) | 30,981 (a cap of 2^21) |
| Alice's proof | before the dispute | after `respond` (it covers the hub's signature on `b`) |
| a tower | holds her move keys | holds signatures only |

## What this run shows, and what to tidy

- **A true claim survives a hostile hub,** in five transactions. The
  hub can't stop it by challenging, and its challenge is the costly
  move: 20,717 vB of the 30,471, and its reserve.
- **The proof fits between `respond` and `T_A`:** 15 minutes against
  a week.
- **The deployment's Mutinynet node rejected the TRUC answer**
  (`version`): its image is a 25.99 build, before TRUC. Its peers, 29.x,
  relay it, so the wallet, resumed through mutinynet.com's Esplora,
  posted it within the window. The first fee coin,
  [082a38d5…](https://mutinynet.com/tx/082a38d5d1816479c87b0e97d713ad56a9bc4bc3120c800e9044f396999cbbf7),
  went unused, and the sweep took it back. The node image wants the
  current Mutinynet build; mainnet relays TRUC from Bitcoin Core 28.
- **The hub's two link anchors** (660) are left unspent: it collects
  its bit outputs but not its anchors.

## Reproducing it

A fresh deployment as in [deploy/README.md](../../deploy/README.md),
the sequencer anchoring and its chain prover running, the hub started
with `STATEMENT=babe` and `HOSTILE` set. Alice, with a wallet set up as
a tester's ([RUN_A_HUB.md](../RUN_A_HUB.md#testers)) and
`--statement babe`:

```sh
lichen open 400000 --payout <her address>       # pay the deposit address it prints
lichen withdraw 1000 300000                     # refused
lichen dispute 1000 300000                      # requests; stops when the hub has signed b
lichen withdraw-input 1000 > withdraw-input.json
lichen chain-receipt 1000 chain.receipt
lichen-r0 babe-claim withdraw-input.json <the hub's signature, as dispute printed> chain.receipt claim.hex
lichen dispute 1000 --input claim.hex           # asserts, answers the challenge, sweeps
```

`lichen-r0` runs on x86 Linux with Docker, for the Groth16 wrap.
