# BABE's other endings: unchallenged by a tower, and a false claim

Two disputes on Mutinynet (2026-10-29), on BABE, against a hub that
refuses every cooperative withdrawal but challenges only false claims
(`--refuse-folds`). Read [babe-challenged.md](babe-challenged.md)
first. It explains the five transactions and the garbled circuits, on
the longest honest ending: a true claim, challenged and answered.

- **Contract 1001, a true claim, unchallenged.** Alice withdraws
  300,000 with a real proof, and a tower in Docker on a rented machine
  plays the dispute for her. The hub checks the proof and lets it
  stand, and `success` pays her.
- **Contract 1002, a false claim.** Bob claims 200,000 with a proof
  that verifies, but for another contract. The hub challenges, none of
  Bob's garbled circuits opens, and `failure` hands the hub the
  contract.

Sizes and fees are as mined. Every transaction is linked to the
Mutinynet explorer.

## Contract 1001: a true claim, unchallenged, played by a tower

| # | transaction | block | size | fee | posted by, paid by |
|---|---|---|---|---|---|
| | [deposit](https://mutinynet.com/tx/193705762bbb6a2bf768dcde63333d99d34ea0d77c508b0bda2de3f7c03bad1a) | 3,543,993 | 327 vB | 656 | Alice's payer wallet |
| | [funding](https://mutinynet.com/tx/e33343b7825465925311cf007651069856b09727413a968725caba11ccd7930b) | 3,543,995 | 305 vB | 2,000 | the hub; half each |
| 1 | [request](https://mutinynet.com/tx/02af03c89a41e9e6546c0e39bb8c410b74c1ab2bd94d77f20861d14696e656b8) | 3,544,013 | 457 vB | 458 | Alice's wallet; the contract |
| 2 | [respond](https://mutinynet.com/tx/4130af01aa5a8b7a135062fd4baa5a8a0037615c518880565e42afa1ae3c1ea0) | 3,544,014 | 759 vB | 761 | the hub; the contract |
| 3 | [assert](https://mutinynet.com/tx/3475a9895e2cd0d5206f1020c7b928676c4a60c99b9f284b9b2c255462dd3610) | 3,544,085 | 7,725 vB | 7,725 | the tower; the contract |
| | [fee coin](https://mutinynet.com/tx/46c33ccbbc872cefb985c3512b8eaa4fec2b4db8702875a241464f9a78554af5) | 3,544,326 | 154 vB | 160 | the tower; Alice's fee budget |
| 4 | [success](https://mutinynet.com/tx/d1e013902f73d46e1ad311a4d356fffb19616081939241ae35c1a38141cf62ce) | 3,544,326 | 780 vB | 783 | the tower; Alice's fee budget |
| | [the hub collects](https://mutinynet.com/tx/a1cc6998d2f94aed8b38103184323c8ab8fa75c42b5ee4f42ef0dee6365ef5fa) | 3,544,331 | 2,733 vB | 2,735 | what it swept |
| | [Alice's sweep](https://mutinynet.com/tx/9d80c59bfdb34f0f7e3d5444bb52603ad9763704b0028cbeb8f2a1813777837c) | 3,544,367 | 1,687 vB | 1,689 | what it swept |

The dispute is transactions 1 to 4: **9,721 vB, 9,727 sats in fees**,
a third of the challenged ending's 30,471 vB. No challenge means no
`challenge_assert` (20,717 vB) and no answer.

### What Alice did

On her own device: `lichen withdraw 1001 300000`, which the hub
refused, then `lichen dispute 1001 300000`. Her wallet posted `request`,
signing `b` = 300,000. The hub posted `respond` the next block, signing
the same `b`. Her wallet then wrote the hub's signature out and stopped,
the proof due by `T_A`, block 3,563,793, 6.9 days away. Her proof covers
the hub's signature on `b`, so it can only be made now.

She proved on a 4-vCPU x86 VPS, from her return's note and path, the
sequencer's chain receipt and the hub's signature: 1,213 s to prove and
434 s to wrap. That's slower than contract 1000's 662 and 257, because
the machine was also building the tower's image. Then she exported the
dispute with the proof (`lichen export-dispute 1001 --input claim.hex`):
a 740 KB `package.json` and the kept instances' `package.d`, 243 MB,
copied to the VPS in 40 s. That was her last move until the sweep.

### What the tower did

The tower is `deploy/tower`'s compose file on that VPS, with
`STATEMENT=babe` and mutinynet.com's Esplora twice
([RUN_A_TOWER.md](../RUN_A_TOWER.md)). Its image takes about 50 minutes
to build on 4 vCPUs, once. Its package holds her signatures (on `b`, on
π1's digits, and on each kept instance's `wrongly_challenged`), the
claim, and her fee budget's key. It holds no key that signs a move of
the dispute. Its whole log:

```
requesting 300000 sats, 02af03c8…
waiting for the hub's response: its window ends at block 3544053
the hub responded: asserting the proof, 3475a989…
asserted at 3544085: the hub may challenge until block 3544325
no challenge came: success pays the user, d1e01390…
Unchallenged(d1e01390…): the payout is d1e01390….
```

It read `request` and `respond` back from the chain, as a resumed
dispute does, and posted `assert` from her signatures on π1. The hub
checked the proof against contract 1001's journal: `the user's proof is
valid; success will pay her`. It then waited out `Δ2`, 240 blocks (two
hours). The tower split a fee coin from her budget and posted `success`
the block after the window closed. `success` is pre-signed
ALL|ANYONECANPAY at zero fee, so the tower adds the coin as an input.
`success` is version 2, so the coin needed no confirmation first.

A tower can't sweep: her bit outputs and the reserve output wait for
her wallet's key. She copied the tower's state file back. The file is
root's, written by the container, so `docker compose cp` makes a copy
she can read. Then she ran `lichen sweep-dispute 1001 --tower-state
package.state.json`, which waited out `δ` (40 blocks) and swept.

### Where the money went

| | sats |
|---|---|
| Alice paid in (the deposit) | 451,000 |
| Alice received at her payout address | 379,557 |
| still hers: tokens on the L2 (400,000 minted, 300,000 returned) | 100,000 |
| the hub put in (the funding, less its change) | 1,740,094 |
| the hub received: its 8 bit outputs less the fee, 1,794,385, and 511 | 1,794,896 |
| the hub's: `respond`'s anchor, unspent | 330 |
| fees in all: the links 8,944, `success` 783 and its coin 160, the sweeps 4,424, the funding 2,000 | 16,311 |

Alice's sweep held:
- `b` rounded down, 299,520 (2^18 + 2^15 + 2^12 + 2^9, as in 1000);
- the reserve output, 52,009;
- her two links' anchors, 660;
- the rest of her fee budget, 29,057;
- less the sweep's fee, 1,689.

The reserve output is `r_A + r_H` (20,000 + 41,943) less the three
links' floors and anchors (9,934). So without challenging, the hub still
lost its reserve: 9,934 paid for the dispute it forced, and 32,009 went
to Alice. A dispute's floors come from the loser's reserve, and a hub
that refuses a true claim loses.

## Contract 1002: a false claim, challenged

| # | transaction | block | size | fee | posted by, paid by |
|---|---|---|---|---|---|
| | [deposit](https://mutinynet.com/tx/535db0d882d1983e1dd99c5e94966588decf8601e664f87f2d8a2a9e42b323cd) | 3,543,995 | 300 vB | 600 | Bob's payer wallet |
| | [funding](https://mutinynet.com/tx/c3214ceb1e6673f8020576ef7bb4df79f3fc28f761f68962eafbdc4e58b7091b) | 3,543,998 | 545 vB | 2,000 | the hub; half each |
| 1 | [request](https://mutinynet.com/tx/1326ae918f6c8bc5235fa48751871bb75e620fd69d52875d42d9e15ef370138b) | 3,544,024 | 456 vB | 458 | Bob; the contract |
| 2 | [respond](https://mutinynet.com/tx/ec824390120e64958d8449e76379af22de572464966d0d1b962a54e04beaf02e) | 3,544,025 | 758 vB | 761 | the hub; the contract |
| 3 | [assert](https://mutinynet.com/tx/d8639f66dbfd0feb26ae69bda1e6b80dabf1959ad6d570f6661aa6cf4deee928) | 3,544,026 | 7,725 vB | 7,725 | Bob; the contract |
| 4 | [challenge_assert](https://mutinynet.com/tx/095228500e168ef032a7fceb2ecf3daed01d55bc6c987f534e3211c979e50d7d) | 3,544,027 | 20,717 vB | 20,717 | the hub; the contract |
| | [fee coin](https://mutinynet.com/tx/54e7d5077cee4125d624230b021bc6d814ef1a005ff3de88f4245dc80a77df1e) | 3,544,150 | 212 vB | 221 | the hub's wallet |
| 5 | [failure](https://mutinynet.com/tx/dd2eaf779acaaf9ca82e86a26fc4b24112704f8720cd031220c72f81e4ff9bf3) | 3,544,150 | 237 vB | 330 | the hub; its fee coin |
| | [Bob's fee budget, swept](https://mutinynet.com/tx/a545efece55082d4bd5bea62bc290d3cf00b12bdd019b5bfe395eeb841c7a73e) | 3,544,375 | 99 vB | 200 | the budget |

The dispute is transactions 1 to 5: **29,893 vB, 29,991 sats in fees**.
That's almost exactly the challenged true claim's size: the same four
links, then a 237 vB `failure` where Alice posted an 821 vB answer.

### The claim

Bob's proof is contract 1000's, from [babe-challenged.md](babe-challenged.md).
It is a real RISC Zero proof of a real return, wrapped in Groth16, and
it verifies. But its journal commits to contract 1000's `c` and to the
hub's key for 1000's `b`, so for contract 1002 the claim is false. His
wallet would refuse it: it checks a claim's journal against the
contract's before asserting. For trials, `lichen dispute --false-claim`
(hidden, test networks only) skips that check. Bob gave the proof up
front, so his wallet asserted the block after `respond`.

### The challenge

The hub checked the proof against 1002's journal, found it false
(`the user's proof is not valid: challenging`), and posted
`challenge_assert` the next block. As in 1000, that reveals the secrets
behind π1's digits. Bob's wallet tried each of his 10 kept instances
with them: 17, 18, 22, 26, 28, 33, 39, 44, 55 and 74. None opened. A
kept instance gives up its `msg` only for a proof that verifies against
the contract's statement, and this one doesn't. So Bob had no answer,
and his wallet said so: `no kept instance opens on this proof: failure
will take the contract`.

### `failure`, and the bug it found

`failure` was valid from `Δ1` (80 blocks) after the challenge, block
3,544,107. The hub's first tries failed: its node wallet wouldn't make
the fee coin, with `Transaction amount too small`. A terminal's
broadcaster adds a coin worth exactly its fee: the transaction's size
plus the coin's input, at the network's rate. At 1 sat/vB that came to
about 240 sats for `failure`, under the 330-sat dust floor of a P2TR
output. Regtest, at 2 sat/vB, never showed it. A terminal's fee is now
at least 330. With the fixed build, the hub's restart posted `failure`
at 3,544,150, 43 blocks late.

The delay cost the hub nothing here. Until `failure` confirms, only an
answer can spend the challenge's output, and Bob had none. Against a
true claim, a late `failure` would only give Alice longer to answer.

### Where the money went

| | sats |
|---|---|
| Bob paid in (the deposit) | 351,000 |
| Bob received: the rest of his fee budget | 29,800 |
| still his: tokens on the L2 (300,000 minted, 200,000 returned) | 100,000 |
| the hub put in: the funding, less its change | 1,840,094 |
| the hub put in: `failure`'s fee coin, and its fee | 551 |
| the hub received: `failure` | 2,128,113 |
| unspent: the four links' anchors | 1,320 |
| fees in all: the links 29,661, `failure` 330, its coin 221, Bob's sweep 200, the funding 2,000 | 32,412 |

`failure` paid the hub the whole contract output: the cap, both
reserves, and Bob's deposit, less the four links' floors and anchors
(30,981).

- **Bob** lost his stake, `D + r_A` = 320,000, and his half of the
  funding fee. His 200,000 returned tokens are the hub's on the L2. The
  100,000 he kept are still his, but no contract of his covers them now
  ([cooperative.md](cooperative.md#alices-5000)).
- **The hub**, net on chain, gained 287,468: Bob's stake less the
  dispute's floors and anchors, its half of the funding fee, and
  `failure`'s fee.

Compare BitVMX ([lie-caught.md](lie-caught.md)). There, at these sizes,
an honest hub lost 58,000 to 159,000 sats beating a liar. The liar chose
the lie, and with it the search's cost: 100,000 to 200,000 vB. Under
BABE a false claim's dispute has one shape whatever the lie, about
30,000 vB. Its floors are the 30,981 the hub's reserve is sized to, and
the liar's stake pays them.

## What these runs show

- **Three of BABE's endings have now run on Mutinynet:** a true claim
  challenged and answered (1000), unchallenged (1001), and a false
  claim (1002). The other two (the hub gone, Alice gone) run on regtest.
- **A tower in Docker played a BABE dispute** holding no key that signs
  a move: only signatures and a fee budget's key. Alice's device did
  nothing between the export and the sweep.
- **A refused true claim costs the hub its reserve,** challenged or
  not. A challenge only moves more of it from Alice to fees: 32,009
  reached her here, 10,962 in 1000. She is paid `b` either way.
- **A false claim costs the liar her stake,** in a dispute of fixed
  size, 29,893 vB.
- **Fixed on the way:**
  - A terminal's fee coin is now at least the dust floor.
  - The hub no longer logs "responding" each time a failed tick re-reads
    a dispute.
  - The tower's last message and [RUN_A_TOWER.md](../RUN_A_TOWER.md)
    now show how to copy its root-owned state file.

## Reproducing it

A deployment as in [deploy/README.md](../../deploy/README.md), the hub
started with `STATEMENT=babe` and `REFUSE_FOLDS` set, with wallets set
up as testers' ([RUN_A_HUB.md](../RUN_A_HUB.md#testers)) and
`--statement babe`.

Alice, to her proof as in [babe-challenged.md](babe-challenged.md#reproducing-it)
(`open`, `withdraw`, `dispute`, `lichen-r0 babe-claim`), then:

```sh
lichen export-dispute 1001 --input claim.hex --out package.json
# to the tower's machine, and deploy/tower's compose up (RUN_A_TOWER.md)
lichen sweep-dispute 1001 --tower-state package.state.json
```

Bob, with any other contract's claim:

```sh
lichen open 300000 --payout <his address>
lichen withdraw 1002 200000                     # refused
lichen dispute 1002 200000 --input <another contract's claim.hex> --false-claim
lichen sweep-fees 1002                          # the rest of his fee budget
```
