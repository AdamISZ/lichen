# Opening a contract

A walkthrough of how Alice opened contract 1001 on Mutinynet
(2026-10-12). That's the contract of Test B, whose dispute is in
[hub-absent.md](hub-absent.md). Opening takes four requests to the hub
and two Bitcoin transactions. Between them, Alice and the hub sign every
transaction any ending of the contract could need, before the contract
holds a single sat.

| transaction | block | size | fee | paid by |
|---|---|---|---|---|
| [deposit](https://mutinynet.com/tx/dc089a531e9a9eb785a6c6cd91c32334ef991d1975e7907092f3d0723543e757) | 3,500,811 | 154 vB | 342 | Alice's payer wallet |
| [funding](https://mutinynet.com/tx/418b42cc4111e06a970d08afef94121f0a9e73cdf7bd8cd2f5e3e19fd6d4f7b6) | 3,500,812 | 305 vB | 2,000 | 1,000 each |

![the opening of contract 1001](img/opening-sequence.svg)

## The terms

Alice asks for three things. The hub sets the other three.

| term | value | set by | meaning |
|---|---|---|---|
| `D` | 30,000 | Alice | her deposit, minted to her as tokens on the L2 |
| `V_max` | 65,535 = 2^16 − 1 | Alice, within the hub's limit | the cap: the most any withdrawal can be |
| `r_A` | 20,000 | Alice | her reserve: back to her in every honest ending |
| contract number | 1001 | the hub | also the memo `c` her returns must carry |
| `T_close` | 3,520,971 | the hub | a week of blocks: after it, with no claim, the contract closes by default |
| `r_H` | 197,356 | the hub | its reserve: what the loser of the deepest dispute pays in fees |

Alice also gives two addresses. Her **payout address**, of any wallet she
likes, is where every ending pays her. Her **L2 address** is where the
hub mints her tokens.

`r_H` looks large next to a cap of 65,535. It is the most that a dispute's
links can peel off the contract as fees: the links pay their own way, at
a fixed floor, out of the contract. The hub measures it from the
pre-signed set itself, and takes the larger of that and a share of the cap
(2%, here 1,310). The amount is the same for every contract on the
statement, because the links' sizes don't depend on the amounts. At this
cap, it dominates.

## 1 and 2. Checking the hub; the deposit address

**`/info`.** Before anything else, Alice's wallet checks that the hub is
the one it means to deal with:

- the same network;
- the same deployment, the sequencer's key and the hub's L2 key, which
  the wallet pinned at `init`;
- the same statement, here Groth16, with the same 21 search depths.

**`/deposit`.** Alice sends a fresh deposit key. The hub answers with the
contract's number, its own key, and a timeout: 2,880 blocks on
Mutinynet, a day. Together these make the deposit address, a taproot
output with two leaves:

- **`deposit_open`:** the hub's signature and Alice's. Only the funding
  transaction spends it this way.
- **`deposit_refund`:** Alice alone, after the timeout. If the hub
  disappears, or the opening fails part-way, she takes her deposit back
  (`lichen refund`).

Thanks to the deposit address, the lichen wallet holds no bitcoin of
Alice's: she pays the address from anywhere, an exchange or a faucet.

## 3. The deposit

Alice paid **71,000** sats to the deposit address
([dc089a53…](https://mutinynet.com/tx/dc089a531e9a9eb785a6c6cd91c32334ef991d1975e7907092f3d0723543e757)):

| | sats |
|---|---|
| `D`, the deposit | 30,000 |
| `r_A`, her reserve | 20,000 |
| her share of the funding's fee | 1,000 |
| her fee budget, for a dispute's terminal transactions | 20,000 |

The wallet waits for it to confirm, then asks to open.

## 4. The offer

**`/open`.** Alice's request carries the terms she asks for, her
addresses, the deposit's coin, and her public keys. Besides her ordinary
signing key, these are **one-time (Winternitz) keys**, generated from
her wallet's seed and a fresh nonce:

- 51 for the claim's input words, one per word. In a dispute she signs
  her claim with these: `b`, the memo, the proof, the deployment.
- one per field of each of her moves in the search: depths 1, 3, 5,
  …, 21;
- 8 for the read challenge: one per hop she might challenge.

The hub checks the request against its limits (a cap of at most 2^16
here), and that the deposit is on chain, confirmed, unspent and paid to
the right address. Then it builds the contract and returns an
**offer**:

- `T_close` and `r_H`;
- its own keys: its signing key, and one-time keys for its moves (depths
  2, 4, …, 20) and for the read challenge's path;
- the funding transaction, unsigned;
- **its signatures on all 141 pre-signed transactions.**

### What is pre-signed

Every transaction that spends an output the two of them share is signed
by both, now. Later, neither side needs the other's cooperation to use
any of them. 141 transactions, with 169 inputs, so 169 signatures from
each side:

| transactions | how many | what they do |
|---|---|---|
| `escalate` | 1 | Alice's claim and move 1: spends the contract output |
| `inputs` | 1 | the rest of the claim's input words |
| `move_2` … `move_21` | 20 | the search's moves, the hub's at even depths and Alice's at odd |
| `timeout_1` … `timeout_21`, `timeout_inputs` | 22 | if a side doesn't move in its window, the other wins: Alice by the payout of her claim, the hub by taking everything |
| `prove_<op>` | 62 | Alice's proof of the disputed last step: one for each instruction variant the verifier runs |
| `path_split`, `combine_1` … `combine_8` | 9 | the hub's read-challenge path, posted in up to 8 chunks then combined |
| `hop_1` … `hop_8` | 8 | Alice challenging one hop of that path |
| `timeout_path_split`, `timeout_combine_*`, `timeout_hop_*` | 17 | the read challenge's windows |
| `default` | 1 | after `T_close` with no claim: Alice's reserve back, the rest to the hub |

`combine_K` has `K` inputs, one per chunk, which is where the extra 28
signatures come from.

Some transactions aren't in the set: those that pay one side everything.
Examples are the hub's disproves, its input-word checks, and its
equivocation leaves. Each needs only the winner's key and the evidence
in its witness, so nobody has to pre-sign it.

67 of each side's signatures are 64 bytes: SIGHASH_DEFAULT, committing to
the whole transaction. The other 102, on every timeout, every
`prove_<op>` and `default`, are 65 bytes: ALL|ANYONECANPAY. These carry no fee of their own,
so whoever broadcasts one adds a coin to pay for it. That's the fee
budget's job.

## 5. Alice checks, then signs

Alice's wallet checks, in order:

- the offer is for her deposit's contract number;
- the terms are hers, and `T_close` is in the future;
- the funding: output 0 is exactly the contract the terms make, output 1
  is her fee budget, and her deposit is spent in full;
- **every one of the hub's 169 signatures**, against the transactions
  she rebuilds herself from the terms and both sides' keys.

Only then does she sign the 141 transactions, and her deposit's input to
the funding. Taproot signatures commit to every input's coin, so hers
fixes the hub's coins as well as her own: the hub can't swap the funding
for another.

**`/accept`.** She sends her 169 signatures and the deposit signature.
The hub checks them all, adds its own signature on the deposit input and
on its coin, and broadcasts the funding.

## The funding

[418b42cc…](https://mutinynet.com/tx/418b42cc4111e06a970d08afef94121f0a9e73cdf7bd8cd2f5e3e19fd6d4f7b6)
· 305 vB · fee 2,000 · block 3,500,812

![the funding of contract 1001](img/opening-funding.svg)

| | sats | |
|---|---|---|
| **in:** Alice's deposit | 71,000 | by `deposit_open`: 4 witness items, the two signatures, a 68-byte script, its control block |
| **in:** a coin of the hub's | 465,964 | by key |
| **out 0:** the contract | 282,891 | `V_max + r_A + r_H` |
| **out 1:** Alice's fee budget | 20,000 | her key |
| **out 2:** the hub's change | 232,073 | its wallet |

Into the contract, Alice put `D + r_A` = 50,000, and the hub
`V_max − D + r_H` = 35,535 + 197,356 = 232,891. The hub covers the rest
of the cap, the part above Alice's deposit. That is what lets her
receive more on the L2 than she deposited, and still withdraw it.

## The mint

When the funding confirms, the hub issues `D` = 30,000 tokens to Alice's
L2 address, through the sequencer. For 1001 and 1002 that took about a
minute from the deposit's confirmation. The contract is now open. Its
endings are:

- a cooperative fold ([cooperative.md](cooperative.md));
- a dispute ([hub-absent.md](hub-absent.md),
  [hub-returns.md](hub-returns.md)), paid out as in
  [payout.md](payout.md);
- `default`, after `T_close`, if Alice never claims.

## Why the order is safe

- **Before the funding, Alice risks only a delay.** Until she signs the
  deposit input, the hub can't spend her deposit. If the hub stalls at
  any point, she refunds after the timeout.
- **Alice signs nothing until she holds the hub's signatures on
  everything.** Her signatures and the funding go last, so the contract
  can't exist without all its exits already signed.
- **The hub broadcasts, but can't change what it broadcasts.** Alice's
  signature on the deposit input commits to the whole funding: its
  outputs, and every coin it spends.
- **The hub risks nothing before it broadcasts.** It checks all 169 of
  Alice's signatures before adding its own to the funding.

## What it costs

On chain, 459 vB: the deposit (154 vB, from Alice's payer wallet) and the
funding (305 vB, 2,000 sats split between the two sides). Off chain,
the offer and the acceptance carry the one-time public keys and 338
signatures. The hub keeps them all in the contract's record, its only
memory of the contract: everything else about a dispute it reads from the
chain ([hub-returns.md](hub-returns.md)).
