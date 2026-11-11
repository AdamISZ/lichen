# Using a lichen wallet

A user runs only `lichen`, the wallet: no node, no coins in it. It reads
Bitcoin from a public Esplora server, holds keys, and talks to the
hub's two services: the L2's sequencer and the hub. Deposits are paid
into it from any Bitcoin wallet, and withdrawals paid out to an address
of any wallet. Running the hub is [RUN_A_HUB.md](RUN_A_HUB.md).

## What you need

- **The wallet.** Build it from source, with ln-gap's checkout beside
  lichen's (lichen's workspace refers to it by path), and Rust:
  ```sh
  git clone https://github.com/AdamISZ/lichen && git clone https://github.com/AdamISZ/ln-gap
  cd lichen && cargo build --release -p lichen-wallet     # target/release/lichen
  ```
- **The hub's two URLs**, the sequencer's (port 18300) and the hub's
  (18310), and the sequencer's key, from the hub's operator.
- **For shielded payments only:** a prover for the spend guest, passed
  as `--spend-prover`: `lichen-r0` itself, built natively from `r0/`
  (`cargo build --release --manifest-path r0/Cargo.toml -p lichen-r0`;
  on a Mac, with Xcode and its Metal toolchain), or Docker and the
  prover image (`docker build -f r0/Dockerfile -t lichen-r0 .`, a large
  image) through `r0/spend-prover.sh`.

Every command takes the network, the wallet file and the two URLs. A
shell alias saves repeating them:

```sh
alias lw='target/release/lichen --network mutinynet --wallet alice.json \
  --sequencer http://<host>:18300 --hub http://<host>:18310 --statement hub-proves \
  --spend-prover r0/target/release/lichen-r0'
```

`--statement` is the hub's (`hub-proves` on a real deployment). The
wallet file holds secrets: keep it, and the directory beside it
(`alice.d/`), private.

## A contract

```sh
lw init                                  # a fresh key; pins the deployment the sequencer announces
lw open 100000 --liquidity 200000
```

`init` pins the deployment: check the sequencer's key it prints against
the operator's. `open` asks the hub for a contract of a 100,000-sat
deposit with 200,000 sats of **liquidity**: what you can receive beyond
your balance. The hub charges for the liquidity (1% by default), kept
out of what it mints you, so `open` first prints its quote:

```
the hub's fee for 200000 sats of liquidity: 2000 sats; you'll be minted 98000 sats, with a cap of 298424 sats
```

The cap, your balance plus the liquidity, is rounded up a little to the
contract's unit (a few hundred sats, in which an exit pays). `open`
then prints a deposit address and an amount, `D` plus your reserve, a
share of the funding fee and a fee budget for an exit's fees, and waits. Pay
it from any wallet or faucet; if you don't like the quote, don't pay.
The deposit address is the hub's key and yours together, or yours alone
after about a day: if the contract never opens, `lw refund <contract>`
takes it back.

Once it's paid and confirmed, the wallet garbles the circuits that would
check the hub's proof if it ever says your exit claim is false (some
10 s), and uploads the 10 the hub keeps: about 240 MB, a minute on a
fast uplink and several on a slow one
([opening](explainers/opening.md)). Once the hub funds the contract,
your deposit, less the fee, is minted to you on the L2. Moving it to
your key is your first spend: acknowledge it (below).

Withdrawals, refunds, your reserve and the fee budget's rest are paid to
the contract's payout address: by default the wallet's own (`lw payout`
prints it and what's there, and `lw send-payout <address> [<amount>]`
pays from it), or any address of yours with `--payout`.

`lw contracts` lists your contracts: each one's cap, its end `T_close`,
and its payout address.

## On the L2

```sh
lw balance                    # transparent and shielded notes
lw address                    # your transparent address; --shielded for the shielded one
lw send <address> <amount>    # to a transparent address (64 hex) or a shielded one (128 hex)
lw shield <amount>            # move transparent notes into a shielded one
lw ack [--wait]               # acknowledge your spends (--wait: until all are)
```

Payments to a transparent address need no proof. A shielded one is
proved by your machine first, in seconds to a couple of minutes on a
recent Mac, and only its nullifiers, commitments and proof are public.
Your deposit's tokens arrive transparent.

**Every spend of yours counts only once you acknowledge it**
([payments](explainers/payments.md)). Until then it's pending: its
outputs, your change and your payee's note, stay locked. Your wallet
acknowledges against an anchor on Bitcoin at or above the spend, once
the sequencer has recorded it, the margin deep (20 blocks on Mutinynet,
about 5 to 10 minutes; 6 on mainnet), and once it holds the data to
check it. So stay online after paying, or run `lw ack --wait` when you
return. `lw balance` counts locked notes; a payment or a claim takes only
unlocked ones. A payment you receive is firm once its sender's
acknowledgment is sequenced.

You can receive up to your contract's cap: tokens beyond it are credit
on the hub, not collateralised by your contract.

## Withdrawing

```sh
lw withdraw <contract> <amount>
```

claims notes of yours worth exactly that amount (in the contract's
units), splitting a note off first if none fits, and asks the hub to
fold. The hub checks the claim against its ledger, records it on the L2,
which retires the notes, and pays you `amount` plus your reserve in one
transaction, closing the contract ([a cooperative
withdrawal](explainers/cooperative.md)). A split is a payment to
yourself, so it waits for its acknowledgment. `lw sweep-fees <contract>`
then sends what is left of the contract's fee budget to the payout
address.

`lw withdraw <contract> 0` closes a contract early with nothing
withdrawn: no claim and no wait, just your reserve back, as the default
would pay it at the end. It's for a contract you've emptied (say, your
whole balance withdrawn from another), and frees the hub's liquidity
too.

Withdraw before `T_close`: at the end, an unwithdrawn contract is the
hub's. Its default then pays you your reserve; the hub posts it, and if
it doesn't, `lw post-default <contract>` does, with a fee coin from the
contract's fee budget.

## If the hub won't pay

If the hub refuses the fold, or doesn't answer, or the operator has
gone, exit on Bitcoin:

```sh
lw exit <contract>
```

It posts the same claim a withdrawal makes, on Bitcoin ([the
exit](explainers/exit.md)). You prove nothing: the hub must prove the
claim false within its window (2 hours on Mutinynet), or its timeout
pays you your claim and both reserves. If it asserts a proof, your
wallet checks it: a valid one means your claim was false (a note spent,
or claimed elsewhere), and it concedes; a false one it challenges, and
the hub, unable to answer, loses. The wallet claims your notes in the
last anchor at least the margin deep (it waits for that once your notes
are anchored), and keeps your notes as it reads the sequencer, so an
exit needs neither the hub nor the sequencer: if both have vanished, `lw
exit` claims from the notes kept. A withdrawal the hub recorded but
didn't fold is exited with its own claim. When `lw withdraw` fails, it
names the next step; `lw withdraw <contract> <amount> --escalate` takes
it at once.

Exit before `T_close`, less the windows: `lw contracts` says by when. A
challenge is yours to make, within a day of the hub's assertion on
Mutinynet; no tower can make it for you, since it reveals your secrets.

## Checking the operator

```sh
lw roots > roots.json              # every signed root your wallet has checked
lw compare-roots <file or URL>     # another wallet's, or the sequencer seen from elsewhere
```

A sequencer that signs two histories can't show both to everyone
without being caught: comparing roots with others finds it, and
anchoring on Bitcoin makes a second history useless.
