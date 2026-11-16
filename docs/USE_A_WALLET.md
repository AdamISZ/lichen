# Using a lichen wallet

A user runs only `lichen`, the wallet: no node, no coins in it. It reads
Bitcoin from a public Esplora server, holds keys, and talks to the hub,
which keeps the L2's notes ([the design](../papers/lichen-grants.pdf)).
Deposits are paid into it from any Bitcoin wallet, and withdrawals paid
out to an address of any wallet. Running the hub is
[RUN_A_HUB.md](RUN_A_HUB.md).

## What you need

- **The wallet.** Build it from source, with ln-gap's checkout beside
  lichen's (lichen's workspace refers to it by path), and Rust:
  ```sh
  git clone -b grants https://github.com/AdamISZ/lichen && git clone https://github.com/AdamISZ/ln-gap
  cd lichen && cargo build --release -p lichen-wallet     # target/release/lichen
  ```
- **The hub's URL and its key** (its issuer key), from the hub's
  operator. The wallet's version must be the hub's: `GET <URL>/info`
  names it.

Every command takes the network and the wallet file, and the hub's URL
on `init`, which the wallet keeps. A shell alias saves repeating them:

```sh
alias lw='target/release/lichen --network mutinynet --wallet alice.json --hub <URL>'
```

`--statement` is the hub's: `hub-proves-mock` (the default, what the
test deployments run) or `hub-proves`. The wallet file holds secrets:
keep it private, and back it up after opening a contract (it holds the
hub's pre-signatures, which nothing else can restore).

## A contract

```sh
lw init                                  # a fresh key; pins the hub's key
lw open 100000 --liquidity 200000
```

`init` pins the hub: check the key it prints against the operator's.
`open` asks the hub for a contract of a 100,000-sat deposit with 200,000
sats of **liquidity**: what you can receive beyond your balance. The hub
charges for the liquidity (1% by default), kept out of what it mints
you, so `open` first prints its quote:

```
the hub's fee for 200000 sats of liquidity: 2000 sats; you'll be minted 98000 sats, with a cap of 298424 sats
```

The cap, your balance plus the liquidity, is rounded up a little to the
contract's unit (a few hundred sats, in which an exit pays). `open`
then prints a deposit address and an amount, `D` plus your reserve, a
share of the funding fee and a fee budget for an exit's fees, and waits.
Pay it from any wallet or faucet; if you don't like the quote, don't
pay. The deposit address is the hub's key and yours together, or yours
alone after about a day: if the contract never opens, `lw refund
<contract>` takes it back.

Once it's paid and confirmed, the wallet garbles the circuits that would
check the hub's proof in a dispute (some 10 s), and uploads the 10 the
hub keeps: about 240 MB, a minute on a fast uplink and several on a
slow one. Once the hub funds the contract, your deposit, less the fee,
is your account's first note on the L2.

Withdrawals, refunds, your reserve and the fee budget's rest are paid to
the contract's payout address: by default the wallet's own (`lw payout`
prints it and what's there, and `lw send-payout <address> [<amount>]`
pays from it), or any address of yours with `--payout`.

`lw contracts` lists your contracts: each one's cap, its end `T_close`,
and its payout address.

## On the L2

```sh
lw balance                    # what your accounts hold, as the hub has them
lw notes                      # each account's live note, and a payment pending
lw address                    # yours, for payers: tlc1… (bech32m)
lw receive [--wait 60]        # take payments, for that many seconds
lw send <address> <amount>    # pay; waits up to --wait seconds for the payee
lw cancel                     # cancel a payment pending
```

Each account holds one note, and each payment moves both the payer's
and the payee's, so **the payee must be online**: running `lw receive`
while the payer runs `lw send`. A payment takes a couple of round trips
through the hub. One payment at a time per account, in either
direction: a payer finding the payee busy retries.

A payment you sent or received is done once your wallet has its seed
from the hub; until then it is pending (`lw notes`). If the hub stops
answering, `lw cancel` asks it to cancel. Whatever happens, your exit
claims the note you held before the payment, and it settles either way.

You can receive up to your contract's cap: value beyond it is credit
on the hub, not collateralised by your contract.

## Withdrawing

```sh
lw withdraw <contract> <amount>
```

claims your account's live note, for that amount in the contract's
units, and asks the hub to fold. The hub takes the claim, closing the
account, and pays you `amount` plus your reserve in one transaction,
closing the contract. What the note held beyond `amount` it credits to
your wallet's key, an account with no contract. `lw sweep-fees
<contract>` then sends what is left of the contract's fee budget to the
payout address.

`lw withdraw <contract> 0` closes a contract early with nothing
withdrawn: just your reserve back, as the default would pay it at the
end.

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

It posts your claim on Bitcoin, and plays the dispute to its end (run
it again to resume). You prove nothing:

- the hub stays silent: after `w_H` (2 hours on Mutinynet), the timeout
  pays your claim;
- the hub corrects it, citing a later payment of yours: if the
  correction is right, the wallet accepts it, paid after `w_A` (a day);
  if not, it countersigns, and the hub must prove its correction within
  `w_H`, or the timeout pays your claim;
- the hub's proof is false: the wallet challenges it, within a day, and
  is paid its claim.

Exit before `T_close`, less the windows: `lw contracts` says by when.
When `lw withdraw` fails, it names the next step; `lw withdraw
<contract> <amount> --escalate` takes it at once.
