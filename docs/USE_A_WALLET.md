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
- **For shielded payments only:** Docker and the prover image,
  `docker build -f r0/Dockerfile -t lichen-r0 .` (a large image), passed
  as `--spend-prover r0/spend-prover.sh`.

Every command takes the network, the wallet file and the two URLs. A
shell alias saves repeating them:

```sh
alias lw='target/release/lichen --network mutinynet --wallet alice.json \
  --sequencer http://<host>:18300 --hub http://<host>:18310 --statement babe \
  --spend-prover r0/spend-prover.sh'
```

`--statement` is the hub's (`babe` on a real deployment). The wallet
file holds secrets: keep it, and the directory beside it (`alice.d/`), private.

## A contract

```sh
lw init                                  # a fresh key; pins the deployment the sequencer announces
lw open 400000 --payout <an address of yours>
```

`init` pins the deployment: check the sequencer's key it prints against
the operator's. `open` asks the hub for a contract of a 400,000-sat
deposit (a cap of 2^21 − 1 sats by default, `--bits`), then prints a
deposit address and an amount, `D` plus your reserve, a share of the
funding fee and a fee budget for a dispute, and waits. Pay it from any
wallet or faucet. The deposit address is the hub's key and yours
together, or yours alone after about a day: if the contract never
opens, `lw refund <contract>` takes it back. Once the hub funds the
contract, your deposit is minted to you on the L2.

`lw contracts` lists your contracts: each one's cap, its end `T_close`,
and its payout address.

## On the L2

```sh
lw balance                    # transparent and shielded notes
lw address                    # your transparent address; --shielded for the shielded one
lw send <address> <amount>    # to a transparent address (64 hex) or a shielded one (128 hex)
lw shield <amount>            # move transparent notes into a shielded one
```

Payments to a transparent address need no proof. A shielded one is
proved by your machine first, in under half a minute on a recent Mac,
and only its nullifiers, commitments and
proof are public. Your deposit's tokens arrive transparent.

You can receive up to your contract's cap: tokens beyond it are credit
on the hub, not collateralised by your contract.

## Withdrawing

```sh
lw withdraw <contract> <amount>
```

returns the amount to the hub on the L2, with the contract's memo, and
asks the hub to fold: it checks the return, with its anchor and the
chain's validity proof, and pays you `amount` plus your reserve in one
transaction, closing the contract. The return has to be anchored on
Bitcoin first, with ten blocks on top: several minutes on Mutinynet, about
two hours on mainnet. `lw sweep-fees <contract>` then sends what is left
of the contract's fee budget to the payout address.

Withdraw before `T_close`: at the end, an unwithdrawn contract is the
hub's.

## If the hub won't pay

If the hub refuses the fold, or doesn't answer, enforce the withdrawal
on Bitcoin. Under BABE that is two steps:

```sh
lw dispute <contract> <amount>      # requests on chain, waits for the hub's response, stops
```

The hub must sign your amount on chain within its window, or you are
paid by timeout. Once it has, prove the withdrawal, with the hub's
signature (written to `alice.d/babe-<contract>/hub-auth.json`), by
`T_A`, shortly before the contract ends:

```sh
lw withdraw-input <contract> > withdraw-input.json
lw chain-receipt <contract> chain.receipt
lichen-r0 babe-claim withdraw-input.json alice.d/babe-<contract>/hub-auth.json chain.receipt claim.hex
lw dispute <contract> --input claim.hex
```

`lichen-r0` is built from `r0/` (`cargo build --release --manifest-path
r0/Cargo.toml -p lichen-r0`, on a Mac with Xcode and its Metal
toolchain), and runs the Groth16 wrap in RISC Zero's prover image, on
Docker. A few minutes on a recent laptop, about fifteen on a 4-vCPU
server. The proof needs no secret of yours, so anyone can make it for
you. The dispute then plays out in a few transactions: [a true claim
challenged](explainers/babe-challenged.md).

To be away while it runs, hand it to a tower: `lw export-dispute
<contract> --input claim.hex --out package.json`
([RUN_A_TOWER.md](RUN_A_TOWER.md)). The tower holds your signatures,
not your keys.

If the operator won't even take your return on the L2, exit instead:
`lw exit <contract>` claims your notes at the latest state anchored on
Bitcoin ([the exit](explainers/exit.md)).

## Checking the operator

```sh
lw roots > roots.json              # every signed root your wallet has checked
lw compare-roots <file or URL>     # another wallet's, or the sequencer seen from elsewhere
```

A sequencer that signs two histories can't show both to everyone
without being caught: comparing roots with others finds it, and
anchoring on Bitcoin makes a second history useless.
