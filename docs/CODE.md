# lichen's code

For working on lichen itself. The contract's skeleton (its output with
the fold and the default, the pre-signed links' floors and anchors, the
payout) is ln-gap's `sessions::skeleton`
([ln-gap](https://github.com/AdamISZ/ln-gap), checked out beside this
repository at the revision in `LNGAP_REV`).

A contract's dispute is the exit (docs/HUB_PROVES_PLAN.md: a claim
against a hostile operator, which the hub must prove false; statement
`hub-proves`, or `hub-proves-mock` for trials), BABE with the roles
swapped (its garbled circuits and witness encryption, `crates/babe`;
docs/BABE_GADGET_PLAN.md): the hub's statement in `withdraw::hp`, its
graph in `babe::hp`, its setup (Alice garbles and uploads) in
`proto::hp`, its record in `validity::exit`, and its play in the hub's
`dispute::hp` and the wallet's `hp`, `engine::hp` and `exit`. A
cooperative withdrawal is the same claim, which the hub records on the
L2 before it folds (`POST /withdraw`).

## Crates

| crate | binary | who runs it |
|---|---|---|
| `ledger` | | everyone: notes (transparent and shielded), mints, transfers, the trees, signed roots |
| `shielded` | | wallet, sequencer, the spend guest: the spend statement (`no_std`) |
| `validity` | | sequencer, the chain guest: the block and chain statements, the nullifier tree, anchor records and what they read of Bitcoin (`btc`: transactions, witnesses through the coinbase's commitment); an exit record, which retires a claim's notes (`exit`) (`no_std`) |
| `withdraw` | | hub: the hub's statement that an exit claim is false (`hp`), on an anchored state shown by a chain receipt, under an anchor with work on it (`no_std`) |
| `babe` | | hub and wallet: BABE's cryptography (the garbled circuit, the witness encryption, the cut-and-choose setup over VSSS, the reveal by adaptor signatures), the swapped graph and its scripts (`hp`), its statement (the mock; a RISC Zero receipt's Groth16 form) |
| `sequencer` | `lichen-sequencer` | the L2's sequencer: orders transactions, seals and signs heights, records blocks for the chain prover, anchors its history on Bitcoin (`anchor`); serves how a nullifier was spent and its proof at a past height, and holds on claimed notes |
| `l2` | | wallet and hub: the sequencer's API and its client; the HTTP agents every client uses (`http`: `quick`, timeouts on connect and each read; `slow`, for a call the server works on before answering; neither reuses a connection) |
| `wallet` | `lichen` | the user: `lichen withdraw`, a claim the hub records and folds, and `lichen exit`, a claim the hub must prove false (`hp`: the opening's garbling and upload, the claims; `exit`: the notes kept as the wallet reads the sequencer) |
| `chain` | | each party: its own bitcoind wallet over RPC, or Esplora |
| `proto` | | wallet and hub: the opening messages, the contract record, the contract's graph (`Built`); the hub-proves setup exchange and dispute plumbing (`hp`, the cut-and-choose's shared parts in `setup`); `request` and transactions read from the chain for the hub's statement (`exit`) |
| `hub` | `lichen-hub` | the hub: opens contracts, issues tokens, records withdrawal claims and folds; proves exit claims false, and records the others on the L2 |
| `demo` | `lichen-demo` | the local web demo of all of the above |

## RISC Zero (`r0/`)

A separate workspace, built natively (on a Mac, with Xcode's Metal
compiler; `--features cuda` for an NVIDIA GPU) or in Docker
(`r0/Dockerfile`, the image `lichen-r0`). Its Groth16 wrap needs x86
Linux (RISC Zero's prover image, on Docker).

| path | what |
|---|---|
| `guest/`, `chain-guest/`, `hp-guest/` | the spend, chain and hub's statement guests |
| `guests/` | their committed builds (`<g>.bin`) and image ids (`<g>.id`), and how each was built (its README) |
| `host/` | `lichen-r0`: proves each guest, and wraps the hub's in Groth16 (`hp-proof`) |
| `build-guest.sh` | a guest's reproducible build (x86 Linux), then packing it (anywhere) |
| `spend-prover.sh`, `chain-prover.sh`, `hp-prover.sh` | `lichen-r0` in its image (`LICHEN_R0_IMAGE`, `lichen-r0` by default), or itself (`LICHEN_R0`), for the wallet, the sequencer's operator and the hub |
| `hp-remote.sh` | `hp-prover.sh` on another machine over ssh (`LICHEN_R0_HOST`), for a hub on a Mac |

The chain guest holds the spend guest's image id, and the hub's guest
the chain guest's, so rebuild them in that order. A new guest is a new
deployment (r0/guests/README.md says how each was built).

## Tests

```sh
cargo test --workspace --release
```

runs everything that needs nothing outside the tree but bitcoind
(regtest; `bitcoind` on the PATH or `LNGAP_BITCOIND`). Opt-in, with
`-- --ignored --nocapture`:

| test | needs | time |
|---|---|---|
| `lichen-wallet --test shielded_r0` | the prover image | 10 minutes: real spend and chain receipts (`LICHEN_KEEP=1` to keep the files) |
| `lichen-hub --test hp_real` | `LICHEN_HP_PROVER` (`r0/hp-prover.sh`, or `r0/hp-remote.sh` from a Mac), and `LICHEN_R0` for the stale-claim case's chain prover | the hub's statement proved and wrapped for real: a malformed claim, 7 minutes; a stale claim, 20 to 25 minutes on a Mac and a 4-vCPU x86 server |
