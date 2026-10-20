# lichen's code

For working on lichen itself. The contracts, the dispute game and the
BitVMX integration are in [ln-gap](https://github.com/AdamISZ/ln-gap)
(`crates/apps/sessions` and the crates it uses), checked out beside this
repository at the revision in `LNGAP_REV`.

## Crates

| crate | binary | who runs it |
|---|---|---|
| `ledger` | | everyone: notes (transparent and shielded), mints, transfers, the trees, signed roots |
| `shielded` | | wallet, sequencer, the spend guest: the spend statement (`no_std`) |
| `validity` | | sequencer, the chain guest: the block and chain statements, the nullifier tree, anchor records and what they read of Bitcoin (`btc`) (`no_std`) |
| `withdraw` | | hub, the withdrawal guest: the withdrawal statement with the chain receipt, under an anchor with work on it (`no_std`) |
| `sequencer` | `lichen-sequencer` | the L2's sequencer: orders transactions, seals and signs heights, records blocks for the chain prover, anchors its history on Bitcoin (`anchor`) |
| `l2` | | wallet and hub: the sequencer's API and its client |
| `wallet` | `lichen` | the user; also `lichen tower`, a dispute played from a package |
| `chain` | | each party: its own bitcoind wallet over RPC, or Esplora |
| `proto` | | wallet and hub: the opening messages, the contract record, the statement's layout |
| `hub` | `lichen-hub` | the hub: opens contracts, issues tokens, folds withdrawals, answers disputes |
| `demo` | `lichen-demo` | the local web demo of all of the above |

## RISC Zero (`r0/`)

A separate workspace, built in Docker (`r0/Dockerfile`, the image
`lichen-r0`), since RISC Zero's prover needs Xcode's Metal compiler on a
Mac and its Groth16 wrap needs x86 Linux.

| path | what |
|---|---|
| `guest/`, `chain-guest/`, `withdraw-guest/` | the spend, chain and withdrawal guests |
| `guests/` | their committed builds (`<g>.bin`) and image ids (`<g>.id`), and how each was built (its README) |
| `host/` | `lichen-r0`: proves each guest, wraps in Groth16, encodes the BitVMX verifier's input |
| `build-guest.sh` | a guest's reproducible build (x86 Linux), then packing it (anywhere) |
| `spend-prover.sh`, `chain-prover.sh`, `withdraw-prover.sh` | `lichen-r0` in its image (`LICHEN_R0_IMAGE`, `lichen-r0` by default), for the wallet, the sequencer's operator and the user |

The guests hold each other's image ids: chain holds spend's, withdraw
holds chain's. So rebuild them in that order. A new withdrawal guest is a
new deployment's contracts (`lichen_proto::IMAGE_ID`).

## Tests

```sh
cargo test --workspace --release
```

runs everything that needs nothing outside the tree but bitcoind
(regtest; `bitcoind` on the PATH or `LNGAP_BITCOIND`). Opt-in, with
`-- --ignored --nocapture`:

| test | needs | time |
|---|---|---|
| `lichen-wallet --test shielded_r0` | the prover image | 10 minutes: real spend, chain and withdrawal receipts (`LICHEN_WRAP=1` on x86 for the wrap, `LICHEN_KEEP=1` to keep the files) |
| `lichen-hub --test groth16` | BitVMX's verifier (fetched by cargo) | half an hour: G1–G3, disputes on the real statement with a canned claim |
| `lichen-hub --test groth16_read` | as above | half an hour: a read lie on the real statement, disproved |
