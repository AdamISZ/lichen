# lichen's code

For working on lichen itself. The contracts, the dispute game and the
BitVMX integration are in [ln-gap](https://github.com/AdamISZ/ln-gap)
(`crates/apps/sessions` and the crates it uses), checked out beside this
repository at the revision in `LNGAP_REV`.

A contract's dispute runs on a verification gadget: BitVMX's search, or
BABE (its garbled circuits and witness encryption, `crates/babe`;
docs/BABE_GADGET_PLAN.md). What every gadget shares (the
contract output with its fold and default, the payout, the pre-signed
links' floors and anchors) is ln-gap's `sessions::skeleton`; each
gadget's keys and play are their own modules: `proto::bitvmx` and
`proto::babe`, the hub's `dispute::bitvmx` and `dispute::babe`, the
wallet's `engine::bitvmx` and `engine::babe` (docs/GADGET_PLAN.md).

The exit (docs/EXIT_PLAN.md: a claim from anchored state against a
hostile operator, and the hub's counter) runs on BABE: its statements in
`withdraw` (`exit`, `counter`, `fixed::check_exit`), its graph in
`babe::graph` (`request`'s claim, `respond`'s two leaves), its record
in `validity::exit`, and its play in the hub's `dispute::babe` and the
wallet's `exit`.

## Crates

| crate | binary | who runs it |
|---|---|---|
| `ledger` | | everyone: notes (transparent and shielded), mints, transfers, the trees, signed roots |
| `shielded` | | wallet, sequencer, the spend guest: the spend statement (`no_std`) |
| `validity` | | sequencer, the chain guest: the block and chain statements, the nullifier tree, anchor records and what they read of Bitcoin (`btc`: transactions, witnesses through the coinbase's commitment); an exit's claim as posted, and the exit record that retires its notes (`exit`) (`no_std`) |
| `withdraw` | | hub, the withdrawal guest: the withdrawal statement with the chain receipt, under an anchor with work on it (`no_std`); BABE's fixed statement, with the hub's signature on `b`, and with the exit its three branches (`fixed`); the exit's claim (`exit`) and the hub's counter to it (`counter`) |
| `groth16` | | the BABE guest, the hub: a RISC Zero Groth16 receipt's check over substrate-bn, for the counter `K` (`no_std`) |
| `babe` | | hub and wallet: BABE's cryptography (the garbled circuit, the witness encryption, the cut-and-choose setup over VSSS, the reveal by adaptor signatures), its graph and scripts, its statement (RISC Zero's or the mock) |
| `sequencer` | `lichen-sequencer` | the L2's sequencer: orders transactions, seals and signs heights, records blocks for the chain prover, anchors its history on Bitcoin (`anchor`); serves exit kits, how a nullifier was spent, and holds on claimed notes |
| `l2` | | wallet and hub: the sequencer's API and its client |
| `wallet` | `lichen` | the user; also `lichen tower`, a dispute played from a package, and `lichen exit`, a claim from anchored state (`exit`) |
| `chain` | | each party: its own bitcoind wallet over RPC, or Esplora |
| `proto` | | wallet and hub: the opening messages, the contract record, the contract built by its verification gadget (`Built`); BitVMX's keys, statement layout and dispute plumbing (`bitvmx`); BABE's setup exchange (with the exit's keys and deposit coin) and dispute plumbing (`babe`); `request` read from the chain for the exit's statements (`exit`) |
| `hub` | `lichen-hub` | the hub: opens contracts, issues tokens, folds withdrawals, answers disputes; counters exit claims, and records the others on the L2 |
| `demo` | `lichen-demo` | the local web demo of all of the above |

## RISC Zero (`r0/`)

A separate workspace, built in Docker (`r0/Dockerfile`, the image
`lichen-r0`), since RISC Zero's prover needs Xcode's Metal compiler on a
Mac and its Groth16 wrap needs x86 Linux.

| path | what |
|---|---|
| `guest/`, `chain-guest/`, `withdraw-guest/`, `counter-guest/`, `babe-guest/` | the spend, chain, withdrawal, counter and BABE (fixed statement, with the exit) guests |
| `guests/` | their committed builds (`<g>.bin`) and image ids (`<g>.id`), and how each was built (its README) |
| `host/` | `lichen-r0`: proves each guest, wraps in Groth16, encodes the BitVMX verifier's input (BABE's claim the same: `babe-claim`; an exit's statement, `babe-exit`; the hub's counter, `counter`) |
| `build-guest.sh` | a guest's reproducible build (x86 Linux), then packing it (anywhere) |
| `spend-prover.sh`, `chain-prover.sh`, `withdraw-prover.sh` | `lichen-r0` in its image (`LICHEN_R0_IMAGE`, `lichen-r0` by default), for the wallet, the sequencer's operator and the user |

The guests hold each other's image ids: chain holds spend's; withdraw,
counter and BABE hold chain's; BABE holds counter's. So rebuild them in
that order. A new withdrawal or BABE guest is a new deployment's
contracts (`lichen_proto::IMAGE_ID`, `lichen_babe::statement::IMAGE_ID`),
and a new chain guest is a new deployment. A rebuild invalidates the
committed proof fixtures (r0/guests/README.md says how they were made).

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
| `lichen-hub --test babe_risc0` | nothing more | half a minute: BABE on RISC Zero's statement with a canned claim (proved after the hub's `respond`): unchallenged, challenged and answered, a false proof taken by `failure` |
