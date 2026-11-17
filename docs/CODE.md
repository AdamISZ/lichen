# lichen's code (the grants L2)

For working on lichen itself, on the `grants` branch: the L2 of
[papers/lichen-grants.pdf](../papers/lichen-grants.pdf), whose notes the
hub keeps, one per account. The contract on Bitcoin (its output with
the fold and the default, the pre-signed links' floors and anchors, the
payout) is the `contract` crate, on
[lichen-btc](https://github.com/lichenbtc-org/lichen-btc) (taproot,
transactions, adaptor signatures, Winternitz, RISC Zero's Groth16 key),
which Cargo fetches at the commit `Cargo.lock` pins.

A contract's dispute is the exit where only the hub proves: Alice posts
a claim of her note, the hub may correct it, she accepts or
countersigns, and the hub proves its correction, checked by BABE with
the roles swapped. The hub's statement and the L2's encodings are in
`withdraw::accounts`, its graph in `babe::countersigned`, its setup
(Alice garbles and uploads) in `proto::hp`, its play in the hub's
`dispute::hp` and the wallet's `engine::hp`. A cooperative withdrawal
is the same claim, which the hub takes into its book before it folds
(`POST /withdraw`). The hub's HTTP API is [hub-api.yaml](hub-api.yaml).

## Crates

| crate | binary | who runs it |
|---|---|---|
| `contract` | | hub and wallet: the contract on Bitcoin: the parties' keys (`keys`), the terms and leaves (`leaves`), the fold, the default, the payout and the pre-signed set (`graph`) |
| `notes` | | hub and wallet: the grants L2's types (notes, halves, spends, grants, claims), the hub's book (`book`), the payment messages (`proto`), L2 addresses (`address`) |
| `withdraw` | | hub, wallet, the hub's guest: the L2's hashes and encodings, Algorithm 1 and the hub's statement (`accounts`, `no_std`) |
| `babe` | | hub and wallet: BABE's cryptography (the garbled circuit, the witness encryption, the cut-and-choose setup over VSSS, the reveal by adaptor signatures), the countersigned graph and its scripts (`countersigned`), its statement (the mock; a RISC Zero receipt's Groth16 form) |
| `proto` | | wallet and hub: the opening messages, the contract record, the contract's graph (`Built`); the setup exchange and dispute plumbing (`hp`, the cut-and-choose's shared parts in `setup`) |
| `hub` | `lichen-hub` | the hub: opens contracts, keeps the book, takes part in payments, takes withdrawal claims and folds; corrects exit claims and proves its corrections |
| `wallet` | `lichen` | the user: accounts and payments (`notes`), the opening (`hp`), `lichen withdraw`, and `lichen exit` (`exit`, `dispute`, `engine`) |
| `chain` | | each party: its own bitcoind wallet over RPC, or Esplora |
| `ledger`, `l2` | | from the base design: keys and the deployment's record (`ledger`), the HTTP agents (`l2::http`) |

`sequencer`, `shielded` and `validity`, and the modules `withdraw::hp`,
`withdraw::grants` and `babe::hp`, are the base design's or earlier
grants versions', kept but not used by the grants deployment.

## RISC Zero (`r0/`)

A separate workspace, built natively (on a Mac, with Xcode's Metal
compiler; `--features cuda` for an NVIDIA GPU) or in Docker
(`r0/Dockerfile`, the image `lichen-r0`). Its Groth16 wrap needs x86
Linux (RISC Zero's prover image, on Docker).

| path | what |
|---|---|
| `hp-guest/` | the hub's statement guest (`withdraw::accounts::check`) |
| `guests/` | the committed builds (`<g>.bin`) and image ids (`<g>.id`), and how each was built (its README) |
| `host/` | `lichen-r0`: proves the hub's guest (`hp`), and wraps it in Groth16 (`hp-proof`) |
| `build-guest.sh` | a guest's reproducible build (x86 Linux), then packing it (anywhere) |
| `hp-prover.sh` | `lichen-r0` in its image (`LICHEN_R0_IMAGE`, `lichen-r0` by default), or itself (`LICHEN_R0`), for the hub |
| `hp-remote.sh` | `hp-prover.sh` on another machine over ssh (`LICHEN_R0_HOST`), for a hub on a Mac |

`guest/` and `chain-guest/` (and `spend-prover.sh`, `chain-prover.sh`)
are the base design's. A new hub guest is a new deployment
(r0/guests/README.md says how each was built).

## Tests

```sh
cargo test --workspace --release
```

runs everything that needs nothing outside the tree but bitcoind
(regtest; `bitcoind` on the PATH or `LICHEN_BITCOIND`), the hub's
statement as its mock. The grants L2's are in `crates/hub/tests`
(`payments`, `withdraw`, `contested`: every ending of an exit) and
`crates/babe/tests/countersigned.rs` (the graph under mainnet's relay
policy).

To prove the statement for real: `LICHEN_DUMP_HP=<dir>` makes the hub
write each contested exit's statement input there (for instance from
`contested`), and `r0/hp-prover.sh hp-proof <input> <out>` proves and
wraps it (on a Mac, `hp` proves the STARK only: about 3 minutes; the
wrap, about 4 more, needs x86).

## Comments citing agent notes

A comment citing `agent notes: docs/<NAME>_PLAN.md` points at the
working notes the code was planned in, kept by its developers and their
coding agents locally and not published (`.gitignore`). Read the code,
and the paper, without them.
