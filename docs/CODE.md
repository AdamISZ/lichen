# lichen's code

lichen is the base an L2 is built on: the contract between a user and the
hub on Bitcoin, its opening, the fold, the default, and the dispute, with
BABE checking the hub's proof. It has no ledger and no binaries of its
own: an L2 brings its ledger and plugs into the hub and the wallet here,
and builds the binaries. [glichen](https://github.com/lichenbtc-org/glichen)
(the grants L2) and [vlichen](https://github.com/lichenbtc-org/vlichen)
(a validity rollup) are the two so far; each takes lichen by git, at a
commit.

The Bitcoin layer (taproot, transactions, adaptor signatures, MuSig2,
Winternitz signatures, RISC Zero's Groth16 key) is
[lichen-btc](https://github.com/lichenbtc-org/lichen-btc), which Cargo
fetches at the commit `Cargo.lock` pins. The design is
[papers/lichen.pdf](../papers/lichen.pdf).

## Crates

| crate | what |
|---|---|
| `contract` | the contract on Bitcoin: the parties' keys (`keys`), the terms and leaves (`leaves`), the cooperative and pre-signed transactions: the fold, on the contract output's key path (both parties' MuSig2 key), the default, the payout of the value Alice signed or, where the hub proves, of the one it signed (`pay_reduced`), and each party's outputs of it (`owned`) (`graph`) |
| `chain` | a party's view of Bitcoin: its own bitcoind over RPC, with a wallet (the hub's), or an Esplora server (a user's: no node, no wallet) |
| `babe` | BABE: the witness encryption for Groth16 (`we`), the garbled circuit (`garble`, `gadget`, `circuit`, `field`), the cut-and-choose setup over verifiable secret sharing (`setup`, `vsss`; both sides of it for a contract, Alice's `Garbler` and the hub's `choose`, `check` and `answer`, in `opening`), the reveal by adaptor signatures (`reveal`); a contract's dispute graph, an L2's front then BABE's tail (`graph`); the statement (`statement`: a RISC Zero receipt's Groth16 form, or a mock for tests) |
| `proto` | what the wallet and the hub exchange to open a contract, and the record each keeps of it; the dispute's setup exchange (`hp`, the cut-and-choose's shared parts in `setup`); the contract's graph (`Built`); the L2's hook into the contract (`Layer`) |
| `hub` | the hub's library: opens contracts, pays withdrawals (the fold), defaults contracts at `T_close`, plays every dispute's tail; its HTTP API (`GET /info`, the opening, `/withdraw`), with the L2's routes beside them; the L2's hooks (`l2`: `HubL2`, `Ctx`) |
| `wallet` | the wallet's library: a key and its contracts with the hub (the opening, the cooperative withdrawal, the exit), the dispute's engine (`engine`), the L2's hooks (`l2`: `WalletL2`) |

## A contract

The wallet asks to open a contract (`proto::OpenRequest`): her keys for
the dispute (the BABE instances she garbled that the hub doesn't keep,
opened), her deposit `D`, cap and reserve. The hub offers
(`OpenOffer`): the contract's number, `T_close`, its keys and reserve,
the funding transaction and its signatures on the whole pre-signed set,
and `D` minted on the L2 behind an adaptor point `T`. She accepts
(`Accept`) with her signatures and a pre-signature on her deposit's
spend locked to `T`: broadcasting the funding puts `t` on chain, which
completes her mint. So the deposit and the mint are one atomic swap.

The contract output's key path is the fold, the cooperative withdrawal:
the user's claim, which the hub takes into its L2, then both parties'
MuSig2 signature (`POST /withdraw/nonce`, the hub's nonce, then `POST
/withdraw`). Its leaves are the default, after `T_close`, and the
dispute:

```text
contract output (key path: the fold; leaves: default, and the front's
│                first link)
└─ front links (the L2's: request, and whatever its exit adds), each
    │          output with its terminal (a timeout paying the user,
    │          a correction's payout, ...)
    └─ assert (the hub: π1 under its Lamport key, π2 and π3)
        ├─ success (after Δ2)            → the front's choice
        └─ challenge_assert (the user: the reveal)
            ├─ wrongly_challenged_k      → the hub (its proof was valid)
            └─ failure (after Δ1)        → the user: her claim
```

The dispute is the exit, where only the hub proves: she claims, and the
hub must prove the claim false (against the L2's statement) or her
timeout pays her. The front, everything before `assert`, is the L2's;
BABE's tail, with the roles swapped (the hub proves, she garbled), is
lichen's.

## Writing an L2

An L2 implements four traits, and its two binaries (a hub and a wallet)
start lichen's `Hub` and `Wallet` with it:

| trait | where | what the L2 gives |
|---|---|---|
| `Front` | `lichen_babe::graph` | the dispute's front: its links from the contract output to `assert` (each with its leaf, its terminal and window), what a front terminal pays, what `success` pays |
| `Layer` | `lichen_proto` | a contract's front, from its record, and the journal its statement's proof is of: what both sides build the contract's graph from |
| `HubL2` | `lichen_hub` (`l2`) | the hub's side: its info and HTTP routes (payments, ...), who may open a contract, the statement's terms at the setup, its keys at the opening, the mint, a withdrawal's claim taken into the ledger, the front's moves in a dispute up to the statement's input, and collecting its payout. `Ctx` is what the hub gives it: the chain, the configuration, the contracts, and the plumbing a front's moves need (posting a link, a terminal, a sweep) |
| `WalletL2` | `lichen_wallet` (`l2`) | the wallet's side, its state kept in the wallet file: the terms it asks for and checks, her keys for the front, the mint, a withdrawal's claim and an exit's plan, the front's moves, and the sweep of a payout she won |

The L2's data rides through lichen as JSON values it defines: the
statement's terms (`HpSetup::l2`), her keys for the front
(`HpCommit::keys`), the contract's L2 keys (`HpKeys::l2`), the offer's
part (`OpenOffer::l2_offer`), the hub's info (`Info::l2`), and the
wallet's record of an offer (`Locked::l2`). The statement is a RISC Zero
guest of the L2's, whose image id is in the contract; lichen checks its
Groth16 wrap (`lichen_babe::statement::Kind::Risc0`).

The two L2s are the worked examples:

| | glichen | vlichen |
|---|---|---|
| `Front` | `Countersigned` (`glichen_proto::front`): request, the hub's correction, her countersignature | `HubProves` (`vlichen_proto::front`): the request only |
| `Layer`, `HubL2`, `WalletL2` | `Grants` (its hub and wallet crates) | `Rollup` (its hub and wallet crates) |
| the ledger | the hub's book, one note per account | a sequencer's, anchored on Bitcoin, proved valid |

## Tests

```sh
cargo test --workspace --release
```

runs everything that needs nothing outside the tree but bitcoind
(regtest; `bitcoind` on the PATH or `LICHEN_BITCOIND`) and, for the
Esplora tests (`crates/chain/tests/esplora.rs`), Blockstream's electrs
(`LICHEN_ELECTRS`). The contract's whole life, opening to every ending of
a dispute, needs an L2: those tests are in glichen's and vlichen's
`crates/hub/tests`. `crates/babe/examples/setup_cost.rs` measures BABE's
setup.

## Comments citing agent notes

A comment citing `agent notes: docs/<NAME>_PLAN.md` points at the
working notes the code was planned in, kept by its developers and their
coding agents locally and not published (`.gitignore`). Read the code,
and the paper, without them.
