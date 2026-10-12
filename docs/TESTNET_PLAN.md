# lichen on Mutinynet: plan

Written 2026-10-12. The goal: a test environment other people can use. A
hub and a sequencer run in one Docker deployment on a VPS (anywhere the
user likes); testers run only the `lichen` wallet, with no node of their
own, on Mutinynet, a public signet with 30-second blocks. Cooperative
withdrawals and real disputes on the Groth16 statement.

Branch `testnet` (lichen). ln-gap needs nothing so far.

## Facts it rests on

- **Mutinynet** (BlockSpaces/mutiny-net): a signet with
  `signetchallenge=512102f7561d208dd9ae99bf497273e16f389bdbd6c4742ddb8e6b216e64fa2928ad8f51ae`,
  peer `45.79.52.207:38333`, 30 s blocks (`signetblocktime=30`). It needs
  benthecarman's patched bitcoind (release `paircommit`,
  `bitcoin-d4a86277ed8a-x86_64-linux-gnu.tar.gz`), not stock Core; it
  also activates some soft forks, which lichen doesn't use. Esplora at
  `https://mutinynet.com/api`; a faucet (URL to confirm). Checked
  2026-10-12 against the repo's `.env.mutinynet` and `Dockerfile`; check
  again before deploying.
- **Contract timing** is lichen's own: `ChannelParams`' fields are
  public, and `proto::params()` is the one place it is set.
- **Blockstream's electrs** (`~/code/electrs`, built) serves the same
  REST API as mutinynet.com/api, so the Esplora backend can be tested on
  regtest.
- **The chain interface** both parties use is twelve calls
  (`crates/chain`): height, new_spk, balance, select, sign_mine,
  fee_coin, broadcast, confirmations, get_tx, unspent, post_link,
  post_terminal.

## T1: networks and timing

- `proto::Net` (`regtest`, `mutinynet`): the address network (Regtest,
  Signet), the contract's `ChannelParams`, the hub's default duration,
  the default Esplora URL. `--network` on the hub and the wallet;
  `Info` and `Record` carry it, and the wallet refuses a hub on another.
- Mutinynet timing (blocks of 30 s): `to_self_delay` 10 (5 min), δ and
  δ′ 40 each (20 min per window: a person, or a restart, has time),
  duration 20,160 blocks (a week). Regtest unchanged, so the tests are.
- Waits: the wallet's and the hub's 300-second limits ("never
  confirmed", "the chain stalled", "not deep enough to escalate")
  become bounds in blocks *and* time (expired when both have passed),
  so slow blocks don't trip them and fast regtest still fails quickly.
- `chain::Chain::connect` takes the network (no more
  `require_network(Regtest)`).
- `--statement groth16` with no path: find BitVMX's verifier ELF in the
  cargo checkout (as `groth16.rs` does) and write the program
  definition (input 204 bytes). Testers then need no paths.
- Done when: the regtest suite is green unchanged; unit tests of the
  networks' parameters.

Status (2026-10-12): DONE. `proto::Net` with each network's timing,
defaults and waits: `Patience` (a confirmation due within blocks and
time) and `Stall` (no new block for a while: regtest 5 min, Mutinynet
30), so a wait bounded by a deadline may take as many blocks as it needs.
`--network` on the hub and the wallet; `Info`, `Record` carry it.
`--statement groth16` finds the verifier ELF (its SHA-256 pinned;
`LICHEN_VERIFIER_ELF` to override). Regtest suite green unchanged.

## T2: the Esplora backend (the wallet's)

- `Chain` becomes two backends behind one interface: bitcoind RPC (the
  hub, the tests) and Esplora with keys held by the wallet.
- The wallet's own coins: single-key P2TR (BIP86-style key path) from
  its secret, an index per address kept in the wallet file; UTXOs from
  Esplora per used address; signing its own inputs (it has every
  prevout, as taproot sighashes need); `fee_coin` as a send to itself.
  Hand-rolled (~200 lines, the repo's style) rather than BDK; BDK is the
  fallback if coin tracking grows hairy.
- `lichen address-btc`, `lichen balance-btc` (or folded into `balance`);
  `--esplora <url>`, defaulting by network.
- Test: regtest with electrs alongside bitcoind (the harness starts it);
  a wallet on Esplora opens, folds and disputes against a hub on RPC.

## T3: the VPS deployment

- `deploy/`: a Docker Compose of
  - `bitcoind`: the Mutinynet build, txindex, RPC on the internal
    network only;
  - `sequencer`, `hub`: lichen's binaries; first start makes the hub's
    keys, the sequencer is started with the hub's `--print-key`;
    volumes for the ledger, the hub's dir, the node;
  - (T4) `wrapper`.
- One x86 image for lichen's binaries, with BitVMX's verifier ELF and
  the program definition baked in (the ELF is GPL: shipped as the
  separate file it is).
- A run book: a VPS (x86, 16 GB for the wrap), `docker compose up`, fund
  the hub from the faucet, publish the hub's and sequencer's URLs.
  Ports: the hub's and the sequencer's HTTP only (no TLS yet: test
  coins, test environment).

## T4: the wrap service

- `POST /wrap`: a succinct receipt in, the BitVMX verifier's input out
  (prove-free: the wrap only). Trustless (TURNKEY_TOWER.md): the wrapper
  sees the receipt and its journal, and can't change `b`; it can only
  refuse, and then the tester uses another.
- The wallet: `lichen claim <memo> --wrapper <url>`: `withdraw-input`,
  the STARK locally (r0vm: 30 s on a Mac), the wrap remotely, the claim
  ready for `lichen dispute --input`.
- Lives in ln-gap's `r0` host (`lngap-r0 serve`), so lichen doesn't take
  on RISC Zero; the image runs it beside the hub.

## T5: a live trial

Open, pay, fold, then a refused withdrawal disputed on the real
statement, on Mutinynet, with the hub on a VPS and a wallet on the Mac.
Measure: times, kvB, fees. Write it up in PLAN.md.

## Not in scope

TLS, accounts, rate limits; several hubs; the turnkey tower; a GUI
beyond the demo; mainnet.
