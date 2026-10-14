# lichen on public test networks: plan

Written 2026-10-12. The goal: a test environment other people can use. A
hub and a sequencer run in one Docker deployment on a VPS (anywhere the
user likes); testers run only the `lichen` wallet, with no node of their
own. Cooperative withdrawals and real disputes on the Groth16
statement.

Four networks from the start (decided 2026-10-12): regtest (the tests),
Mutinynet (first, for fast iteration: 30 s blocks), signet (stock
software, the most widely available), testnet4. A network is a whole
profile, not just magic bytes:

| network | blocks | `to_self_delay` | δ, δ′ | duration | confirmation patience | stalled after | Esplora |
|---|---|---|---|---|---|---|---|
| regtest | as mined | 6 | 6 | 1,000 | 50 blocks | 5 min | (electrs, local) |
| mutinynet | 30 s | 10 (5 min) | 40 (20 min) | 20,160 (a week) | 40 | 30 min | mutinynet.com/api |
| signet | 10 min | 3 (30 min) | 6 (1 h) | 1,008 (a week) | 6 | 1 h | mempool.space/signet/api |
| testnet4 | ~10 min, bursts | 6 | 36 (~6 h) | 1,008 | 12 | 2 h | mempool.space/testnet4/api |

Testnet4's windows are wide in blocks because its difficulty rule makes
blocks come in bursts: a burst could use up a narrow window in minutes.
Deadlines there are the least predictable.

Branch `testnet` (lichen). ln-gap needs nothing so far.

## Facts it rests on

- **Mutinynet** (MutinyWallet/mutiny-net, BlockSpaces fork): a signet with
  `signetchallenge=512102f7561d208dd9ae99bf497273e16f389bdbd6c4742ddb8e6b216e64fa2928ad8f51ae`,
  peer `45.79.52.207:38333`, 30 s blocks (`signetblocktime=30`). It needs
  benthecarman's patched bitcoind (release `paircommit`,
  `bitcoin-d4a86277ed8a-x86_64-linux-gnu.tar.gz`), not stock Core; it
  also activates some soft forks, which lichen doesn't use. One signer
  (a 1-of-1 challenge). Live on 2026-10-12: height 3,500,307, blocks
  every 30-32 s, running about three years. Only the hub's node needs
  the patched bitcoind; testers on Esplora run none. Esplora at
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

Status (2026-10-12): DONE. `Net` (in `lichen-chain`: regtest, mutinynet,
signet, testnet4; the chain connection carries it) and `proto::params`, each network's timing,
defaults and waits: `Patience` (a confirmation due within blocks and
time) and `Stall` (no new block for a while: regtest 5 min, Mutinynet
30), so a wait bounded by a deadline may take as many blocks as it needs.
`--network` on the hub and the wallet; `Info`, `Record` carry it.
`--statement groth16` finds the verifier ELF (its SHA-256 pinned;
`LICHEN_VERIFIER_ELF` to override). Regtest suite green unchanged.

## T2: no user wallet: a deposit address, Esplora

Decided 2026-10-12: the user's side of lichen is not a Bitcoin wallet.
It holds keys (as now) and builds the transactions the protocol defines,
but does no coin selection, no change, and shows no receiving addresses
or balances beyond what a contract needs. (The user's experience with
Babilonia: making the user co-sign PSBTs in Sparrow or Core is a UI
mess.) The hub keeps its bitcoind wallet: operator infrastructure.

Why not "pay the contract address from anywhere": the contract output
is spent only by transactions pre-signed against its outpoint, so they
must exist before money goes in; paid first, the deposit would sit
where the hub alone could refuse to sign. Hence the joint funding
transaction, and the deposit address in front of it.

### The deposit (boarding) address

The pattern of Ark's boarding addresses and Phoenix's swap-ins.

- lichen shows one address per opening: a P2TR output with two leaves,
  Alice and the hub together (2-of-2 for now), and Alice alone after a
  timeout (`deposit_timeout`, per network: a day or so). She pays it from
  any wallet, or a faucet: `D + r_A`, the fee budget below, and her share
  of the funding transaction's fee.
- lichen watches that one address on Esplora and waits for one
  confirmation (an unconfirmed payment could be replaced, changing the
  txid the pre-signed set is built on).
- The opening as now, with the deposit in place of Alice's coins:
  `OpenRequest` carries the deposit's outpoint (and its keys' public
  halves) instead of `coins` and `change`; the hub checks it on its node
  (unspent, the script, the amount). The funding transaction spends the
  deposit and the hub's coins into the contract output, the hub's change
  and Alice's fee budget output. Both sign the whole pre-signed set
  first; then both sign the deposit input (2-of-2) and the hub its
  coins; the hub broadcasts.
- If the hub never funds (gone, refusing, or the opening failing),
  `lichen refund` sweeps the deposit by the timeout leaf to the payout
  address. Alice's worst case is waiting out the timeout.
- Privacy: with MuSig2 for the 2-of-2 (PLAN.md's TODO, for the fold too)
  the cooperative path is a key-path spend: the deposit looks like any
  P2TR output and its spend like any single-key spend; the script tree
  shows only on a refund. What remains is the timing of a deposit
  followed by a funding transaction. MuSig2 is not part of T2.

### Where money goes out: a payout address

- Alice gives one at opening (`lichen open --payout <address>`, any
  wallet's). The fold pays it; so do the dispute's payouts, which are
  pre-signed at opening (hence at opening, not at withdrawal). Replaces
  `payout_spk = chain.new_spk()`.

### Fees: a fee budget, one coin

- A dispute's links pay a floor of 1 sat/vB out of the contract: on
  test networks that usually confirms alone. The poster's child (CPFP,
  above the floor) and the coin a terminal transaction needs come from
  the fee budget: an output of the funding transaction under a key
  lichen holds (Alice's fee key, per contract), spent as a chain: each
  child's change is the next fee coin. One coin, no selection; its
  outpoint kept with the contract.
- Size: the deepest dispute's children and terminals at the backend's
  feerate (`FEERATE`, 2 sat/vB): on the order of 10k sats; 20k by
  default, per network.
- `lichen sweep-fees`: what's left goes to the payout address once the
  contract is closed.
- (A later option in ln-gap: terminal transactions paying their fee from
  their own outputs, so no coin is added. Not needed for T2.)

### The Esplora backend

- The chain queries, for both parties' code: height, broadcast,
  confirmations, get_tx, unspent, and the watch of the deposit address,
  through `esplora-client` (the crate BDK uses), blocking, with
  `--esplora <url>` defaulting by network (`Net::default_esplora`).
- The wallet's side of `Chain` (`new_spk`, `balance`, `select`,
  `sign_mine`, `fee_coin`) splits off: the hub keeps bitcoind's; the
  user's side signs with the keys above and spends the fee coin. In
  code: a chain-query trait both backends implement, and the funding
  roles (the hub's coins, Alice's deposit) as separate code paths in the
  opening, not one generic wallet.
- No BDK: with no user wallet there is nothing for it to do.

Status (2026-10-12): the backend DONE. `Chain` has two backends (RPC,
Esplora via `esplora-client` blocking); queries, broadcast and
`coins_of(script)` on either, wallet calls on RPC only; posting links
takes a `Fees` (`NodeWallet` for a bitcoind wallet). `chain::electrs`
runs Blockstream's electrs on a regtest node for tests;
`chain/tests/esplora.rs` checks Esplora's answers against the node's.
Next: the deposit opening, the payout address, the fee budget.

Status (2026-10-12): T2 DONE. The opening runs through the deposit
address on every backend (on RPC the user's scripts are watched by a
watch-only bitcoind wallet), so the whole suite uses it; `Fees` for the
dispute's children and terminals, `KeyFees` the user's fee budget (one
key, its coins found by script, waiting out an index's lag).
`lichen refund`, `lichen sweep-fees`, `--payout`, `--esplora`.
Sizing found by the tests: a child's fee credits its link's own floor,
and the target feerate is per network (`proto::feerate`: 1, so no
children, on Mutinynet and signet; 2 on regtest and testnet4), as is the
budget (`proto::fee_budget`: 20k sats where there are no children, 150k
where there are; the mock dispute's children took 79k at 2 sat/vB).
`hub/tests/deposit.rs`: E1 open and fold through Esplora, E2 a whole
dispute through Esplora (40 s, blocks every second) and the budget's
rest swept, R a refund after the opening fails. `groth16.rs` on the
new opening: G1 496 s, G2 (the whole search) 730 s within the regtest
budget, G3 545 s.

### Tests

- Regtest with Blockstream's electrs beside bitcoind (`~/code/electrs`;
  the harness starts it): a wallet on Esplora, with no bitcoind wallet,
  pays its deposit from the harness, opens, folds; another disputes
  (fees from its budget); one refunds after a hub that never funds.
- The existing suite, on the RPC backend, unchanged.

## T3: the VPS deployment

- `deploy/`: a Docker Compose of
  - `bitcoind`: per network, chosen at deploy time: the Mutinynet build
    for mutinynet, stock Bitcoin Core for signet and testnet4; txindex,
    RPC on the internal network only;
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

Status (2026-10-12): T3 DONE (deploy/, README there). `LNGAP_REV` pins
ln-gap (lichen keeps path dependencies for development; `build.sh`
exports lichen's HEAD and ln-gap at that commit with `git archive`).
Images: `lichen` (hub, sequencer, wallet, the verifier ELF) and
`lichen-bitcoind:<network>` (Core 31.1, or for Mutinynet benthecarman's
build, which is Core 25.99: it ignores `rpccookieperms`, harmless with
both containers as root). One compose per network, `--profile regtest`
adds a miner; data in `deploy/data/<network>/`. Checked on this Mac
(Colima, arm64): a regtest deployment passes `deploy/smoke.sh` (deposit,
mint, fold, payout) on the Groth16 statement; the node restarted under
the hub keeps its wallets (now created with `load_on_startup`); a
Mutinynet deployment starts against the v25 node (the hub's wallet, its
`/info`), syncing ~10k headers a second. Not yet on an x86 VPS.

## T4: the wrap service (DEFERRED, 2026-10-12)

Deferred by the user: the first trials run locally (a Mutinynet
deployment in Colima on the Mac, the wallet native), and dispute tests
are done by hand between testers who know the Groth16 wrap needs x86
(`linux-claim.sh`). Cooperative withdrawals need no proofs; the mock
statement covers dispute mechanics. Build this if Mac testers' disputes
show the wrap is the friction. Not the tower (TURNKEY_TOWER.md: keys,
moves, liveness): wrap only, stateless, trustless (it can refuse, not
cheat), so even the hub's operator may run it.


- `POST /wrap`: a succinct receipt in, the BitVMX verifier's input out
  (prove-free: the wrap only). Trustless (TURNKEY_TOWER.md): the wrapper
  sees the receipt and its journal, and can't change `b`; it can only
  refuse, and then the tester uses another.
- The user's side: `lichen claim <memo> --wrapper <url>`: `withdraw-input`,
  the STARK locally (r0vm: 30 s on a Mac), the wrap remotely, the claim
  ready for `lichen dispute --input`.
- Lives in ln-gap's `r0` host (`lngap-r0 serve`), so lichen doesn't take
  on RISC Zero; the image runs it beside the hub.

## T5: a live trial

First locally: the deployment in Colima on the Mac (Mutinynet), the
wallet native, paying deposits from the Mutinynet faucet; then on a
VPS with other testers. Open, pay, fold, then a refused withdrawal
disputed (the mock statement, or the real one wrapped on x86).
Measure: times, kvB, fees.

Status (2026-10-13): the local trials are DONE, three contracts on the
Groth16 statement. The setup:

- **Deployment:** Colima on the Mac. The wallet ran natively through
  mutinynet.com's Esplora.
- **Deposits** were paid from a Core wallet ("payer").
- **Claims** were proved and wrapped on an x86 laptop
  (`linux-claim.sh`).
- **Each contract:**
  - a cap of 2^16, a deposit of 30,000, and `r_A` 20,000;
  - the hub's `r_H` 197,356, the floors of the deepest dispute;
  - δ = δ′ = 40.

Walkthroughs, with every transaction: [explainers/](explainers/README.md).

| test | contract | what happened | on chain | fees |
|---|---|---|---|---|
| A | 1000 | Alice pays Bob 5,000 on the L2, withdraws 20,000; the hub folds | fold 193 vB, `sweep-fees` 99 vB | 1,500 |
| B | 1001 | the hub stopped; Alice withdraws 35,000 by dispute | 5 txs, 23,051 vB | 24,903 |
| C | 1002 | as B (30,000), the hub restarted after the escalation: it concedes | 5 txs, 23,957 vB | 23,985 |
| D | 1003 | Alice lies (claims 40,000, a proof that doesn't verify): the exit code | 23 txs, 100,445 vB | 100,576 |
| E | 1004 | as D, propped up by a read lie at step 478,324,074 | 25 txs, 200,493 vB | 200,832 |

The fees are the withdrawal's, not the deposit's or the funding's. From
the deposit's confirmation to the mint took about a minute (1001, 1002).

- **A** ([cooperative.md](explainers/cooperative.md)): the fold confirmed
  25 blocks after the funding, most of it time at the keyboard.
- **B** ([hub-absent.md](explainers/hub-absent.md)): escalation to sweep
  took 67 minutes: a block between the links, then two windows (80 + 40
  blocks). It found three tidy-ups, fixed in 75ba18a and seen in C:
  - the timeout's fee coin was a fixed 2,000; it is now sized to the
    transaction;
  - the anchors were left unspent;
  - the fee budget's rest needed `sweep-fees`.

  The sweep now takes the last two.
- **C** ([hub-returns.md](explainers/hub-returns.md)): the hub was
  started after `inputs` confirmed.
  - It read the claim from the chain, checked it natively, and conceded
    2.4 s after starting.
  - It logged the contract settled when the timeout appeared.
  - The timeout's fee coin was 600.
  - One sweep of 8 inputs took the payout, both anchors and the budget's
    rest: 243,067 in all.

  Starting the hub before C also caught it up on 1001.

- **D and E** ([lie-caught.md](explainers/lie-caught.md), 2026-10-14):
  the hub disputed both and won, each search landing on the lie.
  - D: `disprove_halt_exit` (5,143 vB) on the final step.
  - E: a 66-hop path (`path_split`, then `combine_7` of 81 kvB), then
    `disprove_read_2` (23,599 vB).
  - Before them the hub was rebuilt from 527e767 (the txindex fix).
  - At these sizes the honest hub ends down on chain (−57,836 and
    −159,082): the search's fees exceed the liar's stake `D + r_A`.

Found along the way:

- **Fixed:** a hub's first opening at a small cap (61ad4a0, with
  `open --resume`).
- **Not fixed:** the hub never collects its own bit outputs after a
  dispute (`hub_bit_i`). 1001's and 1002's sit unspent, 30,208 and
  35,328 sats.

Next: a VPS with other testers, and T4 (the wrap service) if Mac
testers' claims are the friction.

## Not in scope

TLS, accounts, rate limits; several hubs; the turnkey tower; a GUI
beyond the demo; mainnet.
