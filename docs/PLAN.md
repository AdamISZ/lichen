# lichen: plan

Single sequencer, single hub, one token; regtest; CLI. Contracts are
standalone outputs (no Lightning channel): one transaction opens a
contract, one folds it.

## M1: the ledger (done)

`ledger` (transparent notes on the withdrawal statement's own `Note`,
commitment tree and state root; nullifiers; hub mints; owner-signed
transfers; sealed, signed heights; the statement's input for a return),
`sequencer` (HTTP: `/tx`, `/seal`, `/state`; persistence; the client),
`wallet` (`lichen`: init, address, balance, send, return, withdraw-input).

## M2: contracts with the hub (done)

- `chain`: a party's own bitcoind wallet over RPC: it supplies coins and
  signs only its own inputs of a jointly built transaction.
- `proto`: the statement (`groth16:<pdf>` for the real verifier, `mock`
  for fast tests) and its input layout (`b`'s word, the checks for memo
  `c`); the opening messages; the contract record both sides keep.
- `hub` (`lichen-hub`): `/info`, `/open`, `/accept`; mints each deposit
  with its offer, locked to the funding (since 2026-10-16; until then,
  once the funding confirmed, which let a hub keep a deposit by never
  minting). The wallet's `lichen open`, `lichen contracts`.
- Opening: Alice sends her keys (move keys for the odd depths, input-word
  keys), `D`, cap and reserve, coins and change; the hub answers with the
  contract's number (memo `c`), `T_close`, its reserve and keys, the
  funding transaction and its signatures on the whole pre-signed set
  (ln-gap's `lngap_sessions::contract`: the default, the chain of links,
  the timeouts, the proofs). Alice checks the funding and every signature,
  signs the set and her inputs; the hub checks hers, signs its inputs,
  broadcasts. Neither signs the funding before holding the other's set.
- Units: plain sats, everywhere (decided 2026-10-09). What the ledger
  carries is bitcoin, not a separate asset: within each user's cap it is
  bitcoin she can take out without trusting anyone. Display may use ksats.
  A note's value is in sats; `b` in the statement's journal is a u32 of
  sats (up to about 42.9 BTC). The dispute path alone has a coarser
  granularity: its payout's bit outputs start at the first bit worth at
  least the dust limit (512 sats), so `b` is rounded down there by less
  than 512 sats; the cooperative fold pays exact sats.
- Fees: the chain's links are ordinary (v2) transactions that pay a
  floor of 1 sat/vB out of the contract and carry an anchor only their
  poster can spend (its child pays the rest); the terminal ones are
  ALL|ANYONECANPAY (the broadcaster adds a coin). The contract output holds
  exactly `V_max` and both reserves; the floors of the links played come
  out of the loser's reserve, so the hub's reserve is at least the floors
  of the deepest dispute (125,017 sats on the mock, 195,411 on Groth16).
  (Until 2026-10-10: TRUC links with a zero-value anchor.)
- TODO: MuSig2 for every 2-of-2 spend both parties sign together (the
  cooperative close first); for now a 2-of-2 fold leaf (M3).
- Test (`crates/hub/tests/open.rs`): opening on the mock statement in
  about 6 s (debug): 47 pre-signed transactions, every signature checked
  by both; the deposit minted with the offer, claimed with `t`.
- The mint as a swap (2026-10-16): the offer mints `D` to
  `H(A ‖ T)·A + T` (`ledger::mint_key`), `T` the funding's adaptor
  point (`t` from the hub's seed, the contract, `A` and the funding's
  txid, so retries never share one); Alice checks it sealed and signs
  the deposit input as an adaptor pre-signature (ln-gap's
  `lngap_btc::adaptor`); the hub completes it to broadcast, which puts
  `t` on chain, and answers with `t`. The hub broadcasts only in the
  first half of the deposit's refund timeout (`broadcast_deadline`).
  `lichen claim-mint` reads `t` from the chain for a hub that didn't
  answer. Test (`crates/hub/tests/mint.rs`): the answer lost, never
  funded, a short mint, resumed too late.
- TODO: fee-bump a funding that stalls (CPFP through the hub's change
  output, which needs nothing from Alice): until then the broadcast
  deadline is the only guard against a funding still unconfirmed when
  the deposit's refund matures, with `t` already public.

## M3: the cooperative withdrawal (done)

- The contract output gains `fold` (2-of-2, signed when it happens; TODO
  MuSig2 key path). `lichen withdraw <contract> <amount>`: Alice returns
  `b` with memo `c`, waits until a sealed height includes it, signs the
  fold (Alice `b + r_A`, the hub the rest less a 1,000-sat fee) and asks
  the hub (`POST /fold`), which checks the return (sealed, the hub's,
  memo `c`, amount `b`, within the cap), signs and broadcasts.
- The default: after `T_close` the hub broadcasts the pre-signed default
  of every contract still open (Alice's reserve back), adding a fee coin.
- Test (`crates/hub/tests/fold.rs`): Alice withdraws 450,000 sats after
  receiving 50,000 from Bob on the L2 (more than her deposit): 470,000 on
  chain (with her reserve), the fold 205 vB, under a second. Bob and Carol
  do nothing; after `T_close` their defaults return their reserves.

## M4: disputes (done, on the mock statement)

- ln-gap gained what two separate parties need (found building this):
  the `inputs` link (the rest of Alice's input after the escalation: the
  hub executes the program on all of it), move 1 signing the claim block
  and the last move the record (the hub's disproves need them), and
  `lngap_sessions::play` (`Prover`, `Verifier`: each side's own emulator,
  moves read back from the links' witnesses; the final rules' native
  mirrors pick the disprove).
- Wallet (`lichen dispute <contract> <amount>`): escalates, plays every
  move from what it reads on chain, takes its timeout if the hub stops,
  proves the last step if no disprove comes, sweeps its bits and the
  reserves; notices its output taken by a check or a disprove.
- Hub (watcher): reads the escalation; applies the input-word checks
  (memo, image id); runs its verifier on the claim: a true claim it
  concedes (an honest hub), a false one it plays and disproves; times out
  an absent Alice. When she wins, it sweeps its bit outputs (the bits
  clear in `b`, by `hub_bit_i` with her signature on `b` from the
  escalation) once the payout confirms, found by `scantxoutset`, then
  closes (since 2026-10-17; a hub from before collects what its closed
  disputes left, once). Test switches: `refuse_folds`,
  `dispute_true_claims`, `leave_bits`.
- TODO: `scantxoutset` reads the whole UTXO set: seconds on the test
  networks, minutes on mainnet, on the watcher's thread. Before mainnet,
  watch the bit outputs' scripts from the escalation instead.
- Fees: every link broadcast alone at its floor, then the poster's child
  spending its anchor (the contract's payment key signs that input, the
  bitcoind wallet its coin); terminal transactions with a fee coin.
- Test (`crates/hub/tests/dispute.rs`, blocks every 150 ms): A, the
  honest hub concedes a true claim (5 s); B, a hub disputing a true claim,
  the whole search played and proved (10 s); C, a false claim disproved
  (`zk_halt_exit`); M, another contract's memo taken by the check.
- Resuming: the wallet keeps the claim (and the payout once posted) with
  the contract; `lichen dispute <contract>` again replays what is on chain
  (each of its links checked to be the move it would make) and carries
  on. The hub keeps nothing of a dispute: after a restart it rebuilds its
  verifier from the claim on chain and replays. Test: `resume.rs` (the
  wallet stops after move 5, the hub restarts, both resume; proved).
- The wallet refuses a claim that breaks a check (it would lose
  everything to it); the hub's checks catch one escalated anyway.
- The real statement: `lngap-r0 prove-input` / `claim` (ln-gap's RISC
  Zero host) prove a wallet's `withdraw-input` JSON; `scripts/linux-claim.sh`
  on x86 Linux gives the claim's hex for `lichen dispute --input`.
  Opt-in test `groth16.rs` (release, the canned proof, hubs numbering
  from 42; 33 minutes): G1, the honest hub runs the verifier on the claim
  and concedes (403 s); G2, a hub disputing a true claim, all 59 moves
  played by the two engines, Alice proves (816 s); G3, b tampered, the
  hub disproves with `zk_halt_exit` (713 s). A return made in lichen's own
  ledger proves under the canonical guest (`lngap-r0 prove-input`, 5.9M
  cycles, 6 minutes on a Mac; the wrap still needs x86 Linux).
- Not yet: watchtowers (undecided).

## The new ladder (ln-gap v3-jumplist, done 2026-10-10)

Ported to ln-gap's reworked ladder (its JUMPLIST_PLAN.md, phase J6):
links without TRUC (a floor of their own, the poster's keyed anchor), an
8-ary search with BitVMX's own moves signed field by field, and reads
settled by an authenticated jump list instead of a second search (the
hub posts a path through its history as a split and a combine of up to
eight inputs; Alice challenges a false hop or the hub's verdict stands).
BitVMX-CPU from the public fork AdamISZ/BitVMX-CPU (branch `lngap`).

- The hub's reserve: the larger of its share of the cap and the floors of
  the deepest dispute (they come out of the loser's reserve): 125,017
  sats on the mock, 195,411 on Groth16, measured at the first opening.
- The native check: on Groth16 the honest hub checks the claim's proof
  natively (`lngap_zk::groth16`, about 1.5 ms) and concedes a true claim
  without emulating; it emulates only an input it will dispute.
- Tests (release, mainnet relay policy): open, fold, dispute (A, B, C, M),
  resume, and `tail.rs` on a full mock table: J (a wrong long-jump hash,
  `disprove_jump`), L (a read lie, a 6-hop path, `disprove_read_1`), F
  (the hub forges a hop; Alice refutes it, her timeout pays), L2 and F2
  (11-hop paths in two chunks). Test switches: `Wallet::lie`,
  `Hub::set_forge_paths`.
- `groth16.rs` (opt-in, 30 minutes, before the native check): G1
  conceded (497 s), G2 the whole search (21 depths) played by both
  engines and proved (725 s, against 816 s for the old 59 moves), G3
  `disprove_halt_exit` (5,142 vB; 540 s).

## Deployment keys (2026-10-12)

The toy keys (`lngap-toy/sequencer`, `lngap-toy/hub`, the hub's seed a
label) let anyone mint, seal or sign as the hub: fine alone on regtest,
fatal in any shared test. Now:

- The statement (ln-gap, r0 core) takes the sequencer's and the hub's
  keys as input; its journal is `b ‖ c ‖ D`, `D` the deployment id
  (`SHA256("lngap/deployment" ‖ sequencer ‖ hub)`): one guest for every
  deployment. The guest uses RISC Zero's accelerated crypto: 440k cycles,
  30 s on an M4 Pro, against 5.9M and 6 minutes.
- `ledger::Deployment` (the two keys, its `id`); the ledger, the
  sequencer's client and the withdrawal input use it instead of
  constants. The sequencer serves it at `GET /info`.
- `lichen-sequencer` makes its key (`--key`) and names the minting hub
  (`--issuer`); `lichen-hub` makes its L2 key and contract seed in its
  `--dir` (`--print-key` for the sequencer); `--toy` keeps the old keys.
- A wallet pins the sequencer's deployment when made (an older file on
  first open) and refuses a hub whose `/info` names another. A contract
  records `D` and checks its eight input words (43-50) like the memo; the
  Groth16 input is 51 words (204 bytes).
- Tests and the demo stay on the toy deployment. `groth16.rs` reads its
  canned claim, `withdraw-9-42-deployment.hex`, from ln-gap, made with the
  canonical guest (`IMAGE_ID` `e0cd81a7...298e`; on the x86 laptop the
  proof took 2 min 24 s, 4.8 GB, against 27.7 min and 9.6 GB).
- Found by `groth16.rs`: with the deployment's eight words the escalation
  (the claim's words and move 1's hashes) exceeded Script's 1,000-element
  stack. A check now says which link publishes its word
  (`Check::in_claim`, ln-gap): the deployment's go in `inputs`, the
  check leaves being on the ladder output after it either way, and the
  hub reads every word before applying the checks. G1 conceded natively
  (495 s), G2 the whole search proved (728 s), G3 `disprove_halt_exit`
  (5,141 vB, 542 s).
- Not covered end to end: a claim breaking a check on a word in `inputs`
  (another deployment's); the mock's only check, the memo, is in the
  escalation.

## Demo: possible improvements

- A dispute on the real statement (option 1, noted 2026-10-09): make the
  demo's state deterministic (fixed seeds, note `rho`s and signing
  randomness), so that the withdrawal made live is one proved in advance
  (on x86 Linux: `lngap-r0 claim`); the demo then disputes it on the
  Groth16 verifier (21 depths, about 12 minutes of emulation, fine while
  people ask questions). Proving live instead needs the wrap on x86
  (a remote box) and, to be quick, the accelerated guest.

## Windows per move (decided 2026-10-16, done 2026-10-17)

Each kind of obligation has its own window (ln-gap's `ladder::Windows`,
branch `per-move-windows` in both repos), instead of one `w = δ + δ′`
for every move:

- `user`: Alice, for each of her moves (`inputs`, her rounds, her final
  record, her choice of a hop) and her proof of the last step;
- `hub`: the hub, for each of its choices (0.3 kvB);
- `path`: the hub's heavy moves: at the final step (a disprove or its
  path's split), the combine (up to 93 kvB), its verdict, a hop's reveal.

Every timeout's lock comes from one place (`ladder::Spec::lock(Site)`,
`Contract::lock` in sessions): after Alice's move the hub's window, after
its choice hers; at the last depth her proofs after `path`, the hub's
timeout after `path + user`; in the tail the carrier's timeout after
`path`, the verdict after `user` (her window to choose a hop), her
timeout after `user + path`, a hop's reveal within `path`. `check` refuses
windows a disprove (after δ) couldn't fit in, or a hub window `post`
couldn't.

- Why: congestion safety needs contracts × heaviest move ≤ window × block
  (the paper's Table 2), so the heavy windows must grow with the hub's
  contract count (75 blocks for 3,000 contracts against a hostile hub,
  280 against hostile users with read lies). With one `w`, a vanished
  hub's users waited that long too; now they wait the hub's short window
  (an absent hub fails its first choice). Disputes stay as long, and
  `Tc` must leave room for the longest.
- Contracts record their windows (`Record::windows`, stated by the hub in
  `OpenOffer::windows`); one saved without (`None`) rebuilds exactly as
  before, so open contracts and the Mutinynet hub's keep their txids.
  The wallet refuses a hub giving her moves less than the network's
  window.
- Per network (`lichen_proto::windows`): regtest 14/10/16 (distinct, so a
  deadline read from the wrong window fails the tests), Mutinynet 80/20/80
  (40 min, 10 min, 40 min: an absent hub's users wait 10 minutes, not 40),
  signet 12/6/12, testnet4 72/18/72.
- Tests: ln-gap `sessions/tests/contract.rs` (every lock with and without
  windows, in the trees too, and bad windows refused); lichen's dispute,
  tail and resume tests run under the regtest windows, and `dispute.rs`'s
  second hub under its own (`--windows`-style config: 16/8/20).
- A hub sets its own (`lichen-hub --windows <user>,<hub>,<path>`, `WINDOWS`
  in `deploy/hub/.env`), sized by its contract count; it refuses at start
  windows that fail `check` or give the user less than the network's.
- The paper names them `w_A`, `w_H`, `w_P` (the dispute chain's
  "Windows by obligation", the Costs section's durations, the watchtower
  section, Table 2's caption).

## The paper: figures still from before the deployment keys

- TODO: the verifier's input is 204 bytes, 51 words (the journal now
  carries `D`), not 172 bytes and 43 words: the pipeline figure, the text
  beside it, the word table, and the Costs rows for the verifier
  (477,943,091 steps, not 478,100,841) and for `inputs` ("the other 32
  input words"; the deployment's eight go there too, per
  `Check::in_claim`). Take the split between `escalate` and `inputs`
  from the code.
- TODO: re-measure the Groth16 wrap (109 s was on the six-segment,
  unaccelerated proof; the proof is now one segment).

## Shielded transfers, then validity proofs (branch `shielded`, 2026-10-18)

Planned in [SHIELDED_PLAN.md](SHIELDED_PLAN.md): shielded notes in the
same tree, each sender proving their spend in RISC Zero, returns and
mints transparent so the withdrawal statement is unchanged; then the
validity chain, so the withdrawal proof judged in a dispute attests a
proven valid history.

## The exit (branch `exit`, 2026-10-30)

Planned in [EXIT_PLAN.md](EXIT_PLAN.md): a user exits from anchored state
when the operator (hub and sequencer) censors or vanishes, and the hub
may answer only with a counter, a later anchored spend or her own signed
claim through another contract. Built under BABE and played on regtest
on the mock statement (2026-10-31); still to do: the real-proof run,
towers' and shielded notes' exits, and sender acknowledgment for the
data-availability gap. Its status and decisions are at the top of that
plan.

## Later

Watchtowers: a turnkey tower, planned in [TOWER_PLAN.md](TOWER_PLAN.md) (papers/lichen-bitvmx-v0.1.2.pdf, the tower section); several hubs
(colours, clearing lines); a GUI.
