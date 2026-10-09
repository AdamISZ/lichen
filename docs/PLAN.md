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
  once its funding confirms. The wallet's `lichen open`, `lichen contracts`.
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
- Fees: no pre-signed transaction pays its own; the chain's links are
  TRUC with a zero-value anchor (the poster's child pays), the terminal
  ones ALL|ANYONECANPAY (the broadcaster adds a coin). The contract output
  holds exactly `V_max` and both reserves.
- TODO: MuSig2 for every 2-of-2 spend both parties sign together (the
  cooperative close first); for now a 2-of-2 fold leaf (M3).
- Test (`crates/hub/tests/open.rs`): opening on the mock statement in
  about 6 s (debug): 47 pre-signed transactions, every signature checked
  by both; the hub mints the deposit on confirmation.

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

## M4: disputes

The wallet proves its return (RISC Zero via `r0vm`; the Groth16 wrap on
x86 Linux, or delegated), runs BitVMX's search over the verifier, escalates
and plays the ladder, paying its own fees; the hub daemon answers
automatically. Then the hub's side: input-word checks, disproves.

## Later

Watchtowers (open problem: research/lngap_v3 §6.4); several hubs
(colours, clearing lines); shielded notes; the accelerated guest; a GUI.
