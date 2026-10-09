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

## M2: contracts with the hub

- `lichen-hub` daemon: bitcoind RPC (regtest); HTTP for the wallet.
- Opening: Alice and the hub fund one output (Alice `D + r_A`, the hub
  `V_max - D + r_H`); the pre-signing ceremony (default, escalate, the
  ladder with lean moves, the final proofs, the payouts), all signed
  `ALL|ANYONECANPAY` at zero fee; then the funding transaction. On
  confirmation the hub mints `D` to Alice.
- Units: plain sats, everywhere (decided 2026-10-09). What the ledger
  carries is bitcoin, not a separate asset: within each user's cap it is
  bitcoin she can take out without trusting anyone. Display may use ksats.
  A note's value is in sats; `b` in the statement's journal is a u32 of
  sats (up to about 42.9 BTC). The dispute path alone has a coarser
  granularity: its payout's bit outputs start at the first bit worth at
  least the dust limit (512 sats), so `b` is rounded down there by less
  than 512 sats; the cooperative fold pays exact sats.
- Cooperative close: a 2-of-2 fold leaf for now. TODO: MuSig2, here and
  wherever else it is feasible (key paths for every 2-of-2 spend that
  both parties sign together).
- Uses ln-gap's `lngap-sessions`, `lngap-v25`, `lngap-zk` (path
  dependencies for now).

## M3: the cooperative withdrawal

Alice returns `b` with memo `c`; the hub sees it in a sealed height and
folds: Alice `b + r_A`, the hub `V_max - b + r_H`. Also: the default at
`T_close`.

## M4: disputes

The wallet proves its return (RISC Zero via `r0vm`; the Groth16 wrap on
x86 Linux, or delegated), runs BitVMX's search over the verifier, escalates
and plays the ladder, paying its own fees; the hub daemon answers
automatically. Then the hub's side: input-word checks, disproves.

## Later

Watchtowers (open problem: research/lngap_v3 §6.4); several hubs
(colours, clearing lines); shielded notes; the accelerated guest; a GUI.
