# Liquidity: a requested amount, a fee, any cap

Working notes for the `liquidity` branch.

## The problem

A contract's cap is `V_max = 2^K - 1` sats, K chosen by the user
(`--bits`, 21 by default): the dispute's payout has an output of `2^i`
sats per bit of `b` (ln-gap's `payout`), which sum to `2^K - 1`, and the
contract must hold them. So the hub locks up to twice what the user
needs: at the default, about 2M sats a contract, whatever she asked.

## The design

- **The request.** Alice asks for liquidity `L` (inbound: what she can
  receive beyond her deposit) with her deposit `D`, and the fee `f` she
  accepts. The hub quotes its rate in `/info` (`fee_ppm`, parts per
  million of `L`; 1% to start, no dependence on time), so the wallet
  knows `f` before the deposit is paid. The hub refuses a request whose
  fee is under its rate, or whose `L` is over its `max_liquidity`.
- **The fee, at opening.** She pays `D` in as now (`Terms.deposit` is
  still `D`, so the funding split is unchanged: she puts in `D + r_A`, the
  hub `V_max - D + r_H`), and is minted `D - f`. The cap is
  `D - f + L`, so her inbound is `L`; the hub puts in `L - f + r_H`. The
  fee is paid in every outcome (fold, dispute, exit, default). `f` is
  kept in the contract's record (lichen's `Record`, not ln-gap's `Terms`).
- **Any cap: a unit.** ln-gap's `Terms` has a unit `u` (lichen's was
  always 1 sat): `V_max = u (2^K - 1)`, bit `i` worth `u 2^i`. Both sides
  derive `(K, u)` from the cap `C` by one rule: the largest `K` with
  `512 (2^K - 1) <= C`, then `u = ceil(C / (2^K - 1))`, so `u` is from 512
  sats to about 1,024 and every bit has an output (`low_bits` 0). `V_max`
  exceeds `C` by under `2^K`, about 0.2% (the hub's); a dispute pays in
  multiples of `u`, as it paid in multiples of 512 before; a fold pays
  exactly.
- **The statement.** `b` is in units: a return of value `r` proves
  `b = floor(r / u)`; an exit's claim of `b` needs `b u` at most its notes'
  total. `u` is bound in the contract's identifier, beside `W`:
  `D = H("lichen/contract" || deployment || genesis seal || W || u)`, so
  the journals keep their layout. The withdrawal, BABE and counter guests
  change (new image ids); the chain guest doesn't.

## Steps

1. `lichen-withdraw`: `unit` in `Anchored`, `WithdrawInput` and
   `contract_id`; `b` in units; the exit's total against `b u`; tests.
2. `lichen-ledger`: the wrappers that build the inputs take the unit.
3. `lichen-proto`: `OpenRequest` (`liquidity`, `fee` for `bits`),
   `Info` (`fee_ppm`, `max_liquidity` for `max_bits`), `terms` with the
   scale rule, `contract_word` with the unit, `Record.fee`; the format
   fixtures.
4. The hub: its policy (`--fee-ppm`, `--max-liquidity`), the mint of
   `D - f`, the fold's journal in units, its reserve on the cap.
5. The wallet: `open <deposit> --liquidity <L>`, the fee shown before
   paying, the mint `D - f`, disputes and exits in units.
6. The demo; deploy's settings (`FEE_PPM`, `MAX_LIQUIDITY` for
   `MAX_BITS`); RUN_A_HUB.md, USE_A_WALLET.md.
7. The guests: withdraw, counter, babe, rebuilt (ELFs on x86, packed
   with Docker), their ids committed; the real-proof fixtures proved
   again (`claim-60-42`, `babe-claim-60-42`, `babe-60-42`). Done
   (2026-10-31): the canned return is now 60 units of the real-statement
   tests' unit (684 sats, `lichen_proto::canned_unit`), since every new
   contract's unit is at least 512 sats.
8. Regtest: the smoke test, a dispute on the real statement. The
   dispute is done (babe_risc0, its claims proved live): it found that a
   plain dispute on a contract with the exit had no proof the wallet
   could make (`babe-claim` proved the statement without the exit, whose
   journal no contract has now). The hub auth the wallet writes carries
   the exit's keys and coin, and `babe-claim` proves the statement with
   the exit, a return (`Mode::Return`). The smoke test remains.

Existing contracts keep their terms; contracts opened after this use the
new guests.
