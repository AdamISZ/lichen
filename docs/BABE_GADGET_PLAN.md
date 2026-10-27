# BABE as a second gadget: plan

2026-10-27, branch `gadget`. Builds on GADGET_PLAN.md (the gadget layer)
and BABE_DISPUTE_PLAN.md (the graph, the windows, the figures). The
design note is papers/lichen-babe; its v0.1.2 and v0.1.3 (the keyless
tower, setup by VSSS) are on branch `exit-counter`, not yet merged.

## What there is to build on

The gadget layer (GADGET_PLAN.md) leaves BABE these, unchanged:

- **ln-gap's skeleton** (`sessions::skeleton`):
  - `Core::tree(escalate)`: BABE's `request` leaf is the escalate;
  - `Core::fold`, `Core::default_tx`;
  - `Core::pay_alice(b_key, …)`: the payout's bit outputs read Alice's
    WOTS signature on `b` under `b_key`, which under BABE is her
    `request` key (one word, `input_key_params`, the shape the payout
    asserts);
  - `Core::link(name, poster, shape, …)`: a link with its floor and its
    poster's anchor, for any name;
  - `Presign` (`new`, `new_multi`), `Signed`, `sign_all`.
- **lichen's proto**:
  - `Gadget`, and the untagged enums `DisputeKeys`, `RequestKeys`,
    `OfferKeys`, to which BABE adds a variant each: a BABE contract's
    record is told from a BitVMX one by its keys;
  - `Built`, to which BABE adds a variant: `tree`, `presign`, `b_key`,
    `terminal_need` dispatch to it, and everything neutral follows.
- **The hub**:
  - `dispute/mod.rs`: the tick dispatches by gadget; `Collect` and
    `Done`; `sweep_bits` with the gadget's `claimed_b` (under BABE, `b`
    read from `request`); `spend_leaf`, `post`;
  - the floors per gadget;
  - `open()` asks the gadget for its keys (`open_keys`).
- **The wallet**:
  - `engine/mod.rs`: posting her links and terminals, waiting on the
    hub's, the claim and the outcome kept;
  - `Signer::bitvmx()`, beside which goes `Signer::babe()`;
  - `won()`: neutral (her anchors are found by the anchor outputs, not
    by link names); `b_wire` by gadget.
- **ln-gap's primitives**: Lamport signatures and their script checks
  (`lngap_lamport`: π1's 508 bits), WOTS (`b`, the hub's `pk_H`),
  adaptor signatures (`lngap_btc::adaptor`: the VSSS label reveal).

## What BABE adds

1. **The fixed statement.** The journal can't carry `b`
   (BABE_DISPUTE_PLAN §2): `c ‖ D ‖ H(pk_H)`, `b` and the hub's
   signature on it in the witness. A second guest, so a second image id;
   `crates/withdraw` gains the check; the hub's native fold check takes
   either journal. (The speculative variant, BABE_DISPUTE_PLAN §11,
   drops `pk_H` from the journal and adds the request's inclusion.)
2. **The graph and its scripts**, about nine pre-signed transactions
   (BABE_DISPUTE_PLAN §3): `request`, `respond` (the hub's WOTS `b`, the
   digit-by-digit equality with Alice's), `request_timeout`, `assert`
   (π1 under Lamport, an absolute deadline), `respond_timeout`,
   `challenge_assert` (the labels), `success`, `wrongly_challenged`
   (`msg`'s preimage), `failure`. Two things the skeleton lacks:
   - an absolute lock on `assert` (CLTV): the skeleton's locks are
     relative, the default's leaf aside;
   - `failure` spends two outputs: a terminal of two inputs (ALL|ACP
     on each), or a link of two (plain ALL).
3. **Windows**: `w_H`, `Δ1`, `Δ2` and the assertion's deadline `T_A`, a
   `BabeWindows` beside BitVMX's `Windows`.
4. **The garbler and the evaluator**: BABE's circuit (the point check,
   the feature bits, the DRE tables), the witness encryption, and the
   setup: cut-and-choose, then VSSS (BABE §9.4; the intended setup, about
   40 s a contract against soldering's 14 min). The paper reports a
   prototype but gives no repository.
5. **The setup at opening**: an exchange beside the request and the
   offer, of megabytes (the finalized instances, M × 22 MiB, or about
   2 MiB if Duty-Free Bits' encoding applies). Alice stores them, in
   files of their own, not in the wallet's JSON.
6. **The drivers**:
   - the hub (`dispute/babe.rs`): answer `request` mechanically, sign
     its `b`; check π natively (Groth16 under the fixed input); challenge
     a false one; take `failure` after `Δ1`; collect;
   - the wallet (`engine/babe.rs`): post `request`; take the hub's `b`
     from `respond` (or its timeout); prove with it; `assert` before
     `T_A`; on a challenge, evaluate, decrypt `msg`, post
     `wrongly_challenged`; `success` after `Δ2`.
7. **The tower**: under BABE it holds none of her keys (the keyless
   tower, babe v0.1.2): a package of its own.

## Order

1. **The statement**: the fixed-statement guest and `withdraw` check, on
   its own: proved and wrapped, its public input the same for every
   amount.
2. **The scripts and the graph, with a stand-in for the garbling**:
   labels as plain hash preimages and `msg` released by a lookup, so
   that the on-chain part is built and played on regtest before any
   circuit exists. Its own fingerprint test, as the BitVMX contract's.
3. **lichen**: `Gadget::Babe` through proto, the hub and the wallet,
   on the stand-in: a dispute played end to end on regtest (true claim,
   false claim, hub gone, user gone, a wrong challenge).
4. **The real garbling**: the circuit, the encryption, cut-and-choose
   then VSSS, the setup exchange, Alice's storage; `challenge_assert`'s
   label reveal by adaptor signatures.
5. **End to end on a real proof**, then Mutinynet; measured.

## Decided (2026-10-27)

- **Where BABE's code lives: lichen**, a crate of its own (the graph, its
  scripts, the garbling). The BitVMX ladder in ln-gap is that project's
  proof of concept, not a pattern; ln-gap's skeleton stays shared.
- **BABE is implemented here**: there is no library. What it needs:
  - **BN254 natively** (Fq, Fr, G1, G2, the pairing): arkworks
    (`ark-bn254`, `ark-ec`, `ark-ff`; MIT/Apache-2.0, already in the lock
    file). For the WE, the setup, the DRE's encoding and decoding, and as
    the reference the gate-level circuits are tested against.
  - **Fq in Boolean gates**: only where there are garbled tables, the
    point-validation gadget (lichen-babe: all but it is a DRE without
    tables). A few Fq multiplications and range checks; written here,
    tested against `ark-ff`. BitVM's `garbled-snark-verifier` has BN254
    gadgets but is GPL-3.0: a reference, not code to take.
  - **Half-gates and free-XOR**: swanky's `fancy-garbling` (MIT) or
    tlsnotary's `mpz` (licence to check). But the input labels are ours:
    Lamport preimages checked in script, revealed under VSSS by adaptor
    signatures. Probably our own garbler, the library a cross-check.
  - **The DRE's MACs (Argo)**: elliptic-curve; which curve to read off
    Argo (2026/049). One whose scalar field is BN254's Fq (Grumpkin)
    would be the natural one.

## Open questions

- **The countersignature or the work-bound request** (BABE_DISPUTE_PLAN
  §2 or §11): the countersignature is designed; the other is
  speculative. Build the first; keep the second as an experiment.
- **VSSS's on-chain design**: the adaptor-per-bit reveal in
  `challenge_assert` (MuSig2 nonces or Alice's own key) isn't designed
  yet.
- **A hub offering both gadgets**: `Info` names one statement and its
  depths; offering BitVMX and BABE side by side changes the handshake.

## Status

- [ ] 1 statement
- [ ] 2 scripts and graph (stand-in)
- [ ] 3 lichen integration (stand-in)
- [ ] 4 the garbling
- [ ] 5 end to end
