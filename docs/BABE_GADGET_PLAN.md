# BABE as a second gadget: plan

2026-10-27, branch `gadget`. Builds on GADGET_PLAN.md (the gadget layer)
and BABE_DISPUTE_PLAN.md (the graph, the windows, the figures). The
design note is papers/lichen-babe-v0.1.6 (v0.1.2 the keyless tower,
v0.1.3 the setup by VSSS, v0.1.4 the honest-setup caveat, v0.1.5 the
adaptor reveal in 2-bit digits, v0.1.6 `wrongly_challenged` signed at
setup).

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
   (`msg`'s preimage), `failure`. As built (2026-10-28), one chain
   carries the value and every transaction has one input (BABE's
   deposit-and-connectors shape isn't needed: there `assert` starts from
   an outside coin); the skeleton's `Presign::new` takes a CLTV as is.
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
  - **Fq in Boolean gates**: the Boolean part of the circuit (BABE §5.6,
    steps 1 and 2), garbled privacy-free (π1 is public): the range
    checks x, y < p, the curve equation, *and* the feature products
    x², y², xy, whose bits it outputs (the generator's, for a point that
    fails). The DRE is linear in those bits, so the products can't be
    its: an earlier reading here had them there, wrongly. The paper's
    split: 6.35 MiB of gates, 15.77 MiB of DRE tables. Written here,
    tested against `ark-ff`. BitVM's `garbled-snark-verifier` has BN254
    gadgets but is GPL-3.0: a reference, not code to take.
  - **Half-gates and free-XOR**: swanky's `fancy-garbling` (MIT) or
    tlsnotary's `mpz` (licence to check). But the input labels are ours:
    Lamport preimages checked in script, revealed under VSSS by adaptor
    signatures. Probably our own garbler, the library a cross-check.
  - **The DRE (Argo MAC, 2026/049)**: no second curve. The MAC of π1 is
    φ(π1) + K in BN254's G1 itself (φ small multiples or the curve's
    endomorphism, K a point), its encoding a degree-3 polynomial in π1's
    coordinates, garbled arithmetically (ITPG) over Fq. Bits to field
    labels is a Yao step. So arkworks' Fq and G1 cover it.

## Open questions

- **Later: reuse the kept instances across renewals** (2026-10-28). The
  garbled circuit computes `r·π1` whatever the statement; only the WE
  ciphertext (480 bytes) and the hashlock are the contract's. Its
  security is spent only when labels are revealed, in
  `challenge_assert`. So a renewal after a fold, or after `success`
  unchallenged, could keep the instances and send a fresh `msg`,
  ciphertext and hashlock each: kilobytes, not the 239 MiB download.
  Needs: an argument that one `r` under ciphertexts for different
  statements is safe while no labels are revealed. Per user only; after
  a challenge, a full setup.

- **The countersignature or the work-bound request** (BABE_DISPUTE_PLAN
  §2 or §11): the countersignature is designed; the other is
  speculative. Build the first; keep the second as an experiment.
- **A hub offering both gadgets**: `Info` names one statement and its
  depths; offering BitVMX and BABE side by side changes the handshake.

## Status

- [x] 1 statement
  - [x] `lichen_withdraw::fixed`: the withdrawal's checks, then the hub's
        Winternitz signature on `b` (ln-gap's digits and checksum, checked
        against its signer, but SHA-256 chains: accelerated in the guest;
        `respond`'s script needs a SHA-256 `wots_verify`, ln-gap's being
        HASH160), journal `c ‖ D ‖ H(pk_H)`; the same journal for two
        amounts, tested
  - [x] `r0/babe-guest`, `build-guest.sh babe`; `lichen-r0
        babe|exec-babe <withdraw input> <hub auth> <chain receipt> <out>`
        (prints the claim digest), `wrap` of either guest
  - [x] built (x86, lichen-vps), image id `74b95bb4…`; executed: 482k
        user cycles against the withdrawal's 333k, one segment; proved
        (660 s) and wrapped (258 s) on a real return; a signature on
        another `b` refused; claim digest printed
- [x] 2 scripts and graph (`graph`): on the real reveal, `msg` the
      only stand-in. One chain `request → respond → assert →
      challenge_assert`, each output with its terminal
      (`request_timeout` after `w_H`, `respond_timeout` from `T_A` by
      CLTV, `success` after `Δ2`, `failure` after `Δ1`), and per kept
      instance `wrongly_challenged_k` (TRUC, 2-of-2 with Alice's
      signature kept from the hub, paying her `b` in bits: a terminal
      can't pay into a pre-signed transaction, its fee input changes its
      id). `respond` checks the hub's SHA-256 Winternitz signature on `b`
      against Alice's digit by digit (ln-gap's `Wots256*`, `1f0db8c`).
      12 pre-signed, fingerprint pinned. On regtest, mainnet's policy,
      every ending: a true claim challenged and paid, a false one taken
      by `failure`, the hub gone, Alice gone, no challenge, and a
      `respond` on another `b` refused. Sizes: `request` 457 vB,
      `respond` 759, `assert` 7,700, `challenge_assert` 20,717,
      `wrongly_challenged` 805 with its fee coin (the note's 0.21: it
      now carries the payout), the timeouts and `failure` 221–780
      (`tests/graph.rs`)
- [x] 3 lichen integration, on the mock statement (a Groth16 proof of
      a toy circuit for the contract's journal; `babe-mock`, and `babe`
      for RISC Zero's)
  - [x] proto: `Statement::Babe`, `Gadget::Babe`, the keys and `Built`
        variants, `Accept`'s adaptor pre-signatures; the program an
        `Option` (BABE has none); `babe::Disputed`; Alice's signature on
        `wrongly_challenged` kept from the hub, the set checked without it
  - [x] the opening's setup: `POST /babe/setup` (the hub deals and
        commits to `N` instances; everything derives from its seed, it
        keeps the commitments and hashlocks), Alice chooses `M`, the offer
        opens the rest (seeds, shares), she checks them (shares on the
        dealing, each rebuilt to its hash), downloads the kept (`GET
        /babe/instance/<cid>/<i>`, bytes) to their hashes and hashlocks,
        keeps them beside the wallet, and pre-signs the reveal. (4, 2) on
        regtest, (78, 10) elsewhere; the wallet refuses less than 2^40
        soundness off regtest
  - [x] the hub (`dispute/babe.rs`): responds to `request`; checks the
        proof from `assert` (π1 from the digits, π2 and π3 beside); lets a
        valid one stand, challenges a false one (or, misbehaving, any);
        `failure` after `Δ1`, `respond_timeout` from `T_A`; collects its
        bit outputs after a loss
  - [x] the wallet (`engine/babe.rs`): request, assert before `T_A`,
        `success` after `Δ2`; on a challenge, extracts π1's secrets,
        interpolates each kept instance's, evaluates, decrypts, and answers
        with `msg`; `request_timeout` if the hub is gone; the sweep
  - [x] on regtest through the hub and the wallet (`hub/tests/babe.rs`):
        a true claim unchallenged; a true claim challenged and answered; a
        false one taken by `failure`; the hub gone. TRUC: the fee coin of
        `wrongly_challenged` confirms before it (`Chain::post_terminal`)
  - [x] restarts and Alice gone (`hub/tests/babe_resume.rs`): her
        wallet stops after `assert`, the hub restarts from its data
        directory, the wallet reopens from its file; both replay the chain,
        the hub challenges, she answers and is paid. Her wallet stops after
        `request` and she never asserts: at `T_A` the hub takes
        `respond_timeout`, and her wallet, resumed, finds the contract lost
  - [x] the keyless tower (`tower.rs`, `hub/tests/babe_tower.rs`): the
        package holds her signatures, none of her keys: on `b` (`request`'s
        wire), on π1 (a preimage a digit, checked against her Lamport key
        before `assert`), and in the contract on `wrongly_challenged`; the
        proof made before export (one the hub would win against is
        refused). The kept instances and the opened shares are copied to
        the package's work directory (`export_instances`; 48 MiB at (4, 2),
        239 at (78, 10)). Played against a hub that challenges true
        claims: answered, paid in 2.2 s, a rerun stops at the payout, the
        wallet sweeps. Links at their floors and the fee budget's key, as
        BitVMX's tower; the anchors' own key is still to come
- [x] 4 the garbling (begun before 2 and 3: it doesn't need them)
  - [x] honest setup, `crates/babe`: the witness encryption
        (Construction 1), the garbled circuit for `r·π1` (Construction 2:
        the point gadget privacy-free with free XOR, the DRE's tables with
        Remark 4's hashed shifts); a Groth16 proof (arkworks, a toy
        statement) decrypts `msg`, a valid proof of another statement
        doesn't; an invalid point gets `r·g`
  - [x] measured (release, a laptop): 528k ANDs, 8.06 MiB (the paper's
        6.35: schoolbook products, not Karatsuba); DRE 516,890 field
        elements, 15.77 MiB, as the paper's; 23.83 MiB an instance;
        garbling 1.2 s, evaluating 0.6 s (the paper's 175 and 127 ms:
        blake3 here, not fixed-key AES; one thread)
  - [x] RISC Zero's verifying key and claim (`lichen_babe::risc0`, from
        ln-gap's `lngap_zk::groth16`, made public for it): step 1's real
        receipt (60, memo 42) decrypts `msg`; another contract's journal
        doesn't
  - [x] cut-and-choose over VSSS-shared input secrets (`setup`, `vsss`):
        an instance a function of its seed and its secrets, committed by
        hash; the secrets Shamir-shared over secp256k1 (degree N − M,
        Feldman, `C_0` the adaptor point), the circuit's free-XOR labels
        reached through a translation table (since the reveal: a secret a
        2-bit digit and value, mapped to both its bits' labels). A
        lie in an opened instance is caught; with one in a kept instance
        Alice opens another. At (78, 10), one machine, 14 cores: 19 s in
        all (dealing 1.3 s, the hub's 78 instances 9.4 s, Alice's checks
        1.5 + 8.1 s); she stores 239 MiB (238 before digits), and downloads it first
        (`examples/setup_cost.rs`)
  - [x] the setup exchange, Alice's storage (built in step 3: `POST
        /babe/setup`, the kept instances as files beside the wallet)
  - [x] `challenge_assert`'s reveal by adaptor signatures (`reveal`; the
        note's v0.1.5): π1 Lamport-signed in 2-bit digits; Alice's one-time
        keys, a pre-signature a digit and value, adapted to the dealing's
        `f(0)·G`; the leaf selects the key by her preimage. On regtest,
        mainnet's relay policy: `assert` 7,598 vB, `challenge_assert`
        20,640 vB (its leaf 60,232 B, 509 witness elements), as the note
        estimated (7.8, 21 kvB); a completion for another value refused;
        Alice reads each digit's secret from the mined transaction. The
        1,000-element limit, checked: 1,000 pass, 1,017 (bit by bit) don't
        (`tests/reveal.rs`)
- [x] 5 end to end
  - [x] the proof after `respond`: the real statement proves the hub's
        signature on `b`, which `respond` carries. With no proof the
        wallet requests, and once the hub responds writes its signature
        (`hub-auth.json`, `lichen-r0 babe`'s format, checked under its key)
        and stops with the proof due by `T_A` (`Outcome::ProofDue`); run
        again with the claim (`lichen-r0 babe-claim`: `babe`, `wrap`,
        `bitvmx-input`), which the wallet reads as the BABE guest's proof
        for the contract's journal. The CLI prints the steps; a tower
        takes over once proved
  - [x] a real proof on regtest (`hub/tests/babe_risc0.rs`, opt-in): the
        toy deployment's return of 60 with memo 42, contract 42, the hubs
        of one seed (one key for `b`, one journal); the hub's signature as
        `respond` carried it, proved on lichen-vps (662 s, the wrap 257 s,
        482k user cycles), canned (`proto/tests/data/babe-claim-60-42.*`).
        An honest hub doesn't challenge, `success` pays; a hub challenging
        true claims is answered from a kept instance; step 1's proof
        (another hub's key) is challenged, opens nothing, and `failure`
        takes the contract. 34 s in all
  - [x] Mutinynet (2026-10-29), a fresh deployment (`0dde353e…`: a new
        sequencer key, genesis seal `6b4efbec…:1`; `8c971e86…` archived),
        anchoring through the hub's node, the chain prover on the Mac; the
        hub hostile, `babe`, at (78, 10): its setup 9.5 s, Alice's kept
        instances 243 MB. Contract 1000, deposit 400,000; a withdrawal of
        300,000 returned and refused after its anchor and chain receipt
        (7 min 44 s). The dispute: `request` (449 vB), the hub's `respond`
        a block later (759 vB), her proof due 34 s after she requested.
        Proved on lichen-vps from the hub's signature: 476k user cycles,
        640 s, the wrap 254 s (895 s in all). `assert` (7,725 vB), the
        hub's `challenge_assert` the next block (20,717 vB); kept instance
        9 opened on the real proof, `wrongly_challenged` (821 vB, v3) five
        blocks after the challenge; the hub collected its 8 bit outputs;
        her sweep after δ, 358,260 sats (b's bits and reserves 330,482,
        anchors 660, the fee budget's rest 28,857, fee 1,739). Each link
        went at its floor (1 sat/vB, no fee child needed); her links'
        floors 8,183 sats, the hub's 21,478.
        Found: the deployment's Mutinynet node (`deploy/hub/bitcoind`, a
        25.99 build) rejects TRUC (`version`); its peers (29.x) relay it,
        so the answer went out through mutinynet.com's Esplora (the
        wallet resumed with `--esplora`), within `Δ1`. The node image
        wants the current Mutinynet build (29.2); mainnet relays TRUC from
        Core 28
