# The committed guests

Each `<g>.bin` is a program the prover (`lichen-r0`) proves and others
verify receipts of: the guest's ELF with RISC Zero's kernel (V1COMPAT),
built by `../build-guest.sh` in RISC Zero's pinned builder image. `<g>.id`
is its image id (`lichen-r0 image-id <g>` recomputes it from the file;
`lichen-r0 check-id` checks both, and the prover image runs it).

- `spend`: the spend statement of `crates/shielded`. The sequencer checks
  every shielded transaction's receipt against `spend.id`.
- `chain`: the chain statement of `crates/validity` (one sealed block,
  and the history before it). It holds `spend.id`, so it is rebuilt
  after the spend guest; the withdrawal guest will check chain receipts
  against `chain.id`.

| guest | built by | image id |
|---|---|---|
| **spend**, the statement of `crates/shielded` (docs/SHIELDED_PLAN.md), 2026-10-18: **the current file** | x86 Linux (GCE `n2-highmem-4`), `build-guest.sh elf`, natively; packed on a Mac (`build-guest.sh pack`). ELF SHA-256 `ca07debb0114ea3b20bc0a1d19f0cb0bd79c61ecf6260e1ece74778cc3ce343c` (rebuilt from the tree after the phase 2 changes: the same); `spend.bin` 324,260 bytes, SHA-256 `1af60862e368598a6e30423cd2f5ba1b15bb329fd853ebb705da6e7109ce82e7` | **`bd46ebb2d918063416513fdd093daf6f0cdb2550056e91805187544d587d5e75`** |
| **chain**, the statement of `crates/validity`, holding the spend guest above, 2026-10-18: **the current file** | the same way (`build-guest.sh elf chain`, `pack chain`). ELF SHA-256 `a2c56188b4fcd6019773beb1c4567a31a1a8b7f14ec99aa55f35be32c6ff7ea2`; `chain.bin` 429,668 bytes, SHA-256 `de5444c0f0f6849e9fbeea7c45b274826980af4ab74b3615d80f7010821b699b` | **`1c0a9bd4625433d02201bde38f0de5d85726e556800f730450e085fdeba1b791`** |

Measured with the spend guest (Mac, Docker, 8 cores; composite
receipts): shielding 10,163 user cycles, 6.4 s; a payment (1 in, 2 out)
46,353, 13.4 s; a return 42,474, 13.3 s. One segment each.
