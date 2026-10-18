# The committed spend guest

`spend.bin` is the program the prover (`lichen-r0`) proves and the
sequencer verifies receipts of: the spend guest's ELF with RISC Zero's
kernel (V1COMPAT), built by `../build-guest.sh` in RISC Zero's pinned
builder image. `spend.id` is its image id, which the sequencer checks
receipts against (`lichen-r0 image-id` recomputes it from the file).

| spend guest | built by | image id |
|---|---|---|
| **the statement of `crates/shielded` (docs/SHIELDED_PLAN.md), 2026-10-18: the current file** | **x86 Linux (GCE `n2-highmem-4`), `build-guest.sh elf`, natively; packed on a Mac (`build-guest.sh pack`). ELF SHA-256 `ca07debb0114ea3b20bc0a1d19f0cb0bd79c61ecf6260e1ece74778cc3ce343c`; `spend.bin` 324,260 bytes, SHA-256 `1af60862e368598a6e30423cd2f5ba1b15bb329fd853ebb705da6e7109ce82e7`** | **`bd46ebb2d918063416513fdd093daf6f0cdb2550056e91805187544d587d5e75`** |

Measured with it (Mac, Docker, 8 cores; composite receipts): shielding
10,163 user cycles, 6.4 s; a payment (1 in, 2 out) 46,353, 13.4 s; a
return 42,474, 13.3 s. One segment each.
