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
  after the spend guest.
- `withdraw`: the withdrawal statement of `crates/withdraw` (ln-gap's,
  plus a chain receipt vouching for the root the withdrawal's path
  reaches). It holds `chain.id`, so it is rebuilt after the chain guest.
  The contracts pin `withdraw.id` (`lichen_proto::IMAGE_ID`): a new build
  is a new deployment's contracts.

| guest | built by | image id |
|---|---|---|
| **spend**, the statement of `crates/shielded` (docs/SHIELDED_PLAN.md), 2026-10-18: **the current file** | x86 Linux (GCE `n2-highmem-4`), `build-guest.sh elf`, natively; packed on a Mac (`build-guest.sh pack`). ELF SHA-256 `ca07debb0114ea3b20bc0a1d19f0cb0bd79c61ecf6260e1ece74778cc3ce343c` (rebuilt from the tree after the phase 2 changes: the same); `spend.bin` 324,260 bytes, SHA-256 `1af60862e368598a6e30423cd2f5ba1b15bb329fd853ebb705da6e7109ce82e7` | **`bd46ebb2d918063416513fdd093daf6f0cdb2550056e91805187544d587d5e75`** |
| **chain**, the statement of `crates/validity`, holding the spend guest above, 2026-10-18: **the current file** | the same way (`build-guest.sh elf chain`, `pack chain`). ELF SHA-256 `190bb2395555f202fd8432acb958ab401389dbebf76dda023df6e0c19cff4a76`; `chain.bin` 436,700 bytes, SHA-256 `112a56fcf0802a78aa5d328623da1cfb93195c51229d731ca4fbf7a68b5c67d6` | **`f6d7255f4afcf9f3ea8a50bc0cccf9ac9e89ec26c6b37ad762c5f51b8f188a51`** |
| **withdraw**, the statement of `crates/withdraw`, holding the chain guest above, 2026-10-19: **the current file** | the same way (`build-guest.sh elf withdraw`, `pack withdraw`). ELF SHA-256 `e2f748ef3e811c5e1c6b9eb2fd17a277e626c7ab81e5b5f533d140939a906817`; `withdraw.bin` 375,980 bytes, SHA-256 `92cfca725b20ca9ee06fea33981c9c891de9026e92c04dffcff37e28bef1726d` | **`6607a2bca6acf852bcf5c862df87fe03069b7f02b2447433fb41d761557c5861`** |
| chain, its first build (`78a5f7d`): the empty subtrees computed in every block | as above. ELF SHA-256 `a2c56188…` | `1c0a9bd4625433d02201bde38f0de5d85726e556800f730450e085fdeba1b791` |

Measured with the chain guest (`lichen-r0 exec-chain`, RISC0_PPROF_OUT
for a profile): a block of one mint, 383k user cycles (1,087k in its
first build); a mint and a transfer, 993k (2,140k). A BIP340 signature
is ~260k, a nullifier insert ~306k.

Measured with the withdrawal guest: 332k user cycles (one segment;
the chain receipt's verification is an assumption, resolved in the
succinct receipt): 75 s on the Mac (Docker, 8 cores), succinct; on the
GCE `n2-highmem-4` (4 vCPUs) 360 s, then 260 s to wrap in Groth16.

Measured with the spend guest (Mac, Docker, 8 cores; composite
receipts): shielding 10,163 user cycles, 6.4 s; a payment (1 in, 2 out)
46,353, 13.4 s; a return 42,474, 13.3 s. One segment each.
