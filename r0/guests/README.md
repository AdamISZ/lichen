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
- `babe`: the fixed statement of `crates/withdraw` (`fixed`), for BABE
  (docs/BABE_GADGET_PLAN.md, step 1): the withdrawal's, `b` in the
  witness under the hub's signature, its journal `c ‖ D ‖ H(pk_H)`. It
  holds `chain.id`.

| guest | built by | image id |
|---|---|---|
| **spend**, the statement of `crates/shielded` (docs/SHIELDED_PLAN.md), 2026-10-18: **the current file** | x86 Linux (GCE `n2-highmem-4`), `build-guest.sh elf`, natively; packed on a Mac (`build-guest.sh pack`). ELF SHA-256 `ca07debb0114ea3b20bc0a1d19f0cb0bd79c61ecf6260e1ece74778cc3ce343c` (rebuilt from the tree after the phase 2 changes: the same); `spend.bin` 324,260 bytes, SHA-256 `1af60862e368598a6e30423cd2f5ba1b15bb329fd853ebb705da6e7109ce82e7` | **`bd46ebb2d918063416513fdd093daf6f0cdb2550056e91805187544d587d5e75`** |
| **chain**, the statement of `crates/validity` after the code review (docs/REVIEW_PLAN.md: an anchor's path as deep as its block's coinbase, mints bound to the deployment, shielded lists bounded), holding the spend guest above, 2026-10-21: **the current file** | x86 Linux (GCE `n2-highmem-4`), `build-guest.sh elf chain`, then `pack chain` there (lichen `4d6110e`). ELF SHA-256 `8076be20b58b1d89d49b0167ff6eb3185687a0cf1ad4fac845c59f5c62fedfe6`; `chain.bin` 453,564 bytes, SHA-256 `a65eebfc6b8a81bca8abd19f523dadb99b598482b4d760c77728007a4eca32ad` | **`d810c7834a24e948ee6c97d319c196dd1053fb789d533785191c57a8d63cbb95`** |
| **withdraw**, the statement of `crates/withdraw` (unchanged), holding the chain guest above, 2026-10-21: **the current file** | the same way (`elf withdraw`, `pack withdraw`). ELF SHA-256 `0efa24819327711598c5a3c6189e5d8375c6186c9bc8f15b3ae7d8c7c8838ad7`; `withdraw.bin` 390,720 bytes, SHA-256 `cadb390918128b1ea42d5851c556349e8db7d24e2cc32d7edd4a5f4d083b1666` | **`11a9f930b722eda7396291432e6daf88648f75631e3a1b9fd6237b2fc3624e67`** |
| **babe**, the fixed statement of `crates/withdraw` (`fixed`), holding the chain guest above, 2026-10-27: **the current file** | x86 Linux (lichen-vps), `build-guest.sh elf babe`, then `pack babe` there (lichen `60131e6` and the next commit). ELF SHA-256 `166be0366b786e925856b4624692f8afb3daf6bce9b51c92474832fa09a121a8`; `babe.bin` 399,964 bytes, SHA-256 `3450c556a5ba763c26c2039d64c4fef561beaa9e4a183e13a380640dae929859` | **`74b95bb41c423a6d67194f1d4b276937608d5a13a14b637c225e2a5a7e85ed8a`** |
| chain, with anchoring, 2026-10-20 | x86 Linux (GCE `n2-highmem-4`), `build-guest.sh elf chain`, natively, then `pack chain` there. ELF SHA-256 `e9b71830a9b9941624b32817dd6a31f90018121cf6f9b1c2ee214c0ddf64c7b2`; `chain.bin` 451,840 bytes, SHA-256 `6d97522e58e9ef3c4402f5dfbf7b99aeac0f7bac2c329ea65cff7b1103ce48d5` | `04debc7720d8dfe2f7994516a94f58eb4a024d0b1e2962dce81bc597edb0d84f` |
| withdraw, with anchoring, 2026-10-20 | the same way (`elf withdraw`, `pack withdraw`). ELF SHA-256 `b9e76ee75fff479468d23a250b843dd6dfe3f6d24a721e018eea210d3b658723`; `withdraw.bin` 390,740 bytes, SHA-256 `2379b562734a70458a871c969f4a60b21fa3c1867e3127544c35168cd982d506` | `9a7b0b4022caf0611d2ce199c12b0ffb1804fb9d826d7548334ad299cce40039` |
| chain, before anchoring, 2026-10-18 | the same way (`build-guest.sh elf chain`, `pack chain`). ELF SHA-256 `190bb2395555f202fd8432acb958ab401389dbebf76dda023df6e0c19cff4a76`; `chain.bin` 436,700 bytes, SHA-256 `112a56fcf0802a78aa5d328623da1cfb93195c51229d731ca4fbf7a68b5c67d6` | **`f6d7255f4afcf9f3ea8a50bc0cccf9ac9e89ec26c6b37ad762c5f51b8f188a51`** |
| withdraw, before anchoring, 2026-10-19 | the same way (`build-guest.sh elf withdraw`, `pack withdraw`). ELF SHA-256 `e2f748ef3e811c5e1c6b9eb2fd17a277e626c7ab81e5b5f533d140939a906817`; `withdraw.bin` 375,980 bytes, SHA-256 `92cfca725b20ca9ee06fea33981c9c891de9026e92c04dffcff37e28bef1726d` | **`6607a2bca6acf852bcf5c862df87fe03069b7f02b2447433fb41d761557c5861`** |
| chain, its first build (`78a5f7d`): the empty subtrees computed in every block | as above. ELF SHA-256 `a2c56188…` | `1c0a9bd4625433d02201bde38f0de5d85726e556800f730450e085fdeba1b791` |

Measured with the chain guest (`lichen-r0 exec-chain`, RISC0_PPROF_OUT
for a profile): a block of one mint, 383k user cycles (1,087k in its
first build); a mint and a transfer, 993k (2,140k). A BIP340 signature
is ~260k, a nullifier insert ~306k.

Measured with the withdrawal guest: 332k user cycles (one segment;
the chain receipt's verification is an assumption, resolved in the
succinct receipt): 75 s on the Mac (Docker, 8 cores), succinct; on the
GCE `n2-highmem-4` (4 vCPUs) 360 s, then 260 s to wrap in Groth16.

Measured with the BABE guest, on the same return (60, memo 42) and the
hub's signature on 60 (120 SHA-256 chain steps): 482k user cycles, one
segment; on lichen-vps (4 vCPUs) proved in 660 s, wrapped in Groth16 in
258 s. The withdrawal guest, on an earlier return: 333k, 360 s there. (Above 2^19
cycles with the paging, perhaps: the time grows more than the cycles.)

Measured with the spend guest (Mac, Docker, 8 cores; composite
receipts): shielding 10,163 user cycles, 6.4 s; a payment (1 in, 2 out)
46,353, 13.4 s; a return 42,474, 13.3 s. One segment each.
