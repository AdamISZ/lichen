//! The wallet's shielded notes (docs/SHIELDED_PLAN.md): its keys and
//! address, note encryption, scanning, and the shielded transactions it
//! builds (shielding, payments, returns to the hub).
//!
//! Keys, from the wallet's secret: `nk` (spends and nullifiers) and an
//! encryption key `e`, x-only `E`. An address is `owner ‖ E`. A new note's
//! value goes to its recipient as `R ‖ ChaCha20-Poly1305(k, value)`, `R`
//! an ephemeral x-only key and `k = SHA256("lichen/note-key" ‖ x(r·E) ‖ R
//! ‖ cm)`; its `rho` the recipient recomputes from the leaf, and checks
//! the commitment.

use std::path::PathBuf;

use anyhow::{bail, ensure, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use lichen_l2::State;
use lichen_ledger::k256::schnorr::SigningKey;
use lichen_ledger::shielded::{self, SNote, SpendInput, TOut, MAX_SPENDS};
use lichen_ledger::{fresh_key, fresh_rho, nullifier, sign, xonly, Hash, Leaf, Note, Proof, SOut, Shielded, Spend, Tx};
use sha2::{Digest, Sha256};

use crate::{Owned, Wallet};

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// A shielded address: who owns a note, and the key its value is
/// encrypted to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SAddress {
    pub owner: Hash,
    pub enc: Hash,
}

impl std::fmt::Display for SAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", hex::encode(self.owner), hex::encode(self.enc))
    }
}

impl std::str::FromStr for SAddress {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<SAddress> {
        let b = hex::decode(s).context("a shielded address is hex")?;
        ensure!(b.len() == 64, "a shielded address is 64 bytes, not {}", b.len());
        Ok(SAddress { owner: b[..32].try_into()?, enc: b[32..].try_into()? })
    }
}

/// How the wallet proves its spends.
#[derive(Clone, Debug, Default)]
pub enum SpendProver {
    /// The statement's input itself, for a sequencer that accepts native
    /// proofs (tests): no privacy.
    #[default]
    Native,
    /// A prover command: `<cmd> spend <input file> <receipt file>`.
    Command(PathBuf),
}

/// An unspent shielded note of ours.
#[derive(Clone, Copy, Debug)]
pub struct SOwned {
    pub value: u64,
    pub rho: Hash,
    pub index: u32,
}

/// The x of `k`·`P`, `P` the even-y point of x-only `p`.
fn ecdh(k: &SigningKey, p: &Hash) -> Result<Hash> {
    use lichen_ledger::k256::elliptic_curve::point::AffineCoordinates;
    let pt = lichen_ledger::k256::schnorr::VerifyingKey::from_bytes(p).context("not a key")?;
    let s = lichen_ledger::k256::ProjectivePoint::from(*pt.as_affine()) * **k.as_nonzero_scalar();
    Ok(s.to_affine().x().into())
}

fn note_key(shared: &Hash, r: &Hash, cm: &Hash) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&sha256(&[b"lichen/note-key", shared, r, cm]).into())
}

/// `value` encrypted to `to`, for the note `cm`.
pub fn encrypt(to: &SAddress, cm: &Hash, value: u64) -> Result<Vec<u8>> {
    let r = fresh_key();
    let rx = xonly(&r);
    let ct = note_key(&ecdh(&r, &to.enc)?, &rx, cm).encrypt(&[0u8; 12].into(), value.to_be_bytes().as_slice()).map_err(|_| anyhow::anyhow!("encrypting a note"))?;
    Ok([rx.as_slice(), &ct].concat())
}

/// The value in `ct`, if it is to the key `e` for the note `cm`.
pub fn decrypt(e: &SigningKey, cm: &Hash, ct: &[u8]) -> Option<u64> {
    let rx: Hash = ct.get(..32)?.try_into().ok()?;
    let pt = note_key(&ecdh(e, &rx).ok()?, &rx, cm).decrypt(&[0u8; 12].into(), &ct[32..]).ok()?;
    Some(u64::from_be_bytes(pt.try_into().ok()?))
}

impl Wallet {
    /// Our nullifier key.
    pub(crate) fn nk(&self) -> Hash {
        sha256(&[b"lichen/nk", &self.key.to_bytes()])
    }
    fn enc_key(&self) -> SigningKey {
        SigningKey::from_bytes(&sha256(&[b"lichen/enc-key", &self.key.to_bytes()])).expect("a scalar, all but certainly")
    }
    pub fn shielded_address(&self) -> SAddress {
        SAddress { owner: shielded::owner(&self.nk()), enc: xonly(&self.enc_key()) }
    }
    /// Our unspent shielded notes: each shielded leaf that decrypts to us
    /// and whose commitment checks, its nullifier unseen.
    pub fn shielded_notes(&self, state: &State) -> Vec<SOwned> {
        let (nk, e, me) = (self.nk(), self.enc_key(), self.shielded_address().owner);
        let spent: std::collections::HashSet<&Hash> = state.nullifiers.iter().collect();
        let mut out = vec![];
        for (index, leaf) in state.notes.iter().enumerate() {
            if let Leaf::Shielded { cm, ciphertext, nf0, i } = leaf {
                let Some(value) = decrypt(&e, cm, ciphertext) else { continue };
                let rho = shielded::rho(nf0, *i);
                if (SNote { value, owner: me, rho }).commitment() == *cm && !spent.contains(&shielded::nullifier(&nk, &rho)) {
                    out.push(SOwned { value, rho, index: index as u32 });
                }
            }
        }
        out
    }
    /// What we hold, transparent and shielded.
    pub fn balances(&self) -> Result<(u64, u64)> {
        let state = self.state()?;
        Ok((self.notes(&state).iter().map(|o| o.note.value).sum(), self.shielded_notes(&state).iter().map(|o| o.value).sum()))
    }

    /// A sealed root holding every leaf below `size`: the last, sealing
    /// a new height if it falls short. The state then.
    fn anchored(&self, size: u32) -> Result<State> {
        let start = std::time::Instant::now();
        loop {
            let state = self.state()?;
            if state.sealed.last().is_some_and(|s| s.size >= size) {
                return Ok(state);
            }
            let _ = self.sequencer.seal();
            ensure!(start.elapsed() < std::time::Duration::from_secs(60), "no sealed root holds the notes to spend");
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    /// Prove `input` with our prover.
    fn prove(&self, input: &SpendInput) -> Result<Proof> {
        match &self.spend_prover {
            SpendProver::Native => Ok(Proof::Native(input.to_bytes())),
            SpendProver::Command(cmd) => {
                // the input holds nk, the notes' spending authority: in a
                // directory of the owner's alone, removed however proving ends
                let dir = std::env::temp_dir().join(format!("lichen-spend-{}", hex::encode(fresh_rho())));
                let mut b = std::fs::DirBuilder::new();
                #[cfg(unix)]
                std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
                b.create(&dir)?;
                let r = (|| -> Result<Vec<u8>> {
                    let (inp, out) = (dir.join("input.bin"), dir.join("receipt.bin"));
                    lichen_ledger::files::write_private(&inp, &input.to_bytes())?;
                    let st = std::process::Command::new(cmd).arg("spend").arg(&inp).arg(&out).status().with_context(|| format!("running {}", cmd.display()))?;
                    ensure!(st.success(), "the prover failed ({st})");
                    std::fs::read(&out).context("the prover's receipt")
                })();
                let _ = std::fs::remove_dir_all(&dir);
                Ok(Proof::Risc0(r?))
            }
        }
    }

    /// Build, prove and submit a shielded transaction spending `spends`
    /// (ours, shielded) and `t_spends` (ours, transparent), paying
    /// `outputs` (shielded) and `t_outputs` (transparent). The new
    /// leaves' indices: the shielded outputs', then the transparent ones'.
    fn submit_shielded(&self, spends: &[SOwned], t_spends: &[Owned], outputs: &[(SAddress, u64)], t_outputs: &[Note]) -> Result<Vec<u32>> {
        let need = spends.iter().map(|s| s.index + 1).max().unwrap_or(0);
        let state = self.anchored(need)?;
        let sealed = state.sealed.last().context("no sealed root")?;
        let tree = state.tree();
        let nk = self.nk();
        let t_list: Vec<Spend> = t_spends.iter().map(|o| Spend { note: o.note, index: o.index }).collect();
        let input = SpendInput {
            anchor: sealed.tree,
            t_nfs: t_list.iter().map(|s| nullifier(&s.note)).collect(),
            t_total: t_list.iter().map(|s| s.note.value).sum(),
            spends: spends.iter().map(|s| shielded::Spend { value: s.value, rho: s.rho, nk, index: s.index, path: tree.path_at(s.index, sealed.size) }).collect(),
            outputs: outputs.iter().map(|(a, v)| (*v, a.owner)).collect(),
            t_outputs: t_outputs.iter().map(|n| TOut { owner: n.owner, value: n.value, memo: n.memo, rho: n.rho }).collect(),
        };
        let j = shielded::check(&input).map_err(|r| anyhow::anyhow!("the spend statement rejects this transaction: {r:?}"))?;
        let souts = outputs.iter().zip(&j.cms).map(|((a, v), cm)| Ok(SOut { cm: *cm, ciphertext: encrypt(a, cm, *v)? })).collect::<Result<Vec<_>>>()?;
        let mut tx = Shielded { anchor: input.anchor, t_spends: t_list, t_sigs: vec![], nfs: j.nfs.clone(), outputs: souts, t_outputs: t_outputs.to_vec(), proof: self.prove(&input)? };
        let d = tx.digest()?;
        tx.t_sigs = tx.t_spends.iter().map(|_| sign(&self.key, &d)).collect();
        self.sequencer.submit(&Tx::Shielded(tx))
    }

    /// Our shielded notes covering `amount`, largest first, at most
    /// `MAX_SPENDS`; their total.
    fn select_shielded(&self, state: &State, amount: u64) -> Result<(Vec<SOwned>, u64)> {
        let mut mine = self.shielded_notes(state);
        mine.sort_by_key(|o| std::cmp::Reverse(o.value));
        let (mut picked, mut total) = (vec![], 0u64);
        for o in mine.into_iter().take(MAX_SPENDS) {
            if total >= amount {
                break;
            }
            total += o.value;
            picked.push(o);
        }
        if total < amount {
            bail!("the shielded notes cover {total}, short of {amount} (at most {MAX_SPENDS} notes a transaction)");
        }
        Ok((picked, total))
    }

    /// Shield `amount` of our transparent notes: a shielded note of ours,
    /// the change transparent. The new leaves' indices.
    pub fn shield(&mut self, amount: u64) -> Result<Vec<u32>> {
        ensure!(amount > 0, "nothing to shield");
        let state = self.state()?;
        let mut mine = self.notes(&state);
        mine.sort_by_key(|o| std::cmp::Reverse(o.note.value));
        let (mut picked, mut total) = (vec![], 0u64);
        for o in mine.into_iter().take(MAX_SPENDS) {
            if total >= amount {
                break;
            }
            total += o.note.value;
            picked.push(o);
        }
        ensure!(total >= amount, "the transparent notes cover {total}, short of {amount}");
        let change: Vec<Note> = if total > amount { vec![lichen_ledger::note(self.address(), total - amount, 0)] } else { vec![] };
        self.submit_shielded(&[], &picked, &[(self.shielded_address(), amount)], &change)
    }

    /// Pay `amount` from our shielded notes to `to`, the change shielded
    /// to us. The new leaves' indices (the payment's first).
    pub fn send_shielded(&mut self, to: &SAddress, amount: u64) -> Result<Vec<u32>> {
        ensure!(amount > 0, "nothing to send");
        let (spends, total) = self.select_shielded(&self.state()?, amount)?;
        let mut outputs = vec![(*to, amount)];
        if total > amount {
            outputs.push((self.shielded_address(), total - amount));
        }
        self.submit_shielded(&spends, &[], &outputs, &[])
    }

    /// Return `b` to the hub with memo `c` from our shielded notes: the
    /// return a transparent note, as the withdrawal statement wants; the
    /// change shielded. The return's index.
    pub(crate) fn return_shielded(&mut self, b: u64, c: u32) -> Result<u32> {
        let (spends, total) = self.select_shielded(&self.state()?, b)?;
        let ret = Note { owner: self.sequencer.deployment.hub, value: b, memo: c, rho: fresh_rho() };
        let change = if total > b { vec![(self.shielded_address(), total - b)] } else { vec![] };
        let idx = self.submit_shielded(&spends, &[], &change, &[ret])?;
        Ok(*idx.last().context("the return's index")?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_note_decrypts_only_to_its_recipient_and_its_commitment() {
        let (e, other) = (fresh_key(), fresh_key());
        let to = SAddress { owner: [1; 32], enc: xonly(&e) };
        let cm = [7u8; 32];
        let ct = encrypt(&to, &cm, 12_345).unwrap();
        assert_eq!(ct.len(), 32 + 8 + 16);
        assert_eq!(decrypt(&e, &cm, &ct), Some(12_345));
        assert_eq!(decrypt(&other, &cm, &ct), None, "another key");
        assert_eq!(decrypt(&e, &[8u8; 32], &ct), None, "another note");
        let mut bad = ct.clone();
        bad[40] ^= 1;
        assert_eq!(decrypt(&e, &cm, &bad), None, "tampered");
        // an address in hex and back
        assert_eq!(to.to_string().parse::<SAddress>().unwrap(), to);
    }
}
