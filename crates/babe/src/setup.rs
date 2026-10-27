//! BABE's instances and their cut-and-choose (BABE §6.2, App. B).
//!
//! An instance is a function of its seed and its input secrets: `r` and
//! `msg` from the seed, the garbled circuit, the witness encryption of
//! `msg`, `H(msg)` for the hashlock. The hub commits to N instances by
//! hash; Alice keeps M, chosen at random; the hub opens the others (their
//! seeds and secrets), which she rebuilds and compares. All M kept are
//! false with probability at most `1 / C(N, M)`; she needs one true.
//!
//! The input secrets are not the circuit's labels: the circuit's input
//! labels are free-XOR's (`L¹ = L⁰ ⊕ Δ`), the secrets are shares
//! ([`crate::vsss`]), independent. A translation table maps one to the
//! other: `T_{j,β} = H(s_{j,β}) ⊕ L^β_j`, two labels an input bit, so a
//! secret revealed on chain gives its bit's label and no other.

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::garble::{garble, Garbled, Label};
use crate::we::{encrypt, Msg, Setup};

/// An input secret: a share's 32 bytes.
pub type Secret = [u8; 32];

pub type Hash = [u8; 32];

/// What Alice keeps of an instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub gc: Garbled,
    /// Each input bit's translation, for 0 and for 1.
    pub table: Vec<[Label; 2]>,
    pub ct: Setup,
    /// `SHA-256(msg)`: the hashlock `wrongly_challenged` opens.
    pub hmsg: Hash,
}

fn translate(s: &Secret, bit: usize, value: bool) -> Label {
    let mut h = blake3::Hasher::new();
    h.update(b"lichen/babe/input");
    h.update(s);
    h.update(&(bit as u32).to_le_bytes());
    h.update(&[value as u8]);
    u128::from_le_bytes(h.finalize().as_bytes()[..16].try_into().unwrap())
}

/// The instance of `seed` and `secrets` (one pair an input bit), for the
/// statement `public`; and its `msg`.
pub fn instance(seed: &[u8; 32], secrets: &[[Secret; 2]], vk: &VerifyingKey<Bn254>, public: &[Fr]) -> (Instance, Msg) {
    let rng = &mut ChaCha20Rng::from_seed(*seed);
    let r = Fr::rand(rng);
    let msg: Msg = rng.gen();
    let (gc, ek) = garble(r, rng);
    assert_eq!(secrets.len(), ek.0.len(), "a secret pair an input bit");
    let table = ek.0.iter().zip(secrets).enumerate().map(|(j, (l, s))| [l[0] ^ translate(&s[0], j, false), l[1] ^ translate(&s[1], j, true)]).collect();
    let ct = encrypt(vk, public, &msg, r);
    (Instance { gc, table, ct, hmsg: Sha256::digest(msg).into() }, msg)
}

impl Instance {
    /// The circuit's input labels for `bits`, from their secrets.
    pub fn labels(&self, bits: &[bool], secrets: &[Secret]) -> Vec<Label> {
        bits.iter().zip(secrets).zip(&self.table).enumerate().map(|(j, ((b, s), t))| t[*b as usize] ^ translate(s, j, *b)).collect()
    }

    /// Whether `msg` opens the hashlock: a decryption that succeeded.
    pub fn is_msg(&self, msg: &Msg) -> bool {
        <Hash>::from(Sha256::digest(msg)) == self.hmsg
    }

    /// The hub's commitment to it.
    pub fn commitment(&self) -> Hash {
        let mut h = blake3::Hasher::new();
        h.update(b"lichen/babe/instance");
        for l in self.gc.ands.iter().chain(self.table.iter().flatten()) {
            h.update(&l.to_le_bytes());
        }
        for f in self.gc.dre.iter().chain(self.gc.constant.iter().flatten()) {
            h.update(&f.into_bigint().to_bytes_le());
        }
        let mut ct = Vec::new();
        self.ct.r_delta.serialize_compressed(&mut ct).expect("serialize");
        h.update(&ct);
        h.update(&self.ct.masked);
        h.update(&self.hmsg);
        *h.finalize().as_bytes()
    }
}

/// Whether an opened instance (its seed and secrets) is the one committed.
pub fn check_opened(commitment: &Hash, seed: &[u8; 32], secrets: &[[Secret; 2]], vk: &VerifyingKey<Bn254>, public: &[Fr]) -> bool {
    instance(seed, secrets, vk, public).0.commitment() == *commitment
}

/// The M instances of N Alice keeps, chosen at random: indices, sorted.
pub fn choose<R: Rng>(n: usize, m: usize, rng: &mut R) -> Vec<usize> {
    let mut all: Vec<usize> = (0..n).collect();
    for i in 0..m {
        let j = rng.gen_range(i..n);
        all.swap(i, j);
    }
    let mut kept = all[..m].to_vec();
    kept.sort();
    kept
}
