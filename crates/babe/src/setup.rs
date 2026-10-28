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
//! ([`crate::vsss`]), independent. And they are per digit, not per bit:
//! π1 is signed and revealed two bits a step (papers/lichen-babe v0.1.5
//! §8.5, as tapscript's stack needs). A translation table maps one to the
//! other: for digit `d` of value `v`, `T_{d,v,k} = H(s_{d,v}, k) ⊕
//! L_{2d+k}^{v_k}`, the labels of its two bits, so a secret revealed on
//! chain gives its digit's labels and no others.

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

/// The values of an input digit: two of the circuit's input bits, `2d` and
/// `2d + 1`, of value `b_{2d} + 2·b_{2d+1}`.
pub const VALUES: usize = 4;

/// π1's digits: its 508 bits, two a digit.
pub const DIGITS: usize = crate::field::BITS;

/// The circuit's input bits as digits.
pub fn digits(bits: &[bool]) -> Vec<u8> {
    bits.chunks(2).map(|c| c[0] as u8 | (c[1] as u8) << 1).collect()
}

pub type Hash = [u8; 32];

/// What Alice keeps of an instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub gc: Garbled,
    /// Each input digit's translation, for each value: its two bits' labels.
    pub table: Vec<[[Label; 2]; VALUES]>,
    pub ct: Setup,
    /// `SHA-256(msg)`: the hashlock `wrongly_challenged` opens.
    pub hmsg: Hash,
}

/// The mask on bit `k` of digit `d`'s label, for the secret of value `v`.
fn translate(s: &Secret, d: usize, v: usize, k: usize) -> Label {
    let mut h = blake3::Hasher::new();
    h.update(b"lichen/babe/input");
    h.update(s);
    h.update(&(d as u32).to_le_bytes());
    h.update(&[v as u8, k as u8]);
    u128::from_le_bytes(h.finalize().as_bytes()[..16].try_into().unwrap())
}

/// The instance of `seed` and `secrets` (one an input digit and value),
/// for the statement `public`; and its `msg`.
pub fn instance(seed: &[u8; 32], secrets: &[[Secret; VALUES]], vk: &VerifyingKey<Bn254>, public: &[Fr]) -> (Instance, Msg) {
    let rng = &mut ChaCha20Rng::from_seed(*seed);
    let r = Fr::rand(rng);
    let msg: Msg = rng.gen();
    let (gc, ek) = garble(r, rng);
    assert_eq!(2 * secrets.len(), ek.0.len(), "a secret an input digit and value");
    let table = secrets
        .iter()
        .enumerate()
        .map(|(d, s)| core::array::from_fn(|v| core::array::from_fn(|k| ek.0[2 * d + k][(v >> k) & 1] ^ translate(&s[v], d, v, k))))
        .collect();
    let ct = encrypt(vk, public, &msg, r);
    (Instance { gc, table, ct, hmsg: Sha256::digest(msg).into() }, msg)
}

impl Instance {
    /// The circuit's input labels for `bits`, from their digits' secrets.
    pub fn labels(&self, bits: &[bool], secrets: &[Secret]) -> Vec<Label> {
        let digits = digits(bits);
        digits
            .iter()
            .zip(secrets)
            .zip(&self.table)
            .enumerate()
            .flat_map(|(d, ((v, s), t))| (0..2).map(move |k| t[*v as usize][k] ^ translate(s, d, *v as usize, k)))
            .collect()
    }

    /// Whether `msg` opens the hashlock: a decryption that succeeded.
    pub fn is_msg(&self, msg: &Msg) -> bool {
        <Hash>::from(Sha256::digest(msg)) == self.hmsg
    }

    /// The hub's commitment to it.
    pub fn commitment(&self) -> Hash {
        let mut h = blake3::Hasher::new();
        h.update(b"lichen/babe/instance");
        for l in self.gc.ands.iter().chain(self.table.iter().flatten().flatten()) {
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
pub fn check_opened(commitment: &Hash, seed: &[u8; 32], secrets: &[[Secret; VALUES]], vk: &VerifyingKey<Bn254>, public: &[Fr]) -> bool {
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
