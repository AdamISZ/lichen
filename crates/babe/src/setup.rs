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

use ark_bn254::{Bn254, Fq, Fr, G2Affine};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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

impl Instance {
    /// Its bytes, as the hub sends it and Alice keeps it: the garbled
    /// circuit, the table, the ciphertext, the hashlock.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.gc.size() + 64 * self.table.len() + 128);
        let put = |n: usize, v: &mut Vec<u8>| v.extend((n as u64).to_le_bytes());
        put(self.gc.ands.len(), &mut v);
        for l in &self.gc.ands {
            v.extend(l.to_le_bytes());
        }
        let flat: Vec<Fq> = self.gc.dre.iter().copied().chain(self.gc.constant.iter().flatten().copied()).collect();
        put(self.gc.dre.len(), &mut v);
        put(self.gc.constant.len(), &mut v);
        flat.serialize_compressed(&mut v).expect("serialize");
        put(self.table.len(), &mut v);
        for l in self.table.iter().flatten().flatten() {
            v.extend(l.to_le_bytes());
        }
        self.ct.r_delta.serialize_compressed(&mut v).expect("serialize");
        v.extend(self.ct.masked);
        v.extend(self.hmsg);
        v
    }

    /// The instance of `b` ([`Instance::to_bytes`]), if it is one: every
    /// length checked against what is left before anything is allocated.
    pub fn from_bytes(b: &[u8]) -> Option<Instance> {
        struct Reader<'a>(&'a [u8]);
        impl<'a> Reader<'a> {
            fn take(&mut self, n: usize) -> Option<&'a [u8]> {
                let (h, t) = (self.0.get(..n)?, self.0.get(n..)?);
                self.0 = t;
                Some(h)
            }
            /// A count of items of `size` bytes, that many bytes left.
            fn count(&mut self, size: usize) -> Option<usize> {
                let n = usize::try_from(u64::from_le_bytes(self.take(8)?.try_into().ok()?)).ok()?;
                (n.checked_mul(size)? <= self.0.len()).then_some(n)
            }
            fn label(&mut self) -> Option<Label> {
                Some(u128::from_le_bytes(self.take(16)?.try_into().ok()?))
            }
        }
        let mut r = Reader(b);
        let ands_n = r.count(16)?;
        let ands = (0..ands_n).map(|_| r.label()).collect::<Option<Vec<Label>>>()?;
        let dre_n = r.count(32)?;
        let const_n = r.count(96)?;
        // the field elements: a length, then each compressed (32 bytes)
        let flat_len = 8 + 32 * (dre_n.checked_add(const_n.checked_mul(3)?)?);
        let flat = Vec::<Fq>::deserialize_compressed(r.take(flat_len)?).ok()?;
        (flat.len() == dre_n + 3 * const_n).then_some(())?;
        let (dre, rest) = (flat[..dre_n].to_vec(), &flat[dre_n..]);
        let constant = rest.chunks(3).map(|c| [c[0], c[1], c[2]]).collect();
        let table_n = r.count(32 * VALUES)?;
        let mut table = Vec::with_capacity(table_n);
        for _ in 0..table_n {
            let mut e = [[0; 2]; VALUES];
            for l in e.iter_mut().flatten() {
                *l = r.label()?;
            }
            table.push(e);
        }
        let r_delta = G2Affine::deserialize_compressed(r.take(64)?).ok()?;
        let masked = r.take(32)?.try_into().ok()?;
        let hmsg = r.take(32)?.try_into().ok()?;
        r.0.is_empty().then_some(Instance { gc: Garbled { ands, dre, constant }, table, ct: Setup { r_delta, masked }, hmsg })
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
