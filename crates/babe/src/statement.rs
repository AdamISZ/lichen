//! The statement BABE verifies, as both parties build it: RISC Zero's (the
//! BABE guest's Groth16 receipt, [`crate::risc0`]) or the mock (a Groth16
//! proof of a toy circuit, for fast tests). Either way its public input is
//! the contract's journal `c ‖ D ‖ H(pk_H)` (`lichen_withdraw::fixed`),
//! fixed at opening. And a proof's encoding, and π1 read back from the
//! bits `assert` signs.

use std::sync::OnceLock;

use ark_bn254::{Bn254, Fq, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use lichen_withdraw::fixed::{key_digest, DIGITS, JOURNAL_LEN, K_LEN};
use sha2::{Digest, Sha256};

use crate::field::BITS;
use crate::setup::Hash;

/// The BABE guest's image id, hex (the build committed in
/// `r0/guests/babe.id`; with the file's newline).
pub const IMAGE_ID: &str = include_str!("../../../r0/guests/babe.id");

/// Which statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// RISC Zero's receipt of the BABE guest.
    Risc0,
    /// A proof anyone can make: for tests of the protocol, not of the
    /// withdrawal.
    Mock,
}

/// The journal: `c` (little-endian), `D`, and the hub's key for `b`.
pub fn journal(c: u32, d: &Hash, hub_b: &[Hash; DIGITS]) -> [u8; JOURNAL_LEN] {
    let mut j = [0u8; JOURNAL_LEN];
    j[..4].copy_from_slice(&c.to_le_bytes());
    j[4..36].copy_from_slice(d);
    j[36..].copy_from_slice(&key_digest(hub_b));
    j
}

/// The mock's circuit: knowledge of `w` equal to the public `y`.
#[derive(Clone)]
struct Echo(Option<Fr>);

impl ConstraintSynthesizer<Fr> for Echo {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        use ark_relations::lc;
        let w = cs.new_witness_variable(|| self.0.ok_or(SynthesisError::AssignmentMissing))?;
        let y = cs.new_input_variable(|| self.0.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + w, lc!() + ark_relations::r1cs::Variable::One, lc!() + y)
    }
}

/// The mock's keys, from a fixed seed: the same for everyone.
fn mock_keys() -> &'static (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
    static KEYS: OnceLock<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> = OnceLock::new();
    KEYS.get_or_init(|| Groth16::<Bn254>::circuit_specific_setup(Echo(None), &mut StdRng::seed_from_u64(0xbabe)).expect("the mock's setup"))
}

/// The mock's public input for a journal.
fn mock_input(journal: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(&Sha256::digest(journal))
}

impl Kind {
    pub fn verifying_key(&self) -> VerifyingKey<Bn254> {
        match self {
            Kind::Risc0 => crate::risc0::verifying_key(),
            Kind::Mock => mock_keys().1.clone(),
        }
    }
    pub fn public_inputs(&self, journal: &[u8]) -> Vec<Fr> {
        match self {
            Kind::Risc0 => crate::risc0::public_inputs(&image_id(), journal).to_vec(),
            Kind::Mock => vec![mock_input(journal)],
        }
    }
    /// Whether `proof` is valid for the contract of `journal`.
    pub fn verify(&self, journal: &[u8], proof: &Proof<Bn254>) -> bool {
        Groth16::<Bn254>::verify(&self.verifying_key(), &self.public_inputs(journal), proof).unwrap_or(false)
    }
}

/// A counter's journal, `D ‖ E` (`lichen_withdraw::counter`).
pub type CounterJournal = [u8; 64];

/// On the mock statement, the hub's counter `K` to the claim of `journal`:
/// a seal anyone can make, so the mock trusts the hub to counter only
/// what its native check of the counter holds (and the regtest tests to
/// forge one when they mean to).
pub fn mock_counter(journal: &CounterJournal) -> [u8; K_LEN] {
    let h: [u8; 32] = Sha256::new().chain_update(b"lichen/mock-counter").chain_update(journal).finalize().into();
    core::array::from_fn(|i| h[i % 32])
}

/// The counter guest's image id, once it is built and committed
/// (`r0/guests/counter.id`); none before, and no counter verifies on the
/// real statement.
pub fn counter_image_id() -> Option<[u8; 32]> {
    None
}

impl Kind {
    /// Whether `k` is a counter for `journal`: a Groth16 proof of the
    /// counter guest with that journal, or on the mock its seal.
    pub fn verify_counter(&self, k: &[u8], journal: &CounterJournal) -> bool {
        match self {
            Kind::Risc0 => counter_image_id().is_some_and(|id| lichen_groth16::verify(&id, k, journal)),
            Kind::Mock => k == mock_counter(journal),
        }
    }
}

/// The BABE guest's image id.
pub fn image_id() -> [u8; 32] {
    let b = (0..32).map(|i| u8::from_str_radix(&IMAGE_ID.trim()[2 * i..2 * i + 2], 16).expect("hex")).collect::<Vec<_>>();
    b.try_into().expect("32 bytes")
}

/// A mock proof for `journal`.
pub fn mock_prove(journal: &[u8]) -> Proof<Bn254> {
    let rng = &mut StdRng::from_seed(Sha256::digest(journal).into());
    Groth16::<Bn254>::prove(&mock_keys().0, Echo(Some(mock_input(journal))), rng).expect("the mock's proof")
}

/// A proof's bytes: its three points, compressed (128 bytes).
/// A RISC Zero claim as `lichen-r0 bitvmx-input` writes it (the image id,
/// the points, the journal): its proof, once the image is the BABE guest's
/// and the journal `journal`.
pub fn risc0_claim(data: &[u8], journal: &[u8]) -> anyhow::Result<Proof<Bn254>> {
    let (id, points, j) = lngap_zk::groth16::split_input(data)?;
    let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
    anyhow::ensure!(id == IMAGE_ID.trim(), "a claim of image {id}, not the BABE guest's");
    anyhow::ensure!(j == journal, "the claim's journal is not the contract's");
    crate::risc0::proof(points)
}

pub fn proof_to_bytes(p: &Proof<Bn254>) -> Vec<u8> {
    let mut v = Vec::new();
    p.serialize_compressed(&mut v).expect("serialize");
    v
}

pub fn proof_from_bytes(b: &[u8]) -> Option<Proof<Bn254>> {
    Proof::deserialize_compressed(b).ok()
}

/// π2 and π3 as `assert` carries them (compressed; neither is signed).
pub fn pi23_to_bytes(p: &Proof<Bn254>) -> (Vec<u8>, Vec<u8>) {
    let (mut b, mut c) = (Vec::new(), Vec::new());
    p.b.serialize_compressed(&mut b).expect("serialize");
    p.c.serialize_compressed(&mut c).expect("serialize");
    (b, c)
}

/// π1 from the 508 bits `assert` signs (x then y, little-endian; the
/// point at infinity as (0, 0)), if they are a point of G1.
pub fn pi1_from_bits(bits: &[bool]) -> Option<G1Affine> {
    if bits.len() != 2 * BITS {
        return None;
    }
    let fq = |b: &[bool]| Fq::from_bigint(<Fq as PrimeField>::BigInt::from_bits_le(b));
    let (x, y) = (fq(&bits[..BITS])?, fq(&bits[BITS..])?);
    if x == Fq::from(0u64) && y == Fq::from(0u64) {
        return Some(G1Affine::zero());
    }
    let p = G1Affine::new_unchecked(x, y);
    p.is_on_curve().then_some(p)
}

/// The whole proof from what `assert` puts on chain: π1's bits, π2, π3.
pub fn proof_from_chain(bits: &[bool], pi2: &[u8], pi3: &[u8]) -> Option<Proof<Bn254>> {
    Some(Proof {
        a: pi1_from_bits(bits)?,
        b: CanonicalDeserialize::deserialize_compressed(pi2).ok()?,
        c: CanonicalDeserialize::deserialize_compressed(pi3).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadget::input;

    #[test]
    fn a_mock_proof_and_its_round_trips() {
        let j = journal(7, &[1; 32], &[[2; 32]; DIGITS]);
        let p = mock_prove(&j);
        assert!(Kind::Mock.verify(&j, &p));
        assert!(!Kind::Mock.verify(&journal(8, &[1; 32], &[[2; 32]; DIGITS]), &p), "another contract's");
        assert_eq!(proof_from_bytes(&proof_to_bytes(&p)), Some(p.clone()));
        assert_eq!(proof_to_bytes(&p).len(), 128);
        let (b, c) = pi23_to_bytes(&p);
        assert_eq!(proof_from_chain(&input(&p.a), &b, &c), Some(p));
        // bits that are no point
        let mut bits = input(&mock_prove(&j).a);
        bits[3] ^= true;
        assert_eq!(pi1_from_bits(&bits), None);
    }
}
