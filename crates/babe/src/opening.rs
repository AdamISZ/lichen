//! The cut-and-choose with the roles swapped ([`crate::graph`]), both sides,
//! for a statement fixed at opening: its [`Kind`] and the contract's
//! journal. Alice garbles N instances ([`Garbler`]), all from one seed so
//! that nothing of them need be kept, and commits to them; the hub keeps M
//! ([`choose`]), which she uploads, and checks the others she opens
//! ([`check`]). In a dispute she reveals π1's secrets ([`Garbler::reveal`]),
//! and the hub answers with a kept instance's `msg` ([`msg`]).
//!
//! The parameters (N, M, the soundness they give), the transport and
//! what each side stores are the caller's.

use anyhow::{ensure, Result};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, VerifyingKey};
use ark_std::rand::{CryptoRng, RngCore};
use lichen_btc::keys::Seed;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::garble::evaluate;
use crate::setup::{check_opened, instance, par, Hash, Instance, Secret, DIGITS, VALUES};
use crate::statement::Kind;
use crate::vsss::{deal, interpolate, Dealer, Dealing};
use crate::we::{decrypt, Msg};

/// An instance opened: its number (from 1), its seed and its shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub i: u32,
    pub seed: [u8; 32],
    pub shares: Vec<[Secret; VALUES]>,
}

/// Alice's side: N instances for the statement, the input secrets dealt
/// with degree `N − M` (M of them kept), from `seed`.
pub struct Garbler {
    seed: Seed,
    n: u32,
    m: u32,
    dealer: Dealer,
    dealing: Dealing,
    vk: VerifyingKey<Bn254>,
    public: Vec<Fr>,
}

impl Garbler {
    pub fn new(seed: &Seed, n: u32, m: u32, kind: &Kind, journal: &[u8]) -> Garbler {
        assert!(0 < m && m < n, "keeping {m} of {n}");
        let (dealer, dealing) = deal(DIGITS, (n - m) as usize, &mut ChaCha20Rng::from_seed(seed.derive_bytes("dealing")));
        Garbler { seed: seed.clone(), n, m, dealer, dealing, vk: kind.verifying_key(), public: kind.public_inputs(journal) }
    }

    /// The dealing's commitments, which she publishes with her own.
    pub fn dealing(&self) -> &Dealing {
        &self.dealing
    }

    fn seed_of(&self, i: u32) -> [u8; 32] {
        self.seed.derive_bytes(&format!("instance/{i}"))
    }

    /// Instance `i` (from 1), built again.
    pub fn instance(&self, i: u32) -> Instance {
        instance(&self.seed_of(i), &self.dealer.shares(u64::from(i)), &self.vk, &self.public).0
    }

    /// The N instances' commitments, built across the machine's cores;
    /// `built` after each.
    pub fn commitments(&self, built: impl Fn() + Sync) -> Vec<Hash> {
        par(self.n as usize, |k| {
            let c = self.instance(k as u32 + 1).commitment();
            built();
            c
        })
    }

    /// The instances not `kept` opened, once `kept` is checked a choice of
    /// M of the N: distinct, increasing, each in `1..=N`.
    pub fn open(&self, kept: &[u32]) -> Result<Vec<Opened>> {
        ensure!(kept.len() == self.m as usize && kept.windows(2).all(|w| w[0] < w[1]) && kept.iter().all(|i| (1..=self.n).contains(i)), "the hub keeps {kept:?}, not {} distinct of {}", self.m, self.n);
        Ok((1..=self.n).filter(|i| !kept.contains(i)).map(|i| Opened { i, seed: self.seed_of(i), shares: self.dealer.shares(u64::from(i)) }).collect())
    }

    /// The secrets of π1's `digits`, as her challenge reveals them.
    pub fn reveal(&self, digits: &[u8]) -> Vec<Secret> {
        digits.iter().enumerate().map(|(j, v)| self.dealer.reveal(j, *v)).collect()
    }
}

/// The soundness of keeping `m` of `n`, in bits, rounded down: a garbler
/// whose kept instances are all false escapes with odds of `1 / C(n, m)`.
pub fn soundness(n: u32, m: u32) -> u32 {
    let ln: f64 = (0..m).map(|k| ((n - k) as f64 / (m - k) as f64).log2()).sum();
    ln.floor() as u32
}

/// The M instances of N the hub keeps, chosen at random: numbers (from
/// 1), increasing.
pub fn choose<R: RngCore>(n: u32, m: u32, rng: &mut R) -> Vec<u32> {
    crate::setup::choose(n as usize, m as usize, rng).into_iter().map(|k| k as u32 + 1).collect()
}

/// The hub's check of her opening: `opened` exactly the instances not
/// `kept`, in order; their shares on `dealing`'s polynomials; each rebuilt
/// to its commitment (`commitments`, instance 1 first) for the statement.
pub fn check<R: RngCore + CryptoRng>(commitments: &[Hash], kept: &[u32], dealing: &Dealing, opened: &[Opened], kind: &Kind, journal: &[u8], rng: &mut R) -> Result<()> {
    let n = commitments.len() as u32;
    let want: Vec<u32> = (1..=n).filter(|i| !kept.contains(i)).collect();
    ensure!(opened.iter().map(|o| o.i).eq(want.iter().copied()), "other instances opened than those not kept");
    let shares: Vec<(u64, Vec<[Secret; VALUES]>)> = opened.iter().map(|o| (u64::from(o.i), o.shares.clone())).collect();
    ensure!(dealing.verify(&shares, rng), "an opened instance's shares are off the dealing's polynomials");
    let (vk, public) = (kind.verifying_key(), kind.public_inputs(journal));
    let ok = par(opened.len(), |k| check_opened(&commitments[opened[k].i as usize - 1], &opened[k].seed, &opened[k].shares, &vk, &public));
    if let Some(k) = ok.iter().position(|o| !o) {
        anyhow::bail!("opened instance {} is not the one committed", opened[k].i);
    }
    Ok(())
}

/// The hub's answer to her challenge from kept instance `i`: its secrets
/// for π1's `bits` from the `revealed` ones and the `opened` shares, its
/// circuit evaluated, and `msg` decrypted under `proof`, if it opens the
/// hashlock.
pub fn msg(inst: &Instance, i: u32, opened: &[Opened], bits: &[bool], revealed: &[Secret], proof: &Proof<Bn254>) -> Option<Msg> {
    if !inst.has_shape() {
        return None;
    }
    let digits = crate::setup::digits(bits);
    let of_digits: Vec<(u64, Vec<Secret>)> = opened.iter().map(|o| (u64::from(o.i), o.shares.iter().zip(&digits).map(|(s, v)| s[*v as usize]).collect())).collect();
    let secrets = interpolate(u64::from(i), &of_digits, revealed)?;
    let r_pi1 = evaluate(&inst.gc, bits, &inst.labels(bits, &secrets));
    let msg = decrypt(&inst.ct, &r_pi1, proof);
    inst.is_msg(&msg).then_some(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadget::input;
    use crate::statement::mock_prove;
    use ark_std::rand::rngs::StdRng;

    #[test]
    fn soundness_is_log2_of_the_binomial() {
        assert_eq!((soundness(4, 2), soundness(6, 3), soundness(78, 10)), (2, 4, 40));
    }

    /// Her side and the hub's, on the mock statement: a valid proof of
    /// the contract's journal opens the kept instance; one of another
    /// journal doesn't; a lie in an opened instance is caught.
    #[test]
    fn her_instances_open_on_a_valid_proof_only() {
        let rng = &mut StdRng::seed_from_u64(5);
        let (kind, journal) = (Kind::Mock, [7u8; 68]);
        let (n, m) = (3, 1);
        let seed = Seed::from_label("alice/hp");
        let g = Garbler::new(&seed, n, m, &kind, &journal);
        let commitments = g.commitments(|| {});
        assert_eq!(commitments.len(), n as usize);
        let kept = choose(n, m, rng);
        // the hub's choice checked
        assert!(g.open(&[1, 2]).is_err() && g.open(&[0]).is_err() && g.open(&[4]).is_err() && g.open(&[]).is_err());
        let opened = g.open(&kept).unwrap();
        assert_eq!(opened.iter().map(|o| o.i).collect::<Vec<_>>(), (1..=n).filter(|i| !kept.contains(i)).collect::<Vec<_>>());
        check(&commitments, &kept, g.dealing(), &opened, &kind, &journal, rng).unwrap();
        // what the hub keeps, as committed, and the same again from the seed
        let i = kept[0];
        let inst = g.instance(i);
        assert_eq!(inst.commitment(), commitments[i as usize - 1]);
        assert_eq!(Garbler::new(&seed, n, m, &kind, &journal).instance(i), inst);
        // its labels split otherwise between the circuit and the table
        // commit otherwise
        let mut resplit = inst.clone();
        let moved: Vec<_> = resplit.gc.ands.drain(resplit.gc.ands.len() - 8..).collect();
        resplit.table.insert(0, core::array::from_fn(|v| [moved[2 * v], moved[2 * v + 1]]));
        assert_ne!(resplit.commitment(), commitments[i as usize - 1]);
        // an opening of other instances, other shares, another statement
        assert!(check(&commitments, &kept, g.dealing(), &opened[1..], &kind, &journal, rng).is_err());
        let mut off = opened.clone();
        off[0].shares[0][0][0] ^= 1;
        assert!(check(&commitments, &kept, g.dealing(), &off, &kind, &journal, rng).is_err());
        assert!(check(&commitments, &kept, g.dealing(), &opened, &kind, &[8u8; 68], rng).is_err());
        // the dispute: a proof of the journal, her secrets of its π1
        let opens = |proof: &Proof<Bn254>| {
            let bits = input(&proof.a);
            msg(&inst, i, &opened, &bits, &g.reveal(&crate::setup::digits(&bits)), proof)
        };
        assert!(opens(&mock_prove(&journal)).is_some());
        assert!(opens(&mock_prove(&[8u8; 68])).is_none(), "another contract's proof");
    }
}
