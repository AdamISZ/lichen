//! The cut-and-choose with the roles swapped ([`crate::graph`]), both sides,
//! for a statement fixed at opening: its [`Kind`] and the contract's
//! journal. Alice garbles N instances ([`Garbler`]), all from one seed
//! bound to the journal, so that nothing of them need be kept, and commits
//! to them; the hub keeps M ([`choose`]), which she uploads, and checks
//! the others, which she opens ([`Garbler::open`], [`check`]). In a
//! dispute she reveals π1's secrets ([`Garbler::reveal`]), and the hub
//! answers with a kept instance's `msg` ([`answer`]), trying every kept
//! instance until one opens.
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
use sha2::{Digest, Sha256};

use crate::setup::{check_opened, instance, par, Hash, Instance, Secret, DIGITS, VALUES};
use crate::statement::Kind;
use crate::vsss::{deal, Dealer, Dealing};
use crate::we::Msg;

/// An instance opened: its number (from 1), its seed and its shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub i: u32,
    pub seed: [u8; 32],
    pub shares: Vec<[Secret; VALUES]>,
}

/// Alice's side: N instances for the statement, the input secrets dealt
/// with degree `N − M` (M of them kept).
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
    /// Her garbler for the contract of `journal`, from `seed`. The dealing
    /// and every instance derive from `seed` and `journal` together, so a
    /// seed used again for another contract deals other secrets: a secret
    /// revealed in one contract's dispute opens no other's instances.
    pub fn new(seed: &Seed, n: u32, m: u32, kind: &Kind, journal: &[u8]) -> Garbler {
        assert!(0 < m && m < n, "keeping {m} of {n}");
        let mut h = Sha256::new();
        h.update(b"lichen/babe/garbler");
        h.update(seed.derive_bytes("garbler"));
        h.update((journal.len() as u64).to_le_bytes());
        h.update(journal);
        let seed = Seed::new(h.finalize().into());
        let (dealer, dealing) = deal(DIGITS, (n - m) as usize, &mut ChaCha20Rng::from_seed(seed.derive_bytes("dealing")));
        Garbler { seed, n, m, dealer, dealing, vk: kind.verifying_key(), public: kind.public_inputs(journal) }
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

    /// The instances the hub doesn't keep, opened, once `kept` is checked a
    /// choice of M of the N: distinct, increasing, each in `1..=N`.
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

/// The hub's answer to her challenge on π1's `bits`, from its kept
/// instances (`(i, bytes)`, in order), the `opened` ones and the secrets
/// she `revealed`: the first `(k, msg)`, `k` its position among them,
/// whose `msg` opens its hashlock. Any failure of a kept instance counts
/// it false, `failed` hears why, and the next is tried
/// ([`crate::setup::answer`]); None only when all have failed.
pub fn answer(kept: impl IntoIterator<Item = (u32, Result<Vec<u8>>)>, opened: &[Opened], bits: &[bool], revealed: &[Secret], proof: &Proof<Bn254>, failed: impl FnMut(u64, &anyhow::Error)) -> Option<(usize, Msg)> {
    let digits = crate::setup::digits(bits);
    let of_digits: Vec<(u64, Vec<Secret>)> = opened.iter().map(|o| (u64::from(o.i), o.shares.iter().zip(&digits).map(|(s, v)| s[*v as usize]).collect())).collect();
    crate::setup::answer(kept.into_iter().map(|(i, b)| (u64::from(i), b)), &of_digits, revealed, bits, proof, failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadget::input;
    use crate::reveal::{check_presigs, complete, extract, points, reveal_args, AdaptorKeys, LamportKey};
    use crate::statement::mock_prove;
    use ark_std::rand::rngs::StdRng;
    use lichen_btc::secp256k1::Message;

    #[test]
    fn soundness_is_log2_of_the_binomial() {
        assert_eq!((soundness(4, 2), soundness(6, 3), soundness(78, 10)), (2, 4, 40));
    }

    /// The whole path on the mock statement: she garbles, the hub keeps
    /// two and checks the others, pre-signs `challenge_assert` under her
    /// dealing's points; in the dispute it asserts π1, she completes its
    /// pre-signatures for π1's digits, and the hub extracts the secrets
    /// and answers from a kept instance, its first kept one malformed.
    /// A lie in an opened instance, another statement's proof and another
    /// contract's dealing are caught.
    #[test]
    fn the_cut_and_choose_from_garbling_to_the_answer() {
        let rng = &mut StdRng::seed_from_u64(5);
        let (kind, journal) = (Kind::Mock, [7u8; 68]);
        let (n, m) = (4, 2);
        let seed = Seed::from_label("alice/hp");
        // her side: N instances and the dealing
        let g = Garbler::new(&seed, n, m, &kind, &journal);
        let commitments = g.commitments(|| {});
        assert_eq!(commitments.len(), n as usize);
        // the hub keeps M; her opening of the others, checked
        let kept = choose(n, m, rng);
        assert!(g.open(&[1]).is_err() && g.open(&[2, 1]).is_err() && g.open(&[0, 1]).is_err() && g.open(&[1, 5]).is_err());
        let opened = g.open(&kept).unwrap();
        assert_eq!(opened.iter().map(|o| o.i).collect::<Vec<_>>(), (1..=n).filter(|i| !kept.contains(i)).collect::<Vec<_>>());
        check(&commitments, &kept, g.dealing(), &opened, &kind, &journal, rng).unwrap();
        assert!(check(&commitments, &kept, g.dealing(), &opened[1..], &kind, &journal, rng).is_err());
        let mut off = opened.clone();
        off[0].shares[0][0][0] ^= 1;
        assert!(check(&commitments, &kept, g.dealing(), &off, &kind, &journal, rng).is_err());
        assert!(check(&commitments, &kept, g.dealing(), &opened, &kind, &[8u8; 68], rng).is_err());
        // what she uploads, as committed, and the same again from the seed
        for i in &kept {
            assert_eq!(g.instance(*i).commitment(), commitments[*i as usize - 1]);
        }
        assert_eq!(Garbler::new(&seed, n, m, &kind, &journal).dealing(), g.dealing());
        // another contract's journal, another dealing and other instances
        let other = Garbler::new(&seed, n, m, &kind, &[8u8; 68]);
        assert_ne!(other.dealing(), g.dealing());
        assert_ne!(other.open(&kept).unwrap()[0].seed, opened[0].seed);

        // the hub pre-signs challenge_assert under her dealing's points
        let hub = Seed::from_label("hub/hp");
        let (lamport, adaptor) = (LamportKey::new(&hub, DIGITS), AdaptorKeys::new(&hub, DIGITS));
        let sighash = Message::from_digest([3; 32]);
        let presigs = adaptor.presign(&sighash, &points(g.dealing()));
        assert!(check_presigs(&adaptor.public(), &sighash, &points(g.dealing()), &presigs));
        assert!(!check_presigs(&adaptor.public(), &sighash, &points(other.dealing()), &presigs), "under another dealing's points");

        // the dispute: π1 asserted, her challenge completes the hub's
        // pre-signatures for its digits, the hub extracts the secrets
        let proof = mock_prove(&journal);
        let bits = input(&proof.a);
        let digits = crate::setup::digits(&bits);
        let sigs = complete(&presigs, &digits, &g.reveal(&digits));
        let (posted, revealed) = extract(&lamport.public(), &presigs, &reveal_args(&lamport.sign(&digits), &sigs)).unwrap();
        assert_eq!(posted, digits);
        // its answer: the first kept instance malformed, the second opens
        let mut broken = g.instance(kept[0]).to_bytes();
        broken.truncate(broken.len() / 2);
        let mut failed = vec![];
        let tries = vec![(kept[0], Ok(broken)), (kept[1], Ok(g.instance(kept[1]).to_bytes()))];
        let (k, msg) = answer(tries, &opened, &bits, &revealed, &proof, |i, _| failed.push(i)).unwrap();
        assert_eq!((k, failed), (1, vec![u64::from(kept[0])]));
        assert!(g.instance(kept[1]).is_msg(&msg));
        // another contract's proof opens none
        let wrong = mock_prove(&[8u8; 68]);
        let tries = kept.iter().map(|i| (*i, Ok(g.instance(*i).to_bytes())));
        assert!(answer(tries, &opened, &input(&wrong.a), &revealed, &wrong, |_, _| ()).is_none());
    }
}
