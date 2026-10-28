//! The setup's cost at an operating point: `cargo run --release -p
//! lichen-babe --example setup_cost [N M]` (default 78 10, BABE's smallest
//! VSSS point). The hub deals the shares and builds N instances; Alice
//! checks the N − M opened ones' shares and rebuilds them; the M kept are
//! what she stores. Instances are built on all cores. On the toy
//! statement: the statement doesn't change the instance's size or time.

use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use lichen_babe::setup::{check_opened, instance, Secret, DIGITS, VALUES};
use lichen_babe::vsss::deal;

struct One;

impl ConstraintSynthesizer<Fr> for One {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let y = cs.new_input_variable(|| Ok(Fr::from(1u64)))?;
        cs.enforce_constraint(lc!() + y, lc!() + y, lc!() + y)?;
        Ok(())
    }
}

/// `f` on 0..n across the cores.
fn par<T: Send>(n: usize, f: impl Fn(usize) -> T + Sync) -> Vec<T> {
    let cores = std::thread::available_parallelism().map_or(1, |c| c.get());
    let mut out: Vec<Option<T>> = (0..n).map(|_| None).collect();
    std::thread::scope(|s| {
        for (c, chunk) in out.chunks_mut(n.div_ceil(cores)).enumerate() {
            let f = &f;
            s.spawn(move || {
                for (k, slot) in chunk.iter_mut().enumerate() {
                    *slot = Some(f(c * n.div_ceil(cores) + k));
                }
            });
        }
    });
    out.into_iter().map(|t| t.unwrap()).collect()
}

fn main() {
    let args: Vec<usize> = std::env::args().skip(1).map(|a| a.parse().expect("N M")).collect();
    let (n, m) = match args[..] {
        [n, m] => (n, m),
        _ => (78, 10),
    };
    let rng = &mut StdRng::seed_from_u64(5);
    let (_, vk) = Groth16::<Bn254>::circuit_specific_setup(One, rng).unwrap();
    let y = [Fr::from(1u64)];
    println!("(N, M) = ({n}, {m}), {} cores", std::thread::available_parallelism().map_or(1, |c| c.get()));

    let t = Instant::now();
    let (dealer, dealing) = deal(DIGITS, n - m, rng);
    println!("hub: dealt {} polynomials of degree {} in {:.1?}", VALUES * DIGITS, n - m, t.elapsed());
    let seeds: Vec<[u8; 32]> = (0..n as u64).map(|i| core::array::from_fn(|k| i.to_le_bytes().get(k).copied().unwrap_or(1))).collect();
    let shares: Vec<Vec<[Secret; VALUES]>> = (1..=n as u64).map(|i| dealer.shares(i)).collect();
    let t = Instant::now();
    let commitments = par(n, |i| instance(&seeds[i], &shares[i], &vk, &y).0.commitment());
    let hub = t.elapsed();
    println!("hub: {n} instances built and committed in {hub:.1?}");

    // Alice keeps the last M; the hub opens the first N − M
    let opened: Vec<(u64, Vec<[Secret; VALUES]>)> = (0..n - m).map(|i| (i as u64 + 1, shares[i].clone())).collect();
    let t = Instant::now();
    assert!(dealing.verify(&opened, rng));
    let vsss = t.elapsed();
    let t = Instant::now();
    let ok = par(n - m, |i| check_opened(&commitments[i], &seeds[i], &shares[i], &vk, &y));
    assert!(ok.iter().all(|b| *b));
    let alice = t.elapsed();
    println!("alice: {} opened shares checked in {vsss:.1?}, the instances rebuilt in {alice:.1?}", n - m);

    let one = instance(&seeds[n - 1], &shares[n - 1], &vk, &y).0;
    let size = one.gc.size() + std::mem::size_of_val(&one.table[..]) + 128 + 32;
    let commit_bytes = dealing.commitments.len() * VALUES * (n - m + 1) * 33;
    println!(
        "alice stores {m} instances: {:.0} MiB, and the commitments: {:.1} MiB",
        (m * size) as f64 / (1 << 20) as f64,
        commit_bytes as f64 / (1 << 20) as f64
    );
    println!("setup in all (one machine, both parties): {:.1?}", hub + vsss + alice);
}
