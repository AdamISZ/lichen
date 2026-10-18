//! `lichen-r0`: proves the spend guest (docs/SHIELDED_PLAN.md).
//!
//! - `spend <input> <receipt>`: prove the spend statement's input (its
//!   bytes, `lichen_shielded::SpendInput::to_bytes`) and write the
//!   composite receipt (bincode); `-` for stdin or stdout, so that Docker
//!   needs no shared folders (r0/spend-prover.sh);
//! - `verify <receipt> <journal hex>`: check a receipt against the guest
//!   and a journal;
//! - `pack <guest ELF> <out>`: the guest's ELF with RISC Zero's kernel
//!   (the program binary the image id is of), for r0/build-guest.sh;
//! - `image-id`: the committed guest's image id; `check-id`: that it is
//!   the committed `spend.id`; `pack-id <bin>`: a packed binary's.
//!
//! The guest proved is the committed `r0/guests/spend.bin`.

use std::io::{Read, Write};

use anyhow::{bail, ensure, Context, Result};
use risc0_zkvm::{compute_image_id, default_prover, Digest, ExecutorEnv, ProverOpts, Receipt};

const SPEND: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../guests/spend.bin");

fn guest() -> Result<Vec<u8>> {
    std::fs::read(SPEND).with_context(|| format!("the committed guest, {SPEND}"))
}

fn image_id(guest: &[u8]) -> Result<Digest> {
    compute_image_id(guest).context("the guest's image id")
}

fn read(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut b = vec![];
        std::io::stdin().read_to_end(&mut b)?;
        return Ok(b);
    }
    std::fs::read(path).with_context(|| format!("reading {path}"))
}

fn write(path: &str, b: &[u8]) -> Result<()> {
    if path == "-" {
        return Ok(std::io::stdout().write_all(b)?);
    }
    std::fs::write(path, b).with_context(|| format!("writing {path}"))
}

/// Prove the spend statement for `input` (its bytes): the composite
/// receipt, checked.
fn prove(guest: &[u8], input: &[u8]) -> Result<Receipt> {
    let journal = lichen_shielded::check(&lichen_shielded::SpendInput::from_bytes(input).map_err(|r| anyhow::anyhow!("the input: {r:?}"))?).map_err(|r| anyhow::anyhow!("the statement rejects the input: {r:?}"))?;
    let mut padded = input.to_vec();
    padded.resize(input.len().div_ceil(4) * 4, 0);
    let words: Vec<u32> = padded.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    let env = ExecutorEnv::builder().write(&(input.len() as u32))?.write_slice(&words).build()?;
    let t = std::time::Instant::now();
    let info = default_prover().prove_with_opts(env, guest, &ProverOpts::default())?;
    eprintln!("lichen-r0: proved in {:.1}s ({} user cycles, {} segments)", t.elapsed().as_secs_f64(), info.stats.user_cycles, info.stats.segments);
    info.receipt.verify(image_id(guest)?)?;
    ensure!(info.receipt.journal.bytes == journal.to_bytes(), "the receipt's journal isn't the statement's");
    Ok(info.receipt)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["spend", input, receipt] => {
            let r = prove(&guest()?, &read(input)?)?;
            write(receipt, &bincode::serialize(&r)?)
        }
        ["verify", receipt, journal] => {
            let r: Receipt = bincode::deserialize(&read(receipt)?).context("a receipt")?;
            r.verify(image_id(&guest()?)?)?;
            ensure!(r.journal.bytes == hex::decode(journal)?, "another journal");
            eprintln!("lichen-r0: the receipt verifies");
            Ok(())
        }
        ["pack", elf, out] => {
            let bin = risc0_binfmt::ProgramBinary::new(&read(elf)?, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
            write(out, &bin)?;
            println!("{}", image_id(&bin)?);
            Ok(())
        }
        ["image-id"] => {
            println!("{}", image_id(&guest()?)?);
            Ok(())
        }
        ["pack-id", bin] => {
            println!("{}", image_id(&read(bin)?)?);
            Ok(())
        }
        ["check-id"] => {
            let id = image_id(&guest()?)?.to_string();
            let committed = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../guests/spend.id"))?;
            ensure!(committed.trim() == id, "spend.id is {}, the committed spend.bin's image id {id}", committed.trim());
            Ok(())
        }
        _ => bail!("usage: lichen-r0 spend <input> <receipt> | verify <receipt> <journal hex> | pack <guest ELF> <out> | pack-id <bin> | image-id | check-id"),
    }
}
