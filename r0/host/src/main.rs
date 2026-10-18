//! `lichen-r0`: proves lichen's guests (docs/SHIELDED_PLAN.md).
//!
//! - `spend <input> <receipt>`: prove the spend statement's input (its
//!   bytes, `lichen_shielded::SpendInput::to_bytes`) and write the
//!   composite receipt (bincode); `-` for stdin or stdout, so that Docker
//!   needs no shared folders (r0/spend-prover.sh);
//! - `verify <receipt> <journal hex>`: check a spend receipt against the
//!   guest and a journal;
//! - `chain <block input> <out> [--prev <chain receipt>] [<spend
//!   receipt>…]`: prove the chain statement for a block (its input's
//!   bytes, `lichen_validity::BlockInput::to_bytes`), the block's spend
//!   receipts and the previous height's chain receipt (none at genesis)
//!   as assumptions; writes the succinct receipt, which resolves them;
//! - `exec-chain`, as `chain`, runs the guest without proving: its cycles
//!   (and, with RISC0_PPROF_OUT, a profile);
//! - `verify-chain <receipt>`: check a chain receipt; print its journal;
//! - `pack <guest ELF> <out>`: a guest's ELF with RISC Zero's kernel (the
//!   program binary the image id is of), for r0/build-guest.sh;
//! - `image-id [spend|chain]`: a committed guest's image id; `check-id`:
//!   that each is its committed `.id`; `pack-id <bin>`: a packed
//!   binary's.
//!
//! The guests proved are the committed `r0/guests/spend.bin` and
//! `chain.bin`.

use std::io::{Read, Write};

use anyhow::{bail, ensure, Context, Result};
use risc0_zkvm::{compute_image_id, default_executor, default_prover, Digest, ExecutorEnv, ProverOpts, Receipt};

const GUESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../guests");

/// A committed guest (`spend`, `chain`).
fn committed(name: &str) -> Result<Vec<u8>> {
    let p = format!("{GUESTS}/{name}.bin");
    std::fs::read(&p).with_context(|| format!("the committed guest, {p}"))
}

fn guest() -> Result<Vec<u8>> {
    committed("spend")
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
    let env = ExecutorEnv::builder().write(&(input.len() as u32))?.write_slice(&words(input)).build()?;
    let t = std::time::Instant::now();
    let info = default_prover().prove_with_opts(env, guest, &ProverOpts::default())?;
    eprintln!("lichen-r0: proved in {:.1}s ({} user cycles, {} segments)", t.elapsed().as_secs_f64(), info.stats.user_cycles, info.stats.segments);
    info.receipt.verify(image_id(guest)?)?;
    ensure!(info.receipt.journal.bytes == journal.to_bytes(), "the receipt's journal isn't the statement's");
    Ok(info.receipt)
}

fn words(bytes: &[u8]) -> Vec<u32> {
    let mut padded = bytes.to_vec();
    padded.resize(bytes.len().div_ceil(4) * 4, 0);
    padded.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect()
}

/// The chain guest's input: its image id, then the block's, raw; the
/// receipts its `env::verify`s need as assumptions.
fn chain_env(chain_id: &[u8; 32], input: &[u8], assumptions: impl Iterator<Item = Receipt>) -> Result<ExecutorEnv<'static>> {
    let mut stream = chain_id.to_vec();
    stream.extend_from_slice(input);
    let mut env = ExecutorEnv::builder();
    env.write(&(stream.len() as u32))?.write_slice(&words(&stream));
    for r in assumptions {
        env.add_assumption(r);
    }
    env.build()
}

/// Prove the chain statement for a block: the succinct receipt, checked
/// (or, `execute_only`, run it and report its cycles).
fn prove_chain(input: &[u8], prev: Option<Receipt>, spends: Vec<Receipt>, execute_only: bool) -> Result<Option<Receipt>> {
    let chain_guest = committed("chain")?;
    let id = image_id(&chain_guest)?;
    let block = lichen_validity::BlockInput::from_bytes(input).map_err(|r| anyhow::anyhow!("the block input: {r:?}"))?;
    let chain_id: [u8; 32] = id.as_bytes().try_into()?;
    // natively first: a refusal here is cheaper than a failed proof
    let journal = lichen_validity::chain(&chain_id, &block, &mut |j| spends.iter().any(|r| r.journal.bytes == j), &mut |j| prev.as_ref().is_some_and(|r| r.journal.bytes == j))
        .map_err(|r| anyhow::anyhow!("the chain statement rejects the block: {r:?}"))?;
    let spend_id = image_id(&guest()?)?;
    for r in &spends {
        r.verify(spend_id).context("a spend receipt")?;
    }
    if let Some(p) = &prev {
        p.verify(id).context("the previous chain receipt")?;
    }
    let env = chain_env(&chain_id, input, spends.into_iter().chain(prev))?;
    if execute_only {
        let s = default_executor().execute(env, &chain_guest)?;
        ensure!(s.journal.bytes == journal.to_bytes(), "the execution's journal isn't the statement's");
        let user: u64 = s.segments.iter().map(|g| g.cycles as u64).sum();
        eprintln!("lichen-r0: executed height {} ({} user cycles, {} segments; RISC0_PPROF_OUT for a profile)", journal.height, user, s.segments.len());
        return Ok(None);
    }
    let t = std::time::Instant::now();
    let info = default_prover().prove_with_opts(env, &chain_guest, &ProverOpts::succinct())?;
    eprintln!("lichen-r0: proved height {} in {:.1}s ({} user cycles, {} segments)", journal.height, t.elapsed().as_secs_f64(), info.stats.user_cycles, info.stats.segments);
    info.receipt.verify(id)?;
    ensure!(info.receipt.journal.bytes == journal.to_bytes(), "the receipt's journal isn't the statement's");
    Ok(Some(info.receipt))
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
        [cmd @ ("chain" | "exec-chain"), input, out, rest @ ..] => {
            let (prev, spends) = match rest {
                ["--prev", p, spends @ ..] => (Some(p), spends),
                spends => (None, spends),
            };
            let load = |p: &str| -> Result<Receipt> { bincode::deserialize(&read(p)?).with_context(|| format!("a receipt, {p}")) };
            let prev = prev.map(|p| load(p)).transpose()?;
            let spends = spends.iter().map(|p| load(p)).collect::<Result<Vec<_>>>()?;
            match prove_chain(&read(input)?, prev, spends, *cmd == "exec-chain")? {
                Some(r) => write(out, &bincode::serialize(&r)?),
                None => Ok(()),
            }
        }
        ["verify-chain", receipt] => {
            let r: Receipt = bincode::deserialize(&read(receipt)?).context("a receipt")?;
            let id = image_id(&committed("chain")?)?;
            r.verify(id)?;
            let j = lichen_validity::ChainJournal::from_bytes(&r.journal.bytes).map_err(|e| anyhow::anyhow!("not a chain journal: {e:?}"))?;
            ensure!(j.chain_id == id.as_bytes(), "the journal names another chain guest");
            println!("height {} root {} recent {} hub {}", j.height, hex::encode(j.root), hex::encode(j.recent), hex::encode(j.hub));
            Ok(())
        }
        ["image-id"] => {
            println!("{}", image_id(&guest()?)?);
            Ok(())
        }
        ["image-id", name] => {
            println!("{}", image_id(&committed(name)?)?);
            Ok(())
        }
        ["pack-id", bin] => {
            println!("{}", image_id(&read(bin)?)?);
            Ok(())
        }
        ["check-id"] => {
            for name in ["spend", "chain"] {
                let id = image_id(&committed(name)?)?.to_string();
                let c = std::fs::read_to_string(format!("{GUESTS}/{name}.id"))?;
                ensure!(c.trim() == id, "{name}.id is {}, the committed {name}.bin's image id {id}", c.trim());
            }
            Ok(())
        }
        _ => bail!("usage: lichen-r0 spend <input> <receipt> | verify <receipt> <journal hex> | chain <block input> <out> [--prev <receipt>] [<spend receipt>...] | verify-chain <receipt> | pack <guest ELF> <out> | pack-id <bin> | image-id [spend|chain] | check-id"),
    }
}
