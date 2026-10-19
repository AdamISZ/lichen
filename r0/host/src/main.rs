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
//! - `withdraw <withdraw input> <chain receipt> <out>`: prove the
//!   withdrawal statement (`lichen_withdraw`) for a return: the input
//!   ln-gap's, as JSON (`lichen withdraw-input`, the tower's), the chain
//!   receipt the sequencer proved at its root's height as an assumption;
//!   writes the succinct receipt, which resolves it; `exec-withdraw`, as
//!   `withdraw`, runs the guest without proving;
//! - `wrap <receipt> <out>`: the Groth16 receipt of a succinct withdrawal
//!   receipt (x86 Linux with Docker: RISC Zero's gnark step);
//!   `bitvmx-input <Groth16 receipt> <out.hex>`: as the BitVMX verifier's
//!   input;
//! - `claim <withdraw input> <chain receipt> <out.hex>`: a claim, whole:
//!   `withdraw`, `wrap`, `bitvmx-input` (what the tower runs);
//! - `image-id [spend|chain|withdraw]`: a committed guest's image id;
//!   `check-id`: that each is its committed `.id`; `pack-id <bin>`: a
//!   packed binary's.
//!
//! The guests proved are the committed `r0/guests/spend.bin`, `chain.bin`
//! and `withdraw.bin`.

mod bitvmx;

use std::io::{Read, Write};

use anyhow::{bail, ensure, Context, Result};
use risc0_zkvm::{compute_image_id, default_executor, default_prover, Digest, ExecutorEnv, InnerReceipt, ProverOpts, Receipt};

const GUESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../guests");

/// A committed guest (`spend`, `chain`, `withdraw`).
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

/// ln-gap's withdrawal input (`lngap-r0-core`'s `WithdrawInput`), as a
/// wallet writes it (JSON).
#[derive(serde::Deserialize)]
struct LnGapInput {
    height: u64,
    nullifiers: [u8; 32],
    signature: Vec<u8>,
    note: LnGapNote,
    index: u32,
    path: Vec<[u8; 32]>,
    sequencer: [u8; 32],
    hub: [u8; 32],
}

#[derive(serde::Deserialize)]
struct LnGapNote {
    owner: [u8; 32],
    value: u64,
    memo: u32,
    rho: [u8; 32],
}

fn load(p: &str) -> Result<Receipt> {
    bincode::deserialize(&read(p)?).with_context(|| format!("a receipt, {p}"))
}

/// The withdrawal statement's input for ln-gap's (`json`) under the chain
/// receipt `chain`: its `recent` from the receipt's journal, which must
/// end at the input's root (checked natively, with the receipt). The
/// input's bytes, the statement's journal.
fn withdraw_input(json: &str, chain: &Receipt) -> Result<(Vec<u8>, [u8; lichen_withdraw::JOURNAL_LEN])> {
    let i: LnGapInput = serde_json::from_slice(&read(json)?).with_context(|| format!("{json}: a withdrawal input"))?;
    let id = image_id(&committed("chain")?)?;
    chain.verify(id).context("the chain receipt")?;
    let c = lichen_validity::ChainJournal::from_bytes(&chain.journal.bytes).map_err(|e| anyhow::anyhow!("not a chain journal: {e:?}"))?;
    let chain_id: [u8; 32] = id.as_bytes().try_into()?;
    ensure!(c.chain_id == chain_id, "the chain receipt names another chain guest");
    ensure!(c.height == i.height, "the chain receipt is of height {}, the withdrawal's root of {}", c.height, i.height);
    let n = i.note;
    let input = lichen_withdraw::WithdrawInput {
        height: i.height,
        nullifiers: i.nullifiers,
        signature: i.signature.as_slice().try_into().context("a signature of 64 bytes")?,
        note: lichen_validity::TNote { owner: n.owner, value: n.value, memo: n.memo, rho: n.rho },
        index: i.index,
        path: i.path,
        sequencer: i.sequencer,
        hub: i.hub,
        recent: c.recent,
    };
    let journal = lichen_withdraw::check(&input, &chain_id, &mut |j| j == chain.journal.bytes.as_slice()).map_err(|r| anyhow::anyhow!("the withdrawal statement rejects the input: {r:?}"))?;
    eprintln!("lichen-r0: the return of {} with memo {} at index {}, under the root of height {}", n.value, n.memo, input.index, input.height);
    Ok((input.to_bytes(), journal))
}

/// Prove the withdrawal statement (or, `execute_only`, run it): the
/// succinct receipt, checked.
fn prove_withdraw(json: &str, chain: Receipt, execute_only: bool) -> Result<Option<Receipt>> {
    let guest = committed("withdraw")?;
    let id = image_id(&guest)?;
    let (input, journal) = withdraw_input(json, &chain)?;
    let mut env = ExecutorEnv::builder();
    env.write(&(input.len() as u32))?.write_slice(&words(&input));
    env.add_assumption(chain);
    let env = env.build()?;
    if execute_only {
        let s = default_executor().execute(env, &guest)?;
        ensure!(s.journal.bytes == journal, "the execution's journal isn't the statement's");
        let user: u64 = s.segments.iter().map(|g| g.cycles as u64).sum();
        eprintln!("lichen-r0: executed the withdrawal ({} user cycles, {} segments)", user, s.segments.len());
        return Ok(None);
    }
    let t = std::time::Instant::now();
    let info = default_prover().prove_with_opts(env, &guest, &ProverOpts::succinct())?;
    eprintln!("lichen-r0: proved the withdrawal in {:.1}s ({} user cycles, {} segments)", t.elapsed().as_secs_f64(), info.stats.user_cycles, info.stats.segments);
    info.receipt.verify(id)?;
    ensure!(info.receipt.journal.bytes == journal, "the receipt's journal isn't the statement's");
    Ok(Some(info.receipt))
}

/// The Groth16 receipt of a succinct withdrawal receipt, checked.
fn wrap(r: &Receipt) -> Result<Receipt> {
    let id = image_id(&committed("withdraw")?)?;
    let t = std::time::Instant::now();
    let g = default_prover().compress(&ProverOpts::groth16(), r)?;
    eprintln!("lichen-r0: wrapped in Groth16 in {:.1}s", t.elapsed().as_secs_f64());
    g.verify(id)?;
    Ok(g)
}

/// The BitVMX verifier's input for a Groth16 withdrawal receipt.
fn bitvmx_input(r: &Receipt) -> Result<Vec<u8>> {
    let InnerReceipt::Groth16(g) = &r.inner else { bail!("not a Groth16 receipt") };
    let id = image_id(&committed("withdraw")?)?;
    r.verify(id)?;
    bitvmx::input(&id.as_bytes().try_into()?, &g.seal, &r.journal.bytes)
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
            let prev = prev.map(|p| load(p)).transpose()?;
            let spends = spends.iter().map(|p| load(p)).collect::<Result<Vec<_>>>()?;
            match prove_chain(&read(input)?, prev, spends, *cmd == "exec-chain")? {
                Some(r) => write(out, &bincode::serialize(&r)?),
                None => Ok(()),
            }
        }
        [cmd @ ("withdraw" | "exec-withdraw"), json, chain, out] => match prove_withdraw(json, load(chain)?, *cmd == "exec-withdraw")? {
            Some(r) => write(out, &bincode::serialize(&r)?),
            None => Ok(()),
        },
        ["wrap", receipt, out] => write(out, &bincode::serialize(&wrap(&load(receipt)?)?)?),
        ["bitvmx-input", receipt, out] => write(out, hex::encode(bitvmx_input(&load(receipt)?)?).as_bytes()),
        ["claim", json, chain, out] => {
            let r = prove_withdraw(json, load(chain)?, false)?.context("a receipt")?;
            let bytes = bitvmx_input(&wrap(&r)?)?;
            write(out, hex::encode(&bytes).as_bytes())?;
            eprintln!("lichen-r0: {out}: the claim's input for the BitVMX verifier, {} bytes", bytes.len());
            Ok(())
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
            for name in ["spend", "chain", "withdraw"] {
                // a guest not built yet has neither file
                if !std::path::Path::new(&format!("{GUESTS}/{name}.bin")).exists() && !std::path::Path::new(&format!("{GUESTS}/{name}.id")).exists() {
                    continue;
                }
                let id = image_id(&committed(name)?)?.to_string();
                let c = std::fs::read_to_string(format!("{GUESTS}/{name}.id"))?;
                ensure!(c.trim() == id, "{name}.id is {}, the committed {name}.bin's image id {id}", c.trim());
            }
            Ok(())
        }
        _ => bail!("usage: lichen-r0 spend <input> <receipt> | verify <receipt> <journal hex> | chain <block input> <out> [--prev <receipt>] [<spend receipt>...] | verify-chain <receipt> | withdraw|exec-withdraw <withdraw input> <chain receipt> <out> | wrap <receipt> <out> | bitvmx-input <receipt> <out.hex> | claim <withdraw input> <chain receipt> <out.hex> | pack <guest ELF> <out> | pack-id <bin> | image-id [spend|chain|withdraw] | check-id"),
    }
}
