//! For trials: find a read lie on a claim that an honest hub's search
//! lands on, and print it as the wallet's `--lie` JSON.
//!
//!     cargo run --release -p lichen-hub --example read_lie -- <input.hex> <work dir> [min hops] [tail steps]
//!
//! It runs the claim's execution once, looks at its last `tail steps`
//! (default 20,000) for a step reading an address written earlier in the
//! execution, flips the value read, and plays the search off chain (both
//! sides' emulators) to check that the dispute lands on that very step,
//! and not on the halt. Reads whose last write is furthest back are tried
//! first: their jump-list paths are the longest. As tail.rs's `a_read_lie`,
//! for a trace too long to collect whole.

use anyhow::{bail, Context, Result};
use emulator::decision::challenge::ForceCondition;
use emulator::executor::utils::{FailConfiguration, FailReads};
use lichen_proto::Statement;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let input = hex::decode(std::fs::read_to_string(args.get(1).context("the claim's input (hex)")?)?.trim())?;
    let dir = std::path::PathBuf::from(args.get(2).context("a work directory")?);
    let min_hops: usize = args.get(3).map_or(Ok(1), |s| s.parse())?;
    let tail: u64 = args.get(4).map_or(Ok(20_000), |s| s.parse())?;
    let program = Statement::groth16()?.program(&dir)?;
    let j = program.schedule.jump.context("a jump list")?;
    let d = format!("{}/exec/", dir.display());
    std::fs::create_dir_all(&d)?;
    let e = |e: emulator::EmulatorError| anyhow::anyhow!("{e}");
    let (_, last, _) = emulator::decision::challenge::prover_execute(&program.pdf, input.clone(), &d, &d, true, None, false).map_err(e)?;
    eprintln!("the execution: {last} steps");
    let pd = emulator::loader::program_definition::ProgramDefinition::from_config(&program.pdf).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let (_, trace) = pd.execute_helper(&d, &d, input.clone(), Some((last.saturating_sub(tail).max(1)..=last).collect()), None, false).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    // BitVMX's "never written"
    let never = u64::MAX;
    let mut candidates = vec![];
    for (t, _) in &trace {
        for (r, rd) in [(2u8, &t.read_2), (1, &t.read_1)] {
            if rd.last_step == never || rd.last_step == 0 || t.step_number <= rd.last_step + 2 || t.step_number == last {
                continue;
            }
            let hops = j.path(t.step_number - 1, rd.last_step).len();
            if hops >= min_hops {
                candidates.push((t.step_number - rd.last_step, hops, r, t.step_number, rd.address, rd.value, rd.last_step));
            }
        }
    }
    candidates.sort_by(|a, b| b.cmp(a));
    eprintln!("{} candidate reads in the last {tail} steps", candidates.len());
    for (k, (_, hops, r, step, address, value, last_step)) in candidates.into_iter().take(8).enumerate() {
        let args: Vec<String> = vec![step.to_string(), format!("{address:#x}"), format!("{:#x}", value ^ 1), format!("{address:#x}"), last_step.to_string()];
        let fail = FailConfiguration::new_fail_reads(if r == 1 { FailReads::new(Some(&args), None) } else { FailReads::new(None, Some(&args)) });
        eprintln!("probe {k}: step {step}, read_{r} of {address:#x} (last written at step {last_step}, {hops} hops): searching...");
        let found = lngap_zk::dispute::search(&program.pdf, &input, &dir.join(format!("probe-{step}")), &lngap_zk::dispute::Behaviour { fail: Some(fail.clone()) }, &lngap_zk::dispute::Behaviour::default(), ForceCondition::No)?;
        match found {
            Some(sr) if sr.step == step && sr.final_step.claim_last_step != sr.step => {
                eprintln!("  the search lands on it");
                println!("{}", serde_json::to_string(&fail)?);
                return Ok(());
            }
            Some(sr) => eprintln!("  the search lands on step {} instead", sr.step),
            None => eprintln!("  the verifier agrees: no dispute"),
        }
    }
    bail!("no read lie found that the search lands on")
}
