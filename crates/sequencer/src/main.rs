//! `lichen-sequencer`: the L2's sequencer.
//!
//! Its key is made on first start and kept in `--key`; the hub that mints
//! is named by its key (`--issuer`, as `lichen-hub --print-key` prints it).
//! `--toy` runs the toy deployment instead (keys anyone can derive: tests
//! and regtest demos only).

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;
use lichen_ledger::{load_or_create_key, regtest_sequencer, Hash, HUB_KEY};
use lichen_l2::Client;
use lichen_sequencer::{Options, Sequencer};

#[derive(Parser)]
#[command(about = "The lichen L2's sequencer")]
struct Args {
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:18300")]
    listen: String,
    /// Where the ledger is kept.
    #[arg(long, default_value = "ledger.json")]
    ledger: PathBuf,
    /// The sequencer's secret key (hex), made here on first start.
    #[arg(long, default_value = "sequencer.key")]
    key: PathBuf,
    /// The hub's L2 key (x-only, hex): who may mint.
    #[arg(long)]
    issuer: Option<String>,
    /// The toy deployment's keys (anyone can derive them).
    #[arg(long)]
    toy: bool,
    /// Seal a height every this many seconds (0: only on request).
    #[arg(long, default_value_t = 5)]
    seal_every: u64,
    /// Accept native proofs of shielded spends, which carry the sender's
    /// private input in the clear: tests and demos only.
    #[arg(long)]
    native_proofs: bool,
}

fn main() -> Result<()> {
    let a = Args::parse();
    let (key, issuer) = match (a.toy, &a.issuer) {
        (true, None) => (regtest_sequencer(), HUB_KEY),
        (false, Some(h)) => {
            let issuer: Hash = hex::decode(h).ok().and_then(|v| v.try_into().ok()).context("--issuer: a 32-byte hex key")?;
            (load_or_create_key(&a.key)?, issuer)
        }
        (true, Some(_)) => bail!("--toy and --issuer: one or the other"),
        (false, None) => bail!("name the hub with --issuer <its L2 key> (or run the toy deployment with --toy)"),
    };
    let s = Sequencer::start_with(&a.listen, Some(a.ledger), key, issuer, Options { native_proofs: a.native_proofs })?;
    let client = Client::new(&s.url)?;
    let d = client.deployment;
    println!("lichen sequencer at {}: sequencer {}, hub {}, deployment {}", s.url, hex::encode(d.sequencer), hex::encode(d.hub), hex::encode(d.id()));
    let mut last = 0;
    loop {
        if a.seal_every == 0 {
            std::thread::park();
            continue;
        }
        std::thread::sleep(std::time::Duration::from_secs(a.seal_every));
        // (no new height when nothing changed: say so only when there is one)
        match client.seal() {
            Ok(r) if r.height != last => {
                last = r.height;
                println!("sealed {r}");
            }
            Ok(_) => {}
            Err(e) => eprintln!("seal: {e:#}"),
        }
    }
}
