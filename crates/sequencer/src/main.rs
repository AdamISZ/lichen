//! `lichen-sequencer`: the regtest deployment's sequencer.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_sequencer::{Client, Sequencer};

#[derive(Parser)]
#[command(about = "The lichen L2's sequencer (regtest keys)")]
struct Args {
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:18300")]
    listen: String,
    /// Where the ledger is kept.
    #[arg(long, default_value = "ledger.json")]
    ledger: PathBuf,
    /// Seal a height every this many seconds (0: only on request).
    #[arg(long, default_value_t = 5)]
    seal_every: u64,
}

fn main() -> Result<()> {
    let a = Args::parse();
    let s = Sequencer::start(&a.listen, Some(a.ledger), regtest_sequencer(), HUB_KEY)?;
    println!("lichen sequencer at {}", s.url);
    let client = Client::new(&s.url);
    loop {
        if a.seal_every == 0 {
            std::thread::park();
            continue;
        }
        std::thread::sleep(std::time::Duration::from_secs(a.seal_every));
        match client.seal() {
            Ok(r) => println!("sealed {r}"),
            Err(e) => eprintln!("seal: {e:#}"),
        }
    }
}
