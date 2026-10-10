//! `lichen-hub`: the hub's daemon (regtest).

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use lichen_hub::{Config, Hub};
use lichen_proto::Statement;

#[derive(Parser)]
#[command(about = "A lichen hub (regtest)")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:18310")]
    listen: String,
    #[arg(long, default_value = "http://127.0.0.1:18300")]
    sequencer: String,
    /// The node's RPC URL and cookie file; the hub's wallet there.
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    cookie: PathBuf,
    #[arg(long, default_value = "hub")]
    chain_wallet: String,
    /// `mock`, or `groth16:<path to the verifier's program definition>`.
    #[arg(long, default_value = "mock")]
    statement: Statement,
    /// Where the hub keeps its contracts.
    #[arg(long, default_value = "hub-data")]
    dir: PathBuf,
    /// The hub's secret seed (a label; regtest only).
    #[arg(long, default_value = "lichen-regtest-hub")]
    seed: String,
    /// The hub's reserve, parts per million of the cap.
    #[arg(long, default_value_t = 20_000)]
    reserve_ppm: u64,
    #[arg(long, default_value_t = 24)]
    max_bits: u32,
    /// Blocks from opening to T_close.
    #[arg(long, default_value_t = 1_000)]
    duration: u32,
}

fn main() -> Result<()> {
    let a = Args::parse();
    let hub = Hub::start(Config {
        listen: a.listen,
        sequencer: a.sequencer,
        rpc_url: a.rpc_url,
        cookie: a.cookie,
        wallet: a.chain_wallet,
        statement: a.statement,
        dir: a.dir,
        seed: a.seed,
        reserve_ppm: a.reserve_ppm,
        max_bits: a.max_bits,
        duration: a.duration,
        refuse_folds: false,
        dispute_true_claims: false,
        first_cid: 1000,
    })?;
    println!("lichen hub at {}", hub.url);
    loop {
        std::thread::park();
    }
}
