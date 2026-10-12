//! `lichen-hub`: the hub's daemon.
//!
//! Its secrets are made on first start and kept in `--dir`: its L2 key
//! (`l2.key`: it mints; the sequencer names it with `--issuer`, as
//! `--print-key` prints it) and the seed of its contract keys (`seed`).
//! `--toy` uses the toy deployment's keys instead (anyone can derive
//! them: tests and regtest demos only).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use lichen_hub::{Config, Hub};
use lichen_ledger::{fresh_rho, load_or_create_key, regtest_hub, xonly};
use lichen_proto::Statement;

#[derive(Parser)]
#[command(about = "A lichen hub")]
struct Args {
    /// `regtest` or `mutinynet`.
    #[arg(long, default_value = "regtest")]
    network: lichen_proto::Net,
    #[arg(long, default_value = "127.0.0.1:18310")]
    listen: String,
    #[arg(long, default_value = "http://127.0.0.1:18300")]
    sequencer: String,
    /// The node's RPC URL and cookie file; the hub's wallet there.
    #[arg(long)]
    rpc_url: Option<String>,
    #[arg(long)]
    cookie: Option<PathBuf>,
    #[arg(long, default_value = "hub")]
    chain_wallet: String,
    /// `mock`, or `groth16:<path to the verifier's program definition>`.
    #[arg(long, default_value = "mock")]
    statement: Statement,
    /// Where the hub keeps its contracts.
    #[arg(long, default_value = "hub-data")]
    dir: PathBuf,
    /// The toy deployment's keys (anyone can derive them).
    #[arg(long)]
    toy: bool,
    /// Print the hub's L2 key (making it if needed) and exit.
    #[arg(long)]
    print_key: bool,
    /// The hub's reserve, parts per million of the cap.
    #[arg(long, default_value_t = 20_000)]
    reserve_ppm: u64,
    #[arg(long, default_value_t = 24)]
    max_bits: u32,
    /// Blocks from opening to T_close (the network's default: a week on
    /// Mutinynet).
    #[arg(long)]
    duration: Option<u32>,
}

fn main() -> Result<()> {
    let a = Args::parse();
    let (l2_key, seed) = if a.toy {
        (regtest_hub(), "lichen-regtest-hub".to_string())
    } else {
        let seed_file = a.dir.join("seed");
        if !seed_file.exists() {
            std::fs::create_dir_all(&a.dir)?;
            std::fs::write(&seed_file, hex::encode(fresh_rho()))?;
        }
        (load_or_create_key(&a.dir.join("l2.key"))?, std::fs::read_to_string(&seed_file)?.trim().to_string())
    };
    if a.print_key {
        println!("{}", hex::encode(xonly(&l2_key)));
        return Ok(());
    }
    let hub = Hub::start(Config {
        network: a.network,
        listen: a.listen,
        sequencer: a.sequencer,
        rpc_url: a.rpc_url.context("--rpc-url: the node's RPC URL")?,
        cookie: a.cookie.context("--cookie: the node's cookie file")?,
        wallet: a.chain_wallet,
        statement: a.statement,
        dir: a.dir,
        seed,
        l2_key,
        reserve_ppm: a.reserve_ppm,
        max_bits: a.max_bits,
        duration: a.duration.unwrap_or(a.network.default_duration()),
        refuse_folds: false,
        dispute_true_claims: false,
        first_cid: 1000,
    })?;
    println!("lichen hub at {}", hub.url);
    loop {
        std::thread::park();
    }
}
