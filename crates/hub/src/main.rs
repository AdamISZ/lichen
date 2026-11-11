//! `lichen-hub`: the hub's daemon.
//!
//! Its secrets are made on first start and kept in `--dir`: its L2 key
//! (`l2.key`: it mints; the sequencer names it with `--issuer`, as
//! `--print-key` prints it) and the seed of its contract keys (`seed`).
//! `--toy` uses the toy deployment's keys instead (anyone can derive
//! them: tests only).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use lichen_hub::{Config, Hub};
use lichen_ledger::{fresh_rho, load_or_create_key, regtest_hub, xonly};
use lichen_proto::Statement;

#[derive(Parser)]
#[command(about = "A lichen hub")]
struct Args {
    /// `regtest`, `mutinynet`, `signet` or `testnet4`.
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
    /// The hub's statement: `hub-proves-mock` (a proof of a toy circuit,
    /// for trials) or `hub-proves` (its guest, not built yet).
    #[arg(long, default_value = "hub-proves-mock")]
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
    /// The hub's fee for a contract's liquidity, parts per million of it,
    /// kept out of the user's minted deposit.
    #[arg(long, default_value_t = 10_000)]
    fee_ppm: u64,
    /// The most liquidity a contract may ask, in sats.
    #[arg(long, default_value_t = 10_000_000)]
    max_liquidity: u64,
    /// Blocks from opening to T_close (the network's default: a week on
    /// Mutinynet).
    #[arg(long)]
    duration: Option<u32>,
    /// For trials, on test networks only: refuse every cooperative
    /// withdrawal and assert a false proof against every exit claim that
    /// holds, so that each exit is played to its end on chain (the user
    /// challenges, and `failure` pays her).
    #[arg(long)]
    hostile: bool,
    /// For trials, on test networks only: refuse every cooperative
    /// withdrawal, so that each is an exit, but assert only against false
    /// claims (a true one is paid by its timeout).
    #[arg(long)]
    refuse_folds: bool,
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
    if a.hostile {
        anyhow::ensure!(a.network.is_test(), "--hostile is for test networks only, not {}", a.network);
        println!("hostile: refusing every cooperative withdrawal and asserting against every exit claim");
    } else if a.refuse_folds {
        anyhow::ensure!(a.network.is_test(), "--refuse-folds is for test networks only, not {}", a.network);
        println!("refusing every cooperative withdrawal; asserting against false claims only");
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
        fee_ppm: a.fee_ppm,
        max_liquidity: a.max_liquidity,
        duration: a.duration.unwrap_or(lichen_proto::default_duration(a.network)),
        refuse_folds: a.hostile || a.refuse_folds,
        forge_assertions: a.hostile,
        first_cid: 1000,
    })?;
    println!("lichen hub at {}", hub.url);
    loop {
        std::thread::park();
    }
}
