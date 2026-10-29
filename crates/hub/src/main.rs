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
use lichen_proto::bitvmx::Windows;
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
    /// BitVMX's: `mock`, `groth16` (its verifier, found in the cargo
    /// checkout) or `groth16:<path to the verifier's program definition>`;
    /// BABE's: `babe` (the RISC Zero proof) or `babe-mock`.
    #[arg(long, default_value = "babe-mock")]
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
    /// The dispute's windows, in blocks, `<user>,<hub>,<path>`: the user's
    /// for each of her moves, the hub's for its choices, the hub's for its
    /// heavy moves (the network's default if not given). Size the heavy
    /// ones by the contracts the hub will hold.
    #[arg(long, value_parser = parse_windows)]
    windows: Option<Windows>,
    /// For trials, on test networks only: refuse every cooperative
    /// withdrawal and dispute every claim, true ones too, so that each
    /// withdrawal is played to its end on chain; a valid last step not
    /// proved in the user's window is taken by the hub's timeout.
    #[arg(long)]
    hostile: bool,
    /// For trials, on test networks only: refuse every cooperative
    /// withdrawal, so that each is played on chain, but dispute only
    /// false claims (a true one ends unchallenged).
    #[arg(long)]
    refuse_folds: bool,
}

fn parse_windows(s: &str) -> Result<Windows, String> {
    let n: Vec<u16> = s.split(',').map(|x| x.trim().parse::<u16>().map_err(|e| format!("{x}: {e}"))).collect::<Result<_, _>>()?;
    let [user, hub, path] = n[..] else { return Err("three windows, <user>,<hub>,<path>".into()) };
    Ok(Windows { user, hub, path })
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
        println!("hostile: refusing every cooperative withdrawal and disputing every claim");
    } else if a.refuse_folds {
        anyhow::ensure!(a.network.is_test(), "--refuse-folds is for test networks only, not {}", a.network);
        println!("refusing every cooperative withdrawal; disputing false claims only");
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
        duration: a.duration.unwrap_or(lichen_proto::default_duration(a.network)),
        windows: a.windows,
        refuse_folds: a.hostile || a.refuse_folds,
        dispute_true_claims: a.hostile,
        first_cid: 1000,
    })?;
    println!("lichen hub at {}", hub.url);
    loop {
        std::thread::park();
    }
}
