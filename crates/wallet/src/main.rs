//! `lichen`: the user's wallet.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use lichen_wallet::Wallet;

#[derive(Parser)]
#[command(about = "A lichen wallet")]
struct Args {
    /// The wallet file.
    #[arg(long, default_value = "wallet.json")]
    wallet: PathBuf,
    /// The sequencer.
    #[arg(long, default_value = "http://127.0.0.1:18300")]
    sequencer: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a wallet with a fresh key.
    Init,
    /// The wallet's L2 address.
    Address,
    /// The balance on the L2.
    Balance,
    /// Pay an L2 address.
    Send { to: String, amount: u64 },
    /// Return `amount` to the hub with the contract's memo: a withdrawal's
    /// first step.
    Return { amount: u64, memo: u32 },
    /// Print the withdrawal statement's input for a return (JSON).
    WithdrawInput { memo: u32 },
}

fn main() -> Result<()> {
    let a = Args::parse();
    if let Cmd::Init = a.cmd {
        let w = Wallet::create(&a.wallet, &a.sequencer)?;
        println!("{}", hex::encode(w.address()));
        return Ok(());
    }
    let mut w = Wallet::open(&a.wallet, &a.sequencer)?;
    match a.cmd {
        Cmd::Init => unreachable!(),
        Cmd::Address => println!("{}", hex::encode(w.address())),
        Cmd::Balance => println!("{}", w.balance()?),
        Cmd::Send { to, amount } => {
            let to: [u8; 32] = hex::decode(&to)?.try_into().ok().context("an address is 32 bytes, hex")?;
            println!("sent: note {}", w.send(to, amount, 0)?[0]);
        }
        Cmd::Return { amount, memo } => println!("returned: note {}", w.return_to_hub(amount, memo)?),
        Cmd::WithdrawInput { memo } => println!("{}", serde_json::to_string_pretty(&w.withdraw_input(memo)?)?),
    }
    Ok(())
}
