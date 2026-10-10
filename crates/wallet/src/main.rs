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
    /// The hub.
    #[arg(long, default_value = "http://127.0.0.1:18310")]
    hub: String,
    /// The node's RPC URL and cookie file, and this wallet's coins there.
    #[arg(long)]
    rpc_url: Option<String>,
    #[arg(long)]
    cookie: Option<PathBuf>,
    #[arg(long, default_value = "alice")]
    chain_wallet: String,
    /// `mock`, or `groth16:<path to the verifier's program definition>`.
    #[arg(long, default_value = "mock")]
    statement: lichen_proto::Statement,
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
    /// Open a contract with the hub: deposit `deposit` sats, a cap of
    /// 2^bits - 1 sats, a reserve of `reserve` sats.
    Open {
        deposit: u64,
        #[arg(long, default_value_t = 21)]
        bits: u32,
        #[arg(long, default_value_t = 20_000)]
        reserve: u64,
    },
    /// The contracts this wallet holds.
    Contracts,
    /// Withdraw `amount` sats from a contract cooperatively.
    Withdraw { contract: u32, amount: u64 },
    /// Enforce a withdrawal (already returned on the L2) on Bitcoin, when
    /// the hub won't fold it: escalate and play the dispute to its end.
    /// Run again to resume (the claim is kept with the contract).
    Dispute {
        contract: u32,
        /// The amount withdrawn (not needed to resume).
        amount: Option<u32>,
        /// The statement program's input for the claim, hex (for Groth16:
        /// the verifier's 172-byte input for the proof). The mock's is
        /// built here.
        #[arg(long)]
        input: Option<PathBuf>,
    },
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
        Cmd::Open { deposit, bits, reserve } => {
            let (url, cookie) = (a.rpc_url.context("--rpc-url")?, a.cookie.context("--cookie")?);
            let chain = lichen_chain::Chain::connect(&url, &cookie, &a.chain_wallet)?;
            let dir = a.wallet.with_extension("d");
            let h = w.open_contract(&a.hub, &chain, &a.statement, &dir, lichen_wallet::Ask { deposit, bits, reserve })?;
            let t = &h.record.terms;
            println!("contract {} (memo {}): deposit {} sats, cap {} sats, T_close {}; funding {}", h.record.cid(), t.id, t.deposit, t.v_max().to_sat(), t.t_close, h.record.funding.txid);
        }
        Cmd::Contracts => {
            for h in &w.contracts {
                let t = &h.record.terms;
                let state = h.closed.map_or("open".to_string(), |x| format!("folded in {x}"));
                println!("{}: deposit {} sats, cap {} sats, T_close {}, funding {}; {state}", h.record.cid(), t.deposit, t.v_max().to_sat(), t.t_close, h.record.funding.txid);
            }
        }
        Cmd::Dispute { contract, amount, input } => {
            let (url, cookie) = (a.rpc_url.context("--rpc-url")?, a.cookie.context("--cookie")?);
            let chain = lichen_chain::Chain::connect(&url, &cookie, &a.chain_wallet)?;
            let kept = w.contracts.iter().find(|h| h.record.cid() == contract).and_then(|h| h.claim.clone());
            let (amount, input) = match (kept, amount, input) {
                (Some((b, i)), _, _) => (b, hex::decode(i)?),
                (None, Some(b), Some(p)) => (b, hex::decode(std::fs::read_to_string(p)?.trim())?),
                (None, Some(b), None) => (b, a.statement.mock_input(b, contract).context("--input: the claim's input (a proof's, for groth16)")?),
                (None, None, _) => anyhow::bail!("the amount withdrawn"),
            };
            let (outcome, swept) = w.dispute(&chain, &a.statement, &a.wallet.with_extension("d"), contract, amount, &input)?;
            println!("{outcome:?}; swept {swept:?}");
        }
        Cmd::Withdraw { contract, amount } => {
            let txid = w.withdraw(&a.hub, &a.statement, &a.wallet.with_extension("d"), contract, amount)?;
            println!("withdrew {amount} sats from contract {contract}: the fold is {txid}");
        }
    }
    Ok(())
}
