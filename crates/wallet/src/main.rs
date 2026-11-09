//! `lichen`: the user's wallet.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use lichen_wallet::Wallet;

#[derive(Parser)]
#[command(about = "A lichen wallet")]
struct Args {
    /// `regtest`, `mutinynet`, `signet` or `testnet4`.
    #[arg(long, default_value = "regtest")]
    network: lichen_proto::Net,
    /// The wallet file.
    #[arg(long, default_value = "wallet.json")]
    wallet: PathBuf,
    /// The sequencer.
    #[arg(long, default_value = "http://127.0.0.1:18300")]
    sequencer: String,
    /// The hub.
    #[arg(long, default_value = "http://127.0.0.1:18310")]
    hub: String,
    /// Esplora servers, comma-separated (the network's public one by
    /// default: mempool.space or mutinynet.com). With two or more, none is
    /// trusted alone: a move is answered only once all report it confirmed
    /// in the same block with the same witness.
    #[arg(long)]
    esplora: Option<String>,
    /// Instead of Esplora: a node's RPC URL and cookie file.
    #[arg(long)]
    rpc_url: Option<String>,
    #[arg(long)]
    cookie: Option<PathBuf>,
    #[arg(long, default_value = "alice")]
    chain_wallet: String,
    /// The hub's statement: `hub-proves-mock` (a proof of a toy circuit,
    /// for trials) or `hub-proves` (its guest, not built yet).
    #[arg(long, default_value = "hub-proves-mock")]
    statement: lichen_proto::Statement,
    /// The prover of shielded spends: a command run as `<cmd> spend <input
    /// file> <receipt file>`. Without it, spends carry native proofs (the
    /// private input in the clear), which only a sequencer started with
    /// --native-proofs accepts.
    #[arg(long)]
    spend_prover: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a wallet with a fresh key.
    Init,
    /// The wallet's L2 address (transparent), or its shielded address.
    Address {
        #[arg(long)]
        shielded: bool,
    },
    /// The balance on the L2: transparent and shielded notes.
    Balance,
    /// Pay an L2 address: a transparent one (32 bytes, hex) from
    /// transparent notes, a shielded one (64 bytes) from shielded notes.
    Send { to: String, amount: u64 },
    /// Acknowledge your spends: each one the sequencer has sealed and an
    /// anchor on Bitcoin holds (docs/HUB_PROVES_PLAN.md, "Data
    /// availability"). Until you do, a spend doesn't count against you and
    /// its outputs, your change and your payee's note, stay locked. With
    /// --wait, until none waits (about one anchor, the margin deep).
    Ack {
        #[arg(long)]
        wait: bool,
    },
    /// Move `amount` of transparent notes into a shielded note.
    Shield { amount: u64 },
    /// Move `amount` of shielded notes into a transparent note of ours (a
    /// withdrawal's claim, or an exit's, takes transparent notes).
    Unshield { amount: u64 },
    /// Print every signed root this wallet has checked (JSON), for others
    /// to compare with theirs: a sequencer that signs two histories can't
    /// show both to everyone without being caught.
    Roots,
    /// Compare signed roots from elsewhere with this wallet's: another
    /// wallet's `lichen roots`, or a sequencer's URL (a mirror's, or the
    /// sequencer's seen from another network). Prints how many heights
    /// agree, or the two conflicting roots, written as evidence.
    CompareRoots { from: String },
    /// Check evidence that the sequencer signed two histories (an
    /// `equivocation.json`): both roots at one height, both signed by this
    /// wallet's sequencer.
    CheckEquivocation { file: PathBuf },
    /// Open a contract with the hub: deposit `deposit` sats, with
    /// `liquidity` sats of inbound (what you can receive beyond your
    /// balance), a reserve of `reserve` sats. Prints the hub's fee for the
    /// liquidity (kept out of what it mints you) and the cap, then a
    /// deposit address and the amount to pay it (from any wallet), and
    /// waits.
    Open {
        deposit: u64,
        #[arg(long, default_value_t = 0)]
        liquidity: u64,
        #[arg(long, default_value_t = 20_000)]
        reserve: u64,
        /// Where withdrawals, refunds and the fee budget's rest are paid
        /// (an address of any wallet of yours; by default this wallet's
        /// own payout address, `lichen payout`).
        #[arg(long)]
        payout: Option<String>,
        /// Finish the opening of this contract with its deposit, already
        /// paid (an opening that failed after the deposit); the payout
        /// address is the deposit's.
        #[arg(long)]
        resume: Option<u32>,
    },
    /// Send what is left of a contract's fee budget to its payout address
    /// (once it is closed, unless --force). A won dispute's sweep takes it
    /// already; this is for a fold, a refund or a lost dispute.
    SweepFees {
        contract: u32,
        #[arg(long, default_value_t = 500)]
        fee: u64,
        #[arg(long)]
        force: bool,
    },
    /// Take back a deposit whose contract never opened, once its timeout
    /// has passed (to the payout address given at `open`).
    Refund {
        contract: u32,
        #[arg(long, default_value_t = 500)]
        fee: u64,
    },
    /// Claim a contract's deposit, minted before its funding, when the hub
    /// broadcast the funding but didn't answer: `t` is read from the
    /// funding on chain. Also opens a contract whose opening's answer was
    /// lost.
    ClaimMint { contract: u32 },
    /// The contracts this wallet holds.
    Contracts,
    /// Withdraw `amount` sats from a contract cooperatively (rounded down
    /// to the contract's unit): a claim of your notes worth exactly that,
    /// which the hub records on the L2, then the fold. 0 closes it early
    /// with nothing withdrawn: your reserve back, as the default would pay
    /// it at T_close.
    Withdraw {
        contract: u32,
        amount: u64,
        /// If the cooperative withdrawal fails, exit at once on Bitcoin
        /// (without it, the next step is named).
        #[arg(long)]
        escalate: bool,
    },
    /// Post a contract's default after T_close, when the hub hasn't (it
    /// pays you your reserve), with a fee coin from its fee budget.
    PostDefault { contract: u32 },
    /// This wallet's own Bitcoin payout address, and what's there.
    Payout,
    /// Pay from this wallet's payout address: `amount` sats, or everything
    /// (less the fee) without it.
    SendPayout { to: String, amount: Option<u64> },
    /// Exit through a contract when the operator won't fold a withdrawal,
    /// or has gone: claim our notes (after a withdrawal not folded, its
    /// claim), and play the dispute to its end (the hub proves the claim
    /// false or the timeout pays). Run again to resume (the claim is kept
    /// with the contract).
    Exit { contract: u32 },
}

/// The chain: a node if `--rpc-url` is given, else Esplora.
fn chain(a: &Args) -> Result<lichen_chain::Chain> {
    match (&a.rpc_url, &a.cookie) {
        (Some(url), Some(cookie)) => lichen_chain::Chain::connect_on(url, cookie, &a.chain_wallet, a.network),
        (Some(_), None) => anyhow::bail!("--rpc-url needs --cookie"),
        _ => {
            let urls = a.esplora.as_deref().or(a.network.default_esplora()).context("--esplora: no public Esplora for this network")?;
            let urls: Vec<&str> = urls.split(',').map(str::trim).filter(|u| !u.is_empty()).collect();
            lichen_chain::Chain::esploras(&urls, a.network)
        }
    }
}

/// When an exit must confirm: by `T_close`, and how long is left (after
/// it the hub may broadcast the contract's default, her reserve and not
/// `b`).
fn deadline(a: &Args, t_close: u32, height: Option<u32>) -> String {
    let secs = match a.network {
        lichen_chain::Net::Mutinynet => Some(30),
        lichen_chain::Net::Signet | lichen_chain::Net::Testnet4 => Some(600),
        lichen_chain::Net::Regtest => None,
    };
    match height {
        Some(h) if h >= t_close => format!("T_close, block {t_close}, has passed (now {h}): the hub may broadcast the contract's default at any block, which pays you your reserve and not the withdrawal. Escalate at once: it is valid while the contract's funding is unspent."),
        Some(h) => {
            let left = t_close - h;
            let about = secs.map(|s| format!(", about {:.1} hours", f64::from(left) * f64::from(s) / 3600.0)).unwrap_or_default();
            format!("Escalate so that it confirms by block {t_close}, the contract's T_close (now {h}: {left} blocks left{about}). After it the hub may broadcast the contract's default instead, which pays you your reserve and not the withdrawal.")
        }
        None => format!("Escalate so that it confirms by block {t_close}, the contract's T_close. After it the hub may broadcast the contract's default instead, which pays you your reserve and not the withdrawal."),
    }
}

/// The next step when a withdrawal fails: the exit.
fn exit_note(a: &Args, cid: u32, t_close: u32, height: Option<u32>) -> String {
    format!(
        "contract {cid}: the withdrawal wasn't folded, so only an exit on Bitcoin gets it out: a claim of your notes, which needs neither the hub nor the sequencer. You prove nothing: the hub must prove the claim false within its window, or its timeout pays you.\n{}\nWith this command's --network, --wallet and --statement:\n    lichen exit {cid}\nor run this withdrawal again with --escalate.",
        deadline(a, t_close, height)
    )
}

/// `lichen exit`: a contract's exit, played to its end.
fn exit_cmd(a: &Args, w: &mut Wallet, contract: u32) -> Result<()> {
    let chain = chain(a)?;
    w.progress = Some(std::sync::Arc::new(|m: String| println!("{m}")));
    let (outcome, swept) = w.exit(&chain, &a.statement, contract)?;
    match outcome {
        lichen_wallet::dispute::Outcome::Countered => println!("The hub proved the claim false: a note of it isn't yours, isn't live at the last anchor before the request, or was claimed through another contract too. Its success takes the contract."),
        _ => println!("{outcome:?}; swept {swept:?}"),
    }
    Ok(())
}

fn main() -> Result<()> {
    let a = Args::parse();
    if let Cmd::Init = a.cmd {
        let w = Wallet::create(&a.wallet, &a.sequencer)?;
        println!("{}", hex::encode(w.address()));
        return Ok(());
    }
    let mut w = Wallet::open(&a.wallet, &a.sequencer)?;
    if let Some(p) = &a.spend_prover {
        w.spend_prover = lichen_wallet::shielded::SpendProver::Command(p.clone());
    }
    match a.cmd {
        Cmd::Init => unreachable!(),
        Cmd::Address { shielded: false } => println!("{}", hex::encode(w.address())),
        Cmd::Address { shielded: true } => println!("{}", w.shielded_address()),
        Cmd::Balance => {
            let (t, s) = w.balances()?;
            println!("{} (transparent {t}, shielded {s})", t + s);
            // in an anchored deployment: how final, the anchors checked on
            // Bitcoin
            if w.sequencer.deployment.seal.is_some() {
                let f = w.finality(&chain(&a)?)?;
                let depth = lichen_proto::ANCHOR_DEPTH;
                println!("  final (anchored, {depth}+ blocks deep): {}; anchored, not yet {depth} deep: {}; sealed, not yet anchored: {}", f.fin, f.anchored, f.sealed);
                match f.last {
                    Some(c) => println!("  the last anchor: height {}, {} confirmations", c.height, c.confirmations),
                    None => println!("  no anchor yet"),
                }
            }
        }
        Cmd::Send { to, amount } if to.len() == 128 => {
            let to: lichen_wallet::shielded::SAddress = to.parse()?;
            println!("sent: note {}", w.send_shielded(&to, amount)?[0]);
        }
        Cmd::Send { to, amount } => {
            let to: [u8; 32] = hex::decode(&to)?.try_into().ok().context("an address is 32 bytes (transparent) or 64 (shielded), hex")?;
            println!("sent: note {}", w.send(to, amount, 0)?[0]);
            println!("acknowledge it once it is anchored (`lichen ack --wait`): until then the payment is pending, your change locked");
        }
        Cmd::Ack { wait } => {
            let chain = chain(&a)?;
            if wait {
                w.acknowledge_all(&chain, 6 * 3600)?;
                println!("every spend acknowledged");
            } else {
                match w.acknowledge(&chain)? {
                    0 => println!("every spend acknowledged"),
                    n => println!("{n} spends wait for an anchor to acknowledge them against"),
                }
            }
        }
        Cmd::Shield { amount } => println!("shielded: note {}", w.shield(amount)?[0]),
        Cmd::Unshield { amount } => println!("unshielded: note {}", w.unshield(amount)?),
        Cmd::Roots => {
            w.state()?;
            println!("{}", serde_json::to_string_pretty(&w.seen().roots.into_values().collect::<Vec<_>>())?);
        }
        Cmd::CompareRoots { ref from } => {
            w.state()?;
            let roots: Vec<lichen_ledger::SignedRoot> = if from.starts_with("http://") || from.starts_with("https://") {
                lichen_l2::Client::pinned(from, w.sequencer.deployment).state()?.sealed
            } else {
                serde_json::from_slice(&std::fs::read(from)?).context("signed roots (JSON, as `lichen roots` prints)")?
            };
            let agree = w.compare_roots(&roots)?;
            println!("{agree} heights in common, all the same roots ({} given, {} seen here)", roots.len(), w.seen().roots.len());
        }
        Cmd::CheckEquivocation { ref file } => {
            let e: lichen_l2::Equivocation = serde_json::from_slice(&std::fs::read(file)?).context("an equivocation (JSON)")?;
            e.verify(&w.sequencer.deployment.sequencer)?;
            println!("{e}: both signed by sequencer {}", hex::encode(w.sequencer.deployment.sequencer));
        }
        Cmd::Open { deposit, liquidity, reserve, ref payout, resume } => {
            let chain = chain(&a)?;
            let ask = lichen_wallet::Ask { deposit, liquidity, reserve };
            let q = ask.quote(&lichen_wallet::hub_info(&a.hub)?)?;
            println!("the hub's fee for {liquidity} sats of liquidity: {} sats; you'll be minted {} sats, with a cap of {} sats", q.fee, q.minted, q.cap);
            let h = match resume {
                Some(cid) => w.resume_open(&a.hub, &chain, &a.statement, ask, cid)?,
                None => {
                    let payout = match payout.as_deref() {
                        Some(p) => p.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()?.require_network(a.network.bitcoin()).context("--payout")?.script_pubkey(),
                        None => {
                            let spk = w.payout().spk();
                            chain.watch(&spk)?;
                            println!("payouts to this wallet's own address: {}", w.payout_address(a.network));
                            spk
                        }
                    };
                    let pay = |addr: &bitcoin::Address, amount: bitcoin::Amount| -> Result<()> {
                        println!("pay {} sats to {addr}\n(waiting for it to confirm)", amount.to_sat());
                        Ok(())
                    };
                    w.open_contract(&a.hub, &chain, &a.statement, ask, payout, &pay)?
                }
            };
            let t = &h.record.terms;
            println!("contract {} (memo {}): deposit {} sats ({} minted), cap {} sats, T_close {}; funding {}", h.record.cid(), t.id, t.deposit, h.record.minted(), t.v_max().to_sat(), t.t_close, h.record.funding.txid);
        }
        Cmd::Contracts => {
            let addr = |spk: &bitcoin::Script| bitcoin::Address::from_script(spk, a.network.bitcoin()).map_or_else(|_| spk.to_hex_string(), |x| x.to_string());
            for h in &w.contracts {
                let t = &h.record.terms;
                let state = h.closed.map_or("open".to_string(), |x| format!("closed by {x}"));
                println!("contract {}: deposit {} sats, cap {} sats, T_close {}; {state}", h.record.cid(), t.deposit, t.v_max().to_sat(), t.t_close);
                println!("  funding     {}", h.record.funding);
                println!("  payout      {}", addr(&h.record.pubs[0].payout_spk));
                println!("  fee budget  {}", addr(&w.fees(&h.nonce, h.record.network).spk()));
                let k = h.record.hp();
                let win = k.hp_windows;
                println!("  windows     {} blocks for the hub's assertion, {} for the user's challenge, {} for its answer", win.w_h, win.delta2, win.delta1);
                println!("  hub proves  {} instances of the user's kept of {}, margin {} blocks", k.kept.len(), k.n, k.margin);
                if let Some(p) = &h.exit {
                    println!("  claim       {} units ({} sats), kept for its exit", p.b, u64::from(p.b) * t.unit.to_sat());
                }
            }
            for d in &w.deposits {
                let tree = lichen_proto::deposit_tree(&w.deposit_key(&d.nonce).x_only_public_key().0, &d.hub, d.timeout)?;
                println!("deposit for contract {} (not open): {}", d.cid, addr(&tree.script_pubkey()));
                println!("  refund to   {} (after {} blocks)", addr(&d.payout), d.timeout);
            }
        }
        Cmd::SweepFees { contract, fee, force } => {
            let txid = w.sweep_fees(&chain(&a)?, contract, bitcoin::Amount::from_sat(fee), force)?;
            println!("swept contract {contract}'s fee budget: {txid}");
        }
        Cmd::ClaimMint { contract } => {
            w.claim_mint(&chain(&a)?, contract)?;
            println!("contract {contract}'s deposit is ours on the L2");
        }
        Cmd::Refund { contract, fee } => {
            let txid = w.refund(&chain(&a)?, contract, bitcoin::Amount::from_sat(fee))?;
            println!("refunded the deposit for contract {contract}: {txid}");
        }
        Cmd::Exit { contract } => exit_cmd(&a, &mut w, contract)?,
        Cmd::PostDefault { contract } => {
            let txid = w.post_default(&chain(&a)?, &a.statement, contract)?;
            println!("posted contract {contract}'s default: {txid}");
        }
        Cmd::Payout => {
            let chain = chain(&a)?;
            let p = w.payout();
            chain.watch(&p.spk())?;
            println!("{}
{} sats", w.payout_address(a.network), p.balance(&chain)?.to_sat());
        }
        Cmd::SendPayout { ref to, amount } => {
            let to = to.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()?.require_network(a.network.bitcoin()).context("the address")?;
            let txid = w.send_payout(&chain(&a)?, &to.script_pubkey(), amount.map(bitcoin::Amount::from_sat))?;
            println!("paid {} to {to}: {txid}", amount.map_or("everything".into(), |v| format!("{v} sats")));
        }
        Cmd::Withdraw { contract, amount, escalate } => {
            w.progress = Some(std::sync::Arc::new(|m: String| println!("{m}")));
            match w.withdraw(&chain(&a)?, &a.hub, &a.statement, contract, amount) {
                Ok(txid) if amount == 0 => println!("closed contract {contract} with nothing withdrawn, your reserve back: the fold is {txid}"),
                Ok(txid) => println!("withdrew {amount} sats from contract {contract}: the fold is {txid}"),
                Err(e) => {
                    // an open contract with a claim: the exit is the next
                    // step (closing early with nothing withdrawn has none:
                    // the default pays the reserve)
                    let open = w.contracts.iter().find(|h| h.record.cid() == contract && h.closed.is_none()).map(|h| h.record.terms.t_close);
                    let Some(t_close) = open.filter(|_| amount > 0) else { return Err(e) };
                    if escalate {
                        eprintln!("The cooperative withdrawal failed: {e:#}\nExiting on Bitcoin");
                        exit_cmd(&a, &mut w, contract)?;
                    } else {
                        let height = chain(&a).and_then(|c| c.height()).ok();
                        eprintln!("Error: {e:#}\n\n{}", exit_note(&a, contract, t_close, height));
                        std::process::exit(1);
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_note_names_the_exit_the_deadline_and_escalate() {
        let a = Args::parse_from(["lichen", "--network", "mutinynet", "--statement", "hub-proves-mock", "contracts"]);
        let n = exit_note(&a, 1007, 3_519_000, Some(3_514_050));
        println!("{n}");
        assert!(n.contains("lichen exit 1007\n") && n.contains("--escalate") && n.contains("by block 3519000"));
        assert!(n.contains("You prove nothing") && n.contains("its timeout pays you"));
    }
}
