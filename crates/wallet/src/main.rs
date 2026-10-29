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
    /// BitVMX's: `mock`, `groth16` (its verifier, found in the cargo
    /// checkout) or `groth16:<path to the verifier's program definition>`;
    /// BABE's: `babe` (the RISC Zero proof) or `babe-mock`.
    #[arg(long, default_value = "mock")]
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
    /// Move `amount` of transparent notes into a shielded note.
    Shield { amount: u64 },
    /// Return `amount` to the hub with the contract's memo: a withdrawal's
    /// first step.
    Return { amount: u64, memo: u32 },
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
    /// Print the withdrawal statement's input for a return (JSON), for the
    /// prover: in an anchored deployment, under the anchor covering it, with
    /// the headers on the anchor's block its contract asks.
    WithdrawInput { memo: u32 },
    /// Write the sequencer's chain receipt at the height of a return's
    /// root, which the withdrawal's proof needs.
    ChainReceipt { memo: u32, out: PathBuf },
    /// Open a contract with the hub: deposit `deposit` sats, a cap of
    /// 2^bits - 1 sats, a reserve of `reserve` sats. Prints a deposit
    /// address and the amount to pay it (from any wallet), and waits.
    Open {
        deposit: u64,
        #[arg(long, default_value_t = 21)]
        bits: u32,
        #[arg(long, default_value_t = 20_000)]
        reserve: u64,
        /// Where withdrawals, refunds and the fee budget's rest are paid
        /// (an address of any wallet of yours).
        #[arg(long, required_unless_present = "resume")]
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
        /// the verifier's 204-byte input for the proof). The mock's is
        /// built here.
        #[arg(long)]
        input: Option<PathBuf>,
        /// For trials: lie in the dispute's execution, by BitVMX's fault
        /// configuration (JSON). An honest hub wins against any lie.
        #[arg(long, hide = true)]
        lie: Option<PathBuf>,
        /// For trials, on test networks only, under babe: assert --input,
        /// a real proof of another claim, unchecked against this
        /// contract's, so that the hub's challenge is played to `failure`.
        #[arg(long, hide = true)]
        false_claim: bool,
    },
    /// Write the package a tower needs to play a contract's dispute (once
    /// the withdrawal is returned on the L2 and the hub has refused it):
    /// the contract and its one-time secrets, never the wallet's key.
    ExportDispute {
        contract: u32,
        /// Where to write it.
        #[arg(long)]
        out: PathBuf,
        /// The claim's input, hex, if made already (a proof's, for
        /// groth16); the tower builds the mock's. Needed under babe: the
        /// package carries her signature on it, not her key.
        #[arg(long)]
        input: Option<PathBuf>,
    },
    /// Play a contract's dispute from a package (`export-dispute`) to its
    /// end, its state beside the package; needs no wallet. Run again to
    /// resume. A win ends at the payout: the wallet sweeps it
    /// (`sweep-dispute`).
    Tower {
        #[arg(long)]
        package: PathBuf,
        /// The prover, for a package without a claim (`lichen-r0`: `claim
        /// <input.json> <chain receipt> <out.hex>`, the STARK and the
        /// Groth16 wrap).
        #[arg(long, default_value = "lichen-r0")]
        prover: PathBuf,
    },
    /// Sweep what a tower's dispute won (its state file, beside its
    /// package) to the contract's payout address.
    SweepDispute {
        contract: u32,
        #[arg(long)]
        tower_state: PathBuf,
    },
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

/// What to do once a withdrawal's return is on the L2 and the hub hasn't
/// folded it: the dispute, before `T_close` (after it the hub may
/// broadcast the contract's default, her reserve and not `b`).
fn escalate_note(a: &Args, cid: u32, b: u64, t_close: u32, height: Option<u32>) -> String {
    let secs = match a.network {
        lichen_chain::Net::Mutinynet => Some(30),
        lichen_chain::Net::Signet | lichen_chain::Net::Testnet4 => Some(600),
        lichen_chain::Net::Regtest => None,
    };
    let when = match height {
        Some(h) if h >= t_close => format!("T_close, block {t_close}, has passed (now {h}): the hub may broadcast the contract's default at any block, which pays you your reserve and not the withdrawal. Escalate at once: it is valid while the contract's funding is unspent."),
        Some(h) => {
            let left = t_close - h;
            let about = secs.map(|s| format!(", about {:.1} hours", f64::from(left) * f64::from(s) / 3600.0)).unwrap_or_default();
            format!("Escalate so that it confirms by block {t_close}, the contract's T_close (now {h}: {left} blocks left{about}). After it the hub may broadcast the contract's default instead, which pays you your reserve and not the withdrawal.")
        }
        None => format!("Escalate so that it confirms by block {t_close}, the contract's T_close. After it the hub may broadcast the contract's default instead, which pays you your reserve and not the withdrawal."),
    };
    let (proving, yourself) = if matches!(a.statement, lichen_proto::Statement::Babe { mock: false }) {
        (
            "The escalation has to confirm; then the hub signs b and you prove (10 to 15 minutes on 4 x86 cores) before T_A",
            format!("  yourself, then proving on x86 Linux with Docker as it tells you once the hub has signed b:\n    lichen dispute {cid} {b}"),
        )
    } else if a.statement.mock_input(0, cid).is_some() || a.statement == (lichen_proto::Statement::Babe { mock: true }) {
        ("The escalation has to confirm", format!("  yourself:\n    lichen dispute {cid} {b}"))
    } else {
        (
            "Proving takes 10 to 15 minutes on 4 x86 cores, and the escalation has to confirm",
            format!("  yourself, proving on x86 Linux with Docker (the README, \"Disputes on the real statement\"):\n    lichen withdraw-input {cid} > withdraw-input.json\n    lichen chain-receipt {cid} chain.receipt\n    lichen-r0 claim withdraw-input.json chain.receipt claim.hex\n    lichen dispute {cid} {b} --input claim.hex"),
        )
    };
    let tower = match a.statement {
        lichen_proto::Statement::Babe { mock: false } => format!("  or, once you have proved, with a tower, which asserts the proof and answers the hub's challenge while you are away (it holds your signatures, none of your keys):\n    lichen export-dispute {cid} --input claim.hex --out package.json"),
        lichen_proto::Statement::Babe { mock: true } => format!("  or with a tower, which plays it while you are away (it holds your signatures, none of your keys):\n    lichen export-dispute {cid} --out package.json"),
        _ => format!("  or with a tower, which proves and plays it while you are away (docs/RUN_A_TOWER.md):\n    lichen export-dispute {cid} --out package.json"),
    };
    format!(
        "contract {cid}: your {b} sats are returned to the hub on the L2 and not folded, so only a dispute on Bitcoin gets them back (if the hub was only unreachable, `withdraw` again asks with the same return).\n{when} {proving}: don't leave it to the last blocks.\nWith this command's --network, --wallet and --statement:\n{yourself}\n{tower}"
    )
}

fn main() -> Result<()> {
    let a = Args::parse();
    if let Cmd::Init = a.cmd {
        let w = Wallet::create(&a.wallet, &a.sequencer)?;
        println!("{}", hex::encode(w.address()));
        return Ok(());
    }
    if let Cmd::Tower { ref package, ref prover } = a.cmd {
        let chain = chain(&a)?;
        let progress: std::sync::Arc<dyn Fn(String) + Send + Sync> = std::sync::Arc::new(|m: String| println!("{m}"));
        let opts = lichen_wallet::engine::Options { progress: Some(progress), ..Default::default() };
        let outcome = lichen_wallet::tower::run(&chain, &a.statement, package, &lichen_wallet::tower::work_dir(package), prover, opts)?;
        match outcome.payout() {
            Some(txid) => {
                let cid = lichen_wallet::tower::Package::load(package)?.cid();
                let state = package.with_extension("state.json");
                let name = state.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                println!("{outcome:?}: the payout is {txid}.");
                println!("Sweep it on your own device, with the wallet that exported the package: the tower has none of its keys. Copy this tower's state there, {} (on a machine running deploy/tower's compose file, the container's, so root's: `docker compose -f deploy/tower/docker-compose.yml cp tower:/tower/{name} .` makes a copy of your own), then:\n  lichen sweep-dispute {cid} --tower-state {name}", state.display());
            }
            None => println!("{outcome:?}"),
        }
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
        }
        Cmd::Shield { amount } => println!("shielded: note {}", w.shield(amount)?[0]),
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
        Cmd::Return { amount, memo } => println!("returned: note {}", w.return_to_hub(amount, memo)?),
        Cmd::WithdrawInput { memo } => {
            // in an anchored deployment, with the headers on the anchor
            let input = match w.sequencer.deployment.seal {
                Some(_) => serde_json::to_value(w.prover_input(memo, &chain(&a)?)?)?,
                None => serde_json::to_value(w.withdraw_input(memo)?)?,
            };
            println!("{}", serde_json::to_string_pretty(&input)?);
        }
        Cmd::ChainReceipt { memo, ref out } => {
            std::fs::write(out, w.chain_receipt(memo)?)?;
            println!("{}: the chain receipt for the return with memo {memo}", out.display());
        }
        Cmd::Open { deposit, bits, reserve, ref payout, resume } => {
            let chain = chain(&a)?;
            let dir = a.wallet.with_extension("d");
            let ask = lichen_wallet::Ask { deposit, bits, reserve };
            let h = match resume {
                Some(cid) => w.resume_open(&a.hub, &chain, &a.statement, &dir, ask, cid)?,
                None => {
                    let payout = payout.as_deref().context("--payout")?.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()?.require_network(a.network.bitcoin()).context("--payout")?.script_pubkey();
                    let pay = |addr: &bitcoin::Address, amount: bitcoin::Amount| -> Result<()> {
                        println!("pay {} sats to {addr}\n(waiting for it to confirm)", amount.to_sat());
                        Ok(())
                    };
                    w.open_contract(&a.hub, &chain, &a.statement, &dir, ask, payout, &pay)?
                }
            };
            let t = &h.record.terms;
            println!("contract {} (memo {}): deposit {} sats, cap {} sats, T_close {}; funding {}", h.record.cid(), t.id, t.deposit, t.v_max().to_sat(), t.t_close, h.record.funding.txid);
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
                match &h.record.dispute {
                    lichen_proto::DisputeKeys::BitVmx(k) => match k.windows {
                        Some(win) => println!("  windows     {} blocks for each of the user's moves, {} for the hub's choices, {} for its heavy moves", win.user, win.hub, win.path),
                        None => {
                            let p = lichen_proto::params(h.record.network);
                        println!("  windows     {} blocks for every move (a contract from before windows by obligation)", p.delta + p.delta_prime);
                        }
                    },
                    lichen_proto::DisputeKeys::Babe(k) => {
                        let w = k.windows;
                        println!("  windows     {} blocks for the hub's response, assert by block {}, {} for its challenge, {} for the answer", w.w_h, w.t_a, w.delta2, w.delta1);
                        println!("  BABE        {} instances kept of {}", k.kept.len(), k.n);
                    }
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
        Cmd::Dispute { contract, amount, ref input, ref lie, false_claim } => {
            anyhow::ensure!(!false_claim || a.network.is_test(), "--false-claim is for test networks only, not {}", a.network);
            let chain = chain(&a)?;
            let kept = w.contracts.iter().find(|h| h.record.cid() == contract).and_then(|h| h.claim.clone());
            let real_babe = matches!(a.statement, lichen_proto::Statement::Babe { mock: false });
            // under babe, a RISC Zero claim (lichen-r0 babe-claim's) becomes its proof
            let read = |p: &PathBuf, w: &lichen_wallet::Wallet| -> Result<Vec<u8>> {
                let data = hex::decode(std::fs::read_to_string(p)?.trim())?;
                match (real_babe, false_claim) {
                    (true, true) => w.babe_false_input(&data),
                    (true, false) => w.babe_claim_input(contract, &data),
                    _ => Ok(data),
                }
            };
            let (amount, input) = match (kept, amount, input) {
                // the proof, made once the hub responded
                (Some((b, i)), _, Some(p)) if i.is_empty() => (b, read(p, &w)?),
                (Some((b, i)), _, _) => (b, hex::decode(i)?),
                (None, Some(b), Some(p)) => (b, read(p, &w)?),
                (None, Some(b), None) if a.statement == lichen_proto::Statement::Babe { mock: true } => (b, w.babe_mock_input(contract)?),
                // proved once the hub responds, with its signature on b
                (None, Some(b), None) if real_babe => (b, vec![]),
                (None, Some(b), None) => (b, a.statement.mock_input(b, contract).context("--input: the claim's input (a proof's, for groth16 and babe)")?),
                (None, None, _) => anyhow::bail!("the amount withdrawn"),
            };
            if let Some(p) = lie {
                w.lie = Some(serde_json::from_str(&std::fs::read_to_string(p)?).context("--lie: a FailConfiguration")?);
            }
            w.progress = Some(std::sync::Arc::new(|m: String| println!("{m}")));
            let (outcome, swept) = w.dispute(&chain, &a.statement, &a.wallet.with_extension("d"), contract, amount, &input)?;
            match outcome {
                lichen_wallet::dispute::Outcome::ProofDue(t_a) => {
                    let auth = lichen_wallet::engine::babe::data_dir(&a.wallet.with_extension("d"), contract).join("hub-auth.json");
                    println!(
                        "The hub signed b. Your proof is due: assert it before block {t_a} (T_A), after which the hub may take the contract. Prove on x86 Linux with Docker (the README, \"Disputes on the real statement\"), with this command's --network, --wallet and --statement:\n    lichen withdraw-input {contract} > withdraw-input.json\n    lichen chain-receipt {contract} chain.receipt\n    lichen-r0 babe-claim withdraw-input.json {} chain.receipt claim.hex\n    lichen dispute {contract} --input claim.hex\nor, once proved, with a tower: lichen export-dispute {contract} --input claim.hex --out package.json",
                        auth.display()
                    );
                }
                _ => println!("{outcome:?}; swept {swept:?}"),
            }
        }
        Cmd::Tower { .. } => unreachable!(),
        Cmd::ExportDispute { contract, ref out, ref input } => {
            let dir = a.wallet.with_extension("d");
            let program = a.statement.program_if(&dir)?;
            let mut claim = input.as_ref().map(|p| -> Result<Vec<u8>> { Ok(hex::decode(std::fs::read_to_string(p)?.trim())?) }).transpose()?;
            if let (Some(c), lichen_proto::Statement::Babe { mock: false }) = (&claim, &a.statement) {
                claim = Some(w.babe_claim_input(contract, c)?);
            }
            if claim.is_none() && matches!(a.statement, lichen_proto::Statement::Babe { mock: true }) {
                claim = Some(w.babe_mock_input(contract)?);
            }
            let p = w.export_dispute(&a.statement, program.as_ref(), contract, claim.as_deref())?;
            // a tower package holds the contract's one-time secrets
            lichen_ledger::files::write_private(out, &serde_json::to_vec_pretty(&p)?)?;
            if p.pi1.is_some() {
                // under BABE: her signatures, no key; the instances beside it
                let n = w.export_instances(&dir, contract, out)?;
                let to = lichen_wallet::tower::work_dir(out);
                println!("wrote {}: contract {contract}'s dispute (a claim of {} sats) for a tower; it holds her signatures, none of her keys. The kept instances, {} MiB, are in {}: copy it with the package", out.display(), p.b, n >> 20, to.display());
            } else {
                println!("wrote {}: contract {contract}'s dispute (a claim of {} sats) for a tower; it holds this contract's one-time secrets", out.display(), p.b);
            }
        }
        Cmd::SweepDispute { contract, ref tower_state } => {
            let s: lichen_wallet::tower::TowerState = serde_json::from_slice(&std::fs::read(tower_state)?).context("a tower's state")?;
            let (b, _) = s.claim.context("the tower made no claim")?;
            let outcome = s.payout.context("the tower's dispute has no payout")?;
            w.progress = Some(std::sync::Arc::new(|m: String| println!("{m}")));
            let (outcome, swept) = w.sweep_dispute(&chain(&a)?, &a.statement, &a.wallet.with_extension("d"), contract, b, outcome)?;
            println!("{outcome:?}; swept {swept:?}");
        }
        Cmd::Withdraw { contract, amount } => {
            w.progress = Some(std::sync::Arc::new(|m: String| println!("{m}")));
            match w.withdraw(&a.hub, &a.statement, &a.wallet.with_extension("d"), contract, amount) {
                Ok(txid) => println!("withdrew {amount} sats from contract {contract}: the fold is {txid}"),
                Err(e) => {
                    let open = w.contracts.iter().find(|h| h.record.cid() == contract && h.closed.is_none());
                    let (Some(h), Some(_)) = (open, w.returned(contract)) else { return Err(e) };
                    let height = chain(&a).and_then(|c| c.height()).ok();
                    eprintln!("Error: {e:#}\n\n{}", escalate_note(&a, contract, amount, h.record.terms.t_close, height));
                    std::process::exit(1);
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
    fn escalate_note_names_the_deadline_and_both_routes() {
        let a = Args::parse_from(["lichen", "--network", "mutinynet", "--statement", "groth16:v.yaml", "contracts"]);
        let n = escalate_note(&a, 1006, 22_000, 3_519_000, Some(3_514_050));
        println!("{n}");
        assert!(n.contains("by block 3519000") && n.contains("4950 blocks left, about 41.2 hours"));
        assert!(n.contains("lichen chain-receipt 1006 chain.receipt") && n.contains("lichen-r0 claim withdraw-input.json chain.receipt claim.hex") && n.contains("dispute 1006 22000 --input claim.hex") && n.contains("export-dispute 1006"));
        let late = escalate_note(&a, 1006, 22_000, 3_519_000, Some(3_519_001));
        assert!(late.contains("has passed") && late.contains("at once"));
        let mock = Args::parse_from(["lichen", "--network", "regtest", "contracts"]);
        let n = escalate_note(&mock, 7, 100, 50, None);
        println!("{n}");
        assert!(n.contains("lichen dispute 7 100\n") && !n.contains("--input") && !n.contains("Proving"));
    }
}
