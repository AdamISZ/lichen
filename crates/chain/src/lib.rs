//! A party's view of Bitcoin, over one of two backends:
//!
//! - a bitcoind over RPC, with a wallet there (the hub's, and the tests'):
//!   it supplies coins and signs its own inputs of a jointly built
//!   transaction (each party signs only its inputs, so neither needs the
//!   other's keys);
//! - an Esplora server (a user's: no node, and no wallet; see [`Fees`]).
//!
//! Either answers the queries both parties' code makes (height,
//! confirmations, transactions, spentness, a script's coins) and
//! broadcasts.

pub mod electrs;

use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use bitcoin::{Amount, Network, OutPoint, Script, ScriptBuf, Transaction, TxOut, Txid};
use bitcoincore_rpc::json::{AddressType, SignRawTransactionInput};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use esplora_client::BlockingClient;
use serde::{Deserialize, Serialize};

/// The Bitcoin network lichen runs on: its address network, its block
/// time's waits, its public Esplora. (The contracts' timing on it is
/// `lichen_proto::params`.)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Net {
    /// A local regtest, mined as fast as the tests like.
    #[default]
    Regtest,
    /// Mutinynet: a signet with 30-second blocks (a patched bitcoind).
    Mutinynet,
    /// The default signet: 10-minute blocks, stock Bitcoin Core.
    Signet,
    /// Testnet4: nominally 10-minute blocks, in practice in bursts.
    Testnet4,
}

impl std::str::FromStr for Net {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Net> {
        match s {
            "regtest" => Ok(Net::Regtest),
            "mutinynet" => Ok(Net::Mutinynet),
            "signet" => Ok(Net::Signet),
            "testnet4" => Ok(Net::Testnet4),
            _ => bail!("a network is regtest, mutinynet, signet or testnet4"),
        }
    }
}

impl std::fmt::Display for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Net::Regtest => "regtest",
            Net::Mutinynet => "mutinynet",
            Net::Signet => "signet",
            Net::Testnet4 => "testnet4",
        })
    }
}

impl Net {
    /// The address network (Mutinynet is a signet).
    pub fn bitcoin(&self) -> Network {
        match self {
            Net::Regtest => Network::Regtest,
            Net::Mutinynet | Net::Signet => Network::Signet,
            Net::Testnet4 => Network::Testnet4,
        }
    }
    /// How many blocks a confirmation may take before a wait gives up
    /// (with [`Patience`]'s time also passed).
    pub fn patience_blocks(&self) -> u32 {
        match self {
            Net::Regtest => 50,
            Net::Mutinynet => 40,
            Net::Signet => 6,
            Net::Testnet4 => 12,
        }
    }
    /// How long without a new block counts as a stalled chain, in seconds.
    pub fn stall_secs(&self) -> u64 {
        match self {
            Net::Regtest => 300,
            Net::Mutinynet => 1_800,
            Net::Signet => 3_600,
            Net::Testnet4 => 7_200,
        }
    }
    /// The public Esplora (mempool.space's, or Mutinynet's own).
    pub fn default_esplora(&self) -> Option<&'static str> {
        match self {
            Net::Regtest => None,
            Net::Mutinynet => Some("https://mutinynet.com/api"),
            Net::Signet => Some("https://mempool.space/signet/api"),
            Net::Testnet4 => Some("https://mempool.space/testnet4/api"),
        }
    }
}

/// A bounded wait for a confirmation: it expires once the network's
/// [`Net::patience_blocks`] *and* five minutes have passed since it
/// began, so that slow blocks don't trip it and a fast regtest still
/// fails in reasonable time.
pub struct Patience {
    start: std::time::Instant,
    height: u32,
    blocks: u32,
}

impl Patience {
    pub fn new(height: u32, net: Net) -> Patience {
        Patience { start: std::time::Instant::now(), height, blocks: net.patience_blocks() }
    }
    pub fn expired(&self, height: u32) -> bool {
        height >= self.height + self.blocks && self.start.elapsed().as_secs() >= 300
    }
}

/// A watchdog on the chain itself: stalled once no new block has come
/// for the network's [`Net::stall_secs`]. For waits already bounded by a
/// height (a deadline, a depth), which may rightly take many blocks.
pub struct Stall {
    height: u32,
    since: std::time::Instant,
    secs: u64,
}

impl Stall {
    pub fn new(height: u32, net: Net) -> Stall {
        Stall { height, since: std::time::Instant::now(), secs: net.stall_secs() }
    }
    pub fn stalled(&mut self, height: u32) -> bool {
        if height != self.height {
            (self.height, self.since) = (height, std::time::Instant::now());
            return false;
        }
        self.since.elapsed().as_secs() >= self.secs
    }
}

enum Backend {
    Rpc { rpc: Client, wallet: String, url: String, cookie: std::path::PathBuf },
    Esplora(BlockingClient),
}

pub struct Chain {
    backend: Backend,
    /// The network it is on.
    pub network: Net,
}

/// Where a party's fee coins come from: the coin a link's child (CPFP)
/// spends beside its anchor, and the exact coin added to a terminal
/// transaction (pre-signed ALL|ANYONECANPAY, its outputs fixed, so all of
/// it is fee). A bitcoind wallet ([`NodeWallet`]), or a contract's fee
/// budget (the user's: one coin, spent as a chain).
pub trait Fees {
    /// A coin worth at least `amount`, to spend whole (change goes back to
    /// [`Fees::change`]).
    fn coin(&self, chain: &Chain, amount: Amount) -> Result<(OutPoint, TxOut)>;
    /// A coin worth exactly `amount`.
    fn exact_coin(&self, chain: &Chain, amount: Amount) -> Result<(OutPoint, TxOut)>;
    /// Where change goes.
    fn change(&self, chain: &Chain) -> Result<ScriptBuf>;
    /// `tx` with this source's inputs signed (`prevouts`: every input's).
    fn sign(&self, chain: &Chain, tx: &Transaction, prevouts: &[(OutPoint, TxOut)]) -> Result<Transaction>;
}

/// The fees of a party with a bitcoind wallet: its coins.
pub struct NodeWallet;

impl Fees for NodeWallet {
    fn coin(&self, chain: &Chain, amount: Amount) -> Result<(OutPoint, TxOut)> {
        let mut coins = chain.select(amount)?;
        ensure!(coins.len() == 1, "no single coin of {amount} in wallet {}", chain.wallet_name()?);
        Ok(coins.remove(0))
    }
    fn exact_coin(&self, chain: &Chain, amount: Amount) -> Result<(OutPoint, TxOut)> {
        chain.fee_coin(amount)
    }
    fn change(&self, chain: &Chain) -> Result<ScriptBuf> {
        chain.new_spk()
    }
    fn sign(&self, chain: &Chain, tx: &Transaction, prevouts: &[(OutPoint, TxOut)]) -> Result<Transaction> {
        chain.sign_mine(tx, prevouts)
    }
}

/// Fees from coins of one key, as a single-key P2TR output (key path,
/// no scripts): the user's fee budget for a contract. Its coins are found
/// by script ([`Chain::coins_of`]), so a chain of children each spending
/// the last one's change needs no bookkeeping.
pub struct KeyFees {
    pub keypair: bitcoin::key::Keypair,
    /// sat/vB for the split [`Fees::exact_coin`] makes.
    pub feerate: u64,
}

impl KeyFees {
    pub fn spk(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr(&bitcoin::secp256k1::Secp256k1::verification_only(), self.keypair.x_only_public_key().0, None)
    }
    /// What the budget holds.
    pub fn balance(&self, chain: &Chain) -> Result<Amount> {
        Ok(chain.coins_of(&self.spk())?.iter().map(|c| c.1.value).sum())
    }
}

impl Fees for KeyFees {
    /// Waits up to 30 s for one: an index (Esplora's) may not yet show the
    /// change of the child just posted.
    fn coin(&self, chain: &Chain, amount: Amount) -> Result<(OutPoint, TxOut)> {
        let start = std::time::Instant::now();
        loop {
            let coins = chain.coins_of(&self.spk())?;
            if let Some(c) = coins.iter().filter(|c| c.1.value >= amount).max_by_key(|c| c.1.value) {
                return Ok((c.0, c.1.clone()));
            }
            if start.elapsed() > std::time::Duration::from_secs(30) {
                bail!("the fee budget has {}, no coin of {amount}", coins.iter().map(|c| c.1.value).sum::<Amount>());
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    fn exact_coin(&self, chain: &Chain, amount: Amount) -> Result<(OutPoint, TxOut)> {
        // split a coin: `amount` and the change, both back to the budget
        let fee = Amount::from_sat(160 * self.feerate);
        let dust = Amount::from_sat(330);
        let (op, out) = self.coin(chain, amount + fee + dust)?;
        let spk = self.spk();
        let split = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn { previous_output: op, sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME, ..Default::default() }],
            output: vec![TxOut { value: amount, script_pubkey: spk.clone() }, TxOut { value: out.value - amount - fee, script_pubkey: spk }],
        };
        let split = self.sign(chain, &split, &[(op, out)])?;
        let txid = chain.broadcast(&split).context("splitting a fee coin")?;
        Ok((OutPoint { txid, vout: 0 }, split.output[0].clone()))
    }
    fn change(&self, _: &Chain) -> Result<ScriptBuf> {
        Ok(self.spk())
    }
    fn sign(&self, _: &Chain, tx: &Transaction, prevouts: &[(OutPoint, TxOut)]) -> Result<Transaction> {
        use bitcoin::hashes::Hash;
        use bitcoin::key::TapTweak;
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        let spk = self.spk();
        let outs: Vec<TxOut> = prevouts.iter().map(|p| p.1.clone()).collect();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let tweaked = self.keypair.tap_tweak(&secp, None).to_keypair();
        let mut tx = tx.clone();
        for i in 0..tx.input.len() {
            if outs.get(i).map(|o| &o.script_pubkey) != Some(&spk) {
                continue;
            }
            let h = SighashCache::new(&tx).taproot_key_spend_signature_hash(i, &Prevouts::All(&outs), TapSighashType::Default)?;
            let msg = bitcoin::secp256k1::Message::from_digest(h.to_byte_array());
            let sig = secp.sign_schnorr(&msg, &tweaked);
            tx.input[i].witness = bitcoin::Witness::from_slice(&[sig.as_ref().to_vec()]);
        }
        Ok(tx)
    }
}

impl Chain {
    /// Connect to a regtest node at `url` with its cookie, using (creating
    /// if needed) the wallet `wallet`.
    pub fn connect(url: &str, cookie: &Path, wallet: &str) -> Result<Chain> {
        Chain::connect_on(url, cookie, wallet, Net::Regtest)
    }
    /// The same, on `network`.
    pub fn connect_on(url: &str, cookie: &Path, wallet: &str, network: Net) -> Result<Chain> {
        let node = Client::new(url, Auth::CookieFile(cookie.to_path_buf())).context("the node")?;
        let loaded = node.list_wallets()?;
        if !loaded.iter().any(|w| w == wallet) && node.load_wallet(wallet).is_err() {
            node.create_wallet(wallet, None, None, None, None).with_context(|| format!("creating wallet {wallet}"))?;
        }
        let rpc = Client::new(&format!("{url}/wallet/{wallet}"), Auth::CookieFile(cookie.to_path_buf()))?;
        Ok(Chain { backend: Backend::Rpc { rpc, wallet: wallet.to_string(), url: url.to_string(), cookie: cookie.to_path_buf() }, network })
    }
    /// An Esplora server at `url` (e.g. `https://mutinynet.com/api`), on
    /// `network`. No wallet: fees come from a [`Fees`] of the caller's.
    pub fn esplora(url: &str, network: Net) -> Result<Chain> {
        let client = esplora_client::Builder::new(url.trim_end_matches('/')).build_blocking();
        client.get_height().with_context(|| format!("no Esplora answering at {url}"))?;
        Ok(Chain { backend: Backend::Esplora(client), network })
    }

    fn rpc(&self) -> Result<&Client> {
        match &self.backend {
            Backend::Rpc { rpc, .. } => Ok(rpc),
            Backend::Esplora(_) => bail!("the Esplora backend has no wallet"),
        }
    }
    fn wallet_name(&self) -> Result<&str> {
        match &self.backend {
            Backend::Rpc { wallet, .. } => Ok(wallet),
            Backend::Esplora(_) => bail!("the Esplora backend has no wallet"),
        }
    }

    // ----- queries and broadcast: either backend -----

    pub fn height(&self) -> Result<u32> {
        match &self.backend {
            Backend::Rpc { rpc, .. } => Ok(rpc.get_block_count()? as u32),
            Backend::Esplora(e) => Ok(e.get_height()?),
        }
    }
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        match &self.backend {
            Backend::Rpc { rpc, .. } => Ok(rpc.send_raw_transaction(tx)?),
            Backend::Esplora(e) => Ok(e.broadcast(tx)?),
        }
    }
    /// How many blocks have confirmed `txid` (0 if unconfirmed or unknown).
    pub fn confirmations(&self, txid: &Txid) -> Result<u32> {
        match &self.backend {
            // read from the raw JSON (the RPC crate's typed result can lag
            // the node's script types)
            Backend::Rpc { rpc, .. } => {
                let v: serde_json::Value = match rpc.call("getrawtransaction", &[serde_json::json!(txid.to_string()), serde_json::json!(true)]) {
                    Ok(v) => v,
                    Err(_) => return Ok(0),
                };
                Ok(v.get("confirmations").and_then(|c| c.as_u64()).unwrap_or(0) as u32)
            }
            Backend::Esplora(e) => match e.get_tx_status(txid)? {
                esplora_client::TxStatus { confirmed: true, block_height: Some(h), .. } => Ok(self.height()? + 1 - h),
                _ => Ok(0),
            },
        }
    }
    /// A transaction by id (in the chain or the mempool), if known.
    pub fn get_tx(&self, txid: &Txid) -> Option<Transaction> {
        match &self.backend {
            // the node keeps a transaction index
            Backend::Rpc { rpc, .. } => rpc.get_raw_transaction(txid, None).ok(),
            Backend::Esplora(e) => e.get_tx(txid).ok().flatten(),
        }
    }
    /// Whether an outpoint is still unspent (in the chain or the mempool).
    pub fn unspent(&self, op: &OutPoint) -> Result<bool> {
        match &self.backend {
            Backend::Rpc { rpc, .. } => Ok(rpc.get_tx_out(&op.txid, op.vout, Some(true))?.is_some()),
            Backend::Esplora(e) => {
                ensure!(e.get_tx(&op.txid)?.is_some_and(|t| t.output.len() > op.vout as usize), "no output {op}");
                Ok(!e.get_output_status(&op.txid, u64::from(op.vout))?.is_some_and(|s| s.spent))
            }
        }
    }
    /// The node's watch-only wallet (RPC): the scripts [`Chain::watch`]
    /// asked for, whoever's they are.
    fn watcher(&self) -> Result<Client> {
        let Backend::Rpc { url, cookie, .. } = &self.backend else { bail!("no node") };
        let node = Client::new(url, Auth::CookieFile(cookie.clone()))?;
        const W: &str = "lichen-watch";
        if !node.list_wallets()?.iter().any(|w| w == W) && node.load_wallet(W).is_err() {
            node.create_wallet(W, Some(true), Some(true), None, None).context("creating the watch-only wallet")?;
        }
        Ok(Client::new(&format!("{url}/wallet/{W}"), Auth::CookieFile(cookie.clone()))?)
    }
    /// Track a script's coins from now on, for [`Chain::coins_of`]: on RPC,
    /// a watch-only descriptor (coins paid before this aren't seen); on
    /// Esplora nothing is needed.
    pub fn watch(&self, spk: &Script) -> Result<()> {
        if let Backend::Esplora(_) = self.backend {
            return Ok(());
        }
        let w = self.watcher()?;
        let info: serde_json::Value = w.call("getdescriptorinfo", &[serde_json::json!(format!("raw({})", spk.to_hex_string()))])?;
        let desc = info["descriptor"].as_str().context("a descriptor")?;
        let r: serde_json::Value = w.call("importdescriptors", &[serde_json::json!([{ "desc": desc, "timestamp": "now" }])])?;
        ensure!(r[0]["success"].as_bool() == Some(true), "importing {desc}: {r}");
        Ok(())
    }
    /// The unspent coins of a script, confirmed or not (spent in the
    /// mempool counts as spent), with the height each confirmed at: the
    /// user's deposit and fee coins. On RPC, the script must be watched.
    pub fn coins_of(&self, spk: &Script) -> Result<Vec<(OutPoint, TxOut, Option<u32>)>> {
        match &self.backend {
            Backend::Rpc { .. } => {
                let tip = self.height()?;
                let addr = bitcoin::Address::from_script(spk, self.network.bitcoin())?;
                let coins = self.watcher()?.list_unspent(Some(0), None, Some(&[&addr]), Some(true), None)?;
                Ok(coins
                    .into_iter()
                    .map(|c| (OutPoint { txid: c.txid, vout: c.vout }, TxOut { value: c.amount, script_pubkey: spk.to_owned() }, (c.confirmations > 0).then(|| tip + 1 - c.confirmations)))
                    .collect())
            }
            Backend::Esplora(e) => Ok(e
                .get_scripthash_utxos(spk)?
                .into_iter()
                .map(|u| (OutPoint { txid: u.txid, vout: u.vout }, TxOut { value: u.value, script_pubkey: spk.to_owned() }, u.status.block_height.filter(|_| u.status.confirmed)))
                .collect()),
        }
    }

    // ----- a bitcoind wallet's coins: RPC only -----

    /// A fresh address of this wallet, as a script.
    pub fn new_spk(&self) -> Result<ScriptBuf> {
        Ok(self.rpc()?.get_new_address(None, Some(AddressType::Bech32m))?.require_network(self.network.bitcoin())?.script_pubkey())
    }
    pub fn balance(&self) -> Result<Amount> {
        Ok(self.rpc()?.get_balance(Some(1), None)?)
    }
    /// Confirmed coins covering `amount`, largest first.
    pub fn select(&self, amount: Amount) -> Result<Vec<(OutPoint, TxOut)>> {
        let mut coins = self.rpc()?.list_unspent(Some(1), None, None, Some(false), None)?;
        coins.sort_by_key(|c| std::cmp::Reverse(c.amount));
        let (mut out, mut total) = (vec![], Amount::ZERO);
        for c in coins {
            if total >= amount {
                break;
            }
            total += c.amount;
            out.push((OutPoint { txid: c.txid, vout: c.vout }, TxOut { value: c.amount, script_pubkey: c.script_pub_key }));
        }
        if total < amount {
            bail!("wallet {} has {total}, short of {amount}", self.wallet_name()?);
        }
        Ok(out)
    }
    /// Sign this wallet's inputs of `tx` (whose inputs spend `prevouts`),
    /// leaving the others as they are.
    pub fn sign_mine(&self, tx: &Transaction, prevouts: &[(OutPoint, TxOut)]) -> Result<Transaction> {
        let utxos: Vec<SignRawTransactionInput> = prevouts
            .iter()
            .map(|(op, o)| SignRawTransactionInput { txid: op.txid, vout: op.vout, script_pub_key: o.script_pubkey.clone(), redeem_script: None, amount: Some(o.value) })
            .collect();
        let r = self.rpc()?.sign_raw_transaction_with_wallet(tx, Some(&utxos), None)?;
        Ok(r.transaction()?)
    }
    /// Pay `amount` to `spk` from this wallet (tests: a user paying a
    /// deposit address from a wallet of her own).
    pub fn pay(&self, spk: &Script, amount: Amount) -> Result<Txid> {
        let addr = bitcoin::Address::from_script(spk, self.network.bitcoin())?;
        Ok(self.rpc()?.send_to_address(&addr, amount, None, None, None, None, None, None)?)
    }
    /// A coin of exactly `amount` (sent to ourselves, unconfirmed), to add
    /// to a transaction whose outputs are fixed: all of it is fee.
    pub fn fee_coin(&self, amount: Amount) -> Result<(OutPoint, TxOut)> {
        let rpc = self.rpc()?;
        let addr = rpc.get_new_address(None, Some(AddressType::Bech32m))?.require_network(self.network.bitcoin())?;
        let txid = rpc.send_to_address(&addr, amount, None, None, None, None, None, None)?;
        let tx = rpc.get_raw_transaction(&txid, None)?;
        let vout = tx.output.iter().position(|o| o.script_pubkey == addr.script_pubkey()).context("the fee coin")?;
        Ok((OutPoint { txid, vout: vout as u32 }, tx.output[vout].clone()))
    }

    // ----- posting a dispute's links: either backend, fees from `fees` -----

    /// Broadcast a link of a pre-signed chain (unless it is already
    /// there): it pays a floor of its own (1 sat/vB), so it relays alone.
    /// Above that floor, its poster's child: it spends the link's anchor
    /// (output `anchor`, an output only the poster can spend; `sign_anchor`
    /// makes its witness, given the child and its prevouts) and a coin from
    /// `fees`, brings the pair to `feerate` sat/vB (crediting the link's
    /// floor), and returns the change to `fees`. At `feerate` 1 there is no
    /// child.
    pub fn post_link(&self, link: &Transaction, anchor: u32, feerate: u64, sign_anchor: &dyn Fn(&Transaction, &[TxOut]) -> Result<bitcoin::Witness>, fees: &dyn Fees) -> Result<()> {
        if self.get_tx(&link.compute_txid()).is_none() {
            self.broadcast(link).context("the link, at its floor")?;
        }
        if feerate <= 1 {
            return Ok(());
        }
        let fee = Amount::from_sat((link.vsize() as u64 + 220) * feerate - link.vsize() as u64);
        let coin = fees.coin(self, fee + Amount::from_sat(1_000))?;
        let a_op = OutPoint { txid: link.compute_txid(), vout: anchor };
        let a_out = link.output[anchor as usize].clone();
        let change = TxOut { value: coin.1.value + a_out.value - fee, script_pubkey: fees.change(self)? };
        let mut child = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn { previous_output: a_op, sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME, ..Default::default() },
                bitcoin::TxIn { previous_output: coin.0, sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME, ..Default::default() },
            ],
            output: vec![change],
        };
        child = fees.sign(self, &child, &[(a_op, a_out.clone()), coin.clone()])?;
        child.input[0].witness = sign_anchor(&child, &[a_out, coin.1])?;
        self.broadcast(&child).context("the link's fee child")?;
        Ok(())
    }
    /// Broadcast a transaction that ends a chain (pre-signed
    /// ALL|ANYONECANPAY at zero fee, its input 0 spending `prevout`), adding
    /// a coin of exactly `fee` from `fees`.
    pub fn post_terminal(&self, tx: &Transaction, prevout: &TxOut, fee: Amount, fees: &dyn Fees) -> Result<Txid> {
        let (op, coin) = fees.exact_coin(self, fee)?;
        let mut tx = tx.clone();
        tx.input.push(bitcoin::TxIn { previous_output: op, sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME, ..Default::default() });
        let tx = fees.sign(self, &tx, &[(tx.input[0].previous_output, prevout.clone()), (op, coin)])?;
        self.broadcast(&tx)
    }
}
