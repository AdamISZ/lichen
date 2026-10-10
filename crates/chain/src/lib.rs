//! A party's view of Bitcoin: its own wallet in a bitcoind, over RPC. The
//! wallet supplies coins and signs its own inputs of a jointly built
//! transaction (each party signs only its inputs, so neither needs the
//! other's keys); the node broadcasts and reports confirmations.

use std::path::Path;

use anyhow::{bail, Context, Result};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bitcoincore_rpc::json::{AddressType, SignRawTransactionInput};
use bitcoincore_rpc::{Auth, Client, RpcApi};

pub struct Chain {
    rpc: Client,
    pub wallet: String,
}

impl Chain {
    /// Connect to the node at `url` with its cookie, using (creating if
    /// needed) the wallet `wallet`.
    pub fn connect(url: &str, cookie: &Path, wallet: &str) -> Result<Chain> {
        let node = Client::new(url, Auth::CookieFile(cookie.to_path_buf())).context("the node")?;
        let loaded = node.list_wallets()?;
        if !loaded.iter().any(|w| w == wallet) && node.load_wallet(wallet).is_err() {
            node.create_wallet(wallet, None, None, None, None).with_context(|| format!("creating wallet {wallet}"))?;
        }
        let rpc = Client::new(&format!("{url}/wallet/{wallet}"), Auth::CookieFile(cookie.to_path_buf()))?;
        Ok(Chain { rpc, wallet: wallet.to_string() })
    }
    pub fn height(&self) -> Result<u32> {
        Ok(self.rpc.get_block_count()? as u32)
    }
    /// A fresh address of this wallet, as a script.
    pub fn new_spk(&self) -> Result<ScriptBuf> {
        Ok(self.rpc.get_new_address(None, Some(AddressType::Bech32m))?.require_network(Network::Regtest)?.script_pubkey())
    }
    pub fn balance(&self) -> Result<Amount> {
        Ok(self.rpc.get_balance(Some(1), None)?)
    }
    /// Confirmed coins covering `amount`, largest first.
    pub fn select(&self, amount: Amount) -> Result<Vec<(OutPoint, TxOut)>> {
        let mut coins = self.rpc.list_unspent(Some(1), None, None, Some(false), None)?;
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
            bail!("wallet {} has {total}, short of {amount}", self.wallet);
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
        let r = self.rpc.sign_raw_transaction_with_wallet(tx, Some(&utxos), None)?;
        Ok(r.transaction()?)
    }
    /// A coin of exactly `amount` (sent to ourselves, unconfirmed), to add
    /// to a transaction whose outputs are fixed: all of it is fee.
    pub fn fee_coin(&self, amount: Amount) -> Result<(OutPoint, TxOut)> {
        let addr = self.rpc.get_new_address(None, Some(AddressType::Bech32m))?.require_network(Network::Regtest)?;
        let txid = self.rpc.send_to_address(&addr, amount, None, None, None, None, None, None)?;
        let tx = self.rpc.get_raw_transaction(&txid, None)?;
        let vout = tx.output.iter().position(|o| o.script_pubkey == addr.script_pubkey()).context("the fee coin")?;
        Ok((OutPoint { txid, vout: vout as u32 }, tx.output[vout].clone()))
    }
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        Ok(self.rpc.send_raw_transaction(tx)?)
    }
    /// How many blocks have confirmed `txid` (0 if unconfirmed or unknown).
    /// Read from the raw JSON (the RPC crate's typed result can lag the
    /// node's script types).
    pub fn confirmations(&self, txid: &Txid) -> Result<u32> {
        let v: serde_json::Value = match self.rpc.call("getrawtransaction", &[serde_json::json!(txid.to_string()), serde_json::json!(true)]) {
            Ok(v) => v,
            Err(_) => return Ok(0),
        };
        Ok(v.get("confirmations").and_then(|c| c.as_u64()).unwrap_or(0) as u32)
    }
    /// A transaction by id (the node keeps a transaction index), if known.
    pub fn get_tx(&self, txid: &Txid) -> Option<Transaction> {
        self.rpc.get_raw_transaction(txid, None).ok()
    }
    /// Whether an outpoint is still unspent (in the chain or the mempool).
    pub fn unspent(&self, op: &OutPoint) -> Result<bool> {
        Ok(self.rpc.get_tx_out(&op.txid, op.vout, Some(true))?.is_some())
    }
    /// Broadcast a link of a pre-signed chain (unless it is already
    /// there): it pays a floor of its own, so it relays alone. Then its
    /// poster's child: it spends the link's anchor (output `anchor`, an
    /// output only the poster can spend; `sign_anchor` makes its witness,
    /// given the child and its prevouts) and a coin of this wallet, pays
    /// `feerate` sat/vB on both, and returns the change to the wallet.
    pub fn post_link(&self, link: &Transaction, anchor: u32, feerate: u64, sign_anchor: &dyn Fn(&Transaction, &[TxOut]) -> Result<bitcoin::Witness>) -> Result<()> {
        if self.get_tx(&link.compute_txid()).is_none() {
            self.broadcast(link).context("the link, at its floor")?;
        }
        let fee = Amount::from_sat((link.vsize() as u64 + 220) * feerate);
        let coins = self.select(fee + Amount::from_sat(1_000))?;
        let coin = coins[0].clone();
        let a_op = OutPoint { txid: link.compute_txid(), vout: anchor };
        let a_out = link.output[anchor as usize].clone();
        let change = TxOut { value: coin.1.value + a_out.value - fee, script_pubkey: self.new_spk()? };
        let mut child = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn { previous_output: a_op, sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME, ..Default::default() },
                bitcoin::TxIn { previous_output: coin.0, sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME, ..Default::default() },
            ],
            output: vec![change],
        };
        child = self.sign_mine(&child, &[(a_op, a_out.clone()), coin.clone()])?;
        child.input[0].witness = sign_anchor(&child, &[a_out, coin.1])?;
        self.broadcast(&child).context("the link's fee child")?;
        Ok(())
    }
    /// Broadcast a transaction that ends a chain (pre-signed
    /// ALL|ANYONECANPAY at zero fee, its input 0 spending `prevout`), adding
    /// a coin of `fee` from this wallet.
    pub fn post_terminal(&self, tx: &Transaction, prevout: &TxOut, fee: Amount) -> Result<Txid> {
        let (op, coin) = self.fee_coin(fee)?;
        let mut tx = tx.clone();
        tx.input.push(bitcoin::TxIn { previous_output: op, sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME, ..Default::default() });
        let tx = self.sign_mine(&tx, &[(tx.input[0].previous_output, prevout.clone()), (op, coin)])?;
        self.broadcast(&tx)
    }
}
