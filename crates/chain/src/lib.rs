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
    pub fn confirmations(&self, txid: &Txid) -> Result<u32> {
        match self.rpc.get_raw_transaction_info(txid, None) {
            Ok(i) => Ok(i.confirmations.unwrap_or(0)),
            Err(_) => Ok(0),
        }
    }
}
