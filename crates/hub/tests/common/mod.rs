//! What the hub's tests share: a regtest node, a miner if asked, hubs on the
//! hub-proves mock statement. The grants L2 has no sequencer: a hub keeps
//! its notes in its book, and wallets talk to it alone.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_proto::Statement;
use lngap_btc::regtest::Regtest;

pub fn statement() -> Statement {
    Statement::HubProves { mock: true }
}

pub fn wait(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(start.elapsed() < Duration::from_secs(90), "{what}: timed out");
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub struct Env {
    pub rt: Regtest,
    pub dir: PathBuf,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Env {
    /// A node; `name` names the test's directory.
    pub fn new(name: &str) -> Env {
        let rt = Regtest::start_standard().unwrap();
        let dir = std::env::temp_dir().join(format!("lichen-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Env { rt, dir, stop: Arc::new(AtomicBool::new(false)), threads: vec![] }
    }

    fn background(&mut self, every: Duration, f: impl Fn() + Send + 'static) {
        let s = self.stop.clone();
        self.threads.push(std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                f();
                std::thread::sleep(every);
            }
        }));
    }

    /// A block every `every` from now on.
    pub fn mine_every(&mut self, every: Duration) {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", self.rt.rpc_url()), Auth::CookieFile(self.rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        self.background(every, move || {
            let _ = rpc.generate_to_address(1, &addr);
        });
    }

    /// `f`, with a block mined every 150 ms meanwhile.
    pub fn mining<T>(&self, f: impl FnOnce() -> T) -> T {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", self.rt.rpc_url()), Auth::CookieFile(self.rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let t = std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let _ = rpc.generate_to_address(1, &addr);
                std::thread::sleep(Duration::from_millis(150));
            }
        });
        let r = f();
        stop.store(true, Ordering::Relaxed);
        t.join().unwrap();
        r
    }

    pub fn chain(&self, wallet: &str) -> Chain {
        Chain::connect(self.rt.rpc_url(), self.rt.cookie(), wallet).unwrap()
    }

    /// A hub on bitcoind wallet `name` (funded with a coin), its config
    /// the tests' but for `f`'s changes.
    pub fn hub(&self, name: &str, f: impl FnOnce(&mut Config)) -> Hub {
        self.rt.fund(&self.chain(name).new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
        let mut cfg = Config {
            network: lichen_proto::Net::Regtest,
            listen: "127.0.0.1:0".into(),
            rpc_url: self.rt.rpc_url().to_string(),
            cookie: self.rt.cookie().clone(),
            wallet: name.into(),
            statement: statement(),
            dir: self.dir.join(name),
            seed: format!("test-{name}"),
            l2_key: lichen_ledger::regtest_hub(),
            reserve_ppm: 20_000,
            fee_ppm: 0,
            max_liquidity: 10_000_000,
            duration: 2_000,
            refuse_folds: false,
            forge_assertions: false,
            first_cid: 1000,
        };
        f(&mut cfg);
        Hub::start(cfg).unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A payment of `amount` from `a` to `b`, both online: each party's steps
/// in turn until both are done (or `release` off: both signed, the seed
/// withheld, both in flight).
pub fn pay(a: &mut lichen_wallet::Wallet, b: &mut lichen_wallet::Wallet, amount: u64) -> anyhow::Result<String> {
    use lichen_wallet::notes::Step;
    let id = a.pay(b.address(), amount)?;
    let got = b.receive()?;
    anyhow::ensure!(got.as_deref() == Some(id.as_str()), "the payee took {got:?}, not {id}");
    let (mut a_done, mut b_done) = (false, false);
    for _ in 0..6 {
        for s in a.progress()? {
            a_done |= matches!(s, Step::Done(..));
        }
        for s in b.progress()? {
            b_done |= matches!(s, Step::Done(..));
        }
        if a_done && b_done {
            break;
        }
    }
    Ok(id)
}
