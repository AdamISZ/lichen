//! What the hub's tests share: a regtest node, an anchored deployment (the
//! sequencer's genesis seal paid, its history anchored if asked), a
//! sealer, a miner if asked, hubs on the hub-proves mock statement.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_l2::Client;
use lichen_ledger::{regtest_sequencer, xonly, HUB_KEY};
use lichen_proto::Statement;
use lichen_sequencer::anchor::{genesis_seal, Anchoring};
use lichen_sequencer::{Options, Sequencer};
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
    pub seq: Sequencer,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Env {
    /// A node, and the sequencer with its genesis seal paid, sealing every
    /// 200 ms; `name` names its directory.
    pub fn new(name: &str) -> Env {
        let rt = Regtest::start_standard().unwrap();
        let dir = std::env::temp_dir().join(format!("lichen-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let chain = Chain::connect(rt.rpc_url(), rt.cookie(), "sequencer").unwrap();
        rt.fund(&chain.new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
        rt.mine(1).unwrap();
        let key = regtest_sequencer();
        let seal = genesis_seal(&chain, &xonly(&key)).unwrap();
        rt.mine(1).unwrap();
        let seq = Sequencer::start_with("127.0.0.1:0", Some(dir.join("ledger.json")), key, HUB_KEY, Options { native_proofs: true, seal: Some(seal) }).unwrap();
        let mut env = Env { rt, dir, seq, stop: Arc::new(AtomicBool::new(false)), threads: vec![] };
        let url = env.seq.url.clone();
        env.background(Duration::from_millis(200), move || {
            let _ = Client::new(&url).and_then(|c| c.seal());
        });
        env
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

    /// The sequencer anchors its history from now on.
    pub fn anchor(&mut self) {
        self.seq.anchor(self.chain("sequencer"), Anchoring { every: Duration::from_millis(100), confirmations: lichen_proto::hp::margin(lichen_proto::Net::Regtest), ..Default::default() }).unwrap();
    }

    /// A block every `every` from now on.
    pub fn mine_every(&mut self, every: Duration) {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", self.rt.rpc_url()), Auth::CookieFile(self.rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        self.background(every, move || {
            let _ = rpc.generate_to_address(1, &addr);
        });
    }

    /// Acknowledge `w`'s spends (`Wallet::acknowledge`), a block mined
    /// each step, until none waits: an anchor, its confirmations.
    pub fn acknowledge(&self, w: &mut lichen_wallet::Wallet, ch: &Chain) {
        let start = Instant::now();
        while w.acknowledge(ch).unwrap() > 0 {
            assert!(start.elapsed() < Duration::from_secs(120), "spends unacknowledged: timed out");
            self.rt.mine(1).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        }
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
            sequencer: self.seq.url.clone(),
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
