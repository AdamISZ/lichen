//! An Esplora server for tests: Blockstream's electrs (the Esplora REST
//! API, as mutinynet.com/api and mempool.space serve it) on a regtest
//! node's data directory. The binary is `LICHEN_ELECTRS`, or `electrs` on
//! the PATH (github.com/Blockstream/electrs, branch new-index).

use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

fn free_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

/// A running electrs; stopped when dropped.
pub struct Electrs {
    child: Child,
    /// Its Esplora REST API.
    pub url: String,
    db: tempdir::Dir,
}

mod tempdir {
    /// A directory removed when dropped.
    pub struct Dir(pub std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

impl Electrs {
    /// Index the regtest node whose data directory is `datadir` (its
    /// cookie there) and whose RPC is `rpc_url`, and wait until the REST
    /// API answers at the node's height.
    pub fn start(datadir: &Path, rpc_url: &str) -> Result<Electrs> {
        let bin = std::env::var("LICHEN_ELECTRS").unwrap_or_else(|_| "electrs".into());
        let rpc_addr = rpc_url.trim_start_matches("http://").trim_end_matches('/').to_string();
        let (http, electrum, monitoring) = (free_port()?, free_port()?, free_port()?);
        let db = tempdir::Dir(std::env::temp_dir().join(format!("lichen-electrs-{}-{http}", std::process::id())));
        let child = Command::new(&bin)
            .args(["--network", "regtest", "--jsonrpc-import"])
            .arg("--daemon-dir")
            .arg(datadir)
            .args(["--daemon-rpc-addr", &rpc_addr])
            .arg("--db-dir")
            .arg(&db.0)
            .args(["--http-addr", &format!("127.0.0.1:{http}")])
            .args(["--electrum-rpc-addr", &format!("127.0.0.1:{electrum}")])
            .args(["--monitoring-addr", &format!("127.0.0.1:{monitoring}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("starting {bin} (set LICHEN_ELECTRS, or put electrs on the PATH)"))?;
        let mut e = Electrs { child, url: format!("http://127.0.0.1:{http}"), db };
        e.wait_synced(datadir, rpc_url)?;
        Ok(e)
    }

    /// Wait until the REST API's tip is the node's.
    pub fn wait_synced(&mut self, datadir: &Path, rpc_url: &str) -> Result<()> {
        use bitcoincore_rpc::RpcApi;
        let node = bitcoincore_rpc::Client::new(rpc_url, bitcoincore_rpc::Auth::CookieFile(datadir.join("regtest").join(".cookie")))?;
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait()? {
                bail!("electrs exited: {status}");
            }
            let want = node.get_block_count()?;
            let got = ureq_height(&self.url);
            if got == Some(want) {
                return Ok(());
            }
            if start.elapsed() > Duration::from_secs(60) {
                bail!("electrs at {} never reached height {want} (at {got:?})", self.url);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

fn ureq_height(url: &str) -> Option<u64> {
    let client = esplora_client::Builder::new(url).build_blocking();
    client.get_height().ok().map(u64::from)
}

impl Drop for Electrs {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = &self.db;
    }
}
