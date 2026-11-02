//! The listener through an error accepting a connection: tiny_http's ends
//! for good at one (on the Mutinynet hub, 2026-11-02, the sequencer
//! answered nothing for hours while it went on sealing), and the sequencer
//! listens again. Its own test binary: it lowers the process's limit on
//! open files.

#![cfg(unix)]

use std::fs::File;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_sequencer::Sequencer;

#[test]
fn the_listener_comes_back_after_an_accept_error() {
    let s = Sequencer::start("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY).unwrap();
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(2)).build();
    let info = format!("{}/info", s.url);
    agent.get(&info).call().expect("serving");

    // every file descriptor taken, then one freed for a client's socket:
    // the listener can't accept its connection (too many open files)
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
    let low = libc::rlimit { rlim_cur: lim.rlim_cur.min(256), rlim_max: lim.rlim_max };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &low) }, 0);
    let mut files = vec![];
    while let Ok(f) = File::open("/dev/null") {
        files.push(f);
    }
    files.pop();
    let client = TcpStream::connect(s.url.trim_start_matches("http://")).expect("a connection, in the listener's queue");
    std::thread::sleep(Duration::from_millis(500));
    drop(files);
    drop(client);
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) }, 0);

    let start = Instant::now();
    while agent.get(&info).call().is_err() {
        assert!(start.elapsed() < Duration::from_secs(10), "the sequencer doesn't answer again");
        std::thread::sleep(Duration::from_millis(200));
    }
}
