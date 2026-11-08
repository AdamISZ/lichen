//! The two HTTP agents against a server that never answers, one that
//! answers late, and one that answers once on a kept-alive connection
//! and then goes silent on it (`lichen_l2::http`): the quick one gives up
//! on silence, a second call included, and the slow one waits. About
//! 40 s: the quick agent's read timeout, then the late server's delay
//! past it.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use lichen_l2::http;

/// A server answering its one request after `delay` (never: `None`).
fn server(delay: Option<Duration>) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", l.local_addr().unwrap());
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf);
        match delay {
            Some(d) => {
                std::thread::sleep(d);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            }
            // the connection held open, silent, as one whose other end
            // has gone looks
            None => std::thread::sleep(Duration::from_secs(600)),
        }
    });
    url
}

/// A server answering its first request with the connection kept alive,
/// then reading the next request on it and never answering; any other
/// connection, refused (dropped at once).
fn answers_once() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", l.local_addr().unwrap());
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = s.read(&mut buf);
        let held = s;
        for c in l.incoming() {
            drop(c);
        }
        drop(held);
    });
    url
}

/// A second call to a server gone silent after answering a first: ureq 2
/// cleared a pooled connection's read timeout, so this waited for ever.
#[test]
fn quick_gives_up_on_a_second_call_too() {
    let once = answers_once();
    assert_eq!(http::quick().get(&once).call().unwrap().into_string().unwrap(), "ok");
    let start = Instant::now();
    let e = http::quick().get(&once).call().expect_err("a server answering one call only");
    assert!(start.elapsed() < http::QUICK + Duration::from_secs(10), "gave up after {:?}: {e}", start.elapsed());
}

#[test]
fn quick_gives_up_on_silence_and_slow_waits() {
    let silent = server(None);
    let late = server(Some(http::QUICK + Duration::from_secs(5)));
    let slow = std::thread::spawn(move || http::slow().get(&late).call().map(|r| r.into_string().unwrap()));

    let start = Instant::now();
    let e = http::quick().get(&silent).call().expect_err("a server that never answers");
    let took = start.elapsed();
    assert!(e.to_string().contains("timed out"), "{e}");
    assert!(took >= http::QUICK && took < http::QUICK + Duration::from_secs(10), "gave up after {took:?}");

    assert_eq!(slow.join().unwrap().expect("the late answer"), "ok");
}
