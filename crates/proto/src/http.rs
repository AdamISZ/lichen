//! The HTTP agents lichen's clients use. Without timeouts, a call whose
//! server end has gone waits for ever: on 2026-11-03 a GUI's refresh hung
//! in `GET /state` holding its wallet, and a payment queued behind it did
//! nothing. A read timeout is per read, so a long response that keeps
//! arriving (a BABE instance) is never cut off.
//!
//! Neither agent keeps a connection for reuse: ureq 2 sets the read
//! timeout on a connection it opens and clears it on one it returns to
//! its pool, so a reused connection had none, and a call on it to a
//! server gone silent (a VPS powered off, a process alive but not
//! answering) waited for ever (seen on 2026-11-08, an exit's test reading
//! a sequencer it had stopped). A connection a call, then: a TCP
//! handshake each, nothing beside a call's own time.

use std::sync::OnceLock;
use std::time::Duration;

const CONNECT: Duration = Duration::from_secs(10);
/// The longest silence in a quick call's request or response.
pub const QUICK: Duration = Duration::from_secs(30);

/// For a call the server answers at once: the sequencer's, a hub's
/// `/info`, the reads a wallet repeats.
pub fn quick() -> &'static ureq::Agent {
    static A: OnceLock<ureq::Agent> = OnceLock::new();
    A.get_or_init(|| ureq::AgentBuilder::new().timeout_connect(CONNECT).timeout_read(QUICK).timeout_write(QUICK).max_idle_connections(0).build())
}
/// For a call the server works on before it answers (a hub's BABE
/// setup, an instance it builds again, an opening, a fold): a timeout
/// to connect, then as long as it takes. These run inside an
/// operation, its progress shown.
pub fn slow() -> &'static ureq::Agent {
    static A: OnceLock<ureq::Agent> = OnceLock::new();
    A.get_or_init(|| ureq::AgentBuilder::new().timeout_connect(CONNECT).max_idle_connections(0).build())
}
