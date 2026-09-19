//! monitor-agent: reports one Linux host to a monitor hub over WebSocket.

mod collect;

use std::time::Duration;

// Shares the clock `tokio::time::timeout` and `sleep` read, so deadline
// arithmetic cannot drift from the timers enforcing it, and tests can advance
// it. Outside a paused runtime this is the monotonic clock.
use tokio::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use futures_util::{Sink, SinkExt, StreamExt};
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use collect::Collector;

struct Args {
    server: String,
    token: String,
    interval: u64,
    ifaces: collect::Ifaces,
    /// Permits plain HTTP to a hub reached at ip:port with no TLS in front.
    /// Off by default: the token would otherwise travel in the clear.
    insecure: bool,
}

fn usage() -> ! {
    eprintln!(
        "monitor-agent {}\n\n\
         Usage: monitor-agent --server <url> --token <token> [options]\n\n\
         Options:\n  \
           --server <url>       Hub base URL, e.g. https://hub.example.com\n  \
           --token <token>      Node token from the hub panel\n  \
           --interval <secs>    Report interval (default 1)\n  \
           --iface <list>       Count traffic on these interfaces alone, e.g.\n                       \
                                eth1,pppoe-wan. `-name` removes an interface\n                       \
                                from what would be counted. Full names only.\n  \
           --insecure           Allow plain ws:// to a remote hub; the token\n                       \
                                travels in the clear. Only for a hub reached\n                       \
                                at ip:port with no TLS in front.\n",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(2)
}

fn parse_args() -> Result<Args> {
    let (mut server, mut token, mut interval, mut iface, mut insecure) = (None, None, 1u64, None, false);
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--server" => server = Some(value()),
            "--token" => token = Some(value()),
            "--interval" => interval = value().parse().unwrap_or_else(|_| usage()),
            "--iface" => iface = Some(value()),
            "--insecure" => insecure = true,
            "-h" | "--help" => usage(),
            other => bail!("unknown argument: {other}"),
        }
    }
    let server = server.or_else(|| std::env::var("MONITOR_SERVER").ok()).unwrap_or_else(|| usage());
    let token = token.or_else(|| std::env::var("MONITOR_TOKEN").ok()).unwrap_or_else(|| usage());
    let iface = iface.or_else(|| std::env::var("MONITOR_IFACE").ok()).unwrap_or_default();
    let ifaces = collect::Ifaces::parse(&iface).map_err(anyhow::Error::msg)?;
    Ok(Args { server, token, interval: interval.clamp(1, 3600), ifaces, insecure })
}

/// `https://host/path` -> `wss://host/path/api/agent/ws`. The token travels in
/// an Authorization header rather than the query string, keeping it out of
/// reverse-proxy access logs.
///
/// `insecure` declares that the hub has no TLS. It permits plain ws:// to a
/// remote hub and suppresses the bare-host upgrade to TLS; without the latter
/// the flag would dial a port that cannot complete a TLS handshake.
fn ws_url(server: &str, insecure: bool) -> Result<String> {
    let base = server.trim_end_matches('/');
    let scheme = if insecure { "ws" } else { "wss" };
    let base = match base.split_once("://") {
        Some(("https", rest)) => format!("wss://{rest}"),
        Some(("http", rest)) => format!("ws://{rest}"),
        Some(("wss" | "ws", _)) => base.to_owned(),
        _ => format!("{scheme}://{base}"),
    };
    // RFC 3986 places userinfo before the host, so `127.0.0.1:28080@evil.example.com`
    // reads as loopback to any check that splits at the first colon while the
    // connection goes to the name following it -- bypassing both the refusal below
    // and `--insecure`. A hub address never needs userinfo, so it is rejected.
    let authority = base.split("://").nth(1).unwrap_or("").split('/').next().unwrap_or("");
    if authority.contains('@') {
        bail!("server URL must not contain '@': the host is whatever follows it, not what precedes it");
    }
    if base.starts_with("ws://") && !insecure && !is_loopback(&base) {
        bail!(
            "refusing plaintext ws:// to a remote hub; the token would travel in the clear. \
             Pass --insecure if that hub really has no TLS"
        );
    }
    Ok(format!("{base}/api/agent/ws"))
}

/// Parses the host rather than prefix-matching it: `127.attacker.example`
/// begins with the loopback net but resolves elsewhere. IPv6 literals are
/// bracketed, so the port is not split off at the first colon. Anything that is
/// not a literal loopback address falls to the plaintext refusal, including
/// `::ffff:127.0.0.1`.
///
/// `ws_url` has already rejected an authority containing `@`, so the first
/// colon here is the port separator.
fn is_loopback(url: &str) -> bool {
    let authority = url.split("://").nth(1).unwrap_or("").split('/').next().unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    };
    host.parse::<std::net::IpAddr>().map_or(host == "localhost", |ip| ip.is_loopback())
}

#[derive(Deserialize)]
struct Rpc {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Deserialize, Clone, Debug)]
struct PingTask {
    id: i64,
    target: String,
    interval: u64,
}

fn notify(method: &str, params: serde_json::Value) -> Message {
    Message::Text(
        serde_json::json!({"jsonrpc": "2.0", "method": method, "params": params}).to_string().into(),
    )
}

/// Writes under a deadline drawn from the remaining silence budget.
///
/// Reads and writes share one `select!` loop, so a socket that never drains
/// also stalls the watchdog; the kernel abandons such a socket only after
/// tcp_retries2, roughly fifteen minutes.
///
/// Charging the write against the remaining budget rather than a fresh
/// [`HUB_SILENCE`] bounds a stall at the end of a quiet stretch: two full
/// budgets would exceed the 120s after which the hub drops the node. An
/// exhausted budget fails the write and ends the session, as the watchdog
/// would have.
///
/// A timed-out write leaves a partial frame in the stream; every caller ends
/// the session on the error, discarding it with the socket.
async fn send(
    ws: &mut (impl Sink<Message, Error = WsError> + Unpin),
    m: Message,
    budget: Duration,
) -> Result<()> {
    tokio::time::timeout(budget, ws.send(m))
        .await
        .map_err(|_| anyhow!("write stalled for {}s", budget.as_secs()))?
        .context("write")
}

/// Remaining silence budget, measured from the last sign of life.
///
/// Every write draws from this single window, so no sequence of writes can
/// push the give-up point beyond one [`HUB_SILENCE`] past the last frame.
fn remaining(last_frame: Instant) -> Duration {
    HUB_SILENCE.saturating_sub(last_frame.elapsed())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let url = ws_url(&args.server, args.insecure)?;
    // Reported once at startup. install.sh hardens this unit with
    // ProtectHome=yes, which mounts a tmpfs over /home; where /home is its own
    // filesystem the totals then omit it. The unit file owns that decision, but
    // the discrepancy must not go unreported.
    for mount in collect::shadowed_mounts(&std::fs::read_to_string("/proc/self/mounts").unwrap_or_default()) {
        eprintln!("{mount} is covered by another mount and is not counted toward disk totals");
    }
    let mut collector = Collector::new(args.ifaces);
    // Reported once at startup: an interface summed twice otherwise shows only
    // as a total twice the real one. One listed in --iface but absent here,
    // such as a PPPoE link not yet dialled, is counted once it appears.
    let counted = collector.counted_ifaces();
    eprintln!(
        "counting traffic on: {}",
        if counted.is_empty() { "none".to_owned() } else { counted.join(" ") }
    );
    let mut wait = 0u64;

    loop {
        // Set by `session` once the handshake completes, so a connect that
        // never finished cannot pass its CONNECT_DEADLINE off as a session
        // that ran. `None` means never connected, which keeps the backoff
        // doubling.
        let mut connected = None;
        if let Err(e) = session(&url, &args.token, &mut collector, args.interval, &mut connected).await {
            eprintln!("session ended: {e:#}");
        }
        wait = reconnect_wait(wait, connected.map_or(Duration::ZERO, |t: Instant| t.elapsed()));
        tokio::time::sleep(Duration::from_secs(wait)).await;
    }
}

/// Backoff before the next connection attempt, derived from the previous wait
/// and the duration of the session that just ended -- measured from the
/// handshake, so a peer that swallows a connect for the whole
/// [`CONNECT_DEADLINE`] earns no credit.
///
/// A session that reported for a while proves the hub reachable and the token
/// valid, so the wait resets to one second. Only short-lived sessions keep
/// doubling, which keeps an agent off a hub in a crash loop.
fn reconnect_wait(previous: u64, lasted: Duration) -> u64 {
    if lasted >= Duration::from_secs(30) {
        1
    } else {
        (previous * 2).clamp(1, 60)
    }
}

/// Deadline covering every stage of establishing a connection: resolution,
/// the TCP handshake, the TLS exchange and the HTTP upgrade.
///
/// Only the TCP handshake has a deadline of its own; the TLS exchange and the
/// HTTP upgrade have none, so a peer that accepts and then goes silent would
/// leave the handshake pending indefinitely, and the agent running without
/// reporting or logging.
///
/// Deliberately generous: a healthy connect takes a quarter of a second, the
/// slowest measured sixty. This is not a latency budget but the point past
/// which nothing is expected to arrive.
const CONNECT_DEADLINE: Duration = Duration::from_secs(120);

/// How long one of the hub's addresses may take to accept a TCP connection
/// while another remains to be tried: the first SYN and its retransmits at one
/// and three seconds. The last address has no limit of its own and is bounded
/// by [`CONNECT_DEADLINE`] alone, so a hub with a single slow address is
/// reached as before.
///
/// Without it a black-holed address -- typically an AAAA record over a v6
/// route that leads nowhere -- holds the connect for the kernel's 127 seconds
/// of SYN retries, beyond CONNECT_DEADLINE, and the address behind it is never
/// tried.
const DIAL_FALLBACK: Duration = Duration::from_secs(5);

/// The hub sends one kind of message, a probe list a few hundred bytes long.
/// Tungstenite's 64 MiB default would hand the peer this process's entire
/// memory budget.
const MAX_MESSAGE: usize = 64 * 1024;

/// How long the agent waits for any frame from the hub before giving up.
///
/// The hub pings every 30 seconds and drops an agent silent for 120. Without a
/// matching watchdog, a one-way path failure -- an expired NAT entry, a route
/// gone dark -- leaves the agent writing into a socket the kernel retransmits
/// on for fifteen minutes, long after the panel has marked the node offline.
///
/// Staying under the hub's own timeout makes the agent give up first, bounding
/// recovery at this constant rather than at tcp_retries2.
const HUB_SILENCE: Duration = Duration::from_secs(90);

/// One connection: handshake, then report until the socket closes.
async fn session(
    url: &str,
    token: &str,
    collector: &mut Collector,
    interval: u64,
    connected: &mut Option<Instant>,
) -> Result<()> {
    let mut request = url.into_client_request()?;
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().context("token is not header-safe")?);
    let config =
        WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
    let uri = request.uri();
    // Brackets off an IPv6 literal, which `lookup_host` parses bare.
    let host = uri
        .host()
        .context("server URL has no host")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("wss") { 443 } else { 80 });
    // Collected before dialing, as the v4 it reports decides which family is
    // tried first.
    let facts = collector.facts();
    let behind_nat = facts.ipv4.parse().is_ok_and(|ip| !collect::is_public(ip));
    let connect = async {
        let stream = dial(&host, port, behind_nat).await?;
        let peer = stream.peer_addr()?;
        let (ws, _) = tokio_tungstenite::client_async_tls_with_config(request, stream, Some(config), None)
            .await
            .context("handshake")?;
        anyhow::Ok((ws, peer))
    };
    let (mut ws, peer) = tokio::time::timeout(CONNECT_DEADLINE, connect)
        .await
        .with_context(|| format!("no connection after {}s", CONNECT_DEADLINE.as_secs()))??;
    eprintln!("connected to {peer}");
    *connected = Some(Instant::now());
    // The clock starts at the handshake and the hello below draws from it like
    // every other write, so no two writes can each claim a full HUB_SILENCE.
    let mut last_frame = Instant::now();

    send(&mut ws, notify("hello", serde_json::to_value(facts)?), remaining(last_frame)).await?;

    let (result_tx, mut result_rx) = mpsc::channel::<Message>(64);
    let mut ping_tasks: Vec<(PingTask, tokio::task::JoinHandle<()>)> = Vec::new();
    let mut ticker = tokio::time::interval(Duration::from_secs(interval));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let result = loop {
        tokio::select! {
            _ = ticker.tick() => {
                let m = serde_json::to_value(collector.collect())?;
                if let Err(e) = send(&mut ws, notify("report", m), remaining(last_frame)).await { break Err(e); }
            }
            // Rebuilt each pass from the last frame, so silence costs exactly
            // HUB_SILENCE rather than a polling interval more. Kept separate
            // from the report tick, which --interval can stretch to an hour.
            _ = tokio::time::sleep(remaining(last_frame)) => {
                break Err(anyhow!("no frame from the hub in {}s", HUB_SILENCE.as_secs()));
            }
            Some(msg) = result_rx.recv() => {
                if let Err(e) = send(&mut ws, msg, remaining(last_frame)).await { break Err(e); }
            }
            incoming = ws.next() => {
                // Any frame proves the path alive, including the hub's
                // heartbeat ping -- the only one on an otherwise idle link.
                last_frame = Instant::now();
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(rpc) = serde_json::from_str::<Rpc>(&text) {
                            if rpc.method == "ping.tasks" {
                                if let Ok(tasks) = serde_json::from_value::<Vec<PingTask>>(rpc.params) {
                                    respawn_ping_tasks(&mut ping_tasks, tasks, &result_tx);
                                }
                            }
                        }
                    }
                    // Ping included: tungstenite queues the pong itself and
                    // sends it on the next read; a manual reply would duplicate it.
                    Some(Ok(_)) => {}
                    Some(Err(e)) => break Err(e.into()),
                    None => break Ok(()),
                }
            }
        }
    };

    for (_, handle) in ping_tasks {
        handle.abort();
    }
    result
}

/// Opens the TCP connection to the hub, trying its addresses in turn.
///
/// A host whose IPv4 is private tries the hub's IPv4 addresses first. Its
/// public IPv4 exists only on the NAT in front of it, and the hub, which knows
/// no more than the address a connection arrives from, learns it only from a
/// connection made over v4. A public v6 needs no such route: it sits on the
/// interface and travels in the hello. Every other host keeps the resolver's
/// order.
async fn dial(host: &str, port: u16, prefer_v4: bool) -> Result<TcpStream> {
    let mut addrs: Vec<std::net::SocketAddr> =
        tokio::net::lookup_host((host, port)).await.with_context(|| format!("resolve {host}"))?.collect();
    if prefer_v4 {
        addrs.sort_by_key(|a| !a.is_ipv4());
    }
    connect_first(&addrs).await.with_context(|| format!("connect {host}"))
}

/// The first of `addrs` to accept, each but the last given [`DIAL_FALLBACK`].
/// Every failure is kept, so the log names which family failed and how.
async fn connect_first(addrs: &[std::net::SocketAddr]) -> Result<TcpStream> {
    let mut failures = Vec::new();
    for (i, addr) in addrs.iter().enumerate() {
        let attempt = TcpStream::connect(addr);
        let result = if i + 1 < addrs.len() {
            tokio::time::timeout(DIAL_FALLBACK, attempt)
                .await
                .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))
        } else {
            attempt.await
        };
        match result {
            Ok(stream) => return Ok(stream),
            Err(e) => failures.push(format!("{addr}: {e}")),
        }
    }
    if failures.is_empty() {
        bail!("no address");
    }
    bail!("{}", failures.join("; "))
}

/// Ceiling on concurrent probe loops.
///
/// A task serialises to about forty bytes, so one [`MAX_MESSAGE`] frame could
/// request some fifteen hundred; at the five-second interval floor that is
/// hundreds of outbound connects per second to hub-chosen addresses, which on
/// a shared VPS reads as a port scan and acts as an amplifier. A compromised
/// or merely buggy hub is within the threat model, so the list is bounded
/// rather than trusted.
const MAX_PING_TASKS: usize = 64;

/// Replaces the running probe loops with the hub's current task list, leaving
/// unchanged tasks in place so their timers survive a push.
fn respawn_ping_tasks(
    running: &mut Vec<(PingTask, tokio::task::JoinHandle<()>)>,
    mut wanted: Vec<PingTask>,
    tx: &mpsc::Sender<Message>,
) {
    if wanted.len() > MAX_PING_TASKS {
        // Silent truncation would leave no record of which probes run.
        eprintln!("hub asked for {} ping tasks, running {MAX_PING_TASKS}", wanted.len());
        wanted.truncate(MAX_PING_TASKS);
    }
    running.retain(|(task, handle)| {
        let keep =
            wanted.iter().any(|w| w.id == task.id && w.target == task.target && w.interval == task.interval);
        if !keep {
            handle.abort();
        }
        keep
    });
    for task in wanted {
        if running.iter().any(|(t, _)| t.id == task.id) {
            continue;
        }
        let (tx, spawned) = (tx.clone(), task.clone());
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(spawned.interval.clamp(5, 3600)));
            // As with the report ticker, missed ticks must not fire back to
            // back: the default burst behaviour would turn one stalled
            // resolution into a rapid series of connects.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Logged once per probe per session: a resolver that overruns does
            // so every round, and the resulting gap would otherwise be
            // unexplained.
            let mut said = false;
            loop {
                ticker.tick().await;
                let Some(latency) = tcp_ping(&spawned.target).await else {
                    if !std::mem::replace(&mut said, true) {
                        eprintln!(
                            "{}: name resolution runs past {}ms, so these rounds report no sample \
                             rather than a loss",
                            spawned.target,
                            HANDSHAKE_DEADLINE.as_millis()
                        );
                    }
                    continue;
                };
                let msg =
                    notify("ping.result", serde_json::json!({"task_id": spawned.id, "latency_ms": latency}));
                if tx.send(msg).await.is_err() {
                    return;
                }
            }
        });
        running.push((task, handle));
    }
}

/// Deadline for one handshake, deliberately under the kernel's first SYN
/// retransmit.
///
/// Linux arms its initial SYN timer at one second. A longer wait turns a
/// dropped SYN into a late success, reporting the retransmit timer plus the
/// round trip as latency.
///
/// Cutting it short guarantees that every reading belongs to a handshake
/// completed on the first SYN, and that a dropped one becomes -1. The cost is
/// that a link whose genuine round trip exceeds this reads as unreachable.
const HANDSHAKE_DEADLINE: Duration = Duration::from_millis(900);

/// How many of a name's addresses one probe attempts.
///
/// Each dead address costs a [`HANDSHAKE_DEADLINE`], and a probe must not
/// outlast the five-second floor on its own interval.
const MAX_PING_ADDRS: usize = 3;

/// Round-trip time of a TCP handshake in milliseconds; -1 when no address
/// answered within [`HANDSHAKE_DEADLINE`], `None` when the name could not be
/// resolved in that time.
///
/// The two failure modes must stay distinct. -1 is the protocol's word for a
/// target that did not answer, and the hub folds every negative reading into a
/// bucket's packet loss, so returning it for a slow resolver would draw loss on
/// a link that dropped nothing. An overrun resolution is a sample not taken,
/// which is not a reading of zero.
///
/// The name is resolved before the clock starts: `TcpStream::connect` on a
/// hostname resolves first and connects second, which would fold resolver
/// latency into every sample. glibc caches nothing, so this happens each round.
///
/// ponytail: the `None` arm has no runtime reproduction; forcing it would
/// require either a genuinely overrunning resolver or a test-only deadline
/// parameter. The assertions below spell `Some(-1)`, so collapsing the two
/// answers back into one `i32` fails to compile.
async fn tcp_ping(target: &str) -> Option<i32> {
    // Bounded by the handshake deadline: a resolution slower than a connect is
    // useless as a latency sample, and `lookup_host` has no deadline of its own
    // -- glibc against a black-holed nameserver takes tens of seconds.
    //
    // This does not cancel the underlying `getaddrinfo`, which runs to
    // completion on a blocking thread; it only keeps this probe on cadence.
    let Ok(resolved) = tokio::time::timeout(HANDSHAKE_DEADLINE, tokio::net::lookup_host(target)).await else {
        return None;
    };
    // A resolution error is an unreachable target, which is what -1 reports.
    // Only the deadline above is ambiguous.
    let Ok(addresses) = resolved else { return Some(-1) };
    Some(handshake(addresses).await)
}

/// Round-trip time of the first address that completes a handshake.
///
/// The clock restarts on each address, so a dead one contributes nothing;
/// summing them would report the accumulated wait as latency.
///
/// Every failure advances to the next address, refusals included. glibc
/// returns the v6 address first, and on a host whose v6 has no route stopping
/// there would permanently report a target reachable over v4 as down.
async fn handshake(addresses: impl Iterator<Item = std::net::SocketAddr>) -> i32 {
    for address in addresses.take(MAX_PING_ADDRS) {
        let started = std::time::Instant::now();
        if let Ok(Ok(_)) = tokio::time::timeout(HANDSHAKE_DEADLINE, TcpStream::connect(address)).await {
            return started.elapsed().as_millis().min(i32::MAX as u128) as i32;
        }
    }
    -1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hub_restart_costs_a_second_while_an_unreachable_one_still_backs_off() {
        // Nothing on the other end: double to the ceiling and hold. Zero is
        // what the caller passes for a connect that never completed, so a
        // stalled attempt cannot be credited as a session that ran.
        let mut wait = 0;
        let climb: Vec<u64> = (0..8)
            .map(|_| {
                wait = reconnect_wait(wait, Duration::ZERO);
                wait
            })
            .collect();
        assert_eq!(climb, [1, 2, 4, 8, 16, 32, 60, 60]);

        // A session that ran resets the wait however high it had climbed:
        // the hub-restart case.
        assert_eq!(reconnect_wait(60, Duration::from_secs(3600)), 1);
        // Connected but dropped too early to prove anything: still a retreat.
        assert_eq!(reconnect_wait(4, Duration::from_secs(29)), 8);
    }

    #[test]
    fn ws_url_upgrades_scheme_and_refuses_plaintext_to_remote() {
        assert_eq!(ws_url("https://hub.example.com/", false).unwrap(), "wss://hub.example.com/api/agent/ws");
        assert_eq!(ws_url("http://127.0.0.1:28080", false).unwrap(), "ws://127.0.0.1:28080/api/agent/ws");
        // A bare host defaults to TLS rather than leaking the token.
        assert!(ws_url("hub.example.com", false).unwrap().starts_with("wss://"));
        assert!(ws_url("http://hub.example.com", false).is_err());
        // Bracketed IPv6 loopback is not remote.
        assert_eq!(ws_url("http://[::1]:28080", false).unwrap(), "ws://[::1]:28080/api/agent/ws");
        assert_eq!(ws_url("http://localhost:28080", false).unwrap(), "ws://localhost:28080/api/agent/ws");
        // A name that merely begins like the loopback net belongs to someone
        // else: the host is parsed, not prefix-matched.
        assert!(ws_url("http://127.attacker.example/", false).is_err());
        // Fail closed: a mapped literal is not read as loopback either.
        assert!(ws_url("http://[::ffff:127.0.0.1]:28080", false).is_err());
        // Userinfo places a loopback address where the host check looks and
        // another name where the socket goes; http::Uri resolves this authority's
        // host to evil.example.com. --insecure skips the plaintext refusal, so the
        // check cannot live inside it.
        assert!(ws_url("http://127.0.0.1:28080@evil.example.com/", false).is_err());
        assert!(ws_url("http://127.0.0.1:28080@evil.example.com/", true).is_err());
        assert!(ws_url("https://hub.example.com@evil.example.com/", false).is_err());
        // No token anywhere in the URL; it travels in a header.
        assert!(!ws_url("https://hub.example.com", false).unwrap().contains("token"));
    }

    /// `--insecure` covers a hub reached at ip:port with no TLS: it permits the
    /// plaintext hop and suppresses the bare-host TLS upgrade, which would
    /// otherwise dial wss:// at a port that cannot answer.
    #[test]
    fn insecure_allows_plaintext_to_a_remote_hub_and_stops_upgrading_bare_hosts() {
        assert_eq!(
            ws_url("http://203.0.113.10:28080", true).unwrap(),
            "ws://203.0.113.10:28080/api/agent/ws"
        );
        assert_eq!(ws_url("203.0.113.10:28080", true).unwrap(), "ws://203.0.113.10:28080/api/agent/ws");
        // An explicit https:// hub stays on TLS: the flag permits plaintext
        // rather than forcing it.
        assert_eq!(ws_url("https://hub.example.com", true).unwrap(), "wss://hub.example.com/api/agent/ws");
    }

    #[tokio::test]
    async fn tcp_ping_measures_success_and_reports_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        // A loopback handshake completes within a millisecond, so this reads 0
        // either way; what it pins is the contract that reachable is
        // non-negative and unreachable is -1.
        assert!(tcp_ping(&addr.to_string()).await.unwrap() >= 0);
        assert_eq!(tcp_ping("127.0.0.1:1").await, Some(-1), "nothing is listening there");
        // A failed resolution is an unreachable target, not a missing sample.
        // std rejects this port before the resolver is reached, so the
        // assertion needs no network.
        assert_eq!(tcp_ping("127.0.0.1:99999").await, Some(-1), "an unresolvable target is unreachable");

        // First address dead: a dual-stack target on a host whose v6 goes
        // nowhere. The probe advances rather than reporting it unreachable.
        let dead: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(handshake([dead, addr].into_iter()).await >= 0, "a dead address must not end the probe");
        assert_eq!(handshake([dead, dead].into_iter()).await, -1, "every address failed");
        // Past the ceiling the remainder are skipped; a long address list
        // would otherwise hold a probe past its own interval.
        assert_eq!(
            handshake([dead, dead, dead, addr].into_iter()).await,
            -1,
            "a fourth address is not tried"
        );
    }

    /// A listener whose accept queue is full drops further SYNs rather than
    /// refusing them: a black hole on loopback. The clock is paused, so the
    /// fallback deadline elapses as soon as nothing else can progress, while
    /// without it the connect would wait out the kernel's SYN retries.
    #[tokio::test(start_paused = true)]
    async fn a_black_holed_address_gives_way_to_the_next_within_the_fallback() {
        let hole = tokio::net::TcpSocket::new_v4().unwrap();
        hole.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let hole = hole.listen(0).unwrap();
        let dead = hole.local_addr().unwrap();
        let _queued = std::net::TcpStream::connect(dead).unwrap();
        let live = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = live.local_addr().unwrap();

        let started = Instant::now();
        let stream = connect_first(&[dead, live]).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap(), live);
        assert_eq!(started.elapsed(), DIAL_FALLBACK, "the dead address costs the fallback and no more");
        let e = connect_first(&[dead, "127.0.0.1:1".parse().unwrap()]).await.unwrap_err().to_string();
        assert!(e.contains("timed out") && e.contains("refused"), "each failure is named: {e}");
    }

    /// Where `localhost` resolves to ::1 before 127.0.0.1, only the preference
    /// can land this connect on v4. Elsewhere -- no v6 loopback, or a resolver
    /// ordering v4 first -- the preference is not observable and the test says
    /// so rather than failing.
    #[tokio::test]
    async fn a_host_behind_nat_dials_the_hubs_v4_first() {
        let v4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = v4.local_addr().unwrap().port();
        let Ok(_v6) = std::net::TcpListener::bind(("::1", port)) else {
            return eprintln!("skipped: no IPv6 loopback");
        };
        if !dial("localhost", port, false).await.unwrap().peer_addr().unwrap().is_ipv6() {
            return eprintln!("skipped: the resolver lists 127.0.0.1 first");
        }
        assert!(dial("localhost", port, true).await.unwrap().peer_addr().unwrap().is_ipv4());
        assert!(
            dial("::1", port, true).await.unwrap().peer_addr().unwrap().is_ipv6(),
            "a literal is dialed as given"
        );
    }

    /// The deadline must stay under the kernel's first SYN retransmit, or a
    /// dropped SYN returns as roughly 1200ms of apparent latency -- the 1s timer
    /// plus the round trip. Such readings cluster at 1200ms and 3200ms, the
    /// signature of a retransmit rather than a slow link.
    #[test]
    fn the_handshake_deadline_stays_under_the_kernels_syn_timer() {
        assert!(
            HANDSHAKE_DEADLINE < Duration::from_secs(1),
            "a deadline at or past the 1s initial RTO lets retransmits be reported as latency"
        );
    }

    /// The hub pings every 30s and drops an agent silent for 120s. Both ends of
    /// this window are load-bearing and neither is visible from this file.
    ///
    /// The bound holds only because the watchdog sleeps to a deadline and each
    /// write draws from what remains of that same deadline; the two structures
    /// enforcing that are asserted separately below.
    #[test]
    fn the_agent_gives_up_on_a_silent_hub_before_the_hub_gives_up_on_it() {
        assert!(
            HUB_SILENCE < Duration::from_secs(120),
            "past the hub's own timeout the agent stops being what recovers the connection"
        );
        assert!(HUB_SILENCE > Duration::from_secs(60), "two lost heartbeats are a blip, not a dead link");
    }

    /// A sink that never accepts: the socket whose peer has stopped reading,
    /// which is the case the write deadline exists for.
    struct NeverDrains;

    impl Sink<Message> for NeverDrains {
        type Error = WsError;

        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), WsError>> {
            std::task::Poll::Pending
        }

        fn start_send(self: std::pin::Pin<&mut Self>, _: Message) -> Result<(), WsError> {
            unreachable!("never ready")
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), WsError>> {
            std::task::Poll::Pending
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), WsError>> {
            std::task::Poll::Pending
        }
    }

    /// Every write draws from one clock started at the handshake, so a session
    /// gives up exactly HUB_SILENCE after its last sign of life regardless of
    /// how many writes stalled in between. The hello is the first such write.
    #[tokio::test(start_paused = true)]
    async fn a_slow_hello_cannot_push_the_give_up_point_past_the_hubs_own_timeout() {
        let handshake = Instant::now();
        assert_eq!(remaining(handshake), HUB_SILENCE, "the first write gets the whole budget");

        // A stalled hello must fail at the budget it was handed, not one of
        // its own.
        assert!(send(&mut NeverDrains, notify("hello", serde_json::json!({})), remaining(handshake))
            .await
            .is_err());
        assert_eq!(handshake.elapsed(), HUB_SILENCE, "the stall costs the budget, no more");

        // Afterwards the give-up moment stays at last_frame + HUB_SILENCE:
        // spent plus remaining is always that one window.
        for spent in [0, 30, 89, 90, 200] {
            let last_frame = Instant::now();
            tokio::time::advance(Duration::from_secs(spent)).await;
            assert_eq!(
                last_frame.elapsed() + remaining(last_frame),
                HUB_SILENCE.max(last_frame.elapsed()),
                "{spent}s in, the budget must not push the deadline out"
            );
        }
    }

    #[test]
    fn ping_tasks_keep_their_timers_unless_the_task_changed() {
        // The runtime flavour the binary uses.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _g = rt.enter();
        let (tx, _rx) = mpsc::channel(8);
        let mut running = Vec::new();
        let task = |id, target: &str, interval| PingTask { id, target: target.into(), interval };

        respawn_ping_tasks(&mut running, vec![task(1, "a:1", 60), task(2, "b:2", 60)], &tx);
        assert_eq!(running.len(), 2);
        let (first, second) = (running[0].1.id(), running[1].1.id());

        // Task 1 unchanged, task 2 retargeted, task 3 added.
        respawn_ping_tasks(
            &mut running,
            vec![task(1, "a:1", 60), task(2, "c:3", 60), task(3, "d:4", 60)],
            &tx,
        );
        assert_eq!(running.len(), 3);
        assert_eq!(running[0].1.id(), first, "unchanged task must not be restarted");
        // A task whose target changed must be torn down, or it keeps probing
        // the old address.
        assert_ne!(running[1].1.id(), second, "a retargeted task must be restarted");

        // Interval 0 must not take the probe down: tokio's interval panics on
        // a zero period, and a panicked task stops reporting silently.
        respawn_ping_tasks(&mut running, vec![task(9, "e:5", 0)], &tx);
        rt.block_on(async { tokio::time::sleep(Duration::from_millis(50)).await });
        assert!(!running[0].1.is_finished(), "a zero interval must be clamped, not panic the probe");

        // One 64 KiB frame could carry some fifteen hundred of these; the
        // agent enforces its own ceiling rather than trusting the count.
        let flood = (0..500).map(|id| task(id, "f:6", 60)).collect();
        respawn_ping_tasks(&mut running, flood, &tx);
        assert_eq!(running.len(), MAX_PING_TASKS, "the hub does not choose how many probes run");
    }
}
