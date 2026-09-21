//! Reaching the hub through an HTTP proxy.
//!
//! Where a host has no route off its network except a proxy, the agent opens a
//! CONNECT tunnel and runs everything above it -- TLS, the WebSocket upgrade,
//! every frame -- inside. The proxy sees the hub's address in the CONNECT line
//! and nothing more: the token travels in a header the TLS session above the
//! tunnel encrypts. Under `--insecure` there is no such session, and the proxy
//! reads the token like any other hop on a plaintext path.
//!
//! The hub's name is resolved by the proxy rather than here, so a host with no
//! resolver of its own reaches the hub as long as it can reach the proxy.

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Headers accepted while waiting for the tunnel to open.
///
/// A CONNECT answer is a status line and a handful of headers. The cap bounds
/// what a peer that answers with an endless header stream can make the agent
/// hold.
const MAX_RESPONSE: usize = 8 * 1024;

/// An HTTP proxy to tunnel through: `http://[user:pass@]host:port`.
pub struct Proxy {
    pub host: String,
    pub port: u16,
    /// The `Basic` credential, already encoded and ready for the header.
    ///
    /// Encoding at parse time also settles a password carrying CR/LF: base64
    /// has no line break to end the header with, so such a password cannot add
    /// headers of its own.
    credential: Option<String>,
}

impl Proxy {
    /// Accepts `http://host:port` and the bare `host:port`, either with
    /// `user:pass@` in front, an IPv6 literal in brackets, and a trailing `/`.
    ///
    /// The port is required. Proxies sit on 3128, 8080, 1080 and anything
    /// else; inferring 80 from the scheme would turn a forgotten port into a
    /// connection to a web server, which answers the CONNECT with a puzzling
    /// 400 rather than a message naming what is missing.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        let rest = match spec.split_once("://") {
            Some(("http", rest)) => rest,
            Some((scheme, _)) => bail!(
                "proxy scheme {scheme}:// is not supported; the agent tunnels through an http:// CONNECT proxy"
            ),
            None => spec,
        };
        // `http://proxy:3128/` is how a proxy tends to be written down, and a
        // path means nothing to CONNECT.
        let authority = rest.split('/').next().unwrap_or_default();
        // A password may itself contain '@', so the host is what follows the
        // last one rather than the first.
        let (credential, address) = match authority.rsplit_once('@') {
            Some((userinfo, address)) if !userinfo.is_empty() => (Some(base64(userinfo.as_bytes())), address),
            Some(_) => bail!("proxy URL has '@' with no credentials before it"),
            None => (None, authority),
        };
        // An IPv6 literal carries colons of its own; only brackets say which
        // one separates the port.
        let (host, port) = match address.strip_prefix('[') {
            Some(rest) => {
                let (host, tail) = rest.split_once(']').context("proxy URL has '[' with no ']'")?;
                (host, tail.strip_prefix(':').unwrap_or_default())
            }
            None => address.rsplit_once(':').unwrap_or((address, "")),
        };
        if host.is_empty() {
            bail!("proxy URL has no host");
        }
        let port = port
            .parse()
            .with_context(|| format!("proxy URL needs an explicit port, as in http://{host}:3128"))?;
        Ok(Self { host: host.to_owned(), port, credential })
    }

    /// Opens a tunnel to `host:port` over an established connection to the
    /// proxy. The stream comes back unchanged once the proxy answers 2xx; from
    /// that byte on it carries the hub's.
    ///
    /// Has no deadline of its own: the caller runs the whole connect under
    /// `CONNECT_DEADLINE`, which a proxy that accepts and then goes silent
    /// falls to like any other stalled stage.
    pub async fn tunnel(&self, stream: TcpStream, host: &str, port: u16) -> Result<TcpStream> {
        // An IPv6 literal arrives here bare and has to be bracketed again, or
        // the proxy reads its last group as the port.
        let target = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
        self.tunnel_target(stream, &target).await
    }

    /// The same, for a destination that is already written the way a CONNECT
    /// line carries it: `host:port`, an IPv6 literal bracketed. This is the
    /// form a probe target arrives in from the hub.
    pub async fn tunnel_target(&self, mut stream: TcpStream, target: &str) -> Result<TcpStream> {
        // The hub chooses probe targets and this one goes straight into a
        // request line: a target carrying CR or LF would append headers of the
        // hub's choosing to the CONNECT, or a whole second request behind it.
        if target.is_empty() || target.bytes().any(|b| !(b'!'..=b'~').contains(&b)) {
            bail!("{target:?} is not a host:port a CONNECT line can carry");
        }
        let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(credential) = &self.credential {
            request.push_str(&format!("Proxy-Authorization: Basic {credential}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.context("send CONNECT to the proxy")?;

        let mut response = Vec::new();
        let end = loop {
            let mut chunk = [0u8; 512];
            let read = stream.read(&mut chunk).await.context("read the proxy's answer to CONNECT")?;
            if read == 0 {
                bail!("proxy closed the connection without answering CONNECT");
            }
            response.extend_from_slice(&chunk[..read]);
            // Searched over the whole buffer each pass, so a terminator split
            // across two reads is still found.
            if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                break end + 4;
            }
            if response.len() > MAX_RESPONSE {
                bail!("proxy sent {} bytes of headers without ending them", response.len());
            }
        };
        // "HTTP/1.1 200 Connection established". The reason phrase is the
        // proxy's own wording -- 407 with its realm, 403 with a policy name --
        // and is what tells an operator which rule refused the hub.
        let head = String::from_utf8_lossy(&response[..end]);
        let status = head.lines().next().unwrap_or_default().trim();
        let code = status.split_whitespace().nth(1).and_then(|c| c.parse::<u16>().ok());
        if !matches!(code, Some(200..=299)) {
            bail!("proxy refused CONNECT {target}: {status}");
        }
        if end != response.len() {
            // Inside the tunnel the client speaks first -- the TLS
            // ClientHello, or the upgrade request under --insecure -- so
            // nothing legitimate can already be here. Dropping these bytes
            // would leave every byte after them misread.
            bail!("proxy sent {} bytes before the tunnel opened", response.len() - end);
        }
        Ok(stream)
    }
}

/// Standard base64, the only encoding a `Basic` credential may use.
///
/// Sixteen lines against a dependency whose sole use is this one header.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let bits = u32::from_be_bytes([
            0,
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            // A chunk short of three bytes pads the digits it never filled:
            // one byte leaves two '=', two bytes one.
            out.push(if i > chunk.len() { '=' } else { ALPHABET[(bits >> shift) as usize & 63] as char });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proxy_address_parses_in_the_forms_it_gets_written_in() {
        let plain = Proxy::parse("http://10.0.0.8:3128").unwrap();
        assert_eq!((plain.host.as_str(), plain.port), ("10.0.0.8", 3128));
        // The scheme is optional and a trailing path is ignored.
        assert_eq!(Proxy::parse("10.0.0.8:3128").unwrap().host, "10.0.0.8");
        assert_eq!(Proxy::parse("http://proxy.corp:8080/").unwrap().port, 8080);
        // Brackets say which colon is the port separator.
        let v6 = Proxy::parse("http://[fd00::1]:3128").unwrap();
        assert_eq!((v6.host.as_str(), v6.port), ("fd00::1", 3128));
        // A password may contain '@'; the host is what follows the last one.
        let auth = Proxy::parse("http://user:p@ss@10.0.0.8:3128").unwrap();
        assert_eq!(auth.host, "10.0.0.8");
        assert_eq!(auth.credential.unwrap(), base64(b"user:p@ss"));
        // A forgotten port must be named as such rather than become :80.
        assert!(Proxy::parse("http://10.0.0.8").is_err());
        // Neither TLS to the proxy itself nor SOCKS is what this speaks, and
        // dialing such a URL as a CONNECT proxy would fail obscurely.
        assert!(Proxy::parse("https://10.0.0.8:3128").is_err());
        assert!(Proxy::parse("socks5://10.0.0.8:1080").is_err());
    }

    #[test]
    fn base64_matches_the_encoding_the_header_expects() {
        assert_eq!(base64(b""), "");
        // Each tail length pads differently, and a credential is any length.
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
        assert_eq!(base64(b"alice:s3cr3t"), "YWxpY2U6czNjcjN0");
        // The last two alphabet entries differ between base64 and its URL-safe
        // variant; a header takes this one.
        assert_eq!(base64(&[0xfb, 0xff, 0xfe]), "+//+");
    }

    /// A proxy that reads one CONNECT, answers with `answer`, then echoes
    /// whatever arrives inside the tunnel. Its handle yields the request it
    /// read.
    async fn fake_proxy(answer: &'static [u8]) -> (std::net::SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            // Byte at a time, so nothing of the tunnel is swallowed with the
            // headers.
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8; 1];
                if stream.read_exact(&mut byte).await.is_err() {
                    break;
                }
                request.push(byte[0]);
            }
            stream.write_all(answer).await.unwrap();
            let mut echo = [0u8; 64];
            if let Ok(read) = stream.read(&mut echo).await {
                let _ = stream.write_all(&echo[..read]).await;
            }
            String::from_utf8_lossy(&request).into_owned()
        });
        (address, handle)
    }

    #[tokio::test]
    async fn a_tunnel_carries_the_hubs_bytes_once_the_proxy_answers() {
        let (address, server) = fake_proxy(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
        let proxy = Proxy::parse(&format!("http://alice:s3cr3t@{address}")).unwrap();
        let mut tunnel =
            proxy.tunnel(TcpStream::connect(address).await.unwrap(), "hub.example.com", 443).await.unwrap();

        // The stream comes back positioned at the first byte of the tunnel:
        // what goes in is the hub's, not the proxy's.
        tunnel.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        let request = server.await.unwrap();
        assert!(request.starts_with("CONNECT hub.example.com:443 HTTP/1.1\r\n"), "{request}");
        assert!(request.contains("Host: hub.example.com:443\r\n"), "{request}");
        // The credential is encoded, never the cleartext password.
        assert!(request.contains("Proxy-Authorization: Basic YWxpY2U6czNjcjN0\r\n"), "{request}");
    }

    #[tokio::test]
    async fn a_hub_reached_by_ipv6_literal_keeps_its_brackets_in_the_connect_line() {
        let (address, server) = fake_proxy(b"HTTP/1.1 200 OK\r\n\r\n").await;
        let proxy = Proxy::parse(&address.to_string()).unwrap();
        // The agent strips the brackets off the URL before dialing; without
        // them here the proxy reads `1` as the port.
        proxy.tunnel(TcpStream::connect(address).await.unwrap(), "fd00::1", 8443).await.unwrap();
        let request = server.await.unwrap();
        assert!(request.starts_with("CONNECT [fd00::1]:8443 HTTP/1.1\r\n"), "{request}");
        // No credentials configured, no header.
        assert!(!request.contains("Proxy-Authorization"), "{request}");
    }

    #[tokio::test]
    async fn the_proxys_own_refusal_is_what_the_session_reports() {
        let (address, _server) =
            fake_proxy(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n").await;
        let proxy = Proxy::parse(&address.to_string()).unwrap();
        let failure = proxy
            .tunnel(TcpStream::connect(address).await.unwrap(), "hub.example.com", 443)
            .await
            .unwrap_err()
            .to_string();
        // A missing credential and a blocked destination are different fixes,
        // so the status has to survive into the log.
        assert!(failure.contains("407"), "{failure}");
        assert!(failure.contains("hub.example.com:443"), "{failure}");
    }

    #[tokio::test]
    async fn bytes_arriving_before_the_tunnel_opens_end_the_attempt() {
        let (address, _server) = fake_proxy(b"HTTP/1.1 200 OK\r\n\r\nsurprise").await;
        let proxy = Proxy::parse(&address.to_string()).unwrap();
        let failure = proxy
            .tunnel(TcpStream::connect(address).await.unwrap(), "hub.example.com", 443)
            .await
            .unwrap_err()
            .to_string();
        assert!(failure.contains("before the tunnel"), "{failure}");
    }

    #[tokio::test]
    async fn a_target_that_could_forge_headers_is_refused_before_anything_is_written() {
        // Nothing answers: the refusal happens before a byte is written, so
        // the socket only has to exist.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let proxy = Proxy::parse(&address.to_string()).unwrap();
        // Probe targets come from the hub, which is not trusted to choose
        // what the CONNECT line says.
        let failure = proxy
            .tunnel_target(
                TcpStream::connect(address).await.unwrap(),
                "1.1.1.1:443\r\nProxy-Authorization: Basic YWxpY2U6czNjcjN0",
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(failure.contains("CONNECT line"), "{failure}");
        assert!(proxy.tunnel_target(TcpStream::connect(address).await.unwrap(), "a host:443").await.is_err());
        assert!(proxy.tunnel_target(TcpStream::connect(address).await.unwrap(), "").await.is_err());
    }

    #[tokio::test]
    async fn a_proxy_that_answers_nothing_ends_the_attempt_rather_than_handing_back_the_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });
        let proxy = Proxy::parse(&address.to_string()).unwrap();
        assert!(proxy
            .tunnel(TcpStream::connect(address).await.unwrap(), "hub.example.com", 443)
            .await
            .is_err());
    }
}
