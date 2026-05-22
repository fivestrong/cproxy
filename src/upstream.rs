use eyre::{eyre, Result};
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Wire-protocol family used to talk to the upstream proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamScheme {
    HttpConnect,
    Socks5,
}

#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub scheme: UpstreamScheme,
    /// Host part as written in the URL (IPv4/IPv6 literal or DNS name). For
    /// IPv6 literals this is the bare address WITHOUT surrounding brackets;
    /// `endpoint()` adds them when formatting for resolvers.
    pub host: String,
    pub port: u16,
}

impl UpstreamConfig {
    /// Parse a URL like `http://host:port` or `socks5://host:port`. We do not
    /// support userinfo / path components in v1.
    pub fn parse(s: &str) -> Result<Self> {
        let url = url::Url::parse(s).map_err(|e| eyre!("invalid --upstream URL '{}': {}", s, e))?;
        let scheme = match url.scheme() {
            "http" => UpstreamScheme::HttpConnect,
            "socks5" | "socks5h" => UpstreamScheme::Socks5,
            other => {
                return Err(eyre!(
                    "unsupported --upstream scheme '{}', expected http, socks5, or socks5h",
                    other
                ));
            }
        };
        // `url::Url::host_str()` keeps the surrounding `[...]` for IPv6
        // literals as they appear in the URL. We strip them here so `host`
        // always holds the bare address, and `endpoint()` re-adds brackets
        // as needed when formatting for resolvers.
        let raw_host = url
            .host_str()
            .ok_or_else(|| eyre!("--upstream URL is missing a host"))?;
        let host = if raw_host.starts_with('[') && raw_host.ends_with(']') {
            raw_host[1..raw_host.len() - 1].to_string()
        } else {
            raw_host.to_string()
        };
        let port = url
            .port()
            .ok_or_else(|| eyre!("--upstream URL must specify a port"))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(eyre!(
                "--upstream URLs with username:password are not supported in this build"
            ));
        }
        if let Some(path) = Some(url.path()) {
            if !path.is_empty() && path != "/" {
                return Err(eyre!(
                    "--upstream URL must not include a path (got '{}')",
                    path
                ));
            }
        }
        Ok(Self { scheme, host, port })
    }

    /// Format as a `host:port` string suitable for `tokio::net::lookup_host`.
    /// IPv6 literals are bracketed; IPv4 literals and DNS names are not.
    pub fn endpoint(&self) -> String {
        // A bare IPv6 literal contains at least one colon (e.g. `::1`,
        // `fe80::1`); IPv4 literals and DNS labels never do. URL parsers
        // already strip the surrounding brackets, so we re-add them here.
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Destination the upstream proxy should open for a redirected client.
///
/// Transparent redirect can always recover the original IPv4 destination via
/// `SO_ORIGINAL_DST`, but many upstream proxies behave better when we preserve
/// the hostname the client intended (HTTP `Host`, TLS SNI). We therefore carry
/// either an IP:port fallback or a domain name when one was recovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectTarget {
    Ip(SocketAddrV4),
    Domain { host: String, port: u16 },
}

impl ConnectTarget {
    pub fn authority(&self) -> String {
        match self {
            ConnectTarget::Ip(addr) => format!("{}:{}", addr.ip(), addr.port()),
            ConnectTarget::Domain { host, port } => format!("{}:{}", host, port),
        }
    }
}

/// Locate the byte index immediately after the first `\r\n\r\n` sequence in
/// `buf`. Returns `None` when the marker is not yet present.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Run the HTTP CONNECT handshake on an already-connected socket. On success
/// returns the same stream plus any payload bytes the upstream sent in the
/// same TCP segment as the response headers; the caller MUST flush those
/// bytes to the downstream client before splicing, otherwise server-first
/// protocols (SSH, SMTP, etc.) lose their banner.
pub async fn http_connect(
    mut stream: TcpStream,
    target: &ConnectTarget,
) -> Result<(TcpStream, Vec<u8>)> {
    let authority = target.authority();
    let req = format!(
        "CONNECT {0} HTTP/1.1\r\nHost: {0}\r\nProxy-Connection: keep-alive\r\n\r\n",
        authority
    );
    stream.write_all(req.as_bytes()).await?;

    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut tmp = [0u8; 512];
    let header_end: usize = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(eyre!("upstream closed before CONNECT response completed"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > 8192 {
            return Err(eyre!("HTTP CONNECT response header exceeded 8 KiB"));
        }
    };

    let head = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| eyre!("HTTP CONNECT response was not valid UTF-8"))?;
    let first_line = head.split("\r\n").next().unwrap_or("");
    let mut tokens = first_line.split_whitespace();
    let _http = tokens
        .next()
        .ok_or_else(|| eyre!("malformed HTTP CONNECT response: '{}'", first_line))?;
    let status = tokens
        .next()
        .ok_or_else(|| eyre!("malformed HTTP CONNECT response: '{}'", first_line))?;
    if status != "200" {
        return Err(eyre!(
            "upstream HTTP CONNECT refused (status {}): {}",
            status,
            first_line
        ));
    }

    // Anything past the header terminator is tunneled payload that the
    // upstream sent eagerly (e.g. when the remote server speaks first). The
    // caller has to replay it into the bridged client before relying on
    // copy_bidirectional.
    let prelude = buf[header_end..].to_vec();
    Ok((stream, prelude))
}

/// Run the SOCKS5 (no-auth) handshake + CONNECT for an IPv4 destination.
/// Returns `(stream, prelude)` for symmetry with `http_connect`; SOCKS5
/// always frames its reply exactly so the prelude is always empty.
pub async fn socks5_connect(
    mut stream: TcpStream,
    target: &ConnectTarget,
) -> Result<(TcpStream, Vec<u8>)> {
    // Greeting: VER=5, NMETHODS=1, METHODS=[0x00 (no auth)]
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        return Err(eyre!(
            "SOCKS5 greeting reply: unexpected version 0x{:02x}",
            greeting[0]
        ));
    }
    if greeting[1] != 0x00 {
        return Err(eyre!(
            "SOCKS5 server requires authentication method 0x{:02x}, only no-auth is supported in this build",
            greeting[1]
        ));
    }

    let req = build_socks5_connect_request(target)?;
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(eyre!("SOCKS5 reply: unexpected version 0x{:02x}", head[0]));
    }
    if head[1] != 0x00 {
        return Err(eyre!(
            "SOCKS5 CONNECT failed (REP=0x{:02x}, see RFC1928 section 6)",
            head[1]
        ));
    }
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 4 + 2];
            stream.read_exact(&mut rest).await?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut rest = vec![0u8; len + 2];
            stream.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut rest = [0u8; 16 + 2];
            stream.read_exact(&mut rest).await?;
        }
        other => {
            return Err(eyre!("SOCKS5 reply: unknown ATYP 0x{:02x}", other));
        }
    }
    Ok((stream, Vec::new()))
}

fn build_socks5_connect_request(target: &ConnectTarget) -> Result<Vec<u8>> {
    let mut req = Vec::with_capacity(10);
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    match target {
        ConnectTarget::Ip(addr) => {
            req.push(0x01);
            req.extend_from_slice(&addr.ip().octets());
            req.extend_from_slice(&addr.port().to_be_bytes());
        }
        ConnectTarget::Domain { host, port } => {
            if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
                req.push(0x01);
                req.extend_from_slice(&ipv4.octets());
                req.extend_from_slice(&port.to_be_bytes());
            } else {
                let host_bytes = host.as_bytes();
                if host_bytes.len() > u8::MAX as usize {
                    return Err(eyre!(
                        "SOCKS5 target host '{}' is too long ({} bytes)",
                        host,
                        host_bytes.len()
                    ));
                }
                req.push(0x03);
                req.push(host_bytes.len() as u8);
                req.extend_from_slice(host_bytes);
                req.extend_from_slice(&port.to_be_bytes());
            }
        }
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_url() {
        let cfg = UpstreamConfig::parse("http://192.168.1.10:7890").unwrap();
        assert_eq!(cfg.scheme, UpstreamScheme::HttpConnect);
        assert_eq!(cfg.host, "192.168.1.10");
        assert_eq!(cfg.port, 7890);
        assert_eq!(cfg.endpoint(), "192.168.1.10:7890");
    }

    #[test]
    fn parse_socks5_url() {
        let cfg = UpstreamConfig::parse("socks5://10.0.0.1:1080").unwrap();
        assert_eq!(cfg.scheme, UpstreamScheme::Socks5);
        assert_eq!(cfg.host, "10.0.0.1");
        assert_eq!(cfg.port, 1080);
    }

    #[test]
    fn parse_socks5h_alias() {
        let cfg = UpstreamConfig::parse("socks5h://example.com:1080").unwrap();
        assert_eq!(cfg.scheme, UpstreamScheme::Socks5);
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.endpoint(), "example.com:1080");
    }

    #[test]
    fn parse_rejects_userinfo() {
        assert!(UpstreamConfig::parse("http://user:pass@host:8080").is_err());
    }

    #[test]
    fn parse_rejects_unknown_scheme() {
        assert!(UpstreamConfig::parse("ftp://host:21").is_err());
    }

    #[test]
    fn parse_requires_port() {
        assert!(UpstreamConfig::parse("http://host").is_err());
    }

    #[test]
    fn endpoint_brackets_ipv6_literal() {
        let cfg = UpstreamConfig::parse("http://[::1]:7890").unwrap();
        assert_eq!(cfg.host, "::1");
        assert_eq!(cfg.endpoint(), "[::1]:7890");
    }

    #[test]
    fn endpoint_brackets_full_ipv6() {
        let cfg = UpstreamConfig::parse("socks5://[2001:db8::1]:1080").unwrap();
        assert_eq!(cfg.endpoint(), "[2001:db8::1]:1080");
    }

    #[test]
    fn find_header_end_locates_terminator() {
        assert_eq!(
            find_header_end(b"HTTP/1.1 200 OK\r\nFoo: bar\r\n\r\n"),
            Some(29)
        );
    }

    #[test]
    fn find_header_end_returns_none_when_incomplete() {
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\nFoo: bar\r\n"), None);
    }

    #[test]
    fn find_header_end_captures_trailing_bytes() {
        let buf = b"HTTP/1.1 200 OK\r\n\r\nSSH-2.0-foo\r\n";
        let end = find_header_end(buf).unwrap();
        assert_eq!(&buf[end..], b"SSH-2.0-foo\r\n");
    }

    #[test]
    fn connect_target_authority_preserves_domain() {
        let target = ConnectTarget::Domain {
            host: "www.baidu.com".into(),
            port: 443,
        };
        assert_eq!(target.authority(), "www.baidu.com:443");
    }

    #[test]
    fn build_socks5_request_for_domain_target() {
        let req = build_socks5_connect_request(&ConnectTarget::Domain {
            host: "www.baidu.com".into(),
            port: 443,
        })
        .unwrap();
        assert_eq!(&req[..5], &[0x05, 0x01, 0x00, 0x03, 13]);
        assert_eq!(&req[5..18], b"www.baidu.com");
        assert_eq!(&req[18..], &443u16.to_be_bytes());
    }

    #[test]
    fn build_socks5_request_for_ip_target() {
        let req = build_socks5_connect_request(&ConnectTarget::Ip(SocketAddrV4::new(
            Ipv4Addr::new(1, 2, 3, 4),
            80,
        )))
        .unwrap();
        assert_eq!(req, vec![0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80]);
    }
}
