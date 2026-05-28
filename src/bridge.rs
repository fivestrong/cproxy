use crate::upstream::{
    http_connect, socks5_connect, ConnectTarget, UpstreamConfig, UpstreamScheme,
};
use eyre::{eyre, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::timeout;

/// Apply SO_MARK to the given socket file descriptor so the kernel routes
/// (and netfilter classifies) outgoing traffic with this fwmark. This is what
/// keeps the bridge's connection to the remote upstream from being redirected
/// back into the bridge by our own redirect rule.
fn set_so_mark(fd: i32, mark: u32) -> Result<()> {
    let value: libc::c_int = mark as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(eyre!(
            "setsockopt(SO_MARK={}) failed: {}",
            mark,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Verify the current process can actually set SO_MARK before we install any
/// firewall rules. SO_MARK requires CAP_NET_ADMIN; if the parent euid was
/// dropped to a non-root user before the bridge came up, every upstream
/// connect would EPERM at the first setsockopt call. Catching that here
/// turns it into a clear startup error instead of silently blackholing the
/// first redirected connection.
fn probe_so_mark_capability(mark: u32) -> Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(eyre!(
            "bridge SO_MARK probe failed to create socket: {}",
            std::io::Error::last_os_error()
        ));
    }
    let result = set_so_mark(fd, mark);
    unsafe {
        libc::close(fd);
    }
    result.map_err(|e| {
        eyre!(
            "bridge cannot set SO_MARK (CAP_NET_ADMIN required): {}. \
             Make sure cproxy keeps an effective root uid for the lifetime \
             of the bridge — running as a non-root user, or dropping privileges \
             before the bridge is up, will trigger this.",
            e
        )
    })
}

/// Read SO_ORIGINAL_DST off an already-accepted (REDIRECT-ed) IPv4 TCP socket.
/// This recovers the address the client process originally tried to connect
/// to before the kernel rewrote the packet to land on our listener.
fn get_original_dst_v4(fd: i32) -> Result<SocketAddrV4> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(eyre!(
            "getsockopt(SO_ORIGINAL_DST) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddrV4::new(ip, port))
}

async fn dial_upstream(upstream: &UpstreamConfig, mark: u32) -> Result<TcpStream> {
    let endpoint = upstream.endpoint();
    let mut last_err: Option<eyre::Report> = None;
    let mut resolved = tokio::net::lookup_host(&endpoint)
        .await
        .map_err(|e| eyre!("failed to resolve upstream '{}': {}", endpoint, e))?;
    while let Some(addr) = resolved.next() {
        match dial_one(addr, mark).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                tracing::debug!("upstream dial {} failed: {}", addr, e);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| eyre!("upstream '{}' resolved to no addresses", endpoint)))
}

async fn dial_one(addr: SocketAddr, mark: u32) -> Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    set_so_mark(socket.as_raw_fd(), mark)?;
    let stream = socket.connect(addr).await?;
    Ok(stream)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetHintSource {
    TlsSni,
    HttpHost,
    OriginalDst,
}

async fn recover_connect_target(
    client: &TcpStream,
    original_dst: SocketAddrV4,
) -> (ConnectTarget, TargetHintSource) {
    let mut buf = [0u8; 4096];
    let peeked = match timeout(Duration::from_millis(200), client.peek(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => &buf[..n],
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => &[],
    };

    if let Some(host) = extract_tls_sni(peeked) {
        return (
            ConnectTarget::Domain {
                host,
                port: original_dst.port(),
            },
            TargetHintSource::TlsSni,
        );
    }
    if let Some(host) = extract_http_host(peeked) {
        return (
            ConnectTarget::Domain {
                host,
                port: original_dst.port(),
            },
            TargetHintSource::HttpHost,
        );
    }
    (
        ConnectTarget::Ip(original_dst),
        TargetHintSource::OriginalDst,
    )
}

fn extract_http_host(buf: &[u8]) -> Option<String> {
    if !looks_like_http_request(buf) {
        return None;
    }
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("host") {
            continue;
        }
        return normalize_host(value.trim());
    }
    None
}

fn looks_like_http_request(buf: &[u8]) -> bool {
    let prefixes: &[&[u8]] = &[
        b"GET ",
        b"HEAD ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"TRACE ",
        b"PATCH ",
        b"CONNECT ",
        b"PRI * HTTP/2.0",
    ];
    prefixes.iter().any(|prefix| buf.starts_with(prefix))
}

fn normalize_host(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        return Some(rest[..end].to_string());
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return Some(host.to_string());
        }
    }
    Some(value.to_string())
}

fn extract_tls_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return None;
    }
    let record = &buf[5..5 + record_len];
    if record.len() < 4 || record[0] != 0x01 {
        return None;
    }

    let hello_len =
        ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | (record[3] as usize);
    if record.len() < 4 + hello_len {
        return None;
    }
    let hello = &record[4..4 + hello_len];
    let mut idx = 0usize;

    idx += 2;
    idx += 32;
    let session_id_len = *hello.get(idx)? as usize;
    idx += 1 + session_id_len;

    let cipher_suites_len = u16::from_be_bytes([*hello.get(idx)?, *hello.get(idx + 1)?]) as usize;
    idx += 2 + cipher_suites_len;

    let compression_methods_len = *hello.get(idx)? as usize;
    idx += 1 + compression_methods_len;

    let extensions_len = u16::from_be_bytes([*hello.get(idx)?, *hello.get(idx + 1)?]) as usize;
    idx += 2;
    let extensions_end = idx.checked_add(extensions_len)?;
    let extensions = hello.get(idx..extensions_end)?;

    let mut ext_idx = 0usize;
    while ext_idx + 4 <= extensions.len() {
        let ext_type = u16::from_be_bytes([extensions[ext_idx], extensions[ext_idx + 1]]);
        let ext_len =
            u16::from_be_bytes([extensions[ext_idx + 2], extensions[ext_idx + 3]]) as usize;
        ext_idx += 4;
        let ext_body = extensions.get(ext_idx..ext_idx + ext_len)?;
        ext_idx += ext_len;

        if ext_type != 0x0000 || ext_body.len() < 5 {
            continue;
        }

        let list_len = u16::from_be_bytes([ext_body[0], ext_body[1]]) as usize;
        if list_len + 2 > ext_body.len() {
            return None;
        }
        let name_type = ext_body[2];
        if name_type != 0x00 {
            continue;
        }
        let name_len = u16::from_be_bytes([ext_body[3], ext_body[4]]) as usize;
        let name = ext_body.get(5..5 + name_len)?;
        return std::str::from_utf8(name).ok().map(|s| s.to_string());
    }
    None
}

async fn handle_connection(
    client: TcpStream,
    upstream: Arc<UpstreamConfig>,
    mark: u32,
) -> Result<()> {
    let fd = client.as_raw_fd();
    let original_dst = get_original_dst_v4(fd)?;
    let (target, source) = recover_connect_target(&client, original_dst).await;
    tracing::debug!(
        "bridge: redirecting client -> target {} (source={:?}, orig_dst={}) via upstream {} ({:?})",
        target.authority(),
        source,
        original_dst,
        upstream.endpoint(),
        upstream.scheme
    );

    let upstream_stream = dial_upstream(&upstream, mark).await?;
    let (mut upstream_stream, prelude) = match upstream.scheme {
        UpstreamScheme::HttpConnect => http_connect(upstream_stream, &target).await?,
        UpstreamScheme::Socks5 => socks5_connect(upstream_stream, &target).await?,
    };

    let mut client = client;
    // Replay any tunneled bytes the upstream eagerly delivered alongside the
    // CONNECT response. Server-first protocols (SSH banners, SMTP greetings)
    // depend on this; without replay the client would hang waiting for data
    // that's already been pulled into our buffer.
    if !prelude.is_empty() {
        client.write_all(&prelude).await?;
    }
    match tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await {
        Ok((to_up, to_down)) => {
            tracing::debug!(
                "bridge: closed target={} bytes_up={} bytes_down={}",
                target.authority(),
                to_up,
                to_down
            );
            Ok(())
        }
        Err(e) => Err(eyre!(
            "bridge copy failed for {}: {}",
            target.authority(),
            e
        )),
    }
}

async fn accept_loop(
    listener: TcpListener,
    upstream: Arc<UpstreamConfig>,
    mark: u32,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::debug!("bridge: shutdown signal received");
                return;
            }
            res = listener.accept() => {
                match res {
                    Ok((client, peer)) => {
                        let upstream = upstream.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(client, upstream, mark).await {
                                tracing::warn!("bridge: connection from {} failed: {}", peer, e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("bridge: accept failed: {}", e);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
}

/// RAII guard that owns the tokio runtime hosting the bridge. Dropping it
/// signals shutdown and joins the worker thread.
pub struct BridgeGuard {
    listen_port: u16,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl BridgeGuard {
    /// Start a TCP bridge listening on 127.0.0.1:`listen_port`. Each
    /// redirected connection is forwarded to the configured upstream HTTP /
    /// SOCKS5 proxy. All upstream sockets carry SO_MARK = `bridge_mark` so the
    /// firewall backend's mark-exemption rule sends them out untouched.
    pub fn spawn(listen_port: u16, upstream: UpstreamConfig, bridge_mark: u32) -> Result<Self> {
        // Fail fast if we can't set SO_MARK. The bridge cannot function
        // without it — the upstream connection would loop back into the
        // redirect rule and get pulled back to ourselves.
        probe_so_mark_capability(bridge_mark)?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<u16>>();

        let handle = std::thread::Builder::new()
            .name("cproxy-bridge".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(eyre!("failed to build tokio runtime: {}", e)));
                        return;
                    }
                };
                rt.block_on(async move {
                    let listener = match TcpListener::bind(("127.0.0.1", listen_port)).await {
                        Ok(l) => l,
                        Err(e) => {
                            let _ = ready_tx.send(Err(eyre!(
                                "bridge failed to bind 127.0.0.1:{}: {}",
                                listen_port,
                                e
                            )));
                            return;
                        }
                    };
                    let actual_port = match listener.local_addr() {
                        Ok(addr) => addr.port(),
                        Err(e) => {
                            let _ = ready_tx.send(Err(eyre!(
                                "bridge failed to read local address for 127.0.0.1:{}: {}",
                                listen_port,
                                e
                            )));
                            return;
                        }
                    };
                    if ready_tx.send(Ok(actual_port)).is_err() {
                        return;
                    }
                    accept_loop(listener, Arc::new(upstream), bridge_mark, shutdown_rx).await;
                });
            })
            .map_err(|e| eyre!("failed to spawn bridge thread: {}", e))?;

        match ready_rx.recv() {
            Ok(Ok(actual_port)) => {
                tracing::info!(
                    "bridge listening on 127.0.0.1:{} (mark=0x{:x})",
                    actual_port,
                    bridge_mark
                );
                Ok(Self {
                    listen_port: actual_port,
                    shutdown: Some(shutdown_tx),
                    handle: Some(handle),
                })
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(eyre!("bridge thread terminated before reporting readiness")),
        }
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello_with_sni(host: &str) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host_bytes.len() + 3) as u16).to_be_bytes());
        sni.push(0x00);
        sni.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni.extend_from_slice(host_bytes);

        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&[0x00, 0x2f]);
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let len = hello.len() as u32;
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_tls_sni_from_client_hello() {
        let hello = build_client_hello_with_sni("www.baidu.com");
        assert_eq!(extract_tls_sni(&hello).as_deref(), Some("www.baidu.com"));
    }

    #[test]
    fn extracts_http_host_header() {
        let req = b"HEAD / HTTP/1.1\r\nHost: www.baidu.com\r\nUser-Agent: curl/8\r\n\r\n";
        assert_eq!(extract_http_host(req).as_deref(), Some("www.baidu.com"));
    }

    #[test]
    fn strips_port_from_http_host_header() {
        let req = b"GET / HTTP/1.1\r\nHost: www.baidu.com:80\r\n\r\n";
        assert_eq!(extract_http_host(req).as_deref(), Some("www.baidu.com"));
    }
}

impl Drop for BridgeGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            if let Err(e) = h.join() {
                tracing::warn!("bridge thread join failed: {:?}", e);
            }
        }
    }
}
