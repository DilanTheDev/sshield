//! Port forwarding: local (-L), remote (-R) and dynamic SOCKS5 (-D).

use crate::model::{ForwardKind, PortForward};
use crate::ssh::{Connection, SshError};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

type Result<T> = std::result::Result<T, SshError>;

/// A running forward. Dropping it stops it.
pub struct ForwardHandle {
    pub spec: PortForward,
    /// Actual bound port (useful when 0 was requested).
    pub bound_port: u16,
    pub connections: Arc<AtomicU64>,
    task: Option<JoinHandle<()>>,
}

impl Drop for ForwardHandle {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

pub async fn start(conn: Arc<Connection>, spec: PortForward) -> Result<ForwardHandle> {
    let connections = Arc::new(AtomicU64::new(0));
    match spec.kind {
        ForwardKind::Remote => {
            let port = conn
                .handle
                .tcpip_forward(spec.bind_host.clone(), spec.bind_port as u32)
                .await
                .map_err(|_| SshError::Msg("server refused remote forward".into()))?;
            let bound = if port == 0 { spec.bind_port } else { port as u16 };
            conn.remote_targets
                .lock()
                .unwrap()
                .insert((spec.bind_host.clone(), bound as u32), (spec.dest_host.clone(), spec.dest_port));
            Ok(ForwardHandle { spec, bound_port: bound, connections, task: None })
        }
        ForwardKind::Local | ForwardKind::Dynamic => {
            let listener = TcpListener::bind((spec.bind_host.as_str(), spec.bind_port)).await?;
            let bound_port = listener.local_addr()?.port();
            let (s2, c2, n2) = (spec.clone(), conn.clone(), connections.clone());
            let task = tokio::spawn(async move {
                loop {
                    let Ok((sock, peer)) = listener.accept().await else { break };
                    let (s, c, n) = (s2.clone(), c2.clone(), n2.clone());
                    tokio::spawn(async move {
                        n.fetch_add(1, Ordering::Relaxed);
                        let _ = match s.kind {
                            ForwardKind::Local => bridge_local(&c, sock, &s.dest_host, s.dest_port, peer.port()).await,
                            _ => socks5_serve(&c, sock, peer.port()).await,
                        };
                    });
                }
            });
            Ok(ForwardHandle { spec, bound_port, connections, task: Some(task) })
        }
    }
}

async fn bridge_local(conn: &Connection, mut sock: TcpStream, host: &str, port: u16, origin_port: u16) -> Result<()> {
    let ch = conn.handle.channel_open_direct_tcpip(host.to_string(), port as u32, "127.0.0.1", origin_port as u32).await?;
    let mut s = ch.into_stream();
    let _ = tokio::io::copy_bidirectional(&mut sock, &mut s).await;
    Ok(())
}

#[derive(Debug, PartialEq)]
pub enum SocksTarget {
    V4(Ipv4Addr, u16),
    V6(Ipv6Addr, u16),
    Domain(String, u16),
}

impl SocksTarget {
    pub fn host(&self) -> String {
        match self {
            SocksTarget::V4(a, _) => a.to_string(),
            SocksTarget::V6(a, _) => a.to_string(),
            SocksTarget::Domain(d, _) => d.clone(),
        }
    }
    pub fn port(&self) -> u16 {
        match self {
            SocksTarget::V4(_, p) | SocksTarget::V6(_, p) | SocksTarget::Domain(_, p) => *p,
        }
    }
}

/// Read the SOCKS5 greeting + CONNECT request from `s`. Only "no auth" and CONNECT are supported.
pub async fn socks5_handshake<S: AsyncReadExt + AsyncWriteExt + Unpin>(s: &mut S) -> std::io::Result<SocksTarget> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await?;
    if h[0] != 5 {
        return Err(bad("not socks5"));
    }
    let mut methods = vec![0u8; h[1] as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        s.write_all(&[5, 0xff]).await?;
        return Err(bad("no acceptable auth method"));
    }
    s.write_all(&[5, 0]).await?;
    let mut r = [0u8; 4];
    s.read_exact(&mut r).await?;
    if r[0] != 5 || r[1] != 1 {
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?; // command not supported
        return Err(bad("only CONNECT supported"));
    }
    let target = match r[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            let p = read_port(s).await?;
            SocksTarget::V4(a.into(), p)
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            let p = read_port(s).await?;
            SocksTarget::V6(a.into(), p)
        }
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            s.read_exact(&mut d).await?;
            let p = read_port(s).await?;
            SocksTarget::Domain(String::from_utf8(d).map_err(|_| bad("bad domain"))?, p)
        }
        _ => return Err(bad("bad address type")),
    };
    Ok(target)
}

async fn read_port<S: AsyncReadExt + Unpin>(s: &mut S) -> std::io::Result<u16> {
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;
    Ok(u16::from_be_bytes(p))
}

async fn socks5_serve(conn: &Connection, mut sock: TcpStream, origin_port: u16) -> Result<()> {
    let target = socks5_handshake(&mut sock).await?;
    match conn.handle.channel_open_direct_tcpip(target.host(), target.port() as u32, "127.0.0.1", origin_port as u32).await {
        Ok(ch) => {
            sock.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            let mut s = ch.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut sock, &mut s).await;
            Ok(())
        }
        Err(e) => {
            let _ = sock.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await; // connection refused
            Err(e.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(req: &[u8]) -> (std::io::Result<SocksTarget>, Vec<u8>) {
        let (mut a, mut b) = tokio::io::duplex(256);
        b.write_all(req).await.unwrap();
        let r = socks5_handshake(&mut a).await;
        drop(a);
        let mut reply = vec![];
        b.read_to_end(&mut reply).await.unwrap();
        (r, reply)
    }

    #[tokio::test]
    async fn socks_domain_and_ip() {
        let mut req = vec![5, 1, 0, 5, 1, 0, 3, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        let (r, reply) = run(&req).await;
        assert_eq!(r.unwrap(), SocksTarget::Domain("example.com".into(), 443));
        assert_eq!(reply, vec![5, 0]);

        let (r, _) = run(&[5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 7, 0, 22]).await;
        assert_eq!(r.unwrap(), SocksTarget::V4([10, 0, 0, 7].into(), 22));
    }

    #[tokio::test]
    async fn socks_rejects_bind_and_auth_only() {
        let (r, reply) = run(&[5, 1, 0, 5, 2, 0, 1, 1, 1, 1, 1, 0, 80]).await;
        assert!(r.is_err());
        assert_eq!(&reply[..2], &[5, 0]);
        let (r, reply) = run(&[5, 1, 2]).await; // only user/pass offered
        assert!(r.is_err());
        assert_eq!(reply, vec![5, 0xff]);
        assert!(run(&[4, 1, 0]).await.0.is_err());
    }
}
