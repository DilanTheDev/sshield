//! End-to-end tests against a real (in-process) russh SSH server.

use futures::future::BoxFuture;
use russh::keys::PrivateKey;
use russh::server::{self, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use sshield_core::forward;
use sshield_core::model::*;
use sshield_core::ssh::*;
use sshield_core::vpn::VpnManager;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ----------------------------------------------------------- test server

#[derive(Clone)]
struct TestServer;

impl server::Server for TestServer {
    type Handler = TestHandler;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> TestHandler {
        TestHandler::default()
    }
}

#[derive(Default)]
struct TestHandler {
    shells: std::collections::HashSet<ChannelId>,
    chans: std::collections::HashMap<ChannelId, Channel<Msg>>,
}

impl server::Handler for TestHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> std::result::Result<server::Auth, Self::Error> {
        Ok(if user == "tester" && password == "s3cret" { server::Auth::Accept } else { server::Auth::reject() })
    }

    async fn channel_open_session(&mut self, c: Channel<Msg>, reply: server::ChannelOpenHandle, _s: &mut Session) -> std::result::Result<(), Self::Error> {
        self.chans.insert(c.id(), c);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(&mut self, c: ChannelId, name: &str, s: &mut Session) -> std::result::Result<(), Self::Error> {
        if name == "sftp" {
            if let Some(ch) = self.chans.remove(&c) {
                s.channel_success(c)?;
                let root = std::env::temp_dir().join(format!("sshield-sftp-root-{}", std::process::id()));
                std::fs::create_dir_all(&root).ok();
                russh_sftp::server::run(ch.into_stream(), sshield_core::devserver::FsSftp::new(root)).await;
                return Ok(());
            }
        }
        s.channel_failure(c)?;
        Ok(())
    }

    async fn pty_request(&mut self, c: ChannelId, _t: &str, _w: u32, _h: u32, _pw: u32, _ph: u32, _m: &[(russh::Pty, u32)], s: &mut Session) -> std::result::Result<(), Self::Error> {
        s.channel_success(c)?;
        Ok(())
    }

    async fn shell_request(&mut self, c: ChannelId, s: &mut Session) -> std::result::Result<(), Self::Error> {
        s.channel_success(c)?;
        self.shells.insert(c);
        s.data(c, b"welcome\r\n".to_vec())?;
        Ok(())
    }

    async fn data(&mut self, c: ChannelId, data: &[u8], s: &mut Session) -> std::result::Result<(), Self::Error> {
        if !self.shells.contains(&c) {
            return Ok(()); // forwarded-tcp channels are bridged elsewhere
        }
        let mut out = b"echo:".to_vec();
        out.extend_from_slice(data);
        s.data(c, out)?;
        Ok(())
    }

    async fn exec_request(&mut self, c: ChannelId, data: &[u8], s: &mut Session) -> std::result::Result<(), Self::Error> {
        s.channel_success(c)?;
        s.data(c, format!("ran:{}", String::from_utf8_lossy(data)).into_bytes())?;
        s.exit_status_request(c, 7)?;
        s.eof(c)?;
        s.close(c)?;
        Ok(())
    }

    async fn tcpip_forward(&mut self, address: &str, port: &mut u32, session: &mut Session) -> std::result::Result<bool, Self::Error> {
        let l = TcpListener::bind((address, *port as u16)).await.map_err(|_| russh::Error::Disconnect)?;
        *port = l.local_addr().unwrap().port() as u32;
        let (handle, addr, p) = (session.handle(), address.to_string(), *port);
        tokio::spawn(async move {
            while let Ok((mut sock, peer)) = l.accept().await {
                if let Ok(ch) = handle.channel_open_forwarded_tcpip(addr.clone(), p, "127.0.0.1", peer.port() as u32).await {
                    tokio::spawn(async move {
                        let mut c = ch.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut sock, &mut c).await;
                    });
                }
            }
        });
        Ok(true)
    }

    async fn channel_open_direct_tcpip(&mut self, channel: Channel<Msg>, host: &str, port: u32, _oa: &str, _op: u32, reply: server::ChannelOpenHandle, _s: &mut Session) -> std::result::Result<(), Self::Error> {
        match TcpStream::connect((host, port as u16)).await {
            Ok(mut sock) => {
                reply.accept().await;
                tokio::spawn(async move {
                    let mut c = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut sock, &mut c).await;
                });
            }
            Err(_) => {
                let _ = reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            }
        }
        Ok(())
    }
}

async fn start_server() -> u16 {
    let (pem, _) = generate_ed25519("server").unwrap();
    let key = PrivateKey::from_openssh(&pem).unwrap();
    let cfg = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: std::time::Duration::from_millis(1),
        ..Default::default()
    });
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut s = TestServer;
        let _ = s.run_on_socket(cfg, &l).await;
    });
    port
}

async fn start_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

// ------------------------------------------------------------ test glue

struct Ui {
    trust: bool,
    asked: AtomicUsize,
    last_changed: AtomicUsize,
    password: Option<String>,
}
impl Ui {
    fn new(trust: bool, password: Option<&str>) -> Arc<Ui> {
        Arc::new(Ui { trust, asked: 0.into(), last_changed: 0.into(), password: password.map(Into::into) })
    }
}
impl Interactor for Ui {
    fn confirm_host_key(&self, q: HostKeyQuery) -> BoxFuture<'static, bool> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.last_changed.store(q.changed as usize, Ordering::SeqCst);
        let t = self.trust;
        Box::pin(async move { t })
    }
    fn prompt(&self, _p: String, _e: bool) -> BoxFuture<'static, Option<String>> {
        let p = self.password.clone();
        Box::pin(async move { p })
    }
}

fn tmp_known_hosts() -> std::path::PathBuf {
    let mut b = [0u8; 4];
    getrandom::fill(&mut b).unwrap();
    std::env::temp_dir().join(format!("sshield-e2e-{b:?}")).join("known_hosts")
}

fn host(port: u16, auth: Auth) -> Host {
    let mut h = Host::new("t", "127.0.0.1", "tester");
    h.port = port;
    h.auth = auth;
    h.keepalive_secs = 0;
    h
}

fn connector(ui: Arc<Ui>, kh: &std::path::Path, vpn: Option<VpnPolicy>) -> Connector {
    Connector {
        interactor: ui,
        known_hosts: kh.to_path_buf(),
        vpn: Arc::new(VpnManager::new()),
        identities: vec![],
        vpn_policy: vpn,
        connect_timeout: std::time::Duration::from_secs(5),
    }
}

fn pw(s: &str) -> Auth {
    Auth::Password { password: s.into() }
}

async fn read_until(rx: &mut tokio::sync::mpsc::UnboundedReceiver<ShellEvent>, needle: &str) -> String {
    let mut acc = String::new();
    let fut = async {
        while let Some(ev) = rx.recv().await {
            if let ShellEvent::Output(b) = ev {
                acc.push_str(&String::from_utf8_lossy(&b));
                if acc.contains(needle) {
                    return;
                }
            }
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), fut).await.expect("timed out waiting for output");
    acc
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn tofu_password_shell_exec() {
    let port = start_server().await;
    let kh = tmp_known_hosts();
    let ui = Ui::new(true, None);
    let h = host(port, pw("s3cret"));

    let c = connector(ui.clone(), &kh, None).connect(&h, &[]).await.expect("connect");
    assert_eq!(ui.asked.load(Ordering::SeqCst), 1, "unknown host key must be confirmed once");
    assert!(std::fs::read_to_string(&kh).unwrap().contains("ssh-ed25519"), "key learned");

    let mut sh = open_shell(&c, &h, 80, 24).await.unwrap();
    read_until(&mut sh.rx, "welcome").await;
    sh.tx.send(ShellCmd::Input(b"hi\n".to_vec())).unwrap();
    assert!(read_until(&mut sh.rx, "echo:hi").await.contains("echo:hi"));

    let out = exec(&c, "uname -a").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ran:uname -a");
    assert_eq!(out.code, Some(7));
    c.disconnect().await;

    // second connect: key is known -> no prompt
    connector(ui.clone(), &kh, None).connect(&h, &[]).await.expect("reconnect");
    assert_eq!(ui.asked.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn bad_password_and_rejected_hostkey() {
    let port = start_server().await;
    let kh = tmp_known_hosts();
    let r = connector(Ui::new(true, None), &kh, None).connect(&host(port, pw("wrong")), &[]).await;
    assert!(matches!(r, Err(SshError::AuthFailed { .. })), "{:?}", r.err());

    let kh2 = tmp_known_hosts();
    let r = connector(Ui::new(false, None), &kh2, None).connect(&host(port, pw("s3cret")), &[]).await;
    assert!(matches!(r, Err(SshError::HostKeyRejected(_))), "{:?}", r.err());
    assert!(!kh2.exists(), "rejected key must not be stored");
}

#[tokio::test]
async fn changed_host_key_is_flagged_and_never_overwritten() {
    let port = start_server().await;
    let kh = tmp_known_hosts();
    // pre-seed a different key for this host:port
    let (_, other_pub) = generate_ed25519("other").unwrap();
    let other = russh::keys::PublicKey::from_openssh(&other_pub).unwrap();
    std::fs::create_dir_all(kh.parent().unwrap()).unwrap();
    russh::keys::known_hosts::learn_known_hosts_path("127.0.0.1", port, &other, &kh).unwrap();
    let before = std::fs::read_to_string(&kh).unwrap();

    let ui = Ui::new(false, None);
    let r = connector(ui.clone(), &kh, None).connect(&host(port, pw("s3cret")), &[]).await;
    assert!(matches!(r, Err(SshError::HostKeyRejected(_))));
    assert_eq!(ui.last_changed.load(Ordering::SeqCst), 1, "UI must be told the key CHANGED");

    // even if the user accepts, the old entry is untouched
    let ui = Ui::new(true, None);
    connector(ui, &kh, None).connect(&host(port, pw("s3cret")), &[]).await.unwrap();
    assert_eq!(std::fs::read_to_string(&kh).unwrap(), before);
}

#[tokio::test]
async fn prompt_auth_falls_back_to_password_prompt() {
    let port = start_server().await;
    let kh = tmp_known_hosts();
    let h = host(port, Auth::Prompt);
    connector(Ui::new(true, Some("s3cret")), &kh, None).connect(&h, &[]).await.expect("prompted password works");
    let r = connector(Ui::new(true, None), &kh, None).connect(&h, &[]).await;
    assert!(matches!(r, Err(SshError::Cancelled)));
}

#[tokio::test]
async fn local_forward_and_socks_through_server() {
    let ssh = start_server().await;
    let echo = start_echo().await;
    let kh = tmp_known_hosts();
    let conn = Arc::new(connector(Ui::new(true, None), &kh, None).connect(&host(ssh, pw("s3cret")), &[]).await.unwrap());

    let fwd = forward::start(
        conn.clone(),
        PortForward { kind: ForwardKind::Local, bind_host: "127.0.0.1".into(), bind_port: 0, dest_host: "127.0.0.1".into(), dest_port: echo },
    )
    .await
    .unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", fwd.bound_port)).await.unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    let socks = forward::start(
        conn.clone(),
        PortForward { kind: ForwardKind::Dynamic, bind_host: "127.0.0.1".into(), bind_port: 0, dest_host: String::new(), dest_port: 0 },
    )
    .await
    .unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", socks.bound_port)).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 0]);
    let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
    req.extend_from_slice(&echo.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0, "socks connect succeeded");
    s.write_all(b"socks!").await.unwrap();
    let mut buf = [0u8; 6];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"socks!");
    assert_eq!(fwd.connections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn jump_host_chain() {
    let jump_port = start_server().await;
    let target_port = start_server().await;
    let kh = tmp_known_hosts();
    let ui = Ui::new(true, None);
    let jump = host(jump_port, pw("s3cret"));
    let target = host(target_port, pw("s3cret"));
    let c = connector(ui.clone(), &kh, None).connect(&target, &[jump]).await.expect("via jump");
    assert_eq!(ui.asked.load(Ordering::SeqCst), 2, "both hops verify host keys");
    let out = exec(&c, "id").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ran:id");
}

#[tokio::test]
async fn vpn_policy_is_enforced_end_to_end() {
    let port = start_server().await;
    let kh = tmp_known_hosts();
    let h = host(port, pw("s3cret"));

    // tunnel interface is down -> fail closed, no direct fallback
    let mut down = VpnPolicy { enabled: true, kind: VpnKind::Existing, interface: "wg-not-here".into(), ..Default::default() };
    let r = connector(Ui::new(true, None), &kh, Some(down.clone())).connect(&h, &[]).await;
    assert!(matches!(r, Err(SshError::Vpn(_))), "{:?}", r.err());

    // "tunnel" = loopback, which really carries traffic to 127.0.0.1
    down.interface = sshield_core::vpn::loopback_interface().expect("loopback interface");
    let c = connector(Ui::new(true, None), &kh, Some(down)).connect(&h, &[]).await.expect("via pinned socket");
    assert_eq!(String::from_utf8_lossy(&exec(&c, "x").await.unwrap().stdout), "ran:x");
}

#[test]
fn effective_vpn_never_silently_bypasses() {
    let mut lib = Library::default();
    let mut h = Host::new("a", "a", "u");
    assert!(effective_vpn(&lib, &h).unwrap().is_none());
    h.require_vpn = Some(true);
    assert!(effective_vpn(&lib, &h).is_err(), "host demands VPN but none configured");
    lib.settings.vpn.enabled = true;
    lib.settings.vpn.interface = "wg0".into();
    assert!(effective_vpn(&lib, &h).unwrap().is_some());
    h.require_vpn = None;
    assert!(effective_vpn(&lib, &h).unwrap().is_some(), "global policy applies by default");
    h.require_vpn = Some(false);
    assert!(effective_vpn(&lib, &h).unwrap().is_none(), "explicit per-host opt-out");
}

#[tokio::test]
async fn sftp_roundtrip() {
    use sshield_core::sftp::Sftp;
    use std::sync::atomic::AtomicU64;
    let port = start_server().await;
    let kh = tmp_known_hosts();
    let conn = connector(Ui::new(true, None), &kh, None).connect(&host(port, pw("s3cret")), &[]).await.unwrap();
    let sftp = Sftp::open(&conn).await.expect("sftp subsystem");
    assert_eq!(sftp.home().await.unwrap(), "/");

    // upload a multi-chunk file and download it back
    let dir = std::env::temp_dir().join(format!("sshield-sftp-local-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let src = dir.join("src.bin");
    std::fs::write(&src, &data).unwrap();
    let progress = Arc::new(AtomicU64::new(0));
    let n = sftp.upload(&src, "/big.bin", Some(progress.clone())).await.unwrap();
    assert_eq!(n, data.len() as u64);
    assert_eq!(progress.load(Ordering::Relaxed), data.len() as u64);

    sftp.mkdir("/sub").await.unwrap();
    sftp.write("/sub/note.txt", b"hello").await.unwrap();
    let list = sftp.list("/").await.unwrap();
    let names: Vec<_> = list.iter().map(|e| (e.name.as_str(), e.is_dir)).collect();
    assert_eq!(names, [("sub", true), ("big.bin", false)], "dirs first, then files");
    assert_eq!(list[1].size, data.len() as u64);

    let dst = dir.join("dst.bin");
    sftp.download("/big.bin", &dst, None).await.unwrap();
    assert_eq!(std::fs::read(&dst).unwrap(), data, "download is byte-identical");

    sftp.rename("/sub/note.txt", "/sub/renamed.txt").await.unwrap();
    assert_eq!(sftp.read("/sub/renamed.txt").await.unwrap(), b"hello");
    sftp.remove_tree("/sub").await.unwrap();
    sftp.remove_file("/big.bin").await.unwrap();
    assert!(sftp.list("/").await.unwrap().is_empty());
    assert!(sftp.list("/nope").await.is_err());
}

#[tokio::test]
async fn remote_forward_reaches_local_service() {
    let ssh = start_server().await;
    let echo = start_echo().await; // lives on *our* side
    let kh = tmp_known_hosts();
    let conn = Arc::new(connector(Ui::new(true, None), &kh, None).connect(&host(ssh, pw("s3cret")), &[]).await.unwrap());
    let fwd = forward::start(
        conn.clone(),
        PortForward { kind: ForwardKind::Remote, bind_host: "127.0.0.1".into(), bind_port: 0, dest_host: "127.0.0.1".into(), dest_port: echo },
    )
    .await
    .expect("server accepted -R");
    assert_ne!(fwd.bound_port, 0, "server-chosen port is reported back");
    // connecting to the *server-side* listener must reach the service on the client side
    let mut s = TcpStream::connect(("127.0.0.1", fwd.bound_port)).await.unwrap();
    s.write_all(b"reverse").await.unwrap();
    let mut buf = [0u8; 7];
    tokio::time::timeout(std::time::Duration::from_secs(5), s.read_exact(&mut buf)).await.expect("timeout").unwrap();
    assert_eq!(&buf, b"reverse");
}
