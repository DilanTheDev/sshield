//! Development SSH server for trying sshield without a real machine.
//!
//!     cargo run -p sshield-core --example devserver
//!
//! Listens on 127.0.0.1:2222, user `demo` / password `demo`, and gives you a real
//! `bash` on a pseudo-terminal (Unix only). NOT FOR PRODUCTION: it is intentionally
//! trivial (any client may log in with the demo credentials).

use russh::keys::PrivateKey;
use russh::server::{self, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use sshield_core::ssh::generate_ed25519;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, ChildStdin, Command};

#[derive(Clone)]
struct Srv;
impl server::Server for Srv {
    type Handler = H;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> H {
        H::default()
    }
}

#[derive(Default)]
struct H {
    chans: HashMap<ChannelId, Channel<Msg>>,
    stdin: HashMap<ChannelId, ChildStdin>,
    children: Vec<Child>,
    size: (u32, u32),
}

impl server::Handler for H {
    type Error = russh::Error;

    async fn auth_password(&mut self, u: &str, p: &str) -> Result<server::Auth, Self::Error> {
        Ok(if u == "demo" && p == "demo" { server::Auth::Accept } else { server::Auth::reject() })
    }
    async fn channel_open_session(&mut self, c: Channel<Msg>, r: server::ChannelOpenHandle, _s: &mut Session) -> Result<(), Self::Error> {
        self.chans.insert(c.id(), c);
        r.accept().await;
        Ok(())
    }
    async fn subsystem_request(&mut self, c: ChannelId, name: &str, s: &mut Session) -> Result<(), Self::Error> {
        if name == "sftp" {
            if let Some(ch) = self.chans.remove(&c) {
                s.channel_success(c)?;
                let root = std::env::var("DEVSERVER_SFTP_ROOT").unwrap_or_else(|_| "/tmp/sshield-devserver-files".into());
                std::fs::create_dir_all(&root).ok();
                russh_sftp::server::run(ch.into_stream(), sshield_core::devserver::FsSftp::new(root)).await;
                return Ok(());
            }
        }
        s.channel_failure(c)?;
        Ok(())
    }
    async fn pty_request(&mut self, c: ChannelId, _t: &str, w: u32, h: u32, _pw: u32, _ph: u32, _m: &[(russh::Pty, u32)], s: &mut Session) -> Result<(), Self::Error> {
        self.size = (w, h);
        s.channel_success(c)?;
        Ok(())
    }
    async fn shell_request(&mut self, c: ChannelId, s: &mut Session) -> Result<(), Self::Error> {
        s.channel_success(c)?;
        let (w, h) = self.size;
        // Tiny PTY supervisor: frames on stdin are [type u8][len u16 BE][payload]; type 0 = keystrokes, type 1 = (rows, cols).
        let script = format!(
            r#"
import os, pty, sys, select, struct, fcntl, termios
pid, fd = pty.fork()
if pid == 0:
    os.environ.update(TERM='xterm-256color', PS1=r'\[\e[32m\]demo@sshield\[\e[0m\]:\[\e[34m\]\w\[\e[0m\]$ ')
    os.execvp('bash', ['bash', '--norc', '--noprofile'])
def setsize(r, c):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', r, c, 0, 0))
setsize({h}, {w})
out = sys.stdout.buffer
buf = b''
while True:
    r, _, _ = select.select([0, fd], [], [])
    if fd in r:
        try:
            d = os.read(fd, 65536)
        except OSError:
            break
        if not d:
            break
        out.write(d); out.flush()
    if 0 in r:
        d = os.read(0, 65536)
        if not d:
            break
        buf += d
        while len(buf) >= 3:
            t = buf[0]; n = struct.unpack('>H', buf[1:3])[0]
            if len(buf) < 3 + n:
                break
            p = buf[3:3 + n]; buf = buf[3 + n:]
            if t == 0:
                os.write(fd, p)
            elif t == 1:
                setsize(*struct.unpack('>HH', p))
"#
        );
        let mut child = Command::new("python3")
            .args(["-c", &script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| russh::Error::Disconnect)?;
        let mut out = child.stdout.take().unwrap();
        self.stdin.insert(c, child.stdin.take().unwrap());
        self.children.push(child);
        let handle = s.handle();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok(n) = out.read(&mut buf).await {
                if n == 0 || handle.data(c, buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
            let _ = handle.exit_status_request(c, 0).await;
            let _ = handle.close(c).await;
        });
        Ok(())
    }
    async fn window_change_request(&mut self, c: ChannelId, w: u32, h: u32, _pw: u32, _ph: u32, _s: &mut Session) -> Result<(), Self::Error> {
        if let Some(i) = self.stdin.get_mut(&c) {
            let mut f = vec![1u8, 0, 4];
            f.extend_from_slice(&(h as u16).to_be_bytes());
            f.extend_from_slice(&(w as u16).to_be_bytes());
            let _ = i.write_all(&f).await;
        }
        Ok(())
    }
    async fn data(&mut self, c: ChannelId, d: &[u8], _s: &mut Session) -> Result<(), Self::Error> {
        if let Some(i) = self.stdin.get_mut(&c) {
            for chunk in d.chunks(60_000) {
                let mut f = vec![0u8];
                f.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
                f.extend_from_slice(chunk);
                let _ = i.write_all(&f).await;
            }
        }
        Ok(())
    }
    async fn channel_open_direct_tcpip(&mut self, ch: Channel<Msg>, host: &str, port: u32, _a: &str, _p: u32, reply: server::ChannelOpenHandle, _s: &mut Session) -> Result<(), Self::Error> {
        match TcpStream::connect((host, port as u16)).await {
            Ok(mut sock) => {
                reply.accept().await;
                tokio::spawn(async move {
                    let mut c = ch.into_stream();
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

#[tokio::main]
async fn main() {
    let (pem, _) = generate_ed25519("devserver").unwrap();
    let cfg = Arc::new(server::Config {
        keys: vec![PrivateKey::from_openssh(&pem).unwrap()],
        auth_rejection_time: std::time::Duration::from_millis(100),
        ..Default::default()
    });
    let port: u16 = std::env::args().nth(1).and_then(|p| p.parse().ok()).unwrap_or(2222);
    let l = TcpListener::bind(("127.0.0.1", port)).await.expect("bind");
    eprintln!("devserver on 127.0.0.1:{port}  user=demo password=demo");
    let _ = Srv.run_on_socket(cfg, &l).await;
}
