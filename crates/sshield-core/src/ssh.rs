//! SSH connections: jump-host chains, VPN-pinned first hop, host-key TOFU,
//! password / key / keyboard-interactive auth, interactive shells and exec.

use crate::model::{Auth, Host, Identity, Library, VpnPolicy};
use crate::vpn::{self, VpnManager};
use futures::future::BoxFuture;
use russh::client::{self, AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{self, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("{0}")]
    Msg(String),
    #[error("host key rejected for {0}")]
    HostKeyRejected(String),
    #[error("authentication failed for {user}@{host}")]
    AuthFailed { user: String, host: String },
    #[error("cancelled")]
    Cancelled,
    #[error("ssh: {0}")]
    Ssh(#[from] russh::Error),
    #[error("vpn: {0}")]
    Vpn(#[from] vpn::VpnError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, SshError>;

fn msg<T: Into<String>>(s: T) -> SshError {
    SshError::Msg(s.into())
}

/// What the UI is asked when an unknown / changed host key is seen.
#[derive(Clone, Debug)]
pub struct HostKeyQuery {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    /// True when a *different* key is already on record (possible MITM).
    pub changed: bool,
}

/// Callbacks into the UI. Implemented by the app; tests supply canned answers.
pub trait Interactor: Send + Sync + 'static {
    fn confirm_host_key(&self, q: HostKeyQuery) -> BoxFuture<'static, bool>;
    /// Ask for a secret (password, passphrase, OTP). `None` = cancelled.
    fn prompt(&self, prompt: String, echo: bool) -> BoxFuture<'static, Option<String>>;
}

/// Shared table for `-R` forwards: (bind address, port) -> local destination.
pub type RemoteTargets = Arc<Mutex<HashMap<(String, u32), (String, u16)>>>;

pub struct ClientHandler {
    host: String,
    port: u16,
    known_hosts: PathBuf,
    interactor: Arc<dyn Interactor>,
    remote_targets: RemoteTargets,
    banner: Arc<Mutex<Option<String>>>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn auth_banner(&mut self, banner: &str, _s: &mut client::Session) -> std::result::Result<(), Self::Error> {
        *self.banner.lock().unwrap() = Some(banner.to_string());
        Ok(())
    }

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> std::result::Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            // Host certificates are not supported yet: refuse rather than trust blindly.
            return Ok(false);
        };
        let changed = match keys::known_hosts::check_known_hosts_path(&self.host, self.port, key, &self.known_hosts) {
            Ok(true) => return Ok(true),
            Ok(false) => false,
            Err(russh::keys::Error::KeyChanged { .. }) => true,
            Err(_) => false,
        };
        let q = HostKeyQuery {
            host: self.host.clone(),
            port: self.port,
            algorithm: key.algorithm().to_string(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            changed,
        };
        if self.interactor.confirm_host_key(q).await {
            if let Some(p) = self.known_hosts.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            // On "changed" the old line stays; the user must clean it up deliberately.
            // We only learn brand-new hosts, so a hijack is never silently overwritten.
            if !changed {
                let _ = keys::known_hosts::learn_known_hosts_path(&self.host, self.port, key, &self.known_hosts);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        let target = self
            .remote_targets
            .lock()
            .unwrap()
            .get(&(connected_address.to_string(), connected_port))
            .cloned();
        match target {
            Some((h, p)) => {
                reply.accept().await;
                tokio::spawn(async move {
                    if let Ok(mut s) = TcpStream::connect((h.as_str(), p)).await {
                        let mut c = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut s, &mut c).await;
                    }
                });
            }
            None => {
                let _ = reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
            }
        }
        Ok(())
    }
}

/// An authenticated SSH connection (plus any jump-host hops that carry it).
pub struct Connection {
    pub handle: Handle<ClientHandler>,
    pub label: String,
    pub banner: Option<String>,
    pub remote_targets: RemoteTargets,
    /// Keeps jump-host sessions alive for as long as this connection lives.
    _hops: Vec<Handle<ClientHandler>>,
}

impl Connection {
    pub async fn disconnect(&self) {
        let _ = self.handle.disconnect(Disconnect::ByApplication, "bye", "en").await;
    }
}

/// Everything needed to open connections.
#[derive(Clone)]
pub struct Connector {
    pub interactor: Arc<dyn Interactor>,
    pub known_hosts: PathBuf,
    pub vpn: Arc<VpnManager>,
    pub identities: Vec<Identity>,
    /// Effective VPN policy for this connect (already resolved per host).
    pub vpn_policy: Option<VpnPolicy>,
    pub connect_timeout: Duration,
}

/// Decide which VPN policy (if any) applies to `host`.
/// `Some(true)` demands a configured global policy; absence is an error, never a silent bypass.
pub fn effective_vpn(lib: &Library, host: &Host) -> Result<Option<VpnPolicy>> {
    let g = &lib.settings.vpn;
    let configured = vpn::expected_interface(g).is_some();
    match host.require_vpn {
        Some(false) => Ok(None),
        Some(true) if !(g.enabled || configured) => {
            Err(msg("this host requires a VPN but no VPN is configured in Settings"))
        }
        Some(true) => Ok(Some(VpnPolicy { enabled: true, ..g.clone() })),
        None if g.enabled => Ok(Some(g.clone())),
        None => Ok(None),
    }
}

impl Connector {
    pub fn new(lib: &Library, interactor: Arc<dyn Interactor>, vpn: Arc<VpnManager>, known_hosts: PathBuf, host: &Host) -> Result<Self> {
        Ok(Connector {
            interactor,
            known_hosts,
            vpn,
            identities: lib.identities.clone(),
            vpn_policy: effective_vpn(lib, host)?,
            connect_timeout: Duration::from_secs(20),
        })
    }

    fn config(host: &Host) -> Arc<client::Config> {
        let ka = host.keepalive_secs;
        Arc::new(client::Config {
            keepalive_interval: (ka > 0).then(|| Duration::from_secs(ka as u64)),
            keepalive_max: 3,
            nodelay: true,
            inactivity_timeout: None,
            ..Default::default()
        })
    }

    /// Connect through `chain` (outermost first) to `host`.
    pub async fn connect(&self, host: &Host, chain: &[Host]) -> Result<Connection> {
        let hops: Vec<&Host> = chain.iter().chain(std::iter::once(host)).collect();
        let mut parents: Vec<Handle<ClientHandler>> = vec![];
        let mut last: Option<(Handle<ClientHandler>, RemoteTargets, Option<String>)> = None;

        for (i, h) in hops.iter().enumerate() {
            let remote_targets: RemoteTargets = Default::default();
            let banner = Arc::new(Mutex::new(None));
            let handler = ClientHandler {
                host: h.hostname.clone(),
                port: h.port,
                known_hosts: self.known_hosts.clone(),
                interactor: self.interactor.clone(),
                remote_targets: remote_targets.clone(),
                banner: banner.clone(),
            };
            let cfg = Self::config(h);
            let mut handle = if let Some((prev, ..)) = last.take() {
                let ch = prev
                    .channel_open_direct_tcpip(h.hostname.clone(), h.port as u32, "127.0.0.1", 0)
                    .await
                    .map_err(|e| msg(format!("jump host could not reach {}:{}: {e}", h.hostname, h.port)))?;
                parents.push(prev);
                self.finish_connect(cfg, ch.into_stream(), handler, h).await?
            } else {
                let tcp = self.first_hop(h).await?;
                self.finish_connect(cfg, tcp, handler, h).await?
            };
            self.authenticate(&mut handle, h, i == hops.len() - 1).await?;
            let b = banner.lock().unwrap().clone();
            last = Some((handle, remote_targets, b));
        }
        let (handle, remote_targets, banner) = last.expect("at least one hop");
        Ok(Connection { handle, label: host.label.clone(), banner, remote_targets, _hops: parents })
    }

    async fn first_hop(&self, h: &Host) -> Result<TcpStream> {
        let fut = async {
            match &self.vpn_policy {
                Some(p) => Ok::<_, SshError>(vpn::connect_via(&self.vpn, p, &h.hostname, h.port).await?),
                None => Ok(TcpStream::connect((h.hostname.as_str(), h.port)).await?),
            }
        };
        match tokio::time::timeout(self.connect_timeout, fut).await {
            Ok(r) => r,
            Err(_) => Err(msg(format!("timed out connecting to {}:{}", h.hostname, h.port))),
        }
    }

    async fn finish_connect<S>(&self, cfg: Arc<client::Config>, s: S, handler: ClientHandler, h: &Host) -> Result<Handle<ClientHandler>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        match client::connect_stream(cfg, s, handler).await {
            Ok(x) => Ok(x),
            Err(russh::Error::UnknownKey) => Err(SshError::HostKeyRejected(h.hostname.clone())),
            Err(e) => Err(e.into()),
        }
    }

    fn load_identity(&self, id: &str) -> Result<PrivateKey> {
        let ident = self
            .identities
            .iter()
            .find(|i| i.id == id)
            .ok_or_else(|| msg("identity not found in library"))?;
        keys::decode_secret_key(&ident.private_key, ident.passphrase.as_deref())
            .map_err(|e| msg(format!("cannot read key '{}': {e}", ident.name)))
    }

    async fn authenticate(&self, handle: &mut Handle<ClientHandler>, h: &Host, _final: bool) -> Result<()> {
        let fail = || SshError::AuthFailed { user: h.username.clone(), host: h.hostname.clone() };
        let mut kbd_allowed = true;
        let mut try_result = |r: AuthResult| -> Option<bool> {
            match r {
                AuthResult::Success => Some(true),
                AuthResult::Failure { remaining_methods, .. } => {
                    kbd_allowed = remaining_methods.contains(&russh::MethodKind::KeyboardInteractive);
                    None
                }
            }
        };
        match &h.auth {
            Auth::Password { password } => {
                if try_result(handle.authenticate_password(&h.username, password.clone()).await?).is_some() {
                    return Ok(());
                }
            }
            Auth::Identity { id } => {
                let key = self.load_identity(id)?;
                if try_result(self.auth_key(handle, &h.username, key).await?).is_some() {
                    return Ok(());
                }
            }
            Auth::KeyFile { path, passphrase } => {
                let key = keys::load_secret_key(path, passphrase.as_deref())
                    .map_err(|e| msg(format!("cannot read key file {path}: {e}")))?;
                if try_result(self.auth_key(handle, &h.username, key).await?).is_some() {
                    return Ok(());
                }
            }
            Auth::Prompt => {
                // keyboard-interactive first (covers 2FA); fall back to password
                match self.keyboard_interactive(handle, &h.username).await? {
                    true => return Ok(()),
                    false => {
                        let pw = self
                            .interactor
                            .prompt(format!("Password for {}@{}", h.username, h.hostname), false)
                            .await
                            .ok_or(SshError::Cancelled)?;
                        if try_result(handle.authenticate_password(&h.username, pw).await?).is_some() {
                            return Ok(());
                        }
                    }
                }
            }
        }
        // Server wants a second factor / only offers keyboard-interactive.
        if kbd_allowed && !matches!(h.auth, Auth::Prompt) && self.keyboard_interactive(handle, &h.username).await? {
            return Ok(());
        }
        Err(fail())
    }

    async fn auth_key(&self, handle: &mut Handle<ClientHandler>, user: &str, key: PrivateKey) -> Result<AuthResult> {
        let hash = handle.best_supported_rsa_hash().await?.flatten();
        Ok(handle
            .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
            .await?)
    }

    /// Returns Ok(true) on success, Ok(false) if the server doesn't do keyboard-interactive / refused.
    async fn keyboard_interactive(&self, handle: &mut Handle<ClientHandler>, user: &str) -> Result<bool> {
        let mut resp = handle.authenticate_keyboard_interactive_start(user, None).await?;
        loop {
            match resp {
                KeyboardInteractiveAuthResponse::Success => return Ok(true),
                KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
                KeyboardInteractiveAuthResponse::InfoRequest { name, instructions, prompts } => {
                    let mut answers = Vec::with_capacity(prompts.len());
                    for p in &prompts {
                        let mut text = String::new();
                        for part in [&name, &instructions] {
                            if !part.trim().is_empty() {
                                text.push_str(part.trim());
                                text.push('\n');
                            }
                        }
                        text.push_str(&p.prompt);
                        answers.push(self.interactor.prompt(text, p.echo).await.ok_or(SshError::Cancelled)?);
                    }
                    resp = handle.authenticate_keyboard_interactive_respond(answers).await?;
                }
            }
        }
    }
}

// ------------------------------------------------------------------ shell

pub enum ShellCmd {
    Input(Vec<u8>),
    Resize { cols: u32, rows: u32 },
    Close,
}

#[derive(Debug)]
pub enum ShellEvent {
    Output(Vec<u8>),
    Exit(Option<u32>),
}

pub struct Shell {
    pub tx: UnboundedSender<ShellCmd>,
    pub rx: UnboundedReceiver<ShellEvent>,
}

/// Open an interactive shell with a PTY on `conn`.
pub async fn open_shell(conn: &Connection, host: &Host, cols: u32, rows: u32) -> Result<Shell> {
    let mut ch = conn.handle.channel_open_session().await?;
    ch.request_pty(false, "xterm-256color", cols, rows, 0, 0, &[]).await?;
    for (k, v) in &host.env {
        // servers commonly refuse unknown env; ignore the reply
        let _ = ch.set_env(false, k.clone(), v.clone()).await;
    }
    ch.request_shell(true).await?;
    for cmd in &host.startup {
        ch.data(format!("{cmd}\n").as_bytes()).await?;
    }
    let (cmd_tx, mut cmd_rx) = unbounded_channel::<ShellCmd>();
    let (ev_tx, ev_rx) = unbounded_channel::<ShellEvent>();
    tokio::spawn(async move {
        let mut exit: Option<u32> = None;
        loop {
            tokio::select! {
                m = ch.wait() => match m {
                    Some(ChannelMsg::Data { data }) => { let _ = ev_tx.send(ShellEvent::Output(data.to_vec())); }
                    Some(ChannelMsg::ExtendedData { data, .. }) => { let _ = ev_tx.send(ShellEvent::Output(data.to_vec())); }
                    Some(ChannelMsg::ExitStatus { exit_status }) => exit = Some(exit_status),
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                    _ => {}
                },
                c = cmd_rx.recv() => match c {
                    Some(ShellCmd::Input(b)) => { if ch.data_bytes(b).await.is_err() { break; } }
                    Some(ShellCmd::Resize { cols, rows }) => { let _ = ch.window_change(cols, rows, 0, 0).await; }
                    Some(ShellCmd::Close) | None => { let _ = ch.close().await; break; }
                }
            }
        }
        let _ = ev_tx.send(ShellEvent::Exit(exit));
    });
    Ok(Shell { tx: cmd_tx, rx: ev_rx })
}

#[derive(Debug, Default, Clone)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: Option<u32>,
}

/// Run one command without a PTY and collect its output (used by snippets / multi-exec).
pub async fn exec(conn: &Connection, command: &str) -> Result<ExecOutput> {
    let mut ch = conn.handle.channel_open_session().await?;
    ch.exec(true, command.as_bytes().to_vec()).await?;
    let mut out = ExecOutput::default();
    while let Some(m) = ch.wait().await {
        match m {
            ChannelMsg::Data { data } => out.stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => out.stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => out.code = Some(exit_status),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    Ok(out)
}

/// Fingerprint helper for UIs.
pub fn fingerprint_of(openssh_pubkey: &str) -> Option<String> {
    keys::PublicKey::from_openssh(openssh_pubkey).ok().map(|k| k.fingerprint(HashAlg::Sha256).to_string())
}

/// Generate an Ed25519 key pair; returns (private OpenSSH PEM, public OpenSSH line).
pub fn generate_ed25519(comment: &str) -> Result<(String, String)> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| msg(e.to_string()))?;
    let kp = keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
    let mut key = PrivateKey::from(kp);
    key.set_comment(comment);
    let pem = key.to_openssh(keys::ssh_key::LineEnding::LF).map_err(|e| msg(e.to_string()))?;
    let public = key.public_key().to_openssh().map_err(|e| msg(e.to_string()))?;
    Ok((pem.to_string(), public))
}
