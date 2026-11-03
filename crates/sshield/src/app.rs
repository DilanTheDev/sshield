use crate::sftp_view::SftpTab;
use crate::term::TermView;
use crate::theme::{self, c, Theme};
use eframe::egui::{self, Align, Layout, RichText};
use futures::future::BoxFuture;
use sshield_core::forward::{self, ForwardHandle};
use sshield_core::ssh::{self, Connection, Connector, HostKeyQuery, Interactor, ShellCmd, ShellEvent};
use sshield_core::vault::{self, KdfCost, Vault};
use sshield_core::vpn::{self, VpnManager};
use sshield_core::*;
use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc::UnboundedSender, oneshot};

// ------------------------------------------------------------ messaging

pub struct SessionReady {
    conn: Arc<Connection>,
    shell: Option<(UnboundedSender<ShellCmd>, Receiver<ShellEvent>)>,
    forwards: Vec<ForwardHandle>,
    warnings: Vec<String>,
}

enum UiMsg {
    HostKey(HostKeyQuery, oneshot::Sender<bool>),
    Secret { prompt: String, echo: bool, reply: oneshot::Sender<Option<String>> },
    Session { tab: u64, res: Result<Box<SessionReady>, String> },
    Unlocked(Result<(Vault, Library), String>),
    Toast(String),
}

struct UiInteractor {
    tx: Sender<UiMsg>,
    ctx: egui::Context,
}

impl Interactor for UiInteractor {
    fn confirm_host_key(&self, q: HostKeyQuery) -> BoxFuture<'static, bool> {
        let (r, rx) = oneshot::channel();
        let _ = self.tx.send(UiMsg::HostKey(q, r));
        self.ctx.request_repaint();
        Box::pin(async move { rx.await.unwrap_or(false) })
    }
    fn prompt(&self, prompt: String, echo: bool) -> BoxFuture<'static, Option<String>> {
        let (reply, rx) = oneshot::channel();
        let _ = self.tx.send(UiMsg::Secret { prompt, echo, reply });
        self.ctx.request_repaint();
        Box::pin(async move { rx.await.ok().flatten() })
    }
}

enum Pending {
    HostKey(HostKeyQuery, Option<oneshot::Sender<bool>>),
    Secret { prompt: String, echo: bool, value: String, reply: Option<oneshot::Sender<Option<String>>> },
}

// ----------------------------------------------------------------- tabs

enum TermState {
    Connecting,
    Ready,
    Closed(String),
}

struct TermTab {
    host: Host,
    state: TermState,
    term: TermView,
    conn: Option<Arc<Connection>>,
    tx: Option<UnboundedSender<ShellCmd>>,
    ev_rx: Option<Receiver<ShellEvent>>,
    forwards: Vec<ForwardHandle>,
    log: Option<std::fs::File>,
    banner: Option<String>,
    warnings: Vec<String>,
    started: Instant,
    via: String,
}

enum SftpState {
    Connecting,
    Ready(Box<SftpTab>),
    Failed(String),
}

struct SftpEntry {
    host: Host,
    state: SftpState,
}

enum TabKind {
    Home,
    Term(Box<TermTab>),
    Sftp(Box<SftpEntry>),
}

struct Tab {
    id: u64,
    title: String,
    kind: TabKind,
}

// -------------------------------------------------------------- editors

struct HostEditor {
    host: Host,
    is_new: bool,
    auth_kind: usize,
    password: String,
    identity: String,
    keyfile: String,
    keypass: String,
    tags: String,
    startup: String,
    env: String,
    vpn_choice: usize,
    theme: String,
    error: String,
}

impl HostEditor {
    fn new(host: Host, is_new: bool) -> Self {
        let (auth_kind, password, identity, keyfile, keypass) = match &host.auth {
            Auth::Prompt => (0, String::new(), String::new(), String::new(), String::new()),
            Auth::Password { password } => (1, password.clone(), String::new(), String::new(), String::new()),
            Auth::Identity { id } => (2, String::new(), id.clone(), String::new(), String::new()),
            Auth::KeyFile { path, passphrase } => (3, String::new(), String::new(), path.clone(), passphrase.clone().unwrap_or_default()),
        };
        HostEditor {
            auth_kind,
            password,
            identity,
            keyfile,
            keypass,
            tags: host.tags.join(", "),
            startup: host.startup.join("\n"),
            env: host.env.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("\n"),
            vpn_choice: match host.require_vpn {
                None => 0,
                Some(true) => 1,
                Some(false) => 2,
            },
            theme: host.theme.clone().unwrap_or_default(),
            host,
            is_new,
            error: String::new(),
        }
    }

    fn build(&self) -> Result<Host, String> {
        let mut h = self.host.clone();
        if h.hostname.trim().is_empty() {
            return Err("Hostname is required".into());
        }
        if h.label.trim().is_empty() {
            h.label = h.hostname.clone();
        }
        h.auth = match self.auth_kind {
            1 => Auth::Password { password: self.password.clone() },
            2 if !self.identity.is_empty() => Auth::Identity { id: self.identity.clone() },
            2 => return Err("Pick a key (create one in Settings → Keys)".into()),
            3 if !self.keyfile.trim().is_empty() => Auth::KeyFile {
                path: self.keyfile.trim().into(),
                passphrase: (!self.keypass.is_empty()).then(|| self.keypass.clone()),
            },
            3 => return Err("Key file path is required".into()),
            _ => Auth::Prompt,
        };
        h.tags = self.tags.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        h.startup = self.startup.lines().map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
        h.env = self
            .env
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .filter(|(k, _)| !k.is_empty())
            .collect();
        h.require_vpn = [None, Some(true), Some(false)][self.vpn_choice.min(2)];
        h.theme = (!self.theme.is_empty()).then(|| self.theme.clone());
        Ok(h)
    }
}

#[derive(PartialEq, Clone, Copy)]
enum SettingsTab {
    General,
    Vpn,
    Keys,
    Security,
    Highlights,
    About,
}

enum Action {
    Connect(Id),
    Sftp(Id),
    Edit(Id),
    Delete(Id),
    Duplicate(Id),
    Favorite(Id),
}

pub struct App {
    rt: tokio::runtime::Handle,
    ctx: egui::Context,
    tx: Sender<UiMsg>,
    rx: Receiver<UiMsg>,
    vpn: Arc<VpnManager>,
    data_dir: PathBuf,

    // vault
    vault: Option<Vault>,
    lib: Library,
    dirty: bool,
    unlocking: bool,
    pw: String,
    pw2: String,
    lock_error: String,

    // ui state
    theme: Theme,
    tabs: Vec<Tab>,
    active: usize,
    next_id: u64,
    pending: VecDeque<Pending>,
    toasts: Vec<(String, Instant)>,
    search: String,
    quick: String,
    editor: Option<HostEditor>,
    show_settings: bool,
    settings_tab: SettingsTab,
    show_snippets: bool,
    snippet_draft: (String, String),
    palette: Option<String>,
    broadcast: bool,
    applied_font: String,
    vpn_status: (Instant, Option<bool>),
    vpn_test_target: String,
    new_pw: String,
    key_name: String,
    key_import: String,
    key_pass: String,
    key_error: String,
    new_highlight: (String, u32),
    confirm_delete: Option<Id>,
    sel_identity: Option<Id>,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, rt: tokio::runtime::Handle) -> Self {
        let (tx, rx) = channel();
        let data_dir = vault::data_dir();
        let lib = Library::default();
        let theme = theme::find(&lib.settings.theme);
        theme::apply_visuals(&cc.egui_ctx, &theme, lib.settings.accent, 1.0);
        App {
            rt,
            ctx: cc.egui_ctx.clone(),
            tx,
            rx,
            vpn: Arc::new(VpnManager::new()),
            data_dir,
            vault: None,
            lib,
            dirty: false,
            unlocking: false,
            pw: String::new(),
            pw2: String::new(),
            lock_error: String::new(),
            theme,
            tabs: vec![Tab { id: 0, title: "Hosts".into(), kind: TabKind::Home }],
            active: 0,
            next_id: 1,
            pending: VecDeque::new(),
            toasts: vec![],
            search: String::new(),
            quick: String::new(),
            editor: None,
            show_settings: false,
            settings_tab: SettingsTab::General,
            show_snippets: false,
            snippet_draft: Default::default(),
            palette: None,
            broadcast: false,
            applied_font: "\u{0}".into(),
            vpn_status: (Instant::now() - Duration::from_secs(60), None),
            vpn_test_target: String::new(),
            new_pw: String::new(),
            key_name: String::new(),
            key_import: String::new(),
            key_pass: String::new(),
            key_error: String::new(),
            new_highlight: (String::new(), 0xe0af68),
            confirm_delete: None,
            sel_identity: None,
        }
    }

    fn vault_path(&self) -> PathBuf {
        self.data_dir.join("vault.json")
    }
    fn known_hosts(&self) -> PathBuf {
        self.data_dir.join("known_hosts")
    }
    fn toast(&mut self, s: impl Into<String>) {
        self.toasts.push((s.into(), Instant::now()));
    }

    fn mutate(&mut self, f: impl FnOnce(&mut Library)) {
        f(&mut self.lib);
        self.dirty = true;
    }

    fn save_if_dirty(&mut self) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        if let Some(v) = &mut self.vault {
            v.set_mirror((!self.lib.settings.sync_dir.trim().is_empty()).then(|| PathBuf::from(self.lib.settings.sync_dir.trim())));
            if let Err(e) = v.save(&self.lib) {
                self.toasts.push((format!("Saving vault failed: {e}"), Instant::now()));
            }
        }
    }

    fn apply_theme(&mut self) {
        self.theme = theme::find(&self.lib.settings.theme);
        theme::apply_visuals(&self.ctx, &self.theme, self.lib.settings.accent, self.lib.settings.ui_scale);
        self.apply_font();
    }

    fn apply_font(&mut self) {
        let want = self.lib.settings.font_family.clone();
        if want == self.applied_font {
            return;
        }
        self.applied_font = want.clone();
        let mut fonts = egui::FontDefinitions::default();
        let mut candidates: Vec<String> = vec![];
        if std::path::Path::new(&want).is_file() {
            candidates.push(want);
        }
        candidates.extend(
            [
                r"C:\Windows\Fonts\CascadiaMono.ttf",
                r"C:\Windows\Fonts\consola.ttf",
                "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf",
            ]
            .map(String::from),
        );
        for p in candidates {
            if let Ok(bytes) = std::fs::read(&p) {
                fonts.font_data.insert("user_mono".into(), Arc::new(egui::FontData::from_owned(bytes)));
                fonts.families.entry(egui::FontFamily::Monospace).or_default().insert(0, "user_mono".into());
                break;
            }
        }
        // CJK / symbol fallbacks that ship with Windows, appended after the defaults
        for (name, p) in [("win_yahei", r"C:\Windows\Fonts\msyh.ttc"), ("win_symbols", r"C:\Windows\Fonts\seguisym.ttf")] {
            if let Ok(bytes) = std::fs::read(p) {
                fonts.font_data.insert(name.into(), Arc::new(egui::FontData::from_owned(bytes)));
                for fam in [egui::FontFamily::Monospace, egui::FontFamily::Proportional] {
                    fonts.families.entry(fam).or_default().push(name.into());
                }
            }
        }
        self.ctx.set_fonts(fonts);
    }

    // ------------------------------------------------------------ vault

    fn do_unlock(&mut self, create: bool) {
        let (path, pw, tx, ctx) = (self.vault_path(), self.pw.clone(), self.tx.clone(), self.ctx.clone());
        self.unlocking = true;
        self.lock_error.clear();
        self.rt.spawn_blocking(move || {
            let r = if create {
                Vault::create(&path, &pw, &Library::default(), KdfCost::STRONG).map(|v| (v, Library::default())).map_err(|e| e.to_string())
            } else {
                Vault::unlock(&path, &pw).map_err(|e| e.to_string())
            };
            let _ = tx.send(UiMsg::Unlocked(r));
            ctx.request_repaint();
        });
    }

    fn lock(&mut self) {
        self.tabs.truncate(1);
        self.active = 0;
        self.vault = None;
        self.lib = Library::default();
        self.pw.clear();
        self.pw2.clear();
        self.show_settings = false;
        self.editor = None;
    }

    // --------------------------------------------------------- sessions

    fn new_tab(&mut self, title: String, kind: TabKind) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.tabs.push(Tab { id, title, kind });
        self.active = self.tabs.len() - 1;
        id
    }

    fn open_host(&mut self, host: Host) {
        self.mutate(|l| {
            if let Some(h) = l.hosts.iter_mut().find(|h| h.id == host.id) {
                h.last_connected = Some(now());
            }
        });
        let title = host.label.clone();
        let scrollback = self.lib.settings.scrollback;
        let tab = TermTab {
            host: host.clone(),
            state: TermState::Connecting,
            term: TermView::new(scrollback),
            conn: None,
            tx: None,
            ev_rx: None,
            forwards: vec![],
            log: None,
            banner: None,
            warnings: vec![],
            started: Instant::now(),
            via: String::new(),
        };
        let id = self.new_tab(title, TabKind::Term(Box::new(tab)));
        self.start_connect(id, host, true);
    }

    fn open_sftp(&mut self, host: Host) {
        let title = format!("SFTP · {}", host.label);
        let id = self.new_tab(title, TabKind::Sftp(Box::new(SftpEntry { host: host.clone(), state: SftpState::Connecting })));
        self.start_connect(id, host, false);
    }

    fn fail_tab(&mut self, id: u64, msg: String) {
        if let Some(t) = self.tabs.iter_mut().find(|t| t.id == id) {
            match &mut t.kind {
                TabKind::Term(tt) => tt.state = TermState::Closed(msg),
                TabKind::Sftp(s) => s.state = SftpState::Failed(msg),
                _ => {}
            }
        }
    }

    fn start_connect(&mut self, tab_id: u64, host: Host, want_shell: bool) {
        let chain = match self.lib.jump_chain(&host) {
            Ok(c) => c,
            Err(e) => return self.fail_tab(tab_id, e),
        };
        let interactor = Arc::new(UiInteractor { tx: self.tx.clone(), ctx: self.ctx.clone() });
        let connector = match Connector::new(&self.lib, interactor, self.vpn.clone(), self.known_hosts(), &host) {
            Ok(c) => c,
            Err(e) => return self.fail_tab(tab_id, e.to_string()),
        };
        if let Some(TabKind::Term(t)) = self.tabs.iter_mut().find(|t| t.id == tab_id).map(|t| &mut t.kind) {
            t.via = if chain.is_empty() { String::new() } else { format!("via {}", chain.iter().map(|h| h.label.as_str()).collect::<Vec<_>>().join(" → ")) };
            if connector.vpn_policy.is_some() {
                t.via.push_str(" · 🛡 VPN-pinned");
            }
        }
        let (tx, ctx) = (self.tx.clone(), self.ctx.clone());
        let (cols, rows) = self
            .tabs
            .iter()
            .find(|t| t.id == tab_id)
            .and_then(|t| if let TabKind::Term(t) = &t.kind { Some(t.term.size()) } else { None })
            .unwrap_or((120, 30));
        self.rt.spawn(async move {
            let res: Result<Box<SessionReady>, String> = async {
                let conn = Arc::new(connector.connect(&host, &chain).await.map_err(|e| e.to_string())?);
                let mut warnings = vec![];
                let mut forwards = vec![];
                for f in &host.forwards {
                    match forward::start(conn.clone(), f.clone()).await {
                        Ok(h) => forwards.push(h),
                        Err(e) => warnings.push(format!("forward {}:{} failed: {e}", f.bind_host, f.bind_port)),
                    }
                }
                let shell = if want_shell {
                    let mut sh = ssh::open_shell(&conn, &host, cols as u32, rows as u32).await.map_err(|e| e.to_string())?;
                    let (etx, erx) = channel::<ShellEvent>();
                    let ctx2 = ctx.clone();
                    tokio::spawn(async move {
                        while let Some(ev) = sh.rx.recv().await {
                            let end = matches!(ev, ShellEvent::Exit(_));
                            let _ = etx.send(ev);
                            ctx2.request_repaint();
                            if end {
                                break;
                            }
                        }
                    });
                    Some((sh.tx, erx))
                } else {
                    None
                };
                Ok(Box::new(SessionReady { conn, shell, forwards, warnings }))
            }
            .await;
            let _ = tx.send(UiMsg::Session { tab: tab_id, res });
            ctx.request_repaint();
        });
    }

    fn handle_msgs(&mut self) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                UiMsg::HostKey(q, r) => self.pending.push_back(Pending::HostKey(q, Some(r))),
                UiMsg::Secret { prompt, echo, reply } => {
                    self.pending.push_back(Pending::Secret { prompt, echo, value: String::new(), reply: Some(reply) })
                }
                UiMsg::Toast(s) => self.toast(s),
                UiMsg::Unlocked(r) => {
                    self.unlocking = false;
                    match r {
                        Ok((v, lib)) => {
                            self.vault = Some(v);
                            self.lib = lib;
                            self.pw.clear();
                            self.pw2.clear();
                            self.applied_font = "\u{0}".into();
                            self.apply_theme();
                        }
                        Err(e) => self.lock_error = e,
                    }
                }
                UiMsg::Session { tab, res } => self.on_session(tab, res),
            }
        }
    }

    fn on_session(&mut self, tab: u64, res: Result<Box<SessionReady>, String>) {
        let log_enabled = self.lib.settings.log_sessions;
        let log_dir = if self.lib.settings.log_dir.trim().is_empty() { self.data_dir.join("logs") } else { PathBuf::from(self.lib.settings.log_dir.trim()) };
        let (handle, ctx) = (self.rt.clone(), self.ctx.clone());
        let Some(t) = self.tabs.iter_mut().find(|t| t.id == tab) else { return };
        match (res, &mut t.kind) {
            (Err(e), TabKind::Term(tt)) => tt.state = TermState::Closed(e),
            (Err(e), TabKind::Sftp(s)) => s.state = SftpState::Failed(e),
            (Ok(r), TabKind::Term(tt)) => {
                tt.banner = r.conn.banner.clone();
                tt.warnings = r.warnings;
                tt.forwards = r.forwards;
                tt.conn = Some(r.conn);
                if let Some((tx, rx)) = r.shell {
                    tt.tx = Some(tx);
                    tt.ev_rx = Some(rx);
                }
                tt.started = Instant::now();
                tt.state = TermState::Ready;
                if log_enabled {
                    let _ = std::fs::create_dir_all(&log_dir);
                    let name: String = tt.host.label.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect();
                    tt.log = std::fs::File::create(log_dir.join(format!("{name}-{}.log", now()))).ok();
                }
            }
            (Ok(r), TabKind::Sftp(s)) => {
                s.state = SftpState::Ready(Box::new(SftpTab::new(handle, ctx, r.conn)));
            }
            _ => {}
        }
    }

    fn pump_terminals(&mut self) {
        for t in &mut self.tabs {
            if let TabKind::Term(tt) = &mut t.kind {
                let mut closed: Option<String> = None;
                if let Some(rx) = &tt.ev_rx {
                    let mut budget = 512 * 1024usize;
                    while budget > 0 {
                        match rx.try_recv() {
                            Ok(ShellEvent::Output(b)) => {
                                budget = budget.saturating_sub(b.len());
                                tt.term.feed(&b);
                                if let Some(f) = &mut tt.log {
                                    let _ = f.write_all(&b);
                                }
                            }
                            Ok(ShellEvent::Exit(code)) => {
                                closed = Some(match code {
                                    Some(0) | None => "Session closed.".into(),
                                    Some(c) => format!("Session closed (exit status {c})."),
                                });
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                    if budget == 0 {
                        self.ctx.request_repaint();
                    }
                }
                if let Some(msg) = closed {
                    tt.state = TermState::Closed(msg);
                    tt.tx = None;
                    tt.ev_rx = None;
                    tt.forwards.clear();
                }
            }
        }
    }

    fn close_tab(&mut self, idx: usize) {
        if idx == 0 || idx >= self.tabs.len() {
            return;
        }
        let t = self.tabs.remove(idx);
        if let TabKind::Term(tt) = t.kind {
            if let Some(tx) = &tt.tx {
                let _ = tx.send(ShellCmd::Close);
            }
            if let Some(conn) = tt.conn {
                self.rt.spawn(async move { conn.disconnect().await });
            }
        }
        self.active = self.active.min(self.tabs.len() - 1);
        self.maybe_stop_vpn();
    }

    fn maybe_stop_vpn(&self) {
        let any = self.tabs.iter().any(|t| matches!(&t.kind, TabKind::Term(tt) if tt.conn.is_some()));
        if !any && self.lib.settings.vpn.auto_stop {
            let v = self.vpn.clone();
            self.rt.spawn(async move { v.stop().await });
        }
    }

    fn send_to_active(&mut self, bytes: &[u8]) {
        if let Some(Tab { kind: TabKind::Term(tt), .. }) = self.tabs.get(self.active) {
            if let Some(tx) = &tt.tx {
                let _ = tx.send(ShellCmd::Input(bytes.to_vec()));
            }
        }
    }

    fn send_to_all(&mut self, bytes: &[u8]) {
        for t in &self.tabs {
            if let TabKind::Term(tt) = &t.kind {
                if let Some(tx) = &tt.tx {
                    let _ = tx.send(ShellCmd::Input(bytes.to_vec()));
                }
            }
        }
    }

    fn quick_connect(&mut self) {
        let s = self.quick.trim().to_string();
        if s.is_empty() {
            return;
        }
        let (user, rest) = s.split_once('@').map(|(u, r)| (u.to_string(), r.to_string())).unwrap_or_else(|| {
            (std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "root".into()), s.clone())
        });
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse().unwrap()),
            _ => (rest, 22),
        };
        let mut h = Host::new(&format!("{user}@{host}"), &host, &user);
        h.port = port;
        self.quick.clear();
        self.open_host(h);
    }
}

// ================================================================== UI

impl eframe::App for App {
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if self.lib.settings.vpn.auto_stop {
            let v = self.vpn.clone();
            self.rt.block_on(async move { v.stop().await });
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.handle_msgs();
        if self.vault.is_none() {
            self.lock_screen(ui);
            return;
        }
        self.pump_terminals();
        self.shortcuts(&ctx);
        self.top_bar(ui);
        self.status_bar(ui);
        egui::CentralPanel::default().frame(egui::Frame::NONE.fill(c(self.theme.bg))).show(ui, |ui| self.tab_body(ui));
        self.dialogs(&ctx);
        self.toasts.retain(|(_, t)| t.elapsed() < Duration::from_secs(5));
        if !self.toasts.is_empty() {
            egui::Area::new(egui::Id::unique("toasts")).anchor(egui::Align2::RIGHT_BOTTOM, [-12.0, -36.0]).show(&ctx, |ui| {
                for (s, _) in &self.toasts {
                    egui::Frame::popup(ui.style()).show(ui, |ui| ui.label(s));
                }
            });
            ctx.request_repaint_after(Duration::from_millis(500));
        }
        self.save_if_dirty();
    }
}

impl App {
    fn lock_screen(&mut self, ui: &mut egui::Ui) {
        let exists = Vault::exists(&self.vault_path());
        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() * 0.22);
                ui.heading(RichText::new("🛡 sshield").size(34.0));
                ui.label("A fast, free, native SSH client. Everything is encrypted with your master password.");
                ui.add_space(18.0);
                let mut submit = false;
                ui.scope(|ui| {
                    ui.set_max_width(340.0);
                    let r = ui.add(egui::TextEdit::singleline(&mut self.pw).password(true).hint_text("Master password").desired_width(340.0));
                    if exists {
                        submit |= r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if ui.memory(|m| m.focused().is_none()) {
                            r.request_focus();
                        }
                    } else {
                        let r2 = ui.add(egui::TextEdit::singleline(&mut self.pw2).password(true).hint_text("Repeat master password").desired_width(340.0));
                        submit |= r2.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        ui.small("Choose a long passphrase. It cannot be recovered - there is no server and no reset.");
                    }
                });
                ui.add_space(8.0);
                let label = if exists { "Unlock" } else { "Create encrypted vault" };
                if ui.add_enabled(!self.unlocking, egui::Button::new(RichText::new(label).size(16.0)).min_size(egui::vec2(200.0, 32.0))).clicked() || (submit && !self.unlocking) {
                    if exists {
                        self.do_unlock(false);
                    } else if self.pw.chars().count() < 8 {
                        self.lock_error = "Use at least 8 characters.".into();
                    } else if self.pw != self.pw2 {
                        self.lock_error = "Passwords do not match.".into();
                    } else {
                        self.do_unlock(true);
                    }
                }
                if self.unlocking {
                    ui.add_space(6.0);
                    ui.spinner();
                }
                if !self.lock_error.is_empty() {
                    ui.add_space(6.0);
                    ui.colored_label(c(self.theme.ansi[1]), &self.lock_error);
                }
            });
        });
    }

    fn shortcuts(&mut self, ctx: &egui::Context) {
        use egui::{Key, KeyboardShortcut, Modifiers};
        let k = |m: Modifiers, key: Key| KeyboardShortcut::new(m, key);
        if ctx.input_mut(|i| i.consume_shortcut(&k(Modifiers::COMMAND, Key::K))) {
            self.palette = Some(String::new());
        }
        if ctx.input_mut(|i| i.consume_shortcut(&k(Modifiers::COMMAND | Modifiers::SHIFT, Key::W))) {
            let a = self.active;
            self.close_tab(a);
        }
        for (n, key) in [Key::Num1, Key::Num2, Key::Num3, Key::Num4, Key::Num5, Key::Num6, Key::Num7, Key::Num8, Key::Num9].into_iter().enumerate() {
            if ctx.input_mut(|i| i.consume_shortcut(&k(Modifiers::ALT, key))) && n < self.tabs.len() {
                self.active = n;
            }
        }
    }

    fn vpn_chip(&mut self, ui: &mut egui::Ui) {
        let p = &self.lib.settings.vpn;
        if !p.enabled {
            ui.label(RichText::new("🛡 VPN off").weak()).on_hover_text("SSH traffic is not forced through a VPN. Enable in Settings → VPN.");
            return;
        }
        if self.vpn_status.0.elapsed() > Duration::from_secs(2) {
            let up = vpn::expected_interface(p).map(|i| vpn::find_interface(&i).is_some());
            self.vpn_status = (Instant::now(), up);
        }
        ui.ctx().request_repaint_after(Duration::from_secs(2));
        let iface = vpn::expected_interface(p).unwrap_or_else(|| "?".into());
        match self.vpn_status.1 {
            Some(true) => ui.label(RichText::new(format!("🛡 VPN {iface} ●")).color(c(self.theme.ansi[2]))).on_hover_text("Tunnel is up. SSH is pinned to this interface and blocked otherwise."),
            _ => ui.label(RichText::new(format!("🛡 VPN {iface} ○")).color(c(self.theme.ansi[1]))).on_hover_text(if p.auto_start {
                "Tunnel is down. It will be started on connect; SSH never falls back to a direct connection."
            } else {
                "Tunnel is down. SSH connections are BLOCKED until it is up."
            }),
        };
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("tabs").frame(egui::Frame::NONE.fill(c(self.theme.bg)).inner_margin(egui::Margin::symmetric(8, 6))).show(ui, |ui| {
            ui.horizontal(|ui| {
                let mut close: Option<usize> = None;
                let mut activate: Option<usize> = None;
                for (i, t) in self.tabs.iter().enumerate() {
                    let sel = i == self.active;
                    let dot = match &t.kind {
                        TabKind::Term(tt) => match tt.state {
                            TermState::Ready => "● ",
                            TermState::Connecting => "◌ ",
                            TermState::Closed(_) => "○ ",
                        },
                        TabKind::Home => "⌂ ",
                        _ => "",
                    };
                    let r = ui.selectable_label(sel, format!("{dot}{}", t.title));
                    if r.clicked() {
                        activate = Some(i);
                    }
                    if r.middle_clicked() {
                        close = Some(i);
                    }
                    if i > 0 && ui.small_button("×").clicked() {
                        close = Some(i);
                    }
                    ui.add_space(4.0);
                }
                if let Some(i) = activate {
                    self.active = i;
                }
                if let Some(i) = close {
                    self.close_tab(i);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("🔒").on_hover_text("Lock vault").clicked() {
                        self.lock();
                    }
                    if ui.button("⚙").on_hover_text("Settings").clicked() {
                        self.show_settings = !self.show_settings;
                    }
                    if ui.button("{ } Snippets").clicked() {
                        self.show_snippets = !self.show_snippets;
                    }
                    if ui.button("⌕ Ctrl+K").on_hover_text("Command palette").clicked() {
                        self.palette = Some(String::new());
                    }
                    let terms = self.tabs.iter().filter(|t| matches!(&t.kind, TabKind::Term(tt) if tt.tx.is_some())).count();
                    if terms > 1 {
                        ui.toggle_value(&mut self.broadcast, "📡 Broadcast").on_hover_text("Type once, send to ALL open terminals");
                    } else {
                        self.broadcast = false;
                    }
                    self.vpn_chip(ui);
                });
            });
        });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("status").frame(egui::Frame::NONE.fill(c(self.theme.bg)).inner_margin(egui::Margin::symmetric(10, 3))).show(ui, |ui| {
            ui.horizontal(|ui| {
                match self.tabs.get(self.active).map(|t| &t.kind) {
                    Some(TabKind::Term(tt)) => {
                        let (cols, rows) = tt.term.size();
                        ui.small(format!("{}@{}:{}", tt.host.username, tt.host.hostname, tt.host.port));
                        if !tt.via.is_empty() {
                            ui.small(&tt.via);
                        }
                        if !tt.forwards.is_empty() {
                            ui.small(format!("⇄ {} forwards", tt.forwards.len()));
                        }
                        ui.small(format!("{cols}×{rows}"));
                        if matches!(tt.state, TermState::Ready) {
                            ui.small(format!("up {}", fmt_dur(tt.started.elapsed())));
                        }
                    }
                    _ => {
                        ui.small(format!("{} hosts · {} keys · {} snippets", self.lib.hosts.len(), self.lib.identities.len(), self.lib.snippets.len()));
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.small("vault encrypted · XChaCha20-Poly1305 + Argon2id");
                });
            });
        });
    }

    fn tab_body(&mut self, ui: &mut egui::Ui) {
        if self.active >= self.tabs.len() {
            self.active = 0;
        }
        let active = self.active;
        let kind_tag = match &self.tabs[active].kind {
            TabKind::Home => 0,
            TabKind::Term(_) => 1,
            TabKind::Sftp(_) => 2,
        };
        match kind_tag {
            0 => egui::Frame::NONE.inner_margin(14.0).show(ui, |ui| self.home(ui)).inner,
            1 => self.terminal_body(ui, active),
            _ => {
                let theme = self.theme.clone();
                let mut reopen: Option<Host> = None;
                if let TabKind::Sftp(s) = &mut self.tabs[active].kind {
                    egui::Frame::NONE.inner_margin(10.0).show(ui, |ui| match &mut s.state {
                        SftpState::Connecting => {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(format!("Connecting to {}…", s.host.label));
                            });
                        }
                        SftpState::Failed(e) => {
                            ui.colored_label(c(theme.ansi[1]), e.as_str());
                            if ui.button("Retry").clicked() {
                                reopen = Some(s.host.clone());
                            }
                        }
                        SftpState::Ready(t) => t.ui(ui, &theme),
                    });
                }
                if let Some(h) = reopen {
                    self.close_tab(active);
                    self.open_sftp(h);
                }
            }
        }
    }

    fn terminal_body(&mut self, ui: &mut egui::Ui, idx: usize) {
        let theme_name = if let TabKind::Term(tt) = &self.tabs[idx].kind { tt.host.theme.clone() } else { None };
        let theme = theme_name.map(|n| theme::find(&n)).unwrap_or_else(|| self.theme.clone());
        let settings = self.lib.settings.clone();
        let broadcast = self.broadcast;
        let mut reconnect = false;
        let mut open_sftp: Option<Arc<Connection>> = None;
        let mut submitted: Option<String> = None;
        let mut input_out: Vec<u8> = vec![];
        let mut sftp_host: Option<Host> = None;
        let mut stop_fwd: Option<usize> = None;
        {
            let TabKind::Term(tt) = &mut self.tabs[idx].kind else { return };
            match &tt.state {
                TermState::Connecting => {
                    ui.vertical_centered(|ui| {
                        ui.add_space(ui.available_height() * 0.35);
                        ui.spinner();
                        ui.label(format!("Connecting to {} {}", tt.host.label, tt.via));
                    });
                }
                TermState::Closed(msg) => {
                    let msg = msg.clone();
                    // keep scrollback visible above the message
                    egui::Panel::bottom("closed_bar").show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.colored_label(c(theme.ansi[3]), &msg);
                            if ui.button("↻ Reconnect").clicked() {
                                reconnect = true;
                            }
                        });
                    });
                    tt.term.show(ui, &theme, &settings, false);
                }
                TermState::Ready => {
                    egui::Panel::top("term_bar").frame(egui::Frame::NONE.fill(c(theme.bg)).inner_margin(egui::Margin::symmetric(8, 2))).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            if ui.small_button("📁 SFTP").on_hover_text("Open file browser on this connection").clicked() {
                                open_sftp = tt.conn.clone();
                                sftp_host = Some(tt.host.clone());
                            }
                            if ui.small_button("⌫ Clear").clicked() {
                                tt.term.feed(b"\x1b[2J\x1b[3J\x1b[H");
                            }
                            for (i, f) in tt.forwards.iter().enumerate() {
                                let label = match f.spec.kind {
                                    ForwardKind::Local => format!("L {}→{}:{}", f.bound_port, f.spec.dest_host, f.spec.dest_port),
                                    ForwardKind::Remote => format!("R {}→{}:{}", f.bound_port, f.spec.dest_host, f.spec.dest_port),
                                    ForwardKind::Dynamic => format!("SOCKS5 :{}", f.bound_port),
                                };
                                let n = f.connections.load(std::sync::atomic::Ordering::Relaxed);
                                if ui.small_button(format!("⇄ {label} ({n}) ✕")).on_hover_text("Click to stop this forward").clicked() {
                                    stop_fwd = Some(i);
                                }
                            }
                            for w in &tt.warnings {
                                ui.colored_label(c(theme.ansi[3]), w);
                            }
                        });
                    });
                    let out = tt.term.show(ui, &theme, &settings, true);
                    if let Some(l) = out.submitted {
                        submitted = Some(l);
                    }
                    if let Some((cols, rows)) = out.resize {
                        if let Some(tx) = &tt.tx {
                            let _ = tx.send(ShellCmd::Resize { cols: cols as u32, rows: rows as u32 });
                        }
                    }
                    input_out = out.input;
                    tt.term.update_suggestion(&self.lib);
                    if broadcast && !input_out.is_empty() {
                        // sent to everyone below
                    } else if !input_out.is_empty() {
                        if let Some(tx) = &tt.tx {
                            let _ = tx.send(ShellCmd::Input(std::mem::take(&mut input_out)));
                        }
                    }
                }
            }
            if let Some(i) = stop_fwd {
                tt.forwards.remove(i);
            }
        }
        if broadcast && !input_out.is_empty() {
            self.send_to_all(&input_out);
        }
        if let Some(l) = submitted {
            self.mutate(|lib| lib.push_history(&l));
        }
        if let (Some(conn), Some(host)) = (open_sftp, sftp_host) {
            let title = format!("SFTP · {}", host.label);
            let t = SftpTab::new(self.rt.clone(), self.ctx.clone(), conn);
            self.new_tab(title, TabKind::Sftp(Box::new(SftpEntry { host, state: SftpState::Ready(Box::new(t)) })));
        }
        if reconnect {
            let id = self.tabs[idx].id;
            let host = if let TabKind::Term(tt) = &mut self.tabs[idx].kind {
                tt.state = TermState::Connecting;
                tt.host.clone()
            } else {
                return;
            };
            self.start_connect(id, host, true);
        }
    }

    // ------------------------------------------------------------- home

    fn home(&mut self, ui: &mut egui::Ui) {
        let mut actions: Vec<Action> = vec![];
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("🔍 Search hosts, tags, groups…").desired_width(280.0));
            let r = ui.add(egui::TextEdit::singleline(&mut self.quick).hint_text("Quick connect: user@host[:port]").desired_width(280.0));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                self.quick_connect();
            }
            if ui.button(RichText::new("＋ New host").strong()).clicked() {
                let mut h = Host::new("", "", &std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default());
                h.group = String::new();
                self.editor = Some(HostEditor::new(h, true));
            }
            if ui.button("Import ~/.ssh/config").clicked() {
                let imported = sshconfig::import_default();
                let existing: Vec<String> = self.lib.hosts.iter().map(|h| format!("{}|{}|{}", h.hostname, h.port, h.username)).collect();
                let fresh: Vec<Host> = imported.into_iter().filter(|h| !existing.contains(&format!("{}|{}|{}", h.hostname, h.port, h.username))).collect();
                let n = fresh.len();
                self.mutate(|l| l.hosts.extend(fresh));
                self.toast(format!("Imported {n} hosts"));
            }
        });
        ui.add_space(8.0);
        let q = self.search.to_lowercase();
        let hosts: Vec<Host> = self
            .lib
            .hosts
            .iter()
            .filter(|h| {
                q.is_empty()
                    || h.label.to_lowercase().contains(&q)
                    || h.hostname.to_lowercase().contains(&q)
                    || h.group.to_lowercase().contains(&q)
                    || h.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .cloned()
            .collect();
        if self.lib.hosts.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.heading("No hosts yet");
                ui.label("Add one with “New host”, type user@host above to connect right away, or import your ~/.ssh/config.");
            });
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let mut groups: Vec<String> = hosts.iter().map(|h| h.group.clone()).collect();
            groups.sort();
            groups.dedup();
            let favs: Vec<&Host> = hosts.iter().filter(|h| h.favorite).collect();
            if !favs.is_empty() {
                ui.label(RichText::new("★ Favorites").strong());
                host_grid(ui, &favs, &self.theme, &mut actions, "fav");
                ui.add_space(10.0);
            }
            let mut recents: Vec<&Host> = hosts.iter().filter(|h| h.last_connected.is_some()).collect();
            recents.sort_by_key(|h| std::cmp::Reverse(h.last_connected));
            recents.truncate(4);
            if !recents.is_empty() && q.is_empty() {
                ui.label(RichText::new("Recent").strong());
                host_grid(ui, &recents, &self.theme, &mut actions, "recent");
                ui.add_space(10.0);
            }
            for g in groups {
                let list: Vec<&Host> = hosts.iter().filter(|h| h.group == g).collect();
                let title = if g.is_empty() { "All hosts".to_string() } else { g.clone() };
                egui::CollapsingHeader::new(RichText::new(format!("{title}  ({})", list.len())).strong()).id_salt(format!("grp-{g}")).default_open(true).show(ui, |ui| {
                    host_grid(ui, &list, &self.theme, &mut actions, &format!("g-{g}"));
                });
            }
        });
        for a in actions {
            match a {
                Action::Connect(id) => {
                    if let Some(h) = self.lib.host(&id).cloned() {
                        self.open_host(h)
                    }
                }
                Action::Sftp(id) => {
                    if let Some(h) = self.lib.host(&id).cloned() {
                        self.open_sftp(h)
                    }
                }
                Action::Edit(id) => {
                    if let Some(h) = self.lib.host(&id).cloned() {
                        self.editor = Some(HostEditor::new(h, false))
                    }
                }
                Action::Duplicate(id) => {
                    if let Some(mut h) = self.lib.host(&id).cloned() {
                        h.id = new_id();
                        h.label = format!("{} (copy)", h.label);
                        h.last_connected = None;
                        self.mutate(|l| l.hosts.push(h));
                    }
                }
                Action::Delete(id) => self.confirm_delete = Some(id),
                Action::Favorite(id) => self.mutate(|l| {
                    if let Some(h) = l.hosts.iter_mut().find(|h| h.id == id) {
                        h.favorite = !h.favorite;
                    }
                }),
            }
        }
    }

    // ---------------------------------------------------------- dialogs

    fn dialogs(&mut self, ctx: &egui::Context) {
        self.prompt_dialog(ctx);
        self.host_editor_window(ctx);
        self.snippets_window(ctx);
        self.palette_window(ctx);
        self.settings_window(ctx);
        if let Some(id) = self.confirm_delete.clone() {
            let name = self.lib.host(&id).map(|h| h.label.clone()).unwrap_or_default();
            egui::Window::new("Delete host").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
                ui.label(format!("Delete “{name}”? This cannot be undone."));
                ui.horizontal(|ui| {
                    if ui.button("Delete").clicked() {
                        self.mutate(|l| {
                            l.hosts.retain(|h| h.id != id);
                            for h in &mut l.hosts {
                                if h.jump.as_deref() == Some(&id) {
                                    h.jump = None;
                                }
                            }
                        });
                        self.confirm_delete = None;
                    }
                    if ui.button("Cancel").clicked() {
                        self.confirm_delete = None;
                    }
                });
            });
        }
    }

    fn prompt_dialog(&mut self, ctx: &egui::Context) {
        let red = c(self.theme.ansi[1]);
        let Some(p) = self.pending.front_mut() else { return };
        let mut done = false;
        match p {
            Pending::HostKey(q, reply) => {
                egui::Window::new(if q.changed { "⚠ HOST KEY CHANGED" } else { "Unknown host key" }).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
                    if q.changed {
                        ui.colored_label(red, "The key for this host is different from the one on record.\nSomeone may be intercepting your connection (man-in-the-middle), or the server was reinstalled.");
                    } else {
                        ui.label("The authenticity of this host can't be established yet.");
                    }
                    ui.add_space(6.0);
                    ui.label(format!("{}:{}", q.host, q.port));
                    ui.label(RichText::new(format!("{}  {}", q.algorithm, q.fingerprint)).monospace());
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let go = if q.changed { "Connect once (don't save)" } else { "Trust & connect" };
                        if ui.button(go).clicked() {
                            if let Some(r) = reply.take() {
                                let _ = r.send(true);
                            }
                            done = true;
                        }
                        if ui.button("Cancel").clicked() {
                            if let Some(r) = reply.take() {
                                let _ = r.send(false);
                            }
                            done = true;
                        }
                    });
                });
            }
            Pending::Secret { prompt, echo, value, reply } => {
                egui::Window::new("Authentication").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
                    ui.label(prompt.as_str());
                    let r = ui.add(egui::TextEdit::singleline(value).password(!*echo).desired_width(280.0));
                    // Read Enter *before* touching focus: re-requesting focus in the same frame cancels `lost_focus`.
                    let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if !enter && ui.memory(|m| m.focused().is_none()) {
                        r.request_focus();
                    }
                    ui.horizontal(|ui| {
                        if ui.button("OK").clicked() || enter {
                            if let Some(rp) = reply.take() {
                                let _ = rp.send(Some(std::mem::take(value)));
                            }
                            done = true;
                        }
                        if ui.button("Cancel").clicked() {
                            if let Some(rp) = reply.take() {
                                let _ = rp.send(None);
                            }
                            done = true;
                        }
                    });
                });
            }
        }
        if done {
            self.pending.pop_front();
        }
    }

    fn host_editor_window(&mut self, ctx: &egui::Context) {
        let Some(ed) = &mut self.editor else { return };
        let mut save = false;
        let mut cancel = false;
        let hosts_for_jump: Vec<(Id, String)> = self.lib.hosts.iter().filter(|h| h.id != ed.host.id).map(|h| (h.id.clone(), h.label.clone())).collect();
        let identities: Vec<(Id, String)> = self.lib.identities.iter().map(|i| (i.id.clone(), i.name.clone())).collect();
        let themes = theme::themes();
        egui::Window::new(if ed.is_new { "Unknown host key" } else { "Edit host" }).collapsible(false).default_width(520.0).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
            egui::ScrollArea::vertical().max_height(560.0).show(ui, |ui| {
                egui::Grid::new("host_form").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                    ui.label("Label");
                    ui.text_edit_singleline(&mut ed.host.label);
                    ui.end_row();
                    ui.label("Hostname / IP");
                    ui.text_edit_singleline(&mut ed.host.hostname);
                    ui.end_row();
                    ui.label("Port");
                    ui.add(egui::DragValue::new(&mut ed.host.port).range(1..=65535));
                    ui.end_row();
                    ui.label("Username");
                    ui.text_edit_singleline(&mut ed.host.username);
                    ui.end_row();
                    ui.label("Authentication");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut ed.auth_kind, 0, "Ask");
                        ui.selectable_value(&mut ed.auth_kind, 1, "Password");
                        ui.selectable_value(&mut ed.auth_kind, 2, "Saved key");
                        ui.selectable_value(&mut ed.auth_kind, 3, "Key file");
                    });
                    ui.end_row();
                    match ed.auth_kind {
                        1 => {
                            ui.label("Password");
                            ui.add(egui::TextEdit::singleline(&mut ed.password).password(true));
                            ui.end_row();
                        }
                        2 => {
                            ui.label("Key");
                            egui::ComboBox::from_id_salt("ident").selected_text(identities.iter().find(|i| i.0 == ed.identity).map(|i| i.1.clone()).unwrap_or_else(|| "choose…".into())).show_ui(ui, |ui| {
                                for (id, name) in &identities {
                                    ui.selectable_value(&mut ed.identity, id.clone(), name);
                                }
                            });
                            ui.end_row();
                        }
                        3 => {
                            ui.label("Key file");
                            ui.text_edit_singleline(&mut ed.keyfile);
                            ui.end_row();
                            ui.label("Passphrase");
                            ui.add(egui::TextEdit::singleline(&mut ed.keypass).password(true));
                            ui.end_row();
                        }
                        _ => {}
                    }
                    ui.label("Group");
                    ui.text_edit_singleline(&mut ed.host.group);
                    ui.end_row();
                    ui.label("Tags");
                    ui.add(egui::TextEdit::singleline(&mut ed.tags).hint_text("prod, db, eu-west"));
                    ui.end_row();
                    ui.label("Jump host");
                    egui::ComboBox::from_id_salt("jump").selected_text(hosts_for_jump.iter().find(|h| Some(&h.0) == ed.host.jump.as_ref()).map(|h| h.1.clone()).unwrap_or_else(|| "none".into())).show_ui(ui, |ui| {
                        ui.selectable_value(&mut ed.host.jump, None, "none");
                        for (id, name) in &hosts_for_jump {
                            ui.selectable_value(&mut ed.host.jump, Some(id.clone()), name);
                        }
                    });
                    ui.end_row();
                    ui.label("VPN");
                    egui::ComboBox::from_id_salt("vpn").selected_text(["Follow global setting", "Always require VPN", "Never use VPN"][ed.vpn_choice.min(2)]).show_ui(ui, |ui| {
                        ui.selectable_value(&mut ed.vpn_choice, 0, "Follow global setting");
                        ui.selectable_value(&mut ed.vpn_choice, 1, "Always require VPN");
                        ui.selectable_value(&mut ed.vpn_choice, 2, "Never use VPN");
                    });
                    ui.end_row();
                    ui.label("Terminal theme");
                    egui::ComboBox::from_id_salt("hth").selected_text(if ed.theme.is_empty() { "global default" } else { ed.theme.as_str() }).show_ui(ui, |ui| {
                        ui.selectable_value(&mut ed.theme, String::new(), "global default");
                        for t in &themes {
                            ui.selectable_value(&mut ed.theme, t.name.to_string(), t.name);
                        }
                    });
                    ui.end_row();
                    ui.label("Keep-alive (s)");
                    ui.add(egui::DragValue::new(&mut ed.host.keepalive_secs).range(0..=600));
                    ui.end_row();
                    ui.label("Run after login");
                    ui.add(egui::TextEdit::multiline(&mut ed.startup).desired_rows(2).hint_text("one command per line"));
                    ui.end_row();
                    ui.label("Environment");
                    ui.add(egui::TextEdit::multiline(&mut ed.env).desired_rows(2).hint_text("KEY=value (server must allow AcceptEnv)"));
                    ui.end_row();
                    ui.label("Notes");
                    ui.add(egui::TextEdit::multiline(&mut ed.host.notes).desired_rows(2));
                    ui.end_row();
                });
                ui.separator();
                ui.label(RichText::new("Port forwarding").strong());
                let mut remove: Option<usize> = None;
                for (i, f) in ed.host.forwards.iter_mut().enumerate() {
                    ui.horizontal(|ui| {
                        egui::ComboBox::from_id_salt(("fk", i)).width(90.0).selected_text(match f.kind {
                            ForwardKind::Local => "Local -L",
                            ForwardKind::Remote => "Remote -R",
                            ForwardKind::Dynamic => "SOCKS -D",
                        }).show_ui(ui, |ui| {
                            ui.selectable_value(&mut f.kind, ForwardKind::Local, "Local -L");
                            ui.selectable_value(&mut f.kind, ForwardKind::Remote, "Remote -R");
                            ui.selectable_value(&mut f.kind, ForwardKind::Dynamic, "SOCKS -D");
                        });
                        ui.add(egui::TextEdit::singleline(&mut f.bind_host).desired_width(80.0));
                        ui.add(egui::DragValue::new(&mut f.bind_port));
                        if f.kind != ForwardKind::Dynamic {
                            ui.label("→");
                            ui.add(egui::TextEdit::singleline(&mut f.dest_host).desired_width(110.0));
                            ui.add(egui::DragValue::new(&mut f.dest_port));
                        }
                        if ui.small_button("✕").clicked() {
                            remove = Some(i);
                        }
                    });
                }
                if let Some(i) = remove {
                    ed.host.forwards.remove(i);
                }
                if ui.button("＋ Add forward").clicked() {
                    ed.host.forwards.push(PortForward { kind: ForwardKind::Local, bind_host: "127.0.0.1".into(), bind_port: 8080, dest_host: "localhost".into(), dest_port: 80 });
                }
            });
            if !ed.error.is_empty() {
                ui.colored_label(egui::Color32::LIGHT_RED, &ed.error);
            }
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Save").strong()).clicked() {
                    save = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if save {
            let ed = self.editor.as_mut().unwrap();
            match ed.build() {
                Ok(h) => {
                    self.mutate(|l| {
                        if let Some(slot) = l.hosts.iter_mut().find(|x| x.id == h.id) {
                            *slot = h;
                        } else {
                            l.hosts.push(h);
                        }
                    });
                    self.editor = None;
                }
                Err(e) => ed.error = e,
            }
        } else if cancel {
            self.editor = None;
        }
    }

    fn snippets_window(&mut self, ctx: &egui::Context) {
        if !self.show_snippets {
            return;
        }
        let mut open = true;
        let mut run: Option<(String, bool)> = None;
        let mut delete: Option<Id> = None;
        let mut add = false;
        egui::Window::new("Snippets").open(&mut open).default_width(420.0).show(ctx, |ui| {
            ui.small("Reusable commands. “Run” types into the active terminal; “All” sends to every open terminal (multi-exec).");
            egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                for s in &self.lib.snippets {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&s.name).strong());
                        ui.label(RichText::new(&s.command).monospace().weak());
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.small_button("🗑").clicked() {
                                delete = Some(s.id.clone());
                            }
                            if ui.small_button("All").clicked() {
                                run = Some((s.command.clone(), true));
                            }
                            if ui.small_button("Run").clicked() {
                                run = Some((s.command.clone(), false));
                            }
                        });
                    });
                }
            });
            ui.separator();
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.snippet_draft.0).hint_text("name").desired_width(100.0));
                ui.add(egui::TextEdit::singleline(&mut self.snippet_draft.1).hint_text("command").desired_width(200.0));
                if ui.button("Add").clicked() && !self.snippet_draft.1.trim().is_empty() {
                    add = true;
                }
            });
        });
        if !open {
            self.show_snippets = false;
        }
        if add {
            let (n, cmd) = std::mem::take(&mut self.snippet_draft);
            let name = if n.trim().is_empty() { cmd.chars().take(24).collect() } else { n };
            self.mutate(|l| l.snippets.push(Snippet { id: new_id(), name, command: cmd, tags: vec![] }));
        }
        if let Some(id) = delete {
            self.mutate(|l| l.snippets.retain(|s| s.id != id));
        }
        if let Some((cmd, all)) = run {
            let bytes = format!("{cmd}\r").into_bytes();
            if all { self.send_to_all(&bytes) } else { self.send_to_active(&bytes) }
            self.mutate(|l| l.push_history(&cmd));
        }
    }

    fn palette_window(&mut self, ctx: &egui::Context) {
        let Some(q) = &mut self.palette else { return };
        let mut close = false;
        let mut choose: Option<Host> = None;
        let mut snippet: Option<String> = None;
        let ql = q.to_lowercase();
        let hosts: Vec<&Host> = self.lib.hosts.iter().filter(|h| ql.is_empty() || fuzzy(&ql, &format!("{} {} {}", h.label, h.hostname, h.tags.join(" ")).to_lowercase())).take(8).collect();
        let snips: Vec<&Snippet> = self.lib.snippets.iter().filter(|s| !ql.is_empty() && fuzzy(&ql, &s.name.to_lowercase())).take(4).collect();
        egui::Window::new("palette").title_bar(false).resizable(false).anchor(egui::Align2::CENTER_TOP, [0.0, 80.0]).fixed_size([480.0, 0.0]).show(ctx, |ui| {
            let r = ui.add(egui::TextEdit::singleline(q).hint_text("Connect to… (Esc to close)").desired_width(f32::INFINITY));
            r.request_focus();
            for (i, h) in hosts.iter().enumerate() {
                let label = format!("🖥  {}   {}@{}", h.label, h.username, h.hostname);
                if ui.selectable_label(i == 0, label).clicked() {
                    choose = Some((*h).clone());
                }
            }
            for s in &snips {
                if ui.selectable_label(false, format!("{{ }}  {}  {}", s.name, s.command)).clicked() {
                    snippet = Some(s.command.clone());
                }
            }
            if ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                if let Some(h) = hosts.first() {
                    choose = Some((*h).clone());
                }
            }
            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                close = true;
            }
        });
        if choose.is_some() || snippet.is_some() || close {
            self.palette = None;
        }
        if let Some(h) = choose {
            self.open_host(h);
        }
        if let Some(cmd) = snippet {
            self.send_to_active(format!("{cmd}\r").as_bytes());
        }
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        if !self.show_settings {
            return;
        }
        let mut open = true;
        let before = self.lib.settings.clone();
        egui::Window::new("Settings").open(&mut open).default_size([620.0, 520.0]).show(ctx, |ui| {
            ui.horizontal(|ui| {
                for (t, n) in [
                    (SettingsTab::General, "General"),
                    (SettingsTab::Vpn, "🛡 VPN"),
                    (SettingsTab::Keys, "🔑 Keys"),
                    (SettingsTab::Security, "Security & Sync"),
                    (SettingsTab::Highlights, "Highlights"),
                    (SettingsTab::About, "About"),
                ] {
                    ui.selectable_value(&mut self.settings_tab, t, n);
                }
            });
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| match self.settings_tab {
                SettingsTab::General => self.settings_general(ui),
                SettingsTab::Vpn => self.settings_vpn(ui),
                SettingsTab::Keys => self.settings_keys(ui),
                SettingsTab::Security => self.settings_security(ui),
                SettingsTab::Highlights => self.settings_highlights(ui),
                SettingsTab::About => {
                    ui.heading("sshield");
                    ui.label(format!("version {}", env!("CARGO_PKG_VERSION")));
                    ui.label("Free and open source (Apache-2.0). No accounts, no telemetry, no paywalls.");
                    ui.label(format!("Data directory: {}", self.data_dir.display()));
                }
            });
        });
        if !open {
            self.show_settings = false;
        }
        if before != self.lib.settings {
            self.dirty = true;
            self.apply_theme();
        }
    }

    fn settings_general(&mut self, ui: &mut egui::Ui) {
        let st = &mut self.lib.settings;
        egui::Grid::new("gen").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
            ui.label("Theme");
            egui::ComboBox::from_id_salt("theme").selected_text(st.theme.clone()).show_ui(ui, |ui| {
                for t in theme::themes() {
                    ui.selectable_value(&mut st.theme, t.name.to_string(), t.name);
                }
            });
            ui.end_row();
            ui.label("Accent colour");
            let mut col = c(st.accent);
            if ui.color_edit_button_srgba(&mut col).changed() {
                st.accent = ((col.r() as u32) << 16) | ((col.g() as u32) << 8) | col.b() as u32;
            }
            ui.end_row();
            ui.label("Terminal font size");
            ui.add(egui::Slider::new(&mut st.font_size, 8.0..=32.0));
            ui.end_row();
            ui.label("Font file (.ttf)");
            ui.add(egui::TextEdit::singleline(&mut st.font_family).hint_text(r"C:\Windows\Fonts\CascadiaMono.ttf"));
            ui.end_row();
            ui.label("UI scale");
            ui.add(egui::Slider::new(&mut st.ui_scale, 0.8..=1.8));
            ui.end_row();
            ui.label("Scrollback lines");
            ui.add(egui::DragValue::new(&mut st.scrollback).range(0..=200_000).speed(100));
            ui.end_row();
            ui.label("");
            ui.checkbox(&mut st.copy_on_select, "Copy on select");
            ui.end_row();
            ui.label("");
            ui.checkbox(&mut st.cursor_blink, "Blinking cursor");
            ui.end_row();
            ui.label("");
            ui.checkbox(&mut st.log_sessions, "Log sessions to files (raw output)");
            ui.end_row();
            if st.log_sessions {
                ui.label("Log folder");
                ui.add(egui::TextEdit::singleline(&mut st.log_dir).hint_text("(default: data dir/logs)"));
                ui.end_row();
            }
        });
        ui.small("Scrollback applies to newly opened sessions.");
    }

    fn settings_vpn(&mut self, ui: &mut egui::Ui) {
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        let rt = self.rt.clone();
        let mgr = self.vpn.clone();
        let p = &mut self.lib.settings.vpn;
        ui.heading("Force SSH through a VPN");
        ui.label("When enabled, every SSH connection is (1) refused unless the tunnel interface is up, (2) refused unless the OS routes the destination through that interface, and (3) bound to that interface at the socket level. There is no fallback to your normal connection.");
        ui.add_space(6.0);
        ui.checkbox(&mut p.enabled, "Require VPN for all SSH connections");
        ui.small("Per-host overrides (always / never) are in each host's settings.");
        ui.add_space(4.0);
        egui::Grid::new("vpn").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
            ui.label("Tunnel type");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut p.kind, VpnKind::WireGuard, "WireGuard");
                ui.selectable_value(&mut p.kind, VpnKind::OpenVpn, "OpenVPN");
                ui.selectable_value(&mut p.kind, VpnKind::Existing, "Already running");
            });
            ui.end_row();
            if p.kind != VpnKind::Existing {
                ui.label(if p.kind == VpnKind::WireGuard { "Config (.conf)" } else { "Config (.ovpn)" });
                ui.text_edit_singleline(&mut p.config_path);
                ui.end_row();
            }
            ui.label("Interface name");
            ui.add(egui::TextEdit::singleline(&mut p.interface).hint_text(match p.kind {
                VpnKind::WireGuard => "(default: config file name, e.g. wg0)",
                VpnKind::OpenVpn => "e.g. tun0  /  \"OpenVPN Data Channel Offload\"  /  \"Local Area Connection\"",
                VpnKind::Existing => "name of the VPN adapter",
            }));
            ui.end_row();
            if p.kind != VpnKind::Existing {
                ui.label("Executable");
                ui.add(egui::TextEdit::singleline(&mut p.executable).hint_text("(auto: wg-quick / wireguard.exe / openvpn)"));
                ui.end_row();
                ui.label("");
                ui.checkbox(&mut p.auto_start, "Start the tunnel automatically when needed");
                ui.end_row();
                ui.label("");
                ui.checkbox(&mut p.auto_stop, "Stop it again when the last session closes / app exits");
                ui.end_row();
                ui.label("Start timeout (s)");
                ui.add(egui::DragValue::new(&mut p.start_timeout_secs).range(5..=180));
                ui.end_row();
            }
            ui.label("");
            ui.checkbox(&mut p.fail_closed, "Fail closed if the route can't be verified (recommended)");
            ui.end_row();
        });
        ui.add_space(6.0);
        ui.small("Starting a tunnel needs administrator/root rights (WireGuard service install on Windows, wg-quick/openvpn on Linux/macOS). If you'd rather not run sshield elevated, start the VPN yourself and choose “Already running”.");
        ui.small("Hostnames are resolved by the system resolver before the connection is pinned; use IP addresses or VPN-provided DNS if DNS leakage matters.");
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Test against");
            ui.add(egui::TextEdit::singleline(&mut self.vpn_test_target).hint_text("IP of an SSH host").desired_width(180.0));
            if ui.button("Test VPN").clicked() {
                let policy = p.clone();
                let target = self.vpn_test_target.trim().to_string();
                rt.spawn(async move {
                    let msg = async {
                        let b = mgr.ensure_up(&policy).await.map_err(|e| e.to_string())?;
                        let mut s = format!("Tunnel '{}' is up", b.iface);
                        if !target.is_empty() {
                            let ip: std::net::IpAddr = target.parse().map_err(|_| "test target must be an IP address".to_string())?;
                            vpn::verify_route(&b, ip, true).await.map_err(|e| e.to_string())?;
                            s.push_str(&format!("; {ip} is routed through it ✔"));
                        }
                        Ok::<_, String>(s)
                    }
                    .await;
                    let _ = tx.send(UiMsg::Toast(match msg {
                        Ok(s) => s,
                        Err(e) => format!("VPN test failed: {e}"),
                    }));
                    ctx.request_repaint();
                });
            }
        });
    }

    fn settings_keys(&mut self, ui: &mut egui::Ui) {
        ui.heading("SSH keys");
        ui.label("Private keys live only inside the encrypted vault.");
        let mut delete: Option<Id> = None;
        for i in &self.lib.identities {
            ui.horizontal(|ui| {
                if ui.selectable_label(self.sel_identity.as_ref() == Some(&i.id), format!("🔑 {}", i.name)).clicked() {
                    self.sel_identity = Some(i.id.clone());
                }
                if ui.small_button("🗑").clicked() {
                    delete = Some(i.id.clone());
                }
            });
        }
        if let Some(id) = delete {
            self.mutate(|l| l.identities.retain(|i| i.id != id));
            self.sel_identity = None;
        }
        if let Some(i) = self.sel_identity.as_ref().and_then(|id| self.lib.identity(id)) {
            match sshield_core::russh::keys::decode_secret_key(&i.private_key, i.passphrase.as_deref()).and_then(|k| k.public_key().to_openssh().map_err(Into::into)) {
                Ok(mut pubkey) => {
                    ui.label("Public key (add to the server's authorized_keys):");
                    ui.add(egui::TextEdit::multiline(&mut pubkey).desired_rows(3).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));
                    if ui.button("Copy public key").clicked() {
                        ui.ctx().copy_text(pubkey);
                    }
                }
                Err(e) => {
                    ui.colored_label(egui::Color32::LIGHT_RED, format!("Cannot read key: {e}"));
                }
            }
        }
        ui.separator();
        ui.label(RichText::new("Add a key").strong());
        ui.add(egui::TextEdit::singleline(&mut self.key_name).hint_text("name").desired_width(200.0));
        ui.horizontal(|ui| {
            if ui.button("Generate Ed25519").clicked() {
                let name = if self.key_name.trim().is_empty() { "new-key".to_string() } else { self.key_name.trim().to_string() };
                match ssh::generate_ed25519(&name) {
                    Ok((pem, _)) => {
                        let id = new_id();
                        self.sel_identity = Some(id.clone());
                        self.mutate(|l| l.identities.push(Identity { id, name, private_key: pem, passphrase: None }));
                        self.key_name.clear();
                        self.key_error.clear();
                    }
                    Err(e) => self.key_error = e.to_string(),
                }
            }
        });
        ui.label("…or import (path to a key file, or paste the key text):");
        ui.add(egui::TextEdit::multiline(&mut self.key_import).desired_rows(3).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));
        ui.add(egui::TextEdit::singleline(&mut self.key_pass).password(true).hint_text("passphrase (if the key has one)"));
        if ui.button("Import").clicked() {
            let src = self.key_import.trim().to_string();
            let text = if src.contains("PRIVATE KEY") || src.starts_with("PuTTY-User-Key-File") { src.clone() } else { std::fs::read_to_string(&src).unwrap_or_default() };
            let pass = (!self.key_pass.is_empty()).then(|| self.key_pass.clone());
            match sshield_core::russh::keys::decode_secret_key(&text, pass.as_deref()) {
                Ok(_) => {
                    let name = if self.key_name.trim().is_empty() { "imported-key".to_string() } else { self.key_name.trim().to_string() };
                    let id = new_id();
                    self.sel_identity = Some(id.clone());
                    self.mutate(|l| l.identities.push(Identity { id, name, private_key: text, passphrase: pass }));
                    self.key_import.clear();
                    self.key_pass.clear();
                    self.key_error.clear();
                }
                Err(e) => self.key_error = format!("Could not read key: {e} (wrong passphrase, or not a key file?)"),
            }
        }
        if !self.key_error.is_empty() {
            ui.colored_label(egui::Color32::LIGHT_RED, &self.key_error);
        }
    }

    fn settings_security(&mut self, ui: &mut egui::Ui) {
        ui.heading("Master password");
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.new_pw).password(true).hint_text("new master password (min 8)"));
            if ui.button("Change").clicked() {
                if self.new_pw.chars().count() < 8 {
                    self.toast("Use at least 8 characters");
                } else if let Some(v) = &mut self.vault {
                    match v.change_password(&self.new_pw, &self.lib) {
                        Ok(_) => {
                            self.new_pw.clear();
                            self.toasts.push(("Master password changed".into(), Instant::now()));
                        }
                        Err(e) => self.toasts.push((format!("Failed: {e}"), Instant::now())),
                    }
                }
            }
        });
        ui.separator();
        ui.heading("Sync (no account needed)");
        ui.label("Point this at a folder that Dropbox / OneDrive / iCloud / Syncthing / a NAS already syncs. sshield writes the encrypted vault there on every change. Open the same file on another machine by copying it into that machine's data directory. The file is useless without your master password.");
        ui.add(egui::TextEdit::singleline(&mut self.lib.settings.sync_dir).hint_text("e.g. D:\\Dropbox\\sshield").desired_width(f32::INFINITY));
        ui.small("Mirroring is one-way (this machine → folder); sshield does not merge concurrent edits from two machines.");
        ui.separator();
        ui.label(format!("Vault file: {}", self.vault_path().display()));
        ui.label(format!("Known hosts: {}", self.known_hosts().display()));
    }

    fn settings_highlights(&mut self, ui: &mut egui::Ui) {
        ui.heading("Keyword highlighting");
        ui.label("Words that appear in default-coloured terminal output are recoloured.");
        let mut remove: Option<usize> = None;
        let mut changed = false;
        for (i, (kw, col)) in self.lib.settings.highlights.iter_mut().enumerate() {
            ui.horizontal(|ui| {
                changed |= ui.add(egui::TextEdit::singleline(kw).desired_width(140.0)).changed();
                let mut cc = c(*col);
                if ui.color_edit_button_srgba(&mut cc).changed() {
                    *col = ((cc.r() as u32) << 16) | ((cc.g() as u32) << 8) | cc.b() as u32;
                    changed = true;
                }
                if ui.small_button("✕").clicked() {
                    remove = Some(i);
                }
            });
        }
        if let Some(i) = remove {
            self.lib.settings.highlights.remove(i);
        }
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.new_highlight.0).hint_text("keyword").desired_width(140.0));
            let mut cc = c(self.new_highlight.1);
            if ui.color_edit_button_srgba(&mut cc).changed() {
                self.new_highlight.1 = ((cc.r() as u32) << 16) | ((cc.g() as u32) << 8) | cc.b() as u32;
            }
            if ui.button("Add").clicked() && !self.new_highlight.0.is_empty() {
                let (k, col) = (std::mem::take(&mut self.new_highlight.0), self.new_highlight.1);
                self.lib.settings.highlights.push((k, col));
            }
        });
        let _ = changed;
    }
}

fn host_grid(ui: &mut egui::Ui, hosts: &[&Host], theme: &Theme, actions: &mut Vec<Action>, salt: &str) {
    let w = 300.0;
    let cols = ((ui.available_width() / (w + 34.0)).floor() as usize).max(1);
    egui::Grid::new(format!("grid-{salt}")).spacing([12.0, 12.0]).show(ui, |ui| {
        for (i, h) in hosts.iter().enumerate() {
            let frame = egui::Frame::new()
                .fill(c(theme.bg))
                .stroke(egui::Stroke::new(1.0, c(theme.selection)))
                .corner_radius(10)
                .inner_margin(12.0);
            let r = frame.show(ui, |ui| {
              ui.vertical(|ui| {
                ui.set_width(w);
                ui.horizontal(|ui| {
                    let title = ui.add(egui::Label::new(RichText::new(&h.label).strong().size(15.0)).truncate().selectable(false).sense(egui::Sense::click()));
                    if title.double_clicked() {
                        actions.push(Action::Connect(h.id.clone()));
                    }
                    title.on_hover_text("Double-click to connect");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button(if h.favorite { "★" } else { "☆" }).clicked() {
                            actions.push(Action::Favorite(h.id.clone()));
                        }
                    });
                });
                ui.add(egui::Label::new(RichText::new(format!("{}@{}:{}", h.username, h.hostname, h.port)).monospace().weak()).truncate());
                let has_meta = !h.tags.is_empty() || h.jump.is_some() || h.require_vpn == Some(true) || !h.forwards.is_empty();
                if has_meta {
                    ui.horizontal(|ui| {
                        for t in h.tags.iter().take(3) {
                            ui.label(RichText::new(format!(" {t} ")).small().background_color(c(theme.selection)));
                        }
                        if h.jump.is_some() {
                            ui.small("↪ jump");
                        }
                        if h.require_vpn == Some(true) {
                            ui.small("🛡 vpn");
                        }
                        if !h.forwards.is_empty() {
                            ui.small(format!("⇄ {}", h.forwards.len()));
                        }
                    });
                }
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Connect").color(c(theme.ansi[2]))).clicked() {
                        actions.push(Action::Connect(h.id.clone()));
                    }
                    if ui.button("SFTP").clicked() {
                        actions.push(Action::Sftp(h.id.clone()));
                    }
                    if ui.button("Edit").clicked() {
                        actions.push(Action::Edit(h.id.clone()));
                    }
                    if ui.button("Copy").on_hover_text("Duplicate this host").clicked() {
                        actions.push(Action::Duplicate(h.id.clone()));
                    }
                    if ui.button("🗑").on_hover_text("Delete").clicked() {
                        actions.push(Action::Delete(h.id.clone()));
                    }
                });
              });
            });
            let _ = r;
            if (i + 1) % cols == 0 {
                ui.end_row();
            }
        }
    });
}

fn fmt_dur(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 { format!("{}h{:02}m", s / 3600, (s / 60) % 60) } else { format!("{}m{:02}s", s / 60, s % 60) }
}

/// Subsequence match: every char of `needle` appears in order in `hay`.
fn fuzzy(needle: &str, hay: &str) -> bool {
    let mut it = hay.chars();
    needle.chars().all(|c| it.any(|h| h == c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzzy_matching() {
        assert!(fuzzy("pdb", "prod-db-01"));
        assert!(!fuzzy("dbp", "prod-db"));
        assert!(fuzzy("", "x"));
    }

    #[test]
    fn host_editor_roundtrip_and_validation() {
        let mut h = Host::new("a", "example.com", "me");
        h.auth = Auth::Password { password: "x".into() };
        h.tags = vec!["a".into(), "b".into()];
        h.startup = vec!["cd /srv".into()];
        let ed = HostEditor::new(h.clone(), false);
        let built = ed.build().unwrap();
        assert_eq!(built.tags, h.tags);
        assert_eq!(built.startup, h.startup);
        assert_eq!(built.auth, h.auth);

        let mut bad = HostEditor::new(Host::new("", "", "u"), true);
        assert!(bad.build().is_err());
        bad.host.hostname = "h".into();
        assert_eq!(bad.build().unwrap().label, "h");
        bad.auth_kind = 2;
        assert!(bad.build().is_err(), "saved-key auth requires a key");
    }
}
