//! Dual-pane SFTP browser (local | remote).

use crate::theme::{c, Theme};
use egui::RichText;
use sshield_core::sftp::{self, Entry, Progress, Sftp};
use sshield_core::ssh::Connection;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

enum Msg {
    Ready(Arc<Sftp>),
    Listed(String, Vec<Entry>),
    Done(String),
    Err(String),
}

#[derive(Clone)]
struct Local {
    name: String,
    path: PathBuf,
    is_dir: bool,
    size: u64,
}

pub struct SftpTab {
    handle: tokio::runtime::Handle,
    ctx: egui::Context,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    sftp: Option<Arc<Sftp>>,
    pub status: String,
    remote_cwd: String,
    remote_path_edit: String,
    remote: Vec<Entry>,
    local_cwd: PathBuf,
    local_path_edit: String,
    local: Vec<Local>,
    sel_remote: Option<usize>,
    sel_local: Option<usize>,
    progress: Progress,
    total: u64,
    busy: bool,
    new_dir: String,
    rename_to: String,
    confirm_delete: bool,
    show_hidden: bool,
}

fn list_local(dir: &PathBuf, hidden: bool) -> Vec<Local> {
    let mut v: Vec<Local> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    let md = e.metadata().ok()?;
                    let name = e.file_name().to_string_lossy().into_owned();
                    if !hidden && name.starts_with('.') {
                        return None;
                    }
                    Some(Local { name, path: e.path(), is_dir: md.is_dir(), size: md.len() })
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    v
}

pub fn human(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", units[i]) }
}

impl SftpTab {
    pub fn new(handle: tokio::runtime::Handle, ctx: egui::Context, conn: Arc<Connection>) -> Self {
        let (tx, rx) = channel();
        let local_cwd = dirs_home();
        let mut t = SftpTab {
            handle: handle.clone(),
            ctx: ctx.clone(),
            tx: tx.clone(),
            rx,
            sftp: None,
            status: "Opening SFTP…".into(),
            remote_cwd: "/".into(),
            remote_path_edit: "/".into(),
            remote: vec![],
            local: list_local(&local_cwd, false),
            local_path_edit: local_cwd.to_string_lossy().into_owned(),
            local_cwd,
            sel_remote: None,
            sel_local: None,
            progress: Default::default(),
            total: 0,
            busy: false,
            new_dir: String::new(),
            rename_to: String::new(),
            confirm_delete: false,
            show_hidden: false,
        };
        t.busy = true;
        handle.spawn(async move {
            let r = async {
                let s = Sftp::open(&conn).await?;
                let home = s.home().await?;
                let list = s.list(&home).await?;
                Ok::<_, sshield_core::ssh::SshError>((s, home, list))
            }
            .await;
            match r {
                Ok((s, home, list)) => {
                    let _ = tx.send(Msg::Ready(Arc::new(s)));
                    let _ = tx.send(Msg::Listed(home, list));
                }
                Err(e) => {
                    let _ = tx.send(Msg::Err(e.to_string()));
                }
            }
            ctx.request_repaint();
        });
        t
    }

    fn spawn<F>(&mut self, f: F)
    where
        F: std::future::Future<Output = Result<String, String>> + Send + 'static,
    {
        self.busy = true;
        let (tx, ctx) = (self.tx.clone(), self.ctx.clone());
        self.handle.spawn(async move {
            let _ = tx.send(match f.await {
                Ok(m) => Msg::Done(m),
                Err(e) => Msg::Err(e),
            });
            ctx.request_repaint();
        });
    }

    fn cd_remote(&mut self, path: String) {
        let Some(s) = self.sftp.clone() else { return };
        self.busy = true;
        let (tx, ctx) = (self.tx.clone(), self.ctx.clone());
        self.handle.spawn(async move {
            let _ = tx.send(match s.list(&path).await {
                Ok(l) => Msg::Listed(path, l),
                Err(e) => Msg::Err(e.to_string()),
            });
            ctx.request_repaint();
        });
    }

    fn refresh_remote(&mut self) {
        let p = self.remote_cwd.clone();
        self.cd_remote(p);
    }

    fn cd_local(&mut self, p: PathBuf) {
        self.local = list_local(&p, self.show_hidden);
        self.local_path_edit = p.to_string_lossy().into_owned();
        self.local_cwd = p;
        self.sel_local = None;
    }

    fn poll(&mut self) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Ready(s) => self.sftp = Some(s),
                Msg::Listed(p, l) => {
                    self.remote_cwd = p.clone();
                    self.remote_path_edit = p;
                    self.remote = l;
                    self.sel_remote = None;
                    self.busy = false;
                    self.status = format!("{} items", self.remote.len());
                }
                Msg::Done(m) => {
                    self.busy = false;
                    self.status = m;
                    self.progress.store(0, Ordering::Relaxed);
                    self.total = 0;
                    self.local = list_local(&self.local_cwd, self.show_hidden);
                    self.refresh_remote();
                }
                Msg::Err(e) => {
                    self.busy = false;
                    self.status = format!("Error: {e}");
                    self.progress.store(0, Ordering::Relaxed);
                    self.total = 0;
                }
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, theme: &Theme) {
        self.poll();
        let accent = c(theme.ansi[4]);
        ui.horizontal(|ui| {
            if self.busy {
                ui.spinner();
            }
            ui.label(&self.status);
            if self.total > 0 {
                let done = self.progress.load(Ordering::Relaxed);
                ui.add(egui::ProgressBar::new(done as f32 / self.total as f32).desired_width(200.0).text(format!("{} / {}", human(done), human(self.total))));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.checkbox(&mut self.show_hidden, "Hidden files").changed() {
                    let p = self.local_cwd.clone();
                    self.cd_local(p);
                }
            });
        });
        ui.separator();

        let can_act = self.sftp.is_some() && !self.busy;
        ui.columns(2, |cols| {
            // ---------------- local
            cols[0].heading("Local");
            cols[0].horizontal(|ui| {
                if ui.button("⬆").on_hover_text("Parent directory").clicked() {
                    if let Some(p) = self.local_cwd.parent() {
                        let p = p.to_path_buf();
                        self.cd_local(p);
                    }
                }
                if ui.button("🏠").clicked() {
                    self.cd_local(dirs_home());
                }
                let r = ui.add(egui::TextEdit::singleline(&mut self.local_path_edit).desired_width(f32::INFINITY));
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    let p = PathBuf::from(&self.local_path_edit);
                    if p.is_dir() {
                        self.cd_local(p);
                    }
                }
            });
            let mut go_local: Option<PathBuf> = None;
            egui::ScrollArea::vertical().id_salt("local").auto_shrink([false, false]).max_height(cols[0].available_height() - 40.0).show(&mut cols[0], |ui| {
                for (i, e) in self.local.iter().enumerate() {
                    let label = format!("{} {}", if e.is_dir { "📁" } else { "📄" }, e.name);
                    let r = ui.selectable_label(self.sel_local == Some(i), label);
                    if r.clicked() {
                        self.sel_local = Some(i);
                    }
                    if r.double_clicked() && e.is_dir {
                        go_local = Some(e.path.clone());
                    }
                    if !e.is_dir {
                        r.on_hover_text(human(e.size));
                    }
                }
            });
            if let Some(p) = go_local {
                self.cd_local(p);
            }

            // ---------------- remote
            cols[1].heading("Remote");
            cols[1].horizontal(|ui| {
                if ui.add_enabled(can_act, egui::Button::new("⬆")).on_hover_text("Parent directory").clicked() {
                    let p = sftp::parent(&self.remote_cwd);
                    self.cd_remote(p);
                }
                if ui.add_enabled(can_act, egui::Button::new("⟳")).clicked() {
                    self.refresh_remote();
                }
                let r = ui.add(egui::TextEdit::singleline(&mut self.remote_path_edit).desired_width(f32::INFINITY));
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && can_act {
                    let p = self.remote_path_edit.clone();
                    self.cd_remote(p);
                }
            });
            let mut go_remote: Option<String> = None;
            egui::ScrollArea::vertical().id_salt("remote").auto_shrink([false, false]).max_height(cols[1].available_height() - 40.0).show(&mut cols[1], |ui| {
                for (i, e) in self.remote.iter().enumerate() {
                    let label = format!("{} {}", if e.is_dir { "📁" } else if e.is_symlink { "🔗" } else { "📄" }, e.name);
                    let r = ui.selectable_label(self.sel_remote == Some(i), label);
                    if r.clicked() {
                        self.sel_remote = Some(i);
                    }
                    if r.double_clicked() && e.is_dir {
                        go_remote = Some(e.path.clone());
                    }
                    r.on_hover_text(format!("{}  {}  {}", e.perms, human(e.size), e.modified.map(|m| m.to_string()).unwrap_or_default()));
                }
            });
            if let Some(p) = go_remote {
                if can_act {
                    self.cd_remote(p);
                }
            }
        });

        ui.separator();
        ui.horizontal_wrapped(|ui| {
            let local_sel = self.sel_local.and_then(|i| self.local.get(i).cloned());
            let remote_sel = self.sel_remote.and_then(|i| self.remote.get(i).cloned());
            if ui.add_enabled(can_act && local_sel.as_ref().map(|l| !l.is_dir).unwrap_or(false), egui::Button::new(RichText::new("Upload ➡").color(accent))).clicked() {
                let l = local_sel.clone().unwrap();
                let remote = sftp::join(&self.remote_cwd, &l.name);
                let s = self.sftp.clone().unwrap();
                self.progress.store(0, Ordering::Relaxed);
                self.total = l.size;
                let prog = self.progress.clone();
                let name = l.name.clone();
                self.spawn(async move {
                    s.upload(&l.path, &remote, Some(prog)).await.map(|n| format!("Uploaded {name} ({})", human(n))).map_err(|e| e.to_string())
                });
            }
            if ui.add_enabled(can_act && remote_sel.as_ref().map(|r| !r.is_dir).unwrap_or(false), egui::Button::new(RichText::new("⬅ Download").color(accent))).clicked() {
                let r = remote_sel.clone().unwrap();
                let dest = self.local_cwd.join(&r.name);
                let s = self.sftp.clone().unwrap();
                self.progress.store(0, Ordering::Relaxed);
                self.total = r.size;
                let prog = self.progress.clone();
                self.spawn(async move {
                    s.download(&r.path, &dest, Some(prog)).await.map(|n| format!("Downloaded {} ({})", r.name, human(n))).map_err(|e| e.to_string())
                });
            }
            ui.separator();
            ui.add(egui::TextEdit::singleline(&mut self.new_dir).hint_text("new folder").desired_width(120.0));
            if ui.add_enabled(can_act && !self.new_dir.trim().is_empty(), egui::Button::new("Create")).clicked() {
                let p = sftp::join(&self.remote_cwd, self.new_dir.trim());
                self.new_dir.clear();
                let s = self.sftp.clone().unwrap();
                self.spawn(async move { s.mkdir(&p).await.map(|_| "Folder created".into()).map_err(|e| e.to_string()) });
            }
            ui.separator();
            ui.add(egui::TextEdit::singleline(&mut self.rename_to).hint_text("rename to").desired_width(120.0));
            if ui.add_enabled(can_act && remote_sel.is_some() && !self.rename_to.trim().is_empty(), egui::Button::new("Rename")).clicked() {
                let r = remote_sel.clone().unwrap();
                let to = sftp::join(&self.remote_cwd, self.rename_to.trim());
                self.rename_to.clear();
                let s = self.sftp.clone().unwrap();
                self.spawn(async move { s.rename(&r.path, &to).await.map(|_| "Renamed".into()).map_err(|e| e.to_string()) });
            }
            ui.separator();
            if self.confirm_delete {
                ui.colored_label(c(theme.ansi[1]), "Delete selected remote item?");
                if ui.button("Yes, delete").clicked() {
                    self.confirm_delete = false;
                    if let Some(r) = remote_sel.clone() {
                        let s = self.sftp.clone().unwrap();
                        self.spawn(async move {
                            let res = if r.is_dir && !r.is_symlink { s.remove_tree(&r.path).await } else { s.remove_file(&r.path).await };
                            res.map(|_| format!("Deleted {}", r.name)).map_err(|e| e.to_string())
                        });
                    }
                }
                if ui.button("Cancel").clicked() {
                    self.confirm_delete = false;
                }
            } else if ui.add_enabled(can_act && remote_sel.is_some(), egui::Button::new("🗑 Delete")).clicked() {
                self.confirm_delete = true;
            }
        });
    }
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    #[test]
    fn human_sizes() {
        assert_eq!(super::human(10), "10 B");
        assert_eq!(super::human(1536), "1.5 KB");
        assert_eq!(super::human(5 * 1024 * 1024 * 1024), "5.0 GB");
    }
}
