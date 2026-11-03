//! Terminal widget: vt100 emulation + egui painting + keyboard/mouse input.

use crate::theme::{c, xterm, Theme};
use egui::{Align2, Color32, FontId, Key, Modifiers, Pos2, Rect, Sense, Stroke, Vec2};
use sshield_core::Settings;
use std::num::NonZeroU16;

fn nz(v: u16) -> NonZeroU16 {
    NonZeroU16::new(v.max(1)).unwrap()
}

#[derive(Default)]
pub struct TermOutput {
    /// Bytes to send to the remote (already encoded).
    pub input: Vec<u8>,
    /// New size in cells when the widget was resized.
    pub resize: Option<(u16, u16)>,
    /// A full command line the user just submitted (for history).
    pub submitted: Option<String>,
    pub clicked: bool,
}

pub struct TermView {
    pub parser: vt100::Parser,
    cols: u16,
    rows: u16,
    sel: Option<((u16, u16), (u16, u16))>,
    anchor: Option<(u16, u16)>,
    /// Heuristic tracking of the line being typed (for autocomplete).
    pub line: String,
    line_valid: bool,
    scroll_accum: f32,
    pub suggestion: Option<String>,
}

impl TermView {
    pub fn new(scrollback: usize) -> Self {
        TermView {
            parser: vt100::Parser::new(nz(24), nz(80), scrollback),
            cols: 80,
            rows: 24,
            sel: None,
            anchor: None,
            line: String::new(),
            line_valid: true,
            scroll_accum: 0.0,
            suggestion: None,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    pub fn size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    fn selection_text(&self) -> Option<String> {
        let (a, b) = self.sel?;
        let (s, e) = if a <= b { (a, b) } else { (b, a) };
        let t = self.parser.screen().contents_between(s.0, s.1, e.0, e.1 + 1);
        let t = t.trim_end().to_string();
        (!t.is_empty()).then_some(t)
    }

    /// Draw the terminal into the available space and translate input.
    pub fn show(&mut self, ui: &mut egui::Ui, theme: &Theme, st: &Settings, focused_tab: bool) -> TermOutput {
        let mut out = TermOutput::default();
        let font = FontId::monospace(st.font_size);
        let (cw, ch) = ui.fonts_mut(|f| (f.glyph_width(&font, 'M'), f.row_height(&font)));
        let size = ui.available_size();
        let (rect, resp) = ui.allocate_exact_size(size, Sense::click_and_drag());
        let pad = 6.0;
        let inner = rect.shrink(pad);
        let cols = ((inner.width() / cw).floor() as u16).max(2);
        let rows = ((inner.height() / ch).floor() as u16).max(2);
        if (cols, rows) != (self.cols, self.rows) {
            self.cols = cols;
            self.rows = rows;
            self.parser.set_size(nz(rows), nz(cols));
            out.resize = Some((cols, rows));
        }

        if focused_tab && !resp.has_focus() && !ui.memory(|m| m.focused().is_some()) {
            resp.request_focus();
        }
        if resp.clicked() || resp.drag_started() {
            resp.request_focus();
            out.clicked = true;
        }
        if resp.has_focus() {
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(
                    resp.id,
                    egui::EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true },
                )
            });
        }

        // ---- mouse selection
        let cell_at = |p: Pos2| -> (u16, u16) {
            let x = ((p.x - inner.left()) / cw).floor().clamp(0.0, (cols - 1) as f32) as u16;
            let y = ((p.y - inner.top()) / ch).floor().clamp(0.0, (rows - 1) as f32) as u16;
            (y, x)
        };
        if let Some(p) = resp.interact_pointer_pos() {
            if resp.drag_started() {
                self.anchor = Some(cell_at(p));
                self.sel = None;
            } else if resp.dragged() {
                if let Some(a) = self.anchor {
                    self.sel = Some((a, cell_at(p)));
                }
            }
        }
        if resp.double_clicked() {
            if let Some(p) = resp.interact_pointer_pos() {
                let (r, col) = cell_at(p);
                self.sel = Some(self.word_at(r, col));
            }
        }
        if (resp.drag_stopped() || resp.double_clicked()) && st.copy_on_select {
            if let Some(t) = self.selection_text() {
                ui.ctx().copy_text(t);
            }
        }
        if resp.clicked() && !resp.double_clicked() {
            self.sel = None;
        }
        resp.context_menu(|ui| {
            if ui.button("Copy").clicked() {
                if let Some(t) = self.selection_text() {
                    ui.ctx().copy_text(t);
                }
                ui.close();
            }
            if ui.button("Clear selection").clicked() {
                self.sel = None;
                ui.close();
            }
            if ui.button("Scroll to bottom").clicked() {
                self.parser.screen_mut().set_scrollback(0);
                ui.close();
            }
        });

        // ---- wheel
        if resp.hovered() {
            let dy = ui.input(|i| i.smooth_scroll_delta.y);
            self.scroll_accum += dy / ch;
            let lines = self.scroll_accum.trunc() as i32;
            if lines != 0 {
                self.scroll_accum -= lines as f32;
                let scr = self.parser.screen();
                if scr.alternate_screen() {
                    // alt-screen apps (less, man, vim): wheel => arrow keys
                    let key: &[u8] = if lines > 0 { b"\x1b[A" } else { b"\x1b[B" };
                    for _ in 0..lines.unsigned_abs().min(10) * 3 {
                        out.input.extend_from_slice(key);
                    }
                } else {
                    let cur = scr.scrollback() as i32;
                    self.parser.screen_mut().set_scrollback((cur + lines * 3).max(0) as usize);
                }
            }
        }

        // ---- keyboard
        if resp.has_focus() {
            let events = ui.input(|i| i.events.clone());
            for ev in events {
                self.handle_event(ev, &mut out, ui.ctx());
            }
        }

        // ---- paint
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, c(theme.bg));
        let screen = self.parser.screen();
        let (def_fg, def_bg) = (c(theme.fg), c(theme.bg));
        let sel = self.sel.map(|(a, b)| if a <= b { (a, b) } else { (b, a) });
        let in_sel = |r: u16, col: u16| sel.map(|(s, e)| (r, col) >= s && (r, col) <= e).unwrap_or(false);

        for r in 0..rows {
            let y = inner.top() + r as f32 * ch;
            // keyword highlight overrides
            let mut line_chars: Vec<char> = Vec::with_capacity(cols as usize);
            for col in 0..cols {
                line_chars.push(screen.cell(r, col).and_then(|x| x.contents().chars().next()).unwrap_or(' '));
            }
            let mut hl: Vec<Option<Color32>> = vec![None; cols as usize];
            if !st.highlights.is_empty() {
                for (kw, color) in &st.highlights {
                    if kw.is_empty() {
                        continue;
                    }
                    let kwc: Vec<char> = kw.chars().collect();
                    let mut i = 0;
                    while i + kwc.len() <= line_chars.len() {
                        if line_chars[i..i + kwc.len()] == kwc[..] {
                            for h in hl.iter_mut().skip(i).take(kwc.len()) {
                                *h = Some(c(*color));
                            }
                            i += kwc.len();
                        } else {
                            i += 1;
                        }
                    }
                }
            }

            let mut run = String::new();
            let mut run_start = 0u16;
            let mut run_fg = def_fg;
            let mut run_ul = false;
            let flush = |run: &mut String, start: u16, fg: Color32, ul: bool| {
                if run.is_empty() {
                    return;
                }
                let x = inner.left() + start as f32 * cw;
                painter.text(Pos2::new(x, y), Align2::LEFT_TOP, run.as_str(), font.clone(), fg);
                if ul {
                    let w = run.chars().count() as f32 * cw;
                    painter.line_segment([Pos2::new(x, y + ch - 1.5), Pos2::new(x + w, y + ch - 1.5)], Stroke::new(1.0, fg));
                }
                run.clear();
            };

            for col in 0..cols {
                let Some(cell) = screen.cell(r, col) else { continue };
                if cell.is_wide_continuation() {
                    continue;
                }
                let mut fg = match cell.fgcolor() {
                    vt100::Color::Default => def_fg,
                    vt100::Color::Idx(i) => {
                        // bold brightens the base 8
                        let i = if cell.bold() && i < 8 { i + 8 } else { i };
                        xterm(i, theme)
                    }
                    vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
                };
                let mut bg = match cell.bgcolor() {
                    vt100::Color::Default => None,
                    vt100::Color::Idx(i) => Some(xterm(i, theme)),
                    vt100::Color::Rgb(r, g, b) => Some(Color32::from_rgb(r, g, b)),
                };
                if cell.inverse() {
                    let b = bg.unwrap_or(def_bg);
                    bg = Some(fg);
                    fg = b;
                }
                if cell.dim() {
                    fg = fg.gamma_multiply(0.6);
                }
                if matches!(cell.fgcolor(), vt100::Color::Default) && !cell.inverse() {
                    if let Some(h) = hl[col as usize] {
                        fg = h;
                    }
                }
                if in_sel(r, col) {
                    bg = Some(c(theme.selection));
                }
                let width = if cell.is_wide() { 2.0 } else { 1.0 };
                if let Some(bg) = bg {
                    let x = inner.left() + col as f32 * cw;
                    painter.rect_filled(Rect::from_min_size(Pos2::new(x, y), Vec2::new(cw * width, ch + 0.5)), 0.0, bg);
                }
                let txt = cell.contents();
                if txt.is_empty() || txt == " " {
                    flush(&mut run, run_start, run_fg, run_ul);
                    continue;
                }
                let ul = cell.underline();
                if cell.is_wide() || fg != run_fg || ul != run_ul || run.is_empty() {
                    flush(&mut run, run_start, run_fg, run_ul);
                    run_start = col;
                    run_fg = fg;
                    run_ul = ul;
                }
                // pad skipped (blank) cells so the run stays column-aligned
                let have = run.chars().count() as u16;
                for _ in have..(col - run_start) {
                    run.push(' ');
                }
                run.push_str(txt);
                if cell.is_wide() {
                    flush(&mut run, run_start, run_fg, run_ul);
                }
            }
            flush(&mut run, run_start, run_fg, run_ul);
        }

        // cursor
        if screen.scrollback() == 0 && !screen.hide_cursor() {
            let (cr, cc) = screen.cursor_position();
            let blink_on = !st.cursor_blink || (ui.input(|i| i.time) * 2.0) as i64 % 2 == 0 || !resp.has_focus();
            let x = inner.left() + cc as f32 * cw;
            let y = inner.top() + cr as f32 * ch;
            let r = Rect::from_min_size(Pos2::new(x, y), Vec2::new(cw, ch));
            if resp.has_focus() {
                if blink_on {
                    painter.rect_filled(r, 1.0, c(theme.cursor));
                    if let Some(cell) = screen.cell(cr, cc) {
                        let t = cell.contents();
                        if !t.is_empty() {
                            painter.text(Pos2::new(x, y), Align2::LEFT_TOP, t, font.clone(), c(theme.bg));
                        }
                    }
                }
                if st.cursor_blink {
                    ui.ctx().request_repaint_after(std::time::Duration::from_millis(500));
                }
            } else {
                painter.rect_stroke(r, 1.0, Stroke::new(1.0, c(theme.cursor)), egui::StrokeKind::Inside);
            }
            // autocomplete ghost text
            if let Some(s) = &self.suggestion {
                painter.text(Pos2::new(x, y), Align2::LEFT_TOP, s, font.clone(), c(theme.fg).gamma_multiply(0.38));
            }
        }
        if screen.scrollback() > 0 {
            let g = painter.layout_no_wrap(format!(" scrollback -{} ", screen.scrollback()), FontId::proportional(12.0), c(theme.bg));
            let r = Rect::from_min_size(rect.right_top() + Vec2::new(-8.0 - g.size().x, 6.0), g.size());
            painter.rect_filled(r, 4.0, c(theme.cursor));
            painter.galley(r.min, g, c(theme.bg));
        }
        out
    }

    fn word_at(&self, row: u16, col: u16) -> ((u16, u16), (u16, u16)) {
        let scr = self.parser.screen();
        let is_w = |cc: u16| scr.cell(row, cc).map(|x| !x.contents().is_empty() && !x.contents().chars().all(char::is_whitespace)).unwrap_or(false);
        if !is_w(col) {
            return ((row, col), (row, col));
        }
        let (mut a, mut b) = (col, col);
        while a > 0 && is_w(a - 1) {
            a -= 1;
        }
        while b + 1 < self.cols && is_w(b + 1) {
            b += 1;
        }
        ((row, a), (row, b))
    }

    fn track(&mut self, bytes: &[u8], text: Option<&str>) {
        // maintain an approximation of the command line being typed
        if let Some(t) = text {
            if self.line_valid {
                self.line.push_str(t);
            }
        } else if bytes == b"\x7f" && self.line_valid {
            self.line.pop();
        }
    }

    fn handle_event(&mut self, ev: egui::Event, out: &mut TermOutput, ctx: &egui::Context) {
        use egui::Event;
        match ev {
            Event::Text(t) => {
                self.parser.screen_mut().set_scrollback(0);
                out.input.extend_from_slice(t.as_bytes());
                self.track(&[], Some(&t));
            }
            Event::Paste(t) => {
                self.parser.screen_mut().set_scrollback(0);
                let t = t.replace("\r\n", "\n").replace('\n', "\r");
                if self.parser.screen().bracketed_paste() {
                    out.input.extend_from_slice(b"\x1b[200~");
                    out.input.extend_from_slice(t.as_bytes());
                    out.input.extend_from_slice(b"\x1b[201~");
                } else {
                    out.input.extend_from_slice(t.as_bytes());
                }
                self.line_valid = false;
            }
            // egui turns Ctrl+C into Copy: copy if there is a selection, else it is ^C.
            Event::Copy => {
                if let Some(t) = self.selection_text() {
                    ctx.copy_text(t);
                    self.sel = None;
                } else {
                    out.input.push(0x03);
                    self.reset_line();
                }
            }
            Event::Cut => out.input.push(0x18),
            Event::Key { key, pressed: true, modifiers, .. } => self.handle_key(key, modifiers, out),
            _ => {}
        }
    }

    /// Update the ghost-text suggestion from history/snippets for the line being typed.
    pub fn update_suggestion(&mut self, lib: &sshield_core::Library) {
        self.suggestion = None;
        if self.line_valid && !self.line.is_empty() && self.parser.screen().scrollback() == 0 && !self.parser.screen().alternate_screen() {
            if let Some(s) = lib.complete(&self.line, 1).first() {
                self.suggestion = Some(s[self.line.len()..].to_string());
            }
        }
    }

    fn reset_line(&mut self) {
        self.line.clear();
        self.line_valid = true;
        self.suggestion = None;
    }

    fn handle_key(&mut self, key: Key, m: Modifiers, out: &mut TermOutput) {
        let app = self.parser.screen().application_cursor();
        let csi = |c: char| -> Vec<u8> {
            let mods = 1 + (m.shift as u8) + 2 * (m.alt as u8) + 4 * (m.ctrl as u8);
            if mods > 1 {
                format!("\x1b[1;{mods}{c}").into_bytes()
            } else if app {
                format!("\x1bO{c}").into_bytes()
            } else {
                format!("\x1b[{c}").into_bytes()
            }
        };
        let tilde = |n: u8| -> Vec<u8> {
            let mods = 1 + (m.shift as u8) + 2 * (m.alt as u8) + 4 * (m.ctrl as u8);
            if mods > 1 { format!("\x1b[{n};{mods}~").into_bytes() } else { format!("\x1b[{n}~").into_bytes() }
        };
        let bytes: Vec<u8> = match key {
            Key::Enter => {
                if self.line_valid && !self.line.trim().is_empty() {
                    out.submitted = Some(self.line.clone());
                }
                self.reset_line();
                self.parser.screen_mut().set_scrollback(0);
                b"\r".to_vec()
            }
            Key::Backspace => {
                self.track(b"\x7f", None);
                if m.ctrl { vec![0x17] } else { vec![0x7f] }
            }
            Key::Tab => {
                self.line_valid = false;
                if m.shift { b"\x1b[Z".to_vec() } else { b"\t".to_vec() }
            }
            Key::Escape => b"\x1b".to_vec(),
            Key::ArrowUp => {
                self.line_valid = false;
                self.suggestion = None;
                csi('A')
            }
            Key::ArrowDown => {
                self.line_valid = false;
                self.suggestion = None;
                csi('B')
            }
            Key::ArrowRight => {
                // accept autocomplete suggestion
                if let Some(s) = self.suggestion.take() {
                    self.line.push_str(&s);
                    s.into_bytes()
                } else {
                    csi('C')
                }
            }
            Key::ArrowLeft => {
                self.line_valid = false;
                self.suggestion = None;
                csi('D')
            }
            Key::Home => csi('H'),
            Key::End => csi('F'),
            Key::PageUp if m.shift => {
                let cur = self.parser.screen().scrollback();
                self.parser.screen_mut().set_scrollback(cur + self.rows as usize / 2);
                return;
            }
            Key::PageDown if m.shift => {
                let cur = self.parser.screen().scrollback();
                self.parser.screen_mut().set_scrollback(cur.saturating_sub(self.rows as usize / 2));
                return;
            }
            Key::PageUp => tilde(5),
            Key::PageDown => tilde(6),
            Key::Insert => tilde(2),
            Key::Delete => tilde(3),
            Key::F1 => b"\x1bOP".to_vec(),
            Key::F2 => b"\x1bOQ".to_vec(),
            Key::F3 => b"\x1bOR".to_vec(),
            Key::F4 => b"\x1bOS".to_vec(),
            Key::F5 => tilde(15),
            Key::F6 => tilde(17),
            Key::F7 => tilde(18),
            Key::F8 => tilde(19),
            Key::F9 => tilde(20),
            Key::F10 => tilde(21),
            Key::F11 => tilde(23),
            Key::F12 => tilde(24),
            k if m.ctrl && !m.alt => match ctrl_char(k) {
                Some(b) => {
                    self.line_valid = false;
                    self.suggestion = None;
                    if b == 0x03 || b == 0x04 {
                        self.reset_line();
                    }
                    vec![b]
                }
                None => return,
            },
            k if m.alt && !m.ctrl => {
                // Alt+letter => ESC letter (readline word motions etc.)
                self.line_valid = false;
                match key_char(k, m.shift) {
                    Some(ch) => vec![0x1b, ch as u8],
                    None => return,
                }
            }
            _ => return,
        };
        out.input.extend_from_slice(&bytes);
    }
}

fn key_char(k: Key, shift: bool) -> Option<char> {
    let name = k.name();
    let mut it = name.chars();
    let ch = it.next()?;
    if it.next().is_some() || !ch.is_ascii_alphanumeric() {
        return None;
    }
    Some(if shift { ch.to_ascii_uppercase() } else { ch.to_ascii_lowercase() })
}

fn ctrl_char(k: Key) -> Option<u8> {
    match k {
        Key::OpenBracket => Some(0x1b),
        Key::Backslash => Some(0x1c),
        Key::CloseBracket => Some(0x1d),
        Key::Space => Some(0x00),
        Key::Minus => Some(0x1f),
        _ => {
            let ch = key_char(k, false)?;
            ch.is_ascii_lowercase().then(|| ch as u8 - b'a' + 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctrl_letters() {
        assert_eq!(ctrl_char(Key::A), Some(1));
        assert_eq!(ctrl_char(Key::Z), Some(26));
        assert_eq!(ctrl_char(Key::OpenBracket), Some(27));
        assert_eq!(ctrl_char(Key::Num1), None);
    }

    #[test]
    fn feeds_and_selects_text() {
        let mut t = TermView::new(100);
        t.feed(b"hello world\r\nsecond line");
        assert_eq!(t.parser.screen().contents().lines().next(), Some("hello world"));
        t.sel = Some(((0, 0), (0, 4)));
        assert_eq!(t.selection_text().as_deref(), Some("hello"));
        assert_eq!(t.word_at(0, 8), ((0, 6), (0, 10)));
    }

    #[test]
    fn enter_submits_tracked_line() {
        let mut t = TermView::new(10);
        let mut out = TermOutput::default();
        t.handle_event(egui::Event::Text("ls -la".into()), &mut out, &egui::Context::default());
        t.handle_key(Key::Enter, Modifiers::NONE, &mut out);
        assert_eq!(out.submitted.as_deref(), Some("ls -la"));
        assert!(out.input.ends_with(b"\r"));
        // history navigation invalidates tracking
        let mut out = TermOutput::default();
        t.handle_key(Key::ArrowUp, Modifiers::NONE, &mut out);
        t.handle_key(Key::Enter, Modifiers::NONE, &mut out);
        assert_eq!(out.submitted, None);
    }

    #[test]
    fn arrows_respect_application_mode() {
        let mut t = TermView::new(10);
        let mut out = TermOutput::default();
        t.handle_key(Key::ArrowUp, Modifiers::NONE, &mut out);
        assert_eq!(out.input, b"\x1b[A");
        t.feed(b"\x1b[?1h");
        let mut out = TermOutput::default();
        t.handle_key(Key::ArrowUp, Modifiers::NONE, &mut out);
        assert_eq!(out.input, b"\x1bOA");
        let mut out = TermOutput::default();
        t.handle_key(Key::ArrowUp, Modifiers::CTRL, &mut out);
        assert_eq!(out.input, b"\x1b[1;5A");
    }
}
