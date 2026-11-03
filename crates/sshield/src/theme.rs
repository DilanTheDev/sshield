//! Terminal colour themes + egui visuals.

use egui::Color32;

#[derive(Clone, Debug)]
pub struct Theme {
    pub name: &'static str,
    pub dark: bool,
    pub bg: u32,
    pub fg: u32,
    pub cursor: u32,
    pub selection: u32,
    pub ansi: [u32; 16],
}

pub fn c(v: u32) -> Color32 {
    Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

macro_rules! theme {
    ($name:expr, $dark:expr, $bg:expr, $fg:expr, $cur:expr, $sel:expr, [$($a:expr),*]) => {
        Theme { name: $name, dark: $dark, bg: $bg, fg: $fg, cursor: $cur, selection: $sel, ansi: [$($a),*] }
    };
}

pub fn themes() -> Vec<Theme> {
    vec![
        theme!("Tokyo Night", true, 0x1a1b26, 0xc0caf5, 0xc0caf5, 0x33467c,
            [0x15161e,0xf7768e,0x9ece6a,0xe0af68,0x7aa2f7,0xbb9af7,0x7dcfff,0xa9b1d6,
             0x414868,0xf7768e,0x9ece6a,0xe0af68,0x7aa2f7,0xbb9af7,0x7dcfff,0xc0caf5]),
        theme!("Dracula", true, 0x282a36, 0xf8f8f2, 0xf8f8f2, 0x44475a,
            [0x21222c,0xff5555,0x50fa7b,0xf1fa8c,0xbd93f9,0xff79c6,0x8be9fd,0xf8f8f2,
             0x6272a4,0xff6e6e,0x69ff94,0xffffa5,0xd6acff,0xff92df,0xa4ffff,0xffffff]),
        theme!("Catppuccin Mocha", true, 0x1e1e2e, 0xcdd6f4, 0xf5e0dc, 0x45475a,
            [0x45475a,0xf38ba8,0xa6e3a1,0xf9e2af,0x89b4fa,0xf5c2e7,0x94e2d5,0xbac2de,
             0x585b70,0xf38ba8,0xa6e3a1,0xf9e2af,0x89b4fa,0xf5c2e7,0x94e2d5,0xa6adc8]),
        theme!("Nord", true, 0x2e3440, 0xd8dee9, 0xd8dee9, 0x434c5e,
            [0x3b4252,0xbf616a,0xa3be8c,0xebcb8b,0x81a1c1,0xb48ead,0x88c0d0,0xe5e9f0,
             0x4c566a,0xbf616a,0xa3be8c,0xebcb8b,0x81a1c1,0xb48ead,0x8fbcbb,0xeceff4]),
        theme!("Gruvbox Dark", true, 0x282828, 0xebdbb2, 0xebdbb2, 0x504945,
            [0x282828,0xcc241d,0x98971a,0xd79921,0x458588,0xb16286,0x689d6a,0xa89984,
             0x928374,0xfb4934,0xb8bb26,0xfabd2f,0x83a598,0xd3869b,0x8ec07c,0xebdbb2]),
        theme!("One Dark", true, 0x282c34, 0xabb2bf, 0x528bff, 0x3e4451,
            [0x282c34,0xe06c75,0x98c379,0xe5c07b,0x61afef,0xc678dd,0x56b6c2,0xabb2bf,
             0x5c6370,0xe06c75,0x98c379,0xe5c07b,0x61afef,0xc678dd,0x56b6c2,0xffffff]),
        theme!("Solarized Dark", true, 0x002b36, 0x839496, 0x93a1a1, 0x073642,
            [0x073642,0xdc322f,0x859900,0xb58900,0x268bd2,0xd33682,0x2aa198,0xeee8d5,
             0x002b36,0xcb4b16,0x586e75,0x657b83,0x839496,0x6c71c4,0x93a1a1,0xfdf6e3]),
        theme!("Solarized Light", false, 0xfdf6e3, 0x657b83, 0x586e75, 0xeee8d5,
            [0x073642,0xdc322f,0x859900,0xb58900,0x268bd2,0xd33682,0x2aa198,0xeee8d5,
             0x002b36,0xcb4b16,0x586e75,0x657b83,0x839496,0x6c71c4,0x93a1a1,0xfdf6e3]),
        theme!("GitHub Light", false, 0xffffff, 0x24292f, 0x044289, 0xb6d6fd,
            [0x24292f,0xcf222e,0x116329,0x4d2d00,0x0969da,0x8250df,0x1b7c83,0x6e7781,
             0x57606a,0xa40e26,0x1a7f37,0x633c01,0x218bff,0xa475f9,0x3192aa,0x8c959f]),
        theme!("Monochrome Green", true, 0x000000, 0x33ff66, 0x33ff66, 0x0a3d1a,
            [0x000000,0x22aa44,0x33ff66,0x66ff99,0x22aa44,0x33ff66,0x66ff99,0x33ff66,
             0x116622,0x22cc55,0x44ff77,0x88ffaa,0x22cc55,0x44ff77,0x88ffaa,0xccffdd]),
    ]
}

pub fn find(name: &str) -> Theme {
    themes().into_iter().find(|t| t.name == name).unwrap_or_else(|| themes().remove(0))
}

/// Resolve a 0..=255 xterm palette index.
pub fn xterm(idx: u8, t: &Theme) -> Color32 {
    match idx {
        0..=15 => c(t.ansi[idx as usize]),
        16..=231 => {
            let i = idx - 16;
            let lvl = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
            Color32::from_rgb(lvl(i / 36), lvl((i / 6) % 6), lvl(i % 6))
        }
        232..=255 => {
            let v = 8 + (idx - 232) * 10;
            Color32::from_rgb(v, v, v)
        }
    }
}

fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
    Color32::from_rgb(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()))
}

/// Style the whole app from the terminal theme so UI and terminal feel like one piece.
pub fn apply_visuals(ctx: &egui::Context, t: &Theme, accent: u32, scale: f32) {
    let mut v = if t.dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    let bg = c(t.bg);
    let fg = c(t.fg);
    let accent = c(accent);
    let toward = if t.dark { Color32::BLACK } else { Color32::WHITE };
    let panel = mix(bg, toward, 0.25);
    v.panel_fill = panel;
    v.window_fill = mix(bg, toward, 0.1);
    v.extreme_bg_color = mix(bg, toward, 0.35);
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, mix(panel, fg, 0.16));
    v.faint_bg_color = mix(panel, fg, 0.04);
    v.override_text_color = Some(fg);
    v.selection.bg_fill = mix(bg, accent, 0.45);
    v.selection.stroke = egui::Stroke::new(1.0, accent);
    v.hyperlink_color = accent;
    let r = egui::CornerRadius::same(7);
    v.widgets.noninteractive.corner_radius = r;
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.corner_radius = r;
    v.widgets.inactive.weak_bg_fill = mix(panel, fg, 0.07);
    v.widgets.hovered.weak_bg_fill = mix(panel, accent, 0.30);
    v.widgets.active.weak_bg_fill = mix(panel, accent, 0.50);
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, accent);
    v.window_corner_radius = egui::CornerRadius::same(10);
    ctx.set_visuals(v);
    ctx.set_zoom_factor(scale.clamp(0.7, 2.0));
}
