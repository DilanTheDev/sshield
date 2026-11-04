//! sshield - a fast, free, native SSH client.
#![cfg_attr(all(not(debug_assertions), windows), windows_subsystem = "windows")]

fn main() -> eframe::Result {
    sshield_app::run_desktop()
}
