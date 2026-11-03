//! sshield - a fast, free, native SSH client.
#![cfg_attr(all(not(debug_assertions), windows), windows_subsystem = "windows")]

mod app;
mod sftp_view;
mod term;
mod theme;

fn main() -> eframe::Result {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("tokio runtime");
    let handle = rt.handle().clone();
    let opts = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_title("sshield").with_inner_size([1200.0, 760.0]).with_min_inner_size([760.0, 480.0]),
        ..Default::default()
    };
    let r = eframe::run_native("sshield", opts, Box::new(move |cc| Ok(Box::new(app::App::new(cc, handle.clone())))));
    drop(rt);
    r
}
