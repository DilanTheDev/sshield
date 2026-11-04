//! sshield - a fast, free, native SSH client (desktop binary + Android library).

mod agent;
mod app;
mod sftp_view;
mod term;
mod theme;
mod update;

fn run(opts: eframe::NativeOptions) -> eframe::Result {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let handle = rt.handle().clone();
    let r = eframe::run_native(
        "sshield",
        opts,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, handle.clone())))),
    );
    drop(rt);
    r
}

/// Desktop entry point (called by the `sshield` binary).
#[cfg(not(target_os = "android"))]
pub fn run_desktop() -> eframe::Result {
    run(eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("sshield")
            .with_inner_size([1200.0, 760.0])
            .with_min_inner_size([760.0, 480.0]),
        ..Default::default()
    })
}

/// Android entry point (NativeActivity).
#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: winit::platform::android::activity::AndroidApp) {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info),
    );
    if let Some(dir) = app.internal_data_path() {
        sshield_core::vault::set_data_dir(dir.join("sshield"));
    }
    let opts = eframe::NativeOptions {
        android_app: Some(app),
        ..Default::default()
    };
    if let Err(e) = run(opts) {
        log::error!("sshield exited with error: {e}");
    }
}
