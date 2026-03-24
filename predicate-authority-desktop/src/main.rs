//! Predicate Authority Desktop — local companion for `predicate-authorityd`.

mod api;
mod app;
mod diagnostics;
mod theme;
mod keychain;
mod launch_args;
mod policy_diff;
mod policy_ui;
mod presets;
mod process;
mod sidecar_probe;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([920.0, 680.0])
            .with_title("Predicate Authority Desktop"),
        ..Default::default()
    };
    eframe::run_native(
        "Predicate Authority Desktop",
        options,
        Box::new(|cc| Ok(Box::new(app::DesktopApp::new(cc)))),
    )
}
