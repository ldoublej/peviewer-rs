//! Thin entry point. The actual app + rendering live in sibling modules.

mod app;
use app::PeViewerApp;
use eframe::egui;

const WINDOW_SIZE: [f32; 2] = [1024.0, 720.0];

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size(WINDOW_SIZE),
        ..Default::default()
    };
    eframe::run_native(
        "peviewer-gui",
        options,
        Box::new(|_cc| Ok(Box::<PeViewerApp>::default())),
    )
}
