//! Thin entry point. The actual app + rendering live in sibling modules.

mod app;
mod app_context;

use app::App;
use eframe::egui;

const WINDOW_SIZE: [f32; 2] = [512.0, 720.0];

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size(WINDOW_SIZE),
        ..Default::default()
    };

    eframe::run_native(
        "peviewer-gui",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_zoom_factor(1.25);
            Ok(Box::<App>::default())
        }),
    )
}
