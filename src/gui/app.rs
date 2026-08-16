//! The `PeViewerApp`: PE state, file open/close, menu, tab bar, and the
//! per-frame `update()` that wires the right view in response to the
//! selected [`Section`]. Section rendering itself lives in [`views`].
//!
//! `views` is a sibling module declared in `main.rs`.

use eframe::egui;

pub struct PeViewerApp {
}

impl Default for PeViewerApp {
    fn default() -> Self {
        Self {

        }
    }
}

impl eframe::App for PeViewerApp {
    fn update(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {

    }
}