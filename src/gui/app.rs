use eframe::egui::{self, Rangef, Ui, Vec2};
use rfd::FileDialog;

use pe::PeFile;

use crate::app_context::AppContext;

// ---------------------------------------------------------------------------
// UI state
// ---------------------------------------------------------------------------

/// Which PE section to display in the central panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum View {
    #[default]
    DosHeader,
    NtHeaders,
    Sections,
    Imports,
    Exports,
}

impl View {
    fn label(self) -> &'static str {
        match self {
            View::DosHeader => "DOS Header",
            View::NtHeaders => "NT Headers",
            View::Sections => "Sections",
            View::Imports => "Imports",
            View::Exports => "Exports",
        }
    }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    context: AppContext,
    current_view: View,
    error_message: Option<String>,
    show_about: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            context: AppContext::default(),
            current_view: View::default(),
            error_message: None,
            show_about: false,
        }
    }
}

impl App {
    fn ui_menu_bar(&mut self, ctx: &egui::Context, ui: &mut Ui) {
        egui::menu::bar(ui, |ui| {
            self.ui_menu_file(ctx, ui);
            self.ui_menu_help(ctx, ui);
        });
    }

    fn ui_menu_help(&mut self, ctx: &egui::Context, ui: &mut Ui) {
        ui.menu_button("Help", |ui| {
            if ui.button("About").clicked() {
                ui.close_menu();
                self.show_about = true;
            }
        });
    }

    fn ui_menu_file(&mut self, ctx: &egui::Context, ui: &mut Ui) {
        ui.menu_button("File", |ui| {
            if ui.button("Open...").clicked() {
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Close").clicked() {
                ui.close_menu();
            }
        });
    }

    fn ui_about_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_about;
        egui::Window::new("About")
            .open(&mut open)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label("PE Viewer");
                ui.label(format!("Version: {}", env!("CARGO_PKG_VERSION")));
                ui.separator();
                ui.label("A simple PE (Portable Executable) file viewer.");
                ui.hyperlink("https://github.com/ldoublej/peviewer-rs");
            });
        self.show_about = open;
    }
}

// ---------------------------------------------------------------------------
// eframe::App
// ---------------------------------------------------------------------------

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            self.ui_menu_bar(ctx, ui);
        });

        egui::SidePanel::left("file view")
            .width_range(50.0..=500.0)
            .show(ctx, |ui| {
                // ui.allocate_space(Vec2::new(12.0, 12.0));
                ui.label("test");

                ui.button("text");
            });

        egui::CentralPanel::default().show(ctx, |ui| {});

        self.ui_about_window(ctx);
    }
}
