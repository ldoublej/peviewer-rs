use eframe::egui;
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
            View::DosHeader  => "DOS Header",
            View::NtHeaders  => "NT Headers",
            View::Sections   => "Sections",
            View::Imports    => "Imports",
            View::Exports    => "Exports",
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
}

impl Default for App {
    fn default() -> Self {
        Self {
            context: AppContext::default(),
            current_view: View::default(),
            error_message: None,
        }
    }
}

impl App {
    /// Open a PE file from disk and load it into the app context.
    fn open_pe_file(&mut self) {
        let Some(path) = FileDialog::new()
            .add_filter("PE files", &["exe", "dll", "sys", "ocx", "cpl"])
            .add_filter("All files", &["*"])
            .set_title("Open PE file")
            .pick_file()
        else {
            return; // user cancelled
        };

        match PeFile::open_from_file(&path) {
            Ok(pe) => self.context.set_current_pe(pe),
            Err(e) => self.error_message = Some(format!("Failed to open `{}`: {e}", path.display())),
        }
    }

    /// Close the currently loaded PE file.
    fn close_pe_file(&mut self) {
        self.context.clear_current_pe();
    }

    /// Show an error popup if one is queued.
    fn show_error_dialog(&mut self, ctx: &egui::Context) {
        let Some(msg) = self.error_message.clone() else {
            return;
        };

        let mut open = true;
        egui::Window::new("Error")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(&msg);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("OK").clicked() {
                        self.error_message = None;
                    }
                });
            });

        if !open {
            self.error_message = None;
        }
    }

    // -- top menu bar -------------------------------------------------------

    fn menu_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        egui::menu::bar(ui, |ui| {
            self.file_menu(ui, ctx);
            self.view_menu(ui);
            self.help_menu(ui);
        });
    }

    fn file_menu(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let has_pe = self.context.current_main_pe().is_some();

        ui.menu_button("File", |ui| {
            if ui
                .add(egui::Button::new("Open...").shortcut_text("Ctrl+O"))
                .clicked()
            {
                ui.close_menu();
                self.open_pe_file();
            }

            let close_btn = ui.add_enabled(has_pe, egui::Button::new("Close"));
            if close_btn.clicked() {
                ui.close_menu();
                self.close_pe_file();
            }

            ui.separator();

            if ui.button("Exit").clicked() {
                ui.close_menu();
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });
    }

    fn view_menu(&mut self, ui: &mut egui::Ui) {
        ui.menu_button("View", |ui| {
            for view in [
                View::DosHeader,
                View::NtHeaders,
                View::Sections,
                View::Imports,
                View::Exports,
            ] {
                let label = format!("Show {}", view.label());
                if ui
                    .add(egui::RadioButton::new(self.current_view == view, label))
                    .clicked()
                {
                    self.current_view = view;
                    ui.close_menu();
                }
            }
        });
    }

    fn help_menu(&mut self, ui: &mut egui::Ui) {
        ui.menu_button("Help", |ui| {
            if ui.button("About").clicked() {
                self.error_message = Some(
                    "peviewer-rs\n\nA simple PE (Portable Executable) file inspector."
                        .to_string(),
                );
                ui.close_menu();
            }
        });
    }

    // -- central panel ------------------------------------------------------

    fn central_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| match self.context.current_main_pe() {
            None => self.empty_state(ui),
            Some(pe) => {
                ui.heading(pe.data_source().url());
                ui.separator();
                match self.current_view {
                    View::DosHeader => self.view_dos_header(ui, pe),
                    View::NtHeaders => self.view_nt_headers(ui, pe),
                    View::Sections  => self.view_sections(ui, pe),
                    View::Imports   => self.view_imports(ui, pe),
                    View::Exports   => self.view_exports(ui, pe),
                }
            }
        });
    }

    fn empty_state(&self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.heading("No PE file loaded");
            ui.add_space(8.0);
            ui.label("Use File → Open... (Ctrl+O) to load a PE file.");
        });
    }

    // Per-view renderers. These are placeholders; once the corresponding
    // presentation layer exists they should be replaced with real rendering.
    fn view_dos_header(&self, ui: &mut egui::Ui, _pe: &PeFile) {
        ui.heading(View::DosHeader.label());
        ui.label("(DOS header view not implemented yet.)");
    }
    fn view_nt_headers(&self, ui: &mut egui::Ui, _pe: &PeFile) {
        ui.heading(View::NtHeaders.label());
        ui.label("(NT headers view not implemented yet.)");
    }
    fn view_sections(&self, ui: &mut egui::Ui, _pe: &PeFile) {
        ui.heading(View::Sections.label());
        ui.label("(Sections view not implemented yet.)");
    }
    fn view_imports(&self, ui: &mut egui::Ui, _pe: &PeFile) {
        ui.heading(View::Imports.label());
        ui.label("(Imports view not implemented yet.)");
    }
    fn view_exports(&self, ui: &mut egui::Ui, _pe: &PeFile) {
        ui.heading(View::Exports.label());
        ui.label("(Exports view not implemented yet.)");
    }
}

// ---------------------------------------------------------------------------
// eframe::App
// ---------------------------------------------------------------------------

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // Ctrl+O opens a file regardless of focus.
        if ctx.input(|i| i.key_pressed(egui::Key::O) && i.modifiers.ctrl) {
            self.open_pe_file();
        }

        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            self.menu_bar(ui, ctx);
        });

        self.central_panel(ctx);
        self.show_error_dialog(ctx);
    }
}
