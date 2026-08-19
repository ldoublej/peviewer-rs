use pe::PeFile;

pub struct AppContext {
    current_url: Option<String>,
    pe_file: Option<PeFile>,
}

impl AppContext {
    pub fn current_url(&self) -> &Option<String> {
        &self.current_url
    }

    pub fn set_current_pe(&mut self, pe: PeFile) {
        self.current_url = Some(pe.data_source().url());
        self.pe_file = Some(pe);
    }

    pub fn clear_current_pe(&mut self) {
        self.current_url = None;
        self.pe_file = None;
    }

    pub fn current_main_pe(&self) -> &Option<PeFile> {
        &self.pe_file
    }
}

impl Default for AppContext {
    fn default() -> Self {
        Self {
            current_url: None,
            pe_file: None,
        }
    }
}
