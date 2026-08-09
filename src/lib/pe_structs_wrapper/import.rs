use crate::data_source::{DataSource, DataSourceExt};
use crate::pe_structs::IMAGE_IMPORT_DESCRIPTOR;

#[derive(Debug)]
pub enum ImportEntry {
    ImportByOrdinal(u64),
    ImportByName(u16, String),
}

#[derive(Debug)]
pub struct Import {
    dll_name: String,
    import_desc: IMAGE_IMPORT_DESCRIPTOR,
    import_entry: Vec<ImportEntry>,
}

impl Import {
    pub fn parse<T: DataSource + ?Sized>(
        data_source: &T,
        import_desc: IMAGE_IMPORT_DESCRIPTOR,
    ) -> Self {
        let import_entry: Vec<ImportEntry> = vec![];
        Self {
            dll_name: String::from(""),
            import_desc,
            import_entry,
        }
    }
}
