use crate::data_source::{DataSource, DataSourceExt};
use crate::pe::ParseError;
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
        rva_to_foa: &dyn Fn(u32) -> u32,
        import_desc: IMAGE_IMPORT_DESCRIPTOR,
    ) -> Result<Self, ParseError> {
        let dll_name_foa = rva_to_foa(import_desc.Name);
        let dll_name = data_source
            .read_ascii(dll_name_foa as u64, 256)
            .map_err(ParseError::DataSource)?;
        let import_entry: Vec<ImportEntry> = vec![];
        Ok(Self {
            dll_name,
            import_desc,
            import_entry,
        })
    }
}
