use crate::pe_structs::{IMAGE_IMPORT_DESCRIPTOR};
use crate::data_source::{DataSource, DataSourceExt};
enum ImportEntry {
    ImportByOrdinal(u64),
    ImportByName(u16,String)
}



struct Import {
    dll_name: String,
    entry_import: IMAGE_IMPORT_DESCRIPTOR,
    import_entrys: Vec<ImportEntry>
}

impl Import {
    pub fn parse<T: DataSource + ?Sized>(data_source: &T, offset: u64) -> Option<Self> {
        let size = std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        if data_source.len().unwrap_or(0) < offset + size as u64 {
            return None;
        }

        let mut import_desc = unsafe { std::mem::zeroed::<IMAGE_IMPORT_DESCRIPTOR>() };
        let sz = data_source
            .read_struct(offset, &mut import_desc)
            .map_err(ParseError::DataSource)?;
        debug_assert_eq!(sz, size);
    }
}