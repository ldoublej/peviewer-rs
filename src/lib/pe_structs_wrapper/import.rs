use crate::data_source::{DataSource, DataSourceExt};
use crate::pe::ParseError;
use crate::pe_structs::{IMAGE_IMPORT_DESCRIPTOR, IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64};

#[derive(Clone, Debug)]
pub enum ImportEntry {
    ImportByOrdinal(u32),
    ImportByName(u16, String),
    FunctionAddress(u64),
}

#[derive(Debug)]
pub struct Import {
    dll_name: String,
    _import_desc: IMAGE_IMPORT_DESCRIPTOR,
    int: Vec<ImportEntry>,
    iat: Vec<ImportEntry>,
}

impl Import {
    pub fn parse<T: DataSource + ?Sized>(
        data_source: &T,
        rva_to_foa: &dyn Fn(u32) -> u32,
        import_desc: IMAGE_IMPORT_DESCRIPTOR,
        is_pe32p: bool,
    ) -> Result<Self, ParseError> {
        let dll_name_foa = rva_to_foa(import_desc.Name);
        let dll_name = data_source
            .read_ascii(dll_name_foa as u64, 256)
            .map_err(ParseError::DataSource)?;
        let mut int: Vec<ImportEntry> = vec![];
        let mut iat: Vec<ImportEntry> = vec![];

        // 读取INT。PE32+ 的 thunk 是 8 字节，序号标志位在最高位
        // (IMAGE_ORDINAL_FLAG64 = 0x8000_0000_0000_0000)。如果把 u64 强转成
        // u32 再判位，会把高 32 位——也就是标志位——砍掉，导致所有 PE32+
        // 序号导入被错认成按名导入。
        let mut original_thunk_offset = rva_to_foa(import_desc.OriginalFirstThunk) as u64;
        loop {
            if is_pe32p {
                let thunk = data_source.read_u64(original_thunk_offset)?;
                if thunk == 0 {
                    break;
                }
                if thunk & IMAGE_ORDINAL_FLAG64 != 0 {
                    let ordinal = (thunk & 0xFFFF) as u32;
                    int.push(ImportEntry::ImportByOrdinal(ordinal));
                } else {
                    let name_rva = thunk as u32;
                    let mut import_by_name_offset = rva_to_foa(name_rva) as u64;
                    let hint = data_source.read_u16(import_by_name_offset)?;
                    import_by_name_offset += std::mem::size_of::<u16>() as u64;
                    let name = data_source.read_ascii(import_by_name_offset, 256)?;
                    int.push(ImportEntry::ImportByName(hint, name));
                }
                original_thunk_offset += std::mem::size_of::<u64>() as u64;
            } else {
                let thunk = data_source.read_u32(original_thunk_offset)?;
                if thunk == 0 {
                    break;
                }
                if thunk & IMAGE_ORDINAL_FLAG32 != 0 {
                    let ordinal = thunk & 0x7FFF_FFFF;
                    int.push(ImportEntry::ImportByOrdinal(ordinal));
                } else {
                    let mut import_by_name_offset = rva_to_foa(thunk) as u64;
                    let hint = data_source.read_u16(import_by_name_offset)?;
                    import_by_name_offset += std::mem::size_of::<u16>() as u64;
                    let name = data_source.read_ascii(import_by_name_offset, 256)?;
                    int.push(ImportEntry::ImportByName(hint, name));
                }
                original_thunk_offset += std::mem::size_of::<u32>() as u64;
            }
        }

        // 读取IAT
        let mut first_thunk_offset = rva_to_foa(import_desc.FirstThunk) as u64;
        if !data_source.is_file_aligned() {
            loop {
                let thunk: u64;
                let thunk_size = if is_pe32p {
                    thunk = data_source.read_u64(first_thunk_offset)?;
                    std::mem::size_of::<u64>()
                } else {
                    thunk = data_source.read_u32(first_thunk_offset)? as u64;
                    std::mem::size_of::<u32>()
                };

                if thunk == 0 {
                    break;
                }
                first_thunk_offset += thunk_size as u64;
                int.push(ImportEntry::FunctionAddress(thunk));
            }
        } else {
            iat = int.clone();
        }
        Ok(Self {
            dll_name,
            _import_desc: import_desc,
            int,
            iat,
        })
    }

    pub fn dll_name(&self) -> &str {
        &self.dll_name
    }

    pub fn import_name_table(&self) -> &Vec<ImportEntry> {
        &self.int
    }

    pub fn import_address_table(&self) -> &Vec<ImportEntry> {
        &self.iat
    }
}
