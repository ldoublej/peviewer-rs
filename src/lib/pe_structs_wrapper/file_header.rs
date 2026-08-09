use crate::pe_structs::IMAGE_FILE_HEADER;

/// The COFF file header. Layout is identical for PE32 and PE32+.
#[derive(Debug)]
pub struct FileHeader {
    file_header: IMAGE_FILE_HEADER,
}

impl FileHeader {
    pub(crate) fn new(file_header: IMAGE_FILE_HEADER) -> Self {
        Self { file_header }
    }

    pub fn machine(&self) -> u16 {
        self.file_header.Machine
    }
    pub fn number_of_sections(&self) -> u16 {
        self.file_header.NumberOfSections
    }
    pub fn time_date_stamp(&self) -> u32 {
        self.file_header.TimeDateStamp
    }
    pub fn pointer_to_symbol_table(&self) -> u32 {
        self.file_header.PointerToSymbolTable
    }
    pub fn number_of_symbols(&self) -> u32 {
        self.file_header.NumberOfSymbols
    }
    pub fn size_of_optional_header(&self) -> u16 {
        self.file_header.SizeOfOptionalHeader
    }
    pub fn characteristics(&self) -> u16 {
        self.file_header.Characteristics
    }
}
