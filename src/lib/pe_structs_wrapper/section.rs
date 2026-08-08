use super::align::align_up;
use crate::data_source::DataSource;
use crate::data_source::DataSourceExt;
use crate::pe::ParseError;
use crate::pe_structs::IMAGE_SECTION_HEADER;

/// A parsed section header.
#[derive(Debug)]
pub struct Section {
    section_header: IMAGE_SECTION_HEADER,
    section_data: Option<Vec<u8>>,
}

impl Section {
    /// Read one `IMAGE_SECTION_HEADER` at `offset`. Returns the section
    /// plus the number of bytes consumed (always
    /// `size_of::<IMAGE_SECTION_HEADER>()`).
    ///
    /// `section_alignment` and `file_alignment` come from the optional
    /// header; they are used to round the section's on-image / in-file
    /// size up to a multiple of the alignment. `is_file_aligned` on the
    /// source picks which size is read: the file-aligned `SizeOfRawData`
    /// (rounded up to `file_alignment`) or the in-memory `VirtualSize`
    /// (rounded up to `section_alignment`).
    pub fn parse<T: DataSource + ?Sized>(
        source: &T,
        offset: u64,
        section_alignment: u32,
        file_alignment: u32,
    ) -> Result<(Self, usize), ParseError> {
        let size = std::mem::size_of::<IMAGE_SECTION_HEADER>();
        if source.len().unwrap_or(0) < offset + size as u64 {
            return Err(ParseError::TooSmall(source.len().unwrap_or(0)));
        }

        let mut section_header = unsafe { std::mem::zeroed::<IMAGE_SECTION_HEADER>() };
        let sz = source
            .read_struct(offset, &mut section_header)
            .map_err(ParseError::DataSource)?;
        debug_assert_eq!(sz, size);

        let section_offset = section_header.PointerToRawData as u64;
        let raw_size = section_header.SizeOfRawData as usize;
        let virtual_size = section_header.VirtualSize as usize;
        let section_size = if source.is_file_aligned() {
            align_up(raw_size, file_alignment as usize)
        } else {
            align_up(virtual_size, section_alignment as usize)
        };

        let raw_section_data = source.read_bytes(section_offset, section_size)?;
        Ok((
            Self {
                section_header,
                section_data: Some(raw_section_data),
            },
            sz,
        ))
    }

    /// 8-byte ASCII name, NUL-trimmed.
    pub fn name(&self) -> String {
        let raw = &self.section_header.Name;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    }

    pub fn section_data(&self) -> Option<&Vec<u8>> {
        self.section_data.as_ref()
    }

    pub fn virtual_address(&self) -> u32 {
        self.section_header.VirtualAddress
    }
    pub fn virtual_size(&self) -> u32 {
        self.section_header.VirtualSize
    }
    pub fn raw_size(&self) -> u32 {
        self.section_header.SizeOfRawData
    }
    pub fn raw_offset(&self) -> u32 {
        self.section_header.PointerToRawData
    }
    pub fn pointer_to_relocations(&self) -> u32 {
        self.section_header.PointerToRelocations
    }
    pub fn pointer_to_linenumbers(&self) -> u32 {
        self.section_header.PointerToLinenumbers
    }
    pub fn number_of_relocations(&self) -> u16 {
        self.section_header.NumberOfRelocations
    }
    pub fn number_of_linenumbers(&self) -> u16 {
        self.section_header.NumberOfLinenumbers
    }
    pub fn characteristics(&self) -> u32 {
        self.section_header.Characteristics
    }
}
