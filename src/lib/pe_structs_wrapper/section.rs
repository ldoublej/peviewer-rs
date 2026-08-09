use super::align::align_up;
use crate::data_source::DataSource;
use crate::data_source::DataSourceExt;
use crate::pe::ParseError;
use crate::pe_structs::IMAGE_SECTION_HEADER;

#[derive(Debug)]
pub struct Sections {
    sections: Vec<Section>,
}

impl Sections {
    pub fn parse<T: DataSource + ?Sized>(
        data_source: &T,
        offset: u64,
        count: usize,
        alignment: usize,
    ) -> Result<Self, ParseError> {
        let mut section_offset = offset;
        let mut sections = Vec::with_capacity(count);
        for _ in 0..count {
            let (section, bytes_read) = Section::parse(data_source, section_offset, alignment)?;
            section_offset += bytes_read as u64;
            sections.push(section);
        }
        Ok(Self { sections })
    }

    #[allow(non_snake_case)]
    pub fn RVA2FOA(&self, rva: u32) -> u32 {
        let rva = rva as u64;
        let option_section = self.sections.iter().find(|s| {
            // BSS 段 (SizeOfRawData == 0) 在文件中没有内容，不应被命中——
            // 否则会返回一个看起来合法但其实指向空数据的 FOA。
            if s.raw_size() == 0 {
                return false;
            }
            // 用 u64 计算结束地址，避免 VirtualAddress + VirtualSize 在 u32 上溢出
            let va = s.virtual_address() as u64;
            let vs = s.virtual_size() as u64;
            rva >= va && rva < va.saturating_add(vs)
        });
        if let Some(section) = option_section {
            let section_offset = (rva - section.virtual_address() as u64) as u32;
            section.raw_offset().saturating_add(section_offset)
        } else {
            0
        }
    }

    pub fn sections(&self) -> &Vec<Section> {
        &self.sections
    }

    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name() == name)
    }

    pub fn len(&self) -> usize {
        self.sections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }
}

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
    /// `alignment` comes from the optional header and is used to round
    /// the section's on-image / in-file size up to a multiple of the
    /// alignment. `is_file_aligned` on the source picks which size is
    /// read: the file-aligned `SizeOfRawData` (rounded up to
    /// `file_alignment`) or the in-memory `VirtualSize` (rounded up
    /// to `section_alignment`).
    ///
    /// # In-memory read path
    ///
    /// The non-file-aligned branch is a scaffold for a future mmap
    /// view; it treats `VirtualAddress` as a direct byte offset, which
    /// is wrong for a real image (an RVA only becomes a real virtual
    /// address once `ImageBase` is added). Today every `DataSource`
    /// impl that returns `is_file_aligned() == false`
    /// (`Vec<u8>`, `&[u8]`) still holds a file-layout buffer, so the
    /// file-aligned branch is the only one that's actually exercised.
    /// Callers that want correct in-memory reads should add a real
    /// mapped-image `DataSource` and a proper RVA→VA translation
    /// here.
    pub fn parse<T: DataSource + ?Sized>(
        data_source: &T,
        offset: u64,
        alignment: usize,
    ) -> Result<(Self, usize), ParseError> {
        let size = std::mem::size_of::<IMAGE_SECTION_HEADER>();
        // 流式 DataSource 的 len() 可能返回 None；不要因为取不到总长就拒绝解析，
        // 让真正的 read_exact 在越界时报错即可。
        if let Some(len) = data_source.len()
            && len < offset + size as u64
        {
            return Err(ParseError::TooSmall(len));
        }

        let mut section_header = unsafe { std::mem::zeroed::<IMAGE_SECTION_HEADER>() };
        let sz = data_source
            .read_struct(offset, &mut section_header)
            .map_err(ParseError::DataSource)?;
        debug_assert_eq!(sz, size);

        let section_offset = if data_source.is_file_aligned() {
            section_header.PointerToRawData as u64
        } else {
            section_header.VirtualAddress as u64
        };
        let raw_size = section_header.SizeOfRawData as usize;
        let virtual_size = section_header.VirtualSize as usize;
        let section_size = if data_source.is_file_aligned() {
            align_up(raw_size, alignment)
        } else {
            align_up(virtual_size, alignment)
        };

        let raw_section_data = data_source.read_bytes(section_offset, section_size)?;
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
