use crate::data_source::{DataSource, FileDataSource};
use crate::pe_structs_wrapper::{DosHeader, NtHeaders, Section};
use crate::pe_structs::{*};
use std::path::Path;

#[derive(Debug)]
pub struct PeFile {
    data_source: Box<dyn DataSource>,
    dos_header: DosHeader,
    nt_headers: NtHeaders,
    sections: Vec<Section>,
}


#[allow(non_snake_case)]
fn RVA2FOA(sections: &Vec<Section>, rva: u32) -> u32 {
    let option_section =  sections.iter().find(|s| {
        rva >= s.virtual_address() && rva < s.virtual_address() + s.virtual_size()
    });
    if let Some(section) = option_section {
        let section_offset = rva - section.virtual_address();
        section.raw_offset() + section_offset
    }
    else {
        0
    }
}


impl PeFile {
    pub fn open_from_datasource(data_source: Box<dyn DataSource>) -> Result<Self, ParseError> {
        let dos_header = DosHeader::parse(&*data_source)?;
        let nt_start = dos_header.e_lfanew() as u64;
        let nt_headers = NtHeaders::parse(&*data_source, nt_start)?;

        let mut section_offset = nt_start + nt_headers.total_size();
        let count = nt_headers.file_header().number_of_sections() as usize;
        let opt = nt_headers.optional_header();
        let section_alignment = opt.section_alignment();
        let file_alignment = opt.file_alignment();
        let mut sections = Vec::with_capacity(count);
        for _ in 0..count {
            let (section, bytes_read) = Section::parse(
                &*data_source,
                section_offset,
                section_alignment,
                file_alignment,
            )?;
            section_offset += bytes_read as u64;
            sections.push(section);
        }

        // 根据对齐方式计算导入表偏移
        let input_table = if data_source.is_file_aligned() {
            let virtual_size = nt_headers.optional_header().data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress;
            RVA2FOA(&sections, virtual_size)
        } else {
            nt_headers.optional_header().data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress
        };

        debug_assert!(input_table > 0);
        

        Ok(Self {
            dos_header,
            data_source,
            nt_headers,
            sections,
        })
    }

    pub fn open_from_file(file_path: &Path) -> Result<Self, ParseError> {
        let file_data = FileDataSource::open_file(file_path)?;
        PeFile::open_from_datasource(file_data)
    }

    pub fn data_source(&self) -> &dyn DataSource {
        self.data_source.as_ref()
    }

    pub fn dos_header(&self) -> &DosHeader {
        &self.dos_header
    }

    pub fn nt_headers(&self) -> &NtHeaders {
        &self.nt_headers
    }

    pub fn sections(&self) -> &Vec<Section> {
        &self.sections
    }

    // -- Reports ------------------------------------------------------------
    // These expose the parsed structures as presentation-agnostic `Report`s
    // (title + headers + rows) so a frontend can print them uniformly without
    // needing access to the private `pe_structs` types.

    /// Report for the DOS header.
    pub fn dos_header_report(&self) -> crate::report::Report {
        crate::report::Report::from_fields(
            "DOS Header",
            crate::report::dos_header_fields(&self.dos_header),
        )
    }

    /// Report for the COFF file header.
    pub fn file_header_report(&self) -> crate::report::Report {
        crate::report::Report::from_fields(
            "File Header",
            crate::report::file_header_fields(self.nt_headers.file_header()),
        )
    }

    /// Report for the optional header (PE32 or PE32+).
    pub fn optional_header_report(&self) -> crate::report::Report {
        crate::report::Report::from_fields(
            "Optional Header",
            crate::report::optional_header_fields(self.nt_headers.optional_header()),
        )
    }

    /// Report for the section table.
    pub fn sections_report(&self) -> crate::report::Report {
        let rows = self
            .sections
            .iter()
            .map(crate::report::section_row)
            .collect();
        crate::report::Report::new("Sections", crate::report::SECTION_COLUMNS, rows)
    }

    /// Returns the section named exactly `.text`, if present.
    pub fn text_section(&self) -> Option<&Section> {
        self.sections.iter().find(|s| s.name() == ".text")
    }

    /// The `ImageBase` + `AddressOfEntryPoint` (the entry RVA). Callers
    /// that want a runtime virtual address add this to the image base
    /// (which depends on bit width).
    pub fn address_of_entry_point(&self) -> u32 {
        self.nt_headers.optional_header().address_of_entry_point()
    }

    /// True if the image is PE32+ (64-bit).
    pub fn is_pe32_plus(&self) -> bool {
        self.nt_headers.optional_header().is_pe32_plus()
    }

    pub fn rva2foa(&self, rva: u32) -> u32 {
        RVA2FOA(&self.sections, rva)
    }
}

// ---------------------------------------------------------------------------
// ParseError
// ---------------------------------------------------------------------------

/// Errors that can occur when parsing a PE image.
#[derive(Debug)]
pub enum ParseError {
    /// The data source is too small to contain a valid PE header.
    TooSmall(u64),
    /// The DOS magic ("MZ") was not found.
    InvalidMagic {
        expected: &'static str,
        found: String,
    },
    /// An underlying data-source error.
    DataSource(crate::data_source::DataSourceError),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::TooSmall(len) => {
                write!(f, "PE data too small: {len} bytes (need at least 64)")
            }
            ParseError::InvalidMagic { expected, found } => {
                write!(
                    f,
                    "invalid DOS magic: expected \"{expected}\", got \"{found}\""
                )
            }
            ParseError::DataSource(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<crate::data_source::DataSourceError> for ParseError {
    fn from(e: crate::data_source::DataSourceError) -> Self {
        ParseError::DataSource(e)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_source::DataSourceExt;

    /// Build a minimal PE32 image: a valid DOS header whose `e_lfanew`
    /// points to a signature + COFF file header + a tiny optional header.
    fn minimal_pe32() -> Vec<u8> {
        // Layout (all offsets are byte offsets in the image):
        //   0x00  DOS header (64 bytes)            e_lfanew = 0x80
        //   0x40  DOS stub bytes (we leave them zero)
        //   0x80  NT signature "PE\0\0"            (4 bytes)
        //   0x84  COFF file header                 (20 bytes)
        //   0x98  Optional header magic            (2 bytes) + rest zeroed
        // The SizeOfOptionalHeader we declare in the COFF header dictates
        // how many bytes the parser consumes from the optional header; we
        // set it to 224 (sizeof(IMAGE_OPTIONAL_HEADER32) including the
        // 16 IMAGE_DATA_DIRECTORY entries) and size the buffer to match.
        let opt_size: u16 = 224;
        let total = 0x80 + 4 + 20 + opt_size as usize;
        let mut buf = vec![0u8; total];

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew at offset 0x3C, little-endian
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // NT signature at 0x80
        buf[0x80..0x84].copy_from_slice(b"PE\0\0");

        // COFF file header at 0x84
        let coff = 0x84;
        buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes()); // Machine
        buf[coff + 2..coff + 4].copy_from_slice(&0u16.to_le_bytes()); // NumberOfSections
        buf[coff + 4..coff + 8].copy_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        buf[coff + 8..coff + 12].copy_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
        buf[coff + 12..coff + 16].copy_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
        buf[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes()); // SizeOfOptionalHeader
        buf[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

        // Optional header magic at 0x98: PE32 = 0x10B
        let opt = 0x98;
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());

        buf
    }

    #[test]
    fn open_minimal_pe32() {
        let raw = minimal_pe32();
        let pe = PeFile::open_from_datasource(Box::new(raw)).expect("parse should succeed");

        // DOS header
        assert_eq!(pe.dos_header().magic(), 0x5A4D);
        assert_eq!(pe.dos_header().e_lfanew(), 0x80);

        // NT header
        assert_eq!(pe.nt_headers().signature(), 0x00004550);
        assert!(!pe.nt_headers().optional_header().is_pe32_plus());
        assert_eq!(pe.nt_headers().file_header().number_of_sections(), 0);

        // File header
        assert_eq!(pe.nt_headers().file_header().machine(), 0x014C);
        assert_eq!(pe.nt_headers().file_header().characteristics(), 0x0102);

        // Optional header
        assert_eq!(pe.nt_headers().optional_header().magic(), 0x010B);

        // No sections
        assert!(pe.sections().is_empty());
    }

    #[test]
    fn reject_bad_dos_magic() {
        let raw = vec![0u8; 0x100];
        let err = PeFile::open_from_datasource(Box::new(raw)).unwrap_err();
        assert!(matches!(err, ParseError::InvalidMagic { .. }));
    }

    #[test]
    fn reject_bad_nt_signature() {
        let mut raw = minimal_pe32();
        // Corrupt the NT signature.
        raw[0x80] = b'X';
        let err = PeFile::open_from_datasource(Box::new(raw)).unwrap_err();
        assert!(matches!(err, ParseError::InvalidMagic { .. }));
    }

    #[test]
    fn reject_unknown_optional_magic() {
        let mut raw = minimal_pe32();
        let opt = 0x98;
        raw[opt..opt + 2].copy_from_slice(&0x9999u16.to_le_bytes());
        let err = PeFile::open_from_datasource(Box::new(raw)).unwrap_err();
        assert!(matches!(err, ParseError::InvalidMagic { .. }));
    }

    #[test]
    fn dos_header_report_has_fields() {
        let raw = minimal_pe32();
        let pe = PeFile::open_from_datasource(Box::new(raw)).unwrap();
        let report = pe.dos_header_report();
        assert_eq!(report.title, "DOS Header");
        // e_magic and e_lfanew should both be present.
        assert!(report.rows.iter().any(|r| r[0] == "e_magic"));
        assert!(report.rows.iter().any(|r| r[0] == "e_lfanew"));
    }

    #[test]
    fn data_source_still_accessible() {
        let raw = minimal_pe32();
        let pe = PeFile::open_from_datasource(Box::new(raw.clone())).unwrap();
        // The data source is kept; we can still read through it.
        let b: [u8; 2] = pe.data_source().read_array(0).unwrap();
        assert_eq!(b, [b'M', b'Z']);
        // And the data is still there.
        let _ = raw;
    }
}
