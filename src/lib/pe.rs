use crate::data_source::{DataSource, DataSourceExt, FileDataSource};
use crate::pe_structs::*;
use crate::pe_structs_wrapper::{DosHeader, Export, Import, NtHeaders, Sections};
use std::mem::MaybeUninit;
use std::path::Path;
#[derive(Debug)]
pub struct PeFile {
    data_source: Box<dyn DataSource>,
    dos_header: DosHeader,
    nt_headers: NtHeaders,
    sections: Sections,
    imports: Vec<Import>,
    export: Option<Export>,
    url: String,
}

impl PeFile {
    pub fn open_from_datasource(data_source: Box<dyn DataSource>) -> Result<Self, ParseError> {
        let dos_header = DosHeader::parse(&*data_source)?;
        let nt_start = dos_header.e_lfanew() as u64;
        let nt_headers = NtHeaders::parse(&*data_source, nt_start)?;

        let section_offset = nt_start + nt_headers.total_size();
        let count = nt_headers.file_header().number_of_sections() as usize;

        let section_alignment = if data_source.is_file_aligned() {
            nt_headers.optional_header().file_alignment()
        } else {
            nt_headers.optional_header().section_alignment()
        } as usize;

        let sections = Sections::parse(&*data_source, section_offset, count, section_alignment)?;

        let is_file_aligned = data_source.is_file_aligned();
        let auto_rva = |rva: u32| {
            if is_file_aligned {
                sections.RVA2FOA(rva)
            } else {
                rva
            }
        };

        // 根据对齐方式计算导入表偏移
        let mut input_table_offset = auto_rva(
            nt_headers
                .optional_header()
                .data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)
                .VirtualAddress,
        );

        // 无导入表时 IMAGE_DIRECTORY_ENTRY_IMPORT.VirtualAddress == 0，
        // 不应继续向下解析（否则会把 DOS 头当 IMAGE_IMPORT_DESCRIPTOR）。
        // 用真正的运行时检查代替 debug_assert!，保证 release 也安全。
        let mut imports: Vec<Import> = vec![];
        if input_table_offset > 0 {
            loop {
                let mut uninit_import_desc = MaybeUninit::<IMAGE_IMPORT_DESCRIPTOR>::uninit();
                unsafe {
                    let sz = data_source.read_struct(
                        input_table_offset as u64,
                        &mut (*uninit_import_desc.as_mut_ptr()),
                    )?;
                    let import_desc = uninit_import_desc.assume_init();
                    input_table_offset += sz as u32;

                    if import_desc.is_null() {
                        break;
                    }

                    let import = Import::parse(
                        &*data_source,
                        &auto_rva,
                        import_desc,
                        nt_headers.optional_header().is_pe32_plus(),
                    )?;
                    imports.push(import);
                }
            }
        }

        // 根据对齐方式计算导入表偏移
        let export_table_offset = auto_rva(
            nt_headers
                .optional_header()
                .data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)
                .VirtualAddress,
        );

        let export = if export_table_offset > 0 {
            let mut uninit_export_desc = MaybeUninit::<IMAGE_EXPORT_DIRECTORY>::uninit();

            unsafe {
                data_source.read_struct(
                    export_table_offset as u64,
                    &mut (*uninit_export_desc.as_mut_ptr()),
                )?;
                let export_desc = uninit_export_desc.assume_init();

                let export_data_dir = nt_headers
                    .optional_header()
                    .data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT);

                let export_dir_range = (export_data_dir.VirtualAddress, export_data_dir.Size);

                Some(Export::parse(
                    &*data_source,
                    export_desc,
                    export_dir_range,
                    &auto_rva,
                )?)
            }
        } else {
            None
        };

        let url = data_source.url();
        Ok(Self {
            dos_header,
            data_source,
            nt_headers,
            sections,
            imports,
            export,
            url
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

    pub fn sections(&self) -> &Sections {
        &self.sections
    }

    pub fn imports(&self) -> &Vec<Import> {
        &self.imports
    }

    pub fn export(&self) -> Option<&Export> {
        self.export.as_ref()
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
            .sections()
            .sections()
            .iter()
            .map(crate::report::section_row)
            .collect();
        crate::report::Report::new("Sections", crate::report::SECTION_COLUMNS, rows)
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
        self.sections.RVA2FOA(rva)
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
    Unknown,
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
            ParseError::Unknown => {
                write!(f, "unknown PE data source error")
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
