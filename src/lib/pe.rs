use crate::data_source::{DataSource, FileDataSource};
use crate::pe_structs_wrapper::{DosHeader, NtHeaders, Section};
use std::path::Path;

pub struct PeFile {
    data_source: Box<dyn DataSource>,
    dos_header: DosHeader,
    nt_header: NtHeaders,
    sections: Vec<Section>,
}

impl PeFile {
    pub fn open_from_datasource(data_source: Box<dyn DataSource>) -> Result<Self, ParseError> {
        let dos_header = DosHeader::parse(&*data_source)?;
        let nt_start = dos_header.pe_offset() as u64;
        let nt_headers = NtHeaders::parse(&*data_source, nt_start)?;

        let mut section_offset = nt_start + nt_headers.total_size();
        let count = nt_headers.number_of_sections() as usize;
        let mut sections = Vec::with_capacity(count);
        for _ in 0..count {
            let (section, bytes_read) = Section::parse(&*data_source, section_offset)?;
            section_offset += bytes_read as u64;
            sections.push(section);
        }

        Ok(Self {
            dos_header,
            data_source,
            nt_header: nt_headers,
            sections,
        })
    }

    pub fn open_from_file(file_path: &Path) -> Result<Self, ParseError> {
        let result = FileDataSource::open_file(file_path);
        match result {
            Ok(file_data) => PeFile::open_from_datasource(file_data),
            Err(e) => Err(crate::pe::ParseError::DataSource(e)),
        }
    }

    pub fn data_source(&self) -> &dyn DataSource {
        self.data_source.as_ref()
    }

    pub fn dos_header(&self) -> &DosHeader {
        &self.dos_header
    }

    pub fn nt_headers(&self) -> &NtHeaders {
        &self.nt_header
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
            crate::report::file_header_fields(self.nt_header.file_header()),
        )
    }

    /// Report for the optional header (PE32 or PE32+).
    pub fn optional_header_report(&self) -> crate::report::Report {
        crate::report::Report::from_fields(
            "Optional Header",
            crate::report::optional_header_fields(self.nt_header.optional_header()),
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
