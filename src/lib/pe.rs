use crate::data_source::{DataSource, DataSourceExt};
use crate::pe_structs::*;

pub struct PeFile {
    dos_header: IMAGE_DOS_HEADER,
    data_source: Box<dyn DataSource>,
    nt_header: IMAGE_NT_HEADERS,
    sections: Vec<IMAGE_SECTION_HEADER>,
}

impl PeFile {
    pub fn parse(data_source: Box<dyn DataSource>) -> Result<Self, ParseError> {
        let len = data_source.len().unwrap_or(0);
        if len < std::mem::size_of::<IMAGE_DOS_HEADER>() as u64 {
            return Err(ParseError::TooSmall(len));
        }

        // 读取解析 IMAGE_DOS_HEADER头
        let mut dos_header = IMAGE_DOS_HEADER::default();
        data_source
            .read_struct(0, &mut dos_header)
            .map_err(ParseError::DataSource)?;
        // DOS magic is "MZ" → 0x5A4D in little-endian u16
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(ParseError::InvalidMagic {
                expected: "MZ",
                found: format!("{:#06X}", dos_header.e_magic),
            });
        }

        // 预先读取 IMAGE_OPTIONAL_HEADER 中的 Magic 字段，判断PE类型（PE32 or PE32P）
        let mut current_offset: usize = dos_header.e_lfanew as usize;
        let magic_offset =
            current_offset + std::mem::size_of::<u32>() + std::mem::size_of::<IMAGE_FILE_HEADER>();
        let magic = data_source
            .read_u16(magic_offset as u64)
            .map_err(ParseError::DataSource)?;

        // 根据 IMAGE_OPTIONAL_HEADER 中的 Magic 决定 IMAGE_NT_HEADERS 的类型
        let nt_header: IMAGE_NT_HEADERS;
        match magic {
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                let mut nt_header64: IMAGE_NT_HEADERS64 = unsafe { std::mem::zeroed() };
                let sz = data_source
                    .read_struct(current_offset as u64, &mut nt_header64)
                    .map_err(ParseError::DataSource)?;
                current_offset += sz;
                nt_header = IMAGE_NT_HEADERS::PE32P(nt_header64);
            }
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                let mut nt_header32: IMAGE_NT_HEADERS32 = unsafe { std::mem::zeroed() };
                let sz = data_source
                    .read_struct(current_offset as u64, &mut nt_header32)
                    .map_err(ParseError::DataSource)?;
                current_offset += sz;
                nt_header = IMAGE_NT_HEADERS::PE32(nt_header32);
            }
            _ => {
                return Err(ParseError::InvalidMagic {
                    expected: "0x10b or 0x20b 0r 0x107",
                    found: format!("{:#06X}", magic),
                });
            }
        }

        // 加载Section
        let section_count;
        match nt_header {
            IMAGE_NT_HEADERS::PE32P(headers) => {
                section_count = headers.FileHeader.NumberOfSections;
            }
            IMAGE_NT_HEADERS::PE32(headers) => {
                section_count = headers.FileHeader.NumberOfSections;
            }
        }
        let mut sections = Vec::new();
        for _ in 0..section_count {
            let mut section_header: IMAGE_SECTION_HEADER = unsafe { std::mem::zeroed() };
            let sz = data_source
                .read_struct(current_offset as u64, &mut section_header)
                .map_err(ParseError::DataSource)?;
            current_offset += sz;
            sections.push(section_header);
        }

        Ok(Self {
            dos_header,
            data_source,
            nt_header,
            sections,
        })
    }

    pub fn data_source(&self) -> &dyn DataSource {
        self.data_source.as_ref()
    }

    pub fn dos_header(&self) -> &IMAGE_DOS_HEADER {
        &self.dos_header
    }

    pub fn nt_headers(&self) -> &IMAGE_NT_HEADERS {
        &self.nt_header
    }

    pub fn sections(&self) -> &Vec<IMAGE_SECTION_HEADER> {
        &self.sections
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
