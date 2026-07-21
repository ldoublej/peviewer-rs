use crate::data_source::{DataSource, DataSourceExt};
use crate::pe_structs::IMAGE_DOS_HEADER;

#[derive(Debug)]
pub struct PeFile {
    dos_header: IMAGE_DOS_HEADER,
    data_source: Box<dyn DataSource>,
}

impl PeFile {
    pub fn parse(source: Box<dyn DataSource>) -> Result<Self, ParseError> {
        let len = source.len().unwrap_or(0);
        if len < 64 {
            return Err(ParseError::TooSmall(len));
        }
        
        // Read the DOS header bytes directly into the struct.
        let mut dos_header = IMAGE_DOS_HEADER::default();
        source.read_struct(0, &mut dos_header).map_err(ParseError::DataSource)?;
        // DOS magic is "MZ" → 0x5A4D in little-endian u16
        if dos_header.e_magic != 0x5A4D {
            return Err(ParseError::InvalidMagic {
                expected: "MZ",
                found: format!("{:#06X}", dos_header.e_magic),
            });
        }
        let mut current_offset : usize = dos_header.e_lfanew as usize;
        


        Ok(Self {
            dos_header,
            data_source: source,
        })
    }

    pub fn get_data_source(&self) -> &dyn DataSource {
        self.data_source.as_ref()
    }

    pub fn get_image_dos_header(&self) -> & IMAGE_DOS_HEADER {
        &self.dos_header
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
    InvalidMagic { expected: &'static str, found: String },
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
                write!(f, "invalid DOS magic: expected \"{expected}\", got \"{found}\"")
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