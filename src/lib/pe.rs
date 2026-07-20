use crate::data_source::{DataSource, DataSourceExt};


#[derive(Debug)]
pub struct PeFile<'a> {
    dos_header: [u8; 64],
    _data_source: &'a dyn DataSource,
}

impl<'a> PeFile<'a> {
    pub fn parse<T: DataSource>(source: &'a T) -> Result<Self, ParseError> {
        let len = source.len().unwrap_or(0);
        if len < 64 {
            return Err(ParseError::TooSmall(len));
        }

        let dos_header: [u8; 64] = source
            .read_array(0)
            .map_err(ParseError::DataSource)?;

        if dos_header[0] != b'M' || dos_header[1] != b'Z' {
            return Err(ParseError::InvalidMagic {
                expected: "MZ",
                found: format!("{}{}", dos_header[0] as char, dos_header[1] as char),
            });
        }

        Ok(Self {
            dos_header,
            _data_source: source,
        })
    }


    /// Returns the DOS signature bytes ("MZ" at offset 0).
    pub fn dos_magic(&self) -> [u8; 2] {
        [self.dos_header[0], self.dos_header[1]]
    }

    /// Returns the file offset of the PE signature (`e_lfanew`, at offset 0x3C).
    pub fn e_lfanew(&self) -> u32 {
        u32::from_le_bytes([
            self.dos_header[0x3C],
            self.dos_header[0x3D],
            self.dos_header[0x3E],
            self.dos_header[0x3F],
        ])
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