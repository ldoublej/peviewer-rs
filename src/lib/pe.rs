use crate::data_source::{DataSource, DataSourceExt};

/// Represents a parsed Portable Executable file.
///
/// The `PeFile` **owns** the data source (`Box<dyn DataSource>`), so it can
/// lazily read more data as needed — the caller does not need to keep the
/// underlying bytes alive.
///
/// # Examples
///
/// ```
/// # use pe::pe::PeFile;
/// // From a Vec<u8> (data is moved in, no lifetime issues):
/// let pe = PeFile::from_vec(vec![
///     b'M', b'Z', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0,
/// ]).unwrap();
/// assert_eq!(pe.dos_magic(), [b'M', b'Z']);
/// assert_eq!(pe.e_lfanew(), 0x80);
/// ```
#[derive(Debug)]
pub struct PeFile {
    /// Owned data source — enables lazy reads for later parsing stages.
    data_source: Box<dyn DataSource>,
    /// The raw DOS header bytes (first 64 bytes of the image), eagerly parsed.
    dos_header: [u8; 64],
}

impl PeFile {
    /// Create a `PeFile` from an owned [`DataSource`].
    ///
    /// Parses and validates the DOS header immediately. The source is kept
    /// for subsequent lazy reads (section data, delayed directories, etc.).
    pub fn new(source: Box<dyn DataSource>) -> Result<Self, ParseError> {
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
            data_source: source,
            dos_header,
        })
    }

    /// Convenience: parse from a `Vec<u8>` directly (wraps it in a `Box`).
    pub fn from_vec(data: Vec<u8>) -> Result<Self, ParseError> {
        Self::new(Box::new(data))
    }

    // -- Accessors ---------------------------------------------------------

    /// Returns a reference to the underlying data source.
    ///
    /// Useful for downstream parsing code that needs to read headers
    /// beyond the DOS stub.
    pub fn data_source(&self) -> &dyn DataSource {
        &*self.data_source
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_dos_header() -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C] = 0x80; // e_lfanew = 0x80
        buf
    }

    #[test]
    fn from_vec() {
        let pe = PeFile::from_vec(valid_dos_header()).unwrap();
        assert_eq!(pe.dos_magic(), [b'M', b'Z']);
        assert_eq!(pe.e_lfanew(), 0x80);
    }

    #[test]
    fn new_with_boxed_vec() {
        let raw = valid_dos_header();
        let pe = PeFile::new(Box::new(raw)).unwrap(); // Box<Vec<u8>> → Box<dyn DataSource>
        assert_eq!(pe.dos_magic(), [b'M', b'Z']);
    }

    #[test]
    fn reject_too_small() {
        let err = PeFile::from_vec(vec![b'M', b'Z']).unwrap_err();
        assert!(matches!(err, ParseError::TooSmall(2)));
    }

    #[test]
    fn reject_bad_magic() {
        let err = PeFile::from_vec(vec![0u8; 64]).unwrap_err();
        assert!(matches!(err, ParseError::InvalidMagic { .. }));
    }

    #[test]
    fn source_accessor() {
        let pe = PeFile::from_vec(valid_dos_header()).unwrap();
        let src = pe.data_source();
        // verify we can read from the source through the trait
        assert_eq!(src.read_u16(0).unwrap(), 0x5A4D); // "MZ" in LE
    }
}
