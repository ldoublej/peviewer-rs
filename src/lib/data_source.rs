use std::fmt::Debug;
use std::path::PathBuf;

mod file_data_source;
pub use file_data_source::FileDataSource;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during data source operations.
#[derive(Debug)]
pub enum DataSourceError {
    /// The requested read extends beyond the data source boundary.
    OutOfBounds {
        offset: u64,
        length: usize,
        source_len: Option<u64>,
    },
    /// The file was not found at the given path.
    FileNotFound {
        path: PathBuf,
    },
    /// An underlying I/O error occurred.
    Io(std::io::Error),
}

impl PartialEq for DataSourceError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::OutOfBounds { offset: a, length: b, source_len: c },
             Self::OutOfBounds { offset: d, length: e, source_len: f }) => a == d && b == e && c == f,
            (Self::FileNotFound { path: a }, Self::FileNotFound { path: b }) => a == b,
            (Self::Io(a), Self::Io(b)) => a.kind() == b.kind(),
            _ => false,
        }
    }
}

impl Eq for DataSourceError {}

impl std::fmt::Display for DataSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataSourceError::OutOfBounds {
                offset,
                length,
                source_len,
            } => {
                write!(f, "read out of bounds: offset={offset}, length={length}")?;
                if let Some(len) = source_len {
                    write!(f, ", source_len={len}")?;
                }
                Ok(())
            }
            DataSourceError::FileNotFound { path } => {
                write!(f, "file not found: {}", path.display())
            }
            DataSourceError::Io(e) => {
                write!(f, "I/O error: {e}")
            }
        }
    }
}

impl std::error::Error for DataSourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DataSourceError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DataSourceError {
    fn from(e: std::io::Error) -> Self {
        DataSourceError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Core trait
// ---------------------------------------------------------------------------

/// A read-only, random-access data source.
///
/// This is the only interface the PE parser uses to obtain raw bytes.
/// It does **not** care where the data comes from — a memory buffer, a
/// memory-mapped file, a decompressed stream, or a remote download.
///
/// # Requirements
///
/// - **Random-access**: `read_exact` is offset-based, not sequential.
/// - **Thread-safe**: `Send + Sync` so the source can be shared across
///   parsing stages (e.g. for section-level parallel reads).
/// - **Immutable reading**: `&self` — reads do not mutate internal state.
///
/// # Implementing
///
/// The simplest implementation is to wrap `&[u8]` (provided via a blanket
/// helper; see the `impl` section below).  For a file-backed source,
/// consider memory-mapping (`memmap2` crate) to get a `&[u8]`, then use
/// that implementation — it is zero-copy and fast.
pub trait DataSource: Debug + Send + Sync {
    /// Total length of the data, if known.
    ///
    /// Returns `None` for streaming sources whose size cannot be determined
    /// in advance.  Most PE sources (files, memory buffers) return `Some`.
    fn len(&self) -> Option<u64>;

    /// Returns `true` if the source is known to be empty.
    fn is_empty(&self) -> bool {
        self.len().map_or(false, |l| l == 0)
    }

    /// Read exactly `buf.len()` bytes starting at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`DataSourceError::OutOfBounds`] if the requested range
    /// `[offset, offset + buf.len())` is not fully contained in the source.
    fn read_exact(&self, offset: u64, buf: &mut [u8]) -> Result<(), DataSourceError>;
}

// ---------------------------------------------------------------------------
// Extension trait  –  higher-level readers built on read_exact
// ---------------------------------------------------------------------------

/// Convenience methods for reading typed values from a [`DataSource`].
///
/// Automatically implemented for every `T: DataSource`.
pub trait DataSourceExt: DataSource {
    /// Read a `u16` in little-endian byte order.
    fn read_u16(&self, offset: u64) -> Result<u16, DataSourceError> {
        let mut buf = [0u8; 2];
        self.read_exact(offset, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    /// Read a `u32` in little-endian byte order.
    fn read_u32(&self, offset: u64) -> Result<u32, DataSourceError> {
        let mut buf = [0u8; 4];
        self.read_exact(offset, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Read a `u64` in little-endian byte order.
    fn read_u64(&self, offset: u64) -> Result<u64, DataSourceError> {
        let mut buf = [0u8; 8];
        self.read_exact(offset, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Read `length` bytes starting at `offset` into a fresh `Vec<u8>`.
    fn read_bytes(&self, offset: u64, length: usize) -> Result<Vec<u8>, DataSourceError> {
        let mut buf = vec![0u8; length];
        self.read_exact(offset, &mut buf)?;
        Ok(buf)
    }

    /// Read a fixed-size byte array.
    fn read_array<const N: usize>(&self, offset: u64) -> Result<[u8; N], DataSourceError> {
        let mut buf = [0u8; N];
        self.read_exact(offset, &mut buf)?;
        Ok(buf)
    }

    /// Read a fixed-length (possibly null-terminated) ASCII string.
    ///
    /// The reader reads `max_len` bytes and trims at the first `NUL`.
    /// Non-ASCII bytes are replaced with `U+FFFD` via `String::from_utf8_lossy`.
    fn read_ascii(&self, offset: u64, max_len: usize) -> Result<String, DataSourceError> {
        let raw = self.read_bytes(offset, max_len)?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        Ok(String::from_utf8_lossy(&raw[..end]).into_owned())
    }

    /// Read a null-terminated UTF-16LE string.
    ///
    /// `max_code_units` is the maximum number of `u16` code units to read
    /// (the underlying byte count is `max_code_units * 2`).  Parsing stops
    /// at the first `NUL` code unit.
    fn read_utf16(&self, offset: u64, max_code_units: usize) -> Result<String, DataSourceError> {
        let raw = self.read_bytes(offset, max_code_units * 2)?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }

    // -- "checked" variants that return Option instead of Result -----------

    fn checked_read_u16(&self, offset: u64) -> Option<u16> {
        self.read_u16(offset).ok()
    }

    fn checked_read_u32(&self, offset: u64) -> Option<u32> {
        self.read_u32(offset).ok()
    }

    fn checked_read_u64(&self, offset: u64) -> Option<u64> {
        self.read_u64(offset).ok()
    }

    fn checked_read_bytes(&self, offset: u64, length: usize) -> Option<Vec<u8>> {
        self.read_bytes(offset, length).ok()
    }
}

// Blanket implementation: every DataSource also gets DataSourceExt.
impl<T: DataSource + ?Sized> DataSourceExt for T {}

// ---------------------------------------------------------------------------
// Built-in implementations
// ---------------------------------------------------------------------------

/// Helper: shared read_exact logic for contiguous byte buffers.
fn slice_read_exact(data: &[u8], offset: u64, buf: &mut [u8]) -> Result<(), DataSourceError> {
    let start = offset as usize;
    let end = start.checked_add(buf.len()).ok_or_else(|| DataSourceError::OutOfBounds {
        offset,
        length: buf.len(),
        source_len: Some(data.len() as u64),
    })?;

    if end > data.len() {
        return Err(DataSourceError::OutOfBounds {
            offset,
            length: buf.len(),
            source_len: Some(data.len() as u64),
        });
    }

    buf.copy_from_slice(&data[start..end]);
    Ok(())
}

impl DataSource for Vec<u8> {
    fn len(&self) -> Option<u64> {
        Some(self.as_slice().len() as u64)
    }

    fn read_exact(&self, offset: u64, buf: &mut [u8]) -> Result<(), DataSourceError> {
        slice_read_exact(self.as_slice(), offset, buf)
    }
}

// -- [u8] -------------------------------------------------------------------
//
// Note: `[u8]` is `!Sized`, but that is fine — `&[u8]` will auto-coerce to
// `&dyn DataSource` because the receiver of all methods is `&self`.

impl DataSource for [u8] {
    fn len(&self) -> Option<u64> {
        Some(self.len() as u64)
    }

    fn read_exact(&self, offset: u64, buf: &mut [u8]) -> Result<(), DataSourceError> {
        slice_read_exact(self, offset, buf)
    }
}

/// `&[u8]` is a common data source — zero-copy, zero-cost.
impl DataSource for &[u8] {
    fn len(&self) -> Option<u64> {
        Some((*self).len() as u64)
    }

    fn read_exact(&self, offset: u64, buf: &mut [u8]) -> Result<(), DataSourceError> {
        slice_read_exact(self, offset, buf)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_u32_from_slice() {
        let data = 0xDEAD_BEEFu32.to_le_bytes();
        let src: &[u8] = &data;
        assert_eq!(src.read_u32(0).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn out_of_bounds() {
        let src: &[u8] = &[1, 2, 3];
        let err = src.read_u32(0).unwrap_err();
        assert!(matches!(err, DataSourceError::OutOfBounds { .. }));
    }

    #[test]
    fn read_ascii_with_nul() {
        let raw = b"PE\0\0";
        let src: &[u8] = raw;
        assert_eq!(src.read_ascii(0, 4).unwrap(), "PE");
    }

    #[test]
    fn read_utf16_le() {
        let raw: &[u8] = &[0x50, 0x00, 0x45, 0x00, 0x00, 0x00];
        assert_eq!(raw.read_utf16(0, 3).unwrap(), "PE");
    }

    #[test]
    fn vec_u8_impl() {
        let data = vec![0x34, 0x12, 0x00, 0x00];
        assert_eq!(data.read_u16(0).unwrap(), 0x1234);
    }

    #[test]
    fn file_not_found_error() {
        let err = DataSourceError::FileNotFound {
            path: PathBuf::from("foo.exe"),
        };
        assert_eq!(err.to_string(), "file not found: foo.exe");
    }
}