use crate::data_source::{DataSource, DataSourceError};
use std::fs::File;
use std::path::{Path, PathBuf};

// Platform-specific positioned read (like pread on Unix).
#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

/// A [`DataSource`] backed by a real file on disk.
///
/// Uses positioned I/O (`pread`-equivalent) so reads do **not** modify
/// the kernel-side file offset — safe to share across threads.
#[derive(Debug)]
pub struct FileDataSource {
    path: PathBuf,
    file: File,
}

impl FileDataSource {
    /// Open a file for reading as a data source.
    ///
    /// Returns [`DataSourceError::FileNotFound`] if the path does not exist.
    pub fn open_file(path: &Path) -> Result<Box<Self>, DataSourceError> {
        if !path.exists() {
            return Err(DataSourceError::FileNotFound {
                path: path.to_path_buf(),
            });
        }

        let file = std::fs::File::open(path)?;
        Ok(Box::new(Self {
            path: path.to_path_buf(),
            file,
        }))
    }
}

// ---------------------------------------------------------------------------
// DataSource implementation
// ---------------------------------------------------------------------------

impl DataSource for FileDataSource {
    fn len(&self) -> Option<u64> {
        self.file.metadata().ok().map(|m| m.len())
    }

    fn is_file_aligned(&self) -> bool {
        true
    }

    fn image_base(&self) -> u64 {
        0
    }

    fn read_exact(&self, offset: u64, buf: &mut [u8]) -> Result<usize, DataSourceError> {
        let mut cursor = 0usize;

        while cursor < buf.len() {
            let n = self.read_at(&mut buf[cursor..], offset + cursor as u64)?;

            if n == 0 {
                // Premature EOF
                return Err(DataSourceError::OutOfBounds {
                    offset: offset + cursor as u64,
                    length: buf.len() - cursor,
                    source_len: self.len(),
                });
            }

            cursor += n;
        }

        Ok(cursor)
    }

    fn url(&self) -> String {
        self.path.to_string_lossy().to_string()
    }
}

// ---------------------------------------------------------------------------
// Positioned read — cross-platform abstraction
// ---------------------------------------------------------------------------

#[cfg(unix)]
impl FileDataSource {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        self.file.read_at(buf, offset)
    }
}

#[cfg(windows)]
impl FileDataSource {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        self.file.seek_read(buf, offset)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Create a temp file with the given data.  Returns `(TempDir, PathBuf)`
    /// — the `TempDir` is kept alive until the caller drops it.
    fn temp_file_with(data: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pe");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(data).unwrap();
        (dir, path)
    }

    #[test]
    fn open_and_read() {
        let raw = b"MZ\x00\x00\x00\x00\x00\x00"; // 8 bytes
        let (_dir, path) = temp_file_with(raw);
        let ds = FileDataSource::open_file(&path).unwrap();
        assert_eq!(ds.len(), Some(8));

        let mut buf = [0u8; 2];
        ds.read_exact(0, &mut buf).unwrap();
        assert_eq!(buf, [b'M', b'Z']);
    }

    #[test]
    fn file_not_found() {
        let err = FileDataSource::open_file(Path::new("/nonexistent/foo.exe")).unwrap_err();
        assert!(matches!(err, DataSourceError::FileNotFound { .. }));
    }

    #[test]
    fn out_of_bounds() {
        let (_dir, path) = temp_file_with(b"1234");
        let ds = FileDataSource::open_file(&path).unwrap();
        let mut buf = [0u8; 8];
        let err = ds.read_exact(0, &mut buf).unwrap_err();
        assert!(matches!(err, DataSourceError::OutOfBounds { .. }));
    }

    #[test]
    fn read_at_offset() {
        let (_dir, path) = temp_file_with(b"ABCDEFGH");
        let ds = FileDataSource::open_file(&path).unwrap();
        let mut buf = [0u8; 4];
        ds.read_exact(4, &mut buf).unwrap();
        assert_eq!(buf, [b'E', b'F', b'G', b'H']);
    }
}
