use super::file_header::FileHeader;
use super::optional_header::OptionalHeader;
use crate::data_source::DataSource;
use crate::data_source::DataSourceExt;
use crate::pe::ParseError;
use crate::pe_structs::{
    IMAGE_FILE_HEADER, IMAGE_NT_HEADERS, IMAGE_NT_HEADERS_SIGNATURE, IMAGE_NT_HEADERS32,
    IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
};

/// A parsed NT headers block (signature + COFF file header + optional
/// header), with PE32 vs PE32+ dispatch kept entirely inside this type.
///
/// Use [`NtHeaders::parse`] to construct; raw `IMAGE_NT_HEADERS` is
/// unreachable from outside the wrapper module.
#[derive(Debug)]
pub struct NtHeaders {
    nt_headers: IMAGE_NT_HEADERS,
    /// `4 + 20 + FileHeader.SizeOfOptionalHeader` — the number of bytes
    /// the NT-headers block occupies on disk.
    nt_headers_size: u16,
    file_header: FileHeader,
    optional_header: OptionalHeader,
}

impl NtHeaders {
    /// Parse the NT-headers block starting at `offset`. Validates the
    /// `PE\0\0` signature and the optional-header magic, then dispatches
    /// to PE32 or PE32+.
    pub fn parse<T: DataSource + ?Sized>(source: &T, offset: u64) -> Result<Self, ParseError> {
        let min_size = std::mem::size_of::<u32>() + std::mem::size_of::<IMAGE_FILE_HEADER>();
        if source.len().unwrap_or(0) < offset + min_size as u64 {
            return Err(ParseError::TooSmall(source.len().unwrap_or(0)));
        }

        // Signature ---------------------------------------------------------
        let mut signature = [0u8; 4];
        source
            .read_exact(offset, &mut signature)
            .map_err(ParseError::DataSource)?;
        let signature_u32 = u32::from_le_bytes(signature);
        if signature_u32 != IMAGE_NT_HEADERS_SIGNATURE {
            return Err(ParseError::InvalidMagic {
                expected: "PE\\0\\0",
                found: format!("{signature_u32:#010X}"),
            });
        }

        // File header -------------------------------------------------------
        let file_header_off = offset + 4;
        let mut file_header = unsafe { std::mem::zeroed::<IMAGE_FILE_HEADER>() };
        let sz = source
            .read_struct(file_header_off, &mut file_header)
            .map_err(ParseError::DataSource)?;
        debug_assert_eq!(sz, std::mem::size_of::<IMAGE_FILE_HEADER>());

        // Optional header magic dispatch -----------------------------------
        let opt_header_off = file_header_off + sz as u64;
        let opt_magic = source
            .read_u16(opt_header_off)
            .map_err(ParseError::DataSource)?;

        let (nt_headers, optional_header) = match opt_magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                let mut h32: IMAGE_NT_HEADERS32 = unsafe { std::mem::zeroed() };
                source
                    .read_struct(offset, &mut h32)
                    .map_err(ParseError::DataSource)?;
                (
                    IMAGE_NT_HEADERS::PE32(h32),
                    OptionalHeader::pe32(h32.OptionalHeader),
                )
            }
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                let mut h64: IMAGE_NT_HEADERS64 = unsafe { std::mem::zeroed() };
                source
                    .read_struct(offset, &mut h64)
                    .map_err(ParseError::DataSource)?;
                (
                    IMAGE_NT_HEADERS::PE32P(h64),
                    OptionalHeader::pe32_plus(h64.OptionalHeader),
                )
            }
            _ => {
                return Err(ParseError::InvalidMagic {
                    expected: "0x10b or 0x20b or 0x107",
                    found: format!("{opt_magic:#06X}"),
                });
            }
        };

        let nt_headers_size = (4
            + std::mem::size_of::<IMAGE_FILE_HEADER>()
            + file_header.SizeOfOptionalHeader as usize) as u16;

        Ok(Self {
            nt_headers,
            nt_headers_size,
            file_header: FileHeader::new(file_header),
            optional_header,
        })
    }

    /// NT signature (always `0x00004550` after a successful parse).
    pub fn signature(&self) -> u32 {
        match &self.nt_headers {
            IMAGE_NT_HEADERS::PE32(h) => h.Signature,
            IMAGE_NT_HEADERS::PE32P(h) => h.Signature,
        }
    }

    /// Total size in bytes of the NT-headers block (signature + file
    /// header + optional header). Used to compute the offset of the
    /// first section header.
    pub fn total_size(&self) -> u64 {
        u64::from(self.nt_headers_size)
    }

    pub fn file_header(&self) -> &FileHeader {
        &self.file_header
    }

    pub fn optional_header(&self) -> &OptionalHeader {
        &self.optional_header
    }
}
