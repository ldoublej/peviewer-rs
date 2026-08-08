use crate::data_source::DataSource;
use crate::data_source::DataSourceExt;
use crate::pe::ParseError;
use crate::pe_structs::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE};

/// A parsed DOS header. The underlying [`IMAGE_DOS_HEADER`] is
/// **encapsulated**: external callers obtain its fields through the
/// public accessor methods ([`DosHeader::e_lfanew`], [`DosHeader::magic`], ...).
#[derive(Debug)]
pub struct DosHeader {
    dos_header: IMAGE_DOS_HEADER,
}

impl DosHeader {
    /// Parse a DOS header from the start of `source`.
    pub fn parse<T: DataSource + ?Sized>(source: &T) -> Result<Self, ParseError> {
        let len = source.len().unwrap_or(0);
        if len < std::mem::size_of::<IMAGE_DOS_HEADER>() as u64 {
            return Err(ParseError::TooSmall(len));
        }

        let mut dos_header = IMAGE_DOS_HEADER::default();
        source
            .read_struct(0, &mut dos_header)
            .map_err(ParseError::DataSource)?;

        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(ParseError::InvalidMagic {
                expected: "MZ",
                found: format!("{:#06X}", dos_header.e_magic),
            });
        }

        Ok(Self { dos_header })
    }

    /// The file offset of the NT headers (`e_lfanew`).
    pub fn e_lfanew(&self) -> u32 {
        self.dos_header.e_lfanew
    }

    /// The DOS magic bytes (`e_magic`), expected to be `0x5A4D` ("MZ").
    pub fn magic(&self) -> u16 {
        self.dos_header.e_magic
    }

    pub fn e_cblp(&self) -> u16 {
        self.dos_header.e_cblp
    }
    pub fn e_cp(&self) -> u16 {
        self.dos_header.e_cp
    }
    pub fn e_crlc(&self) -> u16 {
        self.dos_header.e_crlc
    }
    pub fn e_cparhdr(&self) -> u16 {
        self.dos_header.e_cparhdr
    }
    pub fn e_minalloc(&self) -> u16 {
        self.dos_header.e_minalloc
    }
    pub fn e_maxalloc(&self) -> u16 {
        self.dos_header.e_maxalloc
    }
    pub fn e_ss(&self) -> u16 {
        self.dos_header.e_ss
    }
    pub fn e_sp(&self) -> u16 {
        self.dos_header.e_sp
    }
    pub fn e_csum(&self) -> u16 {
        self.dos_header.e_csum
    }
    pub fn e_ip(&self) -> u16 {
        self.dos_header.e_ip
    }
    pub fn e_cs(&self) -> u16 {
        self.dos_header.e_cs
    }
    pub fn e_lfarlc(&self) -> u16 {
        self.dos_header.e_lfarlc
    }
    pub fn e_ovno(&self) -> u16 {
        self.dos_header.e_ovno
    }
    pub fn e_oemid(&self) -> u16 {
        self.dos_header.e_oemid
    }
    pub fn e_oeminfo(&self) -> u16 {
        self.dos_header.e_oeminfo
    }
}
