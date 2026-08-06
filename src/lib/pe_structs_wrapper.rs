use crate::data_source::DataSourceExt;
use crate::pe::ParseError;
use crate::pe_structs::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_FILE_HEADER, IMAGE_NT_HEADERS,
    IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS_SIGNATURE, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64,
    IMAGE_SECTION_HEADER,
};


// ---------------------------------------------------------------------------
// ImageBase
// ---------------------------------------------------------------------------

/// A 32-bit or 64-bit unsigned address / size value, depending on the
/// PE kind. Used for fields like `ImageBase`, `SizeOfStackReserve`, ...
/// whose bit width is fixed by whether the image is PE32 or PE32+.
#[derive(Clone, Copy, Debug)]
pub enum ImageBase {
    U32(u32),
    U64(u64),
}

impl ImageBase {
    /// Zero-extend the value to `u64`.
    pub fn as_u64(&self) -> u64 {
        match self {
            ImageBase::U32(v) => u64::from(*v),
            ImageBase::U64(v) => *v,
        }
    }

    /// Format as `0x...` (16 hex digits, zero-padded).
    pub fn to_hex_string(&self) -> String {
        format!("{:#018X}", self.as_u64())
    }
}


// ---------------------------------------------------------------------------
// FileHeader
// ---------------------------------------------------------------------------

/// The COFF file header. Layout is identical for PE32 and PE32+.
#[derive(Debug)]
pub struct FileHeader {
    file_header: IMAGE_FILE_HEADER,
}

impl FileHeader {
    pub(crate) fn new(file_header: IMAGE_FILE_HEADER) -> Self {
        Self { file_header }
    }

    pub fn machine(&self) -> u16 {
        self.file_header.Machine
    }
    pub fn number_of_sections(&self) -> u16 {
        self.file_header.NumberOfSections
    }
    pub fn time_date_stamp(&self) -> u32 {
        self.file_header.TimeDateStamp
    }
    pub fn pointer_to_symbol_table(&self) -> u32 {
        self.file_header.PointerToSymbolTable
    }
    pub fn number_of_symbols(&self) -> u32 {
        self.file_header.NumberOfSymbols
    }
    pub fn size_of_optional_header(&self) -> u16 {
        self.file_header.SizeOfOptionalHeader
    }
    pub fn characteristics(&self) -> u16 {
        self.file_header.Characteristics
    }
}


// ---------------------------------------------------------------------------
// OptionalHeader
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub(crate) enum OptionalHeaderInner {
    Pe32(IMAGE_OPTIONAL_HEADER32),
    Pe32Plus(IMAGE_OPTIONAL_HEADER64),
}

/// The PE optional header. The PE32 (32-bit) and PE32+ (64-bit) variants
/// share 19 fields and differ on 5; this type exposes a single, uniform
/// accessor per field. Fields that exist only in PE32 return `None` from
/// the corresponding accessor; fields whose bit width varies return an
/// [`ImageBase`].
#[derive(Debug)]
pub struct OptionalHeader {
    inner: OptionalHeaderInner,
}

impl OptionalHeader {
    pub(crate) fn pe32(h: IMAGE_OPTIONAL_HEADER32) -> Self {
        Self {
            inner: OptionalHeaderInner::Pe32(h),
        }
    }

    pub(crate) fn pe32_plus(h: IMAGE_OPTIONAL_HEADER64) -> Self {
        Self {
            inner: OptionalHeaderInner::Pe32Plus(h),
        }
    }

    pub fn is_pe32_plus(&self) -> bool {
        matches!(self.inner, OptionalHeaderInner::Pe32Plus(_))
    }

    /// `0x10b` for PE32, `0x20b` for PE32+ (`0x107` for ROM is currently
    /// rejected by [`NtHeaders::parse`]).
    pub fn magic(&self) -> u16 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.Magic,
            OptionalHeaderInner::Pe32Plus(h) => h.Magic,
        }
    }

    // 19 common fields -------------------------------------------------

    pub fn linker_version(&self) -> (u8, u8) {
        let v = match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.LinkerVersion,
            OptionalHeaderInner::Pe32Plus(h) => h.LinkerVersion,
        };
        (v.Major, v.Minor)
    }

    pub fn size_of_code(&self) -> u32 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.SizeOfCode,
            OptionalHeaderInner::Pe32Plus(h) => h.SizeOfCode,
        }
    }
    pub fn size_of_initialized_data(&self) -> u32 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.SizeOfInitializedData,
            OptionalHeaderInner::Pe32Plus(h) => h.SizeOfInitializedData,
        }
    }
    pub fn size_of_uninitialized_data(&self) -> u32 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.SizeOfUninitializedData,
            OptionalHeaderInner::Pe32Plus(h) => h.SizeOfUninitializedData,
        }
    }
    pub fn address_of_entry_point(&self) -> u32 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.AddressOfEntryPoint,
            OptionalHeaderInner::Pe32Plus(h) => h.AddressOfEntryPoint,
        }
    }
    pub fn base_of_code(&self) -> u32 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.BaseOfCode,
            OptionalHeaderInner::Pe32Plus(h) => h.BaseOfCode,
        }
    }
    pub fn section_alignment(&self) -> u32 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.SectionAlignment,
            OptionalHeaderInner::Pe32Plus(h) => h.SectionAlignment,
        }
    }
    pub fn file_alignment(&self) -> u32 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.FileAlignment,
            OptionalHeaderInner::Pe32Plus(h) => h.FileAlignment,
        }
    }

    pub fn operating_system_version(&self) -> (u16, u16) {
        let v = match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.OperatingSystemVersion,
            OptionalHeaderInner::Pe32Plus(h) => h.OperatingSystemVersion,
        };
        (v.Major, v.Minor)
    }
    pub fn image_version(&self) -> (u16, u16) {
        let v = match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.ImageVersion,
            OptionalHeaderInner::Pe32Plus(h) => h.ImageVersion,
        };
        (v.Major, v.Minor)
    }
    pub fn subsystem_version(&self) -> (u16, u16) {
        let v = match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.SubsystemVersion,
            OptionalHeaderInner::Pe32Plus(h) => h.SubsystemVersion,
        };
        (v.Major, v.Minor)
    }

    pub fn win32_version_value(&self) -> u32 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.Win32VersionValue,
            OptionalHeaderInner::Pe32Plus(h) => h.Win32VersionValue,
        }
    }
    pub fn size_of_image(&self) -> u32 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.SizeOfImage,
            OptionalHeaderInner::Pe32Plus(h) => h.SizeOfImage,
        }
    }
    pub fn size_of_headers(&self) -> u32 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.SizeOfHeaders,
            OptionalHeaderInner::Pe32Plus(h) => h.SizeOfHeaders,
        }
    }
    pub fn check_sum(&self) -> u32 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.CheckSum,
            OptionalHeaderInner::Pe32Plus(h) => h.CheckSum,
        }
    }
    pub fn subsystem(&self) -> u16 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.Subsystem,
            OptionalHeaderInner::Pe32Plus(h) => h.Subsystem,
        }
    }
    pub fn dll_characteristics(&self) -> u16 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.DllCharacteristics,
            OptionalHeaderInner::Pe32Plus(h) => h.DllCharacteristics,
        }
    }
    pub fn loader_flags(&self) -> u32 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.LoaderFlags,
            OptionalHeaderInner::Pe32Plus(h) => h.LoaderFlags,
        }
    }
    pub fn number_of_rva_and_sizes(&self) -> u32 {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.NumberOfRvaAndSizes,
            OptionalHeaderInner::Pe32Plus(h) => h.NumberOfRvaAndSizes,
        }
    }

    // 5 differing fields -----------------------------------------------

    /// PE32 only; returns `None` for PE32+.
    pub fn base_of_data(&self) -> Option<u32> {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => Some(h.BaseOfData),
            OptionalHeaderInner::Pe32Plus(_) => None,
        }
    }

    pub fn image_base(&self) -> ImageBase {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => ImageBase::U32(h.ImageBase),
            OptionalHeaderInner::Pe32Plus(h) => ImageBase::U64(h.ImageBase),
        }
    }
    pub fn size_of_stack_reserve(&self) -> ImageBase {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => ImageBase::U32(h.SizeOfStackReserve),
            OptionalHeaderInner::Pe32Plus(h) => ImageBase::U64(h.SizeOfStackReserve),
        }
    }
    pub fn size_of_stack_commit(&self) -> ImageBase {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => ImageBase::U32(h.SizeOfStackCommit),
            OptionalHeaderInner::Pe32Plus(h) => ImageBase::U64(h.SizeOfStackCommit),
        }
    }
    pub fn size_of_heap_reserve(&self) -> ImageBase {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => ImageBase::U32(h.SizeOfHeapReserve),
            OptionalHeaderInner::Pe32Plus(h) => ImageBase::U64(h.SizeOfHeapReserve),
        }
    }
    pub fn size_of_heap_commit(&self) -> ImageBase {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => ImageBase::U32(h.SizeOfHeapCommit),
            OptionalHeaderInner::Pe32Plus(h) => ImageBase::U64(h.SizeOfHeapCommit),
        }
    }
}


// ---------------------------------------------------------------------------
// NtHeaders
// ---------------------------------------------------------------------------

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
    _headers_data: Option<Vec<u8>>,
}

impl NtHeaders {
    /// Parse the NT-headers block starting at `offset`. Validates the
    /// `PE\0\0` signature and the optional-header magic, then dispatches
    /// to PE32 or PE32+.
    pub fn parse<T: DataSourceExt + ?Sized>(
        source: &T,
        offset: u64,
    ) -> Result<Self, ParseError> {
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

        let nt_headers_size =
            (4 + std::mem::size_of::<IMAGE_FILE_HEADER>() + file_header.SizeOfOptionalHeader as usize)
                as u16;

        Ok(Self {
            nt_headers,
            nt_headers_size,
            file_header: FileHeader::new(file_header),
            optional_header,
            _headers_data: None,
        })
    }

    /// NT signature (always `0x00004550` after a successful parse).
    pub fn signature(&self) -> u32 {
        match &self.nt_headers {
            IMAGE_NT_HEADERS::PE32(h) => h.Signature,
            IMAGE_NT_HEADERS::PE32P(h) => h.Signature,
        }
    }

    /// `true` iff the optional header is PE32+ (64-bit).
    pub fn is_pe32_plus(&self) -> bool {
        self.optional_header.is_pe32_plus()
    }

    /// Number of section headers that follow this block.
    pub fn number_of_sections(&self) -> u16 {
        self.file_header.number_of_sections()
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


// ---------------------------------------------------------------------------
// DosHeader
// ---------------------------------------------------------------------------

/// A parsed DOS header plus, optionally, the DOS stub bytes that follow it.
///
/// The underlying [`IMAGE_DOS_HEADER`] is **encapsulated**: external callers
/// obtain its fields through the public accessor methods
/// ([`DosHeader::pe_offset`], [`DosHeader::magic`], ...).
#[derive(Debug)]
pub struct DosHeader {
    dos_header: IMAGE_DOS_HEADER,
    _dos_stub: Option<Vec<u8>>,
}

impl DosHeader {
    /// Parse a DOS header from the start of `source`.
    pub fn parse<T: DataSourceExt + ?Sized>(source: &T) -> Result<Self, ParseError> {
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

        Ok(Self {
            dos_header,
            _dos_stub: None,
        })
    }

    /// The file offset of the NT headers (`e_lfanew`).
    pub fn pe_offset(&self) -> u32 {
        self.dos_header.e_lfanew
    }

    /// The DOS magic bytes (`e_magic`), expected to be `0x5A4D` ("MZ").
    pub fn magic(&self) -> u16 {
        self.dos_header.e_magic
    }

    pub fn e_cblp(&self) -> u16 { self.dos_header.e_cblp }
    pub fn e_cp(&self) -> u16 { self.dos_header.e_cp }
    pub fn e_crlc(&self) -> u16 { self.dos_header.e_crlc }
    pub fn e_cparhdr(&self) -> u16 { self.dos_header.e_cparhdr }
    pub fn e_minalloc(&self) -> u16 { self.dos_header.e_minalloc }
    pub fn e_maxalloc(&self) -> u16 { self.dos_header.e_maxalloc }
    pub fn e_ss(&self) -> u16 { self.dos_header.e_ss }
    pub fn e_sp(&self) -> u16 { self.dos_header.e_sp }
    pub fn e_csum(&self) -> u16 { self.dos_header.e_csum }
    pub fn e_ip(&self) -> u16 { self.dos_header.e_ip }
    pub fn e_cs(&self) -> u16 { self.dos_header.e_cs }
    pub fn e_lfarlc(&self) -> u16 { self.dos_header.e_lfarlc }
    pub fn e_ovno(&self) -> u16 { self.dos_header.e_ovno }
    pub fn e_oemid(&self) -> u16 { self.dos_header.e_oemid }
    pub fn e_oeminfo(&self) -> u16 { self.dos_header.e_oeminfo }
}


// ---------------------------------------------------------------------------
// Section
// ---------------------------------------------------------------------------

/// A parsed section header plus, optionally, the section's bytes.
#[derive(Debug)]
pub struct Section {
    section_header: IMAGE_SECTION_HEADER,
    _section_data: Option<Vec<u8>>,
}

impl Section {
    /// Read one `IMAGE_SECTION_HEADER` at `offset`. Returns the section
    /// plus the number of bytes consumed (always
    /// `size_of::<IMAGE_SECTION_HEADER>()`).
    pub fn parse<T: DataSourceExt + ?Sized>(
        source: &T,
        offset: u64,
    ) -> Result<(Self, usize), ParseError> {
        let size = std::mem::size_of::<IMAGE_SECTION_HEADER>();
        if source.len().unwrap_or(0) < offset + size as u64 {
            return Err(ParseError::TooSmall(source.len().unwrap_or(0)));
        }

        let mut section_header = unsafe { std::mem::zeroed::<IMAGE_SECTION_HEADER>() };
        let sz = source
            .read_struct(offset, &mut section_header)
            .map_err(ParseError::DataSource)?;
        debug_assert_eq!(sz, size);

        Ok((
            Self {
                section_header,
                _section_data: None,
            },
            sz,
        ))
    }

    /// 8-byte ASCII name, NUL-trimmed.
    pub fn name(&self) -> String {
        let raw = &self.section_header.Name;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    }

    pub fn virtual_address(&self) -> u32 {
        self.section_header.VirtualAddress
    }
    pub fn virtual_size(&self) -> u32 {
        self.section_header.VirtualSize
    }
    pub fn raw_size(&self) -> u32 {
        self.section_header.SizeOfRawData
    }
    pub fn raw_offset(&self) -> u32 {
        self.section_header.PointerToRawData
    }
    pub fn pointer_to_relocations(&self) -> u32 {
        self.section_header.PointerToRelocations
    }
    pub fn pointer_to_linenumbers(&self) -> u32 {
        self.section_header.PointerToLinenumbers
    }
    pub fn number_of_relocations(&self) -> u16 {
        self.section_header.NumberOfRelocations
    }
    pub fn number_of_linenumbers(&self) -> u16 {
        self.section_header.NumberOfLinenumbers
    }
    pub fn characteristics(&self) -> u32 {
        self.section_header.Characteristics
    }
}
