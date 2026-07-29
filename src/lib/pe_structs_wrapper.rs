use crate::pe_structs::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER};
use std::ops::Deref;

/// A parsed section: the raw [`IMAGE_SECTION_HEADER`] plus derived data
/// (a decoded name, the section's bytes).
///
/// All of the underlying header fields (`VirtualAddress`, `SizeOfRawData`,
/// `Characteristics`, ...) are available directly on a `Section` via [`Deref`],
/// so there is no need to re-declare them here.
#[derive(Debug)]
pub struct Section {
    section_header: IMAGE_SECTION_HEADER,
    _section_data: Option<Vec<u8>>,
}

impl Section {
    pub fn new(image_section_header: IMAGE_SECTION_HEADER, section_data: Option<Vec<u8>>) -> Self {
        Self {
            section_header: image_section_header,
            _section_data: section_data,
        }
    }
}

impl Deref for Section {
    type Target = IMAGE_SECTION_HEADER;

    fn deref(&self) -> &Self::Target {
        &self.section_header
    }
}

/// A parsed DOS header: the raw [`IMAGE_DOS_HEADER`] plus, optionally, the
/// DOS stub bytes that follow it.
///
/// All of the underlying header fields (`e_magic`, `e_lfanew`, ...) are
/// available directly on a `DosHeader` via [`Deref`].
#[derive(Debug)]
pub struct DosHeader {
    dos_header: IMAGE_DOS_HEADER,
    _dos_stub: Option<Vec<u8>>,
}

impl DosHeader {
    pub fn new(image_dos_header: IMAGE_DOS_HEADER, dos_stub: Option<Vec<u8>>) -> Self {
        Self {
            dos_header: image_dos_header,
            _dos_stub: dos_stub,
        }
    }
}

impl Deref for DosHeader {
    type Target = IMAGE_DOS_HEADER;

    fn deref(&self) -> &Self::Target {
        &self.dos_header
    }
}

/// A parsed NT headers block: the raw [`IMAGE_NT_HEADERS`] enum (PE32 or
/// PE32+) plus, optionally, the bytes it was read from.
///
/// `NtHeaders` [`Deref`]s to the [`IMAGE_NT_HEADERS`] enum, so callers still
/// match on `PE32` / `PE32P` to reach the file and optional headers.
#[derive(Debug)]
pub struct NtHeaders {
    nt_headers: IMAGE_NT_HEADERS,
    _headers_data: Option<Vec<u8>>,
}

impl NtHeaders {
    pub fn new(image_nt_headers: IMAGE_NT_HEADERS, headers_data: Option<Vec<u8>>) -> Self {
        Self {
            nt_headers: image_nt_headers,
            _headers_data: headers_data,
        }
    }
}

impl Deref for NtHeaders {
    type Target = IMAGE_NT_HEADERS;

    fn deref(&self) -> &Self::Target {
        &self.nt_headers
    }
}
