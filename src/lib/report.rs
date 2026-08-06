//! Presentation-agnostic report data for a parsed PE image.
//!
//! The library turns raw PE structures into simple, already-formatted rows
//! ([`Field`] for key/value views, `Vec<String>` for multi-column tables).
//! It deliberately depends on nothing but `std` — the CLI (or any other
//! frontend) is responsible for rendering these rows however it likes
//! (a table, JSON, plain text, ...).

use crate::pe_structs::{
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, IMAGE_DLLCHARACTERISTICS_GUARD_CF,
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
    IMAGE_DLLCHARACTERISTICS_NO_BIND, IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
    IMAGE_DLLCHARACTERISTICS_NO_SEH, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, IMAGE_FILE_32BIT_MACHINE,
    IMAGE_FILE_AGGRESIVE_WS_TRIM, IMAGE_FILE_BYTES_REVERSED_HI, IMAGE_FILE_BYTES_REVERSED_LO,
    IMAGE_FILE_DEBUG_STRIPPED, IMAGE_FILE_DLL, IMAGE_FILE_EXECUTABLE_IMAGE,
    IMAGE_FILE_LARGE_ADDRESS_AWARE, IMAGE_FILE_LINE_NUMS_STRIPPED,
    IMAGE_FILE_LOCAL_SYMS_STRIPPED, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_MACHINE_IA64, IMAGE_FILE_NET_RUN_FROM_SWAP, IMAGE_FILE_RELOCS_STRIPPED,
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, IMAGE_FILE_SYSTEM, IMAGE_FILE_UP_SYSTEM_ONLY,
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA,
    IMAGE_SCN_GPREL, IMAGE_SCN_LNK_COMDAT, IMAGE_SCN_LNK_INFO, IMAGE_SCN_LNK_NRELOC_OVFL,
    IMAGE_SCN_LNK_REMOVE, IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_NOT_CACHED,
    IMAGE_SCN_MEM_NOT_PAGED, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_SHARED, IMAGE_SCN_MEM_WRITE,
    IMAGE_SUBSYSTEM_EFI_APPLICATION, IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
    IMAGE_SUBSYSTEM_EFI_ROM, IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER, IMAGE_SUBSYSTEM_NATIVE,
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS, IMAGE_SUBSYSTEM_OS2_CUI, IMAGE_SUBSYSTEM_POSIX_CUI,
    IMAGE_SUBSYSTEM_UNKNOWN, IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI, IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_SUBSYSTEM_WINDOWS_GUI,
    IMAGE_SUBSYSTEM_XBOX,
};
use crate::pe_structs_wrapper::{DosHeader, FileHeader, OptionalHeader, Section};

/// A single labelled row in a key/value view.
#[derive(Clone, Debug)]
pub struct Field {
    /// Field name, e.g. `"Machine"`.
    pub name: &'static str,
    /// Primary value, already formatted (hex / decimal / string).
    pub value: String,
    /// Optional human-readable interpretation: an enum name, a decoded
    /// flag list, an ASCII rendering, etc. `None` when there is nothing
    /// extra to say.
    pub note: Option<String>,
}

impl Field {
    fn new(name: &'static str, value: String, note: Option<String>) -> Self {
        Self { name, value, note }
    }

    /// A field with just a value and no interpretation.
    fn plain(name: &'static str, value: String) -> Self {
        Self::new(name, value, None)
    }
}

/// A renderable table: a title, column headers, and rows of already-formatted
/// cells. A frontend can print any `Report` uniformly without knowing which
/// part of the PE it describes.
#[derive(Clone, Debug)]
pub struct Report {
    /// Section heading, e.g. `"DOS Header"`.
    pub title: String,
    /// Column headers.
    pub headers: Vec<String>,
    /// Rows of cells, each aligned with [`headers`](Self::headers).
    pub rows: Vec<Vec<String>>,
}

impl Report {
    /// Build a report from an explicit header row and pre-formatted rows.
    pub fn new(title: impl Into<String>, headers: &[&str], rows: Vec<Vec<String>>) -> Self {
        Self {
            title: title.into(),
            headers: headers.iter().map(|h| h.to_string()).collect(),
            rows,
        }
    }

    /// Build a key/value report from [`Field`]s, using the standard
    /// `Field / Value / Note` columns.
    pub fn from_fields(title: impl Into<String>, fields: Vec<Field>) -> Self {
        let rows = fields
            .into_iter()
            .map(|f| {
                vec![
                    f.name.to_string(),
                    f.value,
                    f.note.unwrap_or_default(),
                ]
            })
            .collect();
        Self {
            title: title.into(),
            headers: vec!["Field".to_string(), "Value".to_string(), "Note".to_string()],
            rows,
        }
    }
}

// ---------------------------------------------------------------------------
// Value formatting helpers
// ---------------------------------------------------------------------------

fn hex16(v: u16) -> String {
    format!("{v:#06X}")
}
fn hex32(v: u32) -> String {
    format!("{v:#010X}")
}

/// Decode a bitmask into a `A | B | C` string using a table of
/// `(bit, name)` pairs. Any leftover bits are appended as a hex remainder.
fn decode_flags(value: u32, table: &[(u32, &str)]) -> String {
    let mut names = Vec::new();
    let mut remaining = value;
    for &(bit, name) in table {
        if bit != 0 && value & bit == bit {
            names.push(name);
            remaining &= !bit;
        }
    }
    if remaining != 0 {
        return if names.is_empty() {
            format!("{remaining:#010X}")
        } else {
            format!("{} | {:#010X}", names.join(" | "), remaining)
        };
    }
    if names.is_empty() {
        "(none)".to_string()
    } else {
        names.join(" | ")
    }
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        IMAGE_FILE_MACHINE_I386 => "I386",
        IMAGE_FILE_MACHINE_IA64 => "IA64",
        IMAGE_FILE_MACHINE_AMD64 => "AMD64",
        _ => "UNKNOWN",
    }
}

fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        IMAGE_SUBSYSTEM_UNKNOWN => "UNKNOWN",
        IMAGE_SUBSYSTEM_NATIVE => "NATIVE",
        IMAGE_SUBSYSTEM_WINDOWS_GUI => "WINDOWS_GUI",
        IMAGE_SUBSYSTEM_WINDOWS_CUI => "WINDOWS_CUI",
        IMAGE_SUBSYSTEM_OS2_CUI => "OS2_CUI",
        IMAGE_SUBSYSTEM_POSIX_CUI => "POSIX_CUI",
        IMAGE_SUBSYSTEM_NATIVE_WINDOWS => "NATIVE_WINDOWS",
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI => "WINDOWS_CE_GUI",
        IMAGE_SUBSYSTEM_EFI_APPLICATION => "EFI_APPLICATION",
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER => "EFI_BOOT_SERVICE_DRIVER",
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER => "EFI_RUNTIME_DRIVER",
        IMAGE_SUBSYSTEM_EFI_ROM => "EFI_ROM",
        IMAGE_SUBSYSTEM_XBOX => "XBOX",
        IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION => "WINDOWS_BOOT_APPLICATION",
        _ => "UNKNOWN",
    }
}

/// `IMAGE_FILE_*` characteristics of the COFF file header.
const FILE_CHARACTERISTICS: &[(u32, &str)] = &[
    (IMAGE_FILE_RELOCS_STRIPPED as u32, "RELOCS_STRIPPED"),
    (IMAGE_FILE_EXECUTABLE_IMAGE as u32, "EXECUTABLE_IMAGE"),
    (IMAGE_FILE_LINE_NUMS_STRIPPED as u32, "LINE_NUMS_STRIPPED"),
    (IMAGE_FILE_LOCAL_SYMS_STRIPPED as u32, "LOCAL_SYMS_STRIPPED"),
    (IMAGE_FILE_AGGRESIVE_WS_TRIM as u32, "AGGRESIVE_WS_TRIM"),
    (IMAGE_FILE_LARGE_ADDRESS_AWARE as u32, "LARGE_ADDRESS_AWARE"),
    (IMAGE_FILE_BYTES_REVERSED_LO as u32, "BYTES_REVERSED_LO"),
    (IMAGE_FILE_32BIT_MACHINE as u32, "32BIT_MACHINE"),
    (IMAGE_FILE_DEBUG_STRIPPED as u32, "DEBUG_STRIPPED"),
    (IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP as u32, "REMOVABLE_RUN_FROM_SWAP"),
    (IMAGE_FILE_NET_RUN_FROM_SWAP as u32, "NET_RUN_FROM_SWAP"),
    (IMAGE_FILE_SYSTEM as u32, "SYSTEM"),
    (IMAGE_FILE_DLL as u32, "DLL"),
    (IMAGE_FILE_UP_SYSTEM_ONLY as u32, "UP_SYSTEM_ONLY"),
    (IMAGE_FILE_BYTES_REVERSED_HI as u32, "BYTES_REVERSED_HI"),
];

/// `IMAGE_DLLCHARACTERISTICS_*` of the optional header.
const DLL_CHARACTERISTICS: &[(u32, &str)] = &[
    (IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA as u32, "HIGH_ENTROPY_VA"),
    (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE as u32, "DYNAMIC_BASE"),
    (IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY as u32, "FORCE_INTEGRITY"),
    (IMAGE_DLLCHARACTERISTICS_NX_COMPAT as u32, "NX_COMPAT"),
    (IMAGE_DLLCHARACTERISTICS_NO_ISOLATION as u32, "NO_ISOLATION"),
    (IMAGE_DLLCHARACTERISTICS_NO_SEH as u32, "NO_SEH"),
    (IMAGE_DLLCHARACTERISTICS_NO_BIND as u32, "NO_BIND"),
    (IMAGE_DLLCHARACTERISTICS_APPCONTAINER as u32, "APPCONTAINER"),
    (IMAGE_DLLCHARACTERISTICS_WDM_DRIVER as u32, "WDM_DRIVER"),
    (IMAGE_DLLCHARACTERISTICS_GUARD_CF as u32, "GUARD_CF"),
    (IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE as u32, "TERMINAL_SERVER_AWARE"),
];

/// `IMAGE_SCN_*` section characteristics (the meaningful, non-alignment bits).
const SECTION_CHARACTERISTICS: &[(u32, &str)] = &[
    (IMAGE_SCN_CNT_CODE, "CNT_CODE"),
    (IMAGE_SCN_CNT_INITIALIZED_DATA, "CNT_INITIALIZED_DATA"),
    (IMAGE_SCN_CNT_UNINITIALIZED_DATA, "CNT_UNINITIALIZED_DATA"),
    (IMAGE_SCN_LNK_INFO, "LNK_INFO"),
    (IMAGE_SCN_LNK_REMOVE, "LNK_REMOVE"),
    (IMAGE_SCN_LNK_COMDAT, "LNK_COMDAT"),
    (IMAGE_SCN_GPREL, "GPREL"),
    (IMAGE_SCN_LNK_NRELOC_OVFL, "LNK_NRELOC_OVFL"),
    (IMAGE_SCN_MEM_DISCARDABLE, "MEM_DISCARDABLE"),
    (IMAGE_SCN_MEM_NOT_CACHED, "MEM_NOT_CACHED"),
    (IMAGE_SCN_MEM_NOT_PAGED, "MEM_NOT_PAGED"),
    (IMAGE_SCN_MEM_SHARED, "MEM_SHARED"),
    (IMAGE_SCN_MEM_EXECUTE, "MEM_EXECUTE"),
    (IMAGE_SCN_MEM_READ, "MEM_READ"),
    (IMAGE_SCN_MEM_WRITE, "MEM_WRITE"),
];

// (Section::name owns the 8-byte ASCII NUL-trim; no helper here.)

// ---------------------------------------------------------------------------
// Row builders — DOS header
// ---------------------------------------------------------------------------

pub fn dos_header_fields(h: &DosHeader) -> Vec<Field> {
    let magic_note = if h.magic() == 0x5A4D {
        Some("\"MZ\"".to_string())
    } else {
        Some("invalid".to_string())
    };
    vec![
        Field::new("e_magic", hex16(h.magic()), magic_note),
        Field::plain("e_cblp", hex16(h.e_cblp())),
        Field::plain("e_cp", hex16(h.e_cp())),
        Field::plain("e_crlc", hex16(h.e_crlc())),
        Field::plain("e_cparhdr", hex16(h.e_cparhdr())),
        Field::plain("e_minalloc", hex16(h.e_minalloc())),
        Field::plain("e_maxalloc", hex16(h.e_maxalloc())),
        Field::plain("e_ss", hex16(h.e_ss())),
        Field::plain("e_sp", hex16(h.e_sp())),
        Field::plain("e_csum", hex16(h.e_csum())),
        Field::plain("e_ip", hex16(h.e_ip())),
        Field::plain("e_cs", hex16(h.e_cs())),
        Field::plain("e_lfarlc", hex16(h.e_lfarlc())),
        Field::plain("e_ovno", hex16(h.e_ovno())),
        Field::plain("e_oemid", hex16(h.e_oemid())),
        Field::plain("e_oeminfo", hex16(h.e_oeminfo())),
        Field::new(
            "e_lfanew",
            hex32(h.e_lfanew()),
            Some("file offset of NT headers".to_string()),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Row builders — COFF file header
// ---------------------------------------------------------------------------

pub fn file_header_fields(h: &FileHeader) -> Vec<Field> {
    vec![
        Field::new(
            "Machine",
            hex16(h.machine()),
            Some(machine_name(h.machine()).to_string()),
        ),
        Field::plain("NumberOfSections", h.number_of_sections().to_string()),
        Field::plain("TimeDateStamp", hex32(h.time_date_stamp())),
        Field::plain("PointerToSymbolTable", hex32(h.pointer_to_symbol_table())),
        Field::plain("NumberOfSymbols", h.number_of_symbols().to_string()),
        Field::plain("SizeOfOptionalHeader", hex16(h.size_of_optional_header())),
        Field::new(
            "Characteristics",
            hex16(h.characteristics()),
            Some(decode_flags(h.characteristics() as u32, FILE_CHARACTERISTICS)),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Row builders — optional header (PE32 / PE32+)
// ---------------------------------------------------------------------------

pub fn optional_header_fields(h: &OptionalHeader) -> Vec<Field> {
    let kind_note = if h.is_pe32_plus() { "PE32+" } else { "PE32" };
    let (linker_major, linker_minor) = h.linker_version();
    let (os_major, os_minor) = h.operating_system_version();
    let (img_major, img_minor) = h.image_version();
    let (subsys_major, subsys_minor) = h.subsystem_version();

    let mut rows = vec![
        Field::new("Magic", hex16(h.magic()), Some(kind_note.to_string())),
        Field::plain(
            "LinkerVersion",
            format!("{linker_major}.{linker_minor}"),
        ),
        Field::plain("SizeOfCode", hex32(h.size_of_code())),
        Field::plain("SizeOfInitializedData", hex32(h.size_of_initialized_data())),
        Field::plain("SizeOfUninitializedData", hex32(h.size_of_uninitialized_data())),
        Field::plain("AddressOfEntryPoint", hex32(h.address_of_entry_point())),
        Field::plain("BaseOfCode", hex32(h.base_of_code())),
    ];
    if let Some(b) = h.base_of_data() {
        rows.push(Field::plain("BaseOfData", hex32(b)));
    }
    rows.push(Field::plain("ImageBase", h.image_base().to_hex_string()));
    rows.push(Field::plain("SectionAlignment", hex32(h.section_alignment())));
    rows.push(Field::plain("FileAlignment", hex32(h.file_alignment())));
    rows.push(Field::plain(
        "OperatingSystemVersion",
        format!("{os_major}.{os_minor}"),
    ));
    rows.push(Field::plain(
        "ImageVersion",
        format!("{img_major}.{img_minor}"),
    ));
    rows.push(Field::plain(
        "SubsystemVersion",
        format!("{subsys_major}.{subsys_minor}"),
    ));
    rows.push(Field::plain("Win32VersionValue", hex32(h.win32_version_value())));
    rows.push(Field::plain("SizeOfImage", hex32(h.size_of_image())));
    rows.push(Field::plain("SizeOfHeaders", hex32(h.size_of_headers())));
    rows.push(Field::plain("CheckSum", hex32(h.check_sum())));
    rows.push(Field::new(
        "Subsystem",
        hex16(h.subsystem()),
        Some(subsystem_name(h.subsystem()).to_string()),
    ));
    rows.push(Field::new(
        "DllCharacteristics",
        hex16(h.dll_characteristics()),
        Some(decode_flags(h.dll_characteristics() as u32, DLL_CHARACTERISTICS)),
    ));
    rows.push(Field::plain(
        "SizeOfStackReserve",
        h.size_of_stack_reserve().to_hex_string(),
    ));
    rows.push(Field::plain(
        "SizeOfStackCommit",
        h.size_of_stack_commit().to_hex_string(),
    ));
    rows.push(Field::plain(
        "SizeOfHeapReserve",
        h.size_of_heap_reserve().to_hex_string(),
    ));
    rows.push(Field::plain(
        "SizeOfHeapCommit",
        h.size_of_heap_commit().to_hex_string(),
    ));
    rows.push(Field::plain("LoaderFlags", hex32(h.loader_flags())));
    rows.push(Field::plain(
        "NumberOfRvaAndSizes",
        h.number_of_rva_and_sizes().to_string(),
    ));
    rows
}

// ---------------------------------------------------------------------------
// Row builders — section table (multi-column)
// ---------------------------------------------------------------------------

/// Column headers matching the tuple order of [`section_row`].
pub const SECTION_COLUMNS: &[&str] = &[
    "Name",
    "VirtAddr",
    "VirtSize",
    "RawSize",
    "RawPtr",
    "Characteristics",
];

/// One section rendered as a row of already-formatted cells, aligned with
/// [`SECTION_COLUMNS`].
pub fn section_row(s: &Section) -> Vec<String> {
    vec![
        s.name(),
        hex32(s.virtual_address()),
        hex32(s.virtual_size()),
        hex32(s.raw_size()),
        hex32(s.raw_offset()),
        decode_flags(s.characteristics(), SECTION_CHARACTERISTICS),
    ]
}
