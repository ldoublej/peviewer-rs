use super::image_base::ImageBase;
use crate::pe_structs::{
    IMAGE_DATA_DIRECTORY, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64,
};

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

    pub(crate) fn data_directory(&self, index: u16) -> IMAGE_DATA_DIRECTORY {
        match &self.inner {
            OptionalHeaderInner::Pe32(h) => h.DataDirectory[index as usize],
            OptionalHeaderInner::Pe32Plus(h) => h.DataDirectory[index as usize],
        }
    }

    pub fn is_pe32_plus(&self) -> bool {
        matches!(self.inner, OptionalHeaderInner::Pe32Plus(_))
    }

    /// `0x10b` for PE32, `0x20b` for PE32+ (`0x107` for ROM is currently
    /// rejected by [`NtHeaders::parse`](super::NtHeaders::parse)).
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
