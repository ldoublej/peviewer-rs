use crate::pe_structs::IMAGE_SECTION_HEADER;
use std::ops::Deref;

/// A parsed section: the raw [`IMAGE_SECTION_HEADER`] plus derived data
/// (a decoded name, the section's bytes).
///
/// All of the underlying header fields (`VirtualAddress`, `SizeOfRawData`,
/// `Characteristics`, ...) are available directly on a `Section` via [`Deref`],
/// so there is no need to re-declare them here.
#[derive(Debug)]
pub struct Section<'a> {
    section_header: IMAGE_SECTION_HEADER,
    _section_data: Option<&'a [u8]>,
}

impl<'a> Section<'a> {
    pub fn new(image_section_header: IMAGE_SECTION_HEADER, section_data: Option<&'a [u8]>) -> Self {
        Self {
            section_header: image_section_header,
            _section_data: section_data
        }
    }
}

impl<'a> Deref for Section<'a> {
    type Target = IMAGE_SECTION_HEADER;

    fn deref(&self) -> &Self::Target {
        &self.section_header
    }
}
