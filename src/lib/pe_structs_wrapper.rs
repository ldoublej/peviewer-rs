//! Safe wrapper types around the raw `pe_structs` definitions.
//!
//! Each `IMAGE_*` struct in `pe_structs` is exposed here through a small
//! wrapper that validates magic bytes / sizes on parse and presents a
//! uniform API regardless of whether the image is PE32 or PE32+.

mod align;
mod dos_header;
mod file_header;
mod image_base;
mod nt_headers;
mod optional_header;
mod section;

pub use dos_header::DosHeader;
pub use file_header::FileHeader;
pub use image_base::ImageBase;
pub use nt_headers::NtHeaders;
pub use optional_header::OptionalHeader;
pub use section::Section;
