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
