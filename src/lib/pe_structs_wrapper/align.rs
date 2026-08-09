/// Round `value` up to the nearest multiple of `align`. `align` must be
/// non-zero. Returns `value` unchanged if it is already aligned.
pub(crate) fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        value
    } else {
        let rem = value % align;
        if rem == 0 {
            value
        } else {
            value + (align - rem)
        }
    }
}
