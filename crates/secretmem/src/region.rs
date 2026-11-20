//! Page arithmetic shared by the backends and containers.

use crate::{Error, Result};

/// Round `n` up to a whole number of pages. Zero becomes one page: a region is
/// never empty, so guard pages always flank real, wired memory.
#[inline]
pub(crate) fn round_up_pages(n: usize, page: usize) -> Result<usize> {
    debug_assert!(page.is_power_of_two());
    if n == 0 {
        return Ok(page);
    }
    let pages = n
        .checked_add(page - 1)
        .ok_or(Error::TooLarge)?;
    Ok(pages & !(page - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_up() {
        assert_eq!(round_up_pages(1, 4096).unwrap(), 4096);
        assert_eq!(round_up_pages(4096, 4096).unwrap(), 4096);
        assert_eq!(round_up_pages(4097, 4096).unwrap(), 8192);
        assert_eq!(round_up_pages(0, 4096).unwrap(), 4096);
    }

    #[test]
    fn overflow_is_an_error() {
        assert_eq!(round_up_pages(usize::MAX, 4096), Err(Error::TooLarge));
    }
}
