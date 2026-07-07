#![allow(
    unsafe_op_in_unsafe_fn,
    clippy::cast_sign_loss,
    clippy::undocumented_unsafe_blocks
)]
use core::convert::TryInto;

use crate::SlicePos;

#[allow(missing_docs)]
pub(crate) struct Bytes<'a> {
    slice: *const u8,
    start: *const u8,
    end: *const u8,
    /// INVARIANT: start <= cursor && cursor <= end
    cursor: *const u8,
    phantom: core::marker::PhantomData<&'a ()>,
}

#[allow(missing_docs)]
impl<'a> Bytes<'a> {
    #[inline]
    pub(crate) fn new(slice: &'a [u8]) -> Bytes<'a> {
        let start = slice.as_ptr();
        // SAFETY: obtain pointer to slice end; start points to slice start.
        let end = unsafe { start.add(slice.len()) };
        let cursor = start;
        Bytes {
            start,
            end,
            cursor,
            slice: slice.as_ptr(),
            phantom: core::marker::PhantomData,
        }
    }

    #[inline]
    pub(crate) fn pos(&self) -> usize {
        self.cursor as usize - self.start as usize
    }

    #[inline]
    pub(crate) fn slice_pos(&self) -> usize {
        self.cursor as usize - self.slice as usize
    }

    #[inline]
    pub(crate) fn peek(&self) -> Option<u8> {
        if self.cursor < self.end {
            // SAFETY:  bounds checked
            Some(unsafe { *self.cursor })
        } else {
            None
        }
    }

    /// Peek at byte `n` ahead of cursor
    ///
    /// # Safety
    ///
    /// Caller must ensure that `n <= self.len()`, otherwise `self.cursor.add(n)` is UB.
    /// That means there are at least `n-1` bytes between `self.cursor` and `self.end`
    /// and `self.cursor.add(n)` is either `self.end` or points to a valid byte.
    #[inline]
    pub(crate) unsafe fn peek_ahead(&self, n: usize) -> Option<u8> {
        debug_assert!(n <= (self.end as usize - self.cursor as usize));
        // SAFETY: by preconditions
        let p = unsafe { self.cursor.add(n) };
        if p < self.end {
            // SAFETY: by preconditions, if this is not `self.end`,
            // then it is safe to dereference
            Some(unsafe { *p })
        } else {
            None
        }
    }

    #[inline]
    pub(crate) fn peek_n<const N: usize>(&self) -> Option<[u8; N]> {
        self.as_ref().get(..N)?.try_into().ok()
    }

    /// Advance cursor by `n`
    ///
    /// # Safety
    ///
    /// Caller must ensure that Bytes hasn't been advanced/bumped by more than [`Bytes::len()`].
    #[inline]
    pub(crate) unsafe fn advance(&mut self, n: usize) {
        self.cursor = self.cursor.add(n);
        debug_assert!(self.cursor <= self.end, "overflow");
    }

    #[inline]
    pub(crate) fn slice(&mut self) -> &'a [u8] {
        // SAFETY: not moving position at all, so it's safe
        let slice = unsafe { slice_from_ptr_range(self.start, self.cursor) };
        self.commit();
        slice
    }

    // TODO: this is an anti-pattern, should be removed
    /// Deprecated. Do not use!
    /// # Safety
    ///
    /// Caller must ensure that `skip` is at most the number of advances (i.e., `bytes.advance(3)`
    /// implies a skip of at most 3).
    #[inline]
    pub(crate) unsafe fn slice_skip(&mut self, skip: usize) -> &'a [u8] {
        debug_assert!(skip <= self.cursor.offset_from(self.start) as usize);
        let head = slice_from_ptr_range(self.start, self.cursor.sub(skip));
        self.commit();
        head
    }

    #[inline]
    pub(crate) fn slice_position(&mut self, skip: usize) -> SlicePos {
        unsafe {
            debug_assert!(skip <= self.cursor.offset_from(self.start) as usize);
        }
        let start = self.start as usize - self.slice as usize;
        let end = (self.cursor as usize - self.slice as usize) - skip;
        self.commit();
        SlicePos { start, end }
    }

    #[inline]
    pub(crate) fn commit(&mut self) {
        self.start = self.cursor;
    }
}

impl AsRef<[u8]> for Bytes<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        // SAFETY: not moving position at all, so it's safe
        unsafe { slice_from_ptr_range(self.cursor, self.end) }
    }
}

/// # Safety
///
/// Must ensure start and end point to the same memory object to uphold memory safety.
#[inline]
unsafe fn slice_from_ptr_range<'a>(start: *const u8, end: *const u8) -> &'a [u8] {
    debug_assert!(start <= end);
    core::slice::from_raw_parts(start, end as usize - start as usize)
}

impl Iterator for Bytes<'_> {
    type Item = u8;

    #[inline]
    fn next(&mut self) -> Option<u8> {
        if self.cursor < self.end {
            // SAFETY: bounds checked dereference
            unsafe {
                let b = *self.cursor;
                self.advance(1);
                Some(b)
            }
        } else {
            None
        }
    }
}
