#![allow(clippy::cast_sign_loss)]
use core::convert::TryInto;

use crate::{SlicePos, State};

#[allow(missing_docs)]
pub(crate) struct Bytes<'a, 'b> {
    slice: &'a [u8],
    pub(crate) st: &'b mut State,
}

#[allow(missing_docs)]
impl<'a, 'b> Bytes<'a, 'b> {
    #[inline]
    pub(crate) fn new(slice: &'a [u8], st: &'b mut State) -> Bytes<'a, 'b> {
        Bytes { slice, st }
    }

    #[inline]
    pub(crate) fn start(&self) -> usize {
        self.st.start
    }

    #[inline]
    pub(crate) fn cursor(&self) -> usize {
        self.st.cursor
    }

    #[inline]
    pub(crate) fn peek(&self) -> Option<u8> {
        self.slice.get(self.st.cursor).copied()
    }

    /// Peek at byte `n` ahead of cursor
    ///
    /// # Safety
    ///
    /// Caller must ensure that `n <= self.len()`, otherwise `self.cursor.add(n)` is UB.
    /// That means there are at least `n-1` bytes between `self.cursor` and `self.end`
    /// and `self.cursor.add(n)` is either `self.end` or points to a valid byte.
    #[inline]
    pub(crate) fn peek_ahead(&self, n: usize) -> Option<u8> {
        self.slice.get(self.st.cursor + n).copied()
    }

    #[inline]
    pub(crate) fn peek_behind(&self, n: usize) -> Option<u8> {
        if n > self.st.cursor {
            None
        } else {
            self.slice.get(self.st.cursor - n).copied()
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
    pub(crate) fn advance(&mut self, n: usize) {
        self.st.cursor += n;
        debug_assert!(self.st.cursor <= self.slice.len(), "overflow");
    }

    #[inline]
    pub(crate) fn slice_position(&mut self, skip: usize) -> SlicePos {
        //unsafe {
        //debug_assert!(skip <= self.cursor.offset_from(self.start) as usize);
        //}
        let start = self.st.start;
        let end = self.st.cursor - skip;
        self.commit();
        SlicePos { start, end }
    }

    #[inline]
    pub(crate) fn commit(&mut self) {
        self.st.start = self.st.cursor;
    }
}

impl AsRef<[u8]> for Bytes<'_, '_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.slice[self.st.cursor..]
    }
}

impl Iterator for Bytes<'_, '_> {
    type Item = u8;

    #[inline]
    fn next(&mut self) -> Option<u8> {
        let b = self.slice.get(self.st.cursor).copied();
        if b.is_some() {
            self.advance(1);
        }
        b
    }
}
