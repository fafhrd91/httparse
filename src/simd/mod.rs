#![allow(
    unsafe_op_in_unsafe_fn,
    clippy::inline_always,
    clippy::wildcard_imports,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    clippy::ptr_as_ptr
)]
mod swar;

#[cfg(any(
    httparse_disable_simd,
    miri,
    not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_feature = "neon",)
    )),
    all(
        not(feature = "std"),
        not(any(target_feature = "sse4.2", target_feature = "avx2",)),
        any(target_arch = "x86", target_arch = "x86_64",),
    )
))]
pub use self::swar::*;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    any(feature = "std", target_feature = "sse4.2",),
    not(target_feature = "avx2"),
    any(target_arch = "x86", target_arch = "x86_64",),
))]
mod sse42;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    any(
        target_feature = "avx2",
        all(feature = "std", not(target_feature = "sse4.2"),)
    ),
    any(target_arch = "x86", target_arch = "x86_64",),
))]
mod avx2;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    feature = "std",
    not(any(target_feature = "sse4.2", target_feature = "avx2",)),
    any(target_arch = "x86", target_arch = "x86_64",),
))]
mod runtime;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    feature = "std",
    not(any(target_feature = "sse4.2", target_feature = "avx2",)),
    any(target_arch = "x86", target_arch = "x86_64",),
))]
pub use self::runtime::*;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    target_feature = "sse4.2",
    not(target_feature = "avx2"),
    any(target_arch = "x86", target_arch = "x86_64",),
))]
mod sse42_compile_time {
    #[inline(always)]
    pub fn match_header_name_vectored(b: &mut crate::iter::Bytes<'_, '_>) {
        if super::swar::match_header_name_prefix::<16>(b) {
            unsafe { super::sse42::match_header_name_vectored(b) }
        }
    }

    #[inline(always)]
    pub fn match_uri_vectored(b: &mut crate::iter::Bytes<'_, '_>) {
        unsafe { super::sse42::match_uri_vectored(b) }
    }

    #[inline(always)]
    pub fn match_uri_ascii_vectored<const Q: bool>(b: &mut crate::iter::Bytes<'_, '_>) {
        unsafe { super::sse42::match_uri_ascii_vectored::<Q>(b) }
    }

    #[inline(always)]
    pub fn match_header_value_vectored(b: &mut crate::iter::Bytes<'_, '_>) {
        unsafe { super::sse42::match_header_value_vectored(b) }
    }
}

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    target_feature = "sse4.2",
    not(target_feature = "avx2"),
    any(target_arch = "x86", target_arch = "x86_64",),
))]
pub use self::sse42_compile_time::*;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    target_feature = "avx2",
    any(target_arch = "x86", target_arch = "x86_64",),
))]
mod avx2_compile_time {
    #[inline(always)]
    pub fn match_header_name_vectored(b: &mut crate::iter::Bytes<'_, '_>) {
        if super::swar::match_header_name_prefix::<16>(b) {
            unsafe { super::avx2::match_header_name_vectored(b) }
        }
    }

    #[inline(always)]
    pub fn match_uri_vectored(b: &mut crate::iter::Bytes<'_, '_>) {
        unsafe { super::avx2::match_uri_vectored(b) }
    }

    #[inline(always)]
    pub fn match_uri_ascii_vectored<const Q: bool>(b: &mut crate::iter::Bytes<'_, '_>) {
        unsafe { super::avx2::match_uri_ascii_vectored::<Q>(b) }
    }

    #[inline(always)]
    pub fn match_header_value_vectored(b: &mut crate::iter::Bytes<'_, '_>) {
        unsafe { super::avx2::match_header_value_vectored(b) }
    }
}

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    target_feature = "avx2",
    any(target_arch = "x86", target_arch = "x86_64",),
))]
pub use self::avx2_compile_time::*;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    target_arch = "aarch64",
    target_feature = "neon",
))]
mod neon;

#[cfg(all(
    not(any(httparse_disable_simd, miri)),
    target_arch = "aarch64",
    target_feature = "neon",
))]
pub use self::neon::*;

#[cfg(test)]
mod tests {
    use crate::iter::Bytes;

    fn stops_at(b: u8, q: bool) -> bool {
        !(0x21..=0x7e).contains(&b) || (q && b == b'?')
    }

    /// Runs `f` over `_` filled buffers with `byte` at every position and
    /// checks it stops exactly at that byte, or consumes everything.
    fn check<const Q: bool>(name: &str, f: &dyn Fn(&mut Bytes<'_, '_>)) {
        for len in [1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 40, 70] {
            for pos in 0..len {
                for byte in 0..=255u8 {
                    let mut buf = vec![b'_'; len];
                    buf[pos] = byte;
                    let mut st = crate::State::default();
                    let mut bytes = Bytes::new(&buf, &mut st);
                    f(&mut bytes);
                    let expected = if stops_at(byte, Q) { pos } else { len };
                    assert_eq!(
                        bytes.cursor(),
                        expected,
                        "{name}::<{Q}> byte {byte:#04x} at {pos} of {len}"
                    );
                }
            }
        }
    }

    /// STATEMENT: Every `match_uri_ascii_vectored` backend accepts exactly
    /// `0x21..=0x7E`, and also stops at `?` when `Q` is set.
    ///
    /// HOW:
    /// - For the SWAR backend, the selected backend, and the SSE4.2 and AVX2
    ///   backends when compiled in and supported, scan buffers of lengths
    ///   around the 8, 16 and 32 byte block sizes.
    /// - Put each byte value at each position and check the cursor stops at
    ///   it when it is outside the set, and reaches the end otherwise.
    #[test]
    fn match_uri_ascii_vectored_backends() {
        check::<true>("swar", &|b| {
            super::swar::match_uri_ascii_vectored::<true>(b);
        });
        check::<false>("swar", &|b| {
            super::swar::match_uri_ascii_vectored::<false>(b);
        });
        check::<true>("selected", &|b| super::match_uri_ascii_vectored::<true>(b));
        check::<false>("selected", &|b| super::match_uri_ascii_vectored::<false>(b));

        #[cfg(all(
            not(any(httparse_disable_simd, miri)),
            any(feature = "std", target_feature = "sse4.2"),
            not(target_feature = "avx2"),
            any(target_arch = "x86", target_arch = "x86_64"),
        ))]
        if std::is_x86_feature_detected!("sse4.2") {
            #[allow(clippy::undocumented_unsafe_blocks)]
            unsafe {
                check::<true>("sse42", &|b| {
                    super::sse42::match_uri_ascii_vectored::<true>(b);
                });
                check::<false>("sse42", &|b| {
                    super::sse42::match_uri_ascii_vectored::<false>(b);
                });
            }
        }

        #[cfg(all(
            not(any(httparse_disable_simd, miri)),
            any(
                target_feature = "avx2",
                all(feature = "std", not(target_feature = "sse4.2"))
            ),
            any(target_arch = "x86", target_arch = "x86_64"),
        ))]
        if std::is_x86_feature_detected!("avx2") {
            #[allow(clippy::undocumented_unsafe_blocks)]
            unsafe {
                check::<true>("avx2", &|b| {
                    super::avx2::match_uri_ascii_vectored::<true>(b);
                });
                check::<false>("avx2", &|b| {
                    super::avx2::match_uri_ascii_vectored::<false>(b);
                });
            }
        }
    }
}
