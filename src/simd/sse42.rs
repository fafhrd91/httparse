use crate::iter::Bytes;

#[target_feature(enable = "sse4.2")]
pub unsafe fn match_header_name_vectored(bytes: &mut Bytes) {
    while bytes.as_ref().len() >= 16 {
        let advance = match_header_name_char_16_sse(bytes.as_ref());
        bytes.advance(advance);

        if advance != 16 {
            return;
        }
    }
    super::swar::match_header_name_vectored(bytes);
}

// Token chars are looked up in a nibble bitmap: the low nibble selects a
// bitmap entry, the high nibble a bit in it. `pshufb` returns 0 for indices
// with the top bit set, so bytes >= 0x80 are rejected.
#[inline(always)]
unsafe fn match_header_name_char_16_sse(buf: &[u8]) -> usize {
    debug_assert!(buf.len() >= 16);

    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    let bitmap = _mm_loadu_si128(crate::utils::TOKEN_NIBBLES.as_ptr() as *const _);
    let bits = _mm_setr_epi8(1, 2, 4, 8, 16, 32, 64, -128, 1, 2, 4, 8, 16, 32, 64, -128);

    let dat = _mm_lddqu_si128(buf.as_ptr() as *const _);
    let rows = _mm_shuffle_epi8(
        bitmap,
        _mm_and_si128(dat, _mm_set1_epi8(0x8f_u8.cast_signed())),
    );
    let hi = _mm_and_si128(_mm_srli_epi16(dat, 4), _mm_set1_epi8(0x0f));
    let bit = _mm_shuffle_epi8(bits, hi);
    let ok = _mm_cmpeq_epi8(_mm_and_si128(rows, bit), bit);
    let res = _mm_movemask_epi8(ok) as u16;

    res.trailing_ones() as usize
}
#[target_feature(enable = "sse4.2")]
pub unsafe fn match_uri_vectored(bytes: &mut Bytes) {
    while bytes.as_ref().len() >= 16 {
        let advance = match_url_char_16_sse(bytes.as_ref());
        bytes.advance(advance);

        if advance != 16 {
            return;
        }
    }
    super::swar::match_uri_vectored(bytes);
}

#[inline(always)]
#[allow(non_snake_case)]
unsafe fn match_url_char_16_sse(buf: &[u8]) -> usize {
    debug_assert!(buf.len() >= 16);

    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    let ptr = buf.as_ptr();

    // %x21-%x7e %x80-%xff
    let DEL: __m128i = _mm_set1_epi8(0x7f);
    let LOW: __m128i = _mm_set1_epi8(0x21);

    let dat = _mm_lddqu_si128(ptr as *const _);
    // unsigned comparison dat >= LOW
    let low = _mm_cmpeq_epi8(_mm_max_epu8(dat, LOW), dat);
    let del = _mm_cmpeq_epi8(dat, DEL);
    let bit = _mm_andnot_si128(del, low);
    let res = _mm_movemask_epi8(bit) as u16;

    res.trailing_ones() as usize
}

#[target_feature(enable = "sse4.2")]
pub unsafe fn match_header_value_vectored(bytes: &mut Bytes) {
    while bytes.as_ref().len() >= 16 {
        let advance = match_header_value_char_16_sse(bytes.as_ref());
        bytes.advance(advance);

        if advance != 16 {
            return;
        }
    }
    super::swar::match_header_value_vectored(bytes);
}

#[inline(always)]
#[allow(non_snake_case)]
unsafe fn match_header_value_char_16_sse(buf: &[u8]) -> usize {
    debug_assert!(buf.len() >= 16);

    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    let ptr = buf.as_ptr();

    // %x09 %x20-%x7e %x80-%xff
    let TAB: __m128i = _mm_set1_epi8(0x09);
    let DEL: __m128i = _mm_set1_epi8(0x7f);
    let LOW: __m128i = _mm_set1_epi8(0x20);

    let dat = _mm_lddqu_si128(ptr as *const _);
    // unsigned comparison dat >= LOW
    let low = _mm_cmpeq_epi8(_mm_max_epu8(dat, LOW), dat);
    let tab = _mm_cmpeq_epi8(dat, TAB);
    let del = _mm_cmpeq_epi8(dat, DEL);
    let bit = _mm_andnot_si128(del, _mm_or_si128(low, tab));
    let res = _mm_movemask_epi8(bit) as u16;

    res.trailing_ones() as usize
}

#[test]
fn sse_code_matches_uri_chars_table() {
    if !is_x86_feature_detected!("sse4.2") {
        return;
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    unsafe {
        assert!(byte_is_allowed(b'_', match_uri_vectored));

        for (b, allowed) in crate::utils::URI_MAP.iter().copied().enumerate() {
            assert_eq!(
                byte_is_allowed(b as u8, match_uri_vectored),
                allowed,
                "byte_is_allowed({b:?}) should be {allowed:?}"
            );
        }
    }
}

#[test]
fn sse_code_matches_header_value_chars_table() {
    if !is_x86_feature_detected!("sse4.2") {
        return;
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    unsafe {
        assert!(byte_is_allowed(b'_', match_header_value_vectored));

        for (b, allowed) in crate::utils::HEADER_VALUE_MAP.iter().copied().enumerate() {
            assert_eq!(
                byte_is_allowed(b as u8, match_header_value_vectored),
                allowed,
                "byte_is_allowed({b:?}) should be {allowed:?}"
            );
        }
    }
}

#[test]
fn sse_code_matches_header_name_chars_table() {
    if !is_x86_feature_detected!("sse4.2") {
        return;
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    unsafe {
        assert!(byte_is_allowed(b'_', match_header_name_vectored));

        for (b, allowed) in crate::utils::TOKEN_MAP.iter().copied().enumerate() {
            assert_eq!(
                byte_is_allowed(b as u8, match_header_name_vectored),
                allowed,
                "byte_is_allowed({b:?}) should be {allowed:?}"
            );
        }
    }
}

#[allow(clippy::missing_safety_doc)]
#[cfg(test)]
unsafe fn byte_is_allowed(byte: u8, f: unsafe fn(bytes: &mut Bytes<'_, '_>)) -> bool {
    let mut st = crate::State::default();
    let slice = [
        b'_', b'_', b'_', b'_', b'_', b'_', b'_', b'_', b'_', b'_', byte, b'_', b'_', b'_', b'_',
        b'_',
    ];
    let mut bytes = Bytes::new(&slice, &mut st);

    f(&mut bytes);

    match bytes.cursor() - bytes.start() {
        16 => true,
        10 => false,
        _ => unreachable!(),
    }
}
