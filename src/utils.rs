use super::{Error, Result, Status, iter::Bytes};

// char codes to accept URI string.
// i.e. b'!' <= char and char != 127
// TODO: Make a stricter checking for URI string?
pub(crate) static URI_MAP: [bool; 256] = byte_map!(
    b'!'..=0x7e | 0x80..=0xFF
);

pub(crate) static TOKEN_MAP: [bool; 256] = byte_map!(
    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' |  b'*' | b'+' |
    b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
);

pub(crate) static HEADER_VALUE_MAP: [bool; 256] = byte_map!(
    b'\t' | b' '..=0x7e | 0x80..=0xFF
);

/// `TOKEN_MAP` as a nibble bitmap for SIMD table lookups: bit `hi` of entry
/// `lo` is set if byte `hi << 4 | lo` is a token char. Only bytes below 0x80
/// can be token chars.
#[allow(dead_code)]
pub(crate) const TOKEN_NIBBLES: [u8; 16] = {
    let mut map = [0u8; 16];
    let mut b = 0;
    while b < 0x80 {
        if TOKEN_MAP[b] {
            map[b & 0x0f] |= 1 << (b >> 4);
        }
        b += 1;
    }
    map
};

/// Determines if byte is a method token char.
///
/// > ```notrust
/// > token          = 1*tchar
/// >
/// > tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
/// >                / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
/// >                / DIGIT / ALPHA
/// >                ; any VCHAR, except delimiters
/// > ```
#[inline]
pub(crate) fn is_method_token(b: u8) -> bool {
    match b {
        // For the majority case, this can be faster than the table lookup.
        b'A'..=b'Z' => true,
        _ => TOKEN_MAP[b as usize],
    }
}

#[inline]
pub(crate) fn is_uri_token(b: u8) -> bool {
    URI_MAP[b as usize]
}

#[inline]
pub(crate) fn is_header_name_token(b: u8) -> bool {
    TOKEN_MAP[b as usize]
}

#[inline]
pub(crate) fn is_header_value_token(b: u8) -> bool {
    HEADER_VALUE_MAP[b as usize]
}

#[inline]
pub(crate) fn skip_empty_lines(bytes: &mut Bytes<'_, '_>) -> Result<()> {
    loop {
        let b = bytes.peek();
        match b {
            Some(b'\r') => {
                // peeked and found `\r`, so it's safe to bump 1 pos
                bytes.advance(1);
                expect_lf!(bytes => Err(Error::NewLine));
            }
            Some(b'\n') => {
                // peeked and found `\n`, so it's safe to bump 1 pos
                bytes.advance(1);
            }
            Some(..) => {
                bytes.commit();
                return Ok(Status::Complete(()));
            }
            None => return Ok(Status::Partial),
        }
    }
}

#[inline]
pub(crate) fn skip_spaces(bytes: &mut Bytes<'_, '_>) -> Result<()> {
    loop {
        let b = bytes.peek();
        match b {
            Some(b' ') => {
                // peeked and found ` `, so it's safe to bump 1 pos
                bytes.advance(1);
            }
            Some(..) => {
                bytes.commit();
                return Ok(Status::Complete(()));
            }
            None => return Ok(Status::Partial),
        }
    }
}
