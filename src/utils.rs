use super::{iter::Bytes, Error, Result, Status};

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
pub(crate) fn skip_empty_lines(bytes: &mut Bytes<'_>) -> Result<()> {
    loop {
        let b = bytes.peek();
        match b {
            Some(b'\r') => {
                // SAFETY: peeked and found `\r`, so it's safe to bump 1 pos
                unsafe { bytes.bump() };
                expect!(bytes.next() == b'\n' => Err(Error::NewLine));
            }
            Some(b'\n') => {
                // SAFETY: peeked and found `\n`, so it's safe to bump 1 pos
                unsafe {
                    bytes.bump();
                }
            }
            Some(..) => {
                bytes.slice();
                return Ok(Status::Complete(()));
            }
            None => return Ok(Status::Partial),
        }
    }
}

#[inline]
pub(crate) fn skip_spaces(bytes: &mut Bytes<'_>) -> Result<()> {
    loop {
        let b = bytes.peek();
        match b {
            Some(b' ') => {
                // SAFETY: peeked and found ` `, so it's safe to bump 1 pos
                unsafe { bytes.bump() };
            }
            Some(..) => {
                bytes.slice();
                return Ok(Status::Complete(()));
            }
            None => return Ok(Status::Partial),
        }
    }
}
