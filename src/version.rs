use crate::{Error, Result, State, Status, iter::Bytes};

#[inline]
/// Parse request's version
pub fn parse_version(src: &[u8]) -> Result<u8> {
    let mut st = State::default();
    let mut bytes = Bytes::new(src, &mut st);
    parse_version_inner(&mut bytes)
}

#[inline]
#[allow(missing_docs)]
pub(crate) fn parse_version_inner(bytes: &mut Bytes<'_, '_>) -> Result<u8> {
    if let Some(eight) = bytes.peek_n::<8>() {
        const H10: u64 = u64::from_ne_bytes(*b"HTTP/1.0");
        const H11: u64 = u64::from_ne_bytes(*b"HTTP/1.1");
        // peek_n before ensures within bounds
        bytes.advance(8);
        return match u64::from_ne_bytes(eight) {
            H10 => Ok(Status::Complete(0)),
            H11 => Ok(Status::Complete(1)),
            _ => Err(Error::Version),
        };
    }

    // else (but not in `else` because of borrow checker)

    // If there aren't at least 8 bytes, we still want to detect early
    // if this is a valid version or not. If it is, we'll return Partial.
    expect!(bytes.next() == b'H' => Err(Error::Version));
    expect!(bytes.next() == b'T' => Err(Error::Version));
    expect!(bytes.next() == b'T' => Err(Error::Version));
    expect!(bytes.next() == b'P' => Err(Error::Version));
    expect!(bytes.next() == b'/' => Err(Error::Version));
    expect!(bytes.next() == b'1' => Err(Error::Version));
    expect!(bytes.next() == b'.' => Err(Error::Version));
    Ok(Status::Partial)
}
