#![deny(
    clippy::pedantic,
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks
)]
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]
#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![cfg_attr(test, deny(warnings))]

//! # httparse
//!
//! A push library for parsing HTTP/1.x requests and responses.
//!
//! The focus is on speed and safety. Unsafe code is used to keep parsing fast,
//! but unsafety is contained in a submodule, with invariants enforced. The
//! parsing internals use an `Iterator` instead of direct indexing, while
//! skipping bounds checks.
//!
//! SIMD optimizations are enabled automatically when available.
//! If building an executable to be run on multiple platforms, and thus
//! not passing `target_feature` or `target_cpu` flags to the compiler,
//! runtime detection can still detect SSE4.2 or AVX2 support to provide
//! massive wins.
//!
//! If compiling for a specific target, remembering to include
//! `-C target_cpu=native` allows the detection to become compile time checks,
//! making it *even* faster.

use core::{fmt, result, str};

mod iter;
#[macro_use]
mod macros;
mod headers;
mod simd;
mod utils;
mod version;

pub use crate::headers::{Header, HeaderParsed};
pub use crate::version::parse_version;

use crate::iter::Bytes;

/// An error in parsing.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Invalid byte in header name.
    HeaderName,
    /// Invalid byte in header value.
    HeaderValue,
    /// Invalid byte in new line.
    NewLine,
    /// Invalid byte in Response status.
    Status,
    /// Invalid byte where token is required.
    Token,
    /// Parsed more headers than provided buffer can contain.
    TooManyHeaders,
    /// Invalid byte in HTTP version.
    Version,
}

impl Error {
    #[inline]
    fn description_str(self) -> &'static str {
        match self {
            Error::HeaderName => "invalid header name",
            Error::HeaderValue => "invalid header value",
            Error::NewLine => "invalid new line",
            Error::Status => "invalid response status",
            Error::Token => "invalid token",
            Error::TooManyHeaders => "too many headers",
            Error::Version => "invalid HTTP version",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description_str())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn description(&self) -> &str {
        self.description_str()
    }
}

/// An error in parsing a chunk size.
// Note: Move this into the error enum once v2.0 is released.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidChunkSize;

impl fmt::Display for InvalidChunkSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid chunk size")
    }
}

/// A Result of any parsing action.
///
/// If the input is invalid, an `Error` will be returned. Note that incomplete
/// data is not considered invalid, and so will not return an error, but rather
/// a `Ok(Status::Partial)`.
pub type Result<T> = result::Result<Status<T>, Error>;

/// The result of a successful parse pass.
///
/// `Complete` is used when the buffer contained the complete value.
/// `Partial` is used when parsing did not reach the end of the expected value,
/// but no invalid data was found.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Status<T> {
    /// The completed result.
    Complete(T),
    /// A partial result.
    Partial,
}

impl<T> Status<T> {
    /// Convenience method to check if status is complete.
    #[inline]
    pub fn is_complete(&self) -> bool {
        match *self {
            Status::Complete(..) => true,
            Status::Partial => false,
        }
    }

    /// Convenience method to check if status is partial.
    #[inline]
    pub fn is_partial(&self) -> bool {
        match *self {
            Status::Complete(..) => false,
            Status::Partial => true,
        }
    }

    /// Convenience method to unwrap a Complete value. Panics if the status is
    /// `Partial`.
    #[inline]
    pub fn unwrap(self) -> T {
        match self {
            Status::Complete(t) => t,
            Status::Partial => panic!("Tried to unwrap Status::Partial"),
        }
    }
}

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
/// A slice position.
pub struct SlicePos {
    pub start: usize,
    pub end: usize,
}

impl SlicePos {
    pub(crate) fn reset(&mut self) {
        self.start = 0;
        self.end = 0;
    }
}

/// A parsed Request.
///
/// # Example
///
/// ```no_run
/// let buf = b"GET /404 HTTP/1.1\r\nHost:";
/// let mut req = ntex_httparse::Request::default();
/// if let Ok(ntex_httparse::Status::Complete(consumed)) = req.parse(buf) {
///     // check router for path.
///     // /404 doesn't exist? we could stop parsing
///     let _ = req.path;
/// }
/// ```
#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
pub struct Request {
    /// Parsed request's method.
    pub method: SlicePos,
    /// Parsed request's path.
    pub path: SlicePos,
    /// Parsed request's http version.
    pub version: u8,
}

impl Request {
    #[inline]
    /// Parse request
    pub fn parse(&mut self, src: &[u8]) -> Result<usize> {
        let mut bytes = Bytes::new(src);

        self.method = complete!(parse_method_inner(&mut bytes));
        self.path = complete!(parse_uri_inner(&mut bytes)).1;
        self.version = complete!(version::parse_version_inner(&mut bytes));

        newline!(bytes);
        Ok(Status::Complete(bytes.slice_pos()))
    }
}

/// A parsed Response.
#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
pub struct Response {
    /// Parsed response's http version.
    pub version: u8,
    /// Parsed response's code.
    pub code: u16,
    /// Parsed response's reason (start position, length).
    pub reason: SlicePos,
}

impl Response {
    #[inline]
    /// Parse response code and reason
    pub fn parse(&mut self, src: &[u8]) -> Result<usize> {
        let mut bytes = Bytes::new(src);

        complete!(utils::skip_empty_lines(&mut bytes));

        // version
        self.version = complete!(version::parse_version_inner(&mut bytes));
        complete!(utils::skip_empty_lines(&mut bytes));
        expect!(bytes.next() == b' ' => Err(Error::Version));
        bytes.commit();
        complete!(utils::skip_spaces(&mut bytes));

        // code
        self.code = complete!(parse_code(&mut bytes));

        // RFC7230 says there must be 'SP' and then reason-phrase, but admits
        // its only for legacy reasons. With the reason-phrase completely
        // optional (and preferred to be omitted) in HTTP2, we'll just
        // handle any response that doesn't include a reason-phrase, because
        // it's more lenient, and we don't care anyways.
        //
        // So, a SP means parse a reason-phrase.
        // A newline means go to headers.
        // Anything else we'll say is a malformed status.
        self.reason = match next!(bytes) {
            b' ' => {
                complete!(utils::skip_spaces(&mut bytes));
                bytes.commit();
                complete!(parse_reason(&mut bytes))
            }
            b'\r' => {
                expect!(bytes.next() == b'\n' => Err(Error::Status));
                bytes.commit();
                SlicePos::default()
            }
            b'\n' => {
                bytes.commit();
                SlicePos::default()
            }
            _ => return Err(Error::Status),
        };

        Ok(Status::Complete(bytes.slice_pos()))
    }
}

#[inline]
// WARNING: Exported for internal benchmarks, not fit for public consumption
pub fn parse_method(src: &[u8]) -> Result<&str> {
    let s = complete!(parse_method_inner(&mut Bytes::new(src)));
    // SAFETY: parse_method_inner verifies validity of method
    let m = unsafe { str::from_utf8_unchecked(&src[s.start..s.end]) };
    Ok(Status::Complete(m))
}

#[inline]
// WARNING: Exported for internal benchmarks, not fit for public consumption
fn parse_method_inner(bytes: &mut Bytes<'_>) -> Result<SlicePos> {
    const GET: [u8; 4] = *b"GET ";
    const POST: [u8; 4] = *b"POST";

    complete!(utils::skip_empty_lines(bytes));

    match bytes.peek_n::<4>() {
        Some(GET) => {
            // SAFETY: we matched "GET " which has 4 bytes and is ASCII
            let method = unsafe {
                bytes.advance(4); // advance cursor past "GET "
                bytes.slice_position(1)
            };
            complete!(utils::skip_spaces(bytes));
            Ok(Status::Complete(method))
        }
        // SAFETY:
        // If `bytes.peek_n...` returns a Some([u8; 4]),
        // then we are assured that `bytes` contains at least 4 bytes.
        // Thus `bytes.len() >= 4`,
        // and it is safe to peek at byte 4 with `bytes.peek_ahead(4)`.
        Some(POST) if unsafe { bytes.peek_ahead(4) } == Some(b' ') => {
            // SAFETY: we matched "POST " which has 5 bytes
            let method = unsafe {
                bytes.advance(5); // advance cursor past "POST "
                bytes.slice_position(1)
            };
            complete!(utils::skip_spaces(bytes));
            Ok(Status::Complete(method))
        }
        _ => {
            let b = next!(bytes);
            if !utils::is_method_token(b) {
                // First char must be a token char, it can't be a space which would indicate an empty token.
                return Err(Error::Token);
            }

            loop {
                let b = next!(bytes);
                if b == b' ' {
                    return Ok(Status::Complete(
                        // SAFETY: all bytes up till `i` must have been `is_method_token` and therefore also utf-8.
                        bytes.slice_position(1),
                    ));
                } else if !utils::is_method_token(b) {
                    return Err(Error::Token);
                }
            }
        }
    }
}

/// From [RFC 7230](https://tools.ietf.org/html/rfc7230):
///
/// > ```notrust
/// > reason-phrase  = *( HTAB / SP / VCHAR / obs-text )
/// > HTAB           = %x09        ; horizontal tab
/// > VCHAR          = %x21-7E     ; visible (printing) characters
/// > obs-text       = %x80-FF
/// > ```
///
/// > A.2.  Changes from RFC 2616
/// >
/// > Non-US-ASCII content in header fields and the reason phrase
/// > has been obsoleted and made opaque (the TEXT rule was removed).
#[inline]
fn parse_reason(bytes: &mut Bytes<'_>) -> Result<SlicePos> {
    let mut seen_obs_text = false;
    loop {
        let b = next!(bytes);
        if b == b'\r' {
            expect!(bytes.next() == b'\n' => Err(Error::Status));
            return Ok(Status::Complete(
                // SAFETY: (1) calling bytes.slice_skip(2) is safe, because at least two next! calls
                // advance the bytes iterator.
                // (2) calling from_utf8_unchecked is safe, because the bytes returned by slice_skip
                // were validated to be allowed US-ASCII chars by the other arms of the if/else or
                // otherwise `seen_obs_text` is true and an empty string is returned instead.
                if seen_obs_text {
                    // obs-text characters were found, so return the fallback empty string
                    bytes.commit();
                    SlicePos::default()
                } else {
                    // all bytes up till `i` must have been HTAB / SP / VCHAR
                    bytes.slice_position(2)
                },
            ));
        } else if b == b'\n' {
            return Ok(Status::Complete(
                // SAFETY: (1) calling bytes.slice_skip(1) is safe, because at least one next! call
                // advance the bytes iterator.
                // (2) see (2) of safety comment above.
                if seen_obs_text {
                    // obs-text characters were found, so return the fallback empty string
                    bytes.commit();
                    SlicePos::default()
                } else {
                    // all bytes up till `i` must have been HTAB / SP / VCHAR
                    bytes.slice_position(1)
                },
            ));
        } else if !(b == 0x09 || b == b' ' || (0x21..=0x7E).contains(&b) || b >= 0x80) {
            return Err(Error::Status);
        } else if b >= 0x80 {
            seen_obs_text = true;
        }
    }
}

#[inline]
#[allow(missing_docs)]
// WARNING: Exported for internal benchmarks, not fit for public consumption
pub fn parse_uri(src: &[u8]) -> Result<&str> {
    let mut bytes = Bytes::new(src);
    if let Status::Complete((path, _)) = parse_uri_inner(&mut bytes)? {
        Ok(Status::Complete(path))
    } else {
        Ok(Status::Partial)
    }
}

#[inline]
// WARNING: Exported for internal benchmarks, not fit for public consumption
fn parse_uri_inner<'a>(bytes: &mut Bytes<'a>) -> Result<(&'a str, SlicePos)> {
    let start = bytes.slice_pos();
    let b_start = bytes.pos();
    simd::match_uri_vectored(bytes);
    let b_end = bytes.pos();

    if next!(bytes) == b' ' {
        // URI must have at least one char
        if b_end == b_start {
            return Err(Error::Token);
        }

        // SAFETY: all bytes up till `i` must have been `is_token` and therefore also utf-8.
        let uri = unsafe { bytes.slice_skip(1) };
        if let Ok(path) = simdutf8::basic::from_utf8(uri) {
            let end = bytes.slice_pos() - 1;
            complete!(utils::skip_spaces(bytes));
            Ok(Status::Complete((path, SlicePos { start, end })))
        } else {
            Err(Error::Token)
        }
    } else {
        Err(Error::Token)
    }
}

#[inline]
fn parse_code(bytes: &mut Bytes<'_>) -> Result<u16> {
    let hundreds = expect!(bytes.next() == b'0'..=b'9' => Err(Error::Status));
    let tens = expect!(bytes.next() == b'0'..=b'9' => Err(Error::Status));
    let ones = expect!(bytes.next() == b'0'..=b'9' => Err(Error::Status));

    Ok(Status::Complete(
        (hundreds - b'0') as u16 * 100 + (tens - b'0') as u16 * 10 + (ones - b'0') as u16,
    ))
}

/// Parse a buffer of bytes as a chunk size.
///
/// The return value, if complete and successful, includes the index of the
/// buffer that parsing stopped at, and the size of the following chunk.
///
/// # Example
///
/// ```
/// let buf = b"4\r\nRust\r\n0\r\n\r\n";
/// assert_eq!(ntex_httparse::parse_chunk_size(buf),
///            Ok(ntex_httparse::Status::Complete((3, 4))));
/// ```
pub fn parse_chunk_size(buf: &[u8]) -> result::Result<Status<(usize, u64)>, InvalidChunkSize> {
    const RADIX: u64 = 16;
    let mut bytes = Bytes::new(buf);
    let mut size = 0;
    let mut in_chunk_size = true;
    let mut in_ext = false;
    let mut count = 0;
    loop {
        let b = next!(bytes);
        match b {
            b'0'..=b'9' if in_chunk_size => {
                if count > 15 {
                    return Err(InvalidChunkSize);
                }
                count += 1;
                if cfg!(debug_assertions) && size > (u64::MAX / RADIX) {
                    // actually unreachable!(), because count stops the loop at 15 digits before
                    // we can reach u64::MAX / RADIX == 0xfffffffffffffff, which requires 15 hex
                    // digits. This stops mirai reporting a false alarm regarding the `size *=
                    // RADIX` multiplication below.
                    return Err(InvalidChunkSize);
                }
                size *= RADIX;
                size += (b - b'0') as u64;
            }
            b'a'..=b'f' | b'A'..=b'F' if in_chunk_size => {
                if count > 15 {
                    return Err(InvalidChunkSize);
                }
                count += 1;
                if cfg!(debug_assertions) && size > (u64::MAX / RADIX) {
                    return Err(InvalidChunkSize);
                }
                size *= RADIX;
                size += ((b | 0x20) + 10 - b'a') as u64;
            }
            b'\r' => match next!(bytes) {
                b'\n' => break,
                _ => return Err(InvalidChunkSize),
            },
            // If we weren't in the extension yet, the ";" signals its start
            b';' if !in_ext => {
                in_ext = true;
                in_chunk_size = false;
            }
            // "Linear white space" is ignored between the chunk size and the
            // extension separator token (";") due to the "implied *LWS rule".
            b'\t' | b' ' if !in_ext && !in_chunk_size => {}
            // LWS can follow the chunk size, but no more digits can come
            b'\t' | b' ' if in_chunk_size => in_chunk_size = false,
            // We allow any arbitrary octet once we are in the extension, since
            // they all get ignored anyway. According to the HTTP spec, valid
            // extensions would have a more strict syntax:
            //     (token ["=" (token | quoted-string)])
            // but we gain nothing by rejecting an otherwise valid chunk size.
            _ if in_ext => {}
            // Finally, if we aren't in the extension and we're reading any
            // other octet, the chunk size line is invalid!
            _ => return Err(InvalidChunkSize),
        }
    }
    Ok(Status::Complete((bytes.slice_pos(), size)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::items_after_statements)]
    use super::*;

    macro_rules! req {
        ($name:ident, $buf:expr, |$len:ident, $method:ident, $path:ident, $version:ident, $headers:ident, $headers_eof:ident| $body:expr) => {
            #[test]
            fn $name() {
                let mut req = Request::default();
                let mut b = $buf.as_ref();
                if let Ok(Status::Complete(l)) = req.parse(b) {
                    let mut consumed = l;
                    let mut headers = Vec::new();
                    let mut header = Header::default();
                    let mut headers_eof = false;
                    b = &b[consumed..];

                    while let Status::Complete(hdr) = header.parse(b).unwrap() {
                        match hdr {
                            HeaderParsed::Header(l) => {
                                consumed += l;
                                let name = String::from_utf8(Vec::from(
                                    &b[header.name.start..header.name.end],
                                ))
                                .unwrap();
                                let value = Vec::from(&b[header.value.start..header.value.end]);
                                headers.push((name, value));
                                b = &b[l..];
                            }
                            HeaderParsed::Eof(l) => {
                                consumed += l;
                                headers_eof = true;
                                break;
                            }
                        }
                    }

                    // SAFETY: Request::parse() validates path
                    let (path, method) = unsafe {
                        (
                            str::from_utf8_unchecked(&$buf.as_ref()[req.path.start..req.path.end]),
                            str::from_utf8_unchecked(
                                &$buf.as_ref()[req.method.start..req.method.end],
                            ),
                        )
                    };

                    closure(consumed, method, path, req.version, headers, headers_eof);
                } else {
                    panic!()
                }

                fn closure(
                    $len: usize,
                    $method: &str,
                    $path: &str,
                    $version: u8,
                    $headers: Vec<(String, Vec<u8>)>,
                    $headers_eof: bool,
                ) {
                    $body
                }
            }
        };
    }

    macro_rules! headers {
        ($name:ident, $buf:expr, |$len:ident, $headers:ident, $headers_eof:ident| $body:expr) => {
            #[test]
            fn $name() {
                let mut b = $buf.as_ref();
                let mut consumed = 0;
                let mut headers = Vec::new();
                let mut header = Header::default();
                let mut headers_eof = false;

                while let Status::Complete(hdr) = header.parse(b).unwrap() {
                    match hdr {
                        HeaderParsed::Header(l) => {
                            consumed += l;
                            let name = String::from_utf8(Vec::from(
                                &b[header.name.start..header.name.end],
                            ))
                            .unwrap();
                            let value = Vec::from(&b[header.value.start..header.value.end]);
                            headers.push((name, value));
                            b = &b[l..];
                        }
                        HeaderParsed::Eof(l) => {
                            consumed += l;
                            headers_eof = true;
                            break;
                        }
                    }
                }
                closure(consumed, headers, headers_eof);

                fn closure($len: usize, $headers: Vec<(String, Vec<u8>)>, $headers_eof: bool) {
                    $body
                }
            }
        };
    }

    macro_rules! req_err {
        ($name:ident, $buf:expr, $err:expr) => {
            #[test]
            fn $name() {
                assert_eq!(Request::default().parse($buf.as_ref()), $err);
            }
        };
    }

    macro_rules! req_par {
        ($name:ident, $buf:expr) => {
            #[test]
            fn $name() {
                assert_eq!(Request::default().parse($buf.as_ref()), Ok(Status::Partial));
            }
        };
    }

    macro_rules! headers_err {
        ($name:ident, $buf:expr, $err:expr) => {
            #[test]
            fn $name() {
                let mut consumed = 0;
                let mut header = Header::default();

                let result = loop {
                    match header.parse(&$buf.as_ref()[consumed..]) {
                        Ok(Status::Complete(HeaderParsed::Header(l))) => {
                            consumed += l;
                        }
                        Ok(_) => break Ok(()),
                        Err(e) => break Err(e),
                    }
                };
                assert_eq!(result, $err);
            }
        };
    }

    req! {
        test_request_simple,
        b"GET / HTTP/1.1\r\n\r\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 18);
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    req! {
        test_request_simple_with_query_params,
        b"GET /thing?data=a HTTP/1.1\r\n\r\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 30);
            assert_eq!(method, "GET");
            assert_eq!(path, "/thing?data=a");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    req! {
        test_request_simple_with_whatwg_query_params,
        b"GET /thing?data=a^ HTTP/1.1\r\n\r\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 31);
            assert_eq!(method, "GET");
            assert_eq!(path, "/thing?data=a^");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    req! {
        test_request_headers,
        b"GET / HTTP/1.1\r\nHost: foo.com\r\nCookie: \r\n\r\n     ",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 43);
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 2);
            assert_eq!(headers[0].0, "Host");
            assert_eq!(headers[0].1, b"foo.com");
            assert_eq!(headers[1].0, "Cookie");
            assert_eq!(headers[1].1, b"");
            assert!(eof);
        }
    }

    req! {
        test_request_headers_optional_whitespace,
        b"GET / HTTP/1.1\r\nHost: \tfoo.com\t \r\nCookie: \t \r\n\r\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 48);
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 2);
            assert_eq!(headers[0].0, "Host");
            assert_eq!(headers[0].1, b"foo.com");
            assert_eq!(headers[1].0, "Cookie");
            assert_eq!(headers[1].1, b"");
            assert!(eof);
        }
    }

    req! {
        // test the scalar parsing
        test_request_header_value_htab_short,
        b"GET / HTTP/1.1\r\nUser-Agent: some\tagent\r\n\r\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 42);
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "User-Agent");
            assert_eq!(headers[0].1, b"some\tagent");
            assert!(eof);
        }
    }

    req! {
        // test the sse42 parsing
        test_request_header_value_htab_med,
        b"GET / HTTP/1.1\r\nUser-Agent: 1234567890some\tagent\r\n\r\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 52);
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "User-Agent");
            assert_eq!(headers[0].1, b"1234567890some\tagent");
            assert!(eof);
        }
    }

    req! {
        // test the avx2 parsing
        test_request_header_value_htab_long,
        b"GET / HTTP/1.1\r\nUser-Agent: 1234567890some\t1234567890agent1234567890\r\n\r\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 72);
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "User-Agent");
            assert_eq!(headers[0].1, &b"1234567890some\t1234567890agent1234567890"[..]);
            assert!(eof);
        }
    }

    req! {
        // test the avx2 parsing
        test_request_header_no_space_after_colon,
        b"GET / HTTP/1.1\r\nUser-Agent:omg-no-space1234567890some1234567890agent1234567890\r\n\r\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 82);
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "User-Agent");
            assert_eq!(headers[0].1, &b"omg-no-space1234567890some1234567890agent1234567890"[..]);
            assert!(eof);
        }
    }

    req! {
        test_request_headers_max,
        b"GET / HTTP/1.1\r\nA: A\r\nB: B\r\nC: C\r\nD: D\r\n\r\n",
        |_len, _method, _path, _verion, headers, eof| {
            assert_eq!(headers.len(), 4);
            assert!(eof);
        }
    }

    req! {
        test_request_multibyte,
        b"GET / HTTP/1.1\r\nHost: foo.com\r\nUser-Agent: \xe3\x81\xb2\xe3/1.0\r\n\r\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 55);
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 2);
            assert_eq!(headers[0].0, "Host");
            assert_eq!(headers[0].1, b"foo.com");
            assert_eq!(headers[1].0, "User-Agent");
            assert_eq!(headers[1].1, b"\xe3\x81\xb2\xe3/1.0");
            assert!(eof);
        }
    }

    // A single byte which is part of a method is not invalid
    req_par! {
        test_request_one_byte_method,
        b"G"
    }

    // A subset of a method is a partial method, not invalid
    req_par! {
        test_request_partial_method,
        b"GE"
    }

    // A method, without the delimiting space, is a partial request
    req_par! {
        test_request_method_no_delimiter,
        b"GET"
    }

    // Regression test: assert that a partial read with just the method and
    // space results in a partial, rather than a token error from uri parsing.
    req_par! {
        test_request_method_only,
        b"GET "
    }

    req! {
        test_request_partial,
        b"GET / HTTP/1.1\r\n\r",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, b"GET / HTTP/1.1\r\n\r".len() - 1);
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
            assert!(!eof);
        }
    }

    req_par! {
        test_request_partial_version,
        b"GET / HTTP/1."
    }

    req_par! {
        test_request_method_path_no_delimiter,
        b"GET /"
    }

    req_par! {
        test_request_method_path_only,
        b"GET / "
    }

    req! {
        test_request_partial_parses_headers_as_much_as_it_can,
        b"GET / HTTP/1.1\r\nHost: yolo\r\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 28);
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "Host");
            assert_eq!(headers[0].1, b"yolo");
            assert!(!eof);
        }
    }

    req! {
        test_request_newlines,
        b"GET / HTTP/1.1\nHost: foo.bar\n\n",
        |_len, _method, _path, _verion, _headers, eof| {
            assert!(eof);
        }
    }

    req! {
        test_request_empty_lines_prefix,
        b"\r\n\r\nGET / HTTP/1.1\r\n\r\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 22);
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    req! {
        test_request_empty_lines_prefix_lf_only,
        b"\n\nGET / HTTP/1.1\n\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 18);
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    req! {
        test_request_path_backslash,
        b"\n\nGET /\\?wayne\\=5 HTTP/1.1\n\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 28);
            assert_eq!(method, "GET");
            assert_eq!(path, "/\\?wayne\\=5");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    req_err! {
        test_request_with_invalid_token_delimiter,
        b"GET\n/ HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        Err(Error::Token)
    }

    req_err! {
        test_request_with_invalid_but_short_version,
        b"GET / HTTP/1!",
        Err(Error::Version)
    }

    req_err! {
        test_request_with_empty_method,
        b" / HTTP/1.1\r\n\r\n",
        Err(Error::Token)
    }

    req_err! {
        test_request_with_empty_path,
        b"GET  HTTP/1.1\r\n\r\n",
        Err(Error::Token)
    }

    req_err! {
        test_request_with_empty_method_and_path,
        b"  HTTP/1.1\r\n\r\n",
        Err(Error::Token)
    }

    headers! {
        test_headers_optional_whitespace,
        b"Host: \tfoo.com\t \r\nCookie: \t \r\n",
        |len, headers, eof| {
            assert_eq!(len, 30);
            assert_eq!(headers.len(), 2);
            assert_eq!(headers[0].0, "Host");
            assert_eq!(headers[0].1, b"foo.com");
            assert_eq!(headers[1].0, "Cookie");
            assert_eq!(headers[1].1, b"");
            assert!(!eof);
        }
    }

    headers_err! {
        test_headers_with_obsolete_line_folding_at_start,
        b"Line-Folded-Header: \r\n   \r\n hello there\r\n\r\n",
        Err(Error::HeaderName)
    }

    headers_err! {
        test_header_with_invalid_name,
        b"Host : foo.bar\r\n\r\n",
        Err(Error::HeaderName)
    }

    macro_rules! res {
        ($name:ident, $buf:expr, |$len:ident, $version:ident, $code:ident, $reason:ident, $headers:ident, $headers_eof:ident| $body:expr) => {
            #[test]
            fn $name() {
                let mut b = $buf.as_ref();
                let mut res = Response::default();
                let mut consumed = res.parse($buf.as_ref()).unwrap().unwrap();
                let mut headers = Vec::new();
                let mut header = Header::default();
                let mut headers_eof = false;
                b = &b[consumed..];

                while let Status::Complete(hdr) = header.parse(b).unwrap() {
                    match hdr {
                        HeaderParsed::Header(l) => {
                            consumed += l;
                            let name = String::from_utf8(Vec::from(
                                &b[header.name.start..header.name.end],
                            ))
                            .unwrap();
                            let value = Vec::from(&b[header.value.start..header.value.end]);
                            headers.push((name, value));
                            b = &b[l..];
                        }
                        HeaderParsed::Eof(l) => {
                            consumed += l;
                            headers_eof = true;
                            break;
                        }
                    }
                }

                // SAFETY: Request::parse() validates reason
                let reason = unsafe {
                    str::from_utf8_unchecked(&$buf.as_ref()[res.reason.start..res.reason.end])
                };

                closure(
                    consumed,
                    res.version,
                    res.code,
                    reason,
                    headers,
                    headers_eof,
                );

                fn closure(
                    $len: usize,
                    $version: u8,
                    $code: u16,
                    $reason: &str,
                    $headers: Vec<(String, Vec<u8>)>,
                    $headers_eof: bool,
                ) {
                    $body
                }
            }
        };
    }

    macro_rules! res_err {
        ($name:ident, $buf:expr, $err:expr) => {
            #[test]
            fn $name() {
                assert_eq!(Response::default().parse($buf.as_ref()), $err);
            }
        };
    }

    macro_rules! res_par {
        ($name:ident, $buf:expr) => {
            #[test]
            fn $name() {
                assert_eq!(
                    Response::default().parse($buf.as_ref()),
                    Ok(Status::Partial)
                );
            }
        };
    }

    res! {
        test_response_simple,
        b"HTTP/1.1 200 OK\r\n\r\n",
        |len, version, code, reason, headers, eof| {
            assert_eq!(len, 19);
            assert_eq!(version, 1);
            assert_eq!(code, 200);
            assert_eq!(reason, "OK");
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    res! {
        test_response_newlines,
        b"HTTP/1.0 403 Forbidden\nServer: foo.bar\n\n",
        |len, version, code, reason, headers, eof| {
            assert_eq!(len, 40);
            assert_eq!(version, 0);
            assert_eq!(code, 403);
            assert_eq!(reason, "Forbidden");
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "Server");
            assert_eq!(headers[0].1, b"foo.bar");
            assert!(eof);
        }
    }

    res! {
        test_response_reason_missing,
        b"HTTP/1.1 200 \r\n\r\n",
        |len, version, code, reason, headers, eof| {
            assert_eq!(len, 17);
            assert_eq!(version, 1);
            assert_eq!(code, 200);
            assert_eq!(reason, "");
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    res! {
        test_response_reason_missing_no_space,
        b"HTTP/1.1 200\r\n\r\n",
        |len, version, code, reason, headers, eof| {
            assert_eq!(len, 16);
            assert_eq!(version, 1);
            assert_eq!(code, 200);
            assert_eq!(reason, "");
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    res! {
        test_response_reason_missing_no_space_with_headers,
        b"HTTP/1.1 200\r\nFoo: bar\r\n\r\n",
        |len, version, code, reason, headers, eof| {
            assert_eq!(len, 26);
            assert_eq!(version, 1);
            assert_eq!(code, 200);
            assert_eq!(reason, "");
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "Foo");
            assert_eq!(headers[0].1, b"bar");
            assert!(eof);
        }
    }

    res! {
        test_response_reason_with_space_and_tab,
        b"HTTP/1.1 101 Switching Protocols\t\r\n\r\n",
        |len, version, code, reason, headers, eof| {
            assert_eq!(len, 37);
            assert_eq!(version, 1);
            assert_eq!(code, 101);
            assert_eq!(reason, "Switching Protocols\t");
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    res! {
        test_response_reason_with_obsolete_text_byte,
        b"HTTP/1.1 200 X\xFFZ\r\n\r\n",
        |len, version, code, reason, headers, eof| {
            assert_eq!(len, 20);
            assert_eq!(version, 1);
            assert_eq!(code, 200);
            // Empty string fallback in case of obs-text
            assert_eq!(reason, "");
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    res_err! {
        test_response_reason_with_nul_byte,
        b"HTTP/1.1 200 \x00\r\n\r\n",
        Err(crate::Error::Status)
    }

    res_par! {
        test_response_version_missing_space,
        b"HTTP/1.1"
    }

    res_par! {
         test_response_code_missing_space,
         b"HTTP/1.1 200"
    }

    res! {
        test_response_partial_parses_headers_as_much_as_it_can,
        b"HTTP/1.1 200 OK\r\nServer: yolo\r\n",
        |len, version, code, reason, headers, eof| {
            assert_eq!(len, 31);
            assert_eq!(version, 1);
            assert_eq!(code, 200);
            assert_eq!(reason, "OK");
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "Server");
            assert_eq!(headers[0].1, b"yolo");
            assert!(!eof);
        }
    }

    res! {
        test_response_empty_lines_prefix_lf_only,
        b"\n\nHTTP/1.1 200 OK\n\n",
        |len, version, code, reason, headers, eof| {
            assert_eq!(len, 19);
            assert_eq!(version, 1);
            assert_eq!(code, 200);
            assert_eq!(reason, "OK");
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    res! {
        test_response_no_cr,
        b"HTTP/1.0 200\nContent-type: text/html\n\n",
        |len, version, code, reason, headers, eof| {
            assert_eq!(len, 38);
            assert_eq!(version, 0);
            assert_eq!(code, 200);
            assert_eq!(reason, "");
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "Content-type");
            assert_eq!(headers[0].1, b"text/html");
            assert!(eof);
        }
    }

    /// Check all subset permutations of a partial request line with no headers
    #[test]
    fn partial_permutations() {
        let req_str = "GET / HTTP/1.1\r\n";
        let mut req = Request::default();
        for i in 0..req_str.len() {
            let status = req.parse(&req_str.as_bytes()[..i]);
            assert_eq!(
                status,
                Ok(Status::Partial),
                "partial request line should return partial. \
                  Portion which failed: '{seg}' (below {i})",
                seg = &req_str[..i]
            );
        }
    }

    headers_err! {
        test_forbid_headers_with_whitespace_between_header_name_and_colon,
        b"Access-Control-Allow-Credentials : true\r\nBread: baguette\r\n\r\n",
        Err(Error::HeaderName)
    }

    headers_err! {
        test_forbid_headers_with_obsolete_line_folding_at_end,
        b"Line-Folded-Header: hello there\r\n   \r\n \r\n\r\n",
        Err(Error::HeaderName)
    }

    headers_err! {
        test_forbid_headers_with_obsolete_line_folding_in_middle,
        b"Line-Folded-Header: hello  \r\n \r\n there\r\n\r\n",
        Err(Error::HeaderName)
    }

    headers_err! {
        test_forbid_headers_with_obsolete_line_folding_in_empty_header,
        b"Line-Folded-Header:   \r\n \r\n \r\n\r\n",
        Err(Error::HeaderName)
    }

    headers_err! {
        test_forbid_headers_with_empty_header_name,
        b": hello\r\nBread: baguette\r\n\r\n",
        Err(Error::HeaderName)
    }

    headers_err! {
        test_forbid_headers_with_empty_header_name_second,
        b"Bread: baguette\r\n: hello\r\n\r\n",
        Err(Error::HeaderName)
    }

    #[test]
    fn test_chunk_size() {
        assert_eq!(parse_chunk_size(b"0\r\n"), Ok(Status::Complete((3, 0))));
        assert_eq!(
            parse_chunk_size(b"12\r\nchunk"),
            Ok(Status::Complete((4, 18)))
        );
        assert_eq!(
            parse_chunk_size(b"3086d\r\n"),
            Ok(Status::Complete((7, 198_765)))
        );
        assert_eq!(
            parse_chunk_size(b"3735AB1;foo bar*\r\n"),
            Ok(Status::Complete((18, 57_891_505)))
        );
        assert_eq!(
            parse_chunk_size(b"3735ab1 ; baz \r\n"),
            Ok(Status::Complete((16, 57_891_505)))
        );
        assert_eq!(parse_chunk_size(b"77a65\r"), Ok(Status::Partial));
        assert_eq!(parse_chunk_size(b"ab"), Ok(Status::Partial));
        assert_eq!(
            parse_chunk_size(b"567f8a\rfoo"),
            Err(crate::InvalidChunkSize)
        );
        assert_eq!(
            parse_chunk_size(b"567f8a\rfoo"),
            Err(crate::InvalidChunkSize)
        );
        assert_eq!(
            parse_chunk_size(b"567xf8a\r\n"),
            Err(crate::InvalidChunkSize)
        );
        assert_eq!(
            parse_chunk_size(b"ffffffffffffffff\r\n"),
            Ok(Status::Complete((18, u64::MAX)))
        );
        assert_eq!(
            parse_chunk_size(b"1ffffffffffffffff\r\n"),
            Err(crate::InvalidChunkSize)
        );
        assert_eq!(
            parse_chunk_size(b"Affffffffffffffff\r\n"),
            Err(crate::InvalidChunkSize)
        );
        assert_eq!(
            parse_chunk_size(b"fffffffffffffffff\r\n"),
            Err(crate::InvalidChunkSize)
        );
    }

    res! {
        test_allow_response_with_multiple_space_delimiters,
        b"HTTP/1.1   200  OK\r\n\r\n",
        |len, version, code, reason, headers, eof| {
            assert_eq!(len, 22);
            assert_eq!(version, 1);
            assert_eq!(code, 200);
            assert_eq!(reason, "OK");
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    // /// This is technically allowed by the spec, but we only support multiple spaces as an option,
    // /// not stray `\r`s.
    res_err! {
        test_forbid_response_with_weird_whitespace_delimiters,
        b"HTTP/1.1 200\rOK\r\n\r\n",
        Err(Error::Status)
    }

    req! {
        test_allow_request_with_multiple_space_delimiters,
        b"GET  /    HTTP/1.1\r\n\r\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 22);
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
            assert!(eof);
        }
    }

    // /// This is technically allowed by the spec, but we only support multiple spaces as an option,
    // /// not stray `\r`s.
    req_err! {
        test_forbid_request_with_weird_whitespace_delimiters,
        b"GET\r/\rHTTP/1.1\r\n\r\n",
        Err(Error::Token)
    }

    req_err! {
        test_request_with_multiple_spaces_and_bad_path,
        b"GET   /foo ohno HTTP/1.1\r\n\r\n",
        Err(Error::Version)
    }

    // // This test ensure there is an error when there is a DEL character in the path
    // // since we allow all char from 0x21 code except DEL, this test ensure that DEL
    // // is not allowed in the path
    req_err! {
        test_request_with_del_in_path,
        b"GET   /foo\x7Fohno HTTP/1.1\r\n\r\n",
        Err(Error::Token)
    }

    // #[test]
    // #[cfg_attr(miri, ignore)] // Miri is too slow for this test
    // fn test_all_utf8_char_in_paths() {
    //     // two code points
    //     for i in 128..256 {
    //         for j in 128..256 {
    //             let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //             let mut request = Request::new(&mut headers[..]);
    //             let bytes = [i as u8, j as u8];

    //             match core::str::from_utf8(&bytes) {
    //                 Ok(s) => {
    //                     let first_line = format!("GET /{} HTTP/1.1\r\n\r\n", s);
    //                     let result = crate::ParserConfig::default()
    //                         .allow_multiple_spaces_in_request_line_delimiters(true)
    //                         .parse_request(&mut request, first_line.as_bytes());

    //                     assert_eq!(
    //                         result,
    //                         Ok(Status::Complete(20)),
    //                         "failed for utf8 char i: {}, j: {}",
    //                         i,
    //                         j
    //                     );
    //                 }
    //                 Err(_) => {
    //                     let mut first_line = b"GET /".to_vec();
    //                     first_line.extend(&bytes);
    //                     first_line.extend(b" HTTP/1.1\r\n\r\n");

    //                     let result = crate::ParserConfig::default()
    //                         .allow_multiple_spaces_in_request_line_delimiters(true)
    //                         .parse_request(&mut request, first_line.as_slice());

    //                     assert_eq!(
    //                         result,
    //                         Err(crate::Error::Token),
    //                         "failed for utf8 char i: {}, j: {}",
    //                         i,
    //                         j
    //                     );
    //                 }
    //             };

    //             // three code points starting from 0xe0
    //             if i < 0xe0 {
    //                 continue;
    //             }

    //             for k in 128..256 {
    //                 let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //                 let mut request = Request::new(&mut headers[..]);
    //                 let bytes = [i as u8, j as u8, k as u8];

    //                 match core::str::from_utf8(&bytes) {
    //                     Ok(s) => {
    //                         let first_line = format!("GET /{} HTTP/1.1\r\n\r\n", s);
    //                         let result = crate::ParserConfig::default()
    //                             .allow_multiple_spaces_in_request_line_delimiters(true)
    //                             .parse_request(&mut request, first_line.as_bytes());

    //                         assert_eq!(
    //                             result,
    //                             Ok(Status::Complete(21)),
    //                             "failed for utf8 char i: {}, j: {}, k: {}",
    //                             i,
    //                             j,
    //                             k
    //                         );
    //                     }
    //                     Err(_) => {
    //                         let mut first_line = b"GET /".to_vec();
    //                         first_line.extend(&bytes);
    //                         first_line.extend(b" HTTP/1.1\r\n\r\n");

    //                         let result = crate::ParserConfig::default()
    //                             .allow_multiple_spaces_in_request_line_delimiters(true)
    //                             .parse_request(&mut request, first_line.as_slice());

    //                         assert_eq!(
    //                             result,
    //                             Err(crate::Error::Token),
    //                             "failed for utf8 char i: {}, j: {}, k: {}",
    //                             i,
    //                             j,
    //                             k
    //                         );
    //                     }
    //                 };

    //                 // four code points starting from 0xf0
    //                 if i < 0xf0 {
    //                     continue;
    //                 }

    //                 for l in 128..256 {
    //                     let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //                     let mut request = Request::new(&mut headers[..]);
    //                     let bytes = [i as u8, j as u8, k as u8, l as u8];

    //                     match core::str::from_utf8(&bytes) {
    //                         Ok(s) => {
    //                             let first_line = format!("GET /{} HTTP/1.1\r\n\r\n", s);
    //                             let result = crate::ParserConfig::default()
    //                                 .allow_multiple_spaces_in_request_line_delimiters(true)
    //                                 .parse_request(&mut request, first_line.as_bytes());

    //                             assert_eq!(
    //                                 result,
    //                                 Ok(Status::Complete(22)),
    //                                 "failed for utf8 char i: {}, j: {}, k: {}, l: {}",
    //                                 i,
    //                                 j,
    //                                 k,
    //                                 l
    //                             );
    //                         }
    //                         Err(_) => {
    //                             let mut first_line = b"GET /".to_vec();
    //                             first_line.extend(&bytes);
    //                             first_line.extend(b" HTTP/1.1\r\n\r\n");

    //                             let result = crate::ParserConfig::default()
    //                                 .allow_multiple_spaces_in_request_line_delimiters(true)
    //                                 .parse_request(&mut request, first_line.as_slice());

    //                             assert_eq!(
    //                                 result,
    //                                 Err(crate::Error::Token),
    //                                 "failed for utf8 char i: {}, j: {}, k: {}, l: {}",
    //                                 i,
    //                                 j,
    //                                 k,
    //                                 l
    //                             );
    //                         }
    //                     };
    //                 }
    //             }
    //         }
    //     }
    // }

    res_err! {
        test_response_with_spaces_in_code,
        b"HTTP/1.1 99 200 OK\r\n\r\n",
        Err(Error::Status)
    }

    headers_err! {
        test_headers_with_whitespace_between_header_name_and_colon,
        b"Access-Control-Allow-Credentials  : true\r\nBread: baguette\r\n\r\n",
        Err(Error::HeaderName)
    }

    headers_err! {
        test_headers_with_invalid_char_between_header_name_and_colon,
        b"Access-Control-Allow-Credentials\xFF: true\r\nBread: baguette\r\n\r\n",
        Err(Error::HeaderName)
    }

    headers_err! {
        test_ignore_header_line_with_missing_colon_in_response,
        b"Access-Control-Allow-Credentials\r\nBread: baguette\r\n\r\n",
        Err(Error::HeaderName)
    }

    headers_err! {
        test_headers_header_with_missing_colon_with_folding,
        b"Access-Control-Allow-Credentials   \r\n hello\r\nBread: baguette\r\n\r\n",
        Err(Error::HeaderName)
    }

    headers_err! {
        test_headers_header_with_nul_in_header_name,
        b"Access-Control-Allow-Cred\0entials: hello\r\nBread: baguette\r\n\r\n",
        Err(Error::HeaderName)
    }

    headers_err! {
        test_header_with_cr_in_header_name,
        b"Access-Control-Allow-Cred\rentials: hello\r\nBread: baguette\r\n\r\n",
        Err(Error::HeaderName)
    }

    headers_err! {
        test_header_with_nul_in_whitespace_before_colon,
        b"Access-Control-Allow-Credentials   \0: hello\r\nBread: baguette\r\n\r\n",
        Err(Error::HeaderName)
    }

    headers_err! {
        test_header_with_nul_in_value,
        b"Access-Control-Allow-Credentials: hell\0o\r\nBread: baguette\r\n\r\n",
        Err(Error::HeaderValue)
    }

    headers_err! {
        test_header_with_invalid_char_in_value,
        b"Access-Control-Allow-Credentials: hell\x01o\r\nBread: baguette\r\n\r\n",
        Err(Error::HeaderValue)
    }

    headers_err! {
        test_header_with_invalid_char_in_value_with_folding,
        b"Access-Control-Allow-Credentials: hell\x01o  \n world!\r\nBread: baguette\r\n\r\n",
        Err(Error::HeaderValue)
    }

    headers_err! {
        test_header_with_space_before_first_header,
        b" Space-Before-Header: hello there\r\n\r\n",
        Err(Error::HeaderName)
    }

    res! {
        test_response_no_space_after_colon,
        b"HTTP/1.1 200 OK\r\nfoo:bar\r\n\r\n",
        |len, version, code, reason, headers, eof| {
            assert_eq!(len, 28);
            assert_eq!(version, 1);
            assert_eq!(code, 200);
            assert_eq!(reason, "OK");
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "foo");
            assert_eq!(headers[0].1, b"bar");
            assert!(eof);
        }
    }

    req_err! {
        test_request_with_leading_space,
        b" GET / HTTP/1.1\r\nfoo:bar\r\n\r\n",
        Err(Error::Token)
    }

    req_err! {
        test_request_with_invalid_method,
        b"P()ST / HTTP/1.1\r\nfoo:bar\r\n\r\n",
        Err(Error::Token)
    }

    req! {
        test_utf8_in_path_ok,
        b"GET /test?post=I\xE2\x80\x99msorryIforkedyou HTTP/1.1\r\nHost: example.org\r\n\r\n",
        |len, method, path, version, headers, eof| {
            assert_eq!(len, 67);
            assert_eq!(method, "GET");
            assert_eq!(path, "/test?post=I’msorryIforkedyou");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "Host");
            assert_eq!(headers[0].1, b"example.org");
            assert!(eof);
        }
    }

    req_err! {
        test_bad_utf8_in_path,
        b"GET /test?post=I\xE2msorryIforkedyou HTTP/1.1\r\nHost: example.org\r\n\r\n",
        Err(Error::Token)
    }

    #[rustfmt::skip]
    res! {
        test_response_bench,
        b"\
HTTP/1.0 200 OK\r\n\
Date: Wed, 21 Oct 2015 07:28:00 GMT\r\n\
Set-Cookie: session=60; user_id=1\r\n\r\n",
        |len, version, code, reason, headers, eof| {
            assert_eq!(len, 91);
            assert_eq!(version, 0);
            assert_eq!(code, 200);
            assert_eq!(reason, "OK");
            assert_eq!(headers.len(), 2);
            assert_eq!(headers[0].0, "Date");
            assert_eq!(headers[0].1, b"Wed, 21 Oct 2015 07:28:00 GMT");
            assert_eq!(headers[1].0, "Set-Cookie");
            assert_eq!(headers[1].1, b"session=60; user_id=1");
            assert!(eof);
        }
    }
}
