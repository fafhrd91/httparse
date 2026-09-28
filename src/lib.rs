#![deny(clippy::pedantic, clippy::missing_safety_doc)]
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]
#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![cfg_attr(test, deny(warnings))]

//! # ntex-httparse
//!
//! A push library for parsing HTTP/1.x requests and responses, used by
//! [ntex](https://crates.io/crates/ntex). It is a fork of
//! [httparse](https://crates.io/crates/httparse) with a lower level API.
//!
//! Parsers do not borrow the input. Parsed parts are returned as
//! [`SlicePos`] ranges into the buffer passed to `parse`. The start line and
//! the headers are parsed separately:
//!
//! * [`Request::parse`] or [`Response::parse`] parses the start line and
//!   returns the position right after it.
//! * [`Header::parse`] parses one header at a time, until it returns
//!   [`HeaderParsed::Eof`] for the empty line ending the header section.
//! * [`parse_chunk_size`] parses the size line of a chunked body.
//!
//! Incomplete input is not an error, the parsers return
//! [`Status::Partial`]. The `parse_with_state` variants save their progress
//! in a [`State`], so the next call with more data continues where the
//! previous one stopped instead of starting over.
//!
//! The focus is on speed and safety. Parsing is bounds-checked, unsafe code
//! is limited to the SIMD matchers in a submodule.
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
//!
//! # Example
//!
//! ```
//! use ntex_httparse::{Header, HeaderParsed, Request, Status};
//!
//! let buf = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
//!
//! let mut req = Request::default();
//! let Status::Complete(mut pos) = req.parse(buf).unwrap() else {
//!     unreachable!("the request line is complete")
//! };
//! assert_eq!(&buf[req.path.start..req.path.end], b"/index.html");
//! assert_eq!(req.version, 1);
//!
//! let mut header = Header::default();
//! loop {
//!     let src = &buf[pos..];
//!     match header.parse(src).unwrap() {
//!         Status::Complete(HeaderParsed::Header(len)) => {
//!             assert_eq!(&src[header.name.start..header.name.end], b"Host");
//!             assert_eq!(&src[header.value.start..header.value.end], b"example.com");
//!             pos += len;
//!         }
//!         Status::Complete(HeaderParsed::Eof(len)) => {
//!             pos += len;
//!             break;
//!         }
//!         // wait for more data, then parse again
//!         Status::Partial => unreachable!(),
//!     }
//! }
//! assert_eq!(&buf[pos..], b"body");
//! ```

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
    /// Unused, kept for compatibility. Headers are parsed one at a time.
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

/// Progress of a resumable parse, used by the `parse_with_state` methods.
///
/// Start with `State::default()` and pass the same `State` again, with the
/// same (possibly grown) buffer, after a [`Status::Partial`] result. Reset it
/// to default before parsing the next item from a different buffer position.
/// The fields are internal bookkeeping and should not be changed by callers.
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct State {
    /// Parser specific step.
    pub state: u8,
    /// Start of the part being parsed.
    pub start: usize,
    /// Position of the next byte to parse.
    pub cursor: usize,
}

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
/// A range of the buffer passed to `parse`, i.e. `&src[pos.start..pos.end]`.
///
/// An empty part, like an empty header value or reason phrase, is `0..0`.
pub struct SlicePos {
    /// Start of the range, inclusive.
    pub start: usize,
    /// End of the range, exclusive.
    pub end: usize,
}

impl SlicePos {
    pub(crate) fn reset(&mut self) {
        self.start = 0;
        self.end = 0;
    }
}

/// A parsed request line.
///
/// Only the request line is parsed, use [`Header`] for the headers that
/// follow it.
///
/// # Example
///
/// ```
/// use ntex_httparse::{Request, State, Status};
///
/// let mut req = Request::default();
/// let mut st = State::default();
///
/// // incomplete data, the parser remembers its progress in `st`
/// let buf = b"GET /index.html HT";
/// assert_eq!(req.parse_with_state(buf, &mut st), Ok(Status::Partial));
///
/// let buf = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
/// assert_eq!(req.parse_with_state(buf, &mut st), Ok(Status::Complete(26)));
/// assert_eq!(&buf[req.method.start..req.method.end], b"GET");
/// assert_eq!(&buf[req.path.start..req.path.end], b"/index.html");
/// ```
#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
pub struct Request {
    /// Request method, an ASCII token.
    pub method: SlicePos,
    /// Request target. May contain bytes `0x80..=0xFF`, so it is not
    /// guaranteed to be UTF-8.
    pub path: SlicePos,
    /// HTTP version, `0` for HTTP/1.0 and `1` for HTTP/1.1.
    pub version: u8,
}

impl Request {
    #[inline]
    /// Parse a request line.
    ///
    /// Returns the position right after the line ending, where the headers
    /// start. Empty lines before the request line are skipped.
    pub fn parse(&mut self, src: &[u8]) -> Result<usize> {
        let mut st = State::default();
        self.parse_with_state(src, &mut st)
    }

    #[inline]
    /// Parse a request line, resuming from `st` saved by a previous `Partial`
    /// result.
    ///
    /// `st` must come from a previous call with the same buffer (which may have
    /// grown since), or be `State::default()`. An invalid state returns
    /// `Error::Token`.
    ///
    /// Bytes accepted by earlier calls are not scanned again, so feeding the
    /// line in pieces takes linear time.
    pub fn parse_with_state(&mut self, src: &[u8], st: &mut State) -> Result<usize> {
        const EMPTY_LINES: u8 = 0;
        const METHOD: u8 = 1;
        const SPACES_BEFORE_URI: u8 = 2;
        const URI: u8 = 3;
        const SPACES_BEFORE_VERSION: u8 = 4;
        const VERSION: u8 = 5;
        const NEWLINE: u8 = 6;

        if st.state > NEWLINE || st.start > st.cursor || st.cursor > src.len() {
            return Err(Error::Token);
        }
        let mut bytes = Bytes::new(src, st);

        if bytes.st.state == EMPTY_LINES {
            complete!(utils::skip_empty_lines(&mut bytes));
            bytes.st.state = METHOD;
        }
        if bytes.st.state == METHOD {
            self.method = complete!(parse_method_inner(&mut bytes));
            bytes.st.state = SPACES_BEFORE_URI;
        }
        if bytes.st.state == SPACES_BEFORE_URI {
            complete!(utils::skip_spaces(&mut bytes));
            bytes.st.state = URI;
        }
        if bytes.st.state == URI {
            self.path = complete!(parse_uri_inner(&mut bytes));
            bytes.st.state = SPACES_BEFORE_VERSION;
        }
        if bytes.st.state == SPACES_BEFORE_VERSION {
            complete!(utils::skip_spaces(&mut bytes));
            bytes.st.state = VERSION;
        }
        if bytes.st.state == VERSION {
            // at most 8 bytes, parsed again from the start if incomplete
            let mut tmp = *bytes.st;
            self.version = complete!(version::parse_version_inner(&mut Bytes::new(src, &mut tmp)));
            *bytes.st = tmp;
            bytes.st.state = NEWLINE;
        }

        newline!(bytes);
        Ok(Status::Complete(bytes.cursor()))
    }
}

/// A parsed status line.
///
/// Only the status line is parsed, use [`Header`] for the headers that
/// follow it.
///
/// # Example
///
/// ```
/// use ntex_httparse::{Response, Status};
///
/// let buf = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
/// let mut res = Response::default();
/// assert_eq!(res.parse(buf), Ok(Status::Complete(24)));
/// assert_eq!(res.code, 404);
/// assert_eq!(&buf[res.reason.start..res.reason.end], b"Not Found");
/// ```
#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
pub struct Response {
    /// HTTP version, `0` for HTTP/1.0 and `1` for HTTP/1.1.
    pub version: u8,
    /// Status code, three digits.
    pub code: u16,
    /// Reason phrase, empty if missing. A non-empty reason is ASCII, a reason
    /// containing obs-text (bytes `0x80..=0xFF`) is returned as empty.
    pub reason: SlicePos,
}

impl Response {
    #[inline]
    /// Parse a status line.
    ///
    /// Returns the position right after the line ending, where the headers
    /// start. Empty lines before the status line are skipped. The reason
    /// phrase is optional.
    pub fn parse(&mut self, src: &[u8]) -> Result<usize> {
        let mut st = State::default();
        self.parse_with_state(src, &mut st)
    }

    #[inline]
    /// Parse a status line, resuming from `st` saved by a previous `Partial`
    /// result.
    ///
    /// `st` must come from a previous call with the same buffer (which may have
    /// grown since), or be `State::default()`. An invalid state returns
    /// `Error::Status`.
    ///
    /// Bytes accepted by earlier calls are not scanned again, so feeding the
    /// line in pieces takes linear time.
    pub fn parse_with_state(&mut self, src: &[u8], st: &mut State) -> Result<usize> {
        const EMPTY_LINES: u8 = 0;
        const VERSION: u8 = 1;
        const SPACES_BEFORE_CODE: u8 = 2;
        const CODE: u8 = 3;
        const AFTER_CODE: u8 = 4;
        const SPACES_BEFORE_REASON: u8 = 5;
        const REASON: u8 = 6;
        const REASON_OBS_TEXT: u8 = 7;

        if st.state > REASON_OBS_TEXT || st.start > st.cursor || st.cursor > src.len() {
            return Err(Error::Status);
        }
        let mut bytes = Bytes::new(src, st);

        if bytes.st.state == EMPTY_LINES {
            complete!(utils::skip_empty_lines(&mut bytes));
            bytes.st.state = VERSION;
        }
        if bytes.st.state == VERSION {
            // at most 9 bytes, parsed again from the start if incomplete
            let mut tmp = *bytes.st;
            let mut b = Bytes::new(src, &mut tmp);
            self.version = complete!(version::parse_version_inner(&mut b));
            expect!(b.next() == b' ' => Err(Error::Version));
            b.commit();
            *bytes.st = tmp;
            bytes.st.state = SPACES_BEFORE_CODE;
        }
        if bytes.st.state == SPACES_BEFORE_CODE {
            complete!(utils::skip_spaces(&mut bytes));
            bytes.st.state = CODE;
        }
        if bytes.st.state == CODE {
            // 3 bytes, parsed again from the start if incomplete
            let mut tmp = *bytes.st;
            self.code = complete!(parse_code(&mut Bytes::new(src, &mut tmp)));
            *bytes.st = tmp;
            bytes.st.state = AFTER_CODE;
        }
        if bytes.st.state == AFTER_CODE {
            // RFC7230 says there must be 'SP' and then reason-phrase, but admits
            // its only for legacy reasons. With the reason-phrase completely
            // optional (and preferred to be omitted) in HTTP2, we'll just
            // handle any response that doesn't include a reason-phrase, because
            // it's more lenient, and we don't care anyways.
            //
            // So, a SP means parse a reason-phrase.
            // A newline means go to headers.
            // Anything else we'll say is a malformed status.
            match next!(bytes) {
                b' ' => bytes.st.state = SPACES_BEFORE_REASON,
                b'\r' => {
                    expect_lf!(bytes => Err(Error::Status));
                    bytes.commit();
                    self.reason = SlicePos::default();
                    return Ok(Status::Complete(bytes.cursor()));
                }
                b'\n' => {
                    bytes.commit();
                    self.reason = SlicePos::default();
                    return Ok(Status::Complete(bytes.cursor()));
                }
                _ => return Err(Error::Status),
            }
        }
        if bytes.st.state == SPACES_BEFORE_REASON {
            complete!(utils::skip_spaces(&mut bytes));
            bytes.st.state = REASON;
        }

        let mut seen_obs_text = bytes.st.state == REASON_OBS_TEXT;
        let res = parse_reason(&mut bytes, &mut seen_obs_text);
        if seen_obs_text {
            bytes.st.state = REASON_OBS_TEXT;
        }
        self.reason = complete!(res);
        Ok(Status::Complete(bytes.cursor()))
    }
}

#[inline]
#[doc(hidden)]
/// Parse a request method. Exported for internal benchmarks, not part of the
/// public API.
pub fn parse_method(src: &[u8]) -> Result<&str> {
    let mut st = State::default();
    let mut bytes = Bytes::new(src, &mut st);
    complete!(utils::skip_empty_lines(&mut bytes));
    let s = complete!(parse_method_inner(&mut bytes));
    // SAFETY: parse_method_inner verifies validity of method
    let m = unsafe { str::from_utf8_unchecked(&src[s.start..s.end]) };
    Ok(Status::Complete(m))
}

/// Parses a method followed by a space, starting at `bytes.start()`. Bytes
/// before the cursor were accepted by a previous call.
#[inline]
fn parse_method_inner(bytes: &mut Bytes<'_, '_>) -> Result<SlicePos> {
    const GET: [u8; 4] = *b"GET ";
    const POST: [u8; 4] = *b"POST";

    if bytes.cursor() == bytes.start() {
        match bytes.peek_n::<4>() {
            Some(GET) => {
                // we matched "GET " which has 4 bytes and is ASCII
                bytes.advance(4);
                return Ok(Status::Complete(bytes.slice_position(1)));
            }
            Some(POST) if bytes.peek_ahead(4) == Some(b' ') => {
                // we matched "POST " which has 5 bytes
                bytes.advance(5);
                return Ok(Status::Complete(bytes.slice_position(1)));
            }
            _ => {}
        }
        // First char must be a token char, it can't be a space which would
        // indicate an empty token.
        if !utils::is_method_token(next!(bytes)) {
            return Err(Error::Token);
        }
    }

    loop {
        let b = next!(bytes);
        if b == b' ' {
            // all bytes are `is_method_token`, so the method is ASCII
            return Ok(Status::Complete(bytes.slice_position(1)));
        } else if !utils::is_method_token(b) {
            return Err(Error::Token);
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
///
/// Parses from `bytes.start()`, bytes before the cursor were accepted by a
/// previous call, `seen_obs_text` carries over whether they had obs-text.
#[inline]
fn parse_reason(bytes: &mut Bytes<'_, '_>, seen_obs_text: &mut bool) -> Result<SlicePos> {
    loop {
        let b = next!(bytes);
        let skip = if b == b'\r' {
            expect_lf!(bytes => Err(Error::Status));
            2
        } else if b == b'\n' {
            1
        } else if !(b == 0x09 || b == b' ' || (0x21..=0x7E).contains(&b) || b >= 0x80) {
            return Err(Error::Status);
        } else {
            if b >= 0x80 {
                *seen_obs_text = true;
            }
            continue;
        };

        // A non-empty reason contains only HTAB / SP / VCHAR, so it is
        // ASCII. With obs-text an empty reason is returned instead.
        return Ok(Status::Complete(if *seen_obs_text {
            bytes.commit();
            SlicePos::default()
        } else {
            bytes.slice_position(skip)
        }));
    }
}

#[inline]
#[doc(hidden)]
/// Parse a request target followed by a space. Exported for internal
/// benchmarks, not part of the public API.
///
/// Unlike [`Request::parse`], returns `Error::Token` if the target is not
/// valid UTF-8.
pub fn parse_uri(src: &[u8]) -> Result<&str> {
    let mut st = State::default();
    let mut bytes = Bytes::new(src, &mut st);
    if let Status::Complete(pos) = parse_uri_inner(&mut bytes)? {
        complete!(utils::skip_spaces(&mut bytes));
        if let Ok(path) = simdutf8::basic::from_utf8(&src[pos.start..pos.end]) {
            Ok(Status::Complete(path))
        } else {
            Err(Error::Token)
        }
    } else {
        Ok(Status::Partial)
    }
}

#[inline]
fn parse_uri_inner(bytes: &mut Bytes<'_, '_>) -> Result<SlicePos> {
    let start = bytes.start();
    simd::match_uri_vectored(bytes);
    let b_end = bytes.cursor();

    if next!(bytes) == b' ' {
        // URI must have at least one char
        if start == b_end {
            return Err(Error::Token);
        }

        // URI bytes may include 0x80..=0xFF, so they are not guaranteed to be UTF-8
        let end = bytes.cursor() - 1;
        bytes.commit();
        Ok(Status::Complete(SlicePos { start, end }))
    } else {
        Err(Error::Token)
    }
}

#[inline]
fn parse_code(bytes: &mut Bytes<'_, '_>) -> Result<u16> {
    let hundreds = expect!(bytes.next() == b'0'..=b'9' => Err(Error::Status));
    let tens = expect!(bytes.next() == b'0'..=b'9' => Err(Error::Status));
    let ones = expect!(bytes.next() == b'0'..=b'9' => Err(Error::Status));

    Ok(Status::Complete(
        (hundreds - b'0') as u16 * 100 + (tens - b'0') as u16 * 10 + (ones - b'0') as u16,
    ))
}

/// Parse a buffer of bytes as a chunk size line.
///
/// The return value, if complete and successful, includes the position right
/// after the line, where the chunk data starts, and the size of the chunk.
/// A size of `0` is the last chunk.
///
/// The size is 1 to 16 hex digits and the line must end with CRLF. Chunk
/// extensions are skipped, control characters other than HTAB are rejected
/// in them.
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
    let mut st = State::default();
    let mut bytes = Bytes::new(buf, &mut st);
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
            // the chunk size must have at least one digit
            b'\r' if count == 0 => return Err(InvalidChunkSize),
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
            // Control characters other than HTAB are not allowed in extensions,
            // a bare LF could be treated as the line end by other parsers.
            0x00..=0x08 | 0x0a..=0x1f | 0x7f if in_ext => return Err(InvalidChunkSize),
            // We allow any other octet once we are in the extension, since
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
    Ok(Status::Complete((bytes.cursor(), size)))
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

    #[test]
    fn test_headers_with_state() {
        const B1: &[u8] = b"Host";
        const B2: &[u8] = b"Host: \t";
        const B3: &[u8] = b"Host: \tfoo.com\t ";
        const B4: &[u8] = b"Host: \tfoo.com\t \r\nCoo";
        const B5: &[u8] = b"Host: \tfoo.com\t \r\nCookie: \t \r\n\r\n";

        let mut st = State::default();
        let mut header = Header::default();
        assert!(header.parse_with_state(B1, &mut st).unwrap().is_partial());
        assert_eq!(st.state, 1);
        assert_eq!(st.start, 0);
        assert_eq!(st.cursor, 4);
        assert_eq!(header.name, SlicePos { start: 0, end: 0 });
        assert!(header.parse_with_state(B2, &mut st).unwrap().is_partial());
        assert_eq!(st.state, 2);
        assert_eq!(st.start, 0);
        assert_eq!(st.cursor, 7);
        assert_eq!(header.name, SlicePos { start: 0, end: 4 });
        assert_eq!(&B5[header.name.start..header.name.end], b"Host");

        assert!(header.parse_with_state(B3, &mut st).unwrap().is_partial());
        assert_eq!(st.state, 3);
        assert_eq!(st.start, 0);
        assert_eq!(st.cursor, 16);
        assert_eq!(header.name, SlicePos { start: 0, end: 4 });
        assert_eq!(header.value, SlicePos { start: 7, end: 0 });

        assert!(header.parse_with_state(B4, &mut st).unwrap().is_complete());
        assert_eq!(st.state, 0);
        assert_eq!(st.start, 18);
        assert_eq!(st.cursor, 18);
        assert_eq!(header.value, SlicePos { start: 7, end: 14 });
        assert_eq!(&B5[header.value.start..header.value.end], b"foo.com");

        assert!(header.parse_with_state(B5, &mut st).unwrap().is_complete());
        assert_eq!(st.state, 0);
        assert_eq!(st.start, 30);
        assert_eq!(st.cursor, 30);
        assert_eq!(header.name, SlicePos { start: 18, end: 24 });
        assert_eq!(header.value, SlicePos { start: 0, end: 0 });
        assert_eq!(&B5[header.name.start..header.name.end], b"Cookie");
        assert_eq!(&B5[header.value.start..header.value.end], b"");

        assert_eq!(
            header.parse_with_state(B5, &mut st),
            Ok(Status::Complete(HeaderParsed::Eof(32)))
        );
        assert_eq!(st.state, 0);
        assert_eq!(st.start, 32);
        assert_eq!(st.cursor, 32);
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

    res_err! {
        test_response_newline_after_version,
        b"HTTP/1.1\r\n\r\n 200 OK\r\n\r\n",
        Err(Error::Version)
    }

    res_err! {
        test_response_bare_newline_after_version,
        b"HTTP/1.1\n 200 OK\r\n\r\n",
        Err(Error::Version)
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

    #[test]
    fn test_chunk_size_empty() {
        for buf in [&b"\r\n"[..], b";a\r\n", b" \r\n", b"\t;a\r\n", b"\r"] {
            assert_eq!(
                parse_chunk_size(buf),
                Err(crate::InvalidChunkSize),
                "{buf:?}"
            );
        }
        assert_eq!(parse_chunk_size(b"0\r\n"), Ok(Status::Complete((3, 0))));
    }

    // Feeds every prefix of `buf` to the resumable parser and checks that the
    // result matches parsing the whole buffer at once.
    fn header_split(buf: &[u8]) -> (Result<HeaderParsed>, Header) {
        let mut one = Header::default();
        let expected = one.parse(buf);
        for split in 0..buf.len() {
            let mut h = Header::default();
            let mut st = State::default();
            let first = h.parse_with_state(&buf[..split], &mut st);
            if first.is_err() {
                assert_eq!(first, expected, "split {split} of {buf:?}");
                continue;
            }
            assert_eq!(first, Ok(Status::Partial), "split {split} of {buf:?}");
            let res = h.parse_with_state(buf, &mut st);
            assert_eq!(res, expected, "split {split} of {buf:?}");
            if expected.is_ok() {
                assert_eq!(h, one, "split {split} of {buf:?}");
            }
        }
        (expected, one)
    }

    #[test]
    fn test_header_split_bare_cr() {
        assert_eq!(header_split(b"X: a\rb\r\n").0, Err(Error::HeaderValue));
        assert_eq!(header_split(b"X:\rb\r\n").0, Err(Error::HeaderValue));
        assert_eq!(header_split(b"\rX: b\r\n").0, Err(Error::NewLine));

        let (res, h) = header_split(b"X: a b\r\n");
        assert_eq!(res, Ok(Status::Complete(HeaderParsed::Header(8))));
        assert_eq!(h.value, SlicePos { start: 3, end: 6 });
        assert_eq!(
            header_split(b"X:\r\n").0,
            Ok(Status::Complete(HeaderParsed::Header(4)))
        );
        assert_eq!(
            header_split(b"\r\n").0,
            Ok(Status::Complete(HeaderParsed::Eof(2)))
        );
    }

    #[test]
    fn test_request_split() {
        for buf in [
            &b"GET /path HTTP/1.1\r\n"[..],
            b"GET  /path   HTTP/1.1\r\n",
            b"PUT /path HTTP/1.0\n",
            b"CUSTOM  /path HTTP/1.1\r\n",
            b"\r\n\nPOST /path HTTP/1.1\r\n",
            b"GET /path HTTP/1.1\r\r\n",
            b"GET /path HTTP/1.1\rX",
            b"\rGET /path HTTP/1.1\r\n",
            b"GE\x00T /path HTTP/1.1\r\n",
            b"GET /pa\x7fth HTTP/1.1\r\n",
            b"GET /path HTTP/2.0\r\n",
        ] {
            check_split(buf, Request::parse_with_state, Request::parse);
        }
    }

    #[test]
    fn test_response_split() {
        for buf in [
            &b"HTTP/1.1 200 OK\r\n"[..],
            b"HTTP/1.0 404  Not Found \n",
            b"\r\nHTTP/1.1 200\r\n",
            b"HTTP/1.1 200\n",
            b"HTTP/1.1   200 \r\n",
            b"HTTP/1.1 200 caf\xc3\xa9\r\n",
            b"HTTP/1.1 200 OK\r\r\n",
            b"HTTP/1.1 200\rX",
            b"HTTP/1.1 2x0 OK\r\n",
            b"HTTP/1.1\r\n200 OK\r\n",
            b"HTTP/1.1 200 O\x00K\r\n",
        ] {
            check_split(buf, Response::parse_with_state, Response::parse);
        }
    }

    // Feeds `buf` split at every position, and byte by byte, to the resumable
    // parser and checks that the result matches parsing it at once.
    fn check_split<T: Default + PartialEq + fmt::Debug>(
        buf: &[u8],
        parse: fn(&mut T, &[u8], &mut State) -> Result<usize>,
        one_shot: fn(&mut T, &[u8]) -> Result<usize>,
    ) {
        let mut one = T::default();
        let expected = one_shot(&mut one, buf);
        let check = |res: Result<usize>, v: &T, what: &str| {
            assert_eq!(res, expected, "{what} of {buf:?}");
            if expected.is_ok() {
                assert_eq!(v, &one, "{what} of {buf:?}");
            }
        };

        for split in 0..buf.len() {
            let mut v = T::default();
            let mut st = State::default();
            let first = parse(&mut v, &buf[..split], &mut st);
            if first.is_err() {
                check(first, &v, &format!("split {split}"));
                continue;
            }
            assert_eq!(first, Ok(Status::Partial), "split {split} of {buf:?}");
            let res = parse(&mut v, buf, &mut st);
            check(res, &v, &format!("split {split}"));
        }

        let mut v = T::default();
        let mut st = State::default();
        for len in 0..=buf.len() {
            let res = parse(&mut v, &buf[..len], &mut st);
            if res != Ok(Status::Partial) || len == buf.len() {
                check(res, &v, &format!("byte by byte, len {len}"));
                break;
            }
            // accepted input is not scanned again, except the version and the
            // status code, at most 9 bytes
            assert!(st.cursor + 9 >= len, "len {len} of {buf:?}");
        }
    }

    #[test]
    fn test_request_resumes_long_method() {
        let buf = [b'A'; 4096];
        let mut req = Request::default();
        let mut st = State::default();
        assert_eq!(req.parse_with_state(&buf, &mut st), Ok(Status::Partial));
        assert_eq!((st.state, st.start, st.cursor), (1, 0, 4096));
    }

    #[test]
    fn test_header_name_chars_at_every_position() {
        // covers the scalar prefix, the SIMD blocks and the tail
        for len in [1, 15, 16, 17, 31, 32, 33, 47, 48, 70] {
            for pos in 1..len {
                for b in 0..=255_u8 {
                    let mut buf = vec![b'x'; len];
                    buf[pos] = b;
                    buf.extend_from_slice(b": v\r\n");
                    let res = Header::default().parse(&buf);
                    if utils::TOKEN_MAP[b as usize] {
                        assert_eq!(
                            res,
                            Ok(Status::Complete(HeaderParsed::Header(len + 5))),
                            "len {len} pos {pos} byte {b}"
                        );
                    } else if b == b':' {
                        assert!(res.is_ok(), "len {len} pos {pos}");
                    } else {
                        assert_eq!(res, Err(Error::HeaderName), "len {len} pos {pos} byte {b}");
                    }
                }
            }
        }
    }

    #[test]
    fn test_header_state_reuse() {
        let buf = b"A: 1\r\nB: 2\r\n\r\nbody";
        let mut h = Header::default();
        let mut st = State::default();
        assert_eq!(
            h.parse_with_state(buf, &mut st),
            Ok(Status::Complete(HeaderParsed::Header(6)))
        );
        assert_eq!(
            h.parse_with_state(buf, &mut st),
            Ok(Status::Complete(HeaderParsed::Header(12)))
        );
        assert_eq!((h.name.start, h.value.end), (6, 10));
        assert_eq!(
            h.parse_with_state(buf, &mut st),
            Ok(Status::Complete(HeaderParsed::Eof(14)))
        );
    }

    #[test]
    fn test_invalid_state() {
        for st in [
            State {
                state: 3,
                start: 0,
                cursor: 100,
            },
            State {
                state: 1,
                start: 2,
                cursor: 1,
            },
            State {
                state: 8,
                start: 0,
                cursor: 0,
            },
        ] {
            let mut s = st;
            assert_eq!(
                Header::default().parse_with_state(b"abc", &mut s),
                Err(Error::HeaderName)
            );
            let mut s = st;
            assert_eq!(
                Request::default().parse_with_state(b"abc", &mut s),
                Err(Error::Token)
            );
            let mut s = st;
            assert_eq!(
                Response::default().parse_with_state(b"abc", &mut s),
                Err(Error::Status)
            );
        }
    }

    #[test]
    fn test_chunk_size_extension_control_chars() {
        for buf in [
            &b"4;a\nX\r\n"[..],
            b"4;a=\"\nX\"\r\n",
            b"4;a\x00\r\n",
            b"4;a\x7f\r\n",
            b"4;\n",
        ] {
            assert_eq!(
                parse_chunk_size(buf),
                Err(crate::InvalidChunkSize),
                "{buf:?}"
            );
        }
        assert_eq!(
            parse_chunk_size(b"4 ;a=\"b\tc \x80\";d\t\r\n"),
            Ok(Status::Complete((17, 4)))
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

    #[test]
    fn test_bad_utf8_in_path() {
        const BUF: &[u8] =
            b"GET /test?post=I\xE2msorryIforkedyou HTTP/1.1\r\nHost: example.org\r\n\r\n";

        let mut req = Request::default();
        assert!(req.parse(BUF).unwrap().is_complete());
        assert!(str::from_utf8(&BUF[req.path.start..req.path.end]).is_err());
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
