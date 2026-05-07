#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(clippy::missing_safety_doc, clippy::undocumented_unsafe_blocks)]
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

use crate::iter::Bytes;

mod iter;
#[macro_use]
mod macros;
mod simd;

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
fn is_method_token(b: u8) -> bool {
    match b {
        // For the majority case, this can be faster than the table lookup.
        b'A'..=b'Z' => true,
        _ => TOKEN_MAP[b as usize],
    }
}

// char codes to accept URI string.
// i.e. b'!' <= char and char != 127
// TODO: Make a stricter checking for URI string?
static URI_MAP: [bool; 256] = byte_map!(
    b'!'..=0x7e | 0x80..=0xFF
);

#[inline]
pub(crate) fn is_uri_token(b: u8) -> bool {
    URI_MAP[b as usize]
}

static TOKEN_MAP: [bool; 256] = byte_map!(
    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' |  b'*' | b'+' |
    b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
);

#[inline]
pub(crate) fn is_header_name_token(b: u8) -> bool {
    TOKEN_MAP[b as usize]
}

static HEADER_VALUE_MAP: [bool; 256] = byte_map!(
    b'\t' | b' '..=0x7e | 0x80..=0xFF
);

#[inline]
pub(crate) fn is_header_value_token(b: u8) -> bool {
    HEADER_VALUE_MAP[b as usize]
}

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
    fn description_str(&self) -> &'static str {
        match *self {
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

/// Parser configuration.
#[derive(Clone, Debug, Default)]
pub struct ParserConfig {
    allow_spaces_after_header_name_in_responses: bool,
    allow_obsolete_multiline_headers_in_responses: bool,
    allow_multiple_spaces_in_request_line_delimiters: bool,
    allow_multiple_spaces_in_response_status_delimiters: bool,
    allow_space_before_first_header_name: bool,
    ignore_invalid_headers_in_responses: bool,
    ignore_invalid_headers_in_requests: bool,
}

impl ParserConfig {
    /// Sets whether spaces and tabs should be allowed after header names in responses.
    pub fn allow_spaces_after_header_name_in_responses(&mut self, value: bool) -> &mut Self {
        self.allow_spaces_after_header_name_in_responses = value;
        self
    }

    /// Sets whether multiple spaces are allowed as delimiters in request lines.
    ///
    /// # Background
    ///
    /// The [latest version of the HTTP/1.1 spec][spec] allows implementations to parse multiple
    /// whitespace characters in place of the `SP` delimiters in the request line, including:
    ///
    /// > SP, HTAB, VT (%x0B), FF (%x0C), or bare CR
    ///
    /// This option relaxes the parser to allow for multiple spaces, but does *not* allow the
    /// request line to contain the other mentioned whitespace characters.
    ///
    /// [spec]: https://httpwg.org/http-core/draft-ietf-httpbis-messaging-latest.html#rfc.section.3.p.3
    pub fn allow_multiple_spaces_in_request_line_delimiters(&mut self, value: bool) -> &mut Self {
        self.allow_multiple_spaces_in_request_line_delimiters = value;
        self
    }

    /// Whether multiple spaces are allowed as delimiters in request lines.
    pub fn multiple_spaces_in_request_line_delimiters_are_allowed(&self) -> bool {
        self.allow_multiple_spaces_in_request_line_delimiters
    }

    /// Sets whether multiple spaces are allowed as delimiters in response status lines.
    ///
    /// # Background
    ///
    /// The [latest version of the HTTP/1.1 spec][spec] allows implementations to parse multiple
    /// whitespace characters in place of the `SP` delimiters in the response status line,
    /// including:
    ///
    /// > SP, HTAB, VT (%x0B), FF (%x0C), or bare CR
    ///
    /// This option relaxes the parser to allow for multiple spaces, but does *not* allow the status
    /// line to contain the other mentioned whitespace characters.
    ///
    /// [spec]: https://httpwg.org/http-core/draft-ietf-httpbis-messaging-latest.html#rfc.section.4.p.3
    pub fn allow_multiple_spaces_in_response_status_delimiters(
        &mut self,
        value: bool,
    ) -> &mut Self {
        self.allow_multiple_spaces_in_response_status_delimiters = value;
        self
    }

    /// Whether multiple spaces are allowed as delimiters in response status lines.
    pub fn multiple_spaces_in_response_status_delimiters_are_allowed(&self) -> bool {
        self.allow_multiple_spaces_in_response_status_delimiters
    }

    /// Sets whether obsolete multiline headers should be allowed.
    ///
    /// This is an obsolete part of HTTP/1. Use at your own risk. If you are
    /// building an HTTP library, the newlines (`\r` and `\n`) should be
    /// replaced by spaces before handing the header value to the user.
    ///
    /// # Example
    ///
    /// ```rust
    /// let buf = b"HTTP/1.1 200 OK\r\nFolded-Header: hello\r\n there \r\n\r\n";
    /// let mut headers = [httparse::EMPTY_HEADER; 16];
    /// let mut response = httparse::Response::new(&mut headers);
    ///
    /// let res = httparse::ParserConfig::default()
    ///     .allow_obsolete_multiline_headers_in_responses(true)
    ///     .parse_response(&mut response, buf);
    ///
    /// assert_eq!(res, Ok(httparse::Status::Complete(buf.len())));
    ///
    /// assert_eq!(response.headers.len(), 1);
    /// assert_eq!(response.headers[0].0, "Folded-Header");
    /// assert_eq!(response.headers[0].1, b"hello\r\n there");
    /// ```
    pub fn allow_obsolete_multiline_headers_in_responses(&mut self, value: bool) -> &mut Self {
        self.allow_obsolete_multiline_headers_in_responses = value;
        self
    }

    /// Whether obsolete multiline headers should be allowed.
    pub fn obsolete_multiline_headers_in_responses_are_allowed(&self) -> bool {
        self.allow_obsolete_multiline_headers_in_responses
    }

    /// Sets whether white space before the first header is allowed
    ///
    /// This is not allowed by spec but some browsers ignore it. So this an option for
    /// compatibility.
    /// See https://github.com/curl/curl/issues/11605 for reference
    /// # Example
    ///
    /// ```rust
    /// let buf = b"HTTP/1.1 200 OK\r\n Space-Before-Header: hello there\r\n\r\n";
    /// let mut headers = [httparse::EMPTY_HEADER; 1];
    /// let mut response = httparse::Response::new(&mut headers[..]);
    /// let result = httparse::ParserConfig::default()
    ///     .allow_space_before_first_header_name(true)
    ///     .parse_response(&mut response, buf);
    ///
    /// assert_eq!(result, Ok(httparse::Status::Complete(buf.len())));
    /// assert_eq!(response.version.unwrap(), 1);
    /// assert_eq!(response.code.unwrap(), 200);
    /// assert_eq!(response.reason.unwrap(), "OK");
    /// assert_eq!(response.headers.len(), 1);
    /// assert_eq!(response.headers[0].0, "Space-Before-Header");
    /// assert_eq!(response.headers[0].1, &b"hello there"[..]);
    /// ```
    pub fn allow_space_before_first_header_name(&mut self, value: bool) -> &mut Self {
        self.allow_space_before_first_header_name = value;
        self
    }

    /// Whether white space before first header is allowed or not
    pub fn space_before_first_header_name_are_allowed(&self) -> bool {
        self.allow_space_before_first_header_name
    }

    /// Sets whether invalid header lines should be silently ignored in responses.
    ///
    /// This mimicks the behaviour of major browsers. You probably don't want this.
    /// You should only want this if you are implementing a proxy whose main
    /// purpose is to sit in front of browsers whose users access arbitrary content
    /// which may be malformed, and they expect everything that works without
    /// the proxy to keep working with the proxy.
    ///
    /// This option will prevent `ParserConfig::parse_response` from returning
    /// an error encountered when parsing a header, except if the error was caused
    /// by the character NUL (ASCII code 0), as Chrome specifically always reject
    /// those, or if the error was caused by a lone character `\r`, as Firefox and
    /// Chrome behave differently in that case.
    ///
    /// The ignorable errors are:
    /// * empty header names;
    /// * characters that are not allowed in header names, except for `\0` and `\r`;
    /// * when `allow_spaces_after_header_name_in_responses` is not enabled,
    ///   spaces and tabs between the header name and the colon;
    /// * missing colon between header name and value;
    /// * when `allow_obsolete_multiline_headers_in_responses` is not enabled,
    ///   headers using obsolete line folding.
    /// * characters that are not allowed in header values except for `\0` and `\r`.
    ///
    /// If an ignorable error is encountered, the parser tries to find the next
    /// line in the input to resume parsing the rest of the headers. As lines
    /// contributing to a header using obsolete line folding always start
    /// with whitespace, those will be ignored too. An error will be emitted
    /// nonetheless if it finds `\0` or a lone `\r` while looking for the
    /// next line.
    pub fn ignore_invalid_headers_in_responses(&mut self, value: bool) -> &mut Self {
        self.ignore_invalid_headers_in_responses = value;
        self
    }

    /// Sets whether invalid header lines should be silently ignored in requests.
    pub fn ignore_invalid_headers_in_requests(&mut self, value: bool) -> &mut Self {
        self.ignore_invalid_headers_in_requests = value;
        self
    }
}

#[inline]
fn skip_empty_lines(bytes: &mut Bytes<'_>) -> Result<()> {
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
fn skip_spaces(bytes: &mut Bytes<'_>) -> Result<()> {
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

#[inline]
/// Parse response code and reason
pub fn parse_request<'b>(src: &'b [u8]) -> Result<(usize, &'b str, &'b str, u8)> {
    let mut bytes = Bytes::new(src);

    let method = complete!(parse_method(&mut bytes));
    let path = complete!(parse_uri(&mut bytes));
    let version = complete!(parse_version(&mut bytes));
    newline!(bytes);
    Ok(Status::Complete((bytes.slice_pos(), method, path, version)))
}

#[inline]
/// Parse response code and reason
pub fn parse_response<'b>(buf: &'b [u8]) -> Result<(usize, u8, u16, &'b str)> {
    let mut bytes = Bytes::new(buf);

    complete!(skip_empty_lines(&mut bytes));
    let version = complete!(parse_version(&mut bytes));
    complete!(skip_empty_lines(&mut bytes));
    space!(bytes or Error::Version);
    complete!(skip_spaces(&mut bytes));
    let code = complete!(parse_code(&mut bytes));

    // RFC7230 says there must be 'SP' and then reason-phrase, but admits
    // its only for legacy reasons. With the reason-phrase completely
    // optional (and preferred to be omitted) in HTTP2, we'll just
    // handle any response that doesn't include a reason-phrase, because
    // it's more lenient, and we don't care anyways.
    //
    // So, a SP means parse a reason-phrase.
    // A newline means go to headers.
    // Anything else we'll say is a malformed status.
    let reason = match next!(bytes) {
        b' ' => {
            complete!(skip_spaces(&mut bytes));
            bytes.slice();
            complete!(parse_reason(&mut bytes))
        }
        b'\r' => {
            expect!(bytes.next() == b'\n' => Err(Error::Status));
            bytes.slice();
            ""
        }
        b'\n' => {
            bytes.slice();
            ""
        }
        _ => return Err(Error::Status),
    };

    Ok(Status::Complete((bytes.slice_pos(), version, code, reason)))
}

/// Represents a parsed header.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Header {
    /// The name portion of a header.
    ///
    /// A header name must be valid ASCII-US, so it's safe to store as a `&str`.
    pub name_start: usize,
    pub name_end: usize,
    /// The value portion of a header.
    ///
    /// While headers **should** be ASCII-US, the specification allows for
    /// values that may not be, and so the value is stored as bytes.
    pub value_start: usize,
    pub value_end: usize,
}

#[inline]
#[allow(missing_docs)]
// WARNING: Exported for internal benchmarks, not fit for public consumption
pub fn parse_version<'a>(bytes: &mut Bytes<'a>) -> Result<u8> {
    if let Some(eight) = bytes.peek_n::<[u8; 8]>(8) {
        const H10: u64 = u64::from_ne_bytes(*b"HTTP/1.0");
        const H11: u64 = u64::from_ne_bytes(*b"HTTP/1.1");
        // SAFETY: peek_n(8) before ensure within bounds
        unsafe {
            bytes.advance(8);
        }
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

#[inline]
#[doc(hidden)]
#[allow(missing_docs)]
// WARNING: Exported for internal benchmarks, not fit for public consumption
fn parse_method<'a>(mut bytes: &mut Bytes<'a>) -> Result<&'a str> {
    complete!(skip_empty_lines(bytes));

    const GET: [u8; 4] = *b"GET ";
    const POST: [u8; 4] = *b"POST";
    match bytes.peek_n::<[u8; 4]>(4) {
        Some(GET) => {
            // SAFETY: we matched "GET " which has 4 bytes and is ASCII
            let method = unsafe {
                bytes.advance(4); // advance cursor past "GET "
                str::from_utf8_unchecked(bytes.slice_skip(1)) // "GET" without space
            };
            complete!(skip_spaces(bytes));
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
                str::from_utf8_unchecked(bytes.slice_skip(1)) // "POST" without space
            };
            complete!(skip_spaces(bytes));
            Ok(Status::Complete(method))
        }
        _ => parse_token(&mut bytes),
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
fn parse_reason<'a>(bytes: &mut Bytes<'a>) -> Result<&'a str> {
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
                unsafe {
                    let bytes = bytes.slice_skip(2);
                    if !seen_obs_text {
                        // all bytes up till `i` must have been HTAB / SP / VCHAR
                        str::from_utf8_unchecked(bytes)
                    } else {
                        // obs-text characters were found, so return the fallback empty string
                        ""
                    }
                },
            ));
        } else if b == b'\n' {
            return Ok(Status::Complete(
                // SAFETY: (1) calling bytes.slice_skip(1) is safe, because at least one next! call
                // advance the bytes iterator.
                // (2) see (2) of safety comment above.
                unsafe {
                    let bytes = bytes.slice_skip(1);
                    if !seen_obs_text {
                        // all bytes up till `i` must have been HTAB / SP / VCHAR
                        str::from_utf8_unchecked(bytes)
                    } else {
                        // obs-text characters were found, so return the fallback empty string
                        ""
                    }
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
fn parse_token<'a>(bytes: &mut Bytes<'a>) -> Result<&'a str> {
    let b = next!(bytes);
    if !is_method_token(b) {
        // First char must be a token char, it can't be a space which would indicate an empty token.
        return Err(Error::Token);
    }

    loop {
        let b = next!(bytes);
        if b == b' ' {
            return Ok(Status::Complete(
                // SAFETY: all bytes up till `i` must have been `is_method_token` and therefore also utf-8.
                unsafe { str::from_utf8_unchecked(bytes.slice_skip(1)) },
            ));
        } else if !is_method_token(b) {
            return Err(Error::Token);
        }
    }
}

#[inline]
#[allow(missing_docs)]
// WARNING: Exported for internal benchmarks, not fit for public consumption
fn parse_uri<'a>(bytes: &mut Bytes<'a>) -> Result<&'a str> {
    let start = bytes.pos();
    simd::match_uri_vectored(bytes);
    let end = bytes.pos();

    if next!(bytes) == b' ' {
        // URI must have at least one char
        if end == start {
            return Err(Error::Token);
        }

        // SAFETY: all bytes up till `i` must have been `is_token` and therefore also utf-8.
        match str::from_utf8(unsafe { bytes.slice_skip(1) }) {
            Ok(uri) => {
                complete!(skip_spaces(bytes));
                Ok(Status::Complete(uri))
            }
            Err(_) => Err(Error::Token),
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

/// Parse a buffer of bytes as headers.
///
/// The return value, if complete and successful, includes the index of the
/// buffer that parsing stopped at, and a sliced reference to the parsed
/// headers. The length of the slice will be equal to the number of properly
/// parsed headers.
///
/// # Example
///
/// ```
/// let buf = b"Host: foo.bar\nAccept: */*\n\nblah blah";
/// let mut headers = [httparse::EMPTY_HEADER; 4];
/// assert_eq!(httparse::parse_headers(buf, &mut headers),
///            Ok(httparse::Status::Complete((27, &[
///                httparse::Header { name: "Host", value: b"foo.bar" },
///                httparse::Header { name: "Accept", value: b"*/*" }
///            ][..]))));
/// ```
pub fn parse_header(src: &[u8]) -> Result<(usize, Option<Header>)> {
    let mut bytes = Bytes::new(src);
    parse_header_iter_uninit(&mut bytes, &HeaderParserConfig::default())
}

#[derive(Clone, Debug, Default)]
struct HeaderParserConfig {
    allow_spaces_after_header_name: bool,
    allow_obsolete_multiline_headers: bool,
}

/* Function which parsers headers into uninitialized buffer.
 *
 * Guarantees that it doesn't write garbage, so casting
 * &mut &mut [Header] -> &mut &mut [MaybeUninit<Header>]
 * is safe here.
 *
 * Also it promises `headers` get shrunk to number of initialized headers,
 * so casting the other way around after calling this function is safe
 */
fn parse_header_iter_uninit<'a>(
    bytes: &mut Bytes<'a>,
    config: &HeaderParserConfig,
) -> Result<(usize, Option<Header>)> {
    // Track starting pointer to calculate the number of bytes parsed.
    let start = bytes.as_ref().as_ptr() as usize;
    let mut header = Header::default();

    macro_rules! maybe_continue_after_obsolete_line_folding {
        ($bytes:ident, $label:lifetime) => {
            if config.allow_obsolete_multiline_headers {
                match $bytes.peek() {
                    None => {
                        // Next byte may be a space, in which case that header
                        // is using obsolete line folding, so we may have more
                        // whitespace to skip after colon.
                        return Ok(Status::Partial);
                    }
                    Some(b' ') | Some(b'\t') => {
                        // The space will be consumed next iteration.
                        continue $label;
                    }
                    _ => {
                        // There is another byte after the end of the line,
                        // but it's not whitespace, so it's probably another
                        // header or the final line return. This header is thus
                        // empty.
                    },
                }
            }
        }
    }

    loop {
        // Return the error `$err` if `ignore_invalid_headers_in_responses`
        // is false, otherwise find the end of the current line and resume
        // parsing on the next one.
        macro_rules! handle_invalid_char {
            ($bytes:ident, $b:ident, $err:ident) => {
                return Err(Error::$err);
            };
        }

        // a newline here means the head is over!
        let b = next!(bytes);
        if b == b'\r' {
            expect!(bytes.next() == b'\n' => Err(Error::NewLine));
            let end = bytes.as_ref().as_ptr() as usize;
            return Ok(Status::Complete((end - start, None)));
        }
        if b == b'\n' {
            let end = bytes.as_ref().as_ptr() as usize;
            return Ok(Status::Complete((end - start, None)));
        }
        if !is_header_name_token(b) {
            handle_invalid_char!(bytes, b, HeaderName);
        }

        header.name_start = bytes.slice_pos() - 1;

        #[allow(clippy::never_loop)]
        // parse header name until colon
        'name: loop {
            simd::match_header_name_vectored(bytes);
            let mut b = next!(bytes);

            // SAFETY: previously bumped by 1 with next! -> always safe.
            header.name_end = bytes.slice_pos() - 1;
            bytes.commit();

            if b == b':' {
                break 'name;
            }

            if config.allow_spaces_after_header_name {
                while b == b' ' || b == b'\t' {
                    b = next!(bytes);

                    if b == b':' {
                        bytes.commit();
                        break 'name;
                    }
                }
            }

            handle_invalid_char!(bytes, b, HeaderName);
        }

        let mut b;

        #[allow(clippy::never_loop)]
        let value_slice = 'value: loop {
            // eat white space between colon and value
            'whitespace_after_colon: loop {
                b = next!(bytes);
                if b == b' ' || b == b'\t' {
                    bytes.slice();
                    continue 'whitespace_after_colon;
                }
                if is_header_value_token(b) {
                    break 'whitespace_after_colon;
                }

                if b == b'\r' {
                    expect!(bytes.next() == b'\n' => Err(Error::HeaderValue));
                } else if b != b'\n' {
                    handle_invalid_char!(bytes, b, HeaderValue);
                }

                maybe_continue_after_obsolete_line_folding!(bytes, 'whitespace_after_colon);

                let whitespace_slice = bytes.slice();

                // This produces an empty slice that points to the beginning
                // of the whitespace.
                break 'value &whitespace_slice[0..0];
            }

            header.value_start = bytes.slice_pos() - 1;

            'value_lines: loop {
                // parse value till EOL

                simd::match_header_value_vectored(bytes);
                let b = next!(bytes);

                //found_ctl
                let skip = if b == b'\r' {
                    expect!(bytes.next() == b'\n' => Err(Error::HeaderValue));
                    2
                } else if b == b'\n' {
                    1
                } else {
                    handle_invalid_char!(bytes, b, HeaderValue);
                };

                maybe_continue_after_obsolete_line_folding!(bytes, 'value_lines);

                // SAFETY: having just checked that a newline exists, it's safe to skip it.
                unsafe {
                    break 'value bytes.slice_skip(skip);
                }
            }
        };

        header.value_end = bytes.slice_pos();

        // trim trailing whitespace in the header
        if let Some(last_visible) = value_slice
            .iter()
            .rposition(|b| *b != b' ' && *b != b'\t' && *b != b'\r' && *b != b'\n')
        {
            header.value_end = header.value_start + last_visible + 1;
        }

        return Ok(Status::Complete((bytes.slice_pos(), Some(header))));
    }
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
/// assert_eq!(httparse::parse_chunk_size(buf),
///            Ok(httparse::Status::Complete((3, 4))));
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
    use super::{parse_request, Error, Status};

    const NUM_OF_HEADERS: usize = 4;

    macro_rules! req {
        ($name:ident, $buf:expr, |($method:ident, $path:ident, $version:ident, $headers:ident)| $body:expr) => {
            req! {$name, $buf, Ok(Status::Complete(item)), |($method, $path, $version, $headers)| $body }
        };
        ($name:ident, $buf:expr, $len:expr, |($method:ident, $path:ident, $version:ident, $headers:ident)| $body:expr) => {
            #[test]
            fn $name() {
                // let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
                let status = parse_request($buf.as_ref());
                let (_, m, p, v) = if let $len = parse_request($buf.as_ref()) {
                    item
                } else {
                    panic!()
                };
                closure((m, p, v, Vec::new()));

                fn closure(($method, $path, $version, $headers): (&str, &str, u8, Vec<(String, Vec<u8>)>)) {
                    $body
                }
            }
        };
    }

    req! {
        test_request_simple,
        b"GET / HTTP/1.1\r\n\r\n",
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
        }
    }

    req! {
        test_request_simple_with_query_params,
        b"GET /thing?data=a HTTP/1.1\r\n\r\n",
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/thing?data=a");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
        }
    }

    req! {
        test_request_simple_with_whatwg_query_params,
        b"GET /thing?data=a^ HTTP/1.1\r\n\r\n",
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/thing?data=a^");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
        }
    }

    req! {
        test_request_headers,
        b"GET / HTTP/1.1\r\nHost: foo.com\r\nCookie: \r\n\r\n",
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 2);
            assert_eq!(headers[0].0, "Host");
            assert_eq!(headers[0].1, b"foo.com");
            assert_eq!(headers[1].0, "Cookie");
            assert_eq!(headers[1].1, b"");
        }
    }

    req! {
        test_request_headers_optional_whitespace,
        b"GET / HTTP/1.1\r\nHost: \tfoo.com\t \r\nCookie: \t \r\n\r\n",
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 2);
            assert_eq!(headers[0].0, "Host");
            assert_eq!(headers[0].1, b"foo.com");
            assert_eq!(headers[1].0, "Cookie");
            assert_eq!(headers[1].1, b"");
        }
    }

    req! {
        // test the scalar parsing
        test_request_header_value_htab_short,
        b"GET / HTTP/1.1\r\nUser-Agent: some\tagent\r\n\r\n",
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "User-Agent");
            assert_eq!(headers[0].1, b"some\tagent");
        }
    }

    req! {
        // test the sse42 parsing
        test_request_header_value_htab_med,
        b"GET / HTTP/1.1\r\nUser-Agent: 1234567890some\tagent\r\n\r\n",
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "User-Agent");
            assert_eq!(headers[0].1, b"1234567890some\tagent");
        }
    }

    req! {
        // test the avx2 parsing
        test_request_header_value_htab_long,
        b"GET / HTTP/1.1\r\nUser-Agent: 1234567890some\t1234567890agent1234567890\r\n\r\n",
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "User-Agent");
            assert_eq!(headers[0].1, &b"1234567890some\t1234567890agent1234567890"[..]);
        }
    }

    req! {
        // test the avx2 parsing
        test_request_header_no_space_after_colon,
        b"GET / HTTP/1.1\r\nUser-Agent:omg-no-space1234567890some1234567890agent1234567890\r\n\r\n",
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "User-Agent");
            assert_eq!(headers[0].1, &b"omg-no-space1234567890some1234567890agent1234567890"[..]);
        }
    }

    req! {
        test_request_headers_max,
        b"GET / HTTP/1.1\r\nA: A\r\nB: B\r\nC: C\r\nD: D\r\n\r\n",
        |(_method, _path, _verion, headers)| {
            assert_eq!(headers.len(), NUM_OF_HEADERS);
        }
    }

    req! {
        test_request_multibyte,
        b"GET / HTTP/1.1\r\nHost: foo.com\r\nUser-Agent: \xe3\x81\xb2\xe3/1.0\r\n\r\n",
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 2);
            assert_eq!(headers[0].0, "Host");
            assert_eq!(headers[0].1, b"foo.com");
            assert_eq!(headers[1].0, "User-Agent");
            assert_eq!(headers[1].1, b"\xe3\x81\xb2\xe3/1.0");
        }
    }

    // A single byte which is part of a method is not invalid
    req! {
        test_request_one_byte_method,
        b"G", Ok(Status::Partial),
        |(_method, _path, _verion, _headers)| {}
    }

    // A subset of a method is a partial method, not invalid
    req! {
        test_request_partial_method,
        b"GE", Ok(Status::Partial),
        |(_method, _path, _verion, _headers)| {}
    }

    // A method, without the delimiting space, is a partial request
    req! {
        test_request_method_no_delimiter,
        b"GET", Ok(Status::Partial),
        |(_method, _path, _verion, _headers)| {}
    }

    // Regression test: assert that a partial read with just the method and
    // space results in a partial, rather than a token error from uri parsing.
    req! {
        test_request_method_only,
        b"GET ", Ok(Status::Partial),
        |(_method, _path, _verion, _headers)| {}
    }

    req! {
        test_request_partial,
        b"GET / HTTP/1.1\r\n\r", Ok(Status::Partial),
        |(_method, _path, _verion, _headers)| {}
    }

    req! {
        test_request_partial_version,
        b"GET / HTTP/1.", Ok(Status::Partial),
        |(_method, _path, _verion, _headers)| {}
    }

    req! {
        test_request_method_path_no_delimiter,
        b"GET /", Ok(Status::Partial),
        |(_method, _path, _verion, _headers)| {}
    }

    req! {
        test_request_method_path_only,
        b"GET / ", Ok(Status::Partial),
        |(_method, _path, _verion, _headers)| {}
    }

    req! {
        test_request_partial_parses_headers_as_much_as_it_can,
        b"GET / HTTP/1.1\r\nHost: yolo\r\n",
        Ok(crate::Status::Partial),
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), NUM_OF_HEADERS); // doesn't slice since not Complete
            assert_eq!(headers[0].0, "Host");
            assert_eq!(headers[0].1, b"yolo");
        }
    }

    req! {
        test_request_newlines,
        b"GET / HTTP/1.1\nHost: foo.bar\n\n",
        |(_method, _path, _verion, _headers)| {}
    }

    req! {
        test_request_empty_lines_prefix,
        b"\r\n\r\nGET / HTTP/1.1\r\n\r\n",
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
        }
    }

    req! {
        test_request_empty_lines_prefix_lf_only,
        b"\n\nGET / HTTP/1.1\n\n",
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
        }
    }

    req! {
        test_request_path_backslash,
        b"\n\nGET /\\?wayne\\=5 HTTP/1.1\n\n",
        |(method, path, version, headers)| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/\\?wayne\\=5");
            assert_eq!(version, 1);
            assert_eq!(headers.len(), 0);
        }
    }

    req! {
        test_request_with_invalid_token_delimiter,
        b"GET\n/ HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
        Err(crate::Error::Token),
        |(_method, _path, _verion, _headers)| {}
    }

    req! {
        test_request_with_invalid_but_short_version,
        b"GET / HTTP/1!",
        Err(crate::Error::Version),
        |(_method, _path, _verion, _headers)| {}
    }

    req! {
        test_request_with_empty_method,
        b" / HTTP/1.1\r\n\r\n",
        Err(crate::Error::Token),
        |(_method, _path, _verion, _headers)| {}
    }

    req! {
        test_request_with_empty_path,
        b"GET  HTTP/1.1\r\n\r\n",
        Err(crate::Error::Token),
        |(_method, _path, _verion, _headers)| {}
    }

    req! {
        test_request_with_empty_method_and_path,
        b"  HTTP/1.1\r\n\r\n",
        Err(crate::Error::Token),
        |(_method, _path, _verion, _headers)| {}
    }

    // macro_rules! res {
    //     ($name:ident, $buf:expr, |$arg:ident| $body:expr) => {
    //         res! {$name, $buf, Ok(Status::Complete($buf.len())), |$arg| $body }
    //     };
    //     ($name:ident, $buf:expr, $len:expr, |$arg:ident| $body:expr) => {
    //         #[test]
    //         fn $name() {
    //             let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //             let mut res = Response::new(&mut headers[..]);
    //             let status = res.parse($buf.as_ref());
    //             assert_eq!(status, $len);
    //             closure(res);

    //             fn closure($arg: Response) {
    //                 $body
    //             }
    //         }
    //     };
    // }

    // res! {
    //     test_response_simple,
    //     b"HTTP/1.1 200 OK\r\n\r\n",
    //     |version, code, reason| {
    //         assert_eq!(res.version.unwrap(), 1);
    //         assert_eq!(res.code.unwrap(), 200);
    //         assert_eq!(res.reason.unwrap(), "OK");
    //     }
    // }

    // res! {
    //     test_response_newlines,
    //     b"HTTP/1.0 403 Forbidden\nServer: foo.bar\n\n",
    //     |_version, _code, _reason| {}
    // }

    // res! {
    //     test_response_reason_missing,
    //     b"HTTP/1.1 200 \r\n\r\n",
    //     |version, code, reason| {
    //         assert_eq!(res.version.unwrap(), 1);
    //         assert_eq!(res.code.unwrap(), 200);
    //         assert_eq!(res.reason.unwrap(), "");
    //     }
    // }

    // res! {
    //     test_response_reason_missing_no_space,
    //     b"HTTP/1.1 200\r\n\r\n",
    //     |version, code, reason| {
    //         assert_eq!(res.version.unwrap(), 1);
    //         assert_eq!(res.code.unwrap(), 200);
    //         assert_eq!(res.reason.unwrap(), "");
    //     }
    // }

    // res! {
    //     test_response_reason_missing_no_space_with_headers,
    //     b"HTTP/1.1 200\r\nFoo: bar\r\n\r\n",
    //     |version, code, reason| {
    //         assert_eq!(res.version.unwrap(), 1);
    //         assert_eq!(res.code.unwrap(), 200);
    //         assert_eq!(res.reason.unwrap(), "");
    //         assert_eq!(res.headers.len(), 1);
    //         assert_eq!(res.headers[0].0, "Foo");
    //         assert_eq!(res.headers[0].1, b"bar");
    //     }
    // }

    // res! {
    //     test_response_reason_with_space_and_tab,
    //     b"HTTP/1.1 101 Switching Protocols\t\r\n\r\n",
    //     |version, code, reason| {
    //         assert_eq!(res.version.unwrap(), 1);
    //         assert_eq!(res.code.unwrap(), 101);
    //         assert_eq!(res.reason.unwrap(), "Switching Protocols\t");
    //     }
    // }

    // static RESPONSE_REASON_WITH_OBS_TEXT_BYTE: &[u8] = b"HTTP/1.1 200 X\xFFZ\r\n\r\n";
    // res! {
    //     test_response_reason_with_obsolete_text_byte,
    //     RESPONSE_REASON_WITH_OBS_TEXT_BYTE,
    //     |version, code, reason| {
    //         assert_eq!(res.version.unwrap(), 1);
    //         assert_eq!(res.code.unwrap(), 200);
    //         // Empty string fallback in case of obs-text
    //         assert_eq!(res.reason.unwrap(), "");
    //     }
    // }

    // res! {
    //     test_response_reason_with_nul_byte,
    //     b"HTTP/1.1 200 \x00\r\n\r\n",
    //     Err(crate::Error::Status),
    //     |_version, _code, _reason| {}
    // }

    // res! {
    //     test_response_version_missing_space,
    //     b"HTTP/1.1",
    //     Ok(Status::Partial),
    //     |_version, _code, _reason| {}
    //     |_res| {}
    // }

    // res! {
    //     test_response_code_missing_space,
    //     b"HTTP/1.1 200",
    //     Ok(Status::Partial),
    //     |_version, _code, _reason| {}
    // }

    // res! {
    //     test_response_partial_parses_headers_as_much_as_it_can,
    //     b"HTTP/1.1 200 OK\r\nServer: yolo\r\n",
    //     Ok(crate::Status::Partial),
    //     |version, code, reason| {
    //         assert_eq!(res.version.unwrap(), 1);
    //         assert_eq!(res.code.unwrap(), 200);
    //         assert_eq!(res.reason.unwrap(), "OK");
    //         assert_eq!(res.headers.len(), NUM_OF_HEADERS); // doesn't slice since not Complete
    //         assert_eq!(res.headers[0].0, "Server");
    //         assert_eq!(res.headers[0].1, b"yolo");
    //     }
    // }

    // res! {
    //     test_response_empty_lines_prefix_lf_only,
    //     b"\n\nHTTP/1.1 200 OK\n\n",
    //     |_version, _code, _reason| {}
    // }

    // res! {
    //     test_response_no_cr,
    //     b"HTTP/1.0 200\nContent-type: text/html\n\n",
    //     |version, code, reason| {
    //         assert_eq!(res.version.unwrap(), 0);
    //         assert_eq!(res.code.unwrap(), 200);
    //         assert_eq!(res.reason.unwrap(), "");
    //         assert_eq!(res.headers.len(), 1);
    //         assert_eq!(res.headers[0].0, "Content-type");
    //         assert_eq!(res.headers[0].1, b"text/html");
    //     }
    // }

    // /// Check all subset permutations of a partial request line with no headers
    // #[test]
    // fn partial_permutations() {
    //     let req_str = "GET / HTTP/1.1\r\n\r\n";
    //     let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //     let mut req = Request::new(&mut headers[..]);
    //     for i in 0..req_str.len() {
    //         let status = req.parse(&req_str.as_bytes()[..i]);
    //         assert_eq!(
    //             status,
    //             Ok(Status::Partial),
    //             "partial request line should return partial. \
    //              Portion which failed: '{seg}' (below {i})",
    //             seg = &req_str[..i]
    //         );
    //     }
    // }

    // static RESPONSE_WITH_WHITESPACE_BETWEEN_HEADER_NAME_AND_COLON: &[u8] =
    //     b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Credentials : true\r\nBread: baguette\r\n\r\n";

    // #[test]
    // fn test_forbid_response_with_whitespace_between_header_name_and_colon() {
    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = response.parse(RESPONSE_WITH_WHITESPACE_BETWEEN_HEADER_NAME_AND_COLON);

    //     assert_eq!(result, Err(crate::Error::HeaderName));
    // }

    // #[test]
    // fn test_allow_response_with_whitespace_between_header_name_and_colon() {
    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .allow_spaces_after_header_name_in_responses(true)
    //         .parse_response(
    //             &mut response,
    //             RESPONSE_WITH_WHITESPACE_BETWEEN_HEADER_NAME_AND_COLON,
    //         );

    //     assert_eq!(result, Ok(Status::Complete(77)));
    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 2);
    //     assert_eq!(response.headers[0].0, "Access-Control-Allow-Credentials");
    //     assert_eq!(response.headers[0].1, &b"true"[..]);
    //     assert_eq!(response.headers[1].0, "Bread");
    //     assert_eq!(response.headers[1].1, &b"baguette"[..]);
    // }

    // #[test]
    // fn test_ignore_header_line_with_whitespaces_after_header_name_in_response() {
    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_responses(true)
    //         .parse_response(
    //             &mut response,
    //             RESPONSE_WITH_WHITESPACE_BETWEEN_HEADER_NAME_AND_COLON,
    //         );

    //     assert_eq!(result, Ok(Status::Complete(77)));
    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 1);
    //     assert_eq!(response.headers[0].0, "Bread");
    //     assert_eq!(response.headers[0].1, &b"baguette"[..]);
    // }

    // static REQUEST_WITH_WHITESPACE_BETWEEN_HEADER_NAME_AND_COLON: &[u8] =
    //     b"GET / HTTP/1.1\r\nHost : localhost\r\n\r\n";

    // #[test]
    // fn test_forbid_request_with_whitespace_between_header_name_and_colon() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut request = Request::new(&mut headers[..]);
    //     let result = request.parse(REQUEST_WITH_WHITESPACE_BETWEEN_HEADER_NAME_AND_COLON);

    //     assert_eq!(result, Err(crate::Error::HeaderName));
    // }

    // #[test]
    // fn test_ignore_header_line_with_whitespaces_after_header_name_in_request() {
    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut request = Request::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_requests(true)
    //         .parse_request(
    //             &mut request,
    //             REQUEST_WITH_WHITESPACE_BETWEEN_HEADER_NAME_AND_COLON,
    //         );

    //     assert_eq!(result, Ok(Status::Complete(36)));
    // }

    // static RESPONSE_WITH_OBSOLETE_LINE_FOLDING_AT_START: &[u8] =
    //     b"HTTP/1.1 200 OK\r\nLine-Folded-Header: \r\n   \r\n hello there\r\n\r\n";

    // #[test]
    // fn test_forbid_response_with_obsolete_line_folding_at_start() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = response.parse(RESPONSE_WITH_OBSOLETE_LINE_FOLDING_AT_START);

    //     assert_eq!(result, Err(crate::Error::HeaderName));
    // }

    // #[test]
    // fn test_allow_response_with_obsolete_line_folding_at_start() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .allow_obsolete_multiline_headers_in_responses(true)
    //         .parse_response(&mut response, RESPONSE_WITH_OBSOLETE_LINE_FOLDING_AT_START);

    //     assert_eq!(
    //         result,
    //         Ok(Status::Complete(
    //             RESPONSE_WITH_OBSOLETE_LINE_FOLDING_AT_START.len()
    //         ))
    //     );
    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 1);
    //     assert_eq!(response.headers[0].0, "Line-Folded-Header");
    //     assert_eq!(response.headers[0].1, &b"hello there"[..]);
    // }

    // static RESPONSE_WITH_OBSOLETE_LINE_FOLDING_AT_END: &[u8] =
    //     b"HTTP/1.1 200 OK\r\nLine-Folded-Header: hello there\r\n   \r\n \r\n\r\n";

    // #[test]
    // fn test_forbid_response_with_obsolete_line_folding_at_end() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = response.parse(RESPONSE_WITH_OBSOLETE_LINE_FOLDING_AT_END);

    //     assert_eq!(result, Err(crate::Error::HeaderName));
    // }

    // #[test]
    // fn test_allow_response_with_obsolete_line_folding_at_end() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .allow_obsolete_multiline_headers_in_responses(true)
    //         .parse_response(&mut response, RESPONSE_WITH_OBSOLETE_LINE_FOLDING_AT_END);

    //     assert_eq!(
    //         result,
    //         Ok(Status::Complete(
    //             RESPONSE_WITH_OBSOLETE_LINE_FOLDING_AT_END.len()
    //         ))
    //     );
    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 1);
    //     assert_eq!(response.headers[0].0, "Line-Folded-Header");
    //     assert_eq!(response.headers[0].1, &b"hello there"[..]);
    // }

    // static RESPONSE_WITH_OBSOLETE_LINE_FOLDING_IN_MIDDLE: &[u8] =
    //     b"HTTP/1.1 200 OK\r\nLine-Folded-Header: hello  \r\n \r\n there\r\n\r\n";

    // #[test]
    // fn test_forbid_response_with_obsolete_line_folding_in_middle() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = response.parse(RESPONSE_WITH_OBSOLETE_LINE_FOLDING_IN_MIDDLE);

    //     assert_eq!(result, Err(crate::Error::HeaderName));
    // }

    // #[test]
    // fn test_allow_response_with_obsolete_line_folding_in_middle() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .allow_obsolete_multiline_headers_in_responses(true)
    //         .parse_response(&mut response, RESPONSE_WITH_OBSOLETE_LINE_FOLDING_IN_MIDDLE);

    //     assert_eq!(
    //         result,
    //         Ok(Status::Complete(
    //             RESPONSE_WITH_OBSOLETE_LINE_FOLDING_IN_MIDDLE.len()
    //         ))
    //     );
    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 1);
    //     assert_eq!(response.headers[0].0, "Line-Folded-Header");
    //     assert_eq!(response.headers[0].1, &b"hello  \r\n \r\n there"[..]);
    // }

    // static RESPONSE_WITH_OBSOLETE_LINE_FOLDING_IN_EMPTY_HEADER: &[u8] =
    //     b"HTTP/1.1 200 OK\r\nLine-Folded-Header:   \r\n \r\n \r\n\r\n";

    // #[test]
    // fn test_forbid_response_with_obsolete_line_folding_in_empty_header() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = response.parse(RESPONSE_WITH_OBSOLETE_LINE_FOLDING_IN_EMPTY_HEADER);

    //     assert_eq!(result, Err(crate::Error::HeaderName));
    // }

    // #[test]
    // fn test_allow_response_with_obsolete_line_folding_in_empty_header() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .allow_obsolete_multiline_headers_in_responses(true)
    //         .parse_response(
    //             &mut response,
    //             RESPONSE_WITH_OBSOLETE_LINE_FOLDING_IN_EMPTY_HEADER,
    //         );

    //     assert_eq!(
    //         result,
    //         Ok(Status::Complete(
    //             RESPONSE_WITH_OBSOLETE_LINE_FOLDING_IN_EMPTY_HEADER.len()
    //         ))
    //     );
    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 1);
    //     assert_eq!(response.headers[0].0, "Line-Folded-Header");
    //     assert_eq!(response.headers[0].1, &b""[..]);
    // }

    // #[test]
    // fn test_chunk_size() {
    //     assert_eq!(parse_chunk_size(b"0\r\n"), Ok(Status::Complete((3, 0))));
    //     assert_eq!(
    //         parse_chunk_size(b"12\r\nchunk"),
    //         Ok(Status::Complete((4, 18)))
    //     );
    //     assert_eq!(
    //         parse_chunk_size(b"3086d\r\n"),
    //         Ok(Status::Complete((7, 198765)))
    //     );
    //     assert_eq!(
    //         parse_chunk_size(b"3735AB1;foo bar*\r\n"),
    //         Ok(Status::Complete((18, 57891505)))
    //     );
    //     assert_eq!(
    //         parse_chunk_size(b"3735ab1 ; baz \r\n"),
    //         Ok(Status::Complete((16, 57891505)))
    //     );
    //     assert_eq!(parse_chunk_size(b"77a65\r"), Ok(Status::Partial));
    //     assert_eq!(parse_chunk_size(b"ab"), Ok(Status::Partial));
    //     assert_eq!(
    //         parse_chunk_size(b"567f8a\rfoo"),
    //         Err(crate::InvalidChunkSize)
    //     );
    //     assert_eq!(
    //         parse_chunk_size(b"567f8a\rfoo"),
    //         Err(crate::InvalidChunkSize)
    //     );
    //     assert_eq!(
    //         parse_chunk_size(b"567xf8a\r\n"),
    //         Err(crate::InvalidChunkSize)
    //     );
    //     assert_eq!(
    //         parse_chunk_size(b"ffffffffffffffff\r\n"),
    //         Ok(Status::Complete((18, u64::MAX)))
    //     );
    //     assert_eq!(
    //         parse_chunk_size(b"1ffffffffffffffff\r\n"),
    //         Err(crate::InvalidChunkSize)
    //     );
    //     assert_eq!(
    //         parse_chunk_size(b"Affffffffffffffff\r\n"),
    //         Err(crate::InvalidChunkSize)
    //     );
    //     assert_eq!(
    //         parse_chunk_size(b"fffffffffffffffff\r\n"),
    //         Err(crate::InvalidChunkSize)
    //     );
    // }

    // static RESPONSE_WITH_MULTIPLE_SPACE_DELIMITERS: &[u8] = b"HTTP/1.1   200  OK\r\n\r\n";

    // #[test]
    // fn test_forbid_response_with_multiple_space_delimiters() {
    //     let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = response.parse(RESPONSE_WITH_MULTIPLE_SPACE_DELIMITERS);

    //     assert_eq!(result, Err(crate::Error::Status));
    // }

    // #[test]
    // fn test_allow_response_with_multiple_space_delimiters() {
    //     let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .allow_multiple_spaces_in_response_status_delimiters(true)
    //         .parse_response(&mut response, RESPONSE_WITH_MULTIPLE_SPACE_DELIMITERS);

    //     assert_eq!(
    //         result,
    //         Ok(Status::Complete(
    //             RESPONSE_WITH_MULTIPLE_SPACE_DELIMITERS.len()
    //         ))
    //     );
    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 0);
    // }

    // /// This is technically allowed by the spec, but we only support multiple spaces as an option,
    // /// not stray `\r`s.
    // static RESPONSE_WITH_WEIRD_WHITESPACE_DELIMITERS: &[u8] = b"HTTP/1.1 200\rOK\r\n\r\n";

    // #[test]
    // fn test_forbid_response_with_weird_whitespace_delimiters() {
    //     let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = response.parse(RESPONSE_WITH_WEIRD_WHITESPACE_DELIMITERS);

    //     assert_eq!(result, Err(crate::Error::Status));
    // }

    // #[test]
    // fn test_still_forbid_response_with_weird_whitespace_delimiters() {
    //     let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .allow_multiple_spaces_in_response_status_delimiters(true)
    //         .parse_response(&mut response, RESPONSE_WITH_WEIRD_WHITESPACE_DELIMITERS);
    //     assert_eq!(result, Err(crate::Error::Status));
    // }

    // static REQUEST_WITH_MULTIPLE_SPACE_DELIMITERS: &[u8] = b"GET  /    HTTP/1.1\r\n\r\n";

    // #[test]
    // fn test_forbid_request_with_multiple_space_delimiters() {
    //     let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //     let mut request = Request::new(&mut headers[..]);
    //     let result = request.parse(REQUEST_WITH_MULTIPLE_SPACE_DELIMITERS);

    //     assert_eq!(result, Err(crate::Error::Token));
    // }

    // #[test]
    // fn test_allow_request_with_multiple_space_delimiters() {
    //     let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //     let mut request = Request::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .allow_multiple_spaces_in_request_line_delimiters(true)
    //         .parse_request(&mut request, REQUEST_WITH_MULTIPLE_SPACE_DELIMITERS);

    //     assert_eq!(
    //         result,
    //         Ok(Status::Complete(
    //             REQUEST_WITH_MULTIPLE_SPACE_DELIMITERS.len()
    //         ))
    //     );
    //     assert_eq!(request.method.unwrap(), "GET");
    //     assert_eq!(request.path.unwrap(), "/");
    //     assert_eq!(request.version.unwrap(), 1);
    //     assert_eq!(request.headers.len(), 0);
    // }

    // /// This is technically allowed by the spec, but we only support multiple spaces as an option,
    // /// not stray `\r`s.
    // static REQUEST_WITH_WEIRD_WHITESPACE_DELIMITERS: &[u8] = b"GET\r/\rHTTP/1.1\r\n\r\n";

    // #[test]
    // fn test_forbid_request_with_weird_whitespace_delimiters() {
    //     let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //     let mut request = Request::new(&mut headers[..]);
    //     let result = request.parse(REQUEST_WITH_WEIRD_WHITESPACE_DELIMITERS);

    //     assert_eq!(result, Err(crate::Error::Token));
    // }

    // #[test]
    // fn test_still_forbid_request_with_weird_whitespace_delimiters() {
    //     let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //     let mut request = Request::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .allow_multiple_spaces_in_request_line_delimiters(true)
    //         .parse_request(&mut request, REQUEST_WITH_WEIRD_WHITESPACE_DELIMITERS);
    //     assert_eq!(result, Err(crate::Error::Token));
    // }

    // static REQUEST_WITH_MULTIPLE_SPACES_AND_BAD_PATH: &[u8] = b"GET   /foo ohno HTTP/1.1\r\n\r\n";

    // #[test]
    // fn test_request_with_multiple_spaces_and_bad_path() {
    //     let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //     let mut request = Request::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .allow_multiple_spaces_in_request_line_delimiters(true)
    //         .parse_request(&mut request, REQUEST_WITH_MULTIPLE_SPACES_AND_BAD_PATH);
    //     assert_eq!(result, Err(crate::Error::Version));
    // }

    // // This test ensure there is an error when there is a DEL character in the path
    // // since we allow all char from 0x21 code except DEL, this test ensure that DEL
    // // is not allowed in the path
    // static REQUEST_WITH_DEL_IN_PATH: &[u8] = b"GET   /foo\x7Fohno HTTP/1.1\r\n\r\n";

    // #[test]
    // fn test_request_with_del_in_path() {
    //     let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //     let mut request = Request::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .allow_multiple_spaces_in_request_line_delimiters(true)
    //         .parse_request(&mut request, crate::tests::REQUEST_WITH_DEL_IN_PATH);
    //     assert_eq!(result, Err(crate::Error::Token));
    // }

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

    // static RESPONSE_WITH_SPACES_IN_CODE: &[u8] = b"HTTP/1.1 99 200 OK\r\n\r\n";

    // #[test]
    // fn test_response_with_spaces_in_code() {
    //     let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .allow_multiple_spaces_in_response_status_delimiters(true)
    //         .parse_response(&mut response, RESPONSE_WITH_SPACES_IN_CODE);
    //     assert_eq!(result, Err(crate::Error::Status));
    // }

    // #[test]
    // fn test_response_with_empty_header_name() {
    //     const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n: hello\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut response = Response::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default()
    //         .allow_spaces_after_header_name_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Ok(Status::Complete(45)));

    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 1);
    //     assert_eq!(response.headers[0].0, "Bread");
    //     assert_eq!(response.headers[0].1, &b"baguette"[..]);
    // }

    // #[test]
    // fn test_request_with_empty_header_name() {
    //     const RESPONSE: &[u8] = b"GET / HTTP/1.1\r\n: hello\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut request = Request::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_request(&mut request, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_requests(true)
    //         .parse_request(&mut request, RESPONSE);
    //     assert_eq!(result, Ok(Status::Complete(44)));
    // }

    // #[test]
    // fn test_request_with_whitespace_between_header_name_and_colon() {
    //     const REQUEST: &[u8] =
    //         b"GET / HTTP/1.1\r\nAccess-Control-Allow-Credentials  : true\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut request = Request::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default()
    //         .allow_spaces_after_header_name_in_responses(true)
    //         .parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_responses(true)
    //         .parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderName));
    // }

    // #[test]
    // fn test_response_with_invalid_char_between_header_name_and_colon() {
    //     const RESPONSE: &[u8] =
    //         b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Credentials\xFF  : true\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut response = Response::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default()
    //         .allow_spaces_after_header_name_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);

    //     assert_eq!(result, Ok(Status::Complete(79)));
    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 1);
    //     assert_eq!(response.headers[0].0, "Bread");
    //     assert_eq!(response.headers[0].1, &b"baguette"[..]);
    // }

    // #[test]
    // fn test_request_with_invalid_char_between_header_name_and_colon() {
    //     const REQUEST: &[u8] =
    //         b"GET / HTTP/1.1\r\nAccess-Control-Allow-Credentials\xFF  : true\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut request = Request::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_requests(true)
    //         .parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Ok(Status::Complete(78)));
    // }

    // #[test]
    // fn test_ignore_header_line_with_missing_colon_in_response() {
    //     const RESPONSE: &[u8] =
    //         b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Credentials\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut response = Response::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Ok(Status::Complete(70)));

    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 1);
    //     assert_eq!(response.headers[0].0, "Bread");
    //     assert_eq!(response.headers[0].1, &b"baguette"[..]);
    // }

    // #[test]
    // fn test_ignore_header_line_with_missing_colon_in_request() {
    //     const REQUEST: &[u8] =
    //         b"GET / HTTP/1.1\r\nAccess-Control-Allow-Credentials\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut request = Request::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_requests(true)
    //         .parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Ok(Status::Complete(69)));
    // }

    // #[test]
    // fn test_response_header_with_missing_colon_with_folding() {
    //     const RESPONSE: &[u8] =
    //         b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Credentials   \r\n hello\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut response = Response::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default()
    //         .allow_obsolete_multiline_headers_in_responses(true)
    //         .allow_spaces_after_header_name_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Ok(Status::Complete(81)));

    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 1);
    //     assert_eq!(response.headers[0].0, "Bread");
    //     assert_eq!(response.headers[0].1, &b"baguette"[..]);
    // }

    // #[test]
    // fn test_request_header_with_missing_colon_with_folding() {
    //     const REQUEST: &[u8] =
    //         b"GET / HTTP/1.1\r\nAccess-Control-Allow-Credentials   \r\n hello\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut request = Request::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_requests(true)
    //         .parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Ok(Status::Complete(80)));
    // }

    // #[test]
    // fn test_response_header_with_nul_in_header_name() {
    //     const RESPONSE: &[u8] =
    //         b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Cred\0entials: hello\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut response = Response::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderName));
    // }

    // #[test]
    // fn test_request_header_with_nul_in_header_name() {
    //     const REQUEST: &[u8] =
    //         b"GET / HTTP/1.1\r\nAccess-Control-Allow-Cred\0entials: hello\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut request = Request::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_requests(true)
    //         .parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderName));
    // }

    // #[test]
    // fn test_header_with_cr_in_header_name() {
    //     const RESPONSE: &[u8] =
    //         b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Cred\rentials: hello\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut response = Response::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     const REQUEST: &[u8] =
    //         b"GET / HTTP/1.1\r\nAccess-Control-Allow-Cred\rentials: hello\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut request = Request::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_requests(true)
    //         .parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderName));
    // }

    // #[test]
    // fn test_header_with_nul_in_whitespace_before_colon() {
    //     const RESPONSE: &[u8] =
    //         b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Credentials   \0: hello\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut response = Response::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default()
    //         .allow_spaces_after_header_name_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     let result = crate::ParserConfig::default()
    //         .allow_spaces_after_header_name_in_responses(true)
    //         .ignore_invalid_headers_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderName));

    //     const REQUEST: &[u8] =
    //         b"GET / HTTP/1.1\r\nAccess-Control-Allow-Credentials   \0: hello\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut request = Request::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_requests(true)
    //         .parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderName));
    // }

    // #[test]
    // fn test_header_with_nul_in_value() {
    //     const RESPONSE: &[u8] =
    //         b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Credentials: hell\0o\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut response = Response::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderValue));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderValue));

    //     const REQUEST: &[u8] =
    //         b"GET / HTTP/1.1\r\nAccess-Control-Allow-Credentials: hell\0o\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut request = Request::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderValue));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_requests(true)
    //         .parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderValue));
    // }

    // #[test]
    // fn test_header_with_invalid_char_in_value() {
    //     const RESPONSE: &[u8] =
    //         b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Credentials: hell\x01o\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut response = Response::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderValue));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Ok(Status::Complete(78)));

    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 1);
    //     assert_eq!(response.headers[0].0, "Bread");
    //     assert_eq!(response.headers[0].1, &b"baguette"[..]);

    //     const REQUEST: &[u8] =
    //         b"GET / HTTP/1.1\r\nAccess-Control-Allow-Credentials: hell\x01o\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut request = Request::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderValue));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_requests(true)
    //         .parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Ok(Status::Complete(77)));

    //     assert_eq!(request.version.unwrap(), 1);
    //     assert_eq!(request.method.unwrap(), "GET");
    //     assert_eq!(request.path.unwrap(), "/");
    //     assert_eq!(request.headers.len(), 1);
    //     assert_eq!(request.headers[0].0, "Bread");
    //     assert_eq!(request.headers[0].1, &b"baguette"[..]);
    // }

    // #[test]
    // fn test_header_with_invalid_char_in_value_with_folding() {
    //     const RESPONSE: &[u8] =
    //         b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Credentials: hell\x01o  \n world!\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut response = Response::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Err(crate::Error::HeaderValue));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_responses(true)
    //         .parse_response(&mut response, RESPONSE);
    //     assert_eq!(result, Ok(Status::Complete(88)));

    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 1);
    //     assert_eq!(response.headers[0].0, "Bread");
    //     assert_eq!(response.headers[0].1, &b"baguette"[..]);

    //     const REQUEST: &[u8] =
    //         b"GET / HTTP/1.1\r\nAccess-Control-Allow-Credentials: hell\x01o  \n world!\r\nBread: baguette\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 2];
    //     let mut request = Request::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Err(crate::Error::HeaderValue));

    //     let result = crate::ParserConfig::default()
    //         .ignore_invalid_headers_in_requests(true)
    //         .parse_request(&mut request, REQUEST);
    //     assert_eq!(result, Ok(Status::Complete(87)));

    //     assert_eq!(request.version.unwrap(), 1);
    //     assert_eq!(request.method.unwrap(), "GET");
    //     assert_eq!(request.path.unwrap(), "/");
    //     assert_eq!(request.headers.len(), 1);
    //     assert_eq!(request.headers[0].0, "Bread");
    //     assert_eq!(request.headers[0].1, &b"baguette"[..]);
    // }

    // #[test]
    // fn test_method_within_buffer() {
    //     const REQUEST: &[u8] = b"GET / HTTP/1.1\r\n\r\n";

    //     let mut headers = [EMPTY_HEADER; 0];
    //     let mut request = Request::new(&mut headers[..]);

    //     crate::ParserConfig::default()
    //         .parse_request(&mut request, REQUEST)
    //         .unwrap();

    //     // SAFETY: will not wrap
    //     let buf_end = unsafe { REQUEST.as_ptr().add(REQUEST.len()) };
    //     // Check that the method str is within the buffer
    //     let method = request.method.unwrap();
    //     assert!(REQUEST.as_ptr() <= method.as_ptr());
    //     assert!(method.as_ptr() <= buf_end);
    // }

    // static RESPONSE_WITH_SPACE_BEFORE_FIRST_HEADER: &[u8] =
    //     b"HTTP/1.1 200 OK\r\n Space-Before-Header: hello there\r\n\r\n";

    // #[test]
    // fn test_forbid_response_with_space_before_first_header() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = response.parse(RESPONSE_WITH_SPACE_BEFORE_FIRST_HEADER);

    //     assert_eq!(result, Err(crate::Error::HeaderName));
    // }

    // #[test]
    // fn test_allow_response_response_with_space_before_first_header() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .allow_space_before_first_header_name(true)
    //         .parse_response(&mut response, RESPONSE_WITH_SPACE_BEFORE_FIRST_HEADER);

    //     assert_eq!(
    //         result,
    //         Ok(Status::Complete(
    //             RESPONSE_WITH_SPACE_BEFORE_FIRST_HEADER.len()
    //         ))
    //     );
    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 1);
    //     assert_eq!(response.headers[0].0, "Space-Before-Header");
    //     assert_eq!(response.headers[0].1, &b"hello there"[..]);
    // }

    // #[test]
    // fn test_no_space_after_colon() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut response = Response::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .parse_response(&mut response, b"HTTP/1.1 200 OK\r\nfoo:bar\r\n\r\n");

    //     assert_eq!(result, Ok(Status::Complete(28)));
    //     assert_eq!(response.version.unwrap(), 1);
    //     assert_eq!(response.code.unwrap(), 200);
    //     assert_eq!(response.reason.unwrap(), "OK");
    //     assert_eq!(response.headers.len(), 1);
    //     assert_eq!(response.headers[0].0, "foo");
    //     assert_eq!(response.headers[0].1, &b"bar"[..]);
    // }

    // #[test]
    // fn test_request_with_leading_space() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut request = Request::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .parse_request(&mut request, b" GET / HTTP/1.1\r\nfoo:bar\r\n\r\n");

    //     assert_eq!(result, Err(Error::Token));
    // }

    // #[test]
    // fn test_request_with_invalid_method() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut request = Request::new(&mut headers[..]);
    //     let result = crate::ParserConfig::default()
    //         .parse_request(&mut request, b"P()ST / HTTP/1.1\r\nfoo:bar\r\n\r\n");

    //     assert_eq!(result, Err(Error::Token));
    // }

    // #[test]
    // fn test_utf8_in_path_ok() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut request = Request::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_request(
    //         &mut request,
    //         b"GET /test?post=I\xE2\x80\x99msorryIforkedyou HTTP/1.1\r\nHost: example.org\r\n\r\n",
    //     );

    //     assert_eq!(result, Ok(Status::Complete(67)));
    //     assert_eq!(request.version.unwrap(), 1);
    //     assert_eq!(request.method.unwrap(), "GET");
    //     assert_eq!(request.path.unwrap(), "/test?post=I’msorryIforkedyou");
    //     assert_eq!(request.headers.len(), 1);
    //     assert_eq!(request.headers[0].0, "Host");
    //     assert_eq!(request.headers[0].1, &b"example.org"[..]);
    // }

    // #[test]
    // fn test_bad_utf8_in_path() {
    //     let mut headers = [EMPTY_HEADER; 1];
    //     let mut request = Request::new(&mut headers[..]);

    //     let result = crate::ParserConfig::default().parse_request(
    //         &mut request,
    //         b"GET /test?post=I\xE2msorryIforkedyou HTTP/1.1\r\nHost: example.org\r\n\r\n",
    //     );

    //     assert_eq!(result, Err(crate::Error::Token));
    // }
}
