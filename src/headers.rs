use crate::{Error, Result, SlicePos, State, Status, iter::Bytes, simd, utils};

/// Represents a parsed header.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Header {
    /// The name portion of a header.
    ///
    /// A header name must be valid ASCII-US, so it's safe to store as a `&str`.
    pub name: SlicePos,
    /// The value portion of a header.
    ///
    /// While headers **should** be ASCII-US, the specification allows for
    /// values that may not be, and so the value is stored as bytes.
    pub value: SlicePos,
}

/// Header parse result result.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HeaderParsed {
    Header(usize),
    Eof(usize),
}

impl Header {
    /// Parse a buffer of bytes as header.
    ///
    /// The return value, if complete and successful, includes the index of the
    /// buffer that parsing stopped at, and a sliced reference to the parsed
    /// headers. The length of the slice will be equal to the number of properly
    /// parsed headers.
    ///
    /// # Example
    ///
    /// ```
    /// use ntex_httparse::{Status, Header, HeaderParsed};
    ///
    /// let buf = b"Host: foo.bar\nAccept: */*\n\nblah blah";
    /// let mut header = Header::default();
    /// assert_eq!(header.parse(buf), Ok(Status::Complete(HeaderParsed::Header(14))));
    /// ```
    pub fn parse(&mut self, src: &[u8]) -> Result<HeaderParsed> {
        let mut st = State::default();
        let mut bytes = Bytes::new(src, &mut st);
        parse_header_iter_uninit(&mut bytes, self)
    }

    pub fn parse_with_state(&mut self, src: &[u8], st: &mut State) -> Result<HeaderParsed> {
        parse_header_iter_uninit(&mut Bytes::new(src, st), self)
    }
}

fn parse_header_iter_uninit(
    bytes: &mut Bytes<'_, '_>,
    header: &mut Header,
) -> Result<HeaderParsed> {
    // header eof
    if bytes.st.state == 0 {
        // a newline here means the head is over!
        let b = next!(bytes);
        if b == b'\r' {
            expect!(bytes.next() == b'\n' => Err(Error::NewLine));
            return Ok(Status::Complete(HeaderParsed::Eof(
                bytes.cursor() - bytes.start(),
            )));
        } else if b == b'\n' {
            return Ok(Status::Complete(HeaderParsed::Eof(
                bytes.cursor() - bytes.start(),
            )));
        } else if !utils::is_header_name_token(b) {
            return Err(Error::HeaderName);
        }
        bytes.st.state = 1;
        header.name.start = bytes.cursor() - 1;
    }

    // parse header name until colon
    if bytes.st.state == 1 {
        simd::match_header_name_vectored(bytes);
        if next!(bytes) == b':' {
            // SAFETY: previously bumped by 1 with next! -> always safe.
            bytes.st.state = 2;
            header.name.end = bytes.cursor() - 1;
        } else {
            return Err(Error::HeaderName);
        }
    }

    let mut b;

    // header value start position
    if bytes.st.state == 2 {
        // eat white space between colon and value
        'whitespace_after_colon: loop {
            b = next!(bytes);
            if b == b' ' || b == b'\t' {
                continue 'whitespace_after_colon;
            }
            if utils::is_header_value_token(b) {
                bytes.st.state = 3;
                header.value.start = bytes.cursor() - 1;
                break 'whitespace_after_colon;
            }

            if b == b'\r' {
                expect!(bytes.next() == b'\n' => Err(Error::HeaderValue));
            } else if b != b'\n' {
                return Err(Error::HeaderValue);
            }

            // This produces an empty slice that points to the beginning
            // of the whitespace.
            header.value.reset();
            bytes.st.state = 0;
            bytes.commit();
            return Ok(Status::Complete(HeaderParsed::Header(bytes.cursor())));
        }
    }

    // header value
    if bytes.st.state == 3 {
        // parse value till EOL
        {
            simd::match_header_value_vectored(bytes);

            // check ctl
            let b = next!(bytes);
            if b == b'\r' {
                expect!(bytes.next() == b'\n' => Err(Error::HeaderValue));
            } else if b != b'\n' {
                return Err(Error::HeaderValue);
            }

            // trim trailing whitespace in the header
            let mut n = 1; // previous next() moves cursor to next item
            while let Some(b) = bytes.peek_behind(n) {
                if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                    n += 1;
                } else {
                    break;
                }
            }

            header.value.end = bytes.cursor() - n + 1;
        }
    }
    bytes.st.state = 0;
    bytes.commit();

    Ok(Status::Complete(HeaderParsed::Header(bytes.cursor())))
}
