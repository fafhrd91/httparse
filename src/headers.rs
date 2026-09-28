use crate::{Error, Result, SlicePos, State, Status, iter::Bytes, simd, utils};

/// A parsed header.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Header {
    /// Header name, an ASCII token.
    pub name: SlicePos,
    /// Header value, without surrounding whitespace, `0..0` if empty.
    ///
    /// May contain HTAB, SP, visible ASCII and bytes `0x80..=0xFF`, so it is
    /// not guaranteed to be UTF-8.
    pub value: SlicePos,
}

/// Header parse result.
///
/// Both variants hold the position in `src` right after the parsed input,
/// i.e. the number of bytes consumed when parsing started at position 0.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HeaderParsed {
    /// A header was parsed, its positions are stored in `Header`.
    Header(usize),
    /// The empty line ending the header section was parsed.
    Eof(usize),
}

impl Header {
    /// Parse a single header from a buffer of bytes.
    ///
    /// If complete and successful, name and value positions are stored in
    /// `self` and the returned `HeaderParsed` holds the position in the
    /// buffer where parsing stopped.
    ///
    /// Obsolete line folding is not supported: a line starting with SP or
    /// HTAB is rejected with `Error::HeaderName`.
    ///
    /// # Example
    ///
    /// ```
    /// use ntex_httparse::{Status, Header, HeaderParsed};
    ///
    /// let buf = b"Host: foo.bar \nAccept: */*\n\nblah blah";
    /// let mut header = Header::default();
    /// assert_eq!(header.parse(buf), Ok(Status::Complete(HeaderParsed::Header(15))));
    /// assert_eq!(&buf[header.name.start..header.name.end], b"Host");
    /// assert_eq!(&buf[header.value.start..header.value.end], b"foo.bar");
    /// ```
    pub fn parse(&mut self, src: &[u8]) -> Result<HeaderParsed> {
        let mut st = State::default();
        let mut bytes = Bytes::new(src, &mut st);
        parse_header_iter_uninit(&mut bytes, self)
    }

    /// Parse a header, resuming from `st` saved by a previous `Partial` result.
    ///
    /// `st` must come from a previous call with the same buffer (which may have
    /// grown since), or be `State::default()`. An invalid state returns
    /// `Error::HeaderName`.
    pub fn parse_with_state(&mut self, src: &[u8], st: &mut State) -> Result<HeaderParsed> {
        if st.state > 3 || st.start > st.cursor || st.cursor > src.len() {
            return Err(Error::HeaderName);
        }
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
            expect_lf!(bytes => Err(Error::NewLine));
            bytes.commit();
            return Ok(Status::Complete(HeaderParsed::Eof(bytes.cursor())));
        } else if b == b'\n' {
            bytes.commit();
            return Ok(Status::Complete(HeaderParsed::Eof(bytes.cursor())));
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
                expect_lf!(bytes => Err(Error::HeaderValue));
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
                expect_lf!(bytes => Err(Error::HeaderValue));
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
