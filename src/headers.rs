use crate::{Error, Result, Status, iter::Bytes, simd, utils};

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
        let mut bytes = Bytes::new(src);
        parse_header_iter_uninit(&mut bytes, self)
    }
}

fn parse_header_iter_uninit(bytes: &mut Bytes<'_>, header: &mut Header) -> Result<HeaderParsed> {
    // Track starting pointer to calculate the number of bytes parsed.
    let start = bytes.as_ref().as_ptr() as usize;

    // a newline here means the head is over!
    let b = next!(bytes);
    if b == b'\r' {
        expect!(bytes.next() == b'\n' => Err(Error::NewLine));
        let end = bytes.as_ref().as_ptr() as usize;
        return Ok(Status::Complete(HeaderParsed::Eof(end - start)));
    } else if b == b'\n' {
        let end = bytes.as_ref().as_ptr() as usize;
        return Ok(Status::Complete(HeaderParsed::Eof(end - start)));
    }

    // parse header name until colon
    {
        if !utils::is_header_name_token(b) {
            return Err(Error::HeaderName);
        }
        header.name_start = bytes.slice_pos() - 1;

        simd::match_header_name_vectored(bytes);
        if next!(bytes) == b':' {
            // SAFETY: previously bumped by 1 with next! -> always safe.
            header.name_end = bytes.slice_pos() - 1;
            bytes.commit();
        } else {
            return Err(Error::HeaderName);
        }
    }

    let mut b;

    // eat white space between colon and value
    'whitespace_after_colon: loop {
        b = next!(bytes);
        if b == b' ' || b == b'\t' {
            bytes.commit();
            continue 'whitespace_after_colon;
        }
        if utils::is_header_value_token(b) {
            header.value_start = bytes.slice_pos() - 1;
            break 'whitespace_after_colon;
        }

        if b == b'\r' {
            expect!(bytes.next() == b'\n' => Err(Error::HeaderValue));
        } else if b != b'\n' {
            return Err(Error::HeaderValue);
        }
        bytes.commit();

        // This produces an empty slice that points to the beginning
        // of the whitespace.
        header.value_start = bytes.slice_pos();
        header.value_end = bytes.slice_pos();
        return Ok(Status::Complete(HeaderParsed::Header(bytes.slice_pos())));
    }

    // parse value till EOL
    {
        simd::match_header_value_vectored(bytes);

        header.value_end = bytes.slice_pos();
        let value = bytes.slice();

        // check ctl
        let b = next!(bytes);
        if b == b'\r' {
            expect!(bytes.next() == b'\n' => Err(Error::HeaderValue));
        } else if b != b'\n' {
            return Err(Error::HeaderValue);
        }

        // trim trailing whitespace in the header
        if let Some(last_visible) = value.iter().rposition(|b| *b != b' ' && *b != b'\t') {
            header.value_end = header.value_start + last_visible + 1;
        }
        bytes.commit();
    }

    Ok(Status::Complete(HeaderParsed::Header(bytes.slice_pos())))
}
