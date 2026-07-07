use ntex_httparse::{Error, Header, HeaderParsed, Request, Status};

macro_rules! req {
    ($name:ident, $buf:expr, |$len:ident, $method:ident, $path:ident, $version:ident, $headers:ident, $headers_eof:ident| $body:expr) => {
        #[test]
        fn $name() {
            let mut b = $buf.as_ref();
            let mut req = Request::default();
            let mut consumed = req.parse(b).unwrap().unwrap();
            let mut headers = Vec::new();
            let mut header = Header::default();
            let mut headers_eof = false;
            b = &b[consumed..];

            while let Ok(Status::Complete(hdr)) = header.parse(b) {
                match hdr {
                    HeaderParsed::Header(l) => {
                        consumed += l;
                        let name =
                            String::from_utf8(Vec::from(&b[header.name.start..header.name.end]))
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

            let path =
                unsafe { str::from_utf8_unchecked(&$buf.as_ref()[req.path.start..req.path.end]) };
            let method = unsafe {
                str::from_utf8_unchecked(&$buf.as_ref()[req.method.start..req.method.end])
            };

            closure(consumed, method, path, req.version, headers, headers_eof);

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

macro_rules! req_err {
    ($name:ident, $buf:expr, $err:expr) => {
        #[test]
        fn $name() {
            assert_eq!(Request::default().parse($buf.as_ref()), $err);
        }
    };
}

req! {
    urltest_001,
    b"GET /bar;par?b HTTP/1.1\r\nHost: foo\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/bar;par?b");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"foo");
        assert!(eof);
    }
}

req! {
    urltest_002,
    b"GET /x HTTP/1.1\r\nHost: test\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/x");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"test");
        assert!(eof);
    }
}

req! {
    urltest_003,
    b"GET /x HTTP/1.1\r\nHost: test\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/x");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"test");
        assert!(eof);
    }
}

req! {
    urltest_004,
    b"GET /foo/foo.com HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/foo.com");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_005,
    b"GET /foo/:foo.com HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/:foo.com");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_006,
    b"GET /foo/foo.com HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/foo.com");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_007,
    b"GET  foo.com HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "foo.com");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_008,
    b"GET /%20b%20?%20d%20 HTTP/1.1\r\nHost: f\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/%20b%20?%20d%20");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"f");
        assert!(eof);
    }
}

req_err! {
    urltest_009,
    b"GET x x HTTP/1.1\r\nHost: \r\n\r\n",
    Err(Error::Version)
}

req! {
    urltest_010,
    b"GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/c");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"f");
        assert!(eof);
    }
}

req! {
    urltest_011,
    b"GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/c");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"f");
        assert!(eof);
    }
}

req! {
    urltest_012,
    b"GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/c");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"f");
        assert!(eof);
    }
}

req! {
    urltest_013,
    b"GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/c");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"f");
        assert!(eof);
    }
}

req! {
    urltest_014,
    b"GET /c HTTP/1.1\r\nHost: f\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/c");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"f");
        assert!(eof);
    }
}

req! {
    urltest_015,
    b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_016,
    b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_017,
    b"GET /foo/:foo.com/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/:foo.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_018,
    b"GET /foo/:foo.com/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/:foo.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_019,
    b"GET /foo/: HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/:");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_020,
    b"GET /foo/:a HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/:a");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_021,
    b"GET /foo/:/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/:/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_022,
    b"GET /foo/:/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/:/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_023,
    b"GET /foo/: HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/:");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_024,
    b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_025,
    b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_026,
    b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_027,
    b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_028,
    b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_029,
    b"GET /foo/:23 HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/:23");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_030,
    b"GET /:23 HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/:23");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_031,
    b"GET /foo/:: HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/::");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_032,
    b"GET /foo/::23 HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/::23");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_033,
    b"GET /d HTTP/1.1\r\nHost: c\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/d");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"c");
        assert!(eof);
    }
}

req! {
    urltest_034,
    b"GET /foo/:@c:29 HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/:@c:29");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_035,
    b"GET //@ HTTP/1.1\r\nHost: foo.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "//@");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"foo.com");
        assert!(eof);
    }
}

req! {
    urltest_036,
    b"GET /b:c/d@foo.com/ HTTP/1.1\r\nHost: a\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/b:c/d@foo.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"a");
        assert!(eof);
    }
}

req! {
    urltest_037,
    b"GET /bar.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/bar.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_038,
    b"GET /////// HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "///////");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_039,
    b"GET ///////bar.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "///////bar.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_040,
    b"GET //:///// HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "//://///");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_041,
    b"GET /foo HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_042,
    b"GET /bar HTTP/1.1\r\nHost: foo\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"foo");
        assert!(eof);
    }
}

req! {
    urltest_043,
    b"GET /path;a??e HTTP/1.1\r\nHost: foo\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/path;a??e");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"foo");
        assert!(eof);
    }
}

req! {
    urltest_044,
    b"GET /abcd?efgh?ijkl HTTP/1.1\r\nHost: foo\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/abcd?efgh?ijkl");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"foo");
        assert!(eof);
    }
}

req! {
    urltest_045,
    b"GET /abcd HTTP/1.1\r\nHost: foo\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/abcd");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"foo");
        assert!(eof);
    }
}

req! {
    urltest_046,
    b"GET /foo/[61:24:74]:98 HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/[61:24:74]:98");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_047,
    b"GET /foo/[61:27]/:foo HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/[61:27]/:foo");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_048,
    b"GET /example.com/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_049,
    b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_050,
    b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_051,
    b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_052,
    b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_053,
    b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_054,
    b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_055,
    b"GET /foo/example.com/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_056,
    b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_057,
    b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_058,
    b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_059,
    b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_060,
    b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_061,
    b"GET /a/b/c HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/a/b/c");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_062,
    b"GET /a/%20/c HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/a/%20/c");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_063,
    b"GET /a%2fc HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/a%2fc");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_064,
    b"GET /a/%2f/c HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/a/%2f/c");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_065,
    b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_066,
    b"GET text/html,test HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "text/html,test");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_067,
    b"GET 1234567890 HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "1234567890");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_068,
    b"GET /c:/foo/bar.html HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/c:/foo/bar.html");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_069,
    b"GET /c:////foo/bar.html HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/c:////foo/bar.html");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_070,
    b"GET /C:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_071,
    b"GET /C:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_072,
    b"GET /C:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_073,
    b"GET /file HTTP/1.1\r\nHost: server\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/file");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"server");
        assert!(eof);
    }
}

req! {
    urltest_074,
    b"GET /file HTTP/1.1\r\nHost: server\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/file");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"server");
        assert!(eof);
    }
}

req! {
    urltest_075,
    b"GET /file HTTP/1.1\r\nHost: server\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/file");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"server");
        assert!(eof);
    }
}

req! {
    urltest_076,
    b"GET /foo/bar.txt HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar.txt");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_077,
    b"GET /home/me HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/home/me");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_078,
    b"GET /test HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_079,
    b"GET /test HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_080,
    b"GET /tmp/mock/test HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/tmp/mock/test");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_081,
    b"GET /tmp/mock/test HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/tmp/mock/test");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_082,
    b"GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_083,
    b"GET /.foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/.foo");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_084,
    b"GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_085,
    b"GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_086,
    b"GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_087,
    b"GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_088,
    b"GET /foo/..bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/..bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_089,
    b"GET /foo/ton HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/ton");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_090,
    b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/a");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_091,
    b"GET /ton HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/ton");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_092,
    b"GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_093,
    b"GET /foo/%2e%2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/%2e%2");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_094,
    b"GET /%2e.bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/%2e.bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_095,
    b"GET // HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "//");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_096,
    b"GET /foo/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_097,
    b"GET /foo/bar/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_098,
    b"GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_099,
    b"GET /%20foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/%20foo");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_100,
    b"GET /foo% HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo%");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_101,
    b"GET /foo%2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo%2");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_102,
    b"GET /foo%2zbar HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo%2zbar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_103,
    b"GET /foo%2%C3%82%C2%A9zbar HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo%2%C3%82%C2%A9zbar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_104,
    b"GET /foo%41%7a HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo%41%7a");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_105,
    b"GET /foo%C2%91%91 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo%C2%91%91");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_106,
    b"GET /foo%00%51 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo%00%51");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_107,
    b"GET /(%28:%3A%29) HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/(%28:%3A%29)");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_108,
    b"GET /%3A%3a%3C%3c HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/%3A%3a%3C%3c");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_109,
    b"GET /foobar HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foobar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_110,
    b"GET //foo//bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "//foo//bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_111,
    b"GET /%7Ffp3%3Eju%3Dduvgw%3Dd HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/%7Ffp3%3Eju%3Dduvgw%3Dd");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_112,
    b"GET /@asdf%40 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/@asdf%40");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_113,
    b"GET /%E4%BD%A0%E5%A5%BD%E4%BD%A0%E5%A5%BD HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/%E4%BD%A0%E5%A5%BD%E4%BD%A0%E5%A5%BD");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_114,
    b"GET /%E2%80%A5/foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/%E2%80%A5/foo");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_115,
    b"GET /%EF%BB%BF/foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/%EF%BB%BF/foo");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_116,
    b"GET /%E2%80%AE/foo/%E2%80%AD/bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/%E2%80%AE/foo/%E2%80%AD/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_117,
    b"GET /foo?bar=baz HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo?bar=baz");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"www.google.com");
        assert!(eof);
    }
}

req! {
    urltest_118,
    b"GET /foo?bar=baz HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo?bar=baz");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"www.google.com");
        assert!(eof);
    }
}

req! {
    urltest_119,
    b"GET test HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "test");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_120,
    b"GET /foo%2Ehtml HTTP/1.1\r\nHost: www\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo%2Ehtml");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"www");
        assert!(eof);
    }
}

req! {
    urltest_121,
    b"GET /foo/html HTTP/1.1\r\nHost: www\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/html");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"www");
        assert!(eof);
    }
}

req! {
    urltest_122,
    b"GET /foo HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"www.google.com");
        assert!(eof);
    }
}

req! {
    urltest_123,
    b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_124,
    b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_125,
    b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_126,
    b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_127,
    b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_128,
    b"GET /example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_129,
    b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_130,
    b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_131,
    b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_132,
    b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_133,
    b"GET example.com/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "example.com/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_134,
    b"GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test.txt");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"www.example.com");
        assert!(eof);
    }
}

req! {
    urltest_135,
    b"GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test.txt");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"www.example.com");
        assert!(eof);
    }
}

req! {
    urltest_136,
    b"GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test.txt");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"www.example.com");
        assert!(eof);
    }
}

req! {
    urltest_137,
    b"GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test.txt");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"www.example.com");
        assert!(eof);
    }
}

req! {
    urltest_138,
    b"GET /aaa/test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/aaa/test.txt");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"www.example.com");
        assert!(eof);
    }
}

req! {
    urltest_139,
    b"GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test.txt");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"www.example.com");
        assert!(eof);
    }
}

req! {
    urltest_140,
    b"GET /%E4%B8%AD/test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/%E4%B8%AD/test.txt");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"www.example.com");
        assert!(eof);
    }
}

req! {
    urltest_141,
    b"GET /... HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/...");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_142,
    b"GET /a HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/a");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_143,
    b"GET /%EF%BF%BD?%EF%BF%BD HTTP/1.1\r\nHost: x\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/%EF%BF%BD?%EF%BF%BD");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"x");
        assert!(eof);
    }
}

req! {
    urltest_144,
    b"GET /bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.com");
        assert!(eof);
    }
}

req! {
    urltest_145,
    b"GET test HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "test");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_146,
    b"GET x@x.com HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "x@x.com");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_147,
    b"GET , HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, ",");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_148,
    b"GET blank HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "blank");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_149,
    b"GET test?test HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "test?test");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_150,
    b"GET /%60%7B%7D?`{} HTTP/1.1\r\nHost: h\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/%60%7B%7D?`{}");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"h");
        assert!(eof);
    }
}

req! {
    urltest_151,
    b"GET /?%27 HTTP/1.1\r\nHost: host\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/?%27");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"host");
        assert!(eof);
    }
}

req! {
    urltest_152,
    b"GET /?' HTTP/1.1\r\nHost: host\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/?'");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"host");
        assert!(eof);
    }
}

req! {
    urltest_153,
    b"GET /some/path HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/some/path");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_154,
    b"GET /smth HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/smth");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_155,
    b"GET /some/path HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/some/path");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_156,
    b"GET /pa/i HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/pa/i");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_157,
    b"GET /i HTTP/1.1\r\nHost: ho\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/i");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"ho");
        assert!(eof);
    }
}

req! {
    urltest_158,
    b"GET /pa/i HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/pa/i");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_159,
    b"GET /i HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/i");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_160,
    b"GET /i HTTP/1.1\r\nHost: ho\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/i");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"ho");
        assert!(eof);
    }
}

req! {
    urltest_161,
    b"GET /i HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/i");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_162,
    b"GET /i HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/i");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_163,
    b"GET /i HTTP/1.1\r\nHost: ho\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/i");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"ho");
        assert!(eof);
    }
}

req! {
    urltest_164,
    b"GET /i HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/i");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_165,
    b"GET /pa/pa?i HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/pa/pa?i");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_166,
    b"GET /pa?i HTTP/1.1\r\nHost: ho\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/pa?i");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"ho");
        assert!(eof);
    }
}

req! {
    urltest_167,
    b"GET /pa/pa?i HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/pa/pa?i");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_168,
    b"GET sd HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "sd");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_169,
    b"GET sd/sd HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "sd/sd");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_170,
    b"GET /pa/pa HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/pa/pa");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_171,
    b"GET /pa HTTP/1.1\r\nHost: ho\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/pa");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"ho");
        assert!(eof);
    }
}

req! {
    urltest_172,
    b"GET /pa/pa HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/pa/pa");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_173,
    b"GET /x HTTP/1.1\r\nHost: %C3%B1\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/x");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"%C3%B1");
        assert!(eof);
    }
}

req! {
    urltest_174,
    b"GET \\.\\./ HTTP/1.1\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "\\.\\./");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 0);
        assert!(eof);
    }
}

req! {
    urltest_175,
    b"GET :a@example.net HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, ":a@example.net");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_176,
    b"GET %NBD HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "%NBD");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_177,
    b"GET %1G HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "%1G");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_178,
    b"GET /relative_import.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/relative_import.html");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"127.0.0.1");
        assert!(eof);
    }
}

req! {
    urltest_179,
    b"GET /?foo=%7B%22abc%22 HTTP/1.1\r\nHost: facebook.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/?foo=%7B%22abc%22");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"facebook.com");
        assert!(eof);
    }
}

req! {
    urltest_180,
    b"GET /jqueryui@1.2.3 HTTP/1.1\r\nHost: localhost\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/jqueryui@1.2.3");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"localhost");
        assert!(eof);
    }
}

req! {
    urltest_181,
    b"GET /path?query HTTP/1.1\r\nHost: host\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/path?query");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"host");
        assert!(eof);
    }
}

req! {
    urltest_182,
    b"GET /foo/bar?a=b&c=d HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar?a=b&c=d");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_183,
    b"GET /foo/bar??a=b&c=d HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar??a=b&c=d");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_184,
    b"GET /foo/bar HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert!(eof);
    }
}

req! {
    urltest_185,
    b"GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/baz?qux");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"foo.bar");
        assert!(eof);
    }
}

req! {
    urltest_186,
    b"GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/baz?qux");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"foo.bar");
        assert!(eof);
    }
}

req! {
    urltest_187,
    b"GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/baz?qux");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"foo.bar");
        assert!(eof);
    }
}

req! {
    urltest_188,
    b"GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/baz?qux");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"foo.bar");
        assert!(eof);
    }
}

req! {
    urltest_189,
    b"GET /baz?qux HTTP/1.1\r\nHost: foo.bar\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/baz?qux");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"foo.bar");
        assert!(eof);
    }
}

req! {
    urltest_190,
    b"GET /C%3A/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C%3A/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_191,
    b"GET /C%7C/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C%7C/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_192,
    b"GET /C:/Users/Domenic/Dropbox/GitHub/tmpvar/jsdom/test/level2/html/files/pix/submit.gif HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/Users/Domenic/Dropbox/GitHub/tmpvar/jsdom/test/level2/html/files/pix/submit.gif");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_193,
    b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_194,
    b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_195,
    b"GET /d: HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/d:");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_196,
    b"GET /d:/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/d:/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_197,
    b"GET /test?test HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?test");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_198,
    b"GET /test?test HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?test");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert!(eof);
    }
}

req! {
    urltest_199,
    b"GET /test?x HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?x");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 32);
        assert!(eof);
    }
}

req! {
    urltest_200,
    b"GET /test?x HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?x");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 32);
        assert!(eof);
    }
}

req! {
    urltest_201,
    b"GET /test?test HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?test");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 35);
        assert!(eof);
    }
}

req! {
    urltest_202,
    b"GET /test?test HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?test");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 35);
        assert!(eof);
    }
}

req! {
    urltest_203,
    b"GET /?fox HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/?fox");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 30);
        assert!(eof);
    }
}

req! {
    urltest_204,
    b"GET /localhost//cat HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/localhost//cat");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 40);
        assert!(eof);
    }
}

req! {
    urltest_205,
    b"GET /localhost//cat HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/localhost//cat");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 40);
        assert!(eof);
    }
}

req! {
    urltest_206,
    b"GET /mouse HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/mouse");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 31);
        assert!(eof);
    }
}

req! {
    urltest_207,
    b"GET /pig HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/pig");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 29);
        assert!(eof);
    }
}

req! {
    urltest_208,
    b"GET /pig HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/pig");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 29);
        assert!(eof);
    }
}

req! {
    urltest_209,
    b"GET /pig HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/pig");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 29);
        assert!(eof);
    }
}

req! {
    urltest_210,
    b"GET /localhost//pig HTTP/1.1\r\nHost: lion\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/localhost//pig");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"lion");
        assert_eq!(_len, 44);
        assert!(eof);
    }
}

req! {
    urltest_211,
    b"GET /rooibos HTTP/1.1\r\nHost: tea\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/rooibos");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"tea");
        assert_eq!(_len, 36);
        assert!(eof);
    }
}

req! {
    urltest_212,
    b"GET /?chai HTTP/1.1\r\nHost: tea\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/?chai");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"tea");
        assert_eq!(_len, 34);
        assert!(eof);
    }
}

req! {
    urltest_213,
    b"GET /C: HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 28);
        assert!(eof);
    }
}

req! {
    urltest_214,
    b"GET /C: HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 28);
        assert!(eof);
    }
}

req! {
    urltest_215,
    b"GET /C: HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 28);
        assert!(eof);
    }
}

req! {
    urltest_216,
    b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 29);
        assert!(eof);
    }
}

req! {
    urltest_217,
    b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 29);
        assert!(eof);
    }
}

req! {
    urltest_218,
    b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 29);
        assert!(eof);
    }
}

req! {
    urltest_219,
    b"GET /dir/C HTTP/1.1\r\nHost: host\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/dir/C");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"host");
        assert_eq!(_len, 35);
        assert!(eof);
    }
}

req! {
    urltest_220,
    b"GET /dir/C|a HTTP/1.1\r\nHost: host\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/dir/C|a");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"host");
        assert_eq!(_len, 37);
        assert!(eof);
    }
}

req! {
    urltest_221,
    b"GET /c:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/c:/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 36);
        assert!(eof);
    }
}

req! {
    urltest_222,
    b"GET /c:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/c:/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 36);
        assert!(eof);
    }
}

req! {
    urltest_223,
    b"GET /c:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/c:/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 36);
        assert!(eof);
    }
}

req! {
    urltest_224,
    b"GET /c:/foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/c:/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 36);
        assert!(eof);
    }
}

req! {
    urltest_225,
    b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 29);
        assert!(eof);
    }
}

req! {
    urltest_226,
    b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 29);
        assert!(eof);
    }
}

req! {
    urltest_227,
    b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 29);
        assert!(eof);
    }
}

req! {
    urltest_228,
    b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 29);
        assert!(eof);
    }
}

req! {
    urltest_229,
    b"GET /C:/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/C:/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 29);
        assert!(eof);
    }
}

req! {
    urltest_230,
    b"GET /?q=v HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/?q=v");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 30);
        assert!(eof);
    }
}

req! {
    urltest_231,
    b"GET ?x HTTP/1.1\r\nHost: %C3%B1\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "?x");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"%C3%B1");
        assert_eq!(_len, 33);
        assert!(eof);
    }
}

req! {
    urltest_232,
    b"GET ?x HTTP/1.1\r\nHost: %C3%B1\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "?x");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"%C3%B1");
        assert_eq!(_len, 33);
        assert!(eof);
    }
}

req! {
    urltest_233,
    b"GET // HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "//");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 27);
        assert!(eof);
    }
}

req! {
    urltest_234,
    b"GET //x/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "//x/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 29);
        assert!(eof);
    }
}

req! {
    urltest_235,
    b"GET /someconfig;mode=netascii HTTP/1.1\r\nHost: foobar.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/someconfig;mode=netascii");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"foobar.com");
        assert_eq!(_len, 60);
        assert!(eof);
    }
}

req! {
    urltest_236,
    b"GET /Index.ut2 HTTP/1.1\r\nHost: 10.10.10.10\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/Index.ut2");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"10.10.10.10");
        assert_eq!(_len, 46);
        assert!(eof);
    }
}

req! {
    urltest_237,
    b"GET /0?baz=bam&qux=baz HTTP/1.1\r\nHost: somehost\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/0?baz=bam&qux=baz");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"somehost");
        assert_eq!(_len, 51);
        assert!(eof);
    }
}

req! {
    urltest_238,
    b"GET /sup HTTP/1.1\r\nHost: host\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/sup");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"host");
        assert_eq!(_len, 33);
        assert!(eof);
    }
}

req! {
    urltest_239,
    b"GET /foo/bar.git HTTP/1.1\r\nHost: github.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar.git");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"github.com");
        assert_eq!(_len, 47);
        assert!(eof);
    }
}

req! {
    urltest_240,
    b"GET /channel?passwd HTTP/1.1\r\nHost: myserver.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/channel?passwd");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"myserver.com");
        assert_eq!(_len, 52);
        assert!(eof);
    }
}

req! {
    urltest_241,
    b"GET /foo.bar.org?type=TXT HTTP/1.1\r\nHost: fw.example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo.bar.org?type=TXT");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"fw.example.org");
        assert_eq!(_len, 60);
        assert!(eof);
    }
}

req! {
    urltest_242,
    b"GET /ou=People,o=JNDITutorial HTTP/1.1\r\nHost: localhost\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/ou=People,o=JNDITutorial");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"localhost");
        assert_eq!(_len, 59);
        assert!(eof);
    }
}

req! {
    urltest_243,
    b"GET /foo/bar HTTP/1.1\r\nHost: github.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"github.com");
        assert_eq!(_len, 43);
        assert!(eof);
    }
}

req! {
    urltest_244,
    b"GET ietf:rfc:2648 HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "ietf:rfc:2648");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 38);
        assert!(eof);
    }
}

req! {
    urltest_245,
    b"GET joe@example.org,2001:foo/bar HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "joe@example.org,2001:foo/bar");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 53);
        assert!(eof);
    }
}

req! {
    urltest_246,
    b"GET /path HTTP/1.1\r\nHost: H%4fSt\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/path");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"H%4fSt");
        assert_eq!(_len, 36);
        assert!(eof);
    }
}

req! {
    urltest_247,
    b"GET https://example.com:443/ HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "https://example.com:443/");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 49);
        assert!(eof);
    }
}

req! {
    urltest_248,
    b"GET d3958f5c-0777-0845-9dcf-2cb28783acaf HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "d3958f5c-0777-0845-9dcf-2cb28783acaf");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 61);
        assert!(eof);
    }
}

req! {
    urltest_249,
    b"GET /test?%22 HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?%22");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert_eq!(_len, 45);
        assert!(eof);
    }
}

req! {
    urltest_250,
    b"GET /test HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert_eq!(_len, 41);
        assert!(eof);
    }
}

req! {
    urltest_251,
    b"GET /test?%3C HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?%3C");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert_eq!(_len, 45);
        assert!(eof);
    }
}

req! {
    urltest_252,
    b"GET /test?%3E HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?%3E");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert_eq!(_len, 45);
        assert!(eof);
    }
}

req! {
    urltest_253,
    b"GET /test?%E2%8C%A3 HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?%E2%8C%A3");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert_eq!(_len, 51);
        assert!(eof);
    }
}

req! {
    urltest_254,
    b"GET /test?%23%23 HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?%23%23");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert_eq!(_len, 48);
        assert!(eof);
    }
}

req! {
    urltest_255,
    b"GET /test?%GH HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?%GH");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert_eq!(_len, 45);
        assert!(eof);
    }
}

req! {
    urltest_256,
    b"GET /test?a HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?a");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert_eq!(_len, 43);
        assert!(eof);
    }
}

req! {
    urltest_257,
    b"GET /test?a HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?a");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert_eq!(_len, 43);
        assert!(eof);
    }
}

req! {
    urltest_258,
    b"GET /test-a-colon-slash.html HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test-a-colon-slash.html");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 49);
        assert!(eof);
    }
}

req! {
    urltest_259,
    b"GET /test-a-colon-slash-slash.html HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test-a-colon-slash-slash.html");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 55);
        assert!(eof);
    }
}

req! {
    urltest_260,
    b"GET /test-a-colon-slash-b.html HTTP/1.1\r\nHost: \r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test-a-colon-slash-b.html");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"");
        assert_eq!(_len, 51);
        assert!(eof);
    }
}

req! {
    urltest_261,
    b"GET /test-a-colon-slash-slash-b.html HTTP/1.1\r\nHost: b\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test-a-colon-slash-slash-b.html");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"b");
        assert_eq!(_len, 58);
        assert!(eof);
    }
}

req! {
    urltest_262,
    b"GET /test?a HTTP/1.1\r\nHost: example.org\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/test?a");
        assert_eq!(version, 1);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"example.org");
        assert_eq!(_len, 43);
        assert!(eof);
    }
}

req! {
    urltest_nvidia,
    b"GET /nvidia_web_services/controller.gfeclientcontent.php/com.nvidia.services.GFEClientContent.getShieldReady/{\"gcV\":\"2.2.2.0\",\"dID\":\"1341\",\"osC\":\"6.20\",\"is6\":\"1\",\"lg\":\"1033\",\"GFPV\":\"389.08\",\"isO\":\"1\",\"sM\":\"16777216\"} HTTP/1.0\r\nHost: gfwsl.geforce.com\r\n\r\n",
    |_len, method, path, version, headers, eof| {
        assert_eq!(method, "GET");
        assert_eq!(path, "/nvidia_web_services/controller.gfeclientcontent.php/com.nvidia.services.GFEClientContent.getShieldReady/{\"gcV\":\"2.2.2.0\",\"dID\":\"1341\",\"osC\":\"6.20\",\"is6\":\"1\",\"lg\":\"1033\",\"GFPV\":\"389.08\",\"isO\":\"1\",\"sM\":\"16777216\"}");
        assert_eq!(version, 0);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, b"gfwsl.geforce.com");
        assert_eq!(_len, 254);
        assert!(eof);
    }
}
