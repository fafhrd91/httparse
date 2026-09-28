# ntex-httparse

[![crates.io](https://img.shields.io/crates/v/ntex-httparse.svg)](https://crates.io/crates/ntex-httparse)
[![Released API docs](https://docs.rs/ntex-httparse/badge.svg)](https://docs.rs/ntex-httparse)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE-MIT)
[![CI](https://github.com/fafhrd91/httparse/actions/workflows/ci.yml/badge.svg)](https://github.com/fafhrd91/httparse/actions/workflows/ci.yml)

A push parser for the HTTP 1.x protocol, used by [ntex](https://crates.io/crates/ntex).
Fork of [httparse](https://crates.io/crates/httparse). Avoids allocations. No copy. **Fast.**

Works with `no_std`, simply disable the `std` Cargo feature.

[Changelog](./CHANGES.md)

## Usage

The request line and headers are parsed separately. Parsed parts are
returned as positions into the buffer.

```rust
use ntex_httparse::{Header, HeaderParsed, Request, Status};

let mut req = Request::default();
let buf = b"GET /index.html HTTP/1.1\r\nHost";
let mut pos = req.parse(buf)?.unwrap();
assert_eq!(&buf[req.path.start..req.path.end], b"/index.html");

let mut header = Header::default();
// a partial header, so we try again once we have more data
assert!(header.parse(&buf[pos..])?.is_partial());

let buf = b"GET /index.html HTTP/1.1\r\nHost: example.domain\r\n\r\n";
while let Status::Complete(parsed) = header.parse(&buf[pos..])? {
    match parsed {
        HeaderParsed::Header(len) => pos += len,
        HeaderParsed::Eof(len) => {
            pos += len;
            break;
        }
    }
}
assert_eq!(pos, buf.len());
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
