# Changes

## [2.2.0] - 2026-09-28

* `parse_chunk_size` rejects control characters other than HTAB in chunk
  extensions. Previously any octet was accepted, so a bare LF inside an
  extension could be treated as the line end by other parsers (request
  smuggling)

* Header parsing resumed after a `Partial` result that ended right after a
  `\r` no longer accepts a bare CR (e.g. `X: a\rb\r\n` split after the `\r`
  produced the value `"a\rb"`)

* `Request::parse_with_state` no longer fails with `Error::Token` when the
  input is split right after the space following the request path

* `parse_chunk_size` rejects a chunk size line without digits (e.g. `\r\n` or
  `;ext\r\n`), which was accepted as the last chunk

* `Request::parse_with_state` and `Header::parse_with_state` return an error
  for an invalid `State` instead of panicking or returning stale positions

* `Response::parse` no longer skips empty lines between the version and the
  status code (e.g. `HTTP/1.1\r\n 200 OK`)

* `HeaderParsed::Eof` holds the position in the buffer, like
  `HeaderParsed::Header`, instead of the length of the final empty line. This
  only differs when `State` is not reset between headers

* Rewrite API docs and README for the fork's API; hide the benchmark-only
  `parse_method` and `parse_uri` from docs
