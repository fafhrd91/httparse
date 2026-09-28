# Changes

## [2.2.0] - 2026-09-28

* `parse_chunk_size` rejects control characters other than HTAB in chunk
  extensions. Previously any octet was accepted, so a bare LF inside an
  extension could be treated as the line end by other parsers (request
  smuggling)
