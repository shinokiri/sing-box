# Local sing-mux patch

Source: `github.com/sagernet/sing-mux` **v0.3.5**, the existing dependency.
The Go sources, module files, and upstream license are copied unchanged except
for `h2mux_conn.go`.

The VLESS TCP multiplex / UDP flow coexistence regression exposed a race
between `httpConn.setup`, `Read`, and `Close`. `Read` now waits for response
publication; `Close` serializes with setup, unblocks a pending reader, and
disposes of a response body that arrives after closure. No protocol changes.

The upstream v0.3.6 source still contains this race as of 2026-09-07. The local
module replacement lets regular Go, gomobile, and CI builds use the same fix
without modifying the module cache or adding build-time patch commands.
Remove the replacement and this directory when an upstream release includes
the fix, keeping the regressions in `protocol/vless`.
