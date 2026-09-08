# Local sing-mux patch

Source: `github.com/sagernet/sing-mux` **v0.3.5**, the existing dependency.
The Go sources, module files, and upstream license are copied unchanged except
for `h2mux_conn.go` and `h2mux.go`.

The VLESS TCP multiplex / UDP flow coexistence regression exposed a race
between `httpConn.setup`, `Read`, and `Close`. `Read` now waits for response
publication; `Close` serializes with setup, unblocks a pending reader, and
disposes of a response body that arrives after closure. No protocol changes.

The CI coexistence test also caught concurrent explicit/session-reader closes
of the HTTP/2 server session panicking on its `done` channel. `sync.Once` now
closes that channel and the transport together, returning the same result to
all callers. Closing also releases an HTTP handler whose stream has not yet
been accepted, instead of leaving it blocked on the inbound channel.
`h2mux_test.go` covers concurrent closes and an unaccepted stream.

The upstream v0.3.6 source still contains this race as of 2026-09-07. The local
module replacement lets regular Go, gomobile, and CI builds use the same fix
without modifying the module cache or adding build-time patch commands.
The separate `test/` module repeats the replacement because Go does not inherit
replacement directives from dependencies.
CI checks both modules' required versions against `UPSTREAM_VERSION`, so an
upstream dependency update requires rebasing this patch before publishing.
Remove the replacement and this directory when an upstream release includes
the fix, keeping the regressions in `protocol/vless`.
