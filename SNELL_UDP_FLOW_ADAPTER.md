# Experimental proxy UDP flow adapters

This branch connects both Snell UDP and VLESS/XUDP outbounds to sing-tun's
existing PreMatch/flow-DNAT path. The adapters are opt-in and do not change the
default behavior of either protocol.

## Why

With endpoint-independent UDP mapping, one application UDP socket may send to
several Fake-IP destinations through one packet association. The legacy packet
path resolves/translates only the destination that created that association, so
a later Fake-IP can be forwarded literally.

The flow path tracks the complete UDP five-tuple. Each Fake-IP target is
therefore independently resolved and DNATed, while sing-tun still reuses the
original source-port selector whenever the reverse tuple is unambiguous.
Different real targets can share one protocol-level UDP packet connection; only
a genuine reverse-tuple collision gets another selector and packet connection.

The common flow-port implementation now lives in `common/udpflow` and is shared
by Snell and VLESS/XUDP. It preserves protocol front/rear headroom and
serializes writes per selector on asynchronous workers. Packet data is copied
before the TUN reader reuses its buffers. Dialing, handshake reads, and writes
therefore do not hold up the TUN reader or other selectors.

Each adapter has distinct internal IPv4/IPv6 addresses so that two outbounds
using the same selector and real server cannot match each other's replies.
These addresses only identify dispatcher mappings; they are not sent to the
proxy server or returned to applications.

## Snell configuration

```json
{
  "type": "snell",
  "tag": "snell-out",
  "server": "example.com",
  "server_port": 443,
  "version": 6,
  "psk": "...",
  "udp_flow": true
}
```

## VLESS/XUDP configuration

```json
{
  "type": "vless",
  "tag": "vless-out",
  "server": "example.com",
  "server_port": 443,
  "uuid": "...",
  "flow": "xtls-rprx-vision",
  "packet_encoding": "xudp",
  "udp_flow": true,
  "tls": {
    "enabled": true
  }
}
```

For the first version, VLESS `udp_flow` requires XUDP and is deliberately
incompatible with outbound `multiplex`. XUDP already multiplexes multiple UDP
destinations inside one connection; adding the separate sing-box multiplex
layer would complicate selector ownership and lifecycle without helping this
use case.

## Route requirement

A `resolve` route action must run before the route action that selects a flow
enabled outbound. Example for IPv4-only UDP destinations:

```json
{
  "route": {
    "rules": [
      {
        "network": "udp",
        "action": "resolve",
        "strategy": "ipv4_only"
      },
      {
        "network": "udp",
        "action": "route",
        "outbound": "vless-out"
      }
    ]
  }
}
```

If a Fake-IP has not been resolved, the existing PreMatch logic rejects that
flow rather than leaking the Fake-IP.

## Scope

- Only UDP is routed through the flow port.
- TCP keeps each protocol's existing connection path.
- The adapter is disabled unless `udp_flow` is true.
- No server-side protocol changes are required.
- Snell and VLESS share the same packet parsing, selector management, reverse
  packet construction, idle cleanup, and headroom regression tests.

## Known limits

- A flow-enabled outbound can attach to one TUN dispatcher at a time. Additional
  inbounds use the existing packet path. Use a separate outbound instance per
  TUN inbound when each needs flow-based Fake-IP translation. This prevents
  independent inbound selector allocators from sharing the wrong association.
- Each selector has a queue of up to 64 pending packets. Each adapter allows up
  to 1,024 associations and 4 MiB of queued/in-flight payload data, excluding
  protocol framing and read buffers. Packets exceeding these limits are
  dropped with a trace-level forwarding error rather than blocking the TUN.
- Dialing and each protocol write have a 15-second timeout. A stalled write
  closes the association, including when the protocol is awaiting a handshake
  reply inside its write method. Later packets can create a fresh association;
  failed or queued packets on the old association are not replayed.
  Successful setup stops the dial timer without canceling the stream context,
  so HTTP/2 and gRPC associations remain usable until flow shutdown.
- UDP packet connections are kept per selector and swept after five minutes of
  inactivity. Network reset, inbound detach, parent context cancellation, and
  outbound close cancel pending dials and close active connections. Detach also
  discards queued packets and prevents late replies reaching a new inbound.
- The external server implementation and its host/cloud firewall still decide
  the final observable UDP mapping/filtering behavior.

## Validation

The regression suite uses the real sing-tun dispatcher to cover IPv4/IPv6
outbound isolation, colliding inbound selectors, and a silent Snell v6 server.
In-process Snell v4/v5 (plain and HTTP-obfuscated), Snell v6 (default,
unshaped, and unsafe-raw), and VLESS/XUDP servers exercise multi-destination
IPv4/IPv6 exchanges over one association. Other tests cover buffer ownership,
queue limits, cancel/timeout cleanup, failed-association replacement, late
replies after detach, and cancellation of the VLESS initial request.
VLESS/gRPC is also tested through the real outbound factory and transport.
Transport regressions cover concurrent response initialization and reads, and
closing before a response arrives without leaking its late response body.
QUIC dial and handshake cancellation, waiting for a shared connection, and
reuse after canceling a completed dial (including a context-bound streaming
UDP detour) are covered. WebSocket and HTTP Upgrade
handshakes are tested against a silent peer, including preservation of the
configured WebSocket subprotocol across attempts.

```sh
go test -race -count=1 ./common/udpflow ./protocol/snell ./protocol/vless ./transport/v2ray ./transport/v2raygrpclite ./transport/v2rayhttp
go test -race -tags with_gvisor,with_grpc,with_quic -count=1 ./common/udpflow ./protocol/snell ./protocol/vless ./transport/v2ray ./transport/v2raygrpclite ./transport/v2rayhttp ./transport/v2rayquic
CGO_ENABLED=0 go build -trimpath -tags "$(cat release/DEFAULT_BUILD_TAGS_OTHERS)" -ldflags "$(cat release/LDFLAGS) -s -w -buildid=" ./cmd/sing-box
```

These checks do not replace tests using a real TUN device and the deployed
proxy server, particularly when assessing public UDP mapping/filtering.

## GitHub Actions

The included `.github/workflows/verify-snell-udp-flow.yml` runs on relevant
pushes and pull requests with Go 1.25 and 1.26. It runs the race and gVisor checks
above, then creates a Linux amd64 artifact with the repository's non-Naive
release feature tags for each Go version.

Pushes to `udpflow` also run the existing `Build` workflow's Android jobs with
Go 1.26.7, NDK r28, and JDK 17. They build all four libbox architectures and the
`other` / `other-legacy` APK variants with the fork's existing signing settings.
The version is `1.14.0-udpflow.g<commit>`, and APKs are uploaded as Actions
artifacts. These push builds do not run release publishing, other platforms, or
repository-wide cache cleanup. Manual Build selections retain their existing
behavior.

Android builds on `udpflow` use the recorded `clients/android` submodule commit
(`b7bf31b6e553b30ab69a90a1769f9273cb25f089`, the 1.14.0 client with its default
interface notification fix). Do not replace it with a moving `dev` checkout:
the 1.15 development client requires libbox APIs absent from this branch.
APK metadata records both the core and Android client commits so each artifact
can be traced to its sources.

## Target base

Prepared from the uploaded `sing-box-snell-udp-flow` snapshot whose archive
comment identifies commit `a5defef983dd0e0584e6bc1e0173c055f76a3bd9`.
