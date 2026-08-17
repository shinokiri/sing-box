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
serializes writes per selector.

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

- The current preparation environment cannot download Go 1.25.5 or modules, so
  the included GitHub Actions workflow must provide the real compile/test
  result.
- UDP packet connections are kept per selector and swept after five minutes of
  inactivity.
- The external server implementation and its host/cloud firewall still decide
  the final observable UDP mapping/filtering behavior.

## GitHub Actions

The included `.github/workflows/verify-snell-udp-flow.yml` now tests the shared
UDP flow package plus Snell and VLESS, then creates a Linux amd64 artifact. Run
the repository's normal multi-platform build workflow after this focused
workflow succeeds.

## Target base

Prepared from the uploaded `sing-box-snell-udp-flow` snapshot whose archive
comment identifies commit `a5defef983dd0e0584e6bc1e0173c055f76a3bd9`.
