---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

### Structure

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "version": 4,
  "psk": "password",
  "userkey": "",
  "reuse": false,
  "udp_flow": false,
  "network": "tcp",
  "obfs_mode": "",
  "obfs_host": "",

  ... // Dial Fields
}
```

### Version 6 Structure

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "version": 6,
  "psk": "password",
  "userkey": "",
  "reuse": false,
  "udp_flow": false,
  "network": "tcp",
  "mode": "",
  "http_framing": false,

  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### version

==Required==

The Snell protocol version, one of `4` `6`.

Version `4` supports HTTP obfuscation (`obfs_mode` / `obfs_host`); version `6`
replaces it with traffic shaping (`mode`) and requires a `psk` of 12 to 255
bytes.

!!! note

    Since we intentionally do not support the QUIC proxy mode of Snell v5, the v5 wire protocol
    is effectively identical to v4, so no separate v4 server or v5 client is provided.

#### psk

==Required==

The pre-shared key.

#### userkey

The user key, used to authenticate against a multi-user server.

#### reuse

Enable connection reuse (the Snell v2 `CONNECT` command).

#### udp_flow

Enable the experimental sing-tun UDP flow adapter. Each UDP five-tuple is independently resolved and DNATed, while selectors reuse one Snell UDP packet connection whenever possible. A `resolve` route action must run before routing Fake-IP UDP traffic to this outbound.

#### network

Enabled network

One of `tcp` `udp`.

Both is enabled by default.

#### obfs_mode

==Version 4 only==

HTTP obfuscation mode, one of `none` `http`.

`none` is used by default.

#### obfs_host

==Version 4 only==

The HTTP `Host` header sent when `obfs_mode` is `http`.

`bing.com` is used by default.

#### mode

==Version 6 only==

Traffic shaping mode, one of `default` `unshaped` `unsafe-raw`.

`default` is used by default.

#### http_framing

==Version 6 default mode only; fork extension==

Enable matched HTTP framing on the first client write to work around the reproduced TCP Fast Open persistent slowdown. Disabled by default. Both endpoints must support this extension: an outbound connects either to an inbound with the same setting or to `snell-http-relay` forwarding to the existing Snell server. It is incompatible with an unmodified Snell listener when enabled directly.

The receiver reconstructs deterministic profile padding and preserves the original Snell salt, ciphertext and authentication. The header is paid for by those recovered bytes; profiles with insufficient recoverable padding are rejected during configuration. The kernel chooses normal TCP segmentation without an MSS cache or a separate warmup connection. Decoding starts as soon as the header and salt-position bytes arrive, without waiting for the complete body. Subsequent writes and server replies retain the normal Snell format. This option does not itself enable TCP Fast Open; use the existing dial/listen setting as appropriate.

The fixed `.invalid` Host value is a framing literal and is not resolved. No HTTP server or TLS handshake is involved. This mechanism has been tested against a specific reproduced path defect; it is not a replacement for Snell encryption.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
