---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

### Structure

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // Listen Fields

  "version": 5,
  "psk": "password",
  "users": [
    {
      "name": "sekai",
      "userkey": "user-password"
    }
  ],
  "obfs_mode": ""
}
```

### Version 6 Structure

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // Listen Fields

  "version": 6,
  "psk": "password",
  "users": [
    {
      "name": "sekai",
      "userkey": "user-password"
    }
  ],
  "mode": "",
  "http_framing": false
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### version

==Required==

The Snell protocol version, one of `5` `6`.

Version `5` supports HTTP obfuscation (`obfs_mode`); version `6` replaces it
with traffic shaping (`mode`) and requires a `psk` of 12 to 255 bytes.

!!! note

    Since we intentionally do not support the QUIC proxy mode of Snell v5, the v5 wire protocol
    is effectively identical to v4, so no separate v4 server or v5 client is provided.

#### psk

==Required==

The pre-shared key.

#### users

Snell users.

When set, the server runs in multi-user mode: each entry has a `name` (optional, used in
logs) and a `userkey` (the user's key).

#### obfs_mode

==Version 5 only==

HTTP obfuscation mode, one of `none` `http`.

`none` is used by default.

#### mode

==Version 6 only==

Traffic shaping mode, one of `default` `unshaped` `unsafe-raw`.

`default` is used by default.

#### http_framing

==Version 6 default mode only; fork extension==

Enable matched HTTP framing on the first client write to work around the reproduced TCP Fast Open persistent slowdown. Disabled by default. Both endpoints must support this extension: an outbound connects either to an inbound with the same setting or to `snell-http-relay` forwarding to the existing Snell server. It is incompatible with an unmodified Snell listener when enabled directly.

The receiver reconstructs deterministic profile padding and preserves the original Snell salt, ciphertext and authentication. The header is paid for by those recovered bytes; profiles with insufficient recoverable padding are rejected during configuration. The kernel chooses normal TCP segmentation without an MSS cache or a separate warmup connection. Decoding starts as soon as the header and salt-position bytes arrive, without waiting for the complete body. Subsequent writes and server replies retain the normal Snell format. This option does not itself enable TCP Fast Open; use the existing dial/listen setting as appropriate.

The fixed `.invalid` Host value is a framing literal and is not resolved. No HTTP server or TLS handshake is involved. This mechanism has been tested against a specific reproduced path defect; it is not a replacement for Snell encryption.
