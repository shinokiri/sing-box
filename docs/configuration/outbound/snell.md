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
  "hello_framing": false,
  "cellular_tfo_compat": false,

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

#### hello_framing

Private Hello carrier for version 6 in `default` mode. Requires the paired
Hello decoder at the receiver. This is not TLS and is not supported by an
unmodified official Snell server.

#### cellular_tfo_compat

Enable the paired relay's SYN-ACK compatibility on Android cellular networks.
Requires version 6, `hello_framing`, `tcp_fast_open`, and a direct outbound
(no `detour`). Disabled by default. Install and verify the
[relay adapter](../../../contrib/snell-tfo-compat/README.md) before enabling it.

The first Hello marks the compatibility request only when the selected Android
NetworkHandle is cellular. Framing and socket binding use the same immutable
network selection. Wi-Fi retains native TFO; an unknown network keeps the
ordinary TCP fallback. Non-Android platforms retain their existing TFO policy.
The setting does not change established connections or Snell session reuse.

The relay changes only the marked connection's SYN-ACK acknowledgment. The
client resends the SYN prefix as ordinary data, which the receiver's TCP stack
deduplicates. This adds a small bandwidth cost and may affect congestion-window
use; it is not a promise of zero overhead or universal carrier compatibility.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
