Experimental Snell v6 hello carrier

This is a private ClientHello-shaped encoding, NOT a TLS connection. The
receiver restores original Snell ciphertext and deterministic padding; the
existing Snell service remains responsible for Snell authentication.

Topology:
  SFA with hello_framing -> relay in pass mode -> landing in decode mode
  -> existing native Snell listener

Pass mode forwards the validated first carrier unchanged and needs no PSK.
Decode mode restores that first frame using the native Snell PSK. Both modes
then forward the remaining stream unchanged. No extra application handshake
or stream multiplexing is introduced.

Build:
  go build -trimpath -o snell-hello ./cmd/snell-hello

Configuration:
Replace the documentation IP addresses in the examples with real endpoints.
The native Snell upstream must already exist. In decode mode, psk_file is
relative to the JSON file and contains the existing 12..255-byte Snell PSK,
optionally followed by one line ending. Keep it readable only by the service
user. Pass mode must not specify psk_file. Do not pass the key in arguments.

  ./snell-hello-linux-amd64 -config ./relay.json -check
  ./snell-hello-linux-amd64 -config ./relay.json

Use landing.json on the landing. -check validates without opening a socket.
SIGINT/SIGTERM release listeners and connections. TCP half-close is preserved.
The executable changes no firewall rule or global TCP setting.

Defaults when omitted:
  listen_tfo / upstream_tfo: false / false
  tfo_queue: 128
  setup_timeout: 5s (initial read, dial and initial write only)
  dial_timeout: 4s (also bounded by remaining setup time)
  max_connections: 256 active physical TCP connections
  TCP keepalive: enabled, idle 30s, interval 10s, 3 probes
  TCP_NODELAY: enabled on both legs
  connection lifetime limit: none
  mode, listen, upstream: required; mode is pass or decode

The examples explicitly enable per-socket TFO. The host must already permit
Linux client/server TFO where needed. Preserve the native Snell settings.
The service template requires an existing snell-hello account and grants only
the capability needed for a port below 1024. Firewall rules are separate.

Client configuration:
Preserve the existing Snell key, version 6, default mode, routing and reuse
choice. Point the candidate node at the NEW pass-mode listener and add:
  "hello_framing": true,
  "tcp_fast_open": true

hello_framing defaults false and supports only Snell v6 default mode. The
older experimental http_framing option is not used. A normal Snell or plain
forwarding port cannot accept hello_framing.

hello_initial_syn_data_limit defaults 0: initial estimates are 496 bytes for
IPv4 and 1180 for IPv6. A positive value is a previously measured path
assumption, including the carrier bytes, not a negotiated MSS. Current peer
and route observations take precedence. The tested IPv4 path used 1200; do
not copy that to a different path blindly. A network change clears learned
observations. No calibration connection is opened.

Backend timestamp workaround:
The optional nftables example removes only the timestamp offer from initial
relay -> candidate decoder SYNs. It does not strip timestamps from established
packets. Endpoints negotiate no timestamps for that connection; TFO, SACK and
window scaling remain. Timestamp RTT measurement and PAWS are lost. Ordinary
TCP RTT sampling remains. This is a path-specific tradeoff.

Edit both documentation IPs and the decoder port before checking with:
  nft -c -f backend-timestamps.example.nft
The table does not open the port through other firewall chains. Deliberate
installation and the applicable exact port allowance are separate steps.

Retirement:
First select the existing ordinary node, or remove hello_framing and
hello_initial_syn_data_limit and restore the original server/port. Preserve
that ordinary node's previously working tcp_fast_open choice. The candidate
APK can use ordinary nodes with all experimental fields absent.
Then stop both candidate services, remove their exact port allowances, and
delete only this named table if it was deliberately installed:
  nft delete table inet snell_hello_backend_candidate

No broad firewall flush, global setting change, native Snell restart or app
data clearing is part of retirement. A candidate may have a higher Android
versionCode; configuration rollback needs no APK downgrade or uninstall.

Evidence boundaries:
The standalone Android harness uses the actual SFA dialer and connection
manager. Tested 512-byte first batches fit in both native SYNs as a complete
711-byte carrier. Bigger first batches may need later segments. Missing TFO
cookies still require cookie acquisition. SYN acceptance, decoding, application
acceptance and response are different milestones; processing can finish after
the final handshake ACK. Not every response completes before that ACK.
Installed VPN startup, actual Android OS network notifications and sustained
daily use still need user-timed validation. This package installs nothing and
must not automatically restart the user's active VPN.
