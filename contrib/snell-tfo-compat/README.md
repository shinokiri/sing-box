# Paired cellular TFO compatibility

This adapter is for the measured Android cellular path that accepts SYN data
at the receiver but drops later client data after a SYN-ACK acknowledging that
data. It is an explicit, experimental capability of a paired Snell Hello
client and relay, not a universal carrier workaround.

The client sets `cellular_tfo_compat: true` alongside `hello_framing: true`,
`tcp_fast_open: true`, and Snell version 6 in default mode. On Android it marks
the first Hello only for a known cellular NetworkHandle. The same immutable
selection supplies the socket binding, TFO policy and network-scoped Hello
size cache. Wi-Fi retains native TFO. The option defaults to false.

On the relay, TCX ingress remembers only marked SYNs for the configured port.
Egress changes only the corresponding SYN-ACK acknowledgment from
`client_isn + 1 + prefix_length` to `client_isn + 1`, fixing the TCP checksum.
The server's TCP state and accepted bytes stay intact. The client retransmits
the prefix as ordinary data; server TCP deduplicates it. This can avoid a
timeout on the measured path, but adds a prefix retransmission and can affect
bandwidth/congestion-window use. Early application responses are not changed.

The marker occupies eight bytes of the existing ignored Hello random field
(`CTFO`, version 1, three zero bytes). It adds no wire bytes or PSK copies and
is a capability request, not authentication. Snell authenticates normally.
The existing Hello receiver needs no update. Keep Hello framing: ACK repair
alone did not fix the separately measured content-dependent throughput loss.

## Build and verify

Requires Linux 6.6+ with TCX, mounted bpffs, libbpf with TCX support (1.3+),
Clang with the BPF target, Linux headers, a C compiler, and Python 3 at build
time. The deployed executable needs only the existing libbpf runtime and its
system dependencies. Compile for the relay's architecture and libc.

```sh
make
sudo python3 lifecycle-test.py "$PWD/snell-tfo-compat"
```

The tests use temporary dummy devices and owned bpffs directories, execute
generated IPv4/IPv6 packets in the actual kernel, verify checksums and byte
preservation, and inject file-descriptor exhaustion during load/attachment.
They also test idempotence, incomplete-instance recovery, unrelated TCX
coexistence, frozen configuration, and device removal/recreation. They do not
attach to a live interface or transmit the generated packets. Real carrier
acceptance must still be performed on the intended phone/network.

## Install and lifecycle

Install the single `snell-tfo-compat` executable as root at
`/usr/local/libexec/snell-tfo-compat`, mode 0755. The BPF object is embedded;
there is no separate runtime object, Python helper, daemon, configuration file
or shared secret. Add these directives to the existing relay **socket** unit,
substituting its actual interface and port:

```ini
[Unit]
BindsTo=sys-subsystem-net-devices-eth0.device
After=sys-subsystem-net-devices-eth0.device
RequiresMountsFor=/sys/fs/bpf

[Socket]
ExecStartPre=/usr/local/libexec/snell-tfo-compat attach --interface=eth0 --port=23781
ExecStopPost=/usr/local/libexec/snell-tfo-compat detach --interface=eth0 --port=23781
TimeoutSec=15s
```

Preserve the existing listener, service dependency and forwarding settings.
The service must have `Requires=` and `After=` on its socket. Its existing
unprivileged proxy and sandbox stay in place. Attach runs before the listener
opens; failure prevents listening. Socket shutdown closes the listener before
detachment. Restarting only the proxy service keeps the pinned kernel hooks.

Stop the socket and its proxy before replacing an active adapter build. Detach
the old instance, install the new executable/socket unit, reload systemd and
start the socket. Verify the relay before enabling the client option. This
explicit cutover interrupts existing connections through that proxy.

```sh
/usr/local/libexec/snell-tfo-compat status --interface=eth0 --port=23781
```

Status is JSON with `active`, immutable configuration/build identity, map and
program IDs, and cumulative per-CPU handshake counters. It logs no addresses,
payloads or keys. An inactive instance is represented by `active: false`;
check that field, not just exit status. Repeating attach is idempotent for the
same build. Different live builds are rejected until explicitly detached.
Repeating detach is safe and works after the network device disappears.

Pins live under `/sys/fs/bpf/snell-tfo-compat/<interface>-<port>/`. An immutable
ownership map lets the loader identify incomplete instances after interruption
and repair them on the next startup. Unknown state is refused. Per-instance
locks in `/run/snell-tfo-compat/` serialize lifecycle operations. Only owned
TCX links/maps are removed; qdiscs and unrelated TC/TCX programs are preserved.

## Scope and resource limits

The 16,384-entry LRU map bounds handshake state; entries expire logically after
120 seconds and are replaced on tuple/initial-sequence changes. Under extreme
churn, eviction before SYN-ACK may prevent adaptation. Failed state insertion
or checksum/write operations drop the affected handshake packet rather than
forwarding a partially repaired packet. Counters expose those failures.

Only ordinary, unfragmented IPv4/IPv6 TCP headers are supported. Other protocols,
ports, unmarked connections and unsupported extension/fragment layouts pass
through. Ordinary established data exits before map helpers or writes, but the
TCX program still runs per packet; kernel test-run timings are not end-to-end
latency or whole-system performance guarantees. Reusing established Snell
connections avoids repeating this handshake work.

The source and tests are intentionally small enough to review. Building and
running isolated tests does not activate this adapter on a production path.
