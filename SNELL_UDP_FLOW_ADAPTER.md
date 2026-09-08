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
The worker publishes protocol headroom requirements so subsequent packets can
reserve their framing space during that ownership copy. It rechecks the actual
requirements before writing and only reallocates when a queued buffer is too
small, such as during setup or a framing change. Each association reuses one
write timer, stopped between writes, and one receive buffer. There is no worker
or periodic wakeup per packet; these changes reduce allocation and copying
without making the TUN reader wait for network I/O.

Each outbound/inbound binding has distinct internal IPv4/IPv6 addresses so
that independently allocated selectors cannot match each other's replies.
These addresses only identify dispatcher mappings; they are not sent to the
proxy server or returned to applications.
The router requests a stable port for each inbound through an optional outbound
interface. Each binding owns its selector map and return path. Bindings share
the outbound's connection/byte budgets, cleanup loop and network-reset handling;
creating a binding starts no goroutines. Detaching an inbound closes only its
associations, while resetting or closing the outbound closes all of them.

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

VLESS `udp_flow` requires XUDP. Outbound `multiplex` can remain enabled for TCP
and the ordinary packet path. UDP flows open independent XUDP associations on
the configured transport; they do not enter the separate multiplex layer.
Resetting a UDP flow therefore does not close a TCP multiplex session.

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

- Multiple TUN inbounds may use the same flow-enabled outbound. Each inbound
  gets a separate binding; a binding still accepts only one dispatcher because
  selectors are local to that dispatcher. Direct users of `udpflow.Port` must
  call `ForInbound` when sharing it across inbounds, as the router does.
- Each selector has a queue of up to 64 pending packets. Each adapter allows up
  to 1,024 associations and 4 MiB of queued/in-flight payload data, excluding
  protocol framing and read buffers. Packets exceeding these limits are
  dropped with a trace-level forwarding error rather than blocking the TUN.
- Flow setup uses the outbound's explicit `connect_timeout`, or 15 seconds
  when unset. Each protocol write has a 15-second timeout. A stalled write
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
outbound isolation, identical five-tuples across inbounds, independent detach,
and a silent Snell v6 server. Resource-limit tests ensure inbound bindings
cannot multiply an outbound's connection or queued-byte budget.
In-process Snell v4/v5 (plain and HTTP-obfuscated), Snell v6 (default,
unshaped, and unsafe-raw), and VLESS/XUDP servers exercise multi-destination
IPv4/IPv6 exchanges over one association. Other tests cover buffer ownership,
queue limits, cancel/timeout cleanup, failed-association replacement, late
replies after detach, and cancellation of the VLESS initial request.
Changing headroom, varying response sizes, and timer reuse across successful,
idle, slow and stalled writes are covered, including virtual-clock tests.
VLESS/gRPC is also tested through the real outbound factory and transport.
VLESS TCP multiplex and UDP flow coexistence is tested with smux, yamux, and
h2mux, including keeping TCP streams alive after UDP flow reset. Constructor
tests check both shorter and longer custom connection timeouts; virtual-clock
tests exercise idle sweeping and receive-only activity without wall-clock waits.
The root integration test decodes a complete configuration and exercises the
real Fake-IP store, hosts resolver, route rules, and TUN routing entry point for
IPv4/IPv6 Snell and VLESS destinations. It also checks rejection without a
resolve rule. This needs the host's network-monitor permissions.
Transport regressions cover concurrent response initialization and reads, and
closing before a response arrives without leaking its late response body.
QUIC dial and handshake cancellation, waiting for a shared connection, and
reuse after canceling a completed dial (including a context-bound streaming
UDP detour) are covered. WebSocket and HTTP Upgrade
handshakes are tested against a silent peer, including preservation of the
configured WebSocket subprotocol across attempts. Closing an established
WebSocket must interrupt blocked reads/writes immediately.

The multiplex coexistence tests also exposed a response publication/close race
in sing-mux v0.3.5. `third_party/sing-mux` contains that version with a local
`h2mux_conn.go` fix and a late-response regression. The root module replacement
applies it consistently to tests and Android builds. See its `README.udpflow.md`
for provenance and the condition for removing the local copy.

```sh
go test -race -tags with_gvisor,with_quic -count=1 ./common/udpflow ./protocol/snell ./protocol/vless ./transport/v2ray ./transport/v2raywebsocket ./transport/v2raygrpclite ./transport/v2rayhttp ./transport/v2rayquic github.com/sagernet/sing-mux
go test -race -tags with_gvisor,with_grpc,with_quic -count=1 ./common/udpflow ./protocol/vless ./transport/v2ray ./transport/v2raywebsocket ./transport/v2raygrpclite ./transport/v2rayhttp ./transport/v2rayquic
go test -exec sudo -tags "$(cat release/DEFAULT_BUILD_TAGS_OTHERS)" -ldflags "$(cat release/LDFLAGS)" ./...
go test -tags with_gvisor -run '^$' -bench '^BenchmarkPortForward$' -benchmem ./common/udpflow
CGO_ENABLED=0 go build -trimpath -tags "$(cat release/DEFAULT_BUILD_TAGS_OTHERS)" -ldflags "$(cat release/LDFLAGS) -s -w -buildid=" ./cmd/sing-box
```

These checks do not replace tests using a real TUN device and the deployed
proxy server, particularly when assessing public UDP mapping/filtering.

## GitHub Actions

The dedicated `.github/workflows/build.yml` runs on `udpflow` pushes, pull
requests, and manual dispatch. Its planning job tests the release scripts,
including actual Git merges in temporary repositories. The build job runs all core-module tests and
`go vet` with release feature tags (excluding the unsafe-pointer diagnostic for
the upstream daemon/libbox deliberate crash hooks), then targeted race tests with both grpclite
(the Android implementation) and full gRPC. Forwarding benchmarks record
allocation counts and throughput in the run summary; each iteration forwards
32 packets, including queueing and buffer copies but excluding encryption and
network latency. Both unframed buffers and buffers requiring 128 bytes of front
headroom and 16 bytes of rear headroom are measured, with IPv4/IPv6 and 64/1200-byte
payloads. Allocation counts and mock-transport throughput are not device power
measurements or network RTT. The separate `test/` module's external-server/Docker suite is
not part of this core-module gate.

After the checks pass, branch push/manual builds compile a signed ARM64 APK
with the pinned client's Go version (currently 1.26.7), NDK r28, and JDK 17.
Pull requests run core checks only. The native
library and APK are built on one runner, with one toolchain setup and cached
Go native compilation. They use `build_libbox -target android -platform android/arm64
-android-legacy=false` and package one signed `other` APK. The Gradle init script
disables ABI splits and filters all native dependencies to `arm64-v8a`; CI
checks that exactly one APK contains only that ABI and includes libbox.
It also verifies the built APK's signature with `apksigner` before uploading.

Formal releases use exactly `<official version>-udpflow`, with one leading `v`
in the Git tag. `release/udpflow.json` records the upstream stable tag and commit;
CI verifies that this commit is an ancestor of the built core and that the
pinned Android client's version matches. Release APKs are named
`SFA-<official version>-udpflow-arm64-v8a.apk`. Once that release is public,
subsequent branch builds use `<official version>-udpflow.g<commit>` and remain
Actions artifacts; published releases and tags are never overwritten.
Both types upload the `binary-android-arm64` Actions artifact. `versionCode` is
`1000000 + GITHUB_RUN_NUMBER`: later runs increase it even though the client
commit is pinned; rerunning a job preserves it. CI reads the actual APK manifest
to check the version and API 24 minimum against the recorded metadata.
No legacy API 21 library, legacy APK, other Android architecture, or universal
APK is built. The same tested artifact is published with `SFA-version-metadata.json`
and `SHA256SUMS`. Assets are uploaded to a draft before publication; the final
release is explicitly stable and Latest, despite the `-udpflow` suffix.
CI checks the branch again before publishing and uses an atomic, non-forced
push for the tested commit and release tag. There is no repository-wide cache cleanup.

Android builds on `udpflow` use the recorded `clients/android` submodule commit
(`b7bf31b6e553b30ab69a90a1769f9273cb25f089`, the 1.14.0 client with its default
interface notification fix). Do not replace it with a moving `dev` checkout:
the 1.15 development client requires libbox APIs absent from this branch.
APK metadata records both the core and Android client commits so each artifact
can be traced to its sources. The upstream Android repository is not modified:
`.github/android-udpflow.patch` is applied to the recorded gitlink at build time,
and metadata also records its SHA-256. Client unit tests in `.github/android-tests`
exercise update selection without loading the native library or making network requests.

### Client updates

The patched `other` client checks this fork's GitHub releases, selects its ARM64
APK and compares monotonic `versionCode` values. Drafts, excluded prereleases,
missing metadata/APKs, wrong architectures and mismatched release metadata are
ignored. F-Droid is not an update source for this fork's signing key.
An already downloaded APK is reused only when its recorded URL matches the
requested release, so a cached older APK cannot stand in for a newer update.
Launch-time update checks default to enabled; an explicitly disabled setting
is preserved. The app shows its existing update prompt when a newer build is
available. The existing optional background/silent-install settings remain
under user control. An old APK whose updater still points to SagerNet requires
one manual installation of the new fork client before this update path works.

### Following official stable releases

The workflow can check upstream every six hours, or immediately through
`workflow_dispatch` with `sync_upstream=true`. It fetches official published stable
tags directly; it does not sync or depend on the fork's `testing` branch.
The recorded upstream commit, current `udpflow` tree and new stable tree form
an explicit three-way merge, including rename detection and upstream deletions.
The new release need not descend from the previous release: resetting or rebasing
upstream development history does not require rewriting this fork's history.
The resulting commit retains both the previous `udpflow` head and the new official
commit as parents. An existing recorded tag changing its target stops the run
for review, rather than replacing an already published version.
The Android `main` commit is pinned only if its version matches, and the Go
version is read from that client. This fork's workflows are retained during
the merge. Other conflicts stop the run before changing the core working tree.
The client patch must apply
cleanly and the resulting source must pass all checks, client tests and the
signed ARM64 build before it is pushed and released. Unchanged scheduled runs
skip the build. No external access token is required; the same workflow publishes
with `GITHUB_TOKEN` rather than relying on another workflow being triggered by its push.

**Keep `udpflow` as the repository's default branch for scheduled updates.**
GitHub loads schedules only from the default branch. Manual dispatch with
`--ref udpflow` and ordinary `udpflow` pushes also run the workflow.

## Target base

Prepared from the uploaded `sing-box-snell-udp-flow` snapshot whose archive
comment identifies commit `a5defef983dd0e0584e6bc1e0173c055f76a3bd9`.
