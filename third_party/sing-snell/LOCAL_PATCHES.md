# Local URLTest session handoff

Upstream: v0.0.0-20260904135315-bc5a12ac736f. Files are copied from the upstream Go module archive. Local changes cover the exclusive URLTest session handoff and shared idle-pool retention policy described below.

URLTestDialer owns one physical Snell v6 session for exactly two logical requests. The first is the existing HTTP warmup; the second waits for its server EOF before reusing the same transport. The reserved session is never inserted into the shared pool, so background traffic cannot consume it between requests. It is closed when the probe finishes or fails.

Reserved URLTest sessions are isolated from the shared idle pool. TCP Fast Open and the configured underlying dialer remain active for the warmup. The measured request still establishes its own destination TCP/TLS connection and performs the original HEAD request; only the proxy-session handoff is made deterministic.

Tests in the parent repository's protocol/snell package exercise the complete URLTest entry point with a Snell server and controlled EOF/connect delays. The existing common/dialer tests verify real Android-path TFO socket controls.

HTTPS close also needs a separate bounded deadline for the Snell EOF: Go 1.26.8 crypto/tls.closeNotify expires the underlying write deadline before calling the logical connection's Close. Reserved probe sessions replace that deadline before sending their EOF; they still honor cancellation and the earlier of the test deadline or a five-second close limit. Ordinary business-session close behavior is unchanged.

# Receive-window-informed idle session retention

On Linux and Android, established TCP sockets expose `TCP_INFO.rcv_ssthresh`.
The shared v4/v5/v6 idle pool uses this receive-window growth clamp as a hint:
among comparable ready sessions it prefers the larger value, with recency as
the tie-breaker. Waiting sessions remain ineligible. When all ten slots are
occupied and all relevant hints are available, an incoming return replaces
the smallest hint only if its own is at least as large; equal victims are
evicted oldest first. Closed returns cannot displace an existing entry.

Unsupported platforms/transports and failed queries preserve recency for
unavailable comparisons, and preserve the old full-pool rejection policy if
admission cannot be compared. Removed sessions are closed outside the pool
mutex; evicted waiting sessions retain their drain-completion accounting.

This is a hint, not a measurement of the currently advertised window or a
throughput guarantee. Queued data and other kernel clamps can reduce that
window. Queries happen at pool transitions only. Capacity, idle expiration,
active-session ownership and automatic TCP receive tuning are unchanged;
no prewarming traffic, keepalives, periodic queries or buffer locks are added.

# Reject closed Snell v6 transports before reuse

The client response decoder keeps a physical EOF distinct from Snell's logical
zero-length EOF record. A closed or truncated TCP stream therefore cannot mark
an active/draining session ready for a later request. On Linux and Android,
shared-pool checkout also rejects sockets whose TCP_INFO state is no longer
ESTABLISHED. State and receive-window hint share one TCP_INFO query. Existing
queries are reused where the socket was already accessible. The metadata
lookup also follows replaceable tracked/deferred-TFO wrappers when an outer
SyscallConn method cannot reach their socket; those paths previously skipped
the receive-window query entirely. Non-replaceable and unopened transports
retain their fallback behavior. No network probe is added, and application
bytes and deadlines are preserved. Normal logical EOF still permits reuse;
other platforms retain their existing idle
transport selection. No application request is replayed after a failed write.

Regression tests exercise scalar, buffer, read-waiter and drain paths after a
physical EOF, plus a real loopback TCP peer that sends FIN after a valid logical
EOF. Existing hello-framing and sequential-reuse tests remain the controls.
Wrapped-socket regressions cover the trackedConn/slowOpenConn syscall behavior,
and benchmarks separately measure ordinary and wrapped pool checkout.
A close racing after checkout can still fail the current request; the change
prevents reuse of a transport already known to be closed.
