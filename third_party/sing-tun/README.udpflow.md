# Local first-flow routing patch

This directory is `github.com/sagernet/sing-tun v0.9.0-beta.4`, copied from
the Go module archive with checksum
`h1:gIIZU4HevhtTQubZiOdMD0/RnECD6csl2kG6666KYmQ=`. Its license and platform
sources, including the upstream Windows DLLs, are retained unchanged.

The patch adds an optional `ContextFlowHandler` and `EnableAsyncFlow` to the
forward dispatcher. The TUN inbound implements the context-aware handler.
System, mixed and gVisor stacks enable it before receiving packets. Other
handlers retain the existing synchronous API.

Only a missing tuple starts a routing worker. The complete original pre-match
operation runs there, including Fake-IP lookup, sniffing, DNS resolve actions
and subsequent IP rules. Established tuples still dispatch inline. Each
dispatcher limits pending work to 64 workers, 64 owned packets per tuple and
4 MiB of packet data, including batches being handed to the ordinary stack.
Overflow drops the new packet without blocking the reader. These limits are
separate from the outbound association/packet queues.

Pending packets are copied before the caller reuses its storage. One pending
entry keeps packets ordered through resolution and ordinary-stack fallback.
Verdicts use the existing NAT, reject and DNS-hijack implementation. Fallback,
DNS hijacking (including synchronous cache hits), and owned reject/MTU replies
run outside the dispatcher mutex. Port batches finish copying borrowed TUN
buffers under the lock. gVisor's ordinary forwarders reuse an
installed verdict instead of repeating DNS under the UDP NAT creation lock.
Reset/close cancel pending work, discard staged packets and prevent late
verdicts from installing a new flow. Canceled workers remain charged until
they exit. Dispatcher state uses an exclusive mutex because routing completion
and the packet reader now both update it.

A transient routing failure may set `RejectTimeout` to a fixed lifetime, which
incoming traffic cannot extend. The core router uses one second for failed DNS
resolve actions. A pending batch that outlives this deadline obtains a fresh
verdict. Policy rejections still use the original idle timeout.

Changes are confined to `flow.go`, `flow_dispatch.go`, `flow_pending.go`,
`stack_system.go`, `stack_mixed.go`, and the gVisor stack/filter/forwarders.
`flow_pending_test.go` covers bounded queues, ordinary fallback ordering,
verdict handling, cancellation and late results after reset. The three real
stack implementations are exercised with an in-memory TUN in
`stack_pending_test.go`, including ordinary UDP, TCP and ICMP delivery.
The core repository also tests a deliberately stalled DNS lookup with its real
router, Fake-IP metadata and IP-CIDR route rules for IPv4 and IPv6.
`flow_writeback_test.go` additionally covers blocked writeback during forwarding,
reset/close, and fixed failure deadlines, including packets queued during I/O.

The root and integration modules both replace sing-tun with this directory.
CI checks `UPSTREAM_VERSION` against both modules' required versions after preparing
an upstream release. If upstream changes this dependency, rebase this patch
onto that version and update the recorded version before publishing; do not
silently keep the old implementation under a newer requirement. Remove the
replacement once a tested upstream release supplies this functionality.
