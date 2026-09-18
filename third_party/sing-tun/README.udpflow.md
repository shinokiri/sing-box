# Local sing-tun patches

Upstream source: v0.9.4-0.20260917142847-fbc0c3dff312, as required by the
sing-box v1.15.0-alpha.6 (8330820fa62505f9574e4c35cd969d9af6eb7769).

The fork retains bounded asynchronous first-flow routing, fixed DNS failure
retry deadlines, writeback outside the flow-table lock, selector cancellation,
UDP association ownership and alias isolation, queued packet identity, and the
live-flow index. These behaviors are covered by the existing regressions.

The new Go stack uses independent dispatcher stages for each worker. Stages
share port registration, selector allocation, and the return lifetime. Socket
allocation and insertion are serialized across stages; packet batches stay
with their original stage and copy borrowed Go frame storage. Return packets
use the owning stage's writeback. Asynchronous ordinary-stack verdicts return
through the Go engine injection queue, which is fenced before engine shutdown.
The system, mixed and gVisor stacks retain their asynchronous receive paths.

The fork exposes ForwardDispatcher's existing API for the protocol integration
tests and callers, and adapts the upstream ForwardStage API around per-worker
dispatchers. Kernel integration tests run with privileges in Android CI; memory
and race tests cover stage isolation and asynchronous Go-engine handoff locally.

The Go TCP stack also keeps pure ACK sequence numbers within a shrunken peer
window. Using SND.NXT beyond that window can stall both directions when the
receiver rejects the ACK. The Linux zero-window regression verifies that
uploaded data is acknowledged while the download remains blocked. The
half-close fixture fills the receive window one frame at a time to account
for Linux IPv6 packet memory limits while retaining the FIN-loss checks.

The alpha.5 update retains the window-edge ACK and incremental half-close
regressions while masking the new goPermitWindowBit in window comparisons.

The alpha.6 update includes upstream's Go memory arenas, read-slot parking,
event-driven connection timers, and iptables DNS-hijack fix. The new idle
sweep query reads each worker's dispatcher table and last-sweep time under
its existing lock. Empty workers do not schedule sweeps; active workers still
retire expired flows. The regression covers worker isolation and idle cleanup.
