# Local sing-tun patches

Upstream source: v0.9.4-0.20260916043548-e842d006fa65, as required by the
sing-box v1.15.0-alpha.5 (37611b410481dfca1265873284c9bfd3f04f8fd6).

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
