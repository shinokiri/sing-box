# Local sing-tun patches

Upstream source: v0.9.4-0.20260912075549-869f0a4d76af, as required by the
sing-box testing snapshot b84b42bc72dd7fad73ee1b3b65bfddf864eacf1b.

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
