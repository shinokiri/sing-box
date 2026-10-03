# Local sing-tun patches

Upstream source: v0.9.7-0.20261002083955-3f8acd9da65b, as required by
sing-box v1.15.0-alpha.10 (c992297988288565a24a6d36e2cf4d77cb835fcd).

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
its existing lock. Workers with neither entries nor pending route decisions do
not schedule sweeps. A pending asynchronous verdict keeps the existing sweep
armed so a later drop/flow entry expires even without another received packet.
Regressions cover worker isolation, idle cleanup, and delayed route completion.

Linux kernel fixtures use keepalive probe intervals above the default 500 ms
invalid-ACK rate limit. The netlink overrun fixture fills its socket before
starting the reader so it deterministically exercises overflow recovery;
production keepalive and network-monitor behavior are unchanged by these tests.

The Linux SACK-reneging fixture uses an observed kernel SACK interval with at
least two queued MSS. Requiring the whole initial burst could deadlock its
setup when early SACKs started loss recovery while the fixture kept dropping
the first segment. A controlled fourth-segment pause covers that ordering in
IPv4 and IPv6. The test still requires actual kernel reneging, complete payload
recovery, and EOF, with the existing deadlines. This changes only test setup.

The alpha.10 update retains upstream's allocation-free address checksum paths,
combined NAT checksum updates, UDP zero-checksum correction, transport input
validation, MSS bounds, and handling of data received after FIN. These changes
also apply to the fork's asynchronous dispatcher; the new address-family guard
remains ahead of flow creation. The SACK fixture and window-edge ACK regression
remain unchanged by this update.
