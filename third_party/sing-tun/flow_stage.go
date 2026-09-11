package tun

// ForwardStage keeps each TUN worker's flow table and borrowed packet batches
// independent. The first stage uses the dispatcher directly for compatibility
// with the system/gVisor asynchronous receive paths; later stages share only
// the port registry and return lifetime.
type ForwardStage struct {
	dispatcher *ForwardDispatcher
}

func (d *ForwardDispatcher) NewStage(writeback ForwardWriteback) *ForwardStage {
	if d == nil {
		return nil
	}
	root := d.root
	root.stagesAccess.Lock()
	defer root.stagesAccess.Unlock()
	if writeback == nil {
		writeback = root.writeback
	}
	worker := root
	if len(root.stages) > 0 {
		worker = NewForwardDispatcher(root.handler, writeback, root.logger, root.udpTimeout, root.icmpTimeout)
		worker.root = root
		worker.epoch = root.epoch
		worker.returnPath = root.returnPath
	}
	worker.writeback = writeback
	stage := &ForwardStage{dispatcher: worker}
	root.stages = append(root.stages, stage)
	return stage
}

func (s *ForwardStage) Dispatch(packet []byte) bool {
	return s != nil && s.dispatcher.Dispatch(packet)
}

func (s *ForwardStage) DispatchParsed(packet []byte, meta ForwardFrameMeta, parsed *forwardPacket) bool {
	if s == nil || s.dispatcher.returnPath.closed.Load() {
		return false
	}
	meta.completeChecksum(packet)
	parsed.frameMeta = &meta
	return s.dispatcher.dispatch(packet, parsed)
}

func (s *ForwardStage) Flush() {
	if s != nil {
		s.dispatcher.Flush()
	}
}

func (s *ForwardStage) teardownFlow(key flowKey, reason FlowCloseReason) {
	if s == nil {
		return
	}
	d := s.dispatcher
	d.access.Lock()
	defer d.access.Unlock()
	if entry := d.table[key]; entry != nil {
		d.removeEntry(key, entry, reason)
	}
}

func (d *ForwardDispatcher) tableCapacity() int {
	d.root.stagesAccess.Lock()
	count := len(d.root.stages)
	d.root.stagesAccess.Unlock()
	return max(flowTableCapacity/max(count, 1), 1024)
}
