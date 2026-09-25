package route

import "github.com/sagernet/sing-box/adapter"

var _ adapter.NetworkTFOProvider = (*NetworkManager)(nil)

func (r *NetworkManager) NetworkTFOState() *adapter.NetworkTFOState {
	return r.networkTFOState.Load()
}

func (r *NetworkManager) updateNetworkTFOState() {
	if !r.networkTFOPolicy {
		return
	}
	// Serialize publishers, not connections. Read current records inside the
	// lock so an older event cannot overwrite a newer event's snapshot.
	r.networkTFOAccess.Lock()
	defer r.networkTFOAccess.Unlock()
	defaultIndex := 0
	if r.interfaceMonitor != nil {
		if iif := r.interfaceMonitor.DefaultInterface(); iif != nil {
			defaultIndex = iif.Index
		}
	}
	r.networkTFOState.Store(adapter.NewNetworkTFOState(defaultIndex, r.networkInterfaces.Load()))
}
