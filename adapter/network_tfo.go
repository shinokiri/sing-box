package adapter

import (
	"net/netip"

	C "github.com/sagernet/sing-box/constant"
)

// NetworkTFOProvider publishes immutable policy snapshots on network events.
// A missing snapshot means the physical network has not been classified yet.
type NetworkTFOProvider interface {
	NetworkTFOState() *NetworkTFOState
}

type NetworkTFOState struct {
	defaultAllowed bool
	byInterface    map[string]bool
	byAddress      map[netip.Addr]string
}

func NewNetworkTFOState(defaultIndex int, interfaces []NetworkInterface) *NetworkTFOState {
	state := &NetworkTFOState{
		byInterface: make(map[string]bool, len(interfaces)),
		byAddress:   make(map[netip.Addr]string),
	}
	for _, iif := range interfaces {
		if iif.Name == "" {
			continue
		}
		allowed := iif.Type == C.InterfaceTypeWIFI || iif.Type == C.InterfaceTypeEthernet || iif.Type == C.InterfaceTypeOther
		state.byInterface[iif.Name] = allowed
		if defaultIndex > 0 && iif.Index == defaultIndex {
			state.defaultAllowed = allowed
		}
		for _, prefix := range iif.Addresses {
			address := prefix.Addr().Unmap()
			if previous, exists := state.byAddress[address]; exists && previous != iif.Name {
				state.byAddress[address] = ""
			} else {
				state.byAddress[address] = iif.Name
			}
		}
	}
	return state
}

func (s *NetworkTFOState) Allowed(interfaceName string, localIP netip.Addr) bool {
	if s == nil {
		return false
	}
	if localIP.IsValid() {
		name := s.byAddress[localIP]
		if name == "" || interfaceName != "" && name != interfaceName {
			return false
		}
		interfaceName = name
	}
	if interfaceName != "" {
		return s.byInterface[interfaceName]
	}
	return s.defaultAllowed
}
