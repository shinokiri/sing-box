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
	defaultNetwork NetworkTFOSelection
	byInterface    map[string]NetworkTFOSelection
	byAddress      map[netip.Addr]string
}

// The policy and binding identity must come from the same immutable snapshot.
type NetworkTFOSelection struct {
	NetworkHandle uint64
	Allowed       bool
}

func NewNetworkTFOState(defaultIndex int, interfaces []NetworkInterface) *NetworkTFOState {
	state := &NetworkTFOState{
		byInterface: make(map[string]NetworkTFOSelection, len(interfaces)),
		byAddress:   make(map[netip.Addr]string),
	}
	for _, iif := range interfaces {
		if iif.Name == "" {
			continue
		}
		allowed := iif.Type == C.InterfaceTypeWIFI || iif.Type == C.InterfaceTypeEthernet || iif.Type == C.InterfaceTypeOther
		selection := NetworkTFOSelection{NetworkHandle: iif.NetworkHandle, Allowed: allowed}
		state.byInterface[iif.Name] = selection
		if defaultIndex > 0 && iif.Index == defaultIndex {
			state.defaultNetwork = selection
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
	return s.Select(interfaceName, localIP).Allowed
}

func (s *NetworkTFOState) Select(interfaceName string, localIP netip.Addr) NetworkTFOSelection {
	if s == nil {
		return NetworkTFOSelection{}
	}
	if localIP.IsValid() {
		name := s.byAddress[localIP]
		if name == "" || interfaceName != "" && name != interfaceName {
			return NetworkTFOSelection{}
		}
		interfaceName = name
	}
	if interfaceName != "" {
		return s.byInterface[interfaceName]
	}
	return s.defaultNetwork
}
