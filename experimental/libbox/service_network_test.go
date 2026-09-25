package libbox

import (
	"errors"
	"testing"
)

type socketBinderTestPlatform struct {
	PlatformInterface
	interfaces []*NetworkInterface
}

func (p socketBinderTestPlatform) GetInterfaces() (NetworkInterfaceIterator, error) {
	return newIterator(p.interfaces), nil
}

type testNetworkSocketBinder struct {
	fd  int32
	err error
}

func (b *testNetworkSocketBinder) BindSocket(fd int32) error {
	b.fd = fd
	return b.err
}

func TestPlatformNetworkSocketBinder(t *testing.T) {
	failure := errors.New("network unavailable")
	wifi := &testNetworkSocketBinder{}
	cellular := &testNetworkSocketBinder{err: failure}
	wrapper := &platformInterfaceWrapper{iif: socketBinderTestPlatform{interfaces: []*NetworkInterface{
		{Name: "wifi", Type: InterfaceTypeWIFI, SocketBinder: wifi},
		{Name: "cellular", Type: InterfaceTypeCellular, SocketBinder: cellular},
		{Name: "unknown"},
	}}}
	interfaces, err := wrapper.NetworkInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 3 {
		t.Fatalf("interfaces: %d", len(interfaces))
	}
	if err := interfaces[0].BindSocket(17); err != nil {
		t.Fatal(err)
	}
	if err := interfaces[1].BindSocket(23); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if wifi.fd != 17 || cellular.fd != 23 {
		t.Fatal("binding callback used a different network")
	}
	if interfaces[2].BindSocket != nil {
		t.Fatal("missing binding was treated as an available network")
	}
}
