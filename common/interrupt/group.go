package interrupt

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common/x/list"
)

type Group struct {
	access      sync.Mutex
	connections list.List[*groupConnItem]
	flowContext context.Context
	cancelFlows context.CancelFunc
}

type groupConnItem struct {
	conn       io.Closer
	isExternal bool
}

func NewGroup() *Group {
	return &Group{}
}

// FlowContext snapshots the current external-flow generation. Call it before
// reading the selected outbound so a concurrent switch cannot be missed.
// One context is shared by all flows; there are no per-flow callbacks or timers.
func (g *Group) FlowContext() context.Context {
	g.access.Lock()
	defer g.access.Unlock()
	if g.flowContext == nil {
		g.flowContext, g.cancelFlows = context.WithCancel(context.Background())
	}
	return g.flowContext
}

func (g *Group) NewConn(conn net.Conn, isExternal bool) net.Conn {
	g.access.Lock()
	defer g.access.Unlock()
	item := g.connections.PushBack(&groupConnItem{conn, isExternal})
	return &Conn{Conn: conn, group: g, element: item}
}

func (g *Group) NewPacketConn(conn net.PacketConn, isExternal bool) net.PacketConn {
	g.access.Lock()
	defer g.access.Unlock()
	item := g.connections.PushBack(&groupConnItem{conn, isExternal})
	return newPacketConn(g, conn, item)
}

func (g *Group) Interrupt(interruptExternalConnections bool) {
	g.access.Lock()
	defer g.access.Unlock()
	if interruptExternalConnections && g.cancelFlows != nil {
		g.cancelFlows()
		g.flowContext, g.cancelFlows = nil, nil
	}
	var toDelete []*list.Element[*groupConnItem]
	for element := g.connections.Front(); element != nil; element = element.Next() {
		if !element.Value.isExternal || interruptExternalConnections {
			element.Value.conn.Close()
			toDelete = append(toDelete, element)
		}
	}
	for _, element := range toDelete {
		g.connections.Remove(element)
	}
}
