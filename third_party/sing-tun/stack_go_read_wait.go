package tun

import (
	"context"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// Bound both the work before a write and the buffers owned by one copy loop.
// The public copy path normally requests eight buffers after its bulk threshold.
const goMaxReadBatch = 8

var _ N.VectorisedReadWaitCreator = (*GoConn)(nil)

func (c *GoConn) CreateVectorisedReadWaiter() (N.VectorisedReadWaiter, bool) {
	return &goVectorisedReadWaiter{conn: c, batchSize: 1}, true
}

type goVectorisedReadWaiter struct {
	conn      *GoConn
	batchSize int
	buffers   [goMaxReadBatch]*buf.Buffer
}

func (w *goVectorisedReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	w.batchSize = max(1, min(options.BatchSize, len(w.buffers)))
	return w.conn.InitializeReadWaiter(options)
}

// WaitReadBuffers waits only for the first buffer. The returned slice is reused
// by the next call, as with the syscall vectorised reader; buffer ownership is
// transferred to the caller.
func (w *goVectorisedReadWaiter) WaitReadBuffers() ([]*buf.Buffer, error) {
	c := w.conn
	err := c.awaitHandshake(context.Background(), c.readDeadline.Wait())
	if err != nil {
		return nil, err
	}
	c.readAccess.Lock()
	buffers, err := w.waitReadBuffersLocked()
	c.readAccess.Unlock()
	c.engine.reapAfterExit()
	return buffers, err
}

func (w *goVectorisedReadWaiter) waitReadBuffersLocked() ([]*buf.Buffer, error) {
	clear(w.buffers[:])
	c := w.conn
	buffer, err := c.waitReadBufferLocked()
	if err != nil {
		return nil, err
	}
	w.buffers[0] = buffer
	count := 1
	// Snapshot readiness once. Do not follow a continuously arriving stream or
	// park for another buffer. readAccess prevents another reader or CloseRead
	// from advancing consumedTail while we drain the already available bytes.
	available := c.receiveAvailable.Load()
	for count < w.batchSize && c.consumedTail.Load() < available {
		buffer, err = c.waitReadBufferLocked()
		if err != nil {
			// Return the data already consumed. The next call observes the error;
			// the public vector copy loop does not accept data together with err.
			break
		}
		w.buffers[count] = buffer
		count++
	}
	return w.buffers[:count], nil
}
