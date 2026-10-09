package reuse

import (
	"context"
	"net"
)

// Acquire races a real-demand dial against a pooled session becoming usable.
// It sends no application data and does not open connections before demand.
// The dial callback must return an exclusively owned, active session, and must
// respect cancellation. If it succeeds after another session won, it is closed.
func (p *Pool[S]) Acquire(ctx context.Context, dial func(context.Context) (S, error)) (session S, reused bool, err error) {
	if err = ctx.Err(); err != nil {
		return
	}
	var closed bool
	var changed <-chan struct{}
	session, reused, closed, changed = p.take(true)
	if closed {
		return session, false, net.ErrClosed
	}
	if reused {
		return
	}
	dialContext, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		session S
		err     error
	}
	// An unbuffered handoff makes ownership explicit: once the caller chooses
	// a pooled session or cancels, a late successful dial must close itself.
	completed := make(chan result)
	go func() {
		fresh, dialErr := dial(dialContext)
		select {
		case completed <- result{fresh, dialErr}:
		case <-dialContext.Done():
			if dialErr == nil {
				fresh.Close()
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return session, false, ctx.Err()
		case <-changed:
			session, reused, closed, changed = p.take(true)
			if closed {
				return session, false, net.ErrClosed
			}
			if reused {
				return session, true, nil
			}
		case fresh := <-completed:
			if err := ctx.Err(); err != nil {
				if fresh.err == nil {
					fresh.session.Close()
				}
				return session, false, err
			}
			// A ready, already-used connection remains preferable when both
			// events finish together, including when the fresh dial failed.
			session, reused, closed = p.Take()
			if closed || reused {
				if fresh.err == nil {
					fresh.session.Close()
				}
				if closed {
					return session, false, net.ErrClosed
				}
				return session, true, nil
			}
			return fresh.session, false, fresh.err
		}
	}
}
