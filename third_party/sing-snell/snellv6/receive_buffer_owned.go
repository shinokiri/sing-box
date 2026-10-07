//go:build owned_receive

package snellv6

import "github.com/sagernet/sing/common/buf"

// Build-only control for comparing shared storage with whole-buffer ownership
// using the unchanged common buffer dependency.
const receiveSharing = false

func receiveHasViews(*buf.Buffer) bool               { return false }
func receiveSlice(*buf.Buffer, int, int) *buf.Buffer { panic("shared receive disabled") }
