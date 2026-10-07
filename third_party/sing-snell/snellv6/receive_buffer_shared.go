//go:build !owned_receive

package snellv6

import "github.com/sagernet/sing/common/buf"

const receiveSharing = true

func receiveHasViews(buffer *buf.Buffer) bool { return buffer.HasSharedViews() }
func receiveSlice(buffer *buf.Buffer, from, to int) *buf.Buffer { return buffer.SharedSlice(from, to) }
