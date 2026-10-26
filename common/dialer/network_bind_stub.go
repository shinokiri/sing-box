//go:build !android || !cgo

package dialer

import "os"

func bindAndroidNetwork(fd uintptr, handle uint64) error {
	return os.ErrInvalid
}
