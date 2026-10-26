//go:build android && cgo

package dialer

/*
#cgo LDFLAGS: -landroid
#include <android/multinetwork.h>
#include <errno.h>

static int box_bind_network(int fd, uint64_t handle) {
	if (android_setsocknetwork((net_handle_t) handle, fd) == 0) return 0;
	return errno;
}
*/
import "C"

import "syscall"

// Bind before connect/MSG_FASTOPEN, using the handle published by Android.
// This avoids a Java callback and duplicating the descriptor on each dial.
func bindAndroidNetwork(fd uintptr, handle uint64) error {
	if errno := C.box_bind_network(C.int(fd), C.uint64_t(handle)); errno != 0 {
		return syscall.Errno(errno)
	}
	return nil
}
