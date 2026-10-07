//go:build linux || android

package snellv6

import "syscall"

// Whole-process user+system CPU, including the local sender and runtime. This
// is intentionally distinct from elapsed response time and decoder-only CPU.
func studyProcessCPU() int64 {
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil { return 0 }
	return (int64(usage.Utime.Sec)+int64(usage.Stime.Sec))*1e9 +
		(int64(usage.Utime.Usec)+int64(usage.Stime.Usec))*1e3
}
