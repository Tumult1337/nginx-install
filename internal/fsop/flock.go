package fsop

import (
	"fmt"
	"os"
	"syscall"
)

// Flock acquires an exclusive flock on path, creating the file if missing.
// Blocks until acquired. Returns a release function the caller MUST defer;
// release closes the fd which drops the lock.
func Flock(path string) (release func(), err error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("flock %s: %w", path, err)
	}
	return func() {
		// Best-effort: closing the fd releases the kernel lock.
		_ = f.Close()
	}, nil
}
