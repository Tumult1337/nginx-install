package fsop

import (
	"fmt"
	"os"
)

// IdempotentSymlink ensures linkPath is a symlink pointing at target.
// - If linkPath doesn't exist: creates it.
// - If linkPath is a symlink (regardless of where it points): replaces it.
// - If linkPath is a regular file or dir: refuses (returns error) — caller
//   must clean up first; we will not silently destroy non-symlinks.
// Returns true if a NEW link was created (so callers can roll back on
// later failure).
func IdempotentSymlink(target, linkPath string) (created bool, err error) {
	info, err := os.Lstat(linkPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, fmt.Errorf("lstat %s: %w", linkPath, err)
		}
		// new
		if err := os.Symlink(target, linkPath); err != nil {
			return false, fmt.Errorf("symlink %s -> %s: %w", linkPath, target, err)
		}
		return true, nil
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return false, fmt.Errorf("refusing to overwrite non-symlink at %s", linkPath)
	}
	// symlink exists; if it already points where we want, we're done
	if cur, err := os.Readlink(linkPath); err == nil && cur == target {
		return false, nil
	}
	if err := os.Remove(linkPath); err != nil {
		return false, fmt.Errorf("remove existing symlink: %w", err)
	}
	if err := os.Symlink(target, linkPath); err != nil {
		return false, fmt.Errorf("symlink %s -> %s: %w", linkPath, target, err)
	}
	return false, nil
}
