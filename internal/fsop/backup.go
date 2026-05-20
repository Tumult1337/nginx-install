package fsop

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Backup copies path into backupDir as <basename>.<RFC3339>. Returns the
// backup path. If path doesn't exist, returns ("", nil) — first deploys
// don't fail here.
func Backup(path, backupDir string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("mkdir backup dir: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	dest := filepath.Join(backupDir, filepath.Base(path)+"."+stamp)
	if err := AtomicWrite(dest, data, 0644); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}
	return dest, nil
}

// Restore copies a backup file back to its original location. Used when
// nginx -t fails after a write.
func Restore(backupPath, originalPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	return AtomicWrite(originalPath, data, 0644)
}
