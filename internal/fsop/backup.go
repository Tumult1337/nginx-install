package fsop

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const maxBackupSuffix = 99

func Backup(path string, data []byte, now time.Time, backupDir string) (string, error) {
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("mkdir backup dir: %w", err)
	}
	base := filepath.Join(backupDir, filepath.Base(path)+"."+now.UTC().Format("20060102T150405Z"))
	dest, err := freeBackupPath(base)
	if err != nil {
		return "", err
	}
	if err := AtomicWrite(dest, data, 0644); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}
	return dest, nil
}

func freeBackupPath(base string) (string, error) {
	for suffix := 0; suffix <= maxBackupSuffix; suffix++ {
		candidate := base
		if suffix > 0 {
			candidate = fmt.Sprintf("%s.%d", base, suffix)
		}
		_, err := os.Lstat(candidate)
		if os.IsNotExist(err) {
			return candidate, nil
		}
		if err != nil {
			return "", fmt.Errorf("stat backup %s: %w", candidate, err)
		}
	}
	return "", fmt.Errorf("no free backup name for %s after %d tries", base, maxBackupSuffix+1)
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
