// Package cert resolves which letsencrypt cert directory to use for a host.
// Walks up the domain labels until it finds a dir containing fullchain.pem,
// so wildcard certs at the parent domain are picked up automatically.
package cert

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Resolve returns the absolute cert dir for host or an error listing what
// was tried. It does NOT verify cert validity — only that fullchain.pem exists.
func Resolve(host, baseDir string) (string, error) {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("host %q has no dot, refusing", host)
	}

	tried := make([]string, 0, len(parts)-1)
	// Walk: full host, then strip leading label until 2 labels remain
	// (don't try just the TLD — would match the wrong cert).
	for i := 0; i <= len(parts)-2; i++ {
		cand := strings.Join(parts[i:], ".")
		dir := filepath.Join(baseDir, cand)
		fc := filepath.Join(dir, "fullchain.pem")
		if _, err := os.Stat(fc); err == nil {
			return dir, nil
		}
		tried = append(tried, dir)
	}
	return "", fmt.Errorf("no cert dir found for %s under %s (tried: %s)",
		host, baseDir, strings.Join(tried, ", "))
}
