// Package nginx wraps `nginx -t` and `systemctl reload nginx` behind an
// Execer interface so the rest of the program can be tested without a real
// nginx or systemd present.
package nginx

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
)

// Execer runs an external command and returns combined stdout+stderr.
// Tests inject a fake; production uses RealExecer.
type Execer interface {
	Run(name string, args ...string) ([]byte, error)
}

type RealExecer struct{}

func (RealExecer) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// Test runs `nginx -t`. Returns nil on success; on failure the error wraps
// nginx's stderr output so the caller can surface it to the user.
func Test(e Execer) error {
	out, err := e.Run("nginx", "-t")
	if err != nil {
		return fmt.Errorf("nginx -t failed: %w\n%s", err, out)
	}
	return nil
}

// Reload runs `systemctl reload nginx`. Spec mandates systemd; on hosts
// without systemd this will fail loudly, which is the desired behavior.
func Reload(e Execer) error {
	out, err := e.Run("systemctl", "reload", "nginx")
	if err != nil {
		return fmt.Errorf("systemctl reload nginx failed: %w\n%s", err, out)
	}
	return nil
}

// VersionInfo holds a parsed nginx version triple.
type VersionInfo struct {
	Major, Minor, Patch int
}

// HTTP2Inline reports whether this nginx version requires the http2 parameter
// on the listen directive (`listen 443 ssl http2;`) rather than the standalone
// `http2 on;` directive introduced in nginx 1.25.1.
func (v VersionInfo) HTTP2Inline() bool {
	switch {
	case v.Major != 1:
		return v.Major < 1
	case v.Minor != 25:
		return v.Minor < 25
	default:
		return v.Patch < 1
	}
}

var versionRE = regexp.MustCompile(`nginx/(\d+)\.(\d+)\.(\d+)`)

// Version runs `nginx -v` and returns the parsed version.
// nginx writes its version string to stderr; CombinedOutput captures both.
func Version(e Execer) (VersionInfo, error) {
	out, _ := e.Run("nginx", "-v")
	m := versionRE.FindSubmatch(out)
	if m == nil {
		return VersionInfo{}, fmt.Errorf("nginx -v: version string not found in %q", out)
	}
	atoi := func(b []byte) int { n, _ := strconv.Atoi(string(b)); return n }
	return VersionInfo{Major: atoi(m[1]), Minor: atoi(m[2]), Patch: atoi(m[3])}, nil
}
