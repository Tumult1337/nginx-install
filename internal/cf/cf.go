// Package cf maintains the Cloudflare allow-list snippet at
// /etc/nginx/snippets/cf-allow.conf. Refreshes from cloudflare.com once
// per day; on fetch failure falls back to the on-disk cache if it's < 7 days
// old. Hard-fails only when both fetch fails and no usable cache exists.
package cf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginx-gen/internal/fsop"
)

const (
	DefaultSnippet = "/etc/nginx/snippets/cf-allow.conf"
	DefaultCache   = "/var/lib/nginx-gen/cf-allow.conf"
	URLv4          = "https://www.cloudflare.com/ips-v4"
	URLv6          = "https://www.cloudflare.com/ips-v6"

	RefreshAfter = 24 * time.Hour
	CacheMaxAge  = 7 * 24 * time.Hour
)

type HTTPGetter interface {
	Get(ctx context.Context, url string) ([]byte, error)
}

type Config struct {
	SnippetPath string
	CachePath   string
	URLv4       string
	URLv6       string
	HTTP        HTTPGetter
	Now         func() time.Time
}

func DefaultConfig() Config {
	return Config{
		SnippetPath: DefaultSnippet,
		CachePath:   DefaultCache,
		URLv4:       URLv4,
		URLv6:       URLv6,
		HTTP:        defaultHTTP{},
		Now:         time.Now,
	}
}

type defaultHTTP struct{}

func (defaultHTTP) Get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	cl := &http.Client{Timeout: 10 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

// Ensure makes sure the snippet exists and is fresh enough. Returns nil if
// no work was needed or work succeeded. Logs a warning to stderr if it had
// to fall back to the cache.
func Ensure(cfg Config) error {
	if !needsRefresh(cfg) {
		return nil
	}

	prefixes, fetchErr := fetchAll(cfg)
	if fetchErr != nil {
		// Try cache fallback
		if used, err := fallbackToCache(cfg); err == nil && used {
			fmt.Fprintln(os.Stderr, "warning: CF fetch failed, using cached snippet:", fetchErr)
			return nil
		}
		return fmt.Errorf("CF fetch failed and no usable cache: %w", fetchErr)
	}

	body := renderSnippet(prefixes, cfg.Now())
	if err := writeSnippetAndCache(cfg, body); err != nil {
		return err
	}
	return nil
}

func needsRefresh(cfg Config) bool {
	info, err := os.Stat(cfg.SnippetPath)
	if err != nil {
		return true
	}
	return cfg.Now().Sub(info.ModTime()) > RefreshAfter
}

func fetchAll(cfg Config) ([]netip.Prefix, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	v4, err := fetchWithRetry(ctx, cfg.HTTP, cfg.URLv4)
	if err != nil {
		return nil, fmt.Errorf("v4: %w", err)
	}
	v6, err := fetchWithRetry(ctx, cfg.HTTP, cfg.URLv6)
	if err != nil {
		return nil, fmt.Errorf("v6: %w", err)
	}

	out := make([]netip.Prefix, 0, 32)
	for _, b := range [][]byte{v4, v6} {
		for line := range strings.FieldsSeq(string(b)) {
			p, err := netip.ParsePrefix(line)
			if err != nil {
				return nil, fmt.Errorf("parse %q: %w", line, err)
			}
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("CF returned zero prefixes")
	}
	return out, nil
}

func fetchWithRetry(ctx context.Context, h HTTPGetter, url string) ([]byte, error) {
	backoffs := []time.Duration{0, 250 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second}
	var lastErr error
	for _, d := range backoffs {
		if d > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(d):
			}
		}
		b, err := h.Get(ctx, url)
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func renderSnippet(prefixes []netip.Prefix, now time.Time) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Managed by nginx-gen. Cloudflare IP ranges. Refreshed: %s\n",
		now.UTC().Format(time.RFC3339))
	for _, p := range prefixes {
		fmt.Fprintf(&buf, "allow %s;\n", p)
	}
	buf.WriteString("deny all;\n")
	return buf.Bytes()
}

func writeSnippetAndCache(cfg Config, body []byte) error {
	if err := ensureDir(cfg.SnippetPath); err != nil {
		return err
	}
	if err := fsop.AtomicWrite(cfg.SnippetPath, body, 0644); err != nil {
		return fmt.Errorf("write snippet: %w", err)
	}
	if err := ensureDir(cfg.CachePath); err != nil {
		return err
	}
	if err := fsop.AtomicWrite(cfg.CachePath, body, 0644); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}
	return nil
}

// fallbackToCache returns (true, nil) if cache existed, was fresh enough,
// and was successfully copied to the snippet path.
func fallbackToCache(cfg Config) (bool, error) {
	info, err := os.Stat(cfg.CachePath)
	if err != nil {
		return false, err
	}
	if cfg.Now().Sub(info.ModTime()) > CacheMaxAge {
		return false, fmt.Errorf("cache too old: %s", info.ModTime())
	}
	body, err := os.ReadFile(cfg.CachePath)
	if err != nil {
		return false, err
	}
	if err := ensureDir(cfg.SnippetPath); err != nil {
		return false, err
	}
	if err := fsop.AtomicWrite(cfg.SnippetPath, body, 0644); err != nil {
		return false, err
	}
	return true, nil
}

func ensureDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0755)
}
