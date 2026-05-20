package cf

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeHTTP struct {
	get func(ctx context.Context, url string) ([]byte, error)
}

func (f fakeHTTP) Get(ctx context.Context, url string) ([]byte, error) {
	return f.get(ctx, url)
}

func tempCfg(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{
		SnippetPath: filepath.Join(dir, "snippets/cf-allow.conf"),
		CachePath:   filepath.Join(dir, "lib/cf-allow.conf"),
		URLv4:       "http://example/v4",
		URLv6:       "http://example/v6",
		Now:         func() time.Time { return time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC) },
	}
}

func TestEnsureFreshNoOp(t *testing.T) {
	cfg := tempCfg(t)
	called := false
	cfg.HTTP = fakeHTTP{get: func(_ context.Context, _ string) ([]byte, error) {
		called = true
		return nil, errors.New("must not be called")
	}}
	// Pre-create snippet recent enough.
	if err := os.MkdirAll(filepath.Dir(cfg.SnippetPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SnippetPath, []byte("# fresh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(cfg.SnippetPath, cfg.Now(), cfg.Now()); err != nil {
		t.Fatal(err)
	}

	if err := Ensure(cfg); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("HTTP called despite fresh snippet")
	}
}

func TestEnsureFetchesAndWrites(t *testing.T) {
	cfg := tempCfg(t)
	cfg.HTTP = fakeHTTP{get: func(_ context.Context, url string) ([]byte, error) {
		switch {
		case strings.HasSuffix(url, "/v4"):
			return []byte("1.1.1.0/24\n2.2.2.0/24\n"), nil
		case strings.HasSuffix(url, "/v6"):
			return []byte("2606:4700::/32\n"), nil
		}
		return nil, errors.New("unknown url")
	}}
	if err := Ensure(cfg); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(cfg.SnippetPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, want := range []string{
		"allow 1.1.1.0/24;",
		"allow 2.2.2.0/24;",
		"allow 2606:4700::/32;",
		"deny all;",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("snippet missing %q\n%s", want, s)
		}
	}
	// Cache also written
	if _, err := os.Stat(cfg.CachePath); err != nil {
		t.Errorf("cache not written: %v", err)
	}
}

func TestEnsureFallsBackToCache(t *testing.T) {
	cfg := tempCfg(t)
	// Seed cache.
	if err := os.MkdirAll(filepath.Dir(cfg.CachePath), 0755); err != nil {
		t.Fatal(err)
	}
	cached := []byte("# cached\nallow 8.8.8.0/24;\ndeny all;\n")
	if err := os.WriteFile(cfg.CachePath, cached, 0644); err != nil {
		t.Fatal(err)
	}
	// Cache mtime within 7 days.
	mt := cfg.Now().Add(-3 * 24 * time.Hour)
	if err := os.Chtimes(cfg.CachePath, mt, mt); err != nil {
		t.Fatal(err)
	}

	cfg.HTTP = fakeHTTP{get: func(_ context.Context, _ string) ([]byte, error) {
		return nil, errors.New("network down")
	}}
	if err := Ensure(cfg); err != nil {
		t.Fatalf("expected fallback to cache, got: %v", err)
	}
	got, _ := os.ReadFile(cfg.SnippetPath)
	if string(got) != string(cached) {
		t.Errorf("snippet not from cache:\n%s", got)
	}
}

func TestEnsureFailsWithoutCache(t *testing.T) {
	cfg := tempCfg(t)
	cfg.HTTP = fakeHTTP{get: func(_ context.Context, _ string) ([]byte, error) {
		return nil, errors.New("network down")
	}}
	err := Ensure(cfg)
	if err == nil {
		t.Fatal("expected error when fetch fails and no cache")
	}
}

func TestEnsureRejectsBadParse(t *testing.T) {
	cfg := tempCfg(t)
	cfg.HTTP = fakeHTTP{get: func(_ context.Context, _ string) ([]byte, error) {
		return []byte("not-a-cidr\n"), nil
	}}
	err := Ensure(cfg)
	if err == nil {
		t.Fatal("expected error parsing garbage")
	}
}

func TestEnsureRefreshesStaleSnippet(t *testing.T) {
	cfg := tempCfg(t)
	if err := os.MkdirAll(filepath.Dir(cfg.SnippetPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SnippetPath, []byte("# stale\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// 2 days old.
	old := cfg.Now().Add(-2 * 24 * time.Hour)
	if err := os.Chtimes(cfg.SnippetPath, old, old); err != nil {
		t.Fatal(err)
	}

	calls := 0
	cfg.HTTP = fakeHTTP{get: func(_ context.Context, url string) ([]byte, error) {
		calls++
		if strings.HasSuffix(url, "/v4") {
			return []byte("3.3.3.0/24\n"), nil
		}
		return []byte("2606:4700::/32\n"), nil
	}}
	if err := Ensure(cfg); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("want 2 fetches, got %d", calls)
	}
	body, _ := os.ReadFile(cfg.SnippetPath)
	if !strings.Contains(string(body), "allow 3.3.3.0/24;") {
		t.Errorf("snippet not refreshed:\n%s", body)
	}
}
