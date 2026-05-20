package cert

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seedCertDir(t *testing.T, base, host string) {
	t.Helper()
	dir := filepath.Join(base, host)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveExactMatch(t *testing.T) {
	base := t.TempDir()
	seedCertDir(t, base, "a.example.com")
	got, err := Resolve("a.example.com", base)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "a.example.com")
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestResolveWalkUpToParent(t *testing.T) {
	base := t.TempDir()
	seedCertDir(t, base, "example.com")
	got, err := Resolve("a.b.c.example.com", base)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "example.com")
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestResolveExhausted(t *testing.T) {
	base := t.TempDir()
	_, err := Resolve("a.b.example.com", base)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "tried:") {
		t.Errorf("error should list tried paths: %v", err)
	}
}

func TestResolveStopsAt2Labels(t *testing.T) {
	// Even if a "com" dir exists, we should not match it.
	base := t.TempDir()
	seedCertDir(t, base, "com")
	_, err := Resolve("a.example.com", base)
	if err == nil {
		t.Fatal("expected error — must not match bare TLD")
	}
}

func TestResolveRejectsBareWord(t *testing.T) {
	_, err := Resolve("localhost", t.TempDir())
	if err == nil {
		t.Fatal("expected error for dotless host")
	}
}

func TestResolveExactBeatsParent(t *testing.T) {
	base := t.TempDir()
	seedCertDir(t, base, "example.com")
	seedCertDir(t, base, "a.example.com")
	got, err := Resolve("a.example.com", base)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "a.example.com")
	if got != want {
		t.Errorf("exact should win: got %q want %q", got, want)
	}
}
