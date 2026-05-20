package marker

import (
	"path/filepath"
	"testing"
	"time"

	"os"
)

func TestRenderParseRoundtripVhost(t *testing.T) {
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	rendered := RenderVhost("example.com", "proxy", true, "cf", now)

	h, ok := Parse([]byte(rendered + "server { ... }\n"))
	if !ok {
		t.Fatal("Parse returned ok=false")
	}
	if h.Kind != KindVhost {
		t.Errorf("Kind: want vhost, got %v", h.Kind)
	}
	if h.Host != "example.com" {
		t.Errorf("Host: %q", h.Host)
	}
	if h.Mode != "proxy" {
		t.Errorf("Mode: %q", h.Mode)
	}
	if !h.SSL {
		t.Error("SSL: want true")
	}
	if h.Allow != "cf" {
		t.Errorf("Allow: %q", h.Allow)
	}
	if !h.TS.Equal(now) {
		t.Errorf("TS: %v vs %v", h.TS, now)
	}
}

func TestRenderParseRoundtripMain(t *testing.T) {
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	rendered := RenderMain(now)
	h, ok := Parse([]byte(rendered + "events { ... }\n"))
	if !ok {
		t.Fatal("Parse returned ok=false")
	}
	if h.Kind != KindMain {
		t.Errorf("Kind: want main, got %v", h.Kind)
	}
	if !h.TS.Equal(now) {
		t.Errorf("TS: %v vs %v", h.TS, now)
	}
}

func TestParseRejectsUnmarked(t *testing.T) {
	cases := [][]byte{
		[]byte("server { listen 80; }\n"),
		[]byte("# Some other comment\n# host=x\n"),
		[]byte(""),
		[]byte(FirstLine + "\n"), // missing second line
		[]byte(FirstLine + "\n# no kind here\n"),
	}
	for i, c := range cases {
		if _, ok := Parse(c); ok {
			t.Errorf("case %d: Parse should reject %q", i, c)
		}
	}
}

func TestRequireOurs(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	// missing
	r, _, err := RequireOurs(filepath.Join(dir, "nope"))
	if err != nil || r != CheckMissing {
		t.Fatalf("missing: r=%v err=%v", r, err)
	}

	// ours
	ours := filepath.Join(dir, "ours.conf")
	if err := os.WriteFile(ours, []byte(RenderVhost("a.com", "static", false, "none", now)+"server{}"), 0644); err != nil {
		t.Fatal(err)
	}
	r, h, err := RequireOurs(ours)
	if err != nil || r != CheckOurs {
		t.Fatalf("ours: r=%v err=%v", r, err)
	}
	if h.Host != "a.com" {
		t.Errorf("ours: Host=%q", h.Host)
	}

	// not ours
	notOurs := filepath.Join(dir, "notours.conf")
	if err := os.WriteFile(notOurs, []byte("server { listen 80; }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r, _, err = RequireOurs(notOurs)
	if err != nil || r != CheckNotOurs {
		t.Fatalf("notours: r=%v err=%v", r, err)
	}
}
