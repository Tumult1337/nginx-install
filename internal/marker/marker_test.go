package marker

import (
	"path/filepath"
	"testing"
	"time"

	"os"
)

func TestRenderParseRoundtripVhost(t *testing.T) {
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	rendered := RenderVhost(Header{Host: "example.com", Mode: "proxy", SSL: true, Allow: "cf", HSTS: "subdomains", TS: now})

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
	if err := os.WriteFile(ours, []byte(RenderVhost(Header{Host: "a.com", Mode: "static", SSL: false, Allow: "none", HSTS: "off", TS: now})+"server{}"), 0644); err != nil {
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

func TestParseHSTSField(t *testing.T) {
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	for _, want := range []string{"off", "on", "subdomains", "preload"} {
		rendered := RenderVhost(Header{
			Host: "example.com", Mode: "proxy", SSL: true, Allow: "none", HSTS: want, TS: now,
		})
		h, ok := Parse([]byte(rendered))
		if !ok {
			t.Fatalf("hsts=%s: Parse returned ok=false", want)
		}
		if h.HSTS != want {
			t.Errorf("HSTS = %q, want %q", h.HSTS, want)
		}
	}
}

// Markers written before --hsts existed have no hsts= field. They must still
// parse cleanly, with HSTS left empty so callers can tell "unknown" apart from
// an explicit "off" — the two imply different prior behavior on the wire.
func TestParsePreHSTSMarker(t *testing.T) {
	legacy := FirstLine + "\n" +
		"# kind=vhost host=example.com mode=proxy ssl=true allow=cf ts=2026-05-03T12:00:00Z\n"
	h, ok := Parse([]byte(legacy))
	if !ok {
		t.Fatal("Parse returned ok=false for pre-hsts marker")
	}
	if h.HSTS != "" {
		t.Errorf("HSTS = %q, want empty for a marker with no hsts= field", h.HSTS)
	}
	if h.Host != "example.com" || h.Allow != "cf" || !h.SSL {
		t.Errorf("other fields corrupted: %+v", h)
	}
}

func TestParseRateLimitField(t *testing.T) {
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	for _, want := range []string{"off", "50r/s:100", "10r/m:5"} {
		rendered := RenderVhost(Header{
			Host: "example.com", Mode: "proxy", SSL: true, Allow: "none", HSTS: "off", RateLimit: want, TS: now,
		})
		h, ok := Parse([]byte(rendered))
		if !ok {
			t.Fatalf("ratelimit=%s: Parse returned ok=false", want)
		}
		if h.RateLimit != want {
			t.Errorf("RateLimit = %q, want %q", h.RateLimit, want)
		}
	}
}

// A marker written before --rate-limit existed has no ratelimit= field. It must
// parse with RateLimit empty, so --list shows "?" (not "off") for a file that
// still carries the old unconditional limit until it is re-rendered.
func TestParsePreRateLimitMarker(t *testing.T) {
	legacy := FirstLine + "\n" +
		"# kind=vhost host=example.com mode=proxy ssl=true allow=cf hsts=on ts=2026-05-03T12:00:00Z\n"
	h, ok := Parse([]byte(legacy))
	if !ok {
		t.Fatal("Parse returned ok=false for pre-ratelimit marker")
	}
	if h.RateLimit != "" {
		t.Errorf("RateLimit = %q, want empty for a marker with no ratelimit= field", h.RateLimit)
	}
	if h.HSTS != "on" || h.Host != "example.com" {
		t.Errorf("other fields corrupted: %+v", h)
	}
}
