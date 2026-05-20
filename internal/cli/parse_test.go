package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidHost(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"a.b.c.example.com", true},
		{"x-y.example.com", true},
		{"123.example.com", true},
		{"", false},
		{".example.com", false},
		{"example.com.", false},
		{"-example.com", false},
		{"example.com-", false},
		{"example..com", false},
		{"a/b", false},
		{"../../etc/passwd", false},
		{"a;b", false},
		{"*.example.com", false},
		{"hello world", false},
		{strings.Repeat("a", 254), false},
	}
	for _, c := range cases {
		if got := ValidHost(c.in); got != c.want {
			t.Errorf("ValidHost(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseUpstream(t *testing.T) {
	cases := []struct {
		in, want string
		err      bool
	}{
		{"1.2.3.4", "1.2.3.4:80", false},
		{"1.2.3.4:8080", "1.2.3.4:8080", false},
		{"::1", "[::1]:80", false},
		{"[::1]:8080", "[::1]:8080", false},
		{"host.example.com", "host.example.com:80", false},
		{"host.example.com:8080", "host.example.com:8080", false},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := ParseUpstream(c.in)
		if c.err {
			if err == nil {
				t.Errorf("ParseUpstream(%q) expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseUpstream(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseUpstream(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestUpstreamName(t *testing.T) {
	if got := UpstreamName("a.example.com"); got != "a_example_com_up" {
		t.Errorf("UpstreamName: %q", got)
	}
	if got := UpstreamName("api-v2.example.com"); got != "api_v2_example_com_up" {
		t.Errorf("UpstreamName with dash: %q", got)
	}
}

func TestParseTargetStatic(t *testing.T) {
	dir := t.TempDir()
	kind, val, err := ParseTarget(dir)
	if err != nil {
		t.Fatal(err)
	}
	if kind != TargetStatic || val != dir {
		t.Errorf("kind=%v val=%q", kind, val)
	}
}

func TestParseTargetStaticMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	_, _, err := ParseTarget(missing)
	if err == nil {
		t.Fatal("expected error for missing static path")
	}
}

func TestParseTargetProxy(t *testing.T) {
	kind, val, err := ParseTarget("10.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if kind != TargetProxy || val != "10.0.0.1:8080" {
		t.Errorf("kind=%v val=%q", kind, val)
	}
}

func TestParseAllow(t *testing.T) {
	k, _, err := ParseAllow("")
	if err != nil || k != AllowNone {
		t.Errorf("empty: k=%v err=%v", k, err)
	}

	k, _, err = ParseAllow("cf")
	if err != nil || k != AllowCF {
		t.Errorf("cf: k=%v err=%v", k, err)
	}

	k, ps, err := ParseAllow("10.0.0.0/8, 192.168.1.0/24")
	if err != nil || k != AllowList || len(ps) != 2 {
		t.Errorf("list: k=%v len=%d err=%v", k, len(ps), err)
	}

	// bare IP gets promoted
	k, ps, err = ParseAllow("8.8.8.8")
	if err != nil || k != AllowList || len(ps) != 1 || ps[0].Bits() != 32 {
		t.Errorf("bare v4: k=%v ps=%v err=%v", k, ps, err)
	}

	k, ps, err = ParseAllow("2606:4700::1")
	if err != nil || k != AllowList || len(ps) != 1 || ps[0].Bits() != 128 {
		t.Errorf("bare v6: k=%v ps=%v err=%v", k, ps, err)
	}

	if _, _, err := ParseAllow("300.0.0.0/8"); err == nil {
		t.Error("expected error on invalid CIDR")
	}
}
