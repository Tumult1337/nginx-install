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
		in, wantScheme, wantHost string
		err                      bool
	}{
		{in: "1.2.3.4", wantScheme: "http", wantHost: "1.2.3.4:80"},
		{in: "1.2.3.4:8080", wantScheme: "http", wantHost: "1.2.3.4:8080"},
		{in: "::1", wantScheme: "http", wantHost: "[::1]:80"},
		{in: "[::1]:8080", wantScheme: "http", wantHost: "[::1]:8080"},
		{in: "host.example.com", wantScheme: "http", wantHost: "host.example.com:80"},
		{in: "host.example.com:8080", wantScheme: "http", wantHost: "host.example.com:8080"},
		// explicit schemes
		{in: "http://1.2.3.4", wantScheme: "http", wantHost: "1.2.3.4:80"},
		{in: "http://1.2.3.4:8080", wantScheme: "http", wantHost: "1.2.3.4:8080"},
		{in: "https://1.2.3.4:8443", wantScheme: "https", wantHost: "1.2.3.4:8443"},
		{in: "https://1.2.3.4", wantScheme: "https", wantHost: "1.2.3.4:443"}, // scheme drives default port
		{in: "https://host.example.com", wantScheme: "https", wantHost: "host.example.com:443"},
		{in: "https://[::1]:8443", wantScheme: "https", wantHost: "[::1]:8443"},
		{in: "https://::1", wantScheme: "https", wantHost: "[::1]:443"},
		// rejections
		{in: "", err: true},
		{in: "https://", err: true},
		{in: "https://host:8443/path", err: true}, // URL path not allowed in upstream
		{in: "http://a?b", err: true},
	}
	for _, c := range cases {
		scheme, host, err := ParseUpstream(c.in)
		if c.err {
			if err == nil {
				t.Errorf("ParseUpstream(%q) expected error, got scheme=%q host=%q", c.in, scheme, host)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseUpstream(%q) error: %v", c.in, err)
			continue
		}
		if scheme != c.wantScheme || host != c.wantHost {
			t.Errorf("ParseUpstream(%q) = (%q, %q), want (%q, %q)", c.in, scheme, host, c.wantScheme, c.wantHost)
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
	kind, val, scheme, err := ParseTarget(dir)
	if err != nil {
		t.Fatal(err)
	}
	if kind != TargetStatic || val != dir || scheme != "" {
		t.Errorf("kind=%v val=%q scheme=%q", kind, val, scheme)
	}
}

func TestParseTargetStaticMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	_, _, _, err := ParseTarget(missing)
	if err == nil {
		t.Fatal("expected error for missing static path")
	}
}

func TestParseTargetProxy(t *testing.T) {
	kind, val, scheme, err := ParseTarget("10.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if kind != TargetProxy || val != "10.0.0.1:8080" || scheme != "http" {
		t.Errorf("kind=%v val=%q scheme=%q", kind, val, scheme)
	}
}

func TestParseTargetProxyHTTPS(t *testing.T) {
	kind, val, scheme, err := ParseTarget("https://5.231.234.5:8443")
	if err != nil {
		t.Fatal(err)
	}
	if kind != TargetProxy || val != "5.231.234.5:8443" || scheme != "https" {
		t.Errorf("kind=%v val=%q scheme=%q", kind, val, scheme)
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
