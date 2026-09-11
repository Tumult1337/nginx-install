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
	if got := UpstreamName("a.example.com"); !strings.HasPrefix(got, "a_example_com_") || !strings.HasSuffix(got, "_up") {
		t.Errorf("UpstreamName: %q", got)
	}
	if got := UpstreamName("api-v2.example.com"); !strings.HasPrefix(got, "api_v2_example_com_") || !strings.HasSuffix(got, "_up") {
		t.Errorf("UpstreamName with dash: %q", got)
	}
}

// Both "." and "-" map to "_", so distinct hosts would collide without the hash
// HostIdent appends. nginx rejects a duplicate upstream/zone name at load.
func TestHostIdentInjective(t *testing.T) {
	a, b := HostIdent("a-b.example.com"), HostIdent("a.b.example.com")
	if a == b {
		t.Errorf("HostIdent collides for a-b.example.com and a.b.example.com: %q", a)
	}
	for _, r := range a {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_'
		if !ok {
			t.Errorf("HostIdent(%q)=%q has non-identifier rune %q", "a-b.example.com", a, r)
		}
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

func TestParseHSTS(t *testing.T) {
	cases := []struct {
		in      string
		want    HSTSKind
		wantErr bool
	}{
		{"", HSTSOff, false},
		{"off", HSTSOff, false},
		{"on", HSTSOn, false},
		{"subdomains", HSTSSubdomains, false},
		{"preload", HSTSPreload, false},
		{"  On  ", HSTSOn, false},
		{"SUBDOMAINS", HSTSSubdomains, false},
		// Unhappy paths: an unrecognized value must fail loudly rather than
		// degrade to off, which would silently drop a header the operator asked for.
		{"true", HSTSOff, true},
		{"yes", HSTSOff, true},
		{"1", HSTSOff, true},
		{"max-age=31536000", HSTSOff, true},
		{"on,subdomains", HSTSOff, true},
	}
	for _, c := range cases {
		got, err := ParseHSTS(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseHSTS(%q): err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("ParseHSTS(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestHSTSKindOrdering(t *testing.T) {
	// warnHSTSDowngrade compares these with <, so the order is load-bearing.
	if HSTSOff >= HSTSOn || HSTSOn >= HSTSSubdomains || HSTSSubdomains >= HSTSPreload {
		t.Error("HSTSKind constants are not ordered by blast radius")
	}
}

func TestParseRateLimit(t *testing.T) {
	cases := []struct {
		in      string
		want    RateLimit
		wantErr bool
	}{
		{"", RateLimit{}, false}, // absent → disabled
		{"true", RateLimit{Enabled: true, Rate: "50r/s", Burst: 100, Conn: 100}, false},  // bare flag
		{"10r/s", RateLimit{Enabled: true, Rate: "10r/s", Burst: 100, Conn: 100}, false}, // rate only, default burst
		{"10r/s:5", RateLimit{Enabled: true, Rate: "10r/s", Burst: 5, Conn: 100}, false},
		{"100r/m:0", RateLimit{Enabled: true, Rate: "100r/m", Burst: 0, Conn: 100}, false}, // burst 0 is valid
		{"  30r/s : 20 ", RateLimit{Enabled: true, Rate: "30r/s", Burst: 20, Conn: 100}, false},
		{"+50r/s", RateLimit{Enabled: true, Rate: "50r/s", Burst: 100, Conn: 100}, false}, // normalized, sign dropped
		// Unhappy paths: reject rather than degrade. A bad value must not
		// silently produce an unlimited or malformed config.
		{"50", RateLimit{}, true},           // missing unit
		{"50r/h", RateLimit{}, true},        // bad unit
		{"0r/s", RateLimit{}, true},         // rate must be ≥ 1
		{"abcr/s", RateLimit{}, true},       // non-numeric rate
		{"10r/s:-1", RateLimit{}, true},     // negative burst
		{"10r/s:abc", RateLimit{}, true},    // non-numeric burst
		{"10r/s:999999", RateLimit{}, true}, // burst above bound
		// Config-injection attempts must be rejected, never written into nginx.conf.
		{"1r/s; deny all", RateLimit{}, true},
		{"1r/s\ninjected", RateLimit{}, true},
		{"1r/s:100}", RateLimit{}, true},
	}
	for _, c := range cases {
		got, err := ParseRateLimit(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseRateLimit(%q): err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if err == nil && got != c.want {
			t.Errorf("ParseRateLimit(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}
