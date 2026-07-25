package render

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Render must always start with the marker.
func TestVhostHasMarker(t *testing.T) {
	cfg := VhostCfg{
		Host:         "a.example.com",
		Mode:         ModeProxy,
		SSL:          true,
		CertDir:      "/etc/letsencrypt/live/example.com",
		Allow:        AllowNone,
		Upstream:     "10.0.0.1:8080",
		UpstreamName: "a_example_com_up",
		Now:          fixedTime,
	}
	out, err := Vhost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("# Managed by nginx-gen.")) {
		t.Fatalf("missing marker: %s", out[:80])
	}
	if !bytes.Contains(out, []byte("kind=vhost host=a.example.com mode=proxy ssl=true allow=none")) {
		t.Errorf("marker fields wrong: %s", firstLines(out, 2))
	}
}

func TestProxySSLWithCF(t *testing.T) {
	cfg := VhostCfg{
		Host:         "p.example.com",
		Mode:         ModeProxy,
		SSL:          true,
		CertDir:      "/etc/letsencrypt/live/example.com",
		Allow:        AllowCF,
		HSTS:         HSTSOn,
		Upstream:     "10.0.0.1:8080",
		UpstreamName: "p_example_com_up",
		Now:          fixedTime,
	}
	out, err := Vhost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	mustContain(t, s, "return 301 https://$host$request_uri;")
	mustContain(t, s, "upstream p_example_com_up {")
	mustContain(t, s, "server 10.0.0.1:8080 max_fails=2")
	mustContain(t, s, "listen 443 ssl;")
	mustContain(t, s, "http2 on;")
	mustContain(t, s, "Strict-Transport-Security")
	mustContain(t, s, "include /etc/nginx/snippets/cf-allow.conf;")
	mustNotContain(t, s, "real_ip_header")   // realip dropped — see cf-allow.conf
	mustNotContain(t, s, "limit_conn perip") // CF vhost skips rate limiting entirely
	mustNotContain(t, s, "limit_req")        // CF handles rate limiting at the edge
	mustContain(t, s, "proxy_pass http://p_example_com_up;")
	mustContain(t, s, "ssl_stapling off;")
	// Plain http upstream must not emit any backend-TLS directives.
	mustNotContain(t, s, "proxy_ssl_")
}

func TestProxyLocationHeaders(t *testing.T) {
	cfg := VhostCfg{
		Host:         "p.example.com",
		Mode:         ModeProxy,
		SSL:          true,
		CertDir:      "/etc/letsencrypt/live/example.com",
		Allow:        AllowNone,
		Upstream:     "10.0.0.1:8080",
		UpstreamName: "p_example_com_up",
		Now:          fixedTime,
	}
	out, err := Vhost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// Setting any proxy_set_header in the location block drops inherited
	// http-block defaults wholesale, so these must all be restated here —
	// this is the actual redirect-to-upstream-name bug class.
	mustContain(t, s, "proxy_set_header Host              $host;")
	mustContain(t, s, "proxy_set_header X-Real-IP         $remote_addr;")
	mustContain(t, s, "proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;")
	mustContain(t, s, "proxy_set_header X-Forwarded-Proto $scheme;")
	mustContain(t, s, "proxy_set_header X-Forwarded-Host  $host;")
	mustContain(t, s, "proxy_set_header Upgrade           $http_upgrade;")
	mustContain(t, s, "proxy_set_header Connection        $connection_upgrade;")
}

func TestProxyHTTPSUpstream(t *testing.T) {
	cfg := VhostCfg{
		Host:         "manager.skybyte.cloud",
		Mode:         ModeProxy,
		SSL:          true,
		CertDir:      "/etc/letsencrypt/live/skybyte.cloud",
		Allow:        AllowNone,
		Upstream:     "5.231.234.5:8443",
		UpstreamName: "manager_skybyte_cloud_up",
		UpstreamSSL:  true,
		Now:          fixedTime,
	}
	out, err := Vhost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	mustContain(t, s, "proxy_pass https://manager_skybyte_cloud_up;")
	mustContain(t, s, "proxy_ssl_server_name on;")
	// SNI/cert name is the public host, not the upstream block name.
	mustContain(t, s, "proxy_ssl_name        manager.skybyte.cloud;")
	mustContain(t, s, "proxy_ssl_verify off;")
	mustNotContain(t, s, "proxy_ssl_verify              on;")
	mustNotContain(t, s, "proxy_ssl_name        manager_skybyte_cloud_up;")
}

func TestProxyHTTPSUpstreamVerify(t *testing.T) {
	cfg := VhostCfg{
		Host:           "manager.skybyte.cloud",
		Mode:           ModeProxy,
		SSL:            true,
		CertDir:        "/etc/letsencrypt/live/skybyte.cloud",
		Allow:          AllowNone,
		Upstream:       "backend.internal:8443",
		UpstreamName:   "manager_skybyte_cloud_up",
		UpstreamSSL:    true,
		UpstreamVerify: true,
		Now:            fixedTime,
	}
	out, err := Vhost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	mustContain(t, s, "proxy_pass https://manager_skybyte_cloud_up;")
	mustContain(t, s, "proxy_ssl_verify              on;")
	mustContain(t, s, "proxy_ssl_verify_depth        2;")
	mustContain(t, s, "proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;")
	mustNotContain(t, s, "proxy_ssl_verify off;")
}

func TestStaplingNotDisabledWithoutCF(t *testing.T) {
	cfg := VhostCfg{
		Host:         "p.example.com",
		Mode:         ModeProxy,
		SSL:          true,
		CertDir:      "/etc/letsencrypt/live/example.com",
		Allow:        AllowNone,
		Upstream:     "10.0.0.1:8080",
		UpstreamName: "p_example_com_up",
		Now:          fixedTime,
	}
	out, err := Vhost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("ssl_stapling off")) {
		t.Errorf("non-CF vhost must not disable stapling:\n%s", out)
	}
}

func TestStaplingNotEmittedWithoutSSL(t *testing.T) {
	// --allow=cf with --ssl=false: still no stapling directive at all
	cfg := VhostCfg{
		Host:  "open.example.com",
		Mode:  ModeStatic,
		SSL:   false,
		Allow: AllowCF,
		Root:  "/var/www/open",
		Now:   fixedTime,
	}
	out, err := Vhost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("ssl_stapling")) {
		t.Errorf("SSL=false must not emit any stapling directive:\n%s", out)
	}
}

func TestStaticNoSSLWithList(t *testing.T) {
	cfg := VhostCfg{
		Host:  "s.example.com",
		Mode:  ModeStatic,
		SSL:   false,
		Allow: AllowList,
		AllowCIDRs: []netip.Prefix{
			mustPrefix(t, "10.0.0.0/8"),
			mustPrefix(t, "192.168.1.0/24"),
		},
		Root: "/var/www/s",
		Now:  fixedTime,
	}
	out, err := Vhost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "return 301") {
		t.Error("static no-SSL should NOT emit redirect")
	}
	if strings.Contains(s, "listen 443") {
		t.Error("static no-SSL should NOT listen 443")
	}
	mustContain(t, s, "listen 80;")
	mustContain(t, s, "root /var/www/s;")
	mustContain(t, s, "try_files $uri $uri/ =404;")
	mustContain(t, s, "allow 10.0.0.0/8;")
	mustContain(t, s, "allow 192.168.1.0/24;")
	mustContain(t, s, "deny all;")
	mustContain(t, s, "limit_conn perip 100;") // non-CF → TCP-peer key
	mustNotContain(t, s, "perip_cf")
	if strings.Contains(s, "snippets/cf-allow") {
		t.Error("AllowList should not emit cf-allow include")
	}
}

func TestStaticAllowNoneNoDeny(t *testing.T) {
	cfg := VhostCfg{
		Host: "open.example.com",
		Mode: ModeStatic,
		SSL:  false,
		Root: "/var/www/open",
		Now:  fixedTime,
	}
	out, err := Vhost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("deny all;")) {
		t.Error("AllowNone must not emit deny all;")
	}
	if bytes.Contains(out, []byte("snippets/cf-allow")) {
		t.Error("AllowNone must not emit cf-allow include")
	}
}

func TestMain(t *testing.T) {
	out, err := Main(MainCfg{Now: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	mustContain(t, s, "# Managed by nginx-gen.")
	mustContain(t, s, "kind=main ts=2026-05-03T12:00:00Z")
	mustContain(t, s, "limit_conn_zone $binary_remote_addr zone=perip:32m;")
	mustContain(t, s, "limit_req_zone  $binary_remote_addr zone=reqip:32m")
	mustNotContain(t, s, "perip_cf")
	mustNotContain(t, s, "reqip_cf")
	mustNotContain(t, s, "$cf_rl_key")
	mustContain(t, s, "ssl_protocols             TLSv1.2 TLSv1.3;")
	mustContain(t, s, "map $http_upgrade $connection_upgrade {")
	mustContain(t, s, "proxy_set_header       Connection        \"\";")
	mustContain(t, s, "include /etc/nginx/conf.d/*.conf;")
	mustContain(t, s, "include /etc/nginx/sites-enabled/*.conf;")
	// conf.d include must precede sites-enabled so http-scope snippets
	// (e.g. `map` blocks) are visible to all vhosts.
	confdIdx := strings.Index(s, "/etc/nginx/conf.d/*.conf")
	sitesIdx := strings.Index(s, "/etc/nginx/sites-enabled/*.conf")
	if confdIdx < 0 || sitesIdx < 0 || confdIdx > sitesIdx {
		t.Errorf("conf.d include must precede sites-enabled; conf.d=%d sites=%d", confdIdx, sitesIdx)
	}
	mustNotContain(t, s, "brotli") // Brotli=false → no brotli directives
}

func TestMainWithBrotli(t *testing.T) {
	out, err := Main(MainCfg{Now: fixedTime, Brotli: true})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	mustContain(t, s, "brotli            on;")
	mustContain(t, s, "brotli_static     on;")
	mustContain(t, s, "brotli_min_length 1024;")
	mustContain(t, s, "brotli_types")
	// Sanity: brotli block is inside http {} and after gzip.
	gzipIdx := strings.Index(s, "gzip              on;")
	brotliIdx := strings.Index(s, "brotli            on;")
	if gzipIdx < 0 || brotliIdx < 0 || brotliIdx < gzipIdx {
		t.Errorf("brotli block must follow gzip block; gzip=%d brotli=%d", gzipIdx, brotliIdx)
	}
}

func mustContain(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("output missing %q\n--- output ---\n%s", sub, s)
	}
}

func mustNotContain(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Errorf("output unexpectedly contains %q\n--- output ---\n%s", sub, s)
	}
}

func firstLines(b []byte, n int) string {
	parts := strings.SplitN(string(b), "\n", n+1)
	if len(parts) > n {
		parts = parts[:n]
	}
	return strings.Join(parts, "\n")
}

func TestHSTSHeader(t *testing.T) {
	const maxAge = "max-age=63072000"
	cases := []struct {
		name string
		ssl  bool
		h    HSTS
		want string
	}{
		{"off", true, HSTSOff, ""},
		{"on", true, HSTSOn, maxAge},
		{"subdomains", true, HSTSSubdomains, maxAge + "; includeSubDomains"},
		{"preload", true, HSTSPreload, maxAge + "; includeSubDomains; preload"},
		// No SSL: RFC 6797 §8.1 has clients ignore HSTS over plain HTTP, so
		// emitting it would only make a config look hardened without being so.
		{"no-ssl off", false, HSTSOff, ""},
		{"no-ssl on", false, HSTSOn, ""},
		{"no-ssl preload", false, HSTSPreload, ""},
	}
	for _, c := range cases {
		got := VhostCfg{SSL: c.ssl, HSTS: c.h}.HSTSHeader()
		if got != c.want {
			t.Errorf("%s: HSTSHeader() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestHSTSOffEmitsNoHeader(t *testing.T) {
	for _, mode := range []Mode{ModeProxy, ModeStatic} {
		cfg := VhostCfg{
			Host: "h.example.com", Mode: mode, SSL: true, HSTS: HSTSOff,
			CertDir:  "/etc/letsencrypt/live/example.com",
			Upstream: "10.0.0.1:8080", UpstreamName: "h_up",
			Root: "/var/www/h", Now: fixedTime,
		}
		out, err := Vhost(cfg)
		if err != nil {
			t.Fatal(err)
		}
		mustNotContain(t, string(out), "Strict-Transport-Security")
	}
}

// nginx inherits add_header from the parent level only when the current level
// declares none. The static asset location sets Cache-Control, so without an
// explicit restatement every css/js/font/image response would silently ship
// without HSTS while the server block still advertised it.
func TestStaticAssetLocationRestatesHSTS(t *testing.T) {
	cfg := VhostCfg{
		Host: "s.example.com", Mode: ModeStatic, SSL: true, HSTS: HSTSSubdomains,
		CertDir: "/etc/letsencrypt/live/example.com",
		Root:    "/var/www/s", Now: fixedTime,
	}
	out, err := Vhost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if n := strings.Count(s, "Strict-Transport-Security"); n != 2 {
		t.Errorf("want HSTS twice (server + asset location), got %d\n%s", n, s)
	}

	_, loc, ok := strings.Cut(s, "location ~*")
	if !ok {
		t.Fatal("asset location block not found")
	}
	if !strings.Contains(loc, "Strict-Transport-Security") {
		t.Errorf("asset location has add_header Cache-Control but no HSTS restatement:\n%s", loc)
	}
	if !strings.Contains(loc, "Cache-Control") {
		t.Errorf("asset location lost Cache-Control:\n%s", loc)
	}
}

// With HSTS off there is nothing to restate, so the asset location must not
// gain a stray header.
func TestStaticAssetLocationNoHSTSWhenOff(t *testing.T) {
	cfg := VhostCfg{
		Host: "s.example.com", Mode: ModeStatic, SSL: true, HSTS: HSTSOff,
		CertDir: "/etc/letsencrypt/live/example.com",
		Root:    "/var/www/s", Now: fixedTime,
	}
	out, err := Vhost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mustNotContain(t, string(out), "Strict-Transport-Security")
	mustContain(t, string(out), `add_header Cache-Control "public, immutable";`)
}

func TestHSTSRecordedInMarker(t *testing.T) {
	for _, c := range []struct {
		h    HSTS
		want string
	}{
		{HSTSOff, "hsts=off"},
		{HSTSOn, "hsts=on"},
		{HSTSSubdomains, "hsts=subdomains"},
		{HSTSPreload, "hsts=preload"},
	} {
		out, err := Vhost(VhostCfg{
			Host: "m.example.com", Mode: ModeStatic, SSL: true, HSTS: c.h,
			CertDir: "/etc/letsencrypt/live/example.com", Root: "/var/www/m", Now: fixedTime,
		})
		if err != nil {
			t.Fatal(err)
		}
		mustContain(t, firstLines(out, 2), c.want)
	}
}
