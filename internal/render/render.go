// Package render produces nginx config bytes from a VhostCfg or for the
// global nginx.conf. The marker header is prepended automatically.
package render

import (
	"bytes"
	"embed"
	"fmt"
	"net/netip"
	"text/template"
	"time"

	"nginx-gen/internal/cli"
	"nginx-gen/internal/marker"
)

type Mode int

const (
	ModeProxy Mode = iota
	ModeStatic
)

func (m Mode) String() string {
	switch m {
	case ModeProxy:
		return "proxy"
	case ModeStatic:
		return "static"
	}
	return "unknown"
}

type AllowSpec int

const (
	AllowNone AllowSpec = iota
	AllowCF
	AllowList
)

func (a AllowSpec) String() string {
	switch a {
	case AllowNone:
		return "none"
	case AllowCF:
		return "cf"
	case AllowList:
		return "list"
	}
	return "unknown"
}

// HSTS selects the Strict-Transport-Security policy for a vhost. Values are
// ordered by blast radius so callers can compare with > to detect a downgrade:
// the header is enforced by browsers against a cache the operator does not
// control, so a mistake outlives the config that caused it.
type HSTS int

const (
	HSTSOff        HSTS = iota // no header
	HSTSOn                     // this host only
	HSTSSubdomains             // + includeSubDomains
	HSTSPreload                // + preload
)

func (h HSTS) String() string {
	switch h {
	case HSTSOff:
		return "off"
	case HSTSOn:
		return "on"
	case HSTSSubdomains:
		return "subdomains"
	case HSTSPreload:
		return "preload"
	}
	return "unknown"
}

// hstsMaxAge is two years. The preload list requires at least one year, so a
// single value serves every enabled policy and there is nothing to tune.
const hstsMaxAge = 63072000

type VhostCfg struct {
	Host           string
	Mode           Mode
	SSL            bool
	CertDir        string // resolved (post auto-detect): /etc/letsencrypt/live/<somedomain>
	Allow          AllowSpec
	HSTS           HSTS
	AllowCIDRs     []netip.Prefix // when Allow == AllowList
	Upstream       string         // "host:port" — for proxy mode (IPv6 already bracketed)
	UpstreamName   string         // safe identifier for `upstream {}` block
	UpstreamSSL    bool           // true → proxy_pass https:// (TLS to the backend)
	UpstreamVerify bool           // true → verify the backend cert (proxy_ssl_verify on)
	Root           string         // absolute existing dir — for static mode
	Now            time.Time      // injectable for golden tests
	HTTP2Inline    bool           // true → emit `listen 443 ssl http2;` (nginx < 1.25.1)

	RateLimit      bool   // opt-in: emit per-vhost limit_req/limit_conn (suppressed under CF)
	RateLimitRate  string // normalized nginx rate token, e.g. "50r/s"
	RateLimitBurst int    // limit_req burst
	RateLimitConn  int    // limit_conn per-IP connection cap
}

// Template-friendly accessors. text/template can't compare against AllowSpec
// constants from outside the package, so expose booleans instead.
func (c VhostCfg) IsCF() bool   { return c.Allow == AllowCF }
func (c VhostCfg) IsList() bool { return c.Allow == AllowList && len(c.AllowCIDRs) > 0 }

// RateLimited reports whether the vhost emits rate-limit directives. CF vhosts
// never do: the key would be $binary_remote_addr, which under Cloudflare is the
// edge IP, so the limit would throttle all clients behind one edge together.
func (c VhostCfg) RateLimited() bool { return c.RateLimit && c.Allow != AllowCF }

// ReqZone and ConnZone are the per-vhost zone names. cli.HostIdent guarantees
// distinct hosts never collide on one name, which nginx rejects at load.
func (c VhostCfg) ReqZone() string  { return cli.HostIdent(c.Host) + "_req" }
func (c VhostCfg) ConnZone() string { return cli.HostIdent(c.Host) + "_conn" }

// HSTSHeader returns the Strict-Transport-Security value, or "" when the
// header should be omitted entirely. Empty without SSL: RFC 6797 §8.1 requires
// clients to ignore an HSTS header not received over a secure transport, so
// emitting one on a plain-HTTP vhost is noise at best. Templates branch on the
// emptiness of this single value rather than on SSL, so the server block and
// any location block that restates the header cannot drift apart.
func (c VhostCfg) HSTSHeader() string {
	if !c.SSL || c.HSTS == HSTSOff {
		return ""
	}
	h := fmt.Sprintf("max-age=%d", hstsMaxAge)
	if c.HSTS >= HSTSSubdomains {
		h += "; includeSubDomains"
	}
	if c.HSTS >= HSTSPreload {
		h += "; preload"
	}
	return h
}

// UpstreamProto returns the scheme for proxy_pass: "https" when TLS to the
// backend is requested, else "http".
func (c VhostCfg) UpstreamProto() string {
	if c.UpstreamSSL {
		return "https"
	}
	return "http"
}

func (c VhostCfg) allowField() string {
	switch c.Allow {
	case AllowCF:
		return "cf"
	case AllowList:
		return fmt.Sprintf("list:%d", len(c.AllowCIDRs))
	}
	return "none"
}

// rateLimitField is the marker value: "off" when no directives are emitted, or
// "<rate>:<burst>" so --list can show the applied limit. Reads RateLimited()
// so a CF vhost that was handed --rate-limit records "off", matching the file.
func (c VhostCfg) rateLimitField() string {
	if !c.RateLimited() {
		return "off"
	}
	return fmt.Sprintf("%s:%d", c.RateLimitRate, c.RateLimitBurst)
}

//go:embed templates/*.tmpl
var tmplFS embed.FS

var tpls = template.Must(template.ParseFS(tmplFS, "templates/*.tmpl"))

// Vhost renders a per-host config file, marker prepended.
func Vhost(cfg VhostCfg) ([]byte, error) {
	tmplName := "proxy.tmpl"
	if cfg.Mode == ModeStatic {
		tmplName = "static.tmpl"
	}
	t := tpls.Lookup(tmplName)
	if t == nil {
		return nil, fmt.Errorf("template %s not found", tmplName)
	}

	var buf bytes.Buffer
	buf.WriteString(marker.RenderVhost(marker.Header{
		Host:      cfg.Host,
		Mode:      cfg.Mode.String(),
		SSL:       cfg.SSL,
		Allow:     cfg.allowField(),
		HSTS:      cfg.HSTS.String(),
		RateLimit: cfg.rateLimitField(),
		TS:        cfg.Now,
	}))
	if err := t.Execute(&buf, cfg); err != nil {
		return nil, fmt.Errorf("render %s: %w", tmplName, err)
	}
	return buf.Bytes(), nil
}

// MainCfg controls optional features in the global nginx.conf.
type MainCfg struct {
	Now    time.Time
	Brotli bool // emit brotli {filter,static} directives (requires the dynamic module)
}

// Main renders /etc/nginx/nginx.conf, marker prepended.
func Main(cfg MainCfg) ([]byte, error) {
	t := tpls.Lookup("main.tmpl")
	if t == nil {
		return nil, fmt.Errorf("template main.tmpl not found")
	}
	var buf bytes.Buffer
	buf.WriteString(marker.RenderMain(cfg.Now))
	if err := t.Execute(&buf, cfg); err != nil {
		return nil, fmt.Errorf("render main.tmpl: %w", err)
	}
	return buf.Bytes(), nil
}
