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

type VhostCfg struct {
	Host         string
	Mode         Mode
	SSL          bool
	CertDir      string // resolved (post auto-detect): /etc/letsencrypt/live/<somedomain>
	Allow        AllowSpec
	AllowCIDRs   []netip.Prefix // when Allow == AllowList
	Upstream     string         // "host:port" — for proxy mode (IPv6 already bracketed)
	UpstreamName string         // safe identifier for `upstream {}` block
	Root         string         // absolute existing dir — for static mode
	Now          time.Time      // injectable for golden tests
	HTTP2Inline  bool           // true → emit `listen 443 ssl http2;` (nginx < 1.25.1)
}

// Template-friendly accessors. text/template can't compare against AllowSpec
// constants from outside the package, so expose booleans instead.
func (c VhostCfg) IsCF() bool   { return c.Allow == AllowCF }
func (c VhostCfg) IsList() bool { return c.Allow == AllowList && len(c.AllowCIDRs) > 0 }

func (c VhostCfg) allowField() string {
	switch c.Allow {
	case AllowCF:
		return "cf"
	case AllowList:
		return fmt.Sprintf("list:%d", len(c.AllowCIDRs))
	}
	return "none"
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
	buf.WriteString(marker.RenderVhost(cfg.Host, cfg.Mode.String(), cfg.SSL, cfg.allowField(), cfg.Now))
	if err := t.Execute(&buf, cfg); err != nil {
		return nil, fmt.Errorf("render %s: %w", tmplName, err)
	}
	return buf.Bytes(), nil
}

// Main renders /etc/nginx/nginx.conf, marker prepended. No variables.
func Main(now time.Time) ([]byte, error) {
	t := tpls.Lookup("main.tmpl")
	if t == nil {
		return nil, fmt.Errorf("template main.tmpl not found")
	}
	var buf bytes.Buffer
	buf.WriteString(marker.RenderMain(now))
	if err := t.Execute(&buf, nil); err != nil {
		return nil, fmt.Errorf("render main.tmpl: %w", err)
	}
	return buf.Bytes(), nil
}
