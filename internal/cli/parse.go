// Package cli parses and validates command-line inputs: host names, vhost
// targets (proxy upstream vs static html path), and the --allow value.
package cli

import (
	"fmt"
	"hash/crc32"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// ValidHost rejects anything that isn't a plain DNS hostname. The value
// flows into the conf filename and into rendered nginx config via
// text/template (no escaping), so unrestricted input is a templating-injection
// and path-traversal vector. Wildcards (*.example.com) are intentionally
// rejected — wildcard certs are handled by cert.Resolve walk-up instead.
func ValidHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if h[0] == '.' || h[0] == '-' || h[len(h)-1] == '.' || h[len(h)-1] == '-' {
		return false
	}
	if strings.Contains(h, "..") {
		return false
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

// ParseUpstream splits a proxy target into its scheme ("http" or "https") and
// a normalized "host:port", bracketing bare IPv6 literals. An optional
// http://  or https:// prefix selects the scheme nginx uses to reach the
// backend; without one the scheme is "http". The default port follows the
// scheme: 80 for http, 443 for https. Accepts:
//   - 1.2.3.4                  -> http,  1.2.3.4:80
//   - 1.2.3.4:8080             -> http,  1.2.3.4:8080
//   - https://1.2.3.4:8443     -> https, 1.2.3.4:8443
//   - https://host.example.com -> https, host.example.com:443
//   - http://host.example.com  -> http,  host.example.com:80
//   - ::1                      -> http,  [::1]:80
//   - https://[::1]:8443       -> https, [::1]:8443
//
// A path/query/fragment is rejected — an nginx `server` directive in an
// upstream block takes host:port only, and unescaped input would otherwise
// flow into the rendered config.
func ParseUpstream(arg string) (scheme, hostport string, err error) {
	if arg == "" {
		return "", "", fmt.Errorf("empty upstream")
	}
	scheme, defPort := "http", "80"
	switch {
	case strings.HasPrefix(arg, "https://"):
		scheme, defPort, arg = "https", "443", arg[len("https://"):]
	case strings.HasPrefix(arg, "http://"):
		arg = arg[len("http://"):]
	}
	if arg == "" {
		return "", "", fmt.Errorf("empty upstream host")
	}
	if strings.ContainsAny(arg, "/?#") {
		return "", "", fmt.Errorf("upstream %q must be host[:port], not a URL with a path", arg)
	}
	if strings.Contains(arg, ":") {
		if _, _, err := net.SplitHostPort(arg); err == nil {
			return scheme, arg, nil
		}
		// Failed SplitHostPort but contains ":" — could be bare IPv6.
		if ip := net.ParseIP(arg); ip != nil {
			if ip.To4() == nil {
				return scheme, fmt.Sprintf("[%s]:%s", arg, defPort), nil
			}
			return scheme, fmt.Sprintf("%s:%s", arg, defPort), nil
		}
		return "", "", fmt.Errorf("invalid upstream %q", arg)
	}
	// No colon: bare IPv4 or hostname, default port per scheme.
	return scheme, fmt.Sprintf("%s:%s", arg, defPort), nil
}

// HostIdent maps a validated host name to a unique nginx identifier. Both "."
// and "-" become "_", which is not injective on its own ("a-b.x" and "a.b.x"
// collapse together), so a CRC32 of the exact host is appended. Two vhosts must
// never derive the same identifier: nginx rejects a duplicate `upstream` block
// or `limit_req_zone`/`limit_conn_zone` name at config load. Callers add a role
// suffix (e.g. "_up", "_req") for the final name.
func HostIdent(host string) string {
	safe := strings.NewReplacer(".", "_", "-", "_").Replace(host)
	return fmt.Sprintf("%s_%08x", safe, crc32.ChecksumIEEE([]byte(host)))
}

// UpstreamName builds the identifier for a vhost's nginx `upstream {}` block.
func UpstreamName(host string) string {
	return HostIdent(host) + "_up"
}

// TargetKind discriminates the second positional arg.
type TargetKind int

const (
	TargetUnknown TargetKind = iota
	TargetProxy
	TargetStatic
)

// ParseTarget classifies the second positional arg as either a proxy upstream
// or a static html path. Proxy values are normalized via ParseUpstream; static
// paths are returned absolute and verified to exist as a directory. The
// returned scheme is "http"/"https" for proxy targets and "" for static.
//
// Disambiguation rules:
//   - starts with "/" -> static. Must exist as a directory; error otherwise.
//     (http:// and https:// start with a letter, so they never collide.)
//   - otherwise       -> proxy. ParseUpstream validates.
func ParseTarget(arg string) (kind TargetKind, value, scheme string, err error) {
	if arg == "" {
		return TargetUnknown, "", "", fmt.Errorf("empty target")
	}
	if strings.HasPrefix(arg, "/") {
		info, err := os.Stat(arg)
		if err != nil {
			return TargetUnknown, "", "", fmt.Errorf("static path %q: %w", arg, err)
		}
		if !info.IsDir() {
			return TargetUnknown, "", "", fmt.Errorf("static path %q is not a directory", arg)
		}
		return TargetStatic, arg, "", nil
	}
	scheme, up, err := ParseUpstream(arg)
	if err != nil {
		return TargetUnknown, "", "", err
	}
	return TargetProxy, up, scheme, nil
}

// HSTSKind discriminates --hsts values, ordered by blast radius.
type HSTSKind int

const (
	HSTSOff HSTSKind = iota
	HSTSOn
	HSTSSubdomains
	HSTSPreload
)

// ParseHSTS handles "" / "off" (no header), "on" (this host only),
// "subdomains" (+ includeSubDomains), and "preload" (+ preload). Case
// -insensitive, matching ParseAllow's handling of "cf".
//
// Anything above "on" is deliberately opt-in: includeSubDomains and preload
// are enforced by browsers against a cache the operator cannot reach, so
// asserting them for a host whose siblings may not serve TLS breaks those
// siblings for as long as the max-age lasts.
func ParseHSTS(s string) (HSTSKind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off":
		return HSTSOff, nil
	case "on":
		return HSTSOn, nil
	case "subdomains":
		return HSTSSubdomains, nil
	case "preload":
		return HSTSPreload, nil
	}
	return HSTSOff, fmt.Errorf("invalid --hsts value %q: want off | on | subdomains | preload", s)
}

// AllowKind discriminates --allow values.
type AllowKind int

const (
	AllowNone AllowKind = iota
	AllowCF
	AllowList
)

// ParseAllow handles "" (none), "cf", or "cidr,cidr,...". CIDRs validated
// via net/netip.
func ParseAllow(s string) (AllowKind, []netip.Prefix, error) {
	if s == "" {
		return AllowNone, nil, nil
	}
	if strings.EqualFold(s, "cf") {
		return AllowCF, nil, nil
	}
	var prefixes []netip.Prefix
	for raw := range strings.SplitSeq(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			// Allow bare IPs by promoting to /32 or /128.
			addr, aerr := netip.ParseAddr(raw)
			if aerr != nil {
				return AllowNone, nil, fmt.Errorf("invalid allow entry %q: %w", raw, err)
			}
			bits := 32
			if addr.Is6() && !addr.Is4In6() {
				bits = 128
			}
			p = netip.PrefixFrom(addr, bits)
		}
		prefixes = append(prefixes, p)
	}
	if len(prefixes) == 0 {
		return AllowNone, nil, fmt.Errorf("--allow value %q produced no entries", s)
	}
	return AllowList, prefixes, nil
}

// RateLimit holds the parsed --rate-limit value. The zero value (Enabled
// false) means the vhost emits no limit_req/limit_conn directives.
type RateLimit struct {
	Enabled bool
	Rate    string // normalized nginx rate token, e.g. "50r/s"
	Burst   int    // limit_req burst
	Conn    int    // limit_conn per-IP connection cap
}

const (
	rateLimitDefaultRate  = "50r/s"
	rateLimitDefaultBurst = 100
	rateLimitConn         = 100    // per-IP connection cap (not configurable via --rate-limit)
	rateLimitMaxBurst     = 100000 // upper bound on burst; a larger value defeats the limit
	rateLimitMaxRate      = 1000000
)

// ParseRateLimit parses a --rate-limit value into per-vhost limit_req settings.
// Forms:
//
//	""               -> disabled (flag absent)
//	"true"           -> enabled with defaults (bare --rate-limit)
//	"<rate>"         -> enabled, given rate, default burst
//	"<rate>:<burst>" -> enabled, given rate and burst
//
// <rate> is an nginx rate token: <n>r/s or <n>r/m. The value flows into a
// generated nginx.conf, so Rate is always rebuilt from the parsed integer and
// unit (never the raw input) to reject config injection through the flag.
func ParseRateLimit(s string) (RateLimit, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return RateLimit{}, nil
	}
	rl := RateLimit{
		Enabled: true,
		Rate:    rateLimitDefaultRate,
		Burst:   rateLimitDefaultBurst,
		Conn:    rateLimitConn,
	}
	if s == "true" { // bare --rate-limit
		return rl, nil
	}
	rateSpec, burstSpec, hasBurst := strings.Cut(s, ":")
	rate, err := normalizeRate(rateSpec)
	if err != nil {
		return RateLimit{}, err
	}
	rl.Rate = rate
	if hasBurst {
		b, err := strconv.Atoi(strings.TrimSpace(burstSpec))
		if err != nil || b < 0 || b > rateLimitMaxBurst {
			return RateLimit{}, fmt.Errorf("invalid --rate-limit burst %q: want integer 0..%d", burstSpec, rateLimitMaxBurst)
		}
		rl.Burst = b
	}
	return rl, nil
}

// normalizeRate validates an nginx rate token and returns it rebuilt from the
// parsed integer and unit, so the rendered value can never carry stray bytes.
func normalizeRate(s string) (string, error) {
	num, unit, ok := strings.Cut(strings.TrimSpace(s), "r/")
	if !ok || (unit != "s" && unit != "m") {
		return "", fmt.Errorf("invalid --rate-limit rate %q: want <n>r/s or <n>r/m", s)
	}
	n, err := strconv.Atoi(num)
	if err != nil || n < 1 || n > rateLimitMaxRate {
		return "", fmt.Errorf("invalid --rate-limit rate %q: want <n>r/s or <n>r/m with n in 1..%d", s, rateLimitMaxRate)
	}
	return fmt.Sprintf("%dr/%s", n, unit), nil
}
