// Package cli parses and validates command-line inputs: host names, vhost
// targets (proxy upstream vs static html path), and the --allow value.
package cli

import (
	"fmt"
	"net"
	"net/netip"
	"os"
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

// UpstreamName builds a safe identifier for nginx's `upstream {}` block from
// a host name. Dots and dashes become underscores; suffix `_up`.
func UpstreamName(host string) string {
	r := strings.NewReplacer(".", "_", "-", "_")
	return r.Replace(host) + "_up"
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
