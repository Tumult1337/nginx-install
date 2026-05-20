// Package marker reads and writes the two-line header that identifies
// nginx-gen-managed config files. Anything without this marker is treated
// as user-managed and cannot be overwritten without --force.
package marker

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"
)

const FirstLine = "# Managed by nginx-gen. Do not edit by hand."

type Kind int

const (
	KindUnknown Kind = iota
	KindMain         // /etc/nginx/nginx.conf
	KindVhost        // sites-available/<host>.conf
)

type Header struct {
	Kind  Kind
	Host  string // KindVhost only
	Mode  string // KindVhost only: "proxy" | "static"
	SSL   bool   // KindVhost only
	Allow string // KindVhost only: "none" | "cf" | "list:<n>"
	TS    time.Time
}

func RenderVhost(host, mode string, ssl bool, allow string, now time.Time) string {
	return FirstLine + "\n" +
		fmt.Sprintf("# kind=vhost host=%s mode=%s ssl=%t allow=%s ts=%s\n",
			host, mode, ssl, allow, now.UTC().Format(time.RFC3339))
}

func RenderMain(now time.Time) string {
	return FirstLine + "\n" +
		fmt.Sprintf("# kind=main ts=%s\n", now.UTC().Format(time.RFC3339))
}

// Parse extracts the marker from the start of content. ok=false if the
// first line doesn't match — caller treats as user-managed.
func Parse(content []byte) (Header, bool) {
	sc := bufio.NewScanner(bytes.NewReader(content))
	if !sc.Scan() {
		return Header{}, false
	}
	if strings.TrimRight(sc.Text(), " \t\r") != FirstLine {
		return Header{}, false
	}
	if !sc.Scan() {
		return Header{}, false
	}
	return parseFields(strings.TrimPrefix(sc.Text(), "# "))
}

func parseFields(s string) (Header, bool) {
	h := Header{}
	for kv := range strings.FieldsSeq(s) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "kind":
			switch v {
			case "main":
				h.Kind = KindMain
			case "vhost":
				h.Kind = KindVhost
			}
		case "host":
			h.Host = v
		case "mode":
			h.Mode = v
		case "ssl":
			h.SSL = v == "true"
		case "allow":
			h.Allow = v
		case "ts":
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				h.TS = t
			}
		}
	}
	return h, h.Kind != KindUnknown
}

type CheckResult int

const (
	CheckOurs    CheckResult = iota // marker present
	CheckNotOurs                    // file exists, no marker
	CheckMissing                    // file does not exist
)

// RequireOurs inspects path. Caller decides whether to refuse on CheckNotOurs.
func RequireOurs(path string) (CheckResult, Header, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return CheckMissing, Header{}, nil
		}
		return 0, Header{}, err
	}
	if h, ok := Parse(b); ok {
		return CheckOurs, h, nil
	}
	return CheckNotOurs, Header{}, nil
}
