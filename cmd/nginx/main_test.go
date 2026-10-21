package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"nginx-gen/internal/cli"
	"nginx-gen/internal/marker"
	"nginx-gen/internal/nginx"
	"nginx-gen/internal/render"
)

var fixedNow = time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)

func tempLayout(t *testing.T) Layout {
	t.Helper()
	dir := t.TempDir()
	return Layout{
		SitesAvailable:     filepath.Join(dir, "sites-available"),
		SitesEnabled:       filepath.Join(dir, "sites-enabled"),
		MainConfPath:       filepath.Join(dir, "nginx.conf"),
		BackupDir:          filepath.Join(dir, "backups"),
		LockPath:           filepath.Join(dir, "lock"),
		SnippetPath:        filepath.Join(dir, "snippets/cf-allow.conf"),
		CachePath:          filepath.Join(dir, "lib/cf-allow.conf"),
		CertDirs:           []string{filepath.Join(dir, "letsencrypt"), filepath.Join(dir, "nginx-ssl")},
		SysctlPath:         filepath.Join(dir, "sysctl.d/99-nginx.conf"),
		SystemdOverrideDir: filepath.Join(dir, "systemd/nginx.service.d"),
		ModulesDir:         filepath.Join(dir, "modules"),
		ModulesEnabledDir:  filepath.Join(dir, "modules-enabled"),
	}
}

// fakeExec records calls; returns canned err / output keyed by argv[0].
type fakeExec struct {
	mu      sync.Mutex
	calls   [][]string
	fail    map[string]error // argv[0] -> err
	out     map[string][]byte
	hook    func(name string, args []string)
	respond func(name string, args []string) (fakeResult, bool)
}

type fakeResult struct {
	out []byte
	err error
}

func (f *fakeExec) Run(name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{name}, args...))
	hook, respond := f.hook, f.respond
	f.mu.Unlock()
	if hook != nil {
		hook(name, args)
	}
	if respond != nil {
		if result, ok := respond(name, args); ok {
			return result.out, result.err
		}
	}
	if e, ok := f.fail[name]; ok {
		return f.out[name], e
	}
	return f.out[name], nil
}

func (f *fakeExec) RunEnv(name string, _ []string, args ...string) ([]byte, error) {
	return f.Run(name, args...)
}

func (f *fakeExec) RunDir(_, name string, args ...string) ([]byte, error) {
	return f.Run(name, args...)
}

func (f *fakeExec) called(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c[0] == name {
			return true
		}
	}
	return false
}

type fakeHTTP struct {
	get func(ctx context.Context, url string) ([]byte, error)
}

func (f fakeHTTP) Get(ctx context.Context, url string) ([]byte, error) { return f.get(ctx, url) }

func defaultDepsFor(t *testing.T) (Deps, *fakeExec, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	// Point the nginx.org sources-list probe at a path under the test's
	// temp directory so the file-stat check in ensureBrotli is deterministic
	// regardless of whether the dev host has /etc/apt/sources.list.d/nginx.list
	// in place. Individual tests can `os.WriteFile(nginxOrgSourcesList, ...)`
	// to simulate "nginx.org repo configured".
	overrideNginxOrgSourcesList(t, filepath.Join(t.TempDir(), "nginx.list"))
	exec := &fakeExec{fail: map[string]error{}, out: map[string][]byte{}}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	d := Deps{
		Layout: tempLayout(t),
		Exec:   exec,
		HTTP: fakeHTTP{get: func(_ context.Context, url string) ([]byte, error) {
			if strings.HasSuffix(url, "/v4") {
				return []byte("1.1.1.0/24\n"), nil
			}
			return []byte("2606:4700::/32\n"), nil
		}},
		Now:    func() time.Time { return fixedNow },
		Stdout: stdout,
		Stderr: stderr,
	}
	return d, exec, stdout, stderr
}

func overrideNginxOrgSourcesList(t *testing.T, path string) {
	t.Helper()
	orig := nginxOrgSourcesList
	nginxOrgSourcesList = path
	t.Cleanup(func() { nginxOrgSourcesList = orig })
}

func seedCert(t *testing.T, layout Layout, host string) {
	t.Helper()
	dir := filepath.Join(layout.CertDirs[0], host)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"fullchain.pem", "privkey.pem"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

// ---- 1. --main ----

func TestRunMainWritesAndCallsTest(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)

	code := Run([]string{"--main"}, d)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, err := os.ReadFile(d.Layout.MainConfPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(marker.FirstLine)) {
		t.Errorf("nginx.conf missing marker:\n%s", b)
	}
	if !exec.called("nginx") || !exec.called("systemctl") {
		t.Errorf("expected nginx -t and systemctl reload calls, got %v", exec.calls)
	}
}

// ---- 2. proxy vhost --ssl --allow=cf ----

func TestRunVhostProxySSLCF(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	seedCert(t, d.Layout, "p.example.com")

	code := Run([]string{"--allow=cf", "--hsts=on", "p.example.com", "10.0.0.1:8080"}, d)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, err := os.ReadFile(filepath.Join(d.Layout.SitesAvailable, "p.example.com.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"include /etc/nginx/snippets/cf-allow.conf",
		"upstream " + cli.UpstreamName("p.example.com") + " {",
		"Strict-Transport-Security",
		"return 301 https://$host$request_uri;",
	} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("vhost missing %q\n%s", want, b)
		}
	}
	// Symlink in sites-enabled
	link := filepath.Join(d.Layout.SitesEnabled, "p.example.com.conf")
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("symlink missing: %v", err)
	}
	// CF snippet was written
	if _, err := os.Stat(d.Layout.SnippetPath); err != nil {
		t.Errorf("cf snippet not written: %v", err)
	}
	if !exec.called("nginx") {
		t.Errorf("expected nginx -t")
	}
}

// ---- 3. static --ssl=false ----

func TestRunVhostStaticNoSSL(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	htmlDir := t.TempDir()
	code := Run([]string{"--ssl=false", "s.example.com", htmlDir}, d)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, _ := os.ReadFile(filepath.Join(d.Layout.SitesAvailable, "s.example.com.conf"))
	s := string(b)
	if strings.Contains(s, "return 301") {
		t.Errorf("--ssl=false must not emit redirect:\n%s", s)
	}
	if strings.Contains(s, "listen 443") {
		t.Errorf("--ssl=false must not listen 443:\n%s", s)
	}
	if !strings.Contains(s, "root "+htmlDir+";") {
		t.Errorf("missing root directive:\n%s", s)
	}
}

// ---- 4. --allow=cidrs / reject bad ----

func TestRunAllowCIDRList(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	htmlDir := t.TempDir()
	code := Run([]string{"--ssl=false", "--allow=10.0.0.0/8,192.168.1.0/24", "s.example.com", htmlDir}, d)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, _ := os.ReadFile(filepath.Join(d.Layout.SitesAvailable, "s.example.com.conf"))
	for _, want := range []string{"allow 10.0.0.0/8;", "allow 192.168.1.0/24;", "deny all;"} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("missing %q\n%s", want, b)
		}
	}
}

// Rate limiting is opt-in: a vhost written without --rate-limit emits no
// limit_req/limit_conn directives.
func TestRunVhostRateLimitDefaultOff(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	htmlDir := t.TempDir()
	if code := Run([]string{"--ssl=false", "s.example.com", htmlDir}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, _ := os.ReadFile(filepath.Join(d.Layout.SitesAvailable, "s.example.com.conf"))
	s := string(b)
	if strings.Contains(s, "limit_req") || strings.Contains(s, "limit_conn") {
		t.Errorf("default must emit no rate-limit directives:\n%s", s)
	}
	if !strings.Contains(s, "ratelimit=off") {
		t.Errorf("marker must record ratelimit=off:\n%s", s)
	}
}

// --rate-limit=<rate>:<burst> emits per-vhost zones keyed on the host and the
// requested rate/burst.
func TestRunVhostRateLimitOptIn(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	htmlDir := t.TempDir()
	if code := Run([]string{"--ssl=false", "--rate-limit=20r/s:50", "s.example.com", htmlDir}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, _ := os.ReadFile(filepath.Join(d.Layout.SitesAvailable, "s.example.com.conf"))
	zc := render.VhostCfg{Host: "s.example.com"}
	req, conn := zc.ReqZone(), zc.ConnZone()
	for _, want := range []string{
		"limit_req_zone  $binary_remote_addr zone=" + req + ":10m rate=20r/s;",
		"limit_conn_zone $binary_remote_addr zone=" + conn + ":10m;",
		"limit_conn " + conn + " 100;",
		"limit_req  zone=" + req + " burst=50 nodelay;",
		"ratelimit=20r/s:50",
	} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("missing %q\n%s", want, b)
		}
	}
}

// --rate-limit=false disables (bool-flag convention), same as omitting it.
func TestRunVhostRateLimitFalseDisables(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	htmlDir := t.TempDir()
	if code := Run([]string{"--ssl=false", "--rate-limit=false", "s.example.com", htmlDir}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, _ := os.ReadFile(filepath.Join(d.Layout.SitesAvailable, "s.example.com.conf"))
	s := string(b)
	if strings.Contains(s, "limit_req") || strings.Contains(s, "limit_conn") {
		t.Errorf("--rate-limit=false must emit no directives:\n%s", s)
	}
	if !strings.Contains(s, "ratelimit=off") {
		t.Errorf("--rate-limit=false must record ratelimit=off:\n%s", s)
	}
}

// A bare --rate-limit uses the defaults.
func TestRunVhostRateLimitBareDefaults(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	htmlDir := t.TempDir()
	if code := Run([]string{"--ssl=false", "--rate-limit", "s.example.com", htmlDir}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, _ := os.ReadFile(filepath.Join(d.Layout.SitesAvailable, "s.example.com.conf"))
	if !bytes.Contains(b, []byte("rate=50r/s;")) || !bytes.Contains(b, []byte("burst=100 nodelay;")) {
		t.Errorf("bare --rate-limit must use defaults 50r/s burst 100\n%s", b)
	}
}

// A malformed --rate-limit value is rejected before any file is written.
func TestRunVhostRateLimitRejectsBad(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	htmlDir := t.TempDir()
	code := Run([]string{"--ssl=false", "--rate-limit=1r/s; deny all", "s.example.com", htmlDir}, d)
	if code != exitUserError {
		t.Fatalf("bad --rate-limit: exit=%d, want %d", code, exitUserError)
	}
	if !strings.Contains(stderr.String(), "rate-limit:") {
		t.Errorf("stderr missing rate-limit error: %s", stderr)
	}
	if _, err := os.Stat(filepath.Join(d.Layout.SitesAvailable, "s.example.com.conf")); err == nil {
		t.Error("no config file should be written on a rejected --rate-limit")
	}
}

// --rate-limit under --allow=cf is suppressed (the key would be the CF edge IP)
// and a note is printed; the file carries no directives.
func TestRunVhostRateLimitSuppressedUnderCF(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	seedCert(t, d.Layout, "p.example.com")
	if code := Run([]string{"--allow=cf", "--rate-limit=50r/s:100", "p.example.com", "10.0.0.1:8080"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, _ := os.ReadFile(filepath.Join(d.Layout.SitesAvailable, "p.example.com.conf"))
	s := string(b)
	if strings.Contains(s, "limit_req_zone") || strings.Contains(s, "limit_conn") {
		t.Errorf("CF vhost must not emit rate-limit directives:\n%s", s)
	}
	if !strings.Contains(s, "ratelimit=off") {
		t.Errorf("marker must record ratelimit=off under CF:\n%s", s)
	}
	if !strings.Contains(stderr.String(), "ignored with --allow=cf") {
		t.Errorf("stderr missing CF-suppression note: %s", stderr)
	}
}

func TestRunAllowRejectsBadCIDR(t *testing.T) {
	d, _, _, _ := defaultDepsFor(t)
	htmlDir := t.TempDir()
	code := Run([]string{"--ssl=false", "--allow=300.0.0.0/8", "s.example.com", htmlDir}, d)
	if code != exitUserError {
		t.Errorf("expected user-error exit, got %d", code)
	}
}

// ---- 5. nonexistent static path ----

func TestRunStaticPathMissing(t *testing.T) {
	d, _, _, _ := defaultDepsFor(t)
	code := Run([]string{"--ssl=false", "s.example.com", "/this/does/not/exist/anywhere"}, d)
	if code != exitUserError {
		t.Errorf("expected user-error exit, got %d", code)
	}
	if _, err := os.Stat(filepath.Join(d.Layout.SitesAvailable, "s.example.com.conf")); err == nil {
		t.Errorf("file should not have been written")
	}
}

// ---- 6. unmanaged file refuses without --force ----

func TestRunRefusesUnmanagedWithoutForce(t *testing.T) {
	d, _, _, _ := defaultDepsFor(t)
	htmlDir := t.TempDir()
	target := filepath.Join(d.Layout.SitesAvailable, "u.example.com.conf")
	_ = os.MkdirAll(d.Layout.SitesAvailable, 0755)
	_ = os.WriteFile(target, []byte("server { listen 80; }\n"), 0644)

	code := Run([]string{"--ssl=false", "u.example.com", htmlDir}, d)
	if code != exitUserError {
		t.Errorf("expected user-error, got %d", code)
	}
	b, _ := os.ReadFile(target)
	if !strings.Contains(string(b), "server { listen 80; }") {
		t.Errorf("file should have been preserved untouched, got:\n%s", b)
	}
}

func TestRunForceOverwritesUnmanaged(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	htmlDir := t.TempDir()
	target := filepath.Join(d.Layout.SitesAvailable, "u.example.com.conf")
	_ = os.MkdirAll(d.Layout.SitesAvailable, 0755)
	_ = os.WriteFile(target, []byte("server { listen 80; }\n"), 0644)

	code := Run([]string{"--ssl=false", "--force", "u.example.com", htmlDir}, d)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, _ := os.ReadFile(target)
	if !bytes.Contains(b, []byte(marker.FirstLine)) {
		t.Errorf("expected marker after --force overwrite:\n%s", b)
	}
}

// ---- 7. nginx -t failure rolls back ----

func TestRunRollbackOnTestFailure(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	htmlDir := t.TempDir()
	target := filepath.Join(d.Layout.SitesAvailable, "r.example.com.conf")

	// Pre-seed a managed file so we can verify it's restored.
	prior := []byte(marker.RenderVhost(marker.Header{Host: "r.example.com", Mode: "static", Allow: "none", HSTS: "off", TS: fixedNow}) +
		"server { listen 80; server_name r.example.com; root /var/www/old; }\n")
	_ = os.MkdirAll(d.Layout.SitesAvailable, 0755)
	_ = os.WriteFile(target, prior, 0644)

	exec.fail["nginx"] = errors.New("exit 1")
	exec.out["nginx"] = []byte("emerg: bogus\n")

	code := Run([]string{"--ssl=false", "r.example.com", htmlDir}, d)
	if code != exitValidation {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, _ := os.ReadFile(target)
	if !bytes.Equal(b, prior) {
		t.Errorf("file not restored:\nwant: %s\ngot:  %s", prior, b)
	}
	// systemctl reload must NOT have been called
	if exec.called("systemctl") {
		t.Errorf("systemctl should not be called when nginx -t fails")
	}
}

func TestRunRollbackRemovesOnFirstDeployFail(t *testing.T) {
	d, exec, _, _ := defaultDepsFor(t)
	htmlDir := t.TempDir()
	target := filepath.Join(d.Layout.SitesAvailable, "r.example.com.conf")

	exec.fail["nginx"] = errors.New("exit 1")
	exec.out["nginx"] = []byte("emerg: bogus\n")

	code := Run([]string{"--ssl=false", "r.example.com", htmlDir}, d)
	if code != exitValidation {
		t.Fatalf("exit=%d", code)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("first-deploy file should be removed on rollback, stat err=%v", err)
	}
}

// ---- 9. concurrent runs serialize via flock ----

func TestRunSerializesViaFlock(t *testing.T) {
	d, _, _, _ := defaultDepsFor(t)
	htmlDir := t.TempDir()

	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range 2 {
		host := fmt.Sprintf("c%d.example.com", i)
		wg.Go(func() {
			d2 := d
			d2.Stdout = &bytes.Buffer{}
			d2.Stderr = &bytes.Buffer{}
			codes[i] = Run([]string{"--ssl=false", host, htmlDir}, d2)
		})
	}
	wg.Wait()
	for i, c := range codes {
		if c != exitOK {
			t.Errorf("run %d exit=%d", i, c)
		}
	}
	for i := range 2 {
		host := fmt.Sprintf("c%d.example.com", i)
		if _, err := os.Stat(filepath.Join(d.Layout.SitesAvailable, host+".conf")); err != nil {
			t.Errorf("missing file for %s: %v", host, err)
		}
	}
}

// ---- 10. --remove ----

func TestRunRemove(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	htmlDir := t.TempDir()
	if code := Run([]string{"--ssl=false", "x.example.com", htmlDir}, d); code != exitOK {
		t.Fatalf("setup write failed: %d %s", code, stderr)
	}

	target_link := filepath.Join(d.Layout.SitesEnabled, "x.example.com.conf")
	target_file := filepath.Join(d.Layout.SitesAvailable, "x.example.com.conf")

	// reset exec calls
	exec.calls = nil

	if code := Run([]string{"--remove", "x.example.com"}, d); code != exitOK {
		t.Fatalf("remove failed: %d %s", code, stderr)
	}
	if _, err := os.Lstat(target_link); !os.IsNotExist(err) {
		t.Errorf("symlink should be gone: %v", err)
	}
	if _, err := os.Stat(target_file); err != nil {
		t.Errorf("sites-available file should be retained: %v", err)
	}
	if !exec.called("systemctl") {
		t.Errorf("expected systemctl reload after remove")
	}
}

// ---- --list ----

func TestRunListAfterDeploys(t *testing.T) {
	d, _, stdout, stderr := defaultDepsFor(t)
	htmlDir := t.TempDir()

	for _, h := range []string{"a.example.com", "b.example.com"} {
		if code := Run([]string{"--ssl=false", h, htmlDir}, d); code != exitOK {
			t.Fatalf("setup write %s failed: stderr=%s", h, stderr)
		}
	}
	stdout.Reset()
	if code := Run([]string{"--list"}, d); code != exitOK {
		t.Fatal("list failed")
	}
	out := stdout.String()
	for _, h := range []string{"a.example.com", "b.example.com"} {
		if !strings.Contains(out, h) {
			t.Errorf("list missing %s:\n%s", h, out)
		}
	}
}

// ---- --domains ----

func TestRunDomainsProxyAndStatic(t *testing.T) {
	d, _, stdout, stderr := defaultDepsFor(t)
	htmlDir := t.TempDir()

	if code := Run([]string{"--ssl=false", "api.example.com", "10.0.0.1:8080"}, d); code != exitOK {
		t.Fatalf("proxy deploy failed: stderr=%s", stderr)
	}
	if code := Run([]string{"--ssl=false", "static.example.com", htmlDir}, d); code != exitOK {
		t.Fatalf("static deploy failed: stderr=%s", stderr)
	}

	stdout.Reset()
	if code := Run([]string{"--domains"}, d); code != exitOK {
		t.Fatalf("domains failed: stderr=%s", stderr)
	}
	out := stdout.String()
	collapsed := strings.Join(strings.Fields(out), " ")
	for _, want := range []string{
		"api.example.com -> 10.0.0.1:8080",
		"static.example.com -> " + htmlDir,
	} {
		if !strings.Contains(collapsed, want) {
			t.Errorf("domains missing %q:\n%s", want, out)
		}
	}
}

func TestRunDomainsRejectsPositionalArg(t *testing.T) {
	d, _, _, _ := defaultDepsFor(t)
	if code := Run([]string{"--domains", "extra"}, d); code != exitUserError {
		t.Errorf("want exitUserError for positional arg, got %d", code)
	}
}

func TestVhostBackendUnmatched(t *testing.T) {
	if got := vhostBackend("proxy", []byte("no upstream here")); got != "?" {
		t.Errorf("unmatched proxy body: want ?, got %q", got)
	}
	if got := vhostBackend("bogus", []byte("root /var/www/x;")); got != "?" {
		t.Errorf("unknown mode: want ?, got %q", got)
	}
}

// ---- --brotli ----

func TestParseBrotliMode(t *testing.T) {
	tests := []struct {
		in   string
		want BrotliMode
		err  bool
	}{
		{"", BrotliAuto, false},
		{"auto", BrotliAuto, false},
		{"AUTO", BrotliAuto, false},
		{"on", BrotliOn, false},
		{"true", BrotliOn, false},
		{"yes", BrotliOn, false},
		{"1", BrotliOn, false},
		{"off", BrotliOff, false},
		{"false", BrotliOff, false},
		{"no", BrotliOff, false},
		{"0", BrotliOff, false},
		{"maybe", 0, true},
	}
	for _, tc := range tests {
		got, err := parseBrotliMode(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("%q: want error, got nil", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: want %v, got %v", tc.in, tc.want, got)
		}
	}
}

func TestRunMainBrotliOffSkipsApt(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)

	code := Run([]string{"--main", "--brotli=off"}, d)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	for _, c := range exec.calls {
		if c[0] == "apt-get" || c[0] == "apt-cache" || c[0] == "dpkg-query" {
			t.Errorf("--brotli=off must not invoke %s, got calls=%v", c[0], exec.calls)
		}
	}
	b, _ := os.ReadFile(d.Layout.MainConfPath)
	if bytes.Contains(b, []byte("brotli")) {
		t.Errorf("--brotli=off must not emit brotli directives:\n%s", b)
	}
}

func TestRunMainBrotliOnAbortsWhenInstallFails(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	exec.fail["apt-get"] = errors.New("exit 100")
	exec.out["apt-get"] = []byte("E: Unable to locate package\n")

	code := Run([]string{"--main", "--brotli=on"}, d)
	if code != exitUserError {
		t.Fatalf("expected exitUserError, got %d stderr=%s", code, stderr)
	}
	if _, err := os.Stat(d.Layout.MainConfPath); err == nil {
		t.Errorf("--brotli=on failure must not write nginx.conf")
	}
	if !strings.Contains(stderr.String(), "--brotli=on") {
		t.Errorf("expected error message mentioning --brotli=on:\n%s", stderr.String())
	}
}

// Upstream nginx.org's package has no `Provides:` field — dpkg-query
// returns empty. The probe must treat that as conclusive (no ABI match)
// rather than inconclusive, to avoid a guaranteed-failure apt-get install.
func TestEnsureBrotliSkipsAptOnEmptyProvides(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	exec.out["apt-cache"] = []byte("libnginx-mod-http-brotli-filter\n  Depends: nginx-abi-1.26.3-1\n")
	exec.out["dpkg-query"] = []byte("") // succeeded, but no Provides

	if got := ensureBrotli(d); got {
		t.Errorf("empty Provides must short-circuit apt; got true")
	}
	if exec.called("apt-get") {
		t.Errorf("apt-get must not run when probe shows missing ABI, got %v", exec.calls)
	}
	if !strings.Contains(stderr.String(), "nginx-abi-1.26.3-1") {
		t.Errorf("warning should name the missing ABI:\n%s", stderr.String())
	}
}

func TestEnsureBrotliSkipsAptOnABIMismatch(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	exec.out["apt-cache"] = []byte(`libnginx-mod-http-brotli-filter
  Depends: nginx-abi-1.26.3-1
  Depends: libbrotli1
`)
	exec.out["dpkg-query"] = []byte("nginx-abi-1.31.1-1, httpd")

	if got := ensureBrotli(d); got {
		t.Errorf("ensureBrotli should return false on ABI mismatch")
	}
	if exec.called("apt-get") {
		t.Errorf("ABI mismatch must short-circuit before apt-get, got calls=%v", exec.calls)
	}
	if !strings.Contains(stderr.String(), "nginx-abi-1.26.3-1") {
		t.Errorf("warning should name the missing ABI:\n%s", stderr.String())
	}
}

func TestEnsureBrotliFallsThroughWhenProbeInconclusive(t *testing.T) {
	d, exec, _, _ := defaultDepsFor(t)
	// apt-cache fails (e.g. not installed) → probe inconclusive → still attempt install
	exec.fail["apt-cache"] = errors.New("command not found")

	_ = ensureBrotli(d)
	if !exec.called("apt-get") {
		t.Errorf("inconclusive probe should still try apt-get, got calls=%v", exec.calls)
	}
}

// Authoritative signal: if nginx.org's apt repo file is present on disk,
// Debian's pre-built brotli packages are ABI-incompatible by construction.
// ensureBrotli must skip the apt round-trip entirely — no apt-cache, no
// dpkg-query, no apt-get — and warn loudly enough that the operator knows
// to expect a from-source build via --install/--convert/--bootstrap.
func TestEnsureBrotliSkipsAptWhenNginxOrgRepoConfigured(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	if err := os.WriteFile(nginxOrgSourcesList,
		[]byte("deb [signed-by=...] https://nginx.org/packages/mainline/debian trixie nginx\n"),
		0644); err != nil {
		t.Fatal(err)
	}

	if got := ensureBrotli(d); got {
		t.Errorf("ensureBrotli must return false when nginx.org repo is configured; got true")
	}
	for _, c := range exec.calls {
		switch c[0] {
		case "apt-get", "apt-cache", "dpkg-query":
			t.Errorf("nginx.org repo signal must short-circuit before %s, got calls=%v", c[0], exec.calls)
		}
	}
	if !strings.Contains(stderr.String(), "nginx.org apt repo is configured") {
		t.Errorf("warning should name the nginx.org repo signal:\n%s", stderr.String())
	}
}

// Inconclusive-probe paths must each emit a single diagnostic line naming
// which probe was inconclusive, so a failed apt install logged in stderr
// can be retroactively explained without re-running on the failed host.
func TestEnsureBrotliDiagnosesInconclusiveProbe(t *testing.T) {
	t.Run("apt-cache failed", func(t *testing.T) {
		d, exec, _, stderr := defaultDepsFor(t)
		exec.fail["apt-cache"] = errors.New("command not found")
		_ = ensureBrotli(d)
		if !strings.Contains(stderr.String(), "apt-cache depends returned no nginx-abi dependency") {
			t.Errorf("expected diagnostic for apt-cache failure:\n%s", stderr.String())
		}
	})
	t.Run("dpkg-query failed", func(t *testing.T) {
		d, exec, _, stderr := defaultDepsFor(t)
		exec.out["apt-cache"] = []byte("libnginx-mod-http-brotli-filter\n  Depends: nginx-abi-1.26.3-1\n")
		exec.fail["dpkg-query"] = errors.New("exit 1")
		_ = ensureBrotli(d)
		if !strings.Contains(stderr.String(), "dpkg-query for installed nginx failed") {
			t.Errorf("expected diagnostic for dpkg-query failure:\n%s", stderr.String())
		}
	})
}

// On a host where apt+Debian-brotli would silently fail in BrotliAuto mode,
// runMain (called inside runInstall) returns OK with a brotli-less render.
// Verifies that the new file-stat probe flips BrotliAuto from "render
// without brotli" to a warning-only path that's safe to chain a build off.
func TestRunMainBrotliAutoSkipsAptWhenNginxOrgRepoConfigured(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	if err := os.WriteFile(nginxOrgSourcesList, []byte("deb ...\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if code := Run([]string{"--main", "--brotli=auto"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	for _, c := range exec.calls {
		if c[0] == "apt-get" || c[0] == "apt-cache" || c[0] == "dpkg-query" {
			t.Errorf("--brotli=auto with nginx.org repo configured must not invoke %s, got %v", c[0], exec.calls)
		}
	}
	b, _ := os.ReadFile(d.Layout.MainConfPath)
	if bytes.Contains(b, []byte("brotli            on;")) {
		t.Errorf("rendered conf must not enable brotli when nginx.org repo blocks Debian packages:\n%s", b)
	}
}

// ---- chainBrotliBuildIfNeeded ----

// Helper: seed enough on-disk state for runMain (invoked by the chain when
// the module is loaded) to succeed. Tests assert against this after the
// chain runs.
func seedForChainTest(t *testing.T, d Deps) {
	t.Helper()
	for _, dir := range []string{
		d.Layout.ModulesEnabledDir,
		filepath.Dir(d.Layout.MainConfPath),
		filepath.Dir(d.Layout.LockPath),
		d.Layout.BackupDir,
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainBrotliBuildIfNeededOffIsNoOp(t *testing.T) {
	d, _, _, _ := defaultDepsFor(t)
	seedForChainTest(t, d)
	called := false
	build := func(_ Deps, _, _ bool) int { called = true; return exitOK }

	if code := chainBrotliBuildIfNeeded(d, BrotliOff, false, build); code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if called {
		t.Errorf("BrotliOff must not invoke build")
	}
	if _, err := os.Stat(d.Layout.MainConfPath); err == nil {
		t.Errorf("BrotliOff must not render nginx.conf via chain")
	}
}

func TestChainBrotliBuildIfNeededAutoSkipsBuildWhenLoaded(t *testing.T) {
	d, _, _, _ := defaultDepsFor(t)
	seedForChainTest(t, d)
	// Module pre-loaded (e.g. user is rerunning --install on a host that
	// already has brotli compiled from a prior run).
	if err := os.WriteFile(
		filepath.Join(d.Layout.ModulesEnabledDir, brotliLoadConf),
		[]byte("load_module modules/ngx_http_brotli_filter_module.so;\n"), 0644,
	); err != nil {
		t.Fatal(err)
	}
	called := false
	build := func(_ Deps, _, _ bool) int { called = true; return exitOK }

	if code := chainBrotliBuildIfNeeded(d, BrotliAuto, false, build); code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if called {
		t.Errorf("already-loaded short-circuit must skip build")
	}
	// Re-render must have run so the loaded module is referenced in
	// nginx.conf (covers the first-pass-was-BrotliOff scenario).
	b, _ := os.ReadFile(d.Layout.MainConfPath)
	if !bytes.Contains(b, []byte("brotli            on;")) {
		t.Errorf("re-render must enable brotli when module is loaded:\n%s", b)
	}
}

func TestChainBrotliBuildIfNeededAutoBuildsThenRenders(t *testing.T) {
	d, _, _, _ := defaultDepsFor(t)
	seedForChainTest(t, d)
	// Fake build: writes the load_module conf, simulating a successful
	// from-source compile. The chain must detect the new module and
	// re-render nginx.conf with brotli enabled.
	build := func(d Deps, _, _ bool) int {
		err := os.WriteFile(
			filepath.Join(d.Layout.ModulesEnabledDir, brotliLoadConf),
			[]byte("load_module modules/ngx_http_brotli_filter_module.so;\n"),
			0644,
		)
		if err != nil {
			t.Fatal(err)
		}
		return exitOK
	}

	if code := chainBrotliBuildIfNeeded(d, BrotliAuto, false, build); code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	b, _ := os.ReadFile(d.Layout.MainConfPath)
	if !bytes.Contains(b, []byte("brotli            on;")) {
		t.Errorf("auto+build-success must render brotli directives:\n%s", b)
	}
}

func TestChainBrotliBuildIfNeededAutoSoftFailsOnBuildErr(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	seedForChainTest(t, d)
	build := func(_ Deps, _, _ bool) int { return exitSystemErr }

	if code := chainBrotliBuildIfNeeded(d, BrotliAuto, false, build); code != exitOK {
		t.Fatalf("BrotliAuto must soft-fail on build error, got exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "brotli-build failed") {
		t.Errorf("expected warning naming brotli-build failure:\n%s", stderr.String())
	}
	// Module never appeared → no re-render → no nginx.conf written.
	if _, err := os.Stat(d.Layout.MainConfPath); err == nil {
		t.Errorf("soft-fail must leave first-pass render intact; chain must not write nginx.conf")
	}
}

func TestChainBrotliBuildIfNeededOnHardFailsOnBuildErr(t *testing.T) {
	d, _, _, _ := defaultDepsFor(t)
	seedForChainTest(t, d)
	build := func(_ Deps, _, _ bool) int { return exitSystemErr }

	if code := chainBrotliBuildIfNeeded(d, BrotliOn, false, build); code == exitOK {
		t.Errorf("BrotliOn must hard-fail on build error, got exit=%d", code)
	}
}

// ---- --convert ----

func TestRunConvertDryRunPrintsRecipe(t *testing.T) {
	d, exec, stdout, stderr := defaultDepsFor(t)
	if code := Run([]string{"--convert", "--dry-run"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"cp -a /etc/nginx",
		"rollback.sh",
		"--install",
		"--sysctl",
		"sites-enabled/ are NOT rewritten",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("dry-run missing %q:\n%s", want, stdout.String())
		}
	}
	if exec.called("cp") || exec.called("apt-get") {
		t.Errorf("dry-run must not exec, got %v", exec.calls)
	}
}

func TestRunConvertRejectsBadBrotli(t *testing.T) {
	d, _, _, _ := defaultDepsFor(t)
	if code := Run([]string{"--convert", "--brotli=yes-please"}, d); code != exitUserError {
		t.Errorf("want exitUserError, got %d", code)
	}
}

func TestRunConvertRejectsBadChannel(t *testing.T) {
	d, _, _, _ := defaultDepsFor(t)
	if code := Run([]string{"--convert", "--channel=edge"}, d); code != exitUserError {
		t.Errorf("want exitUserError, got %d", code)
	}
}

// Rollback script must be syntactically valid bash and reference the
// snapshot path it was written for. Smoke-test by parsing with `bash -n`.
func TestWriteRollbackScriptValid(t *testing.T) {
	dir := t.TempDir()
	rollback := filepath.Join(dir, "rollback.sh")
	if err := writeRollbackScript(rollback, "/var/backups/nginx-gen/convert/20260526T120000Z", "1.26.3-3+deb13u5"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(rollback)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"/var/backups/nginx-gen/convert/20260526T120000Z",
		// PREV_PKG must hold the BARE version. The leading `=` is hard-coded
		// into the apt command — passing a pre-equalsed value produces
		// `nginx==1.2.3`, which apt parses as package name `nginx=` and
		// errors with "Unable to locate package nginx=".
		`PREV_PKG="1.26.3-3+deb13u5"`,
		`apt-get install -y --allow-downgrades --reinstall "nginx=$PREV_PKG"`,
		"systemctl stop nginx",
		"rm -f /etc/apt/sources.list.d/nginx.list",
		"rm -f /etc/apt/preferences.d/99nginx",
		"nginx -t",
		"systemctl start nginx",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("rollback script missing %q\n--- script ---\n%s", want, data)
		}
	}
	// Belt-and-suspenders: forbid the double-equals form anywhere.
	if bytes.Contains(data, []byte(`nginx==`)) {
		t.Errorf("script contains forbidden 'nginx==' (double-equals bug):\n%s", data)
	}
	if bytes.Contains(data, []byte(`PREV_PKG="=`)) {
		t.Errorf("PREV_PKG must hold bare version, no leading `=`:\n%s", data)
	}
	info, _ := os.Stat(rollback)
	if info.Mode().Perm()&0100 == 0 {
		t.Errorf("rollback script not executable: mode=%v", info.Mode())
	}
}

func TestWriteRollbackScriptUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	rollback := filepath.Join(dir, "rollback.sh")
	if err := writeRollbackScript(rollback, "/snap", ""); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(rollback)
	// PREV_PKG must be the empty string — the script's runtime branch then
	// uses the unpinned `apt-get install -y --reinstall nginx` form.
	if !bytes.Contains(data, []byte(`PREV_PKG=""`)) {
		t.Errorf("empty prevPkgVer must produce PREV_PKG=\"\":\n%s", data)
	}
	if !bytes.Contains(data, []byte("nginx-gen --convert")) {
		t.Errorf("script header missing:\n%s", data)
	}
}

// ---- --upgrade / --abi-check ----

func TestRunUpgradeDryRunPrintsRecipe(t *testing.T) {
	d, exec, stdout, stderr := defaultDepsFor(t)
	if code := Run([]string{"--upgrade", "--dry-run"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"apt-get install --only-upgrade -y nginx",
		"--brotli-build --force",
		"nginx-gen --main",
		"systemctl restart nginx",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("dry-run missing %q:\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "render /etc/nginx/nginx.conf") {
		t.Errorf("dry-run must not promise a nginx.conf render:\n%s", stdout.String())
	}
	if exec.called("apt-get") {
		t.Errorf("dry-run must not exec, got %v", exec.calls)
	}
}

func TestBrotliBuildVersionParses(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, brotliLoadConf)
	if err := os.WriteFile(conf,
		[]byte("# Managed by nginx-gen; built against nginx 1.31.1\nload_module x;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := brotliBuildVersion(dir); got != "1.31.1" {
		t.Errorf("want 1.31.1, got %q", got)
	}
}

func TestBrotliBuildVersionEmptyOnMissing(t *testing.T) {
	if got := brotliBuildVersion(t.TempDir()); got != "" {
		t.Errorf("missing conf must return empty, got %q", got)
	}
}

func TestBrotliBuildVersionEmptyOnHandWritten(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, brotliLoadConf)
	if err := os.WriteFile(conf,
		[]byte("load_module modules/brotli.so;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := brotliBuildVersion(dir); got != "" {
		t.Errorf("hand-written conf must return empty, got %q", got)
	}
}

func TestRunVersionCheckNoBrotli(t *testing.T) {
	d, exec, stdout, _ := defaultDepsFor(t)
	exec.out["nginx"] = []byte("nginx version: nginx/1.31.1\n")
	if code := Run([]string{"--abi-check"}, d); code != exitOK {
		t.Fatalf("exit=%d stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout.String(), "nginx: 1.31.1") {
		t.Errorf("missing nginx line:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "brotli: not installed") {
		t.Errorf("missing 'not installed' line:\n%s", stdout.String())
	}
}

func TestRunVersionCheckInSync(t *testing.T) {
	d, exec, stdout, _ := defaultDepsFor(t)
	exec.out["nginx"] = []byte("nginx version: nginx/1.31.1\n")
	if err := os.MkdirAll(d.Layout.ModulesEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(d.Layout.ModulesEnabledDir, brotliLoadConf)
	if err := os.WriteFile(conf,
		[]byte("# Managed by nginx-gen; built against nginx 1.31.1\nload_module x;\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if code := Run([]string{"--abi-check"}, d); code != exitOK {
		t.Fatalf("expected exitOK, got %d stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout.String(), "(in sync)") {
		t.Errorf("expected 'in sync':\n%s", stdout.String())
	}
}

func TestRunVersionCheckDrift(t *testing.T) {
	d, exec, stdout, _ := defaultDepsFor(t)
	exec.out["nginx"] = []byte("nginx version: nginx/1.31.2\n")
	if err := os.MkdirAll(d.Layout.ModulesEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(d.Layout.ModulesEnabledDir, brotliLoadConf)
	if err := os.WriteFile(conf,
		[]byte("# Managed by nginx-gen; built against nginx 1.31.1\nload_module x;\n"), 0644); err != nil {
		t.Fatal(err)
	}

	code := Run([]string{"--abi-check"}, d)
	if code != exitUserError {
		t.Fatalf("expected exit 1 on drift, got %d stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout.String(), "DRIFT") {
		t.Errorf("expected DRIFT in output:\n%s", stdout.String())
	}
}

// ---- --bootstrap ----

func TestRunBootstrapDryRunShowsBothSteps(t *testing.T) {
	d, exec, stdout, stderr := defaultDepsFor(t)

	code := Run([]string{"--bootstrap", "--dry-run"}, d)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if exec.called("apt-get") || exec.called("systemctl") {
		t.Errorf("dry-run must not exec, got %v", exec.calls)
	}
	// Step 1 markers (install recipe)
	for _, want := range []string{
		"nginx.org channel=mainline",
		"apt-get install -y nginx",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing install recipe %q in stdout:\n%s", want, stdout.String())
		}
	}
	// Step 2 markers (sysctl recipe goes to stdout via runSysctl --dry-run)
	for _, want := range []string{
		"99-nginx.conf",
		"tcp_congestion_control = bbr",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing sysctl recipe %q in stdout:\n%s", want, stdout.String())
		}
	}
	// Step delimiters go to stderr
	for _, want := range []string{"step 1/2", "step 2/2"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("missing step marker %q in stderr:\n%s", want, stderr.String())
		}
	}
}

func TestRunBootstrapRejectsBadBrotli(t *testing.T) {
	d, _, _, _ := defaultDepsFor(t)
	if code := Run([]string{"--bootstrap", "--brotli=enabled"}, d); code != exitUserError {
		t.Errorf("want exitUserError, got %d", code)
	}
}

// Regression guard: --main --brotli=on with the module already loaded must
// emit brotli directives. The previous runInstall bug was that the second
// runMain (which emits the directives) was skipped when brotli-build was
// skipped — leaving the module loaded but inert. The actual emission lives
// in resolveBrotli + render.Main; cover it at that layer since runInstall
// requires root.
func TestRunMainWithBrotliOnAndModuleAlreadyLoadedEmitsDirectives(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	if err := os.MkdirAll(d.Layout.ModulesEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(d.Layout.ModulesEnabledDir, "50-mod-http-brotli.conf")
	if err := os.WriteFile(conf, []byte("load_module x;\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if code := Run([]string{"--main", "--brotli=on"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, err := os.ReadFile(d.Layout.MainConfPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("brotli            on;")) {
		t.Errorf("expected brotli directives when module loaded + --brotli=on, got:\n%s", b)
	}
}

// ---- --install ----

func TestParseChannel(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want nginxChannel
		err  bool
	}{
		{"", channelMainline, false},
		{"mainline", channelMainline, false},
		{"MAINLINE", channelMainline, false},
		{"stable", channelStable, false},
		{"edge", "", true},
	} {
		got, err := parseChannel(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("%q: want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected err: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: want %q got %q", tc.in, tc.want, got)
		}
	}
}

func TestChannelAptURL(t *testing.T) {
	if got := channelMainline.aptURL(); !strings.Contains(got, "/mainline/debian") {
		t.Errorf("mainline URL missing /mainline/debian: %s", got)
	}
	if got := channelStable.aptURL(); strings.Contains(got, "mainline") {
		t.Errorf("stable URL must not contain 'mainline': %s", got)
	}
}

func TestRunInstallDryRunPrintsRecipe(t *testing.T) {
	d, exec, stdout, stderr := defaultDepsFor(t)

	code := Run([]string{"--install", "--dry-run"}, d)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	out := stdout.String()
	for _, want := range []string{
		"nginx.org channel=mainline",
		"nginx_signing.key",
		"apt-get install -y nginx",
		"render /etc/nginx/nginx.conf",
		"systemctl",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run missing %q:\n%s", want, out)
		}
	}
	if exec.called("apt-get") || exec.called("curl") || exec.called("systemctl") {
		t.Errorf("dry-run must not exec anything, got %v", exec.calls)
	}
}

func TestRunInstallStableChannel(t *testing.T) {
	d, _, stdout, _ := defaultDepsFor(t)
	if code := Run([]string{"--install", "--channel=stable", "--dry-run"}, d); code != exitOK {
		t.Fatal(code)
	}
	if !strings.Contains(stdout.String(), "channel=stable") {
		t.Errorf("expected channel=stable in recipe:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "/mainline/debian") {
		t.Errorf("stable channel must not reference mainline URL:\n%s", stdout.String())
	}
}

func TestRunInstallRejectsBadChannel(t *testing.T) {
	d, _, _, _ := defaultDepsFor(t)
	if code := Run([]string{"--install", "--channel=nightly"}, d); code != exitUserError {
		t.Errorf("expected exitUserError for bad channel, got %d", code)
	}
}

// ---- --brotli-build ----

func TestRunBrotliBuildDryRunPrintsRecipe(t *testing.T) {
	d, exec, stdout, stderr := defaultDepsFor(t)
	d.NginxVersion = func() (nginx.VersionInfo, error) {
		return nginx.VersionInfo{Major: 1, Minor: 31, Patch: 1}, nil
	}

	code := Run([]string{"--brotli-build", "--dry-run"}, d)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	out := stdout.String()
	for _, want := range []string{
		"nginx 1.31.1",
		"apt-get install",
		"nginx-1.31.1.tar.gz",
		"--with-compat",
		"--add-dynamic-module=../ngx_brotli",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q:\n%s", want, out)
		}
	}
	if exec.called("apt-get") || exec.called("curl") {
		t.Errorf("dry-run must not exec anything, got %v", exec.calls)
	}
}

func TestRunBrotliBuildSkipsIfAlreadyLoaded(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	d.NginxVersion = func() (nginx.VersionInfo, error) {
		return nginx.VersionInfo{Major: 1, Minor: 31, Patch: 1}, nil
	}
	if err := os.MkdirAll(d.Layout.ModulesEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(d.Layout.ModulesEnabledDir, "50-mod-http-brotli.conf")
	if err := os.WriteFile(conf, []byte("load_module modules/x.so;\n"), 0644); err != nil {
		t.Fatal(err)
	}

	code := Run([]string{"--brotli-build"}, d)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if exec.called("apt-get") || exec.called("curl") || exec.called("git") || exec.called("make") {
		t.Errorf("already-loaded short-circuit must skip build, got calls=%v", exec.calls)
	}
	if !strings.Contains(stderr.String(), "already loaded") {
		t.Errorf("expected 'already loaded' notice:\n%s", stderr.String())
	}
}

func TestRunBrotliBuildForceProceedsEvenIfLoaded(t *testing.T) {
	d, exec, _, _ := defaultDepsFor(t)
	d.NginxVersion = func() (nginx.VersionInfo, error) {
		return nginx.VersionInfo{Major: 1, Minor: 31, Patch: 1}, nil
	}
	if err := os.MkdirAll(d.Layout.ModulesEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(d.Layout.ModulesEnabledDir, "brotli.conf"), []byte("x"), 0644)

	// Build will fail at the "read built module" step because fakeExec
	// doesn't produce real .so files. We only assert that --force bypassed
	// the early-return guard and reached the apt install step.
	_ = Run([]string{"--brotli-build", "--force"}, d)
	if !exec.called("apt-get") {
		t.Errorf("--force must proceed past early-return, got %v", exec.calls)
	}
}

func TestRunBrotliBuildAptInstallFailureExits(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	d.NginxVersion = func() (nginx.VersionInfo, error) {
		return nginx.VersionInfo{Major: 1, Minor: 31, Patch: 1}, nil
	}
	exec.fail["apt-get"] = errors.New("exit 100")
	exec.out["apt-get"] = []byte("E: failed to install build-essential\n")

	code := Run([]string{"--brotli-build"}, d)
	if code != exitSystemErr {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if exec.called("curl") {
		t.Errorf("apt-get failure must short-circuit before download, got %v", exec.calls)
	}
}

// ---- --dry-run ----

func TestRunDryRunNoFSChange(t *testing.T) {
	d, exec, stdout, _ := defaultDepsFor(t)
	htmlDir := t.TempDir()
	code := Run([]string{"--ssl=false", "--dry-run", "d.example.com", htmlDir}, d)
	if code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stdout.String(), "server {") {
		t.Errorf("dry-run should print rendered config to stdout")
	}
	if _, err := os.Stat(filepath.Join(d.Layout.SitesAvailable, "d.example.com.conf")); err == nil {
		t.Errorf("dry-run should not write to FS")
	}
	if exec.called("nginx") || exec.called("systemctl") {
		t.Errorf("dry-run should not exec nginx/systemctl")
	}
}

// ---- HSTS ----

func TestHSTSRequiresSSL(t *testing.T) {
	// Browsers ignore HSTS over plain HTTP (RFC 6797 §8.1). Silently honoring
	// this combination would emit a config that reads as hardened but isn't,
	// so it must fail closed with a user error.
	for _, val := range []string{"on", "subdomains", "preload"} {
		d, _, _, stderr := defaultDepsFor(t)
		htmlDir := t.TempDir()
		code := Run([]string{"--ssl=false", "--hsts=" + val, "h.example.com", htmlDir}, d)
		if code != exitUserError {
			t.Errorf("--hsts=%s --ssl=false: exit=%d, want %d", val, code, exitUserError)
		}
		if !strings.Contains(stderr.String(), "requires --ssl") {
			t.Errorf("--hsts=%s: stderr missing explanation: %s", val, stderr)
		}
	}
	// off is the default and must remain compatible with --ssl=false.
	d, _, _, stderr := defaultDepsFor(t)
	htmlDir := t.TempDir()
	if code := Run([]string{"--ssl=false", "--hsts=off", "h.example.com", htmlDir}, d); code != exitOK {
		t.Errorf("--hsts=off --ssl=false: exit=%d stderr=%s", code, stderr)
	}
}

func TestHSTSInvalidValueRejected(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	seedCert(t, d.Layout, "h.example.com")
	code := Run([]string{"--hsts=true", "h.example.com", "10.0.0.1:8080"}, d)
	if code != exitUserError {
		t.Fatalf("exit=%d, want %d (stderr=%s)", code, exitUserError, stderr)
	}
	if !strings.Contains(stderr.String(), "invalid --hsts value") {
		t.Errorf("stderr missing explanation: %s", stderr)
	}
	// Must not have written anything.
	if _, err := os.Stat(filepath.Join(d.Layout.SitesAvailable, "h.example.com.conf")); err == nil {
		t.Error("rejected --hsts wrote a config anyway")
	}
}

func TestHSTSDefaultIsOff(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	seedCert(t, d.Layout, "h.example.com")
	if code := Run([]string{"h.example.com", "10.0.0.1:8080"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, err := os.ReadFile(filepath.Join(d.Layout.SitesAvailable, "h.example.com.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("Strict-Transport-Security")) {
		t.Errorf("default must not emit HSTS:\n%s", b)
	}
	if !bytes.Contains(b, []byte("hsts=off")) {
		t.Errorf("marker missing hsts=off:\n%s", b)
	}
}

func TestHSTSDowngradeWarns(t *testing.T) {
	cases := []struct {
		name     string
		first    []string // args for the first write
		second   []string // args for the re-render
		wantWarn bool
		wantWas  string
	}{
		{"subdomains -> off", []string{"--hsts=subdomains"}, nil, true, "subdomains"},
		{"preload -> on", []string{"--hsts=preload"}, []string{"--hsts=on"}, true, "preload"},
		{"on -> on", []string{"--hsts=on"}, []string{"--hsts=on"}, false, ""},
		{"off -> subdomains", nil, []string{"--hsts=subdomains"}, false, ""},
		{"on -> subdomains", []string{"--hsts=on"}, []string{"--hsts=subdomains"}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _, _, stderr := defaultDepsFor(t)
			seedCert(t, d.Layout, "h.example.com")
			if code := Run(append(c.first, "h.example.com", "10.0.0.1:8080"), d); code != exitOK {
				t.Fatalf("first write: exit=%d stderr=%s", code, stderr)
			}
			stderr.Reset()
			if code := Run(append(c.second, "h.example.com", "10.0.0.1:8080"), d); code != exitOK {
				t.Fatalf("re-render: exit=%d stderr=%s", code, stderr)
			}
			got := strings.Contains(stderr.String(), "previously sent HSTS")
			if got != c.wantWarn {
				t.Errorf("warn=%v want=%v, stderr=%s", got, c.wantWarn, stderr)
			}
			if c.wantWarn && !strings.Contains(stderr.String(), c.wantWas) {
				t.Errorf("warning missing prior policy %q: %s", c.wantWas, stderr)
			}
		})
	}
}

// A config written before --hsts existed has no hsts= field but always served
// includeSubDomains when ssl=true. Re-rendering it without --hsts silently
// stops sending that header, so the warning has to fire on the inferred value.
func TestHSTSDowngradeWarnsForPreFlagMarker(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	seedCert(t, d.Layout, "h.example.com")
	target := filepath.Join(d.Layout.SitesAvailable, "h.example.com.conf")
	if err := os.MkdirAll(d.Layout.SitesAvailable, 0755); err != nil {
		t.Fatal(err)
	}
	legacy := "# Managed by nginx-gen. Do not edit by hand.\n" +
		"# kind=vhost host=h.example.com mode=proxy ssl=true allow=none ts=2026-05-03T12:00:00Z\n" +
		"server { listen 443 ssl; }\n"
	if err := os.WriteFile(target, []byte(legacy), 0644); err != nil {
		t.Fatal(err)
	}

	if code := Run([]string{"h.example.com", "10.0.0.1:8080"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "previously sent HSTS (subdomains)") {
		t.Errorf("pre-flag marker should infer subdomains: %s", stderr)
	}
}

func TestListShowsHSTS(t *testing.T) {
	d, _, stdout, stderr := defaultDepsFor(t)
	seedCert(t, d.Layout, "h.example.com")
	if code := Run([]string{"--hsts=subdomains", "h.example.com", "10.0.0.1:8080"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	stdout.Reset()
	if code := Run([]string{"--list"}, d); code != exitOK {
		t.Fatalf("list exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout.String(), "hsts=subdomains") {
		t.Errorf("--list missing hsts column: %s", stdout)
	}
}

func TestRunMainCatchAllByNginxVersion(t *testing.T) {
	cases := []struct {
		name    string
		version func() (nginx.VersionInfo, error)
		reject  bool
		warn    bool
	}{
		{"old", func() (nginx.VersionInfo, error) { return nginx.VersionInfo{Major: 1, Minor: 18}, nil }, false, true},
		{"new", func() (nginx.VersionInfo, error) { return nginx.VersionInfo{Major: 1, Minor: 30, Patch: 5}, nil }, true, false},
		{"unknown", func() (nginx.VersionInfo, error) { return nginx.VersionInfo{}, errors.New("no nginx") }, true, false},
	}
	for _, c := range cases {
		d, _, _, stderr := defaultDepsFor(t)
		d.NginxVersion = c.version
		if code := Run([]string{"--main"}, d); code != exitOK {
			t.Fatalf("%s: exit=%d stderr=%s", c.name, code, stderr)
		}
		b, err := os.ReadFile(d.Layout.MainConfPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(b, []byte("listen 80 default_server;")) {
			t.Errorf("%s: :80 catch-all missing", c.name)
		}
		if got := bytes.Contains(b, []byte("ssl_reject_handshake on;")); got != c.reject {
			t.Errorf("%s: ssl_reject_handshake present=%v, want %v", c.name, got, c.reject)
		}
		if got := strings.Contains(stderr.String(), "has no ssl_reject_handshake"); got != c.warn {
			t.Errorf("%s: warning present=%v, want %v; stderr=%s", c.name, got, c.warn, stderr)
		}
	}
}

func TestRunVhostCertFromSecondBase(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	dir := filepath.Join(d.Layout.CertDirs[1], "example.com")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"example.com.crt", "example.com.key"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if code := Run([]string{"c.example.com", "10.0.0.1:8080"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, err := os.ReadFile(filepath.Join(d.Layout.SitesAvailable, "c.example.com.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ssl_certificate     " + filepath.Join(dir, "example.com.crt") + ";",
		"ssl_certificate_key " + filepath.Join(dir, "example.com.key") + ";",
	} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("vhost missing %q\n%s", want, b)
		}
	}
}

func TestRunCertDirFlagReplacesDefaultBases(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	seedCert(t, d.Layout, "f.example.com")
	override := t.TempDir()
	if code := Run([]string{"--cert-dir=" + override, "f.example.com", "10.0.0.1:8080"}, d); code != exitUserError {
		t.Fatalf("--cert-dir must be the only base: exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), override) {
		t.Errorf("error should name the --cert-dir base: %s", stderr)
	}
}

func TestDefaultCertDirs(t *testing.T) {
	t.Setenv("NGINX_CERT_DIR", "")
	got := defaultCertDirs()
	want := []string{"/etc/letsencrypt/live", "/etc/nginx/ssl"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("default bases = %v, want %v", got, want)
	}
	t.Setenv("NGINX_CERT_DIR", "/srv/certs")
	if got := defaultCertDirs(); len(got) != 1 || got[0] != "/srv/certs" {
		t.Errorf("$NGINX_CERT_DIR must be the only base, got %v", got)
	}
}

func advancingClock(d *Deps) {
	ticks := 0
	d.Now = func() time.Time {
		ticks++
		return fixedNow.Add(time.Duration(ticks) * time.Minute)
	}
}

func backupEntries(t *testing.T, d Deps) []string {
	t.Helper()
	entries, err := os.ReadDir(d.Layout.BackupDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func statFile(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRunMainTwiceSameInputSkipsBackupAndWrite(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	advancingClock(&d)

	if code := Run([]string{"--main"}, d); code != exitOK {
		t.Fatalf("run 1 exit=%d stderr=%s", code, stderr)
	}
	before := statFile(t, d.Layout.MainConfPath)
	stderr.Reset()

	if code := Run([]string{"--main"}, d); code != exitOK {
		t.Fatalf("run 2 exit=%d stderr=%s", code, stderr)
	}
	if got := backupEntries(t, d); len(got) != 0 {
		t.Errorf("run 2 made backups: %v", got)
	}
	if !strings.Contains(stderr.String(), "unchanged: "+d.Layout.MainConfPath) {
		t.Errorf("stderr missing unchanged line:\n%s", stderr)
	}
	if !os.SameFile(before, statFile(t, d.Layout.MainConfPath)) {
		t.Error("run 2 rewrote nginx.conf")
	}
}

func TestRunMainChangedInputBacksUpOldBytes(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	advancingClock(&d)
	if code := Run([]string{"--main", "--brotli=off"}, d); code != exitOK {
		t.Fatalf("run 1 exit=%d stderr=%s", code, stderr)
	}
	old := readFile(t, d.Layout.MainConfPath)
	if err := os.MkdirAll(d.Layout.ModulesEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	loadConf := filepath.Join(d.Layout.ModulesEnabledDir, brotliLoadConf)
	if err := os.WriteFile(loadConf, []byte("load_module x;\n"), 0644); err != nil {
		t.Fatal(err)
	}

	d.Now = func() time.Time { return fixedNow.Add(time.Hour) }

	if code := Run([]string{"--main", "--brotli=on"}, d); code != exitOK {
		t.Fatalf("run 2 exit=%d stderr=%s", code, stderr)
	}
	got := backupEntries(t, d)
	if len(got) != 1 {
		t.Fatalf("backups: %v", got)
	}
	if !strings.Contains(got[0], "20260503T130000Z") {
		t.Errorf("backup name %q lacks the stamp of d.Now()", got[0])
	}
	if !bytes.Equal(readFile(t, filepath.Join(d.Layout.BackupDir, got[0])), old) {
		t.Error("backup does not hold the old bytes")
	}
}

func TestRunVhostTwiceSameInputSkipsBackupAndWrite(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	advancingClock(&d)
	htmlDir := t.TempDir()
	target := filepath.Join(d.Layout.SitesAvailable, "u.example.com.conf")

	if code := Run([]string{"--ssl=false", "u.example.com", htmlDir}, d); code != exitOK {
		t.Fatalf("run 1 exit=%d stderr=%s", code, stderr)
	}
	before := statFile(t, target)
	stderr.Reset()

	if code := Run([]string{"--ssl=false", "u.example.com", htmlDir}, d); code != exitOK {
		t.Fatalf("run 2 exit=%d stderr=%s", code, stderr)
	}
	if got := backupEntries(t, d); len(got) != 0 {
		t.Errorf("run 2 made backups: %v", got)
	}
	if !strings.Contains(stderr.String(), "unchanged: "+target) {
		t.Errorf("stderr missing unchanged line:\n%s", stderr)
	}
	if !os.SameFile(before, statFile(t, target)) {
		t.Error("run 2 rewrote the vhost")
	}
}

func TestRunVhostChangedInputBacksUpOldBytes(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	advancingClock(&d)
	target := filepath.Join(d.Layout.SitesAvailable, "u.example.com.conf")

	if code := Run([]string{"--ssl=false", "u.example.com", t.TempDir()}, d); code != exitOK {
		t.Fatalf("run 1 exit=%d stderr=%s", code, stderr)
	}
	old := readFile(t, target)

	if code := Run([]string{"--ssl=false", "u.example.com", t.TempDir()}, d); code != exitOK {
		t.Fatalf("run 2 exit=%d stderr=%s", code, stderr)
	}
	got := backupEntries(t, d)
	if len(got) != 1 {
		t.Fatalf("backups: %v", got)
	}
	if !bytes.Equal(readFile(t, filepath.Join(d.Layout.BackupDir, got[0])), old) {
		t.Error("backup does not hold the old bytes")
	}
	if bytes.Equal(readFile(t, target), old) {
		t.Error("vhost was not rewritten")
	}
}

func TestRunVhostUnchangedKeptWhenNginxTestFails(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	advancingClock(&d)
	htmlDir := t.TempDir()
	target := filepath.Join(d.Layout.SitesAvailable, "u.example.com.conf")

	if code := Run([]string{"--ssl=false", "u.example.com", htmlDir}, d); code != exitOK {
		t.Fatalf("run 1 exit=%d stderr=%s", code, stderr)
	}
	want := readFile(t, target)
	exec.fail["nginx"] = errors.New("exit 1")

	if code := Run([]string{"--ssl=false", "u.example.com", htmlDir}, d); code != exitValidation {
		t.Fatalf("run 2 exit=%d stderr=%s", code, stderr)
	}
	if got := readFile(t, target); !bytes.Equal(got, want) {
		t.Errorf("vhost changed after failed nginx -t:\n%s", got)
	}
}

func TestRunMainUnchangedKeptWhenNginxTestFails(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	advancingClock(&d)

	if code := Run([]string{"--main"}, d); code != exitOK {
		t.Fatalf("run 1 exit=%d stderr=%s", code, stderr)
	}
	want := readFile(t, d.Layout.MainConfPath)
	exec.fail["nginx"] = errors.New("exit 1")

	if code := Run([]string{"--main"}, d); code != exitValidation {
		t.Fatalf("run 2 exit=%d stderr=%s", code, stderr)
	}
	if got := readFile(t, d.Layout.MainConfPath); !bytes.Equal(got, want) {
		t.Errorf("nginx.conf changed after failed nginx -t:\n%s", got)
	}
}

func sysctlFilePaths(t *testing.T, d Deps) (string, string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(d.Layout.SysctlPath), 0755); err != nil {
		t.Fatal(err)
	}
	return d.Layout.SysctlPath, filepath.Join(d.Layout.SystemdOverrideDir, "override.conf")
}

func TestRunSysctlTwiceSameInputSkipsBackupAndWrite(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	sysctlPath, overridePath := sysctlFilePaths(t, d)

	if code := Run([]string{"--sysctl", "--no-reload"}, d); code != exitOK {
		t.Fatalf("run 1 exit=%d stderr=%s", code, stderr)
	}
	sysctlBefore, overrideBefore := statFile(t, sysctlPath), statFile(t, overridePath)
	stderr.Reset()

	if code := Run([]string{"--sysctl", "--no-reload"}, d); code != exitOK {
		t.Fatalf("run 2 exit=%d stderr=%s", code, stderr)
	}
	if got := backupEntries(t, d); len(got) != 0 {
		t.Errorf("run 2 made backups: %v", got)
	}
	for _, path := range []string{sysctlPath, overridePath} {
		if !strings.Contains(stderr.String(), "unchanged: "+path) {
			t.Errorf("stderr missing unchanged line for %s:\n%s", path, stderr)
		}
	}
	if !os.SameFile(sysctlBefore, statFile(t, sysctlPath)) || !os.SameFile(overrideBefore, statFile(t, overridePath)) {
		t.Error("run 2 rewrote a file")
	}
}

func TestRunSysctlUnchangedKeptWhenSysctlSystemFails(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	sysctlPath, overridePath := sysctlFilePaths(t, d)
	if code := Run([]string{"--sysctl", "--no-reload"}, d); code != exitOK {
		t.Fatalf("run 1 exit=%d stderr=%s", code, stderr)
	}
	wantSysctl, wantOverride := readFile(t, sysctlPath), readFile(t, overridePath)
	exec.fail["sysctl"] = errors.New("exit 1")

	if code := Run([]string{"--sysctl"}, d); code != exitSystemErr {
		t.Fatalf("run 2 exit=%d stderr=%s", code, stderr)
	}
	if got := readFile(t, sysctlPath); !bytes.Equal(got, wantSysctl) {
		t.Errorf("sysctl file changed:\n%s", got)
	}
	if got := readFile(t, overridePath); !bytes.Equal(got, wantOverride) {
		t.Errorf("override file changed:\n%s", got)
	}
}

func TestRunSysctlUnchangedKeptWhenDaemonReloadFails(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	sysctlPath, overridePath := sysctlFilePaths(t, d)
	if code := Run([]string{"--sysctl", "--no-reload"}, d); code != exitOK {
		t.Fatalf("run 1 exit=%d stderr=%s", code, stderr)
	}
	wantSysctl, wantOverride := readFile(t, sysctlPath), readFile(t, overridePath)
	exec.fail["systemctl"] = errors.New("exit 1")

	if code := Run([]string{"--sysctl"}, d); code != exitSystemErr {
		t.Fatalf("run 2 exit=%d stderr=%s", code, stderr)
	}
	if got := readFile(t, sysctlPath); !bytes.Equal(got, wantSysctl) {
		t.Errorf("sysctl file changed:\n%s", got)
	}
	if got := readFile(t, overridePath); !bytes.Equal(got, wantOverride) {
		t.Errorf("override file changed:\n%s", got)
	}
}

func TestRunSysctlRollsBackOnlyTheChangedFile(t *testing.T) {
	d, exec, _, stderr := defaultDepsFor(t)
	sysctlPath, overridePath := sysctlFilePaths(t, d)
	if code := Run([]string{"--sysctl", "--no-reload"}, d); code != exitOK {
		t.Fatalf("run 1 exit=%d stderr=%s", code, stderr)
	}
	stale := []byte(sysctlManagedPrefix + "\nnet.core.somaxconn = 1\n")
	if err := os.WriteFile(sysctlPath, stale, 0644); err != nil {
		t.Fatal(err)
	}
	wantOverride := readFile(t, overridePath)
	exec.fail["sysctl"] = errors.New("exit 1")

	if code := Run([]string{"--sysctl"}, d); code != exitSystemErr {
		t.Fatalf("run 2 exit=%d stderr=%s", code, stderr)
	}
	if got := readFile(t, sysctlPath); !bytes.Equal(got, stale) {
		t.Errorf("sysctl file not restored:\n%s", got)
	}
	if got := readFile(t, overridePath); !bytes.Equal(got, wantOverride) {
		t.Errorf("unchanged override file touched:\n%s", got)
	}
}

func upgradeDeps(t *testing.T) (Deps, *fakeExec, *bytes.Buffer) {
	t.Helper()
	d, exec, _, stderr := defaultDepsFor(t)
	d.Geteuid = func() int { return 0 }
	exec.out["nginx"] = []byte("nginx version: nginx/1.27.0\n")
	return d, exec, stderr
}

func TestRunUpgradeLeavesUnmanagedMainConfAlone(t *testing.T) {
	d, exec, stderr := upgradeDeps(t)
	unmanaged := []byte("user nginx;\nevents {}\nhttp {}\n")
	if err := os.WriteFile(d.Layout.MainConfPath, unmanaged, 0644); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{{"--upgrade"}, {"--upgrade", "--force"}} {
		if code := Run(args, d); code != exitOK {
			t.Fatalf("%v exit=%d stderr=%s", args, code, stderr)
		}
		if got := readFile(t, d.Layout.MainConfPath); !bytes.Equal(got, unmanaged) {
			t.Errorf("%v rewrote nginx.conf:\n%s", args, got)
		}
		if got := backupEntries(t, d); len(got) != 0 {
			t.Errorf("%v made backups: %v", args, got)
		}
	}
	if !exec.called("apt-get") || !exec.called("systemctl") {
		t.Errorf("upgrade did not run apt-get and restart: %v", exec.calls)
	}
}

func TestRunUpgradeRefusesWhenBrotliDirectivesLostTheirModule(t *testing.T) {
	d, exec, stderr := upgradeDeps(t)
	withBrotli := []byte("events {}\nhttp {\n    brotli on;\n}\n")
	if err := os.WriteFile(d.Layout.MainConfPath, withBrotli, 0644); err != nil {
		t.Fatal(err)
	}

	if code := Run([]string{"--upgrade"}, d); code != exitValidation {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "--main") {
		t.Errorf("stderr does not name --main:\n%s", stderr)
	}
	for _, c := range exec.calls {
		if c[0] == "systemctl" && len(c) > 1 && c[1] == "restart" {
			t.Errorf("nginx was restarted: %v", exec.calls)
		}
	}
	if got := readFile(t, d.Layout.MainConfPath); !bytes.Equal(got, withBrotli) {
		t.Errorf("nginx.conf changed:\n%s", got)
	}
}

func TestRunUpgradeIgnoresCommentedBrotliDirective(t *testing.T) {
	d, _, stderr := upgradeDeps(t)
	conf := []byte("events {}\nhttp {\n    # brotli on;\n}\n")
	if err := os.WriteFile(d.Layout.MainConfPath, conf, 0644); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"--upgrade"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
}

func TestRunUpgradeAllowsBrotliDirectivesWhenModuleLoaded(t *testing.T) {
	d, _, stderr := upgradeDeps(t)
	conf := []byte("events {}\nhttp {\n    brotli_comp_level 5;\n}\n")
	if err := os.WriteFile(d.Layout.MainConfPath, conf, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(d.Layout.ModulesEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	loadConf := filepath.Join(d.Layout.ModulesEnabledDir, brotliLoadConf)
	if err := os.WriteFile(loadConf, []byte("# built against nginx 1.27.0\nload_module x;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"--upgrade"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
}

func TestRunSysctlWritesNothingWhenOverrideCannotBeRead(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	sysctlPath, overridePath := sysctlFilePaths(t, d)
	stale := []byte(sysctlManagedPrefix + "net.core.somaxconn = 1\n")
	if err := os.WriteFile(sysctlPath, stale, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(overridePath, 0755); err != nil {
		t.Fatal(err)
	}

	if code := Run([]string{"--sysctl", "--no-reload"}, d); code != exitSystemErr {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if got := readFile(t, sysctlPath); !bytes.Equal(got, stale) {
		t.Errorf("sysctl file was written:\n%s", got)
	}
}

func TestRunVhostSymlinkFailureKeepsUnchangedFile(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	advancingClock(&d)
	htmlDir := t.TempDir()
	target := filepath.Join(d.Layout.SitesAvailable, "u.example.com.conf")
	link := filepath.Join(d.Layout.SitesEnabled, "u.example.com.conf")

	if code := Run([]string{"--ssl=false", "u.example.com", htmlDir}, d); code != exitOK {
		t.Fatalf("run 1 exit=%d stderr=%s", code, stderr)
	}
	want := readFile(t, target)
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("regular file"), 0644); err != nil {
		t.Fatal(err)
	}

	if code := Run([]string{"--ssl=false", "u.example.com", htmlDir}, d); code != exitSystemErr {
		t.Fatalf("run 2 exit=%d stderr=%s", code, stderr)
	}
	if got := readFile(t, target); !bytes.Equal(got, want) {
		t.Errorf("vhost changed after symlink failure:\n%s", got)
	}
}

func TestRunVhostUnreadableTargetWritesNothing(t *testing.T) {
	d, _, _, stderr := defaultDepsFor(t)
	target := filepath.Join(d.Layout.SitesAvailable, "u.example.com.conf")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}

	if code := Run([]string{"--ssl=false", "u.example.com", t.TempDir()}, d); code != exitSystemErr {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !statFile(t, target).IsDir() {
		t.Error("target directory was replaced")
	}
	if got := backupEntries(t, d); len(got) != 0 {
		t.Errorf("backups made: %v", got)
	}
}

func TestRunUpgradeRefusesOnBrotliUnderscoreDirective(t *testing.T) {
	d, _, stderr := upgradeDeps(t)
	conf := []byte("events {}\nhttp {\n    brotli_static on;\n}\n")
	if err := os.WriteFile(d.Layout.MainConfPath, conf, 0644); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"--upgrade"}, d); code != exitValidation {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
}

const packagedBrotliConf = "50-mod-http-brotli-filter.conf"

func seedBrotliConf(t *testing.T, d Deps, name, content string) string {
	t.Helper()
	if err := os.MkdirAll(d.Layout.ModulesEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(d.Layout.ModulesEnabledDir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func fakeDpkg(exec *fakeExec, installed ...string) {
	exec.respond = func(name string, args []string) (fakeResult, bool) {
		if name != "dpkg-query" {
			return fakeResult{}, false
		}
		if slices.Contains(installed, args[len(args)-1]) {
			return fakeResult{out: []byte("ii ")}, true
		}
		return fakeResult{out: []byte("dpkg-query: no packages found"), err: errors.New("exit 1")}, true
	}
}

func restartCalled(exec *fakeExec) bool {
	exec.mu.Lock()
	defer exec.mu.Unlock()
	for _, c := range exec.calls {
		if c[0] == "systemctl" && len(c) > 1 && c[1] == "restart" {
			return true
		}
	}
	return false
}

func nginxTestCalled(exec *fakeExec) bool {
	exec.mu.Lock()
	defer exec.mu.Unlock()
	for _, c := range exec.calls {
		if c[0] == "nginx" && slices.Contains(c, "-t") {
			return true
		}
	}
	return false
}

func upgradeAptCall(exec *fakeExec) []string {
	exec.mu.Lock()
	defer exec.mu.Unlock()
	for _, c := range exec.calls {
		if c[0] == "apt-get" && slices.Contains(c, "--only-upgrade") {
			return c
		}
	}
	return nil
}

func aptCallHasBrotliPackages(call []string) bool {
	for _, pkg := range brotliPackages {
		if !slices.Contains(call, pkg) {
			return false
		}
	}
	return true
}

func aptCallHasAnyBrotliPackage(call []string) bool {
	for _, pkg := range brotliPackages {
		if slices.Contains(call, pkg) {
			return true
		}
	}
	return false
}

func TestRunUpgradePackagedBrotliStillLoadedUpgradesPackagesWithoutBuild(t *testing.T) {
	for _, args := range [][]string{{"--upgrade"}, {"--upgrade", "--force"}} {
		d, exec, stderr := upgradeDeps(t)
		fakeDpkg(exec, brotliPackages...)
		seedBrotliConf(t, d, packagedBrotliConf, "load_module x;\n")

		if code := Run(args, d); code != exitOK {
			t.Fatalf("%v exit=%d stderr=%s", args, code, stderr)
		}
		if strings.Contains(stderr.String(), "gone") {
			t.Errorf("%v: stderr claims the module is gone:\n%s", args, stderr)
		}
		if !strings.Contains(stderr.String(), `"brotli_rebuilt":false`) {
			t.Errorf("%v: log line lacks brotli_rebuilt false:\n%s", args, stderr)
		}
		call := upgradeAptCall(exec)
		if call == nil || !aptCallHasBrotliPackages(call) {
			t.Errorf("%v: apt call lacks brotli packages: %v", args, call)
		}
		if exec.called("curl") || exec.called("git") {
			t.Errorf("%v: source build ran: %v", args, exec.calls)
		}
	}
}

func TestRunUpgradePackagedBrotliGoneAfterAptBuildsFromSource(t *testing.T) {
	d, exec, stderr := upgradeDeps(t)
	fakeDpkg(exec, brotliPackages...)
	conf := seedBrotliConf(t, d, packagedBrotliConf, "load_module x;\n")
	exec.hook = func(name string, args []string) {
		if name == "apt-get" && slices.Contains(args, "--only-upgrade") {
			_ = os.Remove(conf)
		}
	}

	Run([]string{"--upgrade"}, d)
	if !exec.called("curl") {
		t.Errorf("no source build after the packaged module vanished: %v", exec.calls)
	}
	if !strings.Contains(stderr.String(), "packaged") {
		t.Errorf("stderr does not say the packaged module is gone:\n%s", stderr)
	}
}

func TestRunUpgradeOwnBrotliBuildDecision(t *testing.T) {
	cases := []struct {
		name      string
		builtFor  string
		args      []string
		wantBuild bool
	}{
		{"matching version", "1.27.0", []string{"--upgrade"}, false},
		{"drift", "1.26.0", []string{"--upgrade"}, true},
		{"matching version with force", "1.27.0", []string{"--upgrade", "--force"}, true},
	}
	for _, c := range cases {
		d, exec, stderr := upgradeDeps(t)
		seedBrotliConf(t, d, brotliLoadConf, "# Managed by nginx-gen; built against nginx "+c.builtFor+"\nload_module x;\n")

		code := Run(c.args, d)
		if !c.wantBuild && code != exitOK {
			t.Errorf("%s: exit=%d stderr=%s", c.name, code, stderr)
		}
		if got := exec.called("curl"); got != c.wantBuild {
			t.Errorf("%s: build ran=%t, want %t", c.name, got, c.wantBuild)
		}
		if call := upgradeAptCall(exec); call == nil || aptCallHasAnyBrotliPackage(call) {
			t.Errorf("%s: apt call must not hold brotli packages: %v", c.name, call)
		}
	}
}

func TestRunUpgradeNoBrotliSkipsPackagesAndBuild(t *testing.T) {
	d, exec, stderr := upgradeDeps(t)

	if code := Run([]string{"--upgrade", "--force"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	call := upgradeAptCall(exec)
	if call == nil || aptCallHasAnyBrotliPackage(call) {
		t.Errorf("apt call must not hold brotli packages: %v", call)
	}
	if exec.called("curl") {
		t.Errorf("source build ran: %v", exec.calls)
	}
}

func TestRunUpgradePackagedUpgradesOnlyInstalledPackages(t *testing.T) {
	d, exec, stderr := upgradeDeps(t)
	fakeDpkg(exec, brotliPackages[0])
	seedBrotliConf(t, d, packagedBrotliConf, "load_module x;\n")

	if code := Run([]string{"--upgrade"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	call := upgradeAptCall(exec)
	if !slices.Contains(call, brotliPackages[0]) {
		t.Errorf("apt call lacks the installed package: %v", call)
	}
	if slices.Contains(call, brotliPackages[1]) {
		t.Errorf("apt call holds a package that is not installed: %v", call)
	}
}

func TestRunUpgradeUnknownBrotliSourceTouchesNothing(t *testing.T) {
	notInstalled := map[string]func(*fakeExec){
		"dpkg-query fails": func(exec *fakeExec) { fakeDpkg(exec) },
		"status not ii": func(exec *fakeExec) {
			exec.respond = func(name string, _ []string) (fakeResult, bool) {
				if name == "dpkg-query" {
					return fakeResult{out: []byte("un ")}, true
				}
				return fakeResult{}, false
			}
		},
	}
	for name, setup := range notInstalled {
		d, exec, stderr := upgradeDeps(t)
		setup(exec)
		seedBrotliConf(t, d, "50-hand-written-brotli.conf", "load_module x;\n")

		if code := Run([]string{"--upgrade", "--force"}, d); code != exitOK {
			t.Fatalf("%s: exit=%d stderr=%s", name, code, stderr)
		}
		call := upgradeAptCall(exec)
		if call == nil || aptCallHasAnyBrotliPackage(call) {
			t.Errorf("%s: apt call must not hold brotli packages: %v", name, call)
		}
		if exec.called("curl") {
			t.Errorf("%s: source build ran: %v", name, exec.calls)
		}
	}
}

func TestRunUpgradeOwnBrotliBuildFailureStopsBeforeRestart(t *testing.T) {
	d, exec, stderr := upgradeDeps(t)
	seedBrotliConf(t, d, brotliLoadConf, "# Managed by nginx-gen; built against nginx 1.26.0\nload_module x;\n")
	exec.fail["curl"] = errors.New("exit 1")

	if code := Run([]string{"--upgrade"}, d); code != exitSystemErr {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if restartCalled(exec) || nginxTestCalled(exec) {
		t.Errorf("run continued after the failed rebuild: %v", exec.calls)
	}
}

func gonePackagedWithFailingBuild(t *testing.T, mainConf string) (Deps, *fakeExec, *bytes.Buffer) {
	t.Helper()
	d, exec, stderr := upgradeDeps(t)
	fakeDpkg(exec, brotliPackages...)
	conf := seedBrotliConf(t, d, packagedBrotliConf, "load_module x;\n")
	exec.hook = func(name string, args []string) {
		if name == "apt-get" && slices.Contains(args, "--only-upgrade") {
			_ = os.Remove(conf)
		}
	}
	exec.fail["curl"] = errors.New("exit 1")
	if err := os.WriteFile(d.Layout.MainConfPath, []byte(mainConf), 0644); err != nil {
		t.Fatal(err)
	}
	return d, exec, stderr
}

func TestRunUpgradeFailedFallbackBuildWithBrotliDirectivesRefuses(t *testing.T) {
	d, exec, stderr := gonePackagedWithFailingBuild(t, "events {}\nhttp {\n    brotli on;\n}\n")

	if code := Run([]string{"--upgrade"}, d); code != exitValidation {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "--main") {
		t.Errorf("stderr does not name --main:\n%s", stderr)
	}
	if restartCalled(exec) {
		t.Errorf("nginx was restarted: %v", exec.calls)
	}
}

func TestRunUpgradeFailedFallbackBuildWithoutBrotliDirectivesContinues(t *testing.T) {
	d, exec, stderr := gonePackagedWithFailingBuild(t, "events {}\nhttp {}\n")

	if code := Run([]string{"--upgrade"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "download failed") {
		t.Errorf("stderr does not show the build failure:\n%s", stderr)
	}
	if !nginxTestCalled(exec) || !restartCalled(exec) {
		t.Errorf("run did not reach nginx -t and restart: %v", exec.calls)
	}
}
