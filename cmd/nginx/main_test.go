package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nginx-gen/internal/marker"
	"nginx-gen/internal/nginx"
)

var fixedNow = time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)

func tempLayout(t *testing.T) Layout {
	t.Helper()
	dir := t.TempDir()
	return Layout{
		SitesAvailable:    filepath.Join(dir, "sites-available"),
		SitesEnabled:      filepath.Join(dir, "sites-enabled"),
		MainConfPath:      filepath.Join(dir, "nginx.conf"),
		BackupDir:         filepath.Join(dir, "backups"),
		LockPath:          filepath.Join(dir, "lock"),
		SnippetPath:       filepath.Join(dir, "snippets/cf-allow.conf"),
		CachePath:         filepath.Join(dir, "lib/cf-allow.conf"),
		CertDir:            filepath.Join(dir, "letsencrypt"),
		SysctlPath:         filepath.Join(dir, "sysctl.d/99-nginx.conf"),
		SystemdOverrideDir: filepath.Join(dir, "systemd/nginx.service.d"),
		ModulesDir:         filepath.Join(dir, "modules"),
		ModulesEnabledDir:  filepath.Join(dir, "modules-enabled"),
	}
}

// fakeExec records calls; returns canned err / output keyed by argv[0].
type fakeExec struct {
	mu    sync.Mutex
	calls [][]string
	fail  map[string]error // argv[0] -> err
	out   map[string][]byte
}

func (f *fakeExec) Run(name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{name}, args...))
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

func seedCert(t *testing.T, layout Layout, host string) {
	t.Helper()
	dir := filepath.Join(layout.CertDir, host)
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

	code := Run([]string{"--allow=cf", "p.example.com", "10.0.0.1:8080"}, d)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	b, err := os.ReadFile(filepath.Join(d.Layout.SitesAvailable, "p.example.com.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"include /etc/nginx/snippets/cf-allow.conf",
		"upstream p_example_com_up {",
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
	prior := []byte(marker.RenderVhost("r.example.com", "static", false, "none", fixedNow) +
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

// ---- --upgrade / --version-check ----

func TestRunUpgradeDryRunPrintsRecipe(t *testing.T) {
	d, exec, stdout, stderr := defaultDepsFor(t)
	if code := Run([]string{"--upgrade", "--dry-run"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"apt-get install --only-upgrade -y nginx",
		"--brotli-build --force",
		"systemctl restart nginx",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("dry-run missing %q:\n%s", want, stdout.String())
		}
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
	if code := Run([]string{"--version-check"}, d); code != exitOK {
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

	if code := Run([]string{"--version-check"}, d); code != exitOK {
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

	code := Run([]string{"--version-check"}, d)
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
