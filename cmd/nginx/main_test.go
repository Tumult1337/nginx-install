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
)

var fixedNow = time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)

func tempLayout(t *testing.T) Layout {
	t.Helper()
	dir := t.TempDir()
	return Layout{
		SitesAvailable: filepath.Join(dir, "sites-available"),
		SitesEnabled:   filepath.Join(dir, "sites-enabled"),
		MainConfPath:   filepath.Join(dir, "nginx.conf"),
		BackupDir:      filepath.Join(dir, "backups"),
		LockPath:       filepath.Join(dir, "lock"),
		SnippetPath:    filepath.Join(dir, "snippets/cf-allow.conf"),
		CachePath:      filepath.Join(dir, "lib/cf-allow.conf"),
		CertDir:        filepath.Join(dir, "letsencrypt"),
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
