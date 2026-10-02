package cert

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seedFiles(t *testing.T, base, host string, names ...string) string {
	t.Helper()
	dir := filepath.Join(base, host)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func seedCertDir(t *testing.T, base, host string) string {
	t.Helper()
	return seedFiles(t, base, host, "fullchain.pem", "privkey.pem")
}

func letsencryptPair(dir string) Pair {
	return Pair{Cert: filepath.Join(dir, "fullchain.pem"), Key: filepath.Join(dir, "privkey.pem")}
}

func mustResolve(t *testing.T, host string, bases ...string) Pair {
	t.Helper()
	got, err := Resolve(host, bases)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestResolveExactMatch(t *testing.T) {
	base := t.TempDir()
	dir := seedCertDir(t, base, "a.example.com")
	if got, want := mustResolve(t, "a.example.com", base), letsencryptPair(dir); got != want {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestResolveWalkUpToParent(t *testing.T) {
	base := t.TempDir()
	dir := seedCertDir(t, base, "example.com")
	if got, want := mustResolve(t, "a.b.c.example.com", base), letsencryptPair(dir); got != want {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestResolveExhausted(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	_, err := Resolve("a.b.example.com", []string{first, second})
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"tried:", filepath.Join(first, "example.com"), filepath.Join(second, "a.b.example.com")} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should contain %q: %v", want, err)
		}
	}
}

func TestResolveNoBaseDirs(t *testing.T) {
	if _, err := Resolve("a.example.com", nil); err == nil {
		t.Fatal("expected error for empty base dir list")
	}
}

func TestResolveStopsAt2Labels(t *testing.T) {
	base := t.TempDir()
	seedCertDir(t, base, "com")
	if _, err := Resolve("a.example.com", []string{base}); err == nil {
		t.Fatal("expected error — must not match bare TLD")
	}
}

func TestResolveRejectsBareWord(t *testing.T) {
	if _, err := Resolve("localhost", []string{t.TempDir()}); err == nil {
		t.Fatal("expected error for dotless host")
	}
}

func TestResolveExactBeatsParent(t *testing.T) {
	base := t.TempDir()
	seedCertDir(t, base, "example.com")
	dir := seedCertDir(t, base, "a.example.com")
	if got, want := mustResolve(t, "a.example.com", base), letsencryptPair(dir); got != want {
		t.Errorf("exact should win: got %+v want %+v", got, want)
	}
}

func TestResolveEarlierBaseWins(t *testing.T) {
	letsencrypt, nginxSSL := t.TempDir(), t.TempDir()
	seedCertDir(t, nginxSSL, "a.example.com")
	dir := seedCertDir(t, letsencrypt, "example.com")
	if got, want := mustResolve(t, "a.example.com", letsencrypt, nginxSSL), letsencryptPair(dir); got != want {
		t.Errorf("first base must win even with a parent match: got %+v want %+v", got, want)
	}
}

func TestResolveFallsBackToLaterBase(t *testing.T) {
	letsencrypt, nginxSSL := t.TempDir(), t.TempDir()
	dir := seedCertDir(t, nginxSSL, "example.com")
	if got, want := mustResolve(t, "a.example.com", letsencrypt, nginxSSL), letsencryptPair(dir); got != want {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestResolveFileNamePairs(t *testing.T) {
	cases := []struct {
		name      string
		files     []string
		cert, key string
	}{
		{"letsencrypt", []string{"fullchain.pem", "privkey.pem"}, "fullchain.pem", "privkey.pem"},
		{"cert-key-pem", []string{"cert.pem", "key.pem"}, "cert.pem", "key.pem"},
		{"domain-crt-key", []string{"example.com.crt", "example.com.key"}, "example.com.crt", "example.com.key"},
		{"fullchain-preferred", []string{"cert.pem", "key.pem", "fullchain.pem", "privkey.pem"}, "fullchain.pem", "privkey.pem"},
		{"letsencrypt-layout", []string{"cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"}, "fullchain.pem", "privkey.pem"},
	}
	for _, c := range cases {
		base := t.TempDir()
		dir := seedFiles(t, base, "example.com", c.files...)
		got := mustResolve(t, "a.example.com", base)
		want := Pair{Cert: filepath.Join(dir, c.cert), Key: filepath.Join(dir, c.key)}
		if got != want {
			t.Errorf("%s: got %+v want %+v", c.name, got, want)
		}
	}
}

func TestResolveRejectsIncompletePair(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  string
	}{
		{"cert-only", []string{"fullchain.pem"}, "no matching key"},
		{"key-only", []string{"privkey.pem"}, "no matching cert"},
		{"half-second-pair", []string{"cert.pem"}, "no matching key"},
		{"domain-key-only", []string{"example.com.key"}, "no matching cert"},
	}
	for _, c := range cases {
		letsencrypt, nginxSSL := t.TempDir(), t.TempDir()
		seedFiles(t, letsencrypt, "example.com", c.files...)
		seedCertDir(t, nginxSSL, "example.com")
		_, err := Resolve("example.com", []string{letsencrypt, nginxSSL})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", c.name, c.want, err)
		}
	}
}

func TestResolveRejectsDirectoryAsFile(t *testing.T) {
	base := t.TempDir()
	dir := seedFiles(t, base, "example.com", "privkey.pem")
	if err := os.Mkdir(filepath.Join(dir, "fullchain.pem"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve("example.com", []string{base}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("want not-a-regular-file error, got %v", err)
	}
}

func TestResolveRejectsUnsafePath(t *testing.T) {
	for _, unsafeByte := range []rune{' ', '\t', '\r', '\n', ';', '{', '}', '"', '\'', '#', '$', '\\'} {
		base := filepath.Join(t.TempDir(), "a"+string(unsafeByte)+"b")
		seedCertDir(t, base, "example.com")
		if _, err := Resolve("example.com", []string{base}); err == nil || !strings.Contains(err.Error(), "unsafe") {
			t.Errorf("%q: want unsafe-path error, got %v", unsafeByte, err)
		}
	}
}

func TestResolveFollowsLetsencryptSymlinks(t *testing.T) {
	root := t.TempDir()
	archive := seedFiles(t, filepath.Join(root, "archive"), "example.com", "fullchain1.pem", "privkey1.pem")
	live := filepath.Join(root, "live", "example.com")
	if err := os.MkdirAll(live, 0755); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"fullchain.pem": "fullchain1.pem", "privkey.pem": "privkey1.pem"} {
		if err := os.Symlink(filepath.Join(archive, target), filepath.Join(live, link)); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := mustResolve(t, "a.example.com", filepath.Join(root, "live")), letsencryptPair(live); got != want {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestResolveRejectsSymlinkToDirectory(t *testing.T) {
	base := t.TempDir()
	dir := seedFiles(t, base, "example.com", "privkey.pem")
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "fullchain.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve("example.com", []string{base}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("want not-a-regular-file error, got %v", err)
	}
}

func TestResolveRejectsRelativeBase(t *testing.T) {
	if _, err := Resolve("example.com", []string{"certs"}); err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("want not-absolute error, got %v", err)
	}
}
