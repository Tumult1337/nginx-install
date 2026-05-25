package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVersionMatches(t *testing.T) {
	cases := []struct {
		have, tag string
		want      bool
	}{
		{"v0.0.41", "v0.0.41", true},
		{"0.0.41", "v0.0.41", true},
		{"v0.0.41", "0.0.41", true},
		{"v0.0.41", "v0.0.42", false},
		{"dev", "v0.0.41", false},
		{"", "v0.0.41", false},
	}
	for _, c := range cases {
		if got := versionMatches(c.have, c.tag); got != c.want {
			t.Errorf("versionMatches(%q,%q) = %v, want %v", c.have, c.tag, got, c.want)
		}
	}
}

func TestLookupChecksum(t *testing.T) {
	sums := []byte(
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  nginx-gen_0.0.41_linux_amd64\n" +
			"cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe  nginx-gen_0.0.41_linux_amd64.tar.gz\n" +
			"\n" +
			"abc123  some-other-file\n",
	)
	got, ok := lookupChecksum(sums, "nginx-gen_0.0.41_linux_amd64")
	if !ok {
		t.Fatal("lookup failed")
	}
	if got != "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("wrong sum: %s", got)
	}
	if _, ok := lookupChecksum(sums, "missing"); ok {
		t.Error("expected miss for unknown filename")
	}
}

func TestSelectAssets(t *testing.T) {
	rel := &ghRelease{
		TagName: "v0.0.41",
		Assets: []ghReleaseAsset{
			{Name: "nginx-gen_0.0.41_linux_amd64", URL: "https://example/bin"},
			{Name: "nginx-gen_0.0.41_linux_amd64.tar.gz", URL: "https://example/tgz"},
			{Name: "nginx-gen_0.0.41_darwin_arm64", URL: "https://example/darwin"},
			{Name: "checksums.txt", URL: "https://example/sums"},
		},
	}
	bin, sums, err := selectAssets(rel, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if bin != "https://example/bin" {
		t.Errorf("bin: %s", bin)
	}
	if sums != "https://example/sums" {
		t.Errorf("sums: %s", sums)
	}

	// Missing arch
	if _, _, err := selectAssets(rel, "linux", "riscv64"); err == nil {
		t.Error("expected error for unknown arch")
	}

	// Missing checksums
	noSums := &ghRelease{
		TagName: "v0.0.42",
		Assets:  []ghReleaseAsset{{Name: "nginx-gen_0.0.42_linux_amd64", URL: "x"}},
	}
	if _, _, err := selectAssets(noSums, "linux", "amd64"); err == nil {
		t.Error("expected error for missing checksums.txt")
	}
}

func TestUrlBasename(t *testing.T) {
	for in, want := range map[string]string{
		"https://example/a/b/file": "file",
		"file":                     "file",
		"":                         "",
	} {
		if got := urlBasename(in); got != want {
			t.Errorf("urlBasename(%q) = %q, want %q", in, got, want)
		}
	}
}

// stubHTTP returns canned bodies keyed by URL substring.
type stubHTTP struct {
	bodies map[string][]byte
	err    map[string]error
}

func (s stubHTTP) Get(_ context.Context, url string) ([]byte, error) {
	for key, e := range s.err {
		if strings.Contains(url, key) {
			return nil, e
		}
	}
	for key, b := range s.bodies {
		if strings.Contains(url, key) {
			return b, nil
		}
	}
	return nil, fmt.Errorf("no stub for %s", url)
}

func TestRunVersion(t *testing.T) {
	d, _, stdout, _ := defaultDepsFor(t)
	prev := toolVersion
	toolVersion = "v0.0.99"
	t.Cleanup(func() { toolVersion = prev })

	if code := Run([]string{"--version"}, d); code != exitOK {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stdout.String(), "nginx-gen v0.0.99") {
		t.Errorf("output: %q", stdout.String())
	}
}

func TestRunSelfUpdateDryRunNoNetworkWrite(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "nginx-gen")
	if err := os.WriteFile(binPath, []byte("old binary"), 0755); err != nil {
		t.Fatal(err)
	}

	prevExec := osExecutable
	osExecutable = func() (string, error) { return binPath, nil }
	t.Cleanup(func() { osExecutable = prevExec })

	prevVer := toolVersion
	toolVersion = "v0.0.10"
	t.Cleanup(func() { toolVersion = prevVer })

	assetName := fmt.Sprintf("nginx-gen_0.0.41_%s_%s", runtime.GOOS, runtime.GOARCH)
	relJSON := fmt.Sprintf(`{
		"tag_name": "v0.0.41",
		"assets": [
			{"name": %q, "browser_download_url": "https://example/bin"},
			{"name": "checksums.txt", "browser_download_url": "https://example/sums"}
		]
	}`, assetName)

	d, _, stdout, stderr := defaultDepsFor(t)
	d.ReleaseHTTP = stubHTTP{bodies: map[string][]byte{
		"releases/latest": []byte(relJSON),
	}}

	if code := Run([]string{"--self-update", "--dry-run"}, d); code != exitOK {
		t.Fatalf("exit=%d\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	for _, want := range []string{
		"# would download https://example/bin",
		"# would verify sha256 against https://example/sums",
		"# would atomically replace " + binPath,
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing %q in:\n%s", want, stdout.String())
		}
	}

	got, _ := os.ReadFile(binPath)
	if string(got) != "old binary" {
		t.Errorf("dry-run must not touch binary, got: %q", got)
	}
}

func TestRunSelfUpdateAlreadyCurrent(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "nginx-gen")
	if err := os.WriteFile(binPath, []byte("current"), 0755); err != nil {
		t.Fatal(err)
	}

	prevExec := osExecutable
	osExecutable = func() (string, error) { return binPath, nil }
	t.Cleanup(func() { osExecutable = prevExec })

	prevVer := toolVersion
	toolVersion = "v0.0.41"
	t.Cleanup(func() { toolVersion = prevVer })

	assetName := fmt.Sprintf("nginx-gen_0.0.41_%s_%s", runtime.GOOS, runtime.GOARCH)
	relJSON := fmt.Sprintf(`{
		"tag_name": "v0.0.41",
		"assets": [
			{"name": %q, "browser_download_url": "https://example/bin"},
			{"name": "checksums.txt", "browser_download_url": "https://example/sums"}
		]
	}`, assetName)

	d, _, _, stderr := defaultDepsFor(t)
	d.ReleaseHTTP = stubHTTP{bodies: map[string][]byte{
		"releases/latest": []byte(relJSON),
	}}

	if code := Run([]string{"--self-update"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "already up to date") {
		t.Errorf("missing 'already up to date':\n%s", stderr)
	}

	got, _ := os.ReadFile(binPath)
	if string(got) != "current" {
		t.Errorf("binary should be untouched, got: %q", got)
	}
}

func TestRunSelfUpdateHappyPath(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "nginx-gen")
	if err := os.WriteFile(binPath, []byte("old binary"), 0755); err != nil {
		t.Fatal(err)
	}

	prevExec := osExecutable
	osExecutable = func() (string, error) { return binPath, nil }
	t.Cleanup(func() { osExecutable = prevExec })

	prevVer := toolVersion
	toolVersion = "v0.0.10"
	t.Cleanup(func() { toolVersion = prevVer })

	newBinary := []byte("new binary contents — assume this is a fresh ELF")
	sum := sha256.Sum256(newBinary)
	sumHex := hex.EncodeToString(sum[:])
	assetName := fmt.Sprintf("nginx-gen_0.0.41_%s_%s", runtime.GOOS, runtime.GOARCH)
	binURL := "https://example/download/v0.0.41/" + assetName
	sumsURL := "https://example/download/v0.0.41/checksums.txt"
	relJSON := fmt.Sprintf(`{
		"tag_name": "v0.0.41",
		"assets": [
			{"name": %q, "browser_download_url": %q},
			{"name": "checksums.txt", "browser_download_url": %q}
		]
	}`, assetName, binURL, sumsURL)
	sumsBody := []byte(sumHex + "  " + assetName + "\n" +
		"deadbeef  nginx-gen_0.0.41_linux_amd64.tar.gz\n")

	d, _, _, stderr := defaultDepsFor(t)
	d.ReleaseHTTP = stubHTTP{bodies: map[string][]byte{
		"releases/latest": []byte(relJSON),
		assetName:         newBinary,
		"checksums.txt":   sumsBody,
	}}

	if code := Run([]string{"--self-update"}, d); code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	got, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newBinary) {
		t.Errorf("binary not replaced. got=%q want=%q", got, newBinary)
	}
	info, _ := os.Stat(binPath)
	if info.Mode().Perm()&0111 == 0 {
		t.Errorf("new binary not executable: mode=%v", info.Mode())
	}
	if !strings.Contains(stderr.String(), "verified sha256 ok") {
		t.Errorf("missing verification line:\n%s", stderr)
	}
	if !strings.Contains(stderr.String(), `"action":"self-update"`) {
		t.Errorf("missing log event:\n%s", stderr)
	}
}

func TestRunSelfUpdateChecksumMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "nginx-gen")
	if err := os.WriteFile(binPath, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}

	prevExec := osExecutable
	osExecutable = func() (string, error) { return binPath, nil }
	t.Cleanup(func() { osExecutable = prevExec })

	prevVer := toolVersion
	toolVersion = "v0.0.10"
	t.Cleanup(func() { toolVersion = prevVer })

	assetName := fmt.Sprintf("nginx-gen_0.0.41_%s_%s", runtime.GOOS, runtime.GOARCH)
	binURL := "https://example/download/v0.0.41/" + assetName
	sumsURL := "https://example/download/v0.0.41/checksums.txt"
	relJSON := fmt.Sprintf(`{
		"tag_name": "v0.0.41",
		"assets": [
			{"name": %q, "browser_download_url": %q},
			{"name": "checksums.txt", "browser_download_url": %q}
		]
	}`, assetName, binURL, sumsURL)
	// Checksum intentionally doesn't match the binary body.
	sumsBody := []byte("0000000000000000000000000000000000000000000000000000000000000000  " + assetName + "\n")

	d, _, _, stderr := defaultDepsFor(t)
	d.ReleaseHTTP = stubHTTP{bodies: map[string][]byte{
		"releases/latest": []byte(relJSON),
		assetName:         []byte("payload"),
		"checksums.txt":   sumsBody,
	}}

	if code := Run([]string{"--self-update"}, d); code != exitSystemErr {
		t.Fatalf("expected exitSystemErr, got %d. stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr.String(), "sha256 mismatch") {
		t.Errorf("missing mismatch message:\n%s", stderr)
	}
	got, _ := os.ReadFile(binPath)
	if string(got) != "old" {
		t.Errorf("binary must NOT be replaced on mismatch, got %q", got)
	}
}

func TestRunSelfUpdateAPIError(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "nginx-gen")
	if err := os.WriteFile(binPath, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}

	prevExec := osExecutable
	osExecutable = func() (string, error) { return binPath, nil }
	t.Cleanup(func() { osExecutable = prevExec })

	d, _, _, stderr := defaultDepsFor(t)
	d.ReleaseHTTP = stubHTTP{err: map[string]error{
		"releases/latest": errors.New("network unreachable"),
	}}

	if code := Run([]string{"--self-update"}, d); code != exitSystemErr {
		t.Fatalf("expected exitSystemErr, got %d", code)
	}
	if !strings.Contains(stderr.String(), "fetching latest release") {
		t.Errorf("missing error message:\n%s", stderr)
	}
}
