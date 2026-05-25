// Self-update for the nginx-gen binary itself (distinct from --nginx-upgrade,
// which upgrades the *nginx* package). Fetches the latest release asset
// from GitHub for the current GOOS/GOARCH, verifies its sha256 against
// the release's checksums.txt, and atomically replaces the running binary.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"nginx-gen/internal/fsop"
)

const (
	selfUpdateRepo    = "tumult1337/nginx-install"
	selfUpdateAPIBase = "https://api.github.com"
)

// toolVersion is the running tool's version. Overridden at build time via
//
//	-ldflags="-X main.toolVersion=<vX.Y.Z>"
//
// (set by goreleaser for releases and the local Makefile via `git describe`).
// Defaults to "dev" for `go run` / `go build` without ldflags.
var toolVersion = "dev"

// osExecutable is package-level for test stubbing.
var osExecutable = os.Executable

// httpGetter is the same shape as cf.HTTPGetter; kept local to avoid
// coupling self-update to the cf package.
type httpGetter interface {
	Get(ctx context.Context, url string) ([]byte, error)
}

type ghReleaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName string           `json:"tag_name"`
	Assets  []ghReleaseAsset `json:"assets"`
}

func runVersion(d Deps) int {
	fmt.Fprintln(d.Stdout, "nginx-gen", toolVersion)
	return exitOK
}

func runSelfUpdate(d Deps, dryRun, force bool) int {
	binPath, err := osExecutable()
	if err != nil {
		fmt.Fprintln(d.Stderr, "locating current binary:", err)
		return exitSystemErr
	}
	if resolved, err := filepath.EvalSymlinks(binPath); err == nil {
		binPath = resolved
	}

	rel, err := fetchLatestRelease(d.ReleaseHTTP)
	if err != nil {
		fmt.Fprintln(d.Stderr, "fetching latest release:", err)
		return exitSystemErr
	}

	binAsset, sumsAsset, err := selectAssets(rel, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		fmt.Fprintln(d.Stderr, err)
		return exitSystemErr
	}
	assetName := urlBasename(binAsset)

	fmt.Fprintln(d.Stderr, "current binary :", binPath)
	fmt.Fprintln(d.Stderr, "current version:", toolVersion)
	fmt.Fprintln(d.Stderr, "latest version :", rel.TagName)

	if !force && versionMatches(toolVersion, rel.TagName) {
		fmt.Fprintln(d.Stderr, "already up to date (use --force to reinstall)")
		return exitOK
	}

	if dryRun {
		fmt.Fprintln(d.Stdout, "# would download", binAsset)
		fmt.Fprintln(d.Stdout, "# would verify sha256 against", sumsAsset)
		fmt.Fprintln(d.Stdout, "# would atomically replace", binPath)
		return exitOK
	}

	if !canWriteDir(filepath.Dir(binPath)) {
		fmt.Fprintf(d.Stderr,
			"cannot write to %s — re-run as root (sudo nginx-gen --self-update)\n",
			filepath.Dir(binPath))
		return exitUserError
	}

	fmt.Fprintln(d.Stderr, "fetching", assetName, "...")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bin, err := d.ReleaseHTTP.Get(ctx, binAsset)
	if err != nil {
		fmt.Fprintln(d.Stderr, "download:", err)
		return exitSystemErr
	}
	sums, err := d.ReleaseHTTP.Get(ctx, sumsAsset)
	if err != nil {
		fmt.Fprintln(d.Stderr, "download checksums:", err)
		return exitSystemErr
	}
	expected, ok := lookupChecksum(sums, assetName)
	if !ok {
		fmt.Fprintf(d.Stderr, "no checksum entry for %s in checksums.txt\n", assetName)
		return exitSystemErr
	}
	sum := sha256.Sum256(bin)
	got := hex.EncodeToString(sum[:])
	if got != expected {
		fmt.Fprintf(d.Stderr, "sha256 mismatch: got %s want %s\n", got, expected)
		return exitSystemErr
	}
	fmt.Fprintln(d.Stderr, "verified sha256 ok")

	if err := fsop.AtomicWrite(binPath, bin, 0755); err != nil {
		fmt.Fprintln(d.Stderr, "install:", err)
		return exitSystemErr
	}
	fmt.Fprintf(d.Stderr, "installed %s (%s)\n", binPath, rel.TagName)
	logEvent(d.Stderr, d.Now(), "self-update", "", map[string]any{
		"from":   toolVersion,
		"to":     rel.TagName,
		"path":   binPath,
		"result": "ok",
	})
	return exitOK
}

func fetchLatestRelease(client httpGetter) (*ghRelease, error) {
	url := selfUpdateAPIBase + "/repos/" + selfUpdateRepo + "/releases/latest"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	body, err := client.Get(ctx, url)
	if err != nil {
		return nil, err
	}
	var rel ghRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("parse release JSON: %w", err)
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("release JSON missing tag_name")
	}
	return &rel, nil
}

// selectAssets picks the raw-binary asset for the given GOOS/GOARCH and the
// checksums.txt asset. Returns an error if either is missing.
func selectAssets(rel *ghRelease, goos, goarch string) (binURL, sumsURL string, err error) {
	suffix := "_" + goos + "_" + goarch
	for _, a := range rel.Assets {
		switch {
		case a.Name == "checksums.txt":
			sumsURL = a.URL
		case strings.HasPrefix(a.Name, "nginx-gen_") &&
			strings.HasSuffix(a.Name, suffix):
			// goreleaser produces both a raw binary AND a tar.gz with the same
			// base name; the tar.gz keeps the .tar.gz suffix, the raw binary
			// has no extension. The suffix check above only matches the raw
			// binary because suffix is "_<os>_<arch>".
			binURL = a.URL
		}
	}
	if binURL == "" {
		return "", "", fmt.Errorf("no binary asset for %s/%s in release %s",
			goos, goarch, rel.TagName)
	}
	if sumsURL == "" {
		return "", "", fmt.Errorf("no checksums.txt in release %s", rel.TagName)
	}
	return binURL, sumsURL, nil
}

// lookupChecksum finds the sha256 hex for a given filename in sha256sum-format
// content: "<64-hex>  <filename>" per line (two spaces is the GNU coreutils
// canonical separator; tolerate any whitespace).
func lookupChecksum(sums []byte, name string) (string, bool) {
	for line := range strings.SplitSeq(string(sums), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[len(fields)-1] == name {
			return fields[0], true
		}
	}
	return "", false
}

// versionMatches returns true if the running tool's version equals the given
// release tag, tolerating a leading "v" on either side. "dev" never matches.
func versionMatches(have, tag string) bool {
	if have == "dev" || have == "" {
		return false
	}
	return strings.TrimPrefix(have, "v") == strings.TrimPrefix(tag, "v")
}

func urlBasename(u string) string {
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return u
}

// canWriteDir does a cheap write probe: creating + removing a tmp file is
// the only reliable cross-platform way to know whether the EUID can write
// (mode bits + ACLs + read-only mount can all reject otherwise-writable
// dirs).
func canWriteDir(dir string) bool {
	f, err := os.CreateTemp(dir, ".nginx-gen-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

// releaseHTTP is the default HTTP client for self-update. Longer timeout
// than the cf client (binary download is ~3 MB and S3 redirects add a hop).
type releaseHTTP struct{}

func (releaseHTTP) Get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nginx-gen/"+toolVersion)
	if strings.HasPrefix(url, selfUpdateAPIBase) {
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	cl := &http.Client{Timeout: 90 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}
