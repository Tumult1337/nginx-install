// Package cert resolves which certificate and key files to use for a host.
// Walks up the domain labels until it finds a dir with a known cert/key pair,
// so wildcard certs at the parent domain are picked up automatically.
package cert

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Pair holds the absolute paths nginx loads for ssl_certificate and
// ssl_certificate_key.
type Pair struct {
	Cert string
	Key  string
}

type fileNames struct {
	cert, key string
}

func candidateNames(dirName string) []fileNames {
	return []fileNames{
		{"fullchain.pem", "privkey.pem"},
		{"cert.pem", "key.pem"},
		{dirName + ".crt", dirName + ".key"},
	}
}

// unsafePathChars are bytes that would end, split, or interpolate an nginx
// directive argument written unquoted into the vhost config.
const unsafePathChars = " \t\r\n;{}\"'#$\\"

// Resolve returns the cert/key pair for host or an error listing what was
// tried. Each base dir is searched in order, and within a base the full host
// is tried before each parent domain. It does NOT verify cert validity — only
// that both files of a pair exist. A dir with only one file of a pair is an
// error, not a miss.
func Resolve(host string, baseDirs []string) (Pair, error) {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return Pair{}, fmt.Errorf("host %q has no dot, refusing", host)
	}
	if len(baseDirs) == 0 {
		return Pair{}, errors.New("no cert base dir configured")
	}

	var tried []string
	for _, base := range baseDirs {
		if !filepath.IsAbs(base) {
			return Pair{}, fmt.Errorf("cert base dir %q is not absolute; nginx would resolve it against its own prefix", base)
		}
		// Walk: full host, then strip leading label until 2 labels remain
		// (don't try just the TLD — would match the wrong cert).
		for i := 0; i <= len(parts)-2; i++ {
			name := strings.Join(parts[i:], ".")
			dir := filepath.Join(base, name)
			pair, found, err := pairIn(dir, name)
			if err != nil {
				return Pair{}, err
			}
			if found {
				return pair, nil
			}
			tried = append(tried, dir)
		}
	}
	return Pair{}, fmt.Errorf("no cert found for %s under %s (tried: %s)",
		host, strings.Join(baseDirs, ", "), strings.Join(tried, ", "))
}

func pairIn(dir, dirName string) (Pair, bool, error) {
	for _, names := range candidateNames(dirName) {
		pair := Pair{Cert: filepath.Join(dir, names.cert), Key: filepath.Join(dir, names.key)}
		certFound, err := isFile(pair.Cert)
		if err != nil {
			return Pair{}, false, err
		}
		keyFound, err := isFile(pair.Key)
		if err != nil {
			return Pair{}, false, err
		}
		switch {
		case certFound && keyFound:
			if strings.ContainsAny(pair.Cert+pair.Key, unsafePathChars) {
				return Pair{}, false, fmt.Errorf("cert path %q or %q contains a character unsafe in nginx config", pair.Cert, pair.Key)
			}
			return pair, true, nil
		case certFound:
			return Pair{}, false, fmt.Errorf("%s has no matching key %s", pair.Cert, pair.Key)
		case keyFound:
			return Pair{}, false, fmt.Errorf("%s has no matching cert %s", pair.Key, pair.Cert)
		}
	}
	return Pair{}, false, nil
}

func isFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", path)
	}
	return true, nil
}
