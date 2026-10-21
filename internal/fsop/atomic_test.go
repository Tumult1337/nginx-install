package fsop

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAtomicWriteCreatesAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.conf")
	if err := AtomicWrite(path, []byte("hello"), 0640); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Errorf("content: %q", b)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0640 {
		t.Errorf("perm: %v", info.Mode().Perm())
	}
	// no leftover .tmp files
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "x.conf" {
			t.Errorf("unexpected leftover: %s", e.Name())
		}
	}
}

func TestAtomicWriteOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.conf")
	_ = os.WriteFile(path, []byte("old"), 0644)
	if err := AtomicWrite(path, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "new" {
		t.Errorf("content: %q", b)
	}
}

var backupTime = time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)

func TestBackupWritesGivenBytesWithStampedName(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "x.conf")
	bdir := filepath.Join(dir, "bak")
	if err := os.WriteFile(src, []byte("on disk"), 0644); err != nil {
		t.Fatal(err)
	}

	dest, err := Backup(src, []byte("v1"), backupTime, bdir)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(bdir, "x.conf.20260503T120000Z"); dest != want {
		t.Errorf("dest: got %q, want %q", dest, want)
	}
	b, _ := os.ReadFile(dest)
	if string(b) != "v1" {
		t.Errorf("backup content: %q", b)
	}

	if err := os.WriteFile(src, []byte("v2"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Restore(dest, src); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(src)
	if string(b) != "v1" {
		t.Errorf("after restore: %q", b)
	}
}

func TestBackupSameTimeKeepsBothBackups(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "x.conf")
	bdir := filepath.Join(dir, "bak")

	first, err := Backup(src, []byte("one"), backupTime, bdir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Backup(src, []byte("two"), backupTime, bdir)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("both backups use path %q", first)
	}
	for path, want := range map[string]string{first: "one", second: "two"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != want {
			t.Errorf("%s: got %q, want %q", path, b, want)
		}
	}
}

func TestBackupFailsAfterMaxCollisions(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "x.conf")
	bdir := filepath.Join(dir, "bak")

	for i := range 100 {
		if _, err := Backup(src, fmt.Appendf(nil, "v%d", i), backupTime, bdir); err != nil {
			t.Fatalf("backup %d: %v", i, err)
		}
	}
	if _, err := Backup(src, []byte("overflow"), backupTime, bdir); err == nil {
		t.Fatal("backup 101 must return an error")
	}
	entries, err := os.ReadDir(bdir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 100 {
		t.Errorf("backup entries: got %d, want 100", len(entries))
	}
	b, _ := os.ReadFile(filepath.Join(bdir, "x.conf.20260503T120000Z"))
	if string(b) != "v0" {
		t.Errorf("first backup was overwritten: %q", b)
	}
}

func TestIdempotentSymlinkNew(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	_ = os.WriteFile(target, []byte(""), 0644)

	created, err := IdempotentSymlink(target, link)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("expected created=true")
	}
	got, _ := os.Readlink(link)
	if got != target {
		t.Errorf("link target: %q", got)
	}
}

func TestIdempotentSymlinkRepoint(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	link := filepath.Join(dir, "link")
	_ = os.WriteFile(a, []byte(""), 0644)
	_ = os.WriteFile(b, []byte(""), 0644)
	_ = os.Symlink(a, link)

	created, err := IdempotentSymlink(b, link)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("repoint should not report created=true")
	}
	got, _ := os.Readlink(link)
	if got != b {
		t.Errorf("link target after repoint: %q", got)
	}
}

func TestIdempotentSymlinkAlreadyCorrect(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	_ = os.WriteFile(target, []byte(""), 0644)
	_ = os.Symlink(target, link)

	created, err := IdempotentSymlink(target, link)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("no-op should not report created=true")
	}
}

func TestIdempotentSymlinkRefusesFile(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	_ = os.WriteFile(link, []byte("not a link"), 0644)
	_, err := IdempotentSymlink("anywhere", link)
	if err == nil {
		t.Fatal("expected error refusing to overwrite regular file")
	}
}

func TestFlockSerializes(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "lock")

	// First holder
	rel1, err := Flock(lock)
	if err != nil {
		t.Fatal(err)
	}

	// Second attempt: should block until rel1 is called.
	got := make(chan struct{})
	go func() {
		rel2, err := Flock(lock)
		if err != nil {
			t.Errorf("second flock: %v", err)
			return
		}
		close(got)
		rel2()
	}()

	select {
	case <-got:
		t.Fatal("second flock should have blocked while first was held")
	case <-time.After(100 * time.Millisecond):
		// expected
	}

	rel1()
	select {
	case <-got:
		// expected — second should now succeed
	case <-time.After(2 * time.Second):
		t.Fatal("second flock did not acquire after release")
	}
}

func TestFlockReentrantSerial(t *testing.T) {
	// Acquire and release sequentially within a single process.
	dir := t.TempDir()
	lock := filepath.Join(dir, "lock")
	rel, err := Flock(lock)
	if err != nil {
		t.Fatal(err)
	}
	rel()

	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			rel, err := Flock(lock)
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			defer rel()
			time.Sleep(10 * time.Millisecond)
		})
	}
	wg.Wait()
}
