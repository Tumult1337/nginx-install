package nginx

import (
	"errors"
	"strings"
	"testing"
)

type fakeExec struct {
	wantName string
	wantArgs []string
	out      []byte
	err      error
	calls    int
}

func (f *fakeExec) Run(name string, args ...string) ([]byte, error) {
	f.calls++
	if name != f.wantName {
		return nil, errors.New("unexpected command: " + name)
	}
	if len(args) != len(f.wantArgs) {
		return nil, errors.New("wrong arg count")
	}
	for i, a := range args {
		if a != f.wantArgs[i] {
			return nil, errors.New("wrong arg")
		}
	}
	return f.out, f.err
}

func (f *fakeExec) RunEnv(name string, _ []string, args ...string) ([]byte, error) {
	return f.Run(name, args...)
}

func (f *fakeExec) RunDir(_, name string, args ...string) ([]byte, error) {
	return f.Run(name, args...)
}

func TestTestSuccess(t *testing.T) {
	f := &fakeExec{wantName: "nginx", wantArgs: []string{"-t"}, out: []byte("ok\n")}
	if err := Test(f); err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 {
		t.Errorf("calls: %d", f.calls)
	}
}

func TestTestFailureWrapsOutput(t *testing.T) {
	f := &fakeExec{
		wantName: "nginx",
		wantArgs: []string{"-t"},
		out:      []byte("emerg: invalid directive at line 42\n"),
		err:      errors.New("exit status 1"),
	}
	err := Test(f)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "line 42") {
		t.Errorf("error should include nginx output: %v", err)
	}
}

func TestReloadCallsSystemctl(t *testing.T) {
	f := &fakeExec{wantName: "systemctl", wantArgs: []string{"reload", "nginx"}}
	if err := Reload(f); err != nil {
		t.Fatal(err)
	}
}
