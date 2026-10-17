package runner

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunCapturesOutputAndExitCode(t *testing.T) {
	e := Exec{BaseEnv: map[string]string{"PATH": "/usr/bin:/bin"}}
	r, err := e.Run(context.Background(), Cmd{Name: "sh", Args: []string{"-c", "echo out; echo err >&2; exit 3"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Stdout != "out\n" || r.Stderr != "err\n" || r.ExitCode != 3 {
		t.Fatalf("got %+v", r)
	}
}

func TestArgumentsAreNotInterpretedByAShell(t *testing.T) {
	e := Exec{BaseEnv: map[string]string{"PATH": "/usr/bin:/bin"}}
	r, err := e.Run(context.Background(), Cmd{Name: "echo", Args: []string{"a; touch /tmp/pwned", "$(id)"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Stdout != "a; touch /tmp/pwned $(id)\n" {
		t.Fatalf("got %q", r.Stdout)
	}
}

func TestEnvironmentIsMinimal(t *testing.T) {
	t.Setenv("GATEWAY_SECRET", "do-not-leak")
	e := Exec{BaseEnv: map[string]string{"PATH": "/usr/bin:/bin"}}
	r, err := e.Run(context.Background(), Cmd{Name: "env", Env: map[string]string{"KUBECONFIG": "/k"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.Stdout, "GATEWAY_SECRET") || !strings.Contains(r.Stdout, "KUBECONFIG=/k") {
		t.Fatalf("env: %q", r.Stdout)
	}
}

func TestTimeoutAndCap(t *testing.T) {
	e := Exec{Timeout: 200 * time.Millisecond, BaseEnv: map[string]string{"PATH": "/usr/bin:/bin"}}
	if _, err := e.Run(context.Background(), Cmd{Name: "sleep", Args: []string{"5"}}); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("got %v", err)
	}
	e = Exec{MaxOutput: 5, BaseEnv: map[string]string{"PATH": "/usr/bin:/bin"}}
	r, err := e.Run(context.Background(), Cmd{Name: "echo", Args: []string{"0123456789"}})
	if err != nil || r.Stdout != "01234" || !r.Truncated {
		t.Fatalf("got %+v %v", r, err)
	}
	if _, err := e.Run(context.Background(), Cmd{Name: "definitely-not-a-binary"}); err == nil {
		t.Fatal("missing binary must be an error")
	}
}
