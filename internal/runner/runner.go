// Package runner runs external CLIs (kubectl, terraform, aws, az) for the tools.
//
// It is the one wrapper around os/exec, so tests replace it with a fake and need no CLI, cluster
// or cloud account. Commands never go through a shell: every argument is passed as its own argv
// element, so an argument cannot inject a second command. The child gets a minimal environment
// (PATH, HOME and what the credential provider adds), not the gateway's own, so the gateway's
// secrets do not leak into tools.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"time"
)

// Cmd is one command to run.
type Cmd struct {
	Name string
	Args []string
	Env  map[string]string
	Dir  string
}

// Result is what the command produced. Output beyond the runner's limit is cut and Truncated set.
type Result struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Duration  time.Duration
	Truncated bool
}

// Runner runs commands.
type Runner interface {
	Run(ctx context.Context, c Cmd) (Result, error)
}

// Exec runs commands with os/exec.
type Exec struct {
	// Timeout bounds each command. Default 60 seconds.
	Timeout time.Duration
	// MaxOutput bounds stdout and stderr each, in bytes. Default 1 MiB.
	MaxOutput int
	// BaseEnv is copied into every child environment. Default: PATH and HOME from the gateway.
	BaseEnv map[string]string
}

// Run executes c and waits for it. A non-zero exit is not an error: it is reported in ExitCode so
// the tool can show stderr to the agent. Errors are reserved for "could not run at all".
func (e Exec) Run(ctx context.Context, c Cmd) (Result, error) {
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	limit := e.MaxOutput
	if limit <= 0 {
		limit = 1 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.Name, c.Args...) // #nosec G204 -- argv only, no shell; names come from code, not input
	cmd.Dir = c.Dir
	cmd.Env = buildEnv(e.baseEnv(), c.Env)
	stdout := &capped{limit: limit}
	stderr := &capped{limit: limit}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	start := time.Now()
	err := cmd.Run()
	res := Result{
		Stdout:    stdout.buf.String(),
		Stderr:    stderr.buf.String(),
		Duration:  time.Since(start),
		Truncated: stdout.cut || stderr.cut,
	}
	if ctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("%s timed out after %s", c.Name, timeout)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("run %s: %w", c.Name, err)
	}
	return res, nil
}

func (e Exec) baseEnv() map[string]string {
	if e.BaseEnv != nil {
		return e.BaseEnv
	}
	return map[string]string{"PATH": os.Getenv("PATH"), "HOME": os.Getenv("HOME")}
}

func buildEnv(base, extra map[string]string) []string {
	merged := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range extra {
		merged[k] = v
	}
	out := make([]string, 0, len(merged))
	for k, v := range merged {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// capped keeps the first limit bytes written and drops the rest, so a huge log cannot exhaust
// the gateway's memory.
type capped struct {
	buf   bytes.Buffer
	limit int
	cut   bool
}

func (c *capped) Write(p []byte) (int, error) {
	room := c.limit - c.buf.Len()
	if room <= 0 {
		c.cut = true
		return len(p), nil
	}
	if len(p) > room {
		c.buf.Write(p[:room])
		c.cut = true
		return len(p), nil
	}
	c.buf.Write(p)
	return len(p), nil
}
