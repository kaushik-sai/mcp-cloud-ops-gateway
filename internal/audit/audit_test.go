package audit

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func writeN(t *testing.T, path string, n int) {
	t.Helper()
	l, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < n; i++ {
		if _, err := l.Write(Record{Event: "decision", Principal: "agent", Tool: "k8s_get", Args: map[string]any{"n": float64(i)}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainVerifiesAndContinuesAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeN(t, path, 3)
	writeN(t, path, 2) // reopen continues the chain
	res, err := VerifyFile(path)
	if err != nil || res.Broken || res.Records != 5 {
		t.Fatalf("got %+v, %v", res, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestTamperingIsDetected(t *testing.T) {
	cases := map[string]func(lines []string) []string{
		"edited field": func(l []string) []string { l[1] = strings.Replace(l[1], `"k8s_get"`, `"k8s_scale"`, 1); return l },
		"deleted line": func(l []string) []string { return append(l[:1], l[2:]...) },
		"swapped":      func(l []string) []string { l[0], l[1] = l[1], l[0]; return l },
		"garbage":      func(l []string) []string { l[2] = "{not json"; return l },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			writeN(t, path, 4)
			data, _ := os.ReadFile(path)
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			lines = mutate(lines)
			if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := VerifyFile(path)
			if err != nil || !res.Broken {
				t.Fatalf("tampering not detected: %+v %v", res, err)
			}
			if _, err := Open(path, nil); err == nil {
				t.Fatal("Open must refuse a broken log")
			}
		})
	}
}

func TestConcurrentWritesKeepTheChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var mirror strings.Builder
	var mu sync.Mutex
	l, err := Open(path, writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return mirror.Write(p) }))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = l.Write(Record{Event: "x"}) }()
	}
	wg.Wait()
	_ = l.Close()
	res, err := VerifyFile(path)
	if err != nil || res.Broken || res.Records != 40 {
		t.Fatalf("got %+v %v", res, err)
	}
	if strings.Count(mirror.String(), "\n") != 40 {
		t.Fatal("mirror did not get every record")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
