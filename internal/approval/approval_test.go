package approval

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newTestBroker() (*Broker, *clock) {
	c := &clock{t: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	return NewBroker(Options{PendingTTL: 10 * time.Minute, UseWindow: 2 * time.Minute, MaxPendingPerPrincipal: 2, Now: c.now}), c
}

var args = map[string]any{"namespace": "payments", "deployment": "api", "replicas": 3.0}

func TestApproveThenConsumeOnce(t *testing.T) {
	b, _ := newTestBroker()
	r, err := b.Create("agent", "k8s_scale", args, args, "traffic spike")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.ID) != 20 || r.Status != Pending {
		t.Fatalf("unexpected request %+v", r)
	}
	if _, err := b.Consume(r.ID, "agent", "k8s_scale", args); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("consume before approval: got %v", err)
	}
	if _, err := b.Decide(r.ID, "alice", true, "ok"); err != nil {
		t.Fatal(err)
	}
	got, err := b.Consume(r.ID, "agent", "k8s_scale", args)
	if err != nil || got.DecidedBy != "alice" {
		t.Fatalf("consume: %v %+v", err, got)
	}
	if _, err := b.Consume(r.ID, "agent", "k8s_scale", args); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("second consume: got %v, want not approved (used)", err)
	}
}

func TestApprovalIsBoundToTheCall(t *testing.T) {
	b, _ := newTestBroker()
	r, _ := b.Create("agent", "k8s_scale", args, args, "")
	_, _ = b.Decide(r.ID, "alice", true, "")
	other := map[string]any{"namespace": "payments", "deployment": "api", "replicas": 0.0}
	cases := []struct {
		name, principal, tool string
		args                  map[string]any
	}{
		{"different args", "agent", "k8s_scale", other},
		{"different tool", "agent", "k8s_rollout_restart", args},
		{"different principal", "agent-2", "k8s_scale", args},
	}
	for _, tc := range cases {
		if _, err := b.Consume(r.ID, tc.principal, tc.tool, tc.args); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: got %v, want mismatch", tc.name, err)
		}
	}
	// The original call still works after the failed attempts.
	if _, err := b.Consume(r.ID, "agent", "k8s_scale", args); err != nil {
		t.Fatalf("original call: %v", err)
	}
}

func TestSelfApprovalAndEmptyApprover(t *testing.T) {
	b, _ := newTestBroker()
	r, _ := b.Create("agent", "k8s_scale", args, args, "")
	for _, who := range []string{"agent", "", "  "} {
		if _, err := b.Decide(r.ID, who, true, ""); !errors.Is(err, ErrSelfApproval) {
			t.Errorf("approver %q: got %v", who, err)
		}
	}
}

func TestDenyAndDecideTwice(t *testing.T) {
	b, _ := newTestBroker()
	r, _ := b.Create("agent", "k8s_scale", args, args, "")
	if _, err := b.Decide(r.ID, "alice", false, "no"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Decide(r.ID, "bob", true, ""); !errors.Is(err, ErrNotPending) {
		t.Fatalf("got %v", err)
	}
	if _, err := b.Consume(r.ID, "agent", "k8s_scale", args); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("got %v", err)
	}
	if _, err := b.Decide("apr_missing", "alice", true, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestExpiry(t *testing.T) {
	b, c := newTestBroker()
	r, _ := b.Create("agent", "k8s_scale", args, args, "")
	c.add(11 * time.Minute)
	if _, err := b.Decide(r.ID, "alice", true, ""); !errors.Is(err, ErrExpired) {
		t.Fatalf("decide after TTL: got %v", err)
	}

	r2, _ := b.Create("agent", "k8s_scale", args, args, "")
	_, _ = b.Decide(r2.ID, "alice", true, "")
	c.add(3 * time.Minute)
	if _, err := b.Consume(r2.ID, "agent", "k8s_scale", args); !errors.Is(err, ErrExpired) {
		t.Fatalf("consume after use window: got %v", err)
	}
	c.add(2 * time.Hour)
	if _, err := b.Get(r2.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old request should be forgotten, got %v", err)
	}
}

func TestDuplicateCreateAndPendingLimit(t *testing.T) {
	b, _ := newTestBroker()
	r1, _ := b.Create("agent", "k8s_scale", args, args, "")
	again, _ := b.Create("agent", "k8s_scale", args, args, "")
	if again.ID != r1.ID {
		t.Fatalf("identical request should be reused")
	}
	_, err := b.Create("agent", "k8s_scale", map[string]any{"replicas": 4.0}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Create("agent", "k8s_scale", map[string]any{"replicas": 5.0}, nil, ""); !errors.Is(err, ErrTooManyPending) {
		t.Fatalf("got %v", err)
	}
	if _, err := b.Create("other-agent", "k8s_scale", args, args, ""); err != nil {
		t.Fatalf("limit is per principal: %v", err)
	}
	if n := len(b.List(Pending)); n != 3 {
		t.Fatalf("pending: %d", n)
	}
}

func TestDigestIsStable(t *testing.T) {
	a, _ := Digest("p", "t", map[string]any{"b": 1.0, "a": "x"})
	b, _ := Digest("p", "t", map[string]any{"a": "x", "b": 1.0})
	if a != b {
		t.Fatal("digest depends on map order")
	}
}

func TestConcurrentConsumeOnlyOneWins(t *testing.T) {
	b, _ := newTestBroker()
	r, _ := b.Create("agent", "k8s_scale", args, args, "")
	_, _ = b.Decide(r.ID, "alice", true, "")
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := b.Consume(r.ID, "agent", "k8s_scale", args); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d consumers succeeded, want 1", wins)
	}
}
