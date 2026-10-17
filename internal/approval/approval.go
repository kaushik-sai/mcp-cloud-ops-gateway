// Package approval holds human approvals for tool calls whose policy effect is "ask".
//
// The flow: the gateway creates a pending request and tells the agent its id. A human approves or
// denies it through the admin API, which agents cannot reach (separate listener, separate token).
// The agent then repeats the call with the approval id. The approval is bound to a digest of the
// principal, tool and arguments, so it cannot be reused for a different call; it is single use and
// expires. The requester can never approve their own request.
package approval

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Status is the life-cycle state of a request.
type Status string

const (
	Pending  Status = "pending"
	Approved Status = "approved"
	Denied   Status = "denied"
	Used     Status = "used"
	Expired  Status = "expired"
)

var (
	ErrNotFound       = errors.New("approval not found")
	ErrNotPending     = errors.New("approval is not pending")
	ErrNotApproved    = errors.New("approval has not been approved")
	ErrExpired        = errors.New("approval expired")
	ErrMismatch       = errors.New("approval was granted for a different call")
	ErrSelfApproval   = errors.New("the requester cannot approve their own request")
	ErrTooManyPending = errors.New("too many pending approvals for this principal")
)

// Request is one approval. Args is a redacted copy kept for display to the approver.
type Request struct {
	ID            string         `json:"id"`
	Principal     string         `json:"principal"`
	Tool          string         `json:"tool"`
	Args          map[string]any `json:"args"`
	Justification string         `json:"justification,omitempty"`
	Digest        string         `json:"digest"`
	Status        Status         `json:"status"`
	CreatedAt     time.Time      `json:"created_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	DecidedBy     string         `json:"decided_by,omitempty"`
	DecidedAt     *time.Time     `json:"decided_at,omitempty"`
	Note          string         `json:"note,omitempty"`
}

// Options configure a Broker. Zero values get safe defaults.
type Options struct {
	// PendingTTL is how long a request waits for a decision. Default 15 minutes.
	PendingTTL time.Duration
	// UseWindow is how long an approved request stays usable after the decision. Default 5 minutes.
	UseWindow time.Duration
	// MaxPendingPerPrincipal bounds the queue an agent can create. Default 20.
	MaxPendingPerPrincipal int
	// Now is the clock; tests replace it.
	Now func() time.Time
}

// Broker is an in-memory approval store. It is safe for concurrent use.
type Broker struct {
	mu    sync.Mutex
	items map[string]*Request
	opt   Options
}

// NewBroker returns a Broker with defaults filled in.
func NewBroker(opt Options) *Broker {
	if opt.PendingTTL <= 0 {
		opt.PendingTTL = 15 * time.Minute
	}
	if opt.UseWindow <= 0 {
		opt.UseWindow = 5 * time.Minute
	}
	if opt.MaxPendingPerPrincipal <= 0 {
		opt.MaxPendingPerPrincipal = 20
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &Broker{items: map[string]*Request{}, opt: opt}
}

// Digest binds an approval to one exact call. encoding/json writes map keys in sorted order, so
// the same arguments always give the same digest.
func Digest(principal, tool string, args map[string]any) (string, error) {
	canon, err := json.Marshal(struct {
		P string         `json:"p"`
		T string         `json:"t"`
		A map[string]any `json:"a"`
	}{principal, tool, args})
	if err != nil {
		return "", fmt.Errorf("digest: %w", err)
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// Create opens a pending request, or returns the existing pending one for the same call so an
// agent that retries does not flood the approver.
func (b *Broker) Create(principal, tool string, args, displayArgs map[string]any, justification string) (*Request, error) {
	digest, err := Digest(principal, tool, args)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked()

	pending := 0
	for _, r := range b.items {
		if r.Principal != principal || r.Status != Pending {
			continue
		}
		if r.Digest == digest {
			c := *r
			return &c, nil
		}
		pending++
	}
	if pending >= b.opt.MaxPendingPerPrincipal {
		return nil, ErrTooManyPending
	}

	now := b.opt.Now()
	r := &Request{
		ID:            newID(),
		Principal:     principal,
		Tool:          tool,
		Args:          displayArgs,
		Justification: justification,
		Digest:        digest,
		Status:        Pending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(b.opt.PendingTTL),
	}
	b.items[r.ID] = r
	c := *r
	return &c, nil
}

// Decide records a human decision on a pending request.
func (b *Broker) Decide(id, approver string, approve bool, note string) (*Request, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked()

	r, ok := b.items[id]
	if !ok {
		return nil, ErrNotFound
	}
	if r.Status == Expired {
		return nil, ErrExpired
	}
	if r.Status != Pending {
		return nil, ErrNotPending
	}
	if strings.TrimSpace(approver) == "" || approver == r.Principal {
		return nil, ErrSelfApproval
	}
	now := b.opt.Now()
	r.DecidedBy, r.DecidedAt, r.Note = approver, &now, note
	if approve {
		r.Status = Approved
		r.ExpiresAt = now.Add(b.opt.UseWindow)
	} else {
		r.Status = Denied
	}
	c := *r
	return &c, nil
}

// Consume checks that id approves exactly this call and marks it used. It returns the request so
// the caller can audit who approved it.
func (b *Broker) Consume(id, principal, tool string, args map[string]any) (*Request, error) {
	digest, err := Digest(principal, tool, args)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked()

	r, ok := b.items[id]
	if !ok {
		return nil, ErrNotFound
	}
	switch r.Status {
	case Approved:
	case Expired:
		return nil, ErrExpired
	default:
		return nil, fmt.Errorf("%w (status %s)", ErrNotApproved, r.Status)
	}
	if r.Digest != digest {
		return nil, ErrMismatch
	}
	r.Status = Used
	c := *r
	return &c, nil
}

// Get returns a copy of one request.
func (b *Broker) Get(id string) (*Request, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked()
	r, ok := b.items[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *r
	return &c, nil
}

// List returns copies of the requests with the given status (all when status is empty), oldest
// first.
func (b *Broker) List(status Status) []Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked()
	out := make([]Request, 0, len(b.items))
	for _, r := range b.items {
		if status == "" || r.Status == status {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// expireLocked marks overdue pending and approved requests as expired and forgets finished
// requests after an hour, so memory stays bounded.
func (b *Broker) expireLocked() {
	now := b.opt.Now()
	for id, r := range b.items {
		if (r.Status == Pending || r.Status == Approved) && now.After(r.ExpiresAt) {
			r.Status = Expired
		}
		if r.Status != Pending && r.Status != Approved && now.Sub(r.ExpiresAt) > time.Hour {
			delete(b.items, id)
		}
	}
}

func newID() string {
	var buf [10]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return "apr_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf[:]))
}
