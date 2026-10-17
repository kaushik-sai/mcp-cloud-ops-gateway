// Package audit writes a tamper-evident log of every tool call.
//
// Each record is one JSON line. A record carries the hash of the record before it, and its own
// hash covers its content plus that link, so editing, deleting or reordering any line breaks the
// chain from that point on. Verify walks a file and reports the first broken link. The chain makes
// tampering detectable, not impossible: ship the log to write-once storage (a SIEM, an S3 bucket
// with object lock) for that.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// GenesisHash is the Prev of the first record.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Record is one audited event. Args are redacted before they get here.
type Record struct {
	Seq        uint64         `json:"seq"`
	Time       time.Time      `json:"time"`
	Event      string         `json:"event"`
	Principal  string         `json:"principal,omitempty"`
	Tool       string         `json:"tool,omitempty"`
	Args       map[string]any `json:"args,omitempty"`
	Decision   string         `json:"decision,omitempty"`
	Rule       string         `json:"rule,omitempty"`
	ApprovalID string         `json:"approval_id,omitempty"`
	Approver   string         `json:"approver,omitempty"`
	Outcome    string         `json:"outcome,omitempty"`
	ExitCode   *int           `json:"exit_code,omitempty"`
	DurationMS int64          `json:"duration_ms,omitempty"`
	OutputHash string         `json:"output_sha256,omitempty"`
	Redactions int            `json:"redactions,omitempty"`
	Injection  bool           `json:"injection_suspected,omitempty"`
	Error      string         `json:"error,omitempty"`
	Prev       string         `json:"prev"`
	Hash       string         `json:"hash"`
}

// Logger appends records to a file and, optionally, mirrors them to another writer (stderr for
// a log shipper). It is safe for concurrent use.
type Logger struct {
	mu     sync.Mutex
	file   *os.File
	mirror io.Writer
	seq    uint64
	prev   string
	now    func() time.Time
}

// Open opens or creates the log at path and continues its chain. It refuses to append to a file
// whose chain is already broken, so tampering is not papered over by new records.
func Open(path string, mirror io.Writer) (*Logger, error) {
	res, err := VerifyFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if res.Broken {
		return nil, fmt.Errorf("audit log %s is broken at line %d: %s; move it aside before starting", path, res.Line, res.Problem)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	prev := res.LastHash
	if prev == "" {
		prev = GenesisHash
	}
	return &Logger{file: f, mirror: mirror, seq: res.Records, prev: prev, now: time.Now}, nil
}

// Write seals r into the chain and appends it.
func (l *Logger) Write(r Record) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	r.Seq = l.seq
	if r.Time.IsZero() {
		r.Time = l.now().UTC()
	}
	r.Prev = l.prev
	h, err := hashRecord(r)
	if err != nil {
		l.seq--
		return r, err
	}
	r.Hash = h
	line, err := json.Marshal(r)
	if err != nil {
		l.seq--
		return r, fmt.Errorf("encode audit record: %w", err)
	}
	line = append(line, '\n')
	if _, err := l.file.Write(line); err != nil {
		l.seq--
		return r, fmt.Errorf("write audit record: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return r, fmt.Errorf("sync audit log: %w", err)
	}
	l.prev = h
	if l.mirror != nil {
		_, _ = l.mirror.Write(line)
	}
	return r, nil
}

// Close closes the file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// hashRecord hashes the record with Hash empty. Struct fields marshal in declaration order and
// map keys sorted, so the encoding is stable.
func hashRecord(r Record) (string, error) {
	r.Hash = ""
	b, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("encode audit record: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Result reports a verification.
type Result struct {
	Records  uint64 `json:"records"`
	LastHash string `json:"last_hash,omitempty"`
	Broken   bool   `json:"broken"`
	Line     int    `json:"line,omitempty"`
	Problem  string `json:"problem,omitempty"`
}

// VerifyFile checks the chain in the file at path.
func VerifyFile(path string) (Result, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	return Verify(f)
}

// Verify checks a chain read from r. It stops at the first problem.
func Verify(r io.Reader) (Result, error) {
	var res Result
	prev := GenesisHash
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return broken(res, line, "not valid JSON"), nil
		}
		if rec.Seq != res.Records+1 {
			return broken(res, line, fmt.Sprintf("sequence %d, want %d", rec.Seq, res.Records+1)), nil
		}
		if rec.Prev != prev {
			return broken(res, line, "prev does not match the hash of the record before"), nil
		}
		want, err := hashRecord(rec)
		if err != nil {
			return res, err
		}
		if rec.Hash != want {
			return broken(res, line, "hash does not match the record content"), nil
		}
		prev = rec.Hash
		res.Records++
		res.LastHash = rec.Hash
	}
	if err := sc.Err(); err != nil {
		return res, fmt.Errorf("read audit log: %w", err)
	}
	return res, nil
}

func broken(res Result, line int, problem string) Result {
	res.Broken, res.Line, res.Problem = true, line, problem
	return res
}
