package state

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Entry is one line of the audit log. It never carries a secret: no token,
// no key, no wrapped part.
type Entry struct {
	Time    time.Time `json:"time"`
	Event   string    `json:"event"`
	Device  string    `json:"device,omitempty"` // hex device ID
	Name    string    `json:"name,omitempty"`   // the device's or token's name
	Request string    `json:"request,omitempty"`
	Remote  string    `json:"remote,omitempty"` // the peer's address
	Actor   string    `json:"actor,omitempty"`  // "admin" for the admin interface
	Result  string    `json:"result,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}

// Audit is the append-only audit log. Each line is synced to disk before
// Log returns.
type Audit struct {
	mu   sync.Mutex
	f    *os.File
	size int64
	now  func() time.Time
	subs map[chan Line]struct{}
}

// Line is a written line and the log's size after it.
type Line struct {
	Data []byte
	End  int64
}

// OpenAudit opens (or creates) the audit log for appending. now stamps
// the entries.
func OpenAudit(path string, now func() time.Time) (*Audit, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Audit{f: f, size: st.Size(), now: now, subs: map[chan Line]struct{}{}}, nil
}

// Log appends one entry and syncs it.
func (a *Audit) Log(e Entry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	e.Time = a.now().UTC()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := a.f.Write(b); err != nil {
		return err
	}
	if err := a.f.Sync(); err != nil {
		return err
	}
	a.size += int64(len(b))
	for ch := range a.subs {
		select {
		case ch <- Line{Data: b, End: a.size}:
		default: // a follower that does not keep up misses lines rather than holding the vault
		}
	}
	return nil
}

// Subscribe returns the log's size now and the lines logged from now on,
// until cancel.
func (a *Audit) Subscribe() (int64, <-chan Line, func()) {
	ch := make(chan Line, 256)
	a.mu.Lock()
	a.subs[ch] = struct{}{}
	size := a.size
	a.mu.Unlock()
	return size, ch, func() {
		a.mu.Lock()
		delete(a.subs, ch)
		a.mu.Unlock()
	}
}

// Close closes the log.
func (a *Audit) Close() error { return a.f.Close() }

// CopyAudit writes the first n bytes of the log at path to w.
func CopyAudit(path string, n int64, w io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.CopyN(w, bufio.NewReader(f), n)
	return err
}
