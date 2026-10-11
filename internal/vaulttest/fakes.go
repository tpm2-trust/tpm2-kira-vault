package vaulttest

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/mrwiora/tpm2-kira-vault/internal/keys"
)

// Clock is a clock tests move by hand.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock starts at a fixed time.
func NewClock() *Clock { return &Clock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)} }

// Now implements the server's clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock on.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Sealer is a keys.Sealer without a TPM: it encrypts under a key of its
// own, and records the boot state ("epoch") it sealed in. ChangeBoot moves
// the boot state on: what was sealed before with PCRs no longer unseals, as
// in a TPM whose PCRs moved.
type Sealer struct {
	mu    sync.Mutex
	key   []byte
	epoch byte
	Seals int
}

// NewSealer makes a fake sealer.
func NewSealer() *Sealer {
	k := make([]byte, keys.KeySize)
	rand.Read(k)
	return &Sealer{key: k}
}

// ChangeBoot moves the vault's boot state on.
func (s *Sealer) ChangeBoot() {
	s.mu.Lock()
	s.epoch++
	s.mu.Unlock()
}

// Seal implements keys.Sealer.
func (s *Sealer) Seal(secret []byte, pcrs []uint8) (*keys.Sealed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Seals++
	ct, err := keys.Encrypt(s.key, secret, nil)
	if err != nil {
		return nil, err
	}
	return &keys.Sealed{PCRs: append([]uint8{}, pcrs...), Public: []byte{s.epoch}, Private: ct}, nil
}

// Unseal implements keys.Sealer.
func (s *Sealer) Unseal(sl *keys.Sealed) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(sl.PCRs) > 0 && (len(sl.Public) != 1 || sl.Public[0] != s.epoch) {
		return nil, keys.ErrBootStateChanged
	}
	return keys.Decrypt(s.key, sl.Private, nil)
}
