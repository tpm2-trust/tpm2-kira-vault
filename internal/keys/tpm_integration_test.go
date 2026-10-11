//go:build integration

package keys_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/mrwiora/tpm2-kira-vault/internal/keys"
	"github.com/mrwiora/tpm2-kira-vault/internal/vaulttest"
)

// K_dev seals under PolicyPCR, unseals while the PCRs hold, is refused
// with ErrBootStateChanged once one moves, and unseals again after a seal
// to the new values.
func TestTPMSealer(t *testing.T) {
	sock := vaulttest.StartSWTPM(t)
	s := &keys.TPMSealer{Path: sock}
	kdev, _ := keys.NewKey()

	sealed, err := s.Seal(kdev, []uint8{7, 23})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Unseal(sealed)
	if err != nil || !bytes.Equal(got, kdev) {
		t.Fatalf("unseal: %v", err)
	}
	plain, err := s.Seal(kdev, nil)
	if err != nil {
		t.Fatal(err)
	}

	vaulttest.ExtendPCR(t, sock, 23, "another boot of the vault")
	if _, err := s.Unseal(sealed); !errors.Is(err, keys.ErrBootStateChanged) {
		t.Fatalf("after the PCR moved: %v", err)
	}
	if got, err := s.Unseal(plain); err != nil || !bytes.Equal(got, kdev) {
		t.Fatalf("a seal without PCRs: %v", err)
	}

	resealed, err := s.Seal(kdev, []uint8{7, 23})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Unseal(resealed); err != nil || !bytes.Equal(got, kdev) {
		t.Fatalf("after resealing: %v", err)
	}
	if bytes.Equal(resealed.Public, sealed.Public) {
		t.Fatal("the reseal has the old policy")
	}
}
