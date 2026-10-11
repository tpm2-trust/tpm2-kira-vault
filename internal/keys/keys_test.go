package keys

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncrypt(t *testing.T) {
	k, _ := NewKey()
	ct, err := Encrypt(k, []byte("wrapped R"), []byte("device"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := Decrypt(k, ct, []byte("device")); err != nil || string(pt) != "wrapped R" {
		t.Fatalf("%q %v", pt, err)
	}
	if _, err := Decrypt(k, ct, []byte("another device")); err == nil {
		t.Fatal("opened under another AAD")
	}
	other, _ := NewKey()
	if _, err := Decrypt(other, ct, []byte("device")); err == nil {
		t.Fatal("opened under another key")
	}
}

func TestRecoveryKey(t *testing.T) {
	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := rk.Public()
	kdev, _ := NewKey()
	blob, err := EncryptToRecovery(pub, kdev, []byte("device"))
	if err != nil {
		t.Fatal(err)
	}

	// What is written down reads back, in any case and spacing.
	s := rk.String()
	if len(strings.ReplaceAll(s, "-", "")) != 52 {
		t.Fatalf("recovery key %q", s)
	}
	back, err := ParseRecoveryKey(" " + strings.ToLower(strings.ReplaceAll(s, "-", " ")) + "\n")
	if err != nil || *back != *rk {
		t.Fatalf("parse: %v", err)
	}
	got, err := back.Open(blob, []byte("device"))
	if err != nil || !bytes.Equal(got, kdev) {
		t.Fatalf("open: %v", err)
	}
	if _, err := back.Open(blob, []byte("another device")); err == nil {
		t.Fatal("opened under another AAD")
	}
	other, _ := NewRecoveryKey()
	if _, err := other.Open(blob, []byte("device")); err == nil {
		t.Fatal("another recovery key opened the copy")
	}
	if _, err := ParseRecoveryKey("ABCD-EFGH"); err == nil {
		t.Fatal("a short key parsed")
	}
}
