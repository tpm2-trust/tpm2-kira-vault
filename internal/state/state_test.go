package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAndLock(t *testing.T) {
	d := Dir{Path: filepath.Join(t.TempDir(), "vault")}
	if err := d.Create(); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(d.Path); st.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode %v", st.Mode())
	}
	p := filepath.Join(d.Path, "x.json")
	for _, content := range []string{"one", "two"} {
		if err := WriteFile(p, []byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(p)
	st, _ := os.Stat(p)
	if string(b) != "two" || st.Mode().Perm() != 0o600 {
		t.Fatalf("%q %v", b, st.Mode())
	}
	ents, _ := os.ReadDir(d.Path)
	for _, e := range ents {
		if e.Name()[0] == '.' {
			t.Fatalf("a temporary file is left: %s", e.Name())
		}
	}

	unlock, err := d.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Lock(); !errors.Is(err, ErrLocked) {
		t.Fatalf("a second lock: %v", err)
	}
	unlock()
	again, err := d.Lock()
	if err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	again()
}

func TestTokens(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	d.Create()
	h := []byte{1, 2, 3}
	if err := d.PutToken(h, &Token{Name: "a", Mode: "auto"}); err != nil {
		t.Fatal(err)
	}
	if tok, err := d.Token(h); err != nil || tok.Name != "a" {
		t.Fatalf("%+v %v", tok, err)
	}
	if err := d.ConsumeToken(h); err != nil {
		t.Fatal(err)
	}
	if err := d.ConsumeToken(h); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumed twice: %v", err)
	}
	if _, err := d.Token(h); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a consumed token: %v", err)
	}
}
