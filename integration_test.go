//go:build integration

package main

import (
	"testing"

	"github.com/mrwiora/tpm2-kira/vaultproto"

	"github.com/mrwiora/tpm2-kira-vault/internal/state"
	"github.com/mrwiora/tpm2-kira-vault/internal/vaulttest"
)

// The vault on a software TPM: a release, the vault's PCR 23 moves and the
// release is denied with "run reseal" (the device not held responsible),
// reseal with the recovery key, a release again. A device enrolled with a
// pepper is approved over the operator interface with it, and released
// with it.
func TestVaultOnSWTPM(t *testing.T) {
	sock := vaulttest.StartSWTPM(t)
	v := initVault(t, "--tpm", sock, "--pcrs", "7,23", "--operator-listen", freePort(t))
	v.start()
	m := v.enrol("db-03")
	wantReleased(t, m, v.release(m))
	alice := v.operator("alice")
	p := v.enrolWith("db-04", true)
	res := approve(t, v, alice, p, `{"pepper":"from the operator"}`)
	wantReleased(t, p, res)
	if string(res.Pepper) != "from the operator" {
		t.Fatalf("released pepper %q", res.Pepper)
	}

	vaulttest.ExtendPCR(t, sock, 23, "another boot of the vault")
	for i := 0; i < 6; i++ {
		res := v.release(m)
		if res.Status != vaultproto.StatusDenied || res.Reason != "the vault's own boot state changed: run reseal" {
			t.Fatalf("after PCR 23 moved: %+v", res)
		}
	}
	v.stop()
	d, _ := state.Dir{Path: v.dir}.Devices()
	if len(d) != 2 || d[0].Locked || d[0].Failures != 0 {
		t.Fatalf("the device after the vault's denials: %+v", d)
	}

	if out, err := cli(t, v.recovery+"\n", "reseal", "--dir", v.dir); err != nil {
		t.Fatalf("reseal: %v\n%s", err, out)
	}
	v.start()
	wantReleased(t, m, v.release(m))
	res = approve(t, v, alice, p, `{"pepper":"from the operator"}`)
	wantReleased(t, p, res)
	if string(res.Pepper) != "from the operator" {
		t.Fatalf("released pepper after reseal %q", res.Pepper)
	}
}
