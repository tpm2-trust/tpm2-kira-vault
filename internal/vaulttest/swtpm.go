package vaulttest

import (
	"crypto/sha256"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/tpm2-trust/tpm2-kira-vault/internal/keys"
)

// StartSWTPM runs a fresh software TPM for the test and returns its socket.
// It skips the test when swtpm is not installed.
func StartSWTPM(t testing.TB) string {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "swtpm.sock")
	cmd := exec.Command("swtpm", "socket", "--tpm2",
		"--tpmstate", "dir="+dir,
		"--server", "type=unixio,path="+sock,
		"--ctrl", "type=unixio,path="+sock+".ctrl",
		"--flags", "not-need-init,startup-clear")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	// Wait until it accepts a connection; the deadline bounds a failure.
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.Dial("unix", sock+".ctrl")
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("swtpm does not answer: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return sock
}

// ExtendPCR extends a SHA-256 PCR of the TPM at path, as a boot measures.
func ExtendPCR(t testing.TB, path string, pcr int, data string) {
	t.Helper()
	tpm, err := keys.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	sum := sha256.Sum256([]byte(data))
	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcr), Auth: tpm2.PasswordAuth(nil)},
		Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: sum[:]}}},
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("extending PCR %d: %v", pcr, err)
	}
}
