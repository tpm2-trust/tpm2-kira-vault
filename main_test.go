package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/vaultproto"

	"github.com/mrwiora/tpm2-kira-vault/internal/keys"
	"github.com/mrwiora/tpm2-kira-vault/internal/state"
	"github.com/mrwiora/tpm2-kira-vault/internal/vaulttest"
)

// vault is a state directory made by init, and serve running on it.
type vault struct {
	t        *testing.T
	dir      string
	sock     string
	url      string
	pin      string
	recovery string
	stop     func()
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// cli runs the command line and returns its output.
func cli(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := run(args, strings.NewReader(stdin), &out, &errOut)
	return out.String() + errOut.String(), err
}

var (
	pinRE      = regexp.MustCompile(`pin:\s+(sha256:[0-9a-f]{64})`)
	recoveryRE = regexp.MustCompile(`\n    ([A-Z2-7]{4}(?:-[A-Z2-7]{1,4}){12})\n`)
	tokenRE    = regexp.MustCompile(`token:\s+(\S+)`)
)

// initVault runs init with these extra arguments.
func initVault(t *testing.T, extra ...string) *vault {
	t.Helper()
	dir := t.TempDir()
	addr := freePort(t)
	v := &vault{t: t, dir: filepath.Join(dir, "state"), sock: filepath.Join(dir, "admin.sock"), url: "https://" + addr}
	out, err := cli(t, "", append([]string{"init", "--dir", v.dir, "--listen", addr, "--url", v.url, "--admin-socket", v.sock}, extra...)...)
	if err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	m := pinRE.FindStringSubmatch(out)
	r := recoveryRE.FindStringSubmatch(out)
	if m == nil || r == nil {
		t.Fatalf("init output:\n%s", out)
	}
	v.pin, v.recovery = m[1], r[1]
	return v
}

// start runs serve until stop.
func (v *vault) start() {
	v.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- serve(ctx, state.Dir{Path: v.dir}, io.Discard, ready) }()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		v.t.Fatalf("serve: %v", err)
	}
	v.stop = func() {
		cancel()
		if err := <-done; err != nil {
			v.t.Errorf("serve: %v", err)
		}
		v.stop = nil
	}
	v.t.Cleanup(func() {
		if v.stop != nil {
			v.stop()
		}
	})
}

func (v *vault) client() *vaulttest.Client { return vaulttest.NewClient(v.url, v.pin) }

// enrol creates a token with the CLI and enrols a machine with it.
func (v *vault) enrol(name string) *vaulttest.Machine {
	v.t.Helper()
	out, err := cli(v.t, "", "token", "create", "--name", name, "--socket", v.sock)
	if err != nil {
		v.t.Fatalf("token create: %v\n%s", err, out)
	}
	tok := tokenRE.FindStringSubmatch(out)
	if tok == nil || !strings.Contains(out, "tpm2-kira vault enrol --url "+v.url+" --pin "+v.pin+" --token "+tok[1]) {
		v.t.Fatalf("token create output:\n%s", out)
	}
	m, err := vaulttest.NewMachine(name)
	if err != nil {
		v.t.Fatal(err)
	}
	if _, err := m.Enrol(v.client(), tok[1]); err != nil {
		v.t.Fatalf("enrol: %v", err)
	}
	return m
}

func (v *vault) release(m *vaulttest.Machine) *vaultproto.ReleaseResponse {
	v.t.Helper()
	_, res, err := m.Release(v.client())
	if err != nil {
		v.t.Fatalf("release: %v", err)
	}
	return res
}

func wantReleased(t *testing.T, m *vaulttest.Machine, res *vaultproto.ReleaseResponse) {
	t.Helper()
	if res.Status != vaultproto.StatusReleased {
		t.Fatalf("got %s (%s), want released", res.Status, res.Reason)
	}
	if r, err := m.Open(res.Remote); err != nil || !bytes.Equal(r, m.R) {
		t.Fatalf("the released part does not open: %v", err)
	}
}

// useSealer makes the commands seal with s.
func useSealer(t *testing.T, s keys.Sealer) {
	old := newSealer
	newSealer = func(string) keys.Sealer { return s }
	t.Cleanup(func() { newSealer = old })
}

// init, serve, the admin commands and reseal, end to end, with a sealer
// whose boot state the test moves.
func TestCommands(t *testing.T) {
	sealer := vaulttest.NewSealer()
	useSealer(t, sealer)
	v := initVault(t)
	if _, err := cli(t, "", "init", "--dir", v.dir, "--url", v.url); err == nil || !strings.Contains(err.Error(), "holds a vault already") {
		t.Fatalf("init twice: %v", err)
	}

	v.start()
	m := v.enrol("db-03")
	wantReleased(t, m, v.release(m))

	// init and reseal refuse while serve runs.
	if _, err := cli(t, v.recovery+"\n", "reseal", "--dir", v.dir); !errors.Is(err, state.ErrLocked) {
		t.Fatalf("reseal while serving: %v", err)
	}

	out, err := cli(t, "", "devices", "--dir", v.dir)
	if err != nil || !strings.Contains(out, "db-03") || !strings.Contains(out, "active") {
		t.Fatalf("devices: %v\n%s", err, out)
	}
	if out, err = cli(t, "", "device", "revoke", "db-03", "--socket", v.sock); err != nil || !strings.Contains(out, "revoked") {
		t.Fatalf("revoke: %v\n%s", err, out)
	}
	if res := v.release(m); res.Status != vaultproto.StatusDenied {
		t.Fatalf("a revoked device: %s", res.Status)
	}
	cli(t, "", "device", "unrevoke", "db-03", "--socket", v.sock)
	if out, err = cli(t, "", "device", "mode", "db-03", "approve", "--socket", v.sock); err != nil || !strings.Contains(out, "approve") {
		t.Fatalf("mode: %v\n%s", err, out)
	}
	req, res, err := m.Release(v.client())
	if err != nil || res.Status != vaultproto.StatusPending {
		t.Fatalf("approve mode: %v %+v", err, res)
	}
	if out, err = cli(t, "", "requests", "--socket", v.sock); err != nil || !strings.Contains(out, req.RequestID) {
		t.Fatalf("requests: %v\n%s", err, out)
	}
	if out, err = cli(t, "", "request", "approve", req.RequestID, "--socket", v.sock); err != nil || !strings.Contains(out, "approved") {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	res, err = v.client().Send(req)
	if err != nil {
		t.Fatal(err)
	}
	wantReleased(t, m, res)
	cli(t, "", "device", "mode", "db-03", "auto", "--socket", v.sock)
	if out, err = cli(t, "", "audit", "--socket", v.sock); err != nil || !strings.Contains(out, "released") || !strings.Contains(out, "approve  done") {
		t.Fatalf("audit: %v\n%s", err, out)
	}
	if _, err = cli(t, "", "device", "show", "nothing", "--socket", v.sock); err == nil || !strings.Contains(err.Error(), "no device") {
		t.Fatalf("show an unknown device: %v", err)
	}

	// The vault boots in another state: denied with advice, until reseal.
	v.stop()
	sealer.ChangeBoot()
	v.start()
	res = v.release(m)
	if res.Status != vaultproto.StatusDenied || res.Reason != "the vault's own boot state changed: run reseal" {
		t.Fatalf("after the vault's boot changed: %+v", res)
	}
	v.stop()
	if _, err := cli(t, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA\n", "reseal", "--dir", v.dir); err == nil || !strings.Contains(err.Error(), "not this vault's recovery key") {
		t.Fatalf("reseal with another key: %v", err)
	}
	if out, err := cli(t, strings.ToLower(v.recovery)+"\n", "reseal", "--dir", v.dir); err != nil || !strings.Contains(out, "Resealed 1 device keys to the vault's PCRs 7") {
		t.Fatalf("reseal: %v\n%s", err, out)
	}
	v.start()
	wantReleased(t, m, v.release(m))
	v.stop()

	// Reseal to no PCRs warns, and is kept in the configuration.
	out, err = cli(t, v.recovery+"\n", "reseal", "--dir", v.dir, "--pcrs", "")
	if err != nil || !strings.Contains(out, "Warning: the vault's selection is empty") {
		t.Fatalf("reseal to no PCRs: %v\n%s", err, out)
	}
	cfg, _ := state.Dir{Path: v.dir}.Config()
	if len(cfg.PCRs) != 0 {
		t.Fatalf("configured PCRs %v", cfg.PCRs)
	}
}

func TestParsePCRs(t *testing.T) {
	for in, want := range map[string]string{"7": "7", "14, 7,0,7": "0,7,14", "": "none"} {
		got, err := parsePCRs(in)
		if err != nil || formatPCRs(got) != want {
			t.Fatalf("%q: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"24", "x", "-1"} {
		if _, err := parsePCRs(bad); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
	if out, err := cli(t, "", "help"); err != nil || !strings.Contains(out, "token create") {
		t.Fatalf("help: %v", err)
	}
}
