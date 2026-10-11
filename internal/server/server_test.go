package server_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrwiora/tpm2-kira/vaultproto"

	"github.com/mrwiora/tpm2-kira-vault/internal/keys"
	"github.com/mrwiora/tpm2-kira-vault/internal/server"
	"github.com/mrwiora/tpm2-kira-vault/internal/state"
	"github.com/mrwiora/tpm2-kira-vault/internal/tlsutil"
	"github.com/mrwiora/tpm2-kira-vault/internal/vaulttest"
)

type env struct {
	t      *testing.T
	dir    state.Dir
	cfg    *state.Config
	clock  *vaulttest.Clock
	sealer *vaulttest.Sealer
	rk     *keys.RecoveryKey
	srv    *server.Server
	admin  http.Handler
	ts     *httptest.Server
	pin    string
	client *vaulttest.Client
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, dir: state.Dir{Path: t.TempDir()}, clock: vaulttest.NewClock(), sealer: vaulttest.NewSealer()}
	if err := e.dir.Create(); err != nil {
		t.Fatal(err)
	}
	if err := tlsutil.Write(e.dir, "127.0.0.1", time.Now()); err != nil {
		t.Fatal(err)
	}
	cert, pin, err := tlsutil.Load(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	e.pin = pin
	if e.rk, err = keys.NewRecoveryKey(); err != nil {
		t.Fatal(err)
	}
	rpub, _ := e.rk.Public()
	e.cfg = &state.Config{Listen: ":0", URL: "https://vault.example:8443", PCRs: []uint8{7}, RecoveryPublic: rpub}
	audit, err := state.OpenAudit(e.dir.AuditPath(), e.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	e.srv = server.New(server.Options{Dir: e.dir, Config: e.cfg, Sealer: e.sealer, Audit: audit, Pin: pin, Now: e.clock.Now})
	e.admin = e.srv.AdminHandler()
	e.ts = httptest.NewUnstartedServer(e.srv.MachineHandler())
	e.ts.TLS = tlsutil.ServerConfig(cert)
	e.ts.Config.ErrorLog = log.New(io.Discard, "", 0) // the refused handshake of TestPin
	e.ts.StartTLS()
	t.Cleanup(e.ts.Close)
	e.client = vaulttest.NewClient(e.ts.URL, pin)
	return e
}

// adminDo calls the admin interface and decodes a 2xx answer into out.
func (e *env) adminDo(method, path string, in, out any) (int, string) {
	e.t.Helper()
	var body *bytes.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	} else {
		body = bytes.NewReader(nil)
	}
	rec := httptest.NewRecorder()
	e.admin.ServeHTTP(rec, httptest.NewRequest(method, path, body))
	if rec.Code/100 == 2 && out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			e.t.Fatalf("%s %s: %v", method, path, err)
		}
	}
	var er vaultproto.ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &er)
	return rec.Code, er.Error
}

func (e *env) token(req server.TokenRequest) string {
	e.t.Helper()
	var t server.TokenResponse
	if code, msg := e.adminDo("POST", "/v1/tokens", req, &t); code != 200 {
		e.t.Fatalf("token create: %d %s", code, msg)
	}
	return t.Token
}

func (e *env) machine(mode string) *vaulttest.Machine {
	e.t.Helper()
	m, err := vaulttest.NewMachine("db-03")
	if err != nil {
		e.t.Fatal(err)
	}
	res, err := m.Enrol(e.client, e.token(server.TokenRequest{Name: "db-03", Mode: mode}))
	if err != nil {
		e.t.Fatalf("enrol: %v", err)
	}
	if want := map[string]string{"": "auto"}[mode]; want == "" && res.Mode != mode || want != "" && res.Mode != want {
		e.t.Fatalf("enrolled in mode %q", res.Mode)
	}
	return m
}

func (e *env) device(m *vaulttest.Machine) *state.Device {
	e.t.Helper()
	d, err := e.dir.Device(m.DeviceID)
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

func (e *env) release(m *vaulttest.Machine) *vaultproto.ReleaseResponse {
	e.t.Helper()
	_, res, err := m.Release(e.client)
	if err != nil {
		e.t.Fatalf("release: %v", err)
	}
	return res
}

func wantStatus(t *testing.T, res *vaultproto.ReleaseResponse, status, reason string) {
	t.Helper()
	if res.Status != status || !strings.Contains(res.Reason, reason) {
		t.Fatalf("got %s (%q), want %s (%q)", res.Status, res.Reason, status, reason)
	}
}

func wantHTTP(t *testing.T, err error, code int, msg string) {
	t.Helper()
	var se *vaulttest.StatusError
	if !errors.As(err, &se) || se.Code != code || !strings.Contains(se.Msg, msg) {
		t.Fatalf("got %v, want HTTP %d %q", err, code, msg)
	}
}

func (e *env) auditLines() []state.Entry {
	e.t.Helper()
	b, err := os.ReadFile(e.dir.AuditPath())
	if err != nil {
		e.t.Fatal(err)
	}
	var out []state.Entry
	for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var en state.Entry
		if err := json.Unmarshal(l, &en); err != nil {
			e.t.Fatalf("audit line %q: %v", l, err)
		}
		out = append(out, en)
	}
	return out
}

// A machine enrols (proving its AK with ActivateCredential), and its
// release returns R wrapped as it sent it: its TPM opens it.
func TestEnrolAndRelease(t *testing.T) {
	e := newEnv(t)
	m := e.machine("")
	d := e.device(m)
	if d.Mode != vaultproto.ModeAuto || d.MinGeneration != 5 || d.Name != "db-03" || len(d.Recovery) == 0 || len(d.Sealed.PCRs) != 1 {
		t.Fatalf("device record %+v", d)
	}
	if bytes.Contains(d.Remote, m.Remote.Credential) {
		t.Fatal("the wrapped remote part is stored in the clear")
	}
	// The recovery key opens the device key; the device key opens the record.
	kdev, err := e.rk.Open(d.Recovery, d.ID)
	if err != nil {
		t.Fatalf("recovery copy: %v", err)
	}
	if _, err := keys.Decrypt(kdev, d.Remote, d.ID); err != nil {
		t.Fatalf("record under the recovered key: %v", err)
	}
	if _, err := keys.Decrypt(kdev, d.Remote, make([]byte, 16)); err == nil {
		t.Fatal("the record opens with another device ID as AAD")
	}

	res := e.release(m)
	wantStatus(t, res, vaultproto.StatusReleased, "")
	r, err := m.Open(res.Remote)
	if err != nil || !bytes.Equal(r, m.R) {
		t.Fatalf("the machine opens %x (%v), want its R", r, err)
	}
	if d := e.device(m); d.LastRelease == nil || d.Failures != 0 {
		t.Fatalf("after release: %+v", d)
	}

	// Files are 0600.
	for _, p := range []string{e.dir.AuditPath(), e.dir.TLSKeyPath(), e.dir.Path + "/devices/" + state.DeviceFile(m.DeviceID)} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, st.Mode(), err)
		}
	}
}

// Every step is in the audit log, and no secret is.
func TestAudit(t *testing.T) {
	e := newEnv(t)
	m, _ := vaulttest.NewMachine("web-1")
	tok := e.token(server.TokenRequest{Name: "web-1"})
	if _, err := m.Enrol(e.client, tok); err != nil {
		t.Fatal(err)
	}
	e.release(m)
	e.adminDo("POST", "/v1/devices/web-1/revoke", nil, nil)
	wantStatus(t, e.release(m), vaultproto.StatusDenied, "revoked")

	var got []string
	for _, l := range e.auditLines() {
		got = append(got, l.Event+":"+l.Result)
	}
	want := []string{"token-create:done", "enrol:challenged", "enrol-confirm:enrolled", "challenge:issued", "release:released", "revoke:done", "challenge:issued", "release:denied"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("audit\n got %v\nwant %v", got, want)
	}
	raw, _ := os.ReadFile(e.dir.AuditPath())
	for _, secret := range []string{tok, hex.EncodeToString(m.R)} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("a secret is in the audit log")
		}
	}

	// The admin interface reads the log, and follows it.
	code, _ := e.adminDo("GET", "/v1/audit", nil, nil)
	if code != 200 {
		t.Fatalf("audit: %d", code)
	}
	hs := httptest.NewServer(e.admin)
	defer hs.Close()
	rsp, err := http.Get(hs.URL + "/v1/audit?follow=1")
	if err != nil {
		t.Fatal(err)
	}
	defer rsp.Body.Close()
	sc := bufio.NewScanner(rsp.Body)
	for range want {
		if !sc.Scan() {
			t.Fatal("the log ended early")
		}
	}
	e.adminDo("POST", "/v1/devices/web-1/unrevoke", nil, nil)
	if !sc.Scan() || !strings.Contains(sc.Text(), `"event":"unrevoke"`) {
		t.Fatalf("followed line %q", sc.Text())
	}
}

func TestEnrolTokens(t *testing.T) {
	e := newEnv(t)
	m, _ := vaulttest.NewMachine("a")

	_, err := m.Enrol(e.client, "not-a-token")
	wantHTTP(t, err, 403, "unknown or used")

	expiring := e.token(server.TokenRequest{Name: "a", TTLSeconds: 60})
	e.clock.Advance(61 * time.Second)
	_, err = m.Enrol(e.client, expiring)
	wantHTTP(t, err, 403, "expired")

	tok := e.token(server.TokenRequest{Name: "a"})
	if _, err := m.Enrol(e.client, tok); err != nil {
		t.Fatal(err)
	}
	other, _ := vaulttest.NewMachine("b")
	_, err = other.Enrol(e.client, tok)
	wantHTTP(t, err, 403, "unknown or used")

	// A known device needs a token made for replacing it.
	_, err = m.Enrol(e.client, e.token(server.TokenRequest{Name: "a"}))
	wantHTTP(t, err, 409, "enrolled already")
	repl := e.token(server.TokenRequest{Name: "a", Replace: hex.EncodeToString(m.DeviceID), Mode: vaultproto.ModeApprove})
	_, err = other.Enrol(e.client, repl)
	wantHTTP(t, err, 403, "replaces device")
	m.Gen = 9
	m.Approve()
	if _, err := m.Enrol(e.client, repl); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if d := e.device(m); d.Mode != vaultproto.ModeApprove || d.MinGeneration != 9 {
		t.Fatalf("replaced device %+v", d)
	}

	// A token's form.
	if code, msg := e.adminDo("POST", "/v1/tokens", server.TokenRequest{}, nil); code != 400 || !strings.Contains(msg, "name") {
		t.Fatalf("nameless token: %d %s", code, msg)
	}
	if code, _ := e.adminDo("POST", "/v1/tokens", server.TokenRequest{Name: "x", Mode: "sometimes"}, nil); code != 400 {
		t.Fatalf("bad mode: %d", code)
	}
	var tr server.TokenResponse
	e.adminDo("POST", "/v1/tokens", server.TokenRequest{Name: "x"}, &tr)
	if tr.Pin != e.pin || tr.URL != e.cfg.URL || !strings.Contains(tr.Command, "tpm2-kira vault enrol --url "+e.cfg.URL+" --pin "+e.pin+" --token "+tr.Token) {
		t.Fatalf("token response %+v", tr)
	}
	ents, _ := os.ReadDir(e.dir.Path + "/tokens")
	for _, en := range ents {
		b, _ := os.ReadFile(e.dir.Path + "/tokens/" + en.Name())
		if strings.Contains(string(b), tr.Token) {
			t.Fatal("a token is stored in the clear")
		}
	}
}

// Only the TPM holding the EK returns the enrolment secret.
func TestEnrolWrongProof(t *testing.T) {
	e := newEnv(t)
	m, _ := vaulttest.NewMachine("a")
	tok := e.token(server.TokenRequest{Name: "a"})

	var ch vaultproto.EnrolChallenge
	if err := e.client.Post(vaultproto.PathEnrol, m.EnrolRequest(tok), &ch); err != nil {
		t.Fatal(err)
	}
	var res vaultproto.EnrolResult
	err := e.client.Post(vaultproto.PathEnrolConfirm, vaultproto.EnrolConfirm{EnrolID: ch.EnrolID, Secret: make([]byte, 32)}, &res)
	wantHTTP(t, err, 403, "not in the TPM")
	err = e.client.Post(vaultproto.PathEnrolConfirm, vaultproto.EnrolConfirm{EnrolID: ch.EnrolID, Secret: make([]byte, 32)}, &res)
	wantHTTP(t, err, 404, "unknown enrolment")

	// An AK of another TPM: the credential is for that AK's name, which
	// this TPM's ActivateCredential does not have.
	other, _ := vaulttest.NewMachine("b")
	req := m.EnrolRequest(tok)
	req.AKPublic = other.TPM.AKPub
	if err := e.client.Post(vaultproto.PathEnrol, req, &ch); err != nil {
		t.Fatal(err)
	}
	if _, err := m.TPM.ActivateCredential(ch.Challenge.Credential, ch.Challenge.EncryptedSecret); err == nil {
		t.Fatal("a TPM opened a credential for another TPM's AK")
	}

	// The answer must come within five minutes.
	if err := e.client.Post(vaultproto.PathEnrol, m.EnrolRequest(tok), &ch); err != nil {
		t.Fatal(err)
	}
	secret, err := m.TPM.ActivateCredential(ch.Challenge.Credential, ch.Challenge.EncryptedSecret)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(server.EnrolTTL)
	err = e.client.Post(vaultproto.PathEnrolConfirm, vaultproto.EnrolConfirm{EnrolID: ch.EnrolID, Secret: secret}, &res)
	wantHTTP(t, err, 403, "expired")
	if _, err := e.dir.Device(m.DeviceID); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("a refused enrolment stored the device: %v", err)
	}

	// A malformed enrolment request.
	bad := m.EnrolRequest(e.token(server.TokenRequest{Name: "a"}))
	bad.DeviceID = []byte{1}
	err = e.client.Post(vaultproto.PathEnrol, bad, &ch)
	wantHTTP(t, err, 400, "device ID")
}

func TestChallengeExpiryAndReuse(t *testing.T) {
	e := newEnv(t)
	m := e.machine("")

	ch, err := m.Challenge(e.client)
	if err != nil {
		t.Fatal(err)
	}
	if ch.ExpiresIn != 120 || len(ch.Nonce) != vaultproto.NonceSize {
		t.Fatalf("challenge %+v", ch)
	}
	req, _ := m.ReleaseRequest(ch)
	e.clock.Advance(server.ChallengeTTL)
	res, err := e.client.Send(req)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, res, vaultproto.StatusDenied, "challenge expired")
	_, err = e.client.Send(req)
	wantHTTP(t, err, 404, "unknown request")

	// A released challenge is used up.
	req, res, err = m.Release(e.client)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, res, vaultproto.StatusReleased, "")
	_, err = e.client.Send(req)
	wantHTTP(t, err, 404, "unknown request")

	// An expired challenge is no failed verification.
	if d := e.device(m); d.Failures != 0 {
		t.Fatalf("failures %d", d.Failures)
	}

	// Unknown devices and malformed requests are 4xx.
	_, err = (&vaulttest.Machine{DeviceID: make([]byte, 16)}).Challenge(e.client)
	wantHTTP(t, err, 404, "unknown device")
	var cr vaultproto.ChallengeResponse
	wantHTTP(t, e.client.Post(vaultproto.PathChallenge, map[string]any{"device_id": 5}, &cr), 400, "does not parse")
	big := map[string]string{"device_id": strings.Repeat("A", server.MaxBody)}
	wantHTTP(t, e.client.Post(vaultproto.PathChallenge, big, &cr), 413, "larger")
	ch, _ = m.Challenge(e.client)
	req, _ = m.ReleaseRequest(ch)
	req.DeviceID = make([]byte, 16)
	_, err = e.client.Send(req)
	wantHTTP(t, err, 400, "another device")
}

func TestGenerationRollback(t *testing.T) {
	e := newEnv(t)
	m := e.machine("")
	wantStatus(t, e.release(m), vaultproto.StatusReleased, "")

	m.Gen = 7 // a reseal of the machine
	m.Approve()
	wantStatus(t, e.release(m), vaultproto.StatusReleased, "")
	if d := e.device(m); d.MinGeneration != 7 {
		t.Fatalf("min generation %d", d.MinGeneration)
	}
	m.Gen = 6 // an approval that reseal revoked
	m.Approve()
	wantStatus(t, e.release(m), vaultproto.StatusDenied, "older than 7")
}

func TestLockAfterFailures(t *testing.T) {
	e := newEnv(t)
	m := e.machine("")
	m.TPM.Extend(11, "a kernel the signing key never saw")
	for i := 1; i <= server.MaxFailures; i++ {
		res := e.release(m)
		wantStatus(t, res, vaultproto.StatusDenied, "approval does not cover")
		if locked := strings.Contains(res.Reason, "locked"); locked != (i == server.MaxFailures) {
			t.Fatalf("attempt %d: %q", i, res.Reason)
		}
		e.clock.Advance(10 * time.Second)
	}
	d := e.device(m)
	if !d.Locked || d.Failures != server.MaxFailures {
		t.Fatalf("device %+v", d)
	}
	m.Approve() // the boot state is approved now, but the device is locked
	wantStatus(t, e.release(m), vaultproto.StatusDenied, "locked")

	if code, msg := e.adminDo("POST", "/v1/devices/"+hex.EncodeToString(m.DeviceID)+"/unlock", nil, nil); code != 200 {
		t.Fatalf("unlock: %d %s", code, msg)
	}
	wantStatus(t, e.release(m), vaultproto.StatusReleased, "")

	// A success resets the count: four failures, a success, four more do
	// not lock.
	for round := 0; round < 2; round++ {
		m.TPM.Extend(11, "again")
		for i := 0; i < server.MaxFailures-1; i++ {
			e.clock.Advance(10 * time.Second)
			wantStatus(t, e.release(m), vaultproto.StatusDenied, "approval")
		}
		m.Approve()
		e.clock.Advance(10 * time.Second)
		wantStatus(t, e.release(m), vaultproto.StatusReleased, "")
	}
}

func TestRevoke(t *testing.T) {
	e := newEnv(t)
	m := e.machine("")
	var v server.DeviceView
	if code, _ := e.adminDo("POST", "/v1/devices/db-03/revoke", nil, &v); code != 200 || !v.Revoked {
		t.Fatalf("revoke: %d %+v", code, v)
	}
	wantStatus(t, e.release(m), vaultproto.StatusDenied, "revoked")
	if d := e.device(m); d.Failures != 0 {
		t.Fatal("a revoked device's request counted as a failed verification")
	}
	e.adminDo("POST", "/v1/devices/db-03/unrevoke", nil, &v)
	wantStatus(t, e.release(m), vaultproto.StatusReleased, "")

	// Listing and showing.
	var list []server.DeviceView
	if code, _ := e.adminDo("GET", "/v1/devices", nil, &list); code != 200 || len(list) != 1 || list[0].ID != hex.EncodeToString(m.DeviceID) {
		t.Fatalf("devices %+v", list)
	}
	if code, _ := e.adminDo("GET", "/v1/devices/nothing", nil, nil); code != 404 {
		t.Fatalf("an unknown device: %d", code)
	}
	if code, _ := e.adminDo("POST", "/v1/devices/db-03/mode", server.ModeRequest{Mode: "approve"}, &v); code != 200 || v.Mode != "approve" {
		t.Fatalf("mode: %d %+v", code, v)
	}
	if code, _ := e.adminDo("POST", "/v1/devices/db-03/mode", server.ModeRequest{Mode: "never"}, nil); code != 400 {
		t.Fatalf("a bad mode: %d", code)
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	m := e.machine("")
	for i := 0; i < server.RateLimit; i++ {
		if _, err := m.Challenge(e.client); err != nil {
			t.Fatalf("challenge %d: %v", i, err)
		}
		e.clock.Advance(time.Second)
	}
	_, err := m.Challenge(e.client)
	wantHTTP(t, err, 429, "at most 10")
	e.clock.Advance(server.RateWindow - 10*time.Second) // the first challenge leaves the window, the second not
	if _, err := m.Challenge(e.client); err != nil {
		t.Fatalf("after the window: %v", err)
	}
	_, err = m.Challenge(e.client)
	wantHTTP(t, err, 429, "at most 10")
}

func TestApproveMode(t *testing.T) {
	e := newEnv(t)
	m := e.machine(vaultproto.ModeApprove)

	ask := func() (*vaultproto.ReleaseRequest, string) {
		req, res, err := m.Release(e.client)
		if err != nil {
			t.Fatal(err)
		}
		wantStatus(t, res, vaultproto.StatusPending, "")
		if res.RetryAfter <= 0 {
			t.Fatalf("retry after %d", res.RetryAfter)
		}
		var list []server.RequestView
		e.adminDo("GET", "/v1/requests", nil, &list)
		if len(list) != 1 || list[0].ID != req.RequestID || list[0].State != "pending" || list[0].Generation != 5 || list[0].Name != "db-03" {
			t.Fatalf("requests %+v", list)
		}
		return req, req.RequestID
	}
	send := func(req *vaultproto.ReleaseRequest) *vaultproto.ReleaseResponse {
		res, err := e.client.Send(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	// pending → approve → released, past the challenge's own 120 s.
	req, id := ask()
	e.clock.Advance(3 * time.Minute)
	wantStatus(t, send(req), vaultproto.StatusPending, "")
	changed := *req
	changed.Generation = 6
	_, err := e.client.Send(&changed)
	wantHTTP(t, err, 400, "unchanged")
	if code, msg := e.adminDo("POST", "/v1/requests/"+id+"/approve", map[string]any{"pepper": "secret"}, nil); code != 400 || msg != "this device was enrolled without a pepper" {
		t.Fatalf("pepper: %d %q", code, msg)
	}
	if code, msg := e.adminDo("POST", "/v1/requests/"+id+"/approve", nil, nil); code != 200 {
		t.Fatalf("approve: %d %s", code, msg)
	}
	if code, _ := e.adminDo("POST", "/v1/requests/"+id+"/deny", nil, nil); code != 409 {
		t.Fatalf("deny after approve: %d", code)
	}
	res := send(req)
	wantStatus(t, res, vaultproto.StatusReleased, "")
	if r, err := m.Open(res.Remote); err != nil || !bytes.Equal(r, m.R) {
		t.Fatal("the approved release does not open")
	}
	_, err = e.client.Send(req)
	wantHTTP(t, err, 404, "unknown request")

	// pending → deny → denied.
	req, id = ask()
	if code, _ := e.adminDo("POST", "/v1/requests/"+id+"/deny", nil, nil); code != 200 {
		t.Fatalf("deny: %d", code)
	}
	wantStatus(t, send(req), vaultproto.StatusDenied, "operator denied")
	_, err = e.client.Send(req)
	wantHTTP(t, err, 404, "unknown request")

	// pending, no operator: denied after 15 minutes.
	req, id = ask()
	e.clock.Advance(server.PendingTTL)
	if code, _ := e.adminDo("POST", "/v1/requests/"+id+"/approve", nil, nil); code != 409 {
		t.Fatalf("approving an expired request: %d", code)
	}
	wantStatus(t, send(req), vaultproto.StatusDenied, "not approved within 15 minutes")

	// An approved request of a device revoked meanwhile is denied.
	req, id = ask()
	e.adminDo("POST", "/v1/requests/"+id+"/approve", nil, nil)
	e.adminDo("POST", "/v1/devices/db-03/revoke", nil, nil)
	wantStatus(t, send(req), vaultproto.StatusDenied, "revoked")

	if code, _ := e.adminDo("POST", "/v1/requests/nothing/approve", nil, nil); code != 404 {
		t.Fatalf("an unknown request: %d", code)
	}
}

// A vault whose own PCRs moved denies with advice and does not hold it
// against the device; reseal-like resealing makes it release again.
func TestVaultBootStateChanged(t *testing.T) {
	e := newEnv(t)
	m := e.machine("")
	e.sealer.ChangeBoot()
	for i := 0; i < server.MaxFailures+1; i++ {
		wantStatus(t, e.release(m), vaultproto.StatusDenied, "the vault's own boot state changed: run reseal")
	}
	if d := e.device(m); d.Locked || d.Failures != 0 {
		t.Fatalf("device %+v", d)
	}
	found := false
	for _, l := range e.auditLines() {
		found = found || l.Detail == keys.ErrBootStateChanged.Error()
	}
	if !found {
		t.Fatal("the denial is not in the audit log")
	}
}

// A machine pins the vault's key: another key is a refused vault.
func TestPin(t *testing.T) {
	e := newEnv(t)
	m, _ := vaulttest.NewMachine("a")
	wrong := vaulttest.NewClient(e.ts.URL, vaultproto.PinOf([]byte("another key")))
	_, err := m.Challenge(wrong)
	if err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("a wrong pin: %v", err)
	}
	if _, err := m.Challenge(e.client); err == nil || !strings.Contains(err.Error(), "unknown device") {
		t.Fatalf("the right pin: %v", err)
	}
}
