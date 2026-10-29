package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrwiora/tpm2-kira/core/vaultproto"

	"github.com/tpm2-trust/tpm2-kira-vault/internal/server"
	"github.com/tpm2-trust/tpm2-kira-vault/internal/tlsutil"
	"github.com/tpm2-trust/tpm2-kira-vault/internal/vaulttest"
)

// operatorURL starts the operator interface on its own TLS listener.
func (e *env) operatorURL() string {
	e.t.Helper()
	cert, _, err := tlsutil.Load(e.dir)
	if err != nil {
		e.t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(e.srv.OperatorHandler())
	ts.TLS = tlsutil.ServerConfig(cert)
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	e.t.Cleanup(ts.Close)
	return ts.URL
}

// addOperator adds an operator over the admin socket and returns its token.
func (e *env) addOperator(name string) string {
	e.t.Helper()
	var o server.OperatorAdded
	if code, msg := e.adminDo("POST", "/v1/operators", server.OperatorRequest{Name: name}, &o); code != 200 {
		e.t.Fatalf("operator add: %d %s", code, msg)
	}
	if o.Token == "" || o.CurlPin != tlsutil.CurlPin(e.pin) || !strings.HasPrefix(o.CurlPin, "sha256//") {
		e.t.Fatalf("operator added %+v", o)
	}
	return o.Token
}

// pendingRequest has the machine ask once, in approve mode.
func (e *env) pendingRequest(m *vaulttest.Machine) *vaultproto.ReleaseRequest {
	e.t.Helper()
	req, res, err := m.Release(e.client)
	if err != nil {
		e.t.Fatal(err)
	}
	wantStatus(e.t, res, vaultproto.StatusPending, "")
	return req
}

// grepState fails when s is in any file of the state directory.
func (e *env) grepState(s string) {
	e.t.Helper()
	filepath.WalkDir(e.dir.Path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte(s)) {
			e.t.Fatalf("%q is in %s", s, p)
		}
		return nil
	})
}

func TestPepper(t *testing.T) {
	e := newEnv(t)
	m, _ := vaulttest.NewMachine("db-03")
	m.Pepper = true
	res, err := m.Enrol(e.client, e.token(server.TokenRequest{Name: "db-03", Mode: vaultproto.ModeAuto}))
	if err != nil {
		t.Fatal(err)
	}
	if d := e.device(m); res.Mode != vaultproto.ModeApprove || d.Mode != vaultproto.ModeApprove || !d.PepperRequired {
		t.Fatalf("a pepper device enrolled in mode %s: %+v", res.Mode, d)
	}
	if code, msg := e.adminDo("POST", "/v1/devices/db-03/mode", server.ModeRequest{Mode: "auto"}, nil); code != 400 || !strings.Contains(msg, "enrolled with a pepper") {
		t.Fatalf("mode auto: %d %s", code, msg)
	}
	var v server.DeviceView
	if e.adminDo("GET", "/v1/devices/db-03", nil, &v); !v.Pepper {
		t.Fatalf("show %+v", v)
	}

	const pepper = "correct horse battery staple ☃"
	req := e.pendingRequest(m)
	path := "/v1/requests/" + req.RequestID + "/approve"
	var list []server.RequestView
	if e.adminDo("GET", "/v1/requests", nil, &list); len(list) != 1 || !list[0].Pepper {
		t.Fatalf("requests %+v", list)
	}
	for _, c := range []struct {
		body any
		want string
	}{
		{nil, "this device was enrolled with a pepper: approve with it"},
		{map[string]any{}, "this device was enrolled with a pepper: approve with it"},
		{map[string]any{"pepper": ""}, "1 to 256 bytes"},
		{map[string]any{"pepper": strings.Repeat("p", vaultproto.MaxPepper+1)}, "1 to 256 bytes"},
		{map[string]any{"pepper": 7}, "does not parse"},
	} {
		if code, msg := e.adminDo("POST", path, c.body, nil); code != 400 || !strings.Contains(msg, c.want) {
			t.Fatalf("approve with %v: %d %q", c.body, code, msg)
		}
	}
	if code, _ := e.adminDo("POST", path, map[string]any{"pepper": pepper}, nil); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	rel, err := e.client.Send(req)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, rel, vaultproto.StatusReleased, "")
	if string(rel.Pepper) != pepper {
		t.Fatalf("released pepper %q", rel.Pepper)
	}
	if _, err := e.client.Send(req); err == nil {
		t.Fatal("a re-send after the release was answered")
	}
	e.grepState(pepper)
	found := false
	for _, l := range e.auditLines() {
		found = found || l.Event == "approve" && l.Detail == "with a pepper" && l.Actor == "admin"
	}
	if !found {
		t.Fatal("the approval is not in the audit log")
	}

	// An approval the machine does not collect in time is denied.
	req = e.pendingRequest(m)
	e.adminDo("POST", "/v1/requests/"+req.RequestID+"/approve", map[string]any{"pepper": pepper}, nil)
	e.clock.Advance(server.ChallengeTTL)
	rel, _ = e.client.Send(req)
	wantStatus(t, rel, vaultproto.StatusDenied, "approval expired")
	if len(rel.Pepper) != 0 {
		t.Fatal("a denial carries the pepper")
	}

	// A device revoked after the approval is denied, without the pepper.
	req = e.pendingRequest(m)
	e.adminDo("POST", "/v1/requests/"+req.RequestID+"/approve", map[string]any{"pepper": pepper}, nil)
	e.adminDo("POST", "/v1/devices/db-03/revoke", nil, nil)
	rel, _ = e.client.Send(req)
	wantStatus(t, rel, vaultproto.StatusDenied, "revoked")
	if len(rel.Pepper) != 0 {
		t.Fatal("a denial carries the pepper")
	}

	// A device without a pepper takes none.
	plain := e.machine(vaultproto.ModeApprove)
	req = e.pendingRequest(plain)
	if code, msg := e.adminDo("POST", "/v1/requests/"+req.RequestID+"/approve", map[string]any{"pepper": pepper}, nil); code != 400 || msg != "this device was enrolled without a pepper" {
		t.Fatalf("a pepper for a plain device: %d %q", code, msg)
	}
	e.adminDo("POST", "/v1/requests/"+req.RequestID+"/approve", map[string]any{}, nil)
	rel, _ = e.client.Send(req)
	if wantStatus(t, rel, vaultproto.StatusReleased, ""); len(rel.Pepper) != 0 {
		t.Fatal("a plain device's release carries a pepper")
	}
}

func TestOperatorInterface(t *testing.T) {
	e := newEnv(t)
	url := e.operatorURL()
	m, _ := vaulttest.NewMachine("db-03")
	m.Pepper = true
	if _, err := m.Enrol(e.client, e.token(server.TokenRequest{Name: "db-03"})); err != nil {
		t.Fatal(err)
	}
	token := e.addOperator("alice")
	alice := vaulttest.NewOperator(url, e.pin, token)

	for _, o := range []*vaulttest.Operator{
		vaulttest.NewOperator(url, e.pin, ""),
		vaulttest.NewOperator(url, e.pin, "wrong"),
	} {
		code, body, err := o.Do("GET", "/v1/requests", "")
		if err != nil || code != 401 || strings.TrimSpace(string(body)) != `{"error":"unauthorized"}` {
			t.Fatalf("unauthenticated: %d %s %v", code, body, err)
		}
	}

	if code, body, _ := alice.Do("GET", "/v1/devices", ""); code != 200 || !strings.Contains(string(body), `"pepper":true`) {
		t.Fatalf("devices: %d %s", code, body)
	}
	if code, _, _ := alice.Do("GET", "/v1/devices/db-03", ""); code != 200 {
		t.Fatalf("device: %d", code)
	}
	for _, p := range [][2]string{{"POST", "/v1/tokens"}, {"POST", "/v1/devices/db-03/revoke"}, {"POST", "/v1/devices/db-03/mode"}, {"GET", "/v1/audit"}, {"GET", "/v1/operators"}, {"DELETE", "/v1/operators/alice"}} {
		if code, _, _ := alice.Do(p[0], p[1], `{"name":"x","mode":"auto"}`); code != 404 {
			t.Fatalf("%s %s on the operator interface: %d", p[0], p[1], code)
		}
	}

	// Approve with the pepper; the release carries it.
	req := e.pendingRequest(m)
	code, body, _ := alice.Do("GET", "/v1/requests", "")
	var list []server.RequestView
	json.Unmarshal(body, &list)
	if code != 200 || len(list) != 1 || list[0].ID != req.RequestID {
		t.Fatalf("requests: %d %s", code, body)
	}
	big := `{"pepper":"` + strings.Repeat("p", server.OperatorMaxBody) + `"}`
	if code, body, _ := alice.Do("POST", "/v1/requests/"+req.RequestID+"/approve", big); code != 413 {
		t.Fatalf("a large body: %d %s", code, body)
	}
	if code, body, _ := alice.Do("POST", "/v1/requests/"+req.RequestID+"/approve", `{"pepper":"p3pp3r"}`); code != 200 || !strings.Contains(string(body), `"actor":"alice"`) {
		t.Fatalf("approve: %d %s", code, body)
	}
	rel, err := e.client.Send(req)
	if err != nil || rel.Status != vaultproto.StatusReleased || string(rel.Pepper) != "p3pp3r" {
		t.Fatalf("release: %v %+v", err, rel)
	}

	// Deny.
	req = e.pendingRequest(m)
	if code, _, _ := alice.Do("POST", "/v1/requests/"+req.RequestID+"/deny", ""); code != 200 {
		t.Fatalf("deny: %d", code)
	}
	rel, _ = e.client.Send(req)
	wantStatus(t, rel, vaultproto.StatusDenied, "operator denied")

	var events []string
	for _, l := range e.auditLines() {
		if l.Actor == "alice" {
			events = append(events, l.Event+":"+l.Detail)
		}
		if l.Event == "release" && l.Result == "released" && !strings.Contains(l.Detail, "approved by alice, with a pepper") {
			t.Fatalf("release audit %+v", l)
		}
		if l.Event == "operator-auth" && l.Result != "refused" {
			t.Fatalf("auth audit %+v", l)
		}
	}
	if strings.Join(events, " ") != "approve:with a pepper deny:" {
		t.Fatalf("alice's audit %v", events)
	}
	e.grepState("p3pp3r")
	e.grepState(token)

	// A removed operator is refused.
	if code, _ := e.adminDo("DELETE", "/v1/operators/alice", nil, nil); code != 200 {
		t.Fatalf("remove: %d", code)
	}
	if code, _, _ := alice.Do("GET", "/v1/requests", ""); code != 401 {
		t.Fatalf("a removed operator: %d", code)
	}
	if code, _ := e.adminDo("DELETE", "/v1/operators/alice", nil, nil); code != 404 {
		t.Fatalf("remove twice: %d", code)
	}
}

func TestOperatorAuthRateLimit(t *testing.T) {
	e := newEnv(t)
	url := e.operatorURL()
	bob := vaulttest.NewOperator(url, e.pin, e.addOperator("bob"))
	if code, _ := e.adminDo("POST", "/v1/operators", server.OperatorRequest{Name: "bob"}, nil); code != 409 {
		t.Fatalf("bob twice: %d", code)
	}
	if code, _ := e.adminDo("POST", "/v1/operators", server.OperatorRequest{Name: "../x"}, nil); code != 400 {
		t.Fatalf("a bad name: %d", code)
	}
	mallory := vaulttest.NewOperator(url, e.pin, "guess")
	for i := 0; i < server.AuthFailLimit; i++ {
		if code, _, _ := mallory.Do("GET", "/v1/requests", ""); code != 401 {
			t.Fatalf("guess %d: %d", i, code)
		}
		e.clock.Advance(time.Second)
	}
	// The address is refused now, even with a good token.
	if code, _, _ := bob.Do("GET", "/v1/requests", ""); code != 401 {
		t.Fatalf("a good token from a refused address: %d", code)
	}
	refused := 0
	for _, l := range e.auditLines() {
		if l.Event == "operator-auth" {
			refused++
		}
	}
	if refused != server.AuthFailLimit {
		t.Fatalf("%d refused authentications in the audit log", refused)
	}
	e.clock.Advance(server.AuthFailWindow)
	if code, _, _ := bob.Do("GET", "/v1/requests", ""); code != 200 {
		t.Fatalf("after the window: %d", code)
	}
}
