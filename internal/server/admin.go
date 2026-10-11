package server

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/mrwiora/tpm2-kira/vaultproto"

	"github.com/mrwiora/tpm2-kira-vault/internal/state"
)

// The admin interface's messages. The operator interface serves a part
// of the same handlers over HTTPS with a bearer token (operator.go).

// DeviceView is a device as the operator sees it: no keys.
type DeviceView struct {
	ID            string               `json:"device_id"`
	Name          string               `json:"name"`
	Label         string               `json:"label"`
	Mode          string               `json:"mode"`
	Pepper        bool                 `json:"pepper"` // releases need an approval with the operator's pepper
	MinGeneration uint64               `json:"min_generation"`
	Revoked       bool                 `json:"revoked"`
	Locked        bool                 `json:"locked"`
	Failures      int                  `json:"failures"`
	EnrolledAt    time.Time            `json:"enrolled_at"`
	LastRelease   *time.Time           `json:"last_release,omitempty"`
	Selection     vaultproto.Selection `json:"selection"`
	VaultPCRs     []uint8              `json:"vault_pcrs"` // the vault PCRs its key is sealed to
}

// RequestView is a pending release request.
type RequestView struct {
	ID         string                `json:"request_id"`
	DeviceID   string                `json:"device_id"`
	Name       string                `json:"name"`
	State      string                `json:"state"`
	Pepper     bool                  `json:"pepper"` // approve it with the device's pepper
	Actor      string                `json:"actor,omitempty"`
	Created    time.Time             `json:"created"`
	Expires    time.Time             `json:"expires"`
	Remote     string                `json:"remote"`
	Generation uint64                `json:"generation"`
	PCRValues  []vaultproto.PCRValue `json:"pcr_values"`
}

// ModeRequest is the body of POST /v1/devices/{id}/mode.
type ModeRequest struct {
	Mode string `json:"mode"`
}

// ApproveRequest is the body of POST /v1/requests/{id}/approve. Pepper is
// required for a device enrolled with one and refused for any other: UTF-8,
// 1 to vaultproto.MaxPepper bytes.
type ApproveRequest struct {
	Pepper *string `json:"pepper,omitempty"`
}

// TokenRequest is the body of POST /v1/tokens.
type TokenRequest struct {
	Name       string `json:"name"`
	Mode       string `json:"mode"`        // auto when empty
	TTLSeconds int    `json:"ttl_seconds"` // an hour when 0
	Replace    string `json:"replace,omitempty"`
}

// TokenResponse is a created token: shown once, stored only as its hash.
type TokenResponse struct {
	Token   string    `json:"token"`
	Name    string    `json:"name"`
	Mode    string    `json:"mode"`
	Expires time.Time `json:"expires"`
	URL     string    `json:"url"`
	Pin     string    `json:"pin"`
	Command string    `json:"command"` // to run on the machine
}

// DefaultTokenTTL is a token's validity when none is asked for.
const DefaultTokenTTL = time.Hour

// AdminHandler serves the admin interface.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/devices", s.adminDevices)
	mux.HandleFunc("GET /v1/devices/{id}", s.adminDevice)
	mux.HandleFunc("POST /v1/devices/{id}/revoke", s.adminSetFlag("revoke", func(d *state.Device) { d.Revoked = true }))
	mux.HandleFunc("POST /v1/devices/{id}/unrevoke", s.adminSetFlag("unrevoke", func(d *state.Device) { d.Revoked = false }))
	mux.HandleFunc("POST /v1/devices/{id}/unlock", s.adminSetFlag("unlock", func(d *state.Device) { d.Locked, d.Failures = false, 0 }))
	mux.HandleFunc("POST /v1/devices/{id}/mode", s.adminMode)
	mux.HandleFunc("GET /v1/requests", s.adminRequests)
	mux.HandleFunc("POST /v1/requests/{id}/approve", s.adminDecide(approved))
	mux.HandleFunc("POST /v1/requests/{id}/deny", s.adminDecide(denied))
	mux.HandleFunc("POST /v1/tokens", s.adminToken)
	mux.HandleFunc("GET /v1/audit", s.adminAudit)
	mux.HandleFunc("GET /v1/operators", s.adminOperators)
	mux.HandleFunc("POST /v1/operators", s.adminOperatorAdd)
	mux.HandleFunc("DELETE /v1/operators/{name}", s.adminOperatorRemove)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "no such path")
	})
	return mux
}

func viewOf(d *state.Device) DeviceView {
	return DeviceView{
		ID: hex.EncodeToString(d.ID), Name: d.Name, Label: d.Label, Mode: d.Mode, Pepper: d.PepperRequired,
		MinGeneration: d.MinGeneration, Revoked: d.Revoked, Locked: d.Locked, Failures: d.Failures,
		EnrolledAt: d.EnrolledAt, LastRelease: d.LastRelease, Selection: d.Selection, VaultPCRs: d.Sealed.PCRs,
	}
}

// resolve finds a device by hex ID or by its unique name.
func (s *Server) resolve(ref string) (*state.Device, error) {
	if id, err := hex.DecodeString(ref); err == nil && len(id) == vaultproto.DeviceIDSize {
		d, err := s.dir.Device(id)
		if err == nil || !errors.Is(err, state.ErrNotFound) {
			return d, err
		}
	}
	all, err := s.dir.Devices()
	if err != nil {
		return nil, err
	}
	var found *state.Device
	for _, d := range all {
		if d.Name == ref {
			if found != nil {
				return nil, fail(http.StatusConflict, "several devices are named %q: use the device ID", ref)
			}
			found = d
		}
	}
	if found == nil {
		return nil, fail(http.StatusNotFound, "no device %q", ref)
	}
	return found, nil
}

func (s *Server) adminDevices(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.dir.Devices()
	views := []DeviceView{}
	for _, d := range all {
		views = append(views, viewOf(d))
	}
	s.answer(w, views, err)
}

func (s *Server) adminDevice(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.resolve(r.PathValue("id"))
	if err != nil {
		s.answer(w, nil, err)
		return
	}
	s.answer(w, viewOf(d), nil)
}

// changeDevice applies change to a device, saves and logs it.
func (s *Server) changeDevice(ref, event, actor string, change func(*state.Device) error) (*DeviceView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.resolve(ref)
	if err != nil {
		return nil, err
	}
	if err := change(d); err != nil {
		return nil, err
	}
	if err := s.dir.SaveDevice(d); err != nil {
		return nil, err
	}
	detail := ""
	if event == "mode" {
		detail = d.Mode
	}
	if err := s.logAudit(state.Entry{Event: event, Device: hex.EncodeToString(d.ID), Name: d.Name, Actor: actor, Result: "done", Detail: detail}); err != nil {
		return nil, err
	}
	if d.Revoked { // an approved release of a revoked device is denied: its pepper goes now
		for _, q := range s.requests {
			if bytes.Equal(q.device, d.ID) {
				clear(q.pepper)
				q.pepper = nil
			}
		}
	}
	v := viewOf(d)
	return &v, nil
}

func (s *Server) adminSetFlag(event string, set func(*state.Device)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := s.changeDevice(r.PathValue("id"), event, actorOf(r), func(d *state.Device) error { set(d); return nil })
		s.answer(w, v, err)
	}
}

func checkMode(m string) error {
	if m != vaultproto.ModeAuto && m != vaultproto.ModeApprove {
		return fail(http.StatusBadRequest, "mode %q: auto or approve", m)
	}
	return nil
}

func (s *Server) adminMode(w http.ResponseWriter, r *http.Request) {
	var m ModeRequest
	if err := decode(w, r, &m); err != nil {
		s.answer(w, nil, err)
		return
	}
	if err := checkMode(m.Mode); err != nil {
		s.answer(w, nil, err)
		return
	}
	v, err := s.changeDevice(r.PathValue("id"), "mode", actorOf(r), func(d *state.Device) error {
		if d.PepperRequired && m.Mode != vaultproto.ModeApprove {
			return fail(http.StatusBadRequest, "this device was enrolled with a pepper: it is released only on an operator's approval with it, so its mode stays approve")
		}
		d.Mode = m.Mode
		return nil
	})
	s.answer(w, v, err)
}

var stateNames = map[reqState]string{fresh: "challenged", pending: "pending", approved: "approved", denied: "denied"}

func (s *Server) adminRequests(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	views := []RequestView{}
	for _, q := range s.requests {
		if q.state == fresh || !now.Before(q.expires) {
			continue
		}
		v := RequestView{ID: q.id, DeviceID: hex.EncodeToString(q.device), State: stateNames[q.state], Created: q.created, Expires: q.expires, Remote: q.remote, Actor: q.actor}
		if d, err := s.dir.Device(q.device); err == nil {
			v.Name, v.Pepper = d.Name, d.PepperRequired
		}
		if q.checked != nil {
			v.Generation, v.PCRValues = q.checked.Generation, q.checked.PCRValues
		}
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Created.Before(views[j].Created) })
	s.answer(w, views, nil)
}

func (s *Server) adminDecide(to reqState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var pepper []byte
		if to == approved {
			body, err := readBody(w, r)
			if err != nil {
				s.answer(w, nil, err)
				return
			}
			if !utf8.Valid(body) {
				s.answer(w, nil, fail(http.StatusBadRequest, "the request is not UTF-8"))
				return
			}
			var a ApproveRequest
			if len(bytes.TrimSpace(body)) > 0 {
				if err := json.Unmarshal(body, &a); err != nil {
					s.answer(w, nil, fail(http.StatusBadRequest, "the request does not parse: %v", err))
					return
				}
			}
			clear(body)
			if a.Pepper != nil {
				pepper = []byte(*a.Pepper)
				if len(pepper) == 0 || len(pepper) > vaultproto.MaxPepper {
					s.answer(w, nil, fail(http.StatusBadRequest, "a pepper has 1 to %d bytes", vaultproto.MaxPepper))
					return
				}
			}
		}
		v, err := s.decide(r.PathValue("id"), to, actorOf(r), pepper)
		if err != nil {
			clear(pepper)
		}
		s.answer(w, v, err)
	}
}

// decide approves or denies a pending request. An approval of a device
// enrolled with a pepper takes ownership of the pepper.
func (s *Server) decide(id string, to reqState, actor string, pepper []byte) (*RequestView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	q := s.requests[id]
	if q == nil || q.state == fresh {
		return nil, fail(http.StatusNotFound, "no pending request %q", id)
	}
	if q.state != pending {
		return nil, fail(http.StatusConflict, "request %s is %s already", id, stateNames[q.state])
	}
	if !now.Before(q.expires) {
		return nil, fail(http.StatusConflict, "request %s expired", id)
	}
	d, err := s.dir.Device(q.device)
	if err != nil {
		return nil, err
	}
	detail := ""
	if to == approved {
		switch {
		case d.PepperRequired && pepper == nil:
			return nil, fail(http.StatusBadRequest, "this device was enrolled with a pepper: approve with it")
		case !d.PepperRequired && pepper != nil:
			return nil, fail(http.StatusBadRequest, "this device was enrolled without a pepper")
		case pepper != nil:
			detail = "with a pepper"
		}
	} else if pepper != nil {
		return nil, fail(http.StatusBadRequest, "a denial takes no pepper")
	}
	event := map[reqState]string{approved: "approve", denied: "deny"}[to]
	if err := s.logAudit(state.Entry{Event: event, Device: hex.EncodeToString(q.device), Name: d.Name, Request: q.id, Actor: actor, Result: "done", Detail: detail}); err != nil {
		return nil, err
	}
	q.state, q.actor, q.pepper = to, actor, pepper
	if to == approved {
		q.expires = now.Add(ChallengeTTL) // for the machine's next re-send
	}
	return &RequestView{ID: q.id, DeviceID: hex.EncodeToString(q.device), Name: d.Name, State: stateNames[q.state], Pepper: d.PepperRequired, Actor: actor, Created: q.created, Expires: q.expires, Remote: q.remote}, nil
}

func (s *Server) adminToken(w http.ResponseWriter, r *http.Request) {
	var t TokenRequest
	err := decode(w, r, &t)
	var res *TokenResponse
	if err == nil {
		res, err = s.createToken(&t)
	}
	s.answer(w, res, err)
}

func (s *Server) createToken(t *TokenRequest) (*TokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.Name == "" {
		return nil, fail(http.StatusBadRequest, "a token needs a name")
	}
	if t.Mode == "" {
		t.Mode = vaultproto.ModeAuto
	}
	if err := checkMode(t.Mode); err != nil {
		return nil, err
	}
	ttl := DefaultTokenTTL
	if t.TTLSeconds < 0 {
		return nil, fail(http.StatusBadRequest, "a negative time to live")
	} else if t.TTLSeconds > 0 {
		ttl = time.Duration(t.TTLSeconds) * time.Second
	}
	tok := &state.Token{Name: t.Name, Mode: t.Mode, Expires: s.now().Add(ttl).UTC()}
	if t.Replace != "" {
		d, err := s.resolve(t.Replace)
		if err != nil {
			return nil, err
		}
		tok.Replace = d.ID
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	if err := s.dir.PutToken(TokenHash(value), tok); err != nil {
		return nil, err
	}
	detail := fmt.Sprintf("mode %s, expires %s", tok.Mode, tok.Expires.Format(time.RFC3339))
	if tok.Replace != nil {
		detail += fmt.Sprintf(", replaces %x", tok.Replace)
	}
	if err := s.logAudit(state.Entry{Event: "token-create", Name: tok.Name, Actor: "admin", Result: "done", Detail: detail}); err != nil {
		return nil, err
	}
	return &TokenResponse{
		Token: value, Name: tok.Name, Mode: tok.Mode, Expires: tok.Expires, URL: s.cfg.URL, Pin: s.pin,
		Command: fmt.Sprintf("tpm2-kira vault enrol --url %s --pin %s --token %s --out /run/tpm2-kira/luks.key", s.cfg.URL, s.pin, value),
	}, nil
}

// adminAudit writes the audit log; with follow=1 it then streams each new
// line until the client goes.
func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request) {
	follow := r.URL.Query().Get("follow") == "1"
	size, lines, cancel := s.audit.Subscribe()
	defer cancel()
	w.Header().Set("Content-Type", "application/x-ndjson")
	bw := bufio.NewWriter(w)
	if err := state.CopyAudit(s.dir.AuditPath(), size, bw); err != nil {
		s.log.Printf("reading the audit log: %v", err)
	}
	bw.Flush()
	if !follow {
		return
	}
	rc := http.NewResponseController(w)
	rc.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case l := <-lines:
			if l.End <= size {
				continue
			}
			if _, err := w.Write(l.Data); err != nil {
				return
			}
			rc.Flush()
		}
	}
}
