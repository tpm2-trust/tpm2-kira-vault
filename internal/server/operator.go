package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tpm2-trust/tpm2-kira-vault/internal/state"
	"github.com/tpm2-trust/tpm2-kira-vault/internal/tlsutil"
)

// The operator interface: a subset of the admin handlers on HTTPS, for
// operators with a bearer token each.
const (
	OperatorMaxBody = 4 << 10
	AuthFailLimit   = 10 // failed authentications per remote address per AuthFailWindow
	AuthFailWindow  = time.Minute
)

// OperatorView is an operator as listed: no token.
type OperatorView struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
}

// OperatorRequest is the body of POST /v1/operators.
type OperatorRequest struct {
	Name string `json:"name"`
}

// OperatorAdded is a new operator's token, shown once.
type OperatorAdded struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Token   string    `json:"token"`
	URL     string    `json:"url,omitempty"` // the operator interface's URL; empty while it is off
	Pin     string    `json:"pin"`
	CurlPin string    `json:"curl_pin"` // the pin as curl's --pinnedpubkey takes it
	Example string    `json:"example,omitempty"`
}

// OperatorHandler serves the operator interface: requests, approvals,
// denials and the devices, behind a bearer token.
func (s *Server) OperatorHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/requests", s.adminRequests)
	mux.HandleFunc("POST /v1/requests/{id}/approve", s.adminDecide(approved))
	mux.HandleFunc("POST /v1/requests/{id}/deny", s.adminDecide(denied))
	mux.HandleFunc("GET /v1/devices", s.adminDevices)
	mux.HandleFunc("GET /v1/devices/{id}", s.adminDevice)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "no such path")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, ok := s.authenticate(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := context.WithValue(r.Context(), actorKey, name)
		ctx = context.WithValue(ctx, limitKey, int64(OperatorMaxBody))
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func remoteHost(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// authenticate finds the operator of the request's bearer token. A remote
// address with AuthFailLimit failures in the window is refused without a
// look at its token.
func (s *Server) authenticate(r *http.Request) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	host := remoteHost(r)
	recent := s.authFails[host][:0]
	for _, t := range s.authFails[host] {
		if now.Sub(t) < AuthFailWindow {
			recent = append(recent, t)
		}
	}
	s.authFails[host] = recent
	if len(recent) == 0 {
		delete(s.authFails, host)
	}
	if len(recent) >= AuthFailLimit {
		return "", false
	}

	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	var name string
	if ok && token != "" {
		sum := sha256.Sum256([]byte(token))
		ops, err := s.dir.Operators()
		if err != nil {
			s.log.Printf("reading the operators: %v", err)
		}
		for _, o := range ops { // every one compared, in constant time
			if subtle.ConstantTimeCompare(sum[:], o.TokenSHA256) == 1 {
				name = o.Name
			}
		}
	}
	if name != "" {
		return name, true
	}
	s.authFails[host] = append(recent, now)
	detail := "no or a wrong bearer token"
	if len(s.authFails[host]) >= AuthFailLimit {
		detail += fmt.Sprintf("; refusing this address for up to %s", AuthFailWindow)
	}
	s.logAudit(state.Entry{Event: "operator-auth", Remote: r.RemoteAddr, Result: "refused", Detail: detail + ": " + r.Method + " " + r.URL.Path})
	return "", false
}

// OperatorURL is the operator interface's URL: the configured URL's host
// with the operator listener's port; empty while it is off.
func OperatorURL(cfg *state.Config) string {
	if cfg.OperatorListen == "" {
		return ""
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return ""
	}
	_, port, err := net.SplitHostPort(cfg.OperatorListen)
	if err != nil {
		return ""
	}
	return "https://" + net.JoinHostPort(u.Hostname(), port)
}

func (s *Server) adminOperators(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ops, err := s.dir.Operators()
	views := []OperatorView{}
	for _, o := range ops {
		views = append(views, OperatorView{Name: o.Name, Created: o.Created})
	}
	s.answer(w, views, err)
}

func (s *Server) adminOperatorAdd(w http.ResponseWriter, r *http.Request) {
	var o OperatorRequest
	err := decode(w, r, &o)
	var res *OperatorAdded
	if err == nil {
		res, err = s.addOperator(o.Name)
	}
	s.answer(w, res, err)
}

func (s *Server) addOperator(name string) (*OperatorAdded, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !state.ValidOperatorName(name) {
		return nil, fail(http.StatusBadRequest, "operator name %q: 1 to 64 letters, digits, '.', '_' or '-'", name)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	o := &state.Operator{Name: name, TokenSHA256: sum[:], Created: s.now().UTC()}
	if err := s.dir.PutOperator(o); errors.Is(err, fs.ErrExist) {
		return nil, fail(http.StatusConflict, "operator %q exists: remove it first to give it a new token", name)
	} else if err != nil {
		return nil, err
	}
	if err := s.logAudit(state.Entry{Event: "operator-add", Name: name, Actor: "admin", Result: "done"}); err != nil {
		return nil, err
	}
	res := &OperatorAdded{Name: name, Created: o.Created, Token: token, URL: OperatorURL(s.cfg), Pin: s.pin, CurlPin: tlsutil.CurlPin(s.pin)}
	if res.URL != "" {
		res.Example = fmt.Sprintf("curl -k --pinnedpubkey %s -H 'Authorization: Bearer %s' %s/v1/requests", res.CurlPin, token, res.URL)
	}
	return res, nil
}

func (s *Server) adminOperatorRemove(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.dir.RemoveOperator(name); errors.Is(err, state.ErrNotFound) {
			return fail(http.StatusNotFound, "no operator %q", name)
		} else if err != nil {
			return err
		}
		return s.logAudit(state.Entry{Event: "operator-remove", Name: name, Actor: "admin", Result: "done"})
	}()
	s.answer(w, OperatorView{Name: name}, err)
}
