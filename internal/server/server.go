// Package server is the vault's HTTP interfaces: the machine-facing
// protocol of vaultproto (served over TLS), the admin interface (served on
// a root-only Unix socket, the CLI's counterpart), and the operator
// interface (a subset of the admin handlers over TLS, behind a bearer token
// per operator, on a listener of its own).
//
// The rules are those of docs/VAULT.md §6.1 of tpm2-kira:
//
//   - a challenge is 32 random bytes, valid ChallengeTTL, for one request;
//     a terminal answer (released, denied) consumes it;
//   - a verified request of a device in approve mode stays pending for
//     PendingTTL and is denied then; the machine sends the same request
//     again and is answered by its request ID; an approved request is
//     answered for ChallengeTTL more;
//   - a device enrolled with a pepper is always in approve mode, and the
//     approval carries the pepper. It is kept in memory with the request,
//     passed on once in the releasing answer, and wiped: never written,
//     never logged;
//   - MaxFailures failed verifications in a row lock the device until an
//     operator unlocks it;
//   - at most RateLimit challenges per device per RateWindow;
//   - the highest verified generation is kept, a lower one is refused;
//   - every enrolment, challenge, verification, release, denial and admin
//     action goes to the audit log.
//
// Pending requests are kept in memory only: after a restart the machine
// starts with a new challenge.
package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/mrwiora/tpm2-kira/attest"
	"github.com/mrwiora/tpm2-kira/vaultproto"

	"github.com/mrwiora/tpm2-kira-vault/internal/keys"
	"github.com/mrwiora/tpm2-kira-vault/internal/state"
)

// The rules.
const (
	ChallengeTTL = 120 * time.Second
	PendingTTL   = 15 * time.Minute
	EnrolTTL     = 5 * time.Minute
	MaxFailures  = 5
	RateLimit    = 10
	RateWindow   = time.Minute
	RetryAfter   = 5 // seconds, for a pending request
	MaxBody      = 1 << 20
)

// Options configure a Server.
type Options struct {
	Dir    state.Dir
	Config *state.Config
	Sealer keys.Sealer
	Audit  *state.Audit
	Pin    string           // the pin of the TLS key, for token create
	Now    func() time.Time // the clock; time.Now when nil
	Log    *log.Logger      // operational messages; never secrets
}

// Server holds the vault's in-memory state: enrolments in progress,
// challenges and pending requests, the rate windows.
type Server struct {
	dir    state.Dir
	cfg    *state.Config
	sealer keys.Sealer
	audit  *state.Audit
	pin    string
	now    func() time.Time
	log    *log.Logger

	mu       sync.Mutex
	enrols   map[string]*enrolment
	requests map[string]*request
	rate     map[string][]time.Time

	authFails map[string][]time.Time // failed operator authentications per remote address
}

type enrolment struct {
	req       *vaultproto.EnrolRequest
	secret    []byte
	tokenHash []byte
	token     *state.Token
	expires   time.Time
}

type reqState int

const (
	fresh    reqState = iota // challenged, not yet verified
	pending                  // verified, waiting for an operator
	approved                 // an operator approved it
	denied                   // an operator denied it
)

type request struct {
	id      string
	device  []byte
	nonce   []byte
	created time.Time
	expires time.Time // the challenge's end, or the pending window's
	state   reqState
	digest  []byte // of the verified request, which a re-sent one must equal
	checked *vaultproto.Checked
	remote  string

	actor  string // who approved or denied it
	pepper []byte // the approval's pepper, until the release passes it on
}

// forget drops a request and wipes its pepper.
func (s *Server) forget(q *request) {
	clear(q.pepper)
	q.pepper = nil
	delete(s.requests, q.id)
}

// New makes a Server.
func New(o Options) *Server {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	lg := o.Log
	if lg == nil {
		lg = log.New(io.Discard, "", 0)
	}
	return &Server{
		dir: o.Dir, cfg: o.Config, sealer: o.Sealer, audit: o.Audit, pin: o.Pin, now: now, log: lg,
		enrols:   map[string]*enrolment{},
		requests: map[string]*request{},
		rate:     map[string][]time.Time{},

		authFails: map[string][]time.Time{},
	}
}

// MachineHandler serves the four paths of vaultproto.
func (s *Server) MachineHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+vaultproto.PathEnrol, s.handleEnrol)
	mux.HandleFunc("POST "+vaultproto.PathEnrolConfirm, s.handleEnrolConfirm)
	mux.HandleFunc("POST "+vaultproto.PathChallenge, s.handleChallenge)
	mux.HandleFunc("POST "+vaultproto.PathRelease, s.handleRelease)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "no such path")
	})
	return mux
}

// ── helpers ──────────────────────────────────────────────────────────────

type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }

func fail(code int, format string, a ...any) error {
	return &httpError{code: code, msg: fmt.Sprintf(format, a...)}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, vaultproto.ErrorResponse{Error: msg})
}

// answer writes v, or the error err stands for.
func (s *Server) answer(w http.ResponseWriter, v any, err error) {
	if err != nil {
		var he *httpError
		if errors.As(err, &he) {
			writeError(w, he.code, he.msg)
			return
		}
		s.log.Printf("internal error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	body, err := readBody(w, r)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fail(http.StatusBadRequest, "the request does not parse: %v", err)
	}
	return nil
}

// readBody reads a request's body, at most the interface's limit.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	limit := bodyLimit(r)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, fail(http.StatusRequestEntityTooLarge, "the request is larger than %d bytes", limit)
		}
		return nil, fail(http.StatusBadRequest, "reading the request: %v", err)
	}
	return body, nil
}

type ctxKey int

const (
	limitKey ctxKey = iota
	actorKey
)

// bodyLimit is MaxBody, or the smaller limit of the operator interface.
func bodyLimit(r *http.Request) int64 {
	if l, ok := r.Context().Value(limitKey).(int64); ok {
		return l
	}
	return MaxBody
}

// actorOf is who calls the admin handlers: "admin" on the Unix socket, the
// operator's name on the operator interface.
func actorOf(r *http.Request) string {
	if a, ok := r.Context().Value(actorKey).(string); ok {
		return a
	}
	return "admin"
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// TokenHash is how a token is stored and looked up.
func TokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func (s *Server) logAudit(e state.Entry) error {
	if err := s.audit.Log(e); err != nil {
		s.log.Printf("audit log: %v", err)
		return err
	}
	return nil
}

// ── enrolment ────────────────────────────────────────────────────────────

func (s *Server) handleEnrol(w http.ResponseWriter, r *http.Request) {
	var req vaultproto.EnrolRequest
	err := decode(w, r, &req)
	var ch *vaultproto.EnrolChallenge
	if err == nil {
		ch, err = s.enrol(&req, r.RemoteAddr)
	}
	s.answer(w, ch, err)
}

func (s *Server) enrol(req *vaultproto.EnrolRequest, remote string) (*vaultproto.EnrolChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	dev := hex.EncodeToString(req.DeviceID)
	refuse := func(code int, msg string) error {
		if err := s.logAudit(state.Entry{Event: "enrol", Device: dev, Name: req.Name, Remote: remote, Result: "refused", Detail: msg}); err != nil {
			return err
		}
		return fail(code, "%s", msg)
	}

	th := TokenHash(req.Token)
	tok, err := s.dir.Token(th)
	if errors.Is(err, state.ErrNotFound) {
		return nil, refuse(http.StatusForbidden, "the token is unknown or used")
	} else if err != nil {
		return nil, err
	}
	if !now.Before(tok.Expires) {
		return nil, refuse(http.StatusForbidden, "the token expired")
	}
	if err := req.Check(); err != nil {
		return nil, refuse(http.StatusBadRequest, "the enrolment request: "+err.Error())
	}
	if tok.Replace != nil && !bytes.Equal(tok.Replace, req.DeviceID) {
		return nil, refuse(http.StatusForbidden, fmt.Sprintf("the token replaces device %x, not this one", tok.Replace))
	}
	if _, err := s.dir.Device(req.DeviceID); err == nil {
		if tok.Replace == nil {
			return nil, refuse(http.StatusConflict, fmt.Sprintf("device %s is enrolled already: create a token with --replace %s", dev, dev))
		}
	} else if !errors.Is(err, state.ErrNotFound) {
		return nil, err
	}

	akPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](req.AKPublic)
	if err != nil {
		return nil, refuse(http.StatusBadRequest, "the attestation key does not parse")
	}
	akName, err := tpm2.ObjectName(akPub)
	if err != nil {
		return nil, refuse(http.StatusBadRequest, "the attestation key has no name")
	}
	secret := randomBytes(vaultproto.SecretSize)
	cred, enc, err := attest.MakeCredential(rand.Reader, req.EKPublic, akName.Buffer, secret)
	if err != nil {
		return nil, refuse(http.StatusBadRequest, "the endorsement key: "+err.Error())
	}
	id := randomID()
	s.sweep(now)
	s.enrols[id] = &enrolment{req: req, secret: secret, tokenHash: th, token: tok, expires: now.Add(EnrolTTL)}
	if err := s.logAudit(state.Entry{Event: "enrol", Device: dev, Name: req.Name, Request: id, Remote: remote, Result: "challenged", Detail: "token " + tok.Name}); err != nil {
		delete(s.enrols, id)
		return nil, err
	}
	return &vaultproto.EnrolChallenge{EnrolID: id, Challenge: vaultproto.Wrapped{Credential: cred, EncryptedSecret: enc}}, nil
}

func (s *Server) handleEnrolConfirm(w http.ResponseWriter, r *http.Request) {
	var c vaultproto.EnrolConfirm
	err := decode(w, r, &c)
	var res *vaultproto.EnrolResult
	if err == nil {
		res, err = s.enrolConfirm(&c, r.RemoteAddr)
	}
	s.answer(w, res, err)
}

func (s *Server) enrolConfirm(c *vaultproto.EnrolConfirm, remote string) (*vaultproto.EnrolResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	e := s.enrols[c.EnrolID]
	if e == nil {
		return nil, fail(http.StatusNotFound, "unknown enrolment: start again")
	}
	delete(s.enrols, c.EnrolID) // one answer per challenge
	req := e.req
	dev := hex.EncodeToString(req.DeviceID)
	refuse := func(code int, msg string) error {
		if err := s.logAudit(state.Entry{Event: "enrol-confirm", Device: dev, Name: req.Name, Request: c.EnrolID, Remote: remote, Result: "refused", Detail: msg}); err != nil {
			return err
		}
		return fail(code, "%s", msg)
	}
	if !now.Before(e.expires) {
		return nil, refuse(http.StatusForbidden, "the enrolment expired: start again")
	}
	if subtle.ConstantTimeCompare(c.Secret, e.secret) != 1 {
		return nil, refuse(http.StatusForbidden, "the attestation key is not in the TPM of the endorsement key")
	}
	if !now.Before(e.token.Expires) {
		return nil, refuse(http.StatusForbidden, "the token expired")
	}

	kdev, err := keys.NewKey()
	if err != nil {
		return nil, err
	}
	defer keys.Wipe(kdev)
	remoteJSON, err := json.Marshal(req.Remote)
	if err != nil {
		return nil, err
	}
	encRemote, err := keys.Encrypt(kdev, remoteJSON, req.DeviceID)
	if err != nil {
		return nil, err
	}
	sealed, err := s.sealer.Seal(kdev, s.cfg.PCRs)
	if err != nil {
		return nil, fmt.Errorf("sealing the device key: %w", err)
	}
	recovery, err := keys.EncryptToRecovery(s.cfg.RecoveryPublic, kdev, req.DeviceID)
	if err != nil {
		return nil, err
	}
	mode := e.token.Mode
	if req.Pepper {
		mode = vaultproto.ModeApprove
	}
	pinned := vaultproto.DeviceOf(req)
	rec := &state.Device{
		ID:                  pinned.DeviceID,
		Name:                req.Name,
		Label:               req.Label,
		Mode:                mode,
		PepperRequired:      req.Pepper,
		EKPublic:            req.EKPublic,
		EKCert:              req.EKCert,
		AKPublic:            pinned.AKPublic,
		SigningPublic:       pinned.SigningPublic,
		PolicyRef:           pinned.PolicyRef,
		GenerationIndexName: pinned.GenerationIndexName,
		Selection:           pinned.Selection,
		MinGeneration:       req.Generation,
		EnrolledAt:          now.UTC(),
		Remote:              encRemote,
		Sealed:              *sealed,
		Recovery:            recovery,
	}

	if err := s.dir.ConsumeToken(e.tokenHash); errors.Is(err, state.ErrNotFound) {
		return nil, refuse(http.StatusForbidden, "the token was used meanwhile")
	} else if err != nil {
		return nil, err
	}
	if err := s.dir.SaveDevice(rec); err != nil {
		return nil, err
	}
	// A device enrolled again starts without the old one's requests.
	for _, q := range s.requests {
		if bytes.Equal(q.device, rec.ID) {
			s.forget(q)
		}
	}
	delete(s.rate, dev)
	detail := "token " + e.token.Name
	if e.token.Replace != nil {
		detail += ", replacing the device's earlier enrolment"
	}
	if rec.PepperRequired {
		detail += ", with a pepper"
	}
	if err := s.logAudit(state.Entry{Event: "enrol-confirm", Device: dev, Name: req.Name, Request: c.EnrolID, Remote: remote, Result: "enrolled", Detail: fmt.Sprintf("%s, mode %s, generation %d", detail, rec.Mode, rec.MinGeneration)}); err != nil {
		return nil, err
	}
	s.log.Printf("enrolled device %s (%s), mode %s", dev, req.Name, rec.Mode)
	return &vaultproto.EnrolResult{DeviceID: rec.ID, Mode: rec.Mode}, nil
}

// ── challenge ────────────────────────────────────────────────────────────

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var c vaultproto.ChallengeRequest
	err := decode(w, r, &c)
	var res *vaultproto.ChallengeResponse
	if err == nil {
		res, err = s.challenge(&c, r.RemoteAddr)
	}
	s.answer(w, res, err)
}

func (s *Server) challenge(c *vaultproto.ChallengeRequest, remote string) (*vaultproto.ChallengeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(c.DeviceID) != vaultproto.DeviceIDSize {
		return nil, fail(http.StatusBadRequest, "a device ID has %d bytes", vaultproto.DeviceIDSize)
	}
	dev := hex.EncodeToString(c.DeviceID)
	d, err := s.dir.Device(c.DeviceID)
	if errors.Is(err, state.ErrNotFound) {
		if err := s.logAudit(state.Entry{Event: "challenge", Device: dev, Remote: remote, Result: "refused", Detail: "unknown device"}); err != nil {
			return nil, err
		}
		return nil, fail(http.StatusNotFound, "unknown device")
	} else if err != nil {
		return nil, err
	}
	s.sweep(now)

	window := s.rate[dev][:0]
	for _, t := range s.rate[dev] {
		if now.Sub(t) < RateWindow {
			window = append(window, t)
		}
	}
	if len(window) >= RateLimit {
		s.rate[dev] = window
		if err := s.logAudit(state.Entry{Event: "challenge", Device: dev, Name: d.Name, Remote: remote, Result: "refused", Detail: "rate limit"}); err != nil {
			return nil, err
		}
		return nil, fail(http.StatusTooManyRequests, "at most %d challenges per device per minute", RateLimit)
	}
	s.rate[dev] = append(window, now)

	q := &request{id: randomID(), device: c.DeviceID, nonce: randomBytes(vaultproto.NonceSize), created: now, expires: now.Add(ChallengeTTL), remote: remote}
	if err := s.logAudit(state.Entry{Event: "challenge", Device: dev, Name: d.Name, Request: q.id, Remote: remote, Result: "issued"}); err != nil {
		return nil, err
	}
	s.requests[q.id] = q
	return &vaultproto.ChallengeResponse{RequestID: q.id, Nonce: q.nonce, ExpiresIn: int(ChallengeTTL / time.Second)}, nil
}

// sweep forgets enrolments and requests well past their end. One past its
// end only shortly is still answered (denied, the challenge expired).
func (s *Server) sweep(now time.Time) {
	for id, e := range s.enrols {
		if now.Sub(e.expires) > EnrolTTL {
			delete(s.enrols, id)
		}
	}
	for _, q := range s.requests {
		if now.Sub(q.expires) > ChallengeTTL {
			s.forget(q)
		}
	}
}

// ── release ──────────────────────────────────────────────────────────────

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	var req vaultproto.ReleaseRequest
	err := decode(w, r, &req)
	var res *vaultproto.ReleaseResponse
	if err == nil {
		res, err = s.release(&req, r.RemoteAddr)
	}
	s.answer(w, res, err)
	if res != nil {
		clear(res.Pepper)
	}
}

func requestDigest(req *vaultproto.ReleaseRequest) []byte {
	b, _ := json.Marshal(req)
	h := sha256.Sum256(b)
	return h[:]
}

func (s *Server) release(req *vaultproto.ReleaseRequest, remote string) (*vaultproto.ReleaseResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	q := s.requests[req.RequestID]
	if q == nil {
		return nil, fail(http.StatusNotFound, "unknown request (expired or answered): start with a new challenge")
	}
	if !bytes.Equal(q.device, req.DeviceID) {
		return nil, fail(http.StatusBadRequest, "the request is for another device than its challenge")
	}
	dev := hex.EncodeToString(q.device)
	entry := state.Entry{Event: "release", Device: dev, Request: q.id, Remote: remote}

	// deny consumes the request and answers denied.
	deny := func(reason string) (*vaultproto.ReleaseResponse, error) {
		s.forget(q)
		entry.Result, entry.Detail = "denied", reason
		if err := s.logAudit(entry); err != nil {
			return nil, err
		}
		return &vaultproto.ReleaseResponse{Status: vaultproto.StatusDenied, Reason: reason}, nil
	}

	if q.state != fresh && subtle.ConstantTimeCompare(q.digest, requestDigest(req)) != 1 {
		return nil, fail(http.StatusBadRequest, "a pending request is answered only when sent again unchanged")
	}
	switch q.state {
	case pending:
		if !now.Before(q.expires) {
			return deny("not approved within 15 minutes")
		}
		return &vaultproto.ReleaseResponse{Status: vaultproto.StatusPending, RetryAfter: RetryAfter}, nil
	case denied:
		return deny("an operator denied the request")
	case approved:
		if !now.Before(q.expires) {
			return deny("the approval expired: the machine did not ask again in time")
		}
	case fresh:
		if !now.Before(q.expires) {
			return deny("the challenge expired")
		}
	}

	d, err := s.dir.Device(q.device)
	if errors.Is(err, state.ErrNotFound) {
		return deny("unknown device")
	} else if err != nil {
		return nil, err
	}
	entry.Name = d.Name
	if d.Revoked {
		return deny("the device is revoked")
	}
	if d.Locked {
		return deny(fmt.Sprintf("the device is locked after %d failed verifications: an operator must unlock it", MaxFailures))
	}

	checked, verr := vaultproto.VerifyRelease(d.Pinned(), q.nonce, req, d.MinGeneration)
	if verr != nil {
		d.Failures++
		reason := verr.Error()
		if d.Failures >= MaxFailures {
			d.Locked = true
			reason += fmt.Sprintf("; the device is locked after %d failed verifications", d.Failures)
		}
		if err := s.dir.SaveDevice(d); err != nil {
			return nil, err
		}
		entry.Event = "verify"
		return deny(reason)
	}
	if d.Failures != 0 {
		d.Failures = 0
		if err := s.dir.SaveDevice(d); err != nil {
			return nil, err
		}
	}

	if q.state == fresh && (d.Mode == vaultproto.ModeApprove || d.PepperRequired) {
		q.state = pending
		q.digest = requestDigest(req)
		q.checked = checked
		q.expires = now.Add(PendingTTL)
		entry.Result, entry.Detail = "pending", fmt.Sprintf("verified at generation %d, waiting for an operator", checked.Generation)
		if err := s.logAudit(entry); err != nil {
			return nil, err
		}
		return &vaultproto.ReleaseResponse{Status: vaultproto.StatusPending, RetryAfter: RetryAfter}, nil
	}

	if d.PepperRequired && len(q.pepper) == 0 { // decide refuses such an approval; this keeps it so
		return deny("this device was enrolled with a pepper, and the approval carries none")
	}

	kdev, err := s.sealer.Unseal(&d.Sealed)
	if err != nil {
		if errors.Is(err, keys.ErrBootStateChanged) {
			s.log.Printf("device %s: %v", dev, err)
			return deny(keys.ErrBootStateChanged.Error())
		}
		s.log.Printf("device %s: unsealing its key: %v", dev, err)
		return deny("the vault could not unseal the device's key")
	}
	plain, err := keys.Decrypt(kdev, d.Remote, d.ID)
	keys.Wipe(kdev)
	if err != nil {
		s.log.Printf("device %s: decrypting its record: %v", dev, err)
		return deny("the vault could not open the device's record")
	}
	var wrapped vaultproto.Wrapped
	err = json.Unmarshal(plain, &wrapped)
	keys.Wipe(plain)
	if err != nil {
		return deny("the vault could not open the device's record")
	}

	if checked.Generation > d.MinGeneration {
		d.MinGeneration = checked.Generation
	}
	t := now.UTC()
	d.LastRelease = &t
	if err := s.dir.SaveDevice(d); err != nil {
		return nil, err
	}
	res := &vaultproto.ReleaseResponse{Status: vaultproto.StatusReleased, Remote: &wrapped}
	entry.Result, entry.Detail = "released", fmt.Sprintf("generation %d, TPM reset count %d", checked.Generation, checked.ResetCount)
	if q.state == approved {
		entry.Detail += ", approved by " + q.actor
	}
	if d.PepperRequired {
		res.Pepper = append([]byte(nil), q.pepper...)
		entry.Detail += ", with a pepper"
	}
	s.forget(q)
	if err := s.logAudit(entry); err != nil {
		clear(res.Pepper)
		return nil, err
	}
	return res, nil
}
