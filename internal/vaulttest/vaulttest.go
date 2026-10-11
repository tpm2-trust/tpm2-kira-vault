// Package vaulttest simulates a machine for the vault's tests: a TPM double
// (attesttest.SoftTPM), a signing key that approved its PCRs at a
// generation, and an HTTP client that pins the vault's key, as tpm2-kira
// does.
package vaulttest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/mrwiora/tpm2-kira/attest"
	"github.com/mrwiora/tpm2-kira/attest/attesttest"
	"github.com/mrwiora/tpm2-kira/vaultproto"

	"github.com/mrwiora/tpm2-kira-vault/internal/tlsutil"
)

// Machine is a simulated machine with one tpm+vault keyslot.
type Machine struct {
	TPM       *attesttest.SoftTPM
	Signer    *ecdsa.PrivateKey
	DeviceID  []byte
	Name      string
	PolicyRef []byte
	GenIndex  []byte
	Selection vaultproto.Selection
	Gen       uint64
	Approval  []byte
	R         []byte             // the remote part in the clear, as the machine drew it
	Remote    vaultproto.Wrapped // R wrapped for the TPM (EK and the AK's name stand in for the release key)
}

// NewMachine makes a machine whose signing key approved its PCRs at
// generation 5.
func NewMachine(name string) (*Machine, error) {
	s, err := attesttest.NewSoftTPM()
	if err != nil {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	m := &Machine{
		TPM: s, Signer: k, Name: name, Gen: 5,
		DeviceID:  make([]byte, vaultproto.DeviceIDSize),
		PolicyRef: bytes.Repeat([]byte{0x9E}, 16),
		GenIndex:  append([]byte{0, 0x0b}, bytes.Repeat([]byte{7}, 32)...),
		Selection: vaultproto.Selection{Alg: uint16(tpm2.TPMAlgSHA256), Indices: []uint8{0, 7, 11}},
		R:         make([]byte, vaultproto.SecretSize),
	}
	rand.Read(m.DeviceID)
	rand.Read(m.R)
	cred, enc, err := attest.MakeCredential(rand.Reader, s.EKPub, s.AKName, m.R)
	if err != nil {
		return nil, err
	}
	m.Remote = vaultproto.Wrapped{Credential: cred, EncryptedSecret: enc}
	m.Approve()
	return m, nil
}

// SigningPublic is the TPMT_PUBLIC of the signing key.
func (m *Machine) SigningPublic() []byte {
	tmpl := attest.AKTemplateECC()
	tmpl.ObjectAttributes.Restricted = false
	tmpl.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: m.Signer.PublicKey.X.FillBytes(make([]byte, 32))},
		Y: tpm2.TPM2BECCParameter{Buffer: m.Signer.PublicKey.Y.FillBytes(make([]byte, 32))},
	})
	return tpm2.Marshal(tmpl)
}

func (m *Machine) values() []vaultproto.PCRValue {
	var vals []vaultproto.PCRValue
	for _, i := range m.Selection.Indices {
		vals = append(vals, vaultproto.PCRValue{Index: i, Value: m.TPM.PCRs[i]})
	}
	return vals
}

// Approve signs the current PCR values at m.Gen, as reseal does.
func (m *Machine) Approve() {
	d := vaultproto.ApprovalDigest(vaultproto.ApprovedPolicy(vaultproto.PolicyPCRDigest(m.Selection, m.values()), m.GenIndex, m.Gen), m.PolicyRef)
	r, s, _ := ecdsa.Sign(rand.Reader, m.Signer, d)
	m.Approval = tpm2.Marshal(tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpm2.TPMAlgSHA256,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: r.FillBytes(make([]byte, 32))},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: s.FillBytes(make([]byte, 32))},
		}),
	})
}

// EnrolRequest is the machine's enrolment request.
func (m *Machine) EnrolRequest(token string) *vaultproto.EnrolRequest {
	return &vaultproto.EnrolRequest{
		Token: token, DeviceID: m.DeviceID, Name: m.Name,
		EKPublic: m.TPM.EKPub, AKPublic: m.TPM.AKPub,
		SigningPublic: m.SigningPublic(), PolicyRef: m.PolicyRef, GenerationIndexName: m.GenIndex,
		Generation: m.Gen, Selection: m.Selection, Remote: m.Remote, Label: "root",
	}
}

// ReleaseRequest is the machine's evidence for a challenge.
func (m *Machine) ReleaseRequest(ch *vaultproto.ChallengeResponse) (*vaultproto.ReleaseRequest, error) {
	sel := attest.PCRSelection{Alg: m.Selection.Alg, Indices: m.Selection.Indices}
	q, err := m.TPM.Quote(vaultproto.QualifyingData(m.DeviceID, ch.RequestID, ch.Nonce), sel)
	if err != nil {
		return nil, err
	}
	req := &vaultproto.ReleaseRequest{
		RequestID: ch.RequestID, DeviceID: m.DeviceID, Quoted: q.Quoted, QuoteSignature: q.Signature,
		Generation: m.Gen, ApprovalSignature: m.Approval,
	}
	for _, v := range q.Values {
		req.PCRValues = append(req.PCRValues, vaultproto.PCRValue{Index: v.Index, Value: v.Digest})
	}
	return req, nil
}

// Client talks to the vault's machine-facing interface.
type Client struct {
	URL  string
	HTTP *http.Client
}

// NewClient pins the vault's key as tpm2-kira does.
func NewClient(url, pin string) *Client {
	return &Client{URL: url, HTTP: &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsutil.PinnedConfig(pin)},
	}}
}

// StatusError is a non-2xx answer.
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Code, e.Msg) }

// Post sends in and decodes the answer into out; a non-2xx answer is a
// *StatusError.
func (c *Client) Post(path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	rsp, err := c.HTTP.Post(c.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return err
	}
	if rsp.StatusCode/100 != 2 {
		var e vaultproto.ErrorResponse
		json.Unmarshal(body, &e)
		return &StatusError{Code: rsp.StatusCode, Msg: e.Error}
	}
	return json.Unmarshal(body, out)
}

// Enrol runs the whole enrolment, the AK's proof included.
func (m *Machine) Enrol(c *Client, token string) (*vaultproto.EnrolResult, error) {
	var ch vaultproto.EnrolChallenge
	if err := c.Post(vaultproto.PathEnrol, m.EnrolRequest(token), &ch); err != nil {
		return nil, err
	}
	secret, err := m.TPM.ActivateCredential(ch.Challenge.Credential, ch.Challenge.EncryptedSecret)
	if err != nil {
		return nil, fmt.Errorf("activating the enrolment credential: %w", err)
	}
	var res vaultproto.EnrolResult
	if err := c.Post(vaultproto.PathEnrolConfirm, vaultproto.EnrolConfirm{EnrolID: ch.EnrolID, Secret: secret}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Challenge asks for a challenge.
func (m *Machine) Challenge(c *Client) (*vaultproto.ChallengeResponse, error) {
	var ch vaultproto.ChallengeResponse
	if err := c.Post(vaultproto.PathChallenge, vaultproto.ChallengeRequest{DeviceID: m.DeviceID}, &ch); err != nil {
		return nil, err
	}
	return &ch, nil
}

// Send sends a release request.
func (c *Client) Send(req *vaultproto.ReleaseRequest) (*vaultproto.ReleaseResponse, error) {
	var res vaultproto.ReleaseResponse
	if err := c.Post(vaultproto.PathRelease, req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Release asks for a challenge and answers it once.
func (m *Machine) Release(c *Client) (*vaultproto.ReleaseRequest, *vaultproto.ReleaseResponse, error) {
	ch, err := m.Challenge(c)
	if err != nil {
		return nil, nil, err
	}
	req, err := m.ReleaseRequest(ch)
	if err != nil {
		return nil, nil, err
	}
	res, err := c.Send(req)
	return req, res, err
}

// Open opens a released remote part with the machine's TPM, as the
// machine's ActivateCredential does.
func (m *Machine) Open(w *vaultproto.Wrapped) ([]byte, error) {
	return m.TPM.ActivateCredential(w.Credential, w.EncryptedSecret)
}
