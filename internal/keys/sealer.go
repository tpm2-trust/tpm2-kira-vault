package keys

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Sealed is a K_dev sealed in the vault's TPM: a keyedHash sealed data
// object under the owner hierarchy's storage primary (tpm2.ECCSRKTemplate,
// re-created on each use), with authPolicy PolicyPCR over PCRs (SHA-256
// bank) at their values when sealing. With no PCRs it has no policy: it is
// bound to the TPM only.
type Sealed struct {
	PCRs    []uint8 `json:"pcrs"`
	Public  []byte  `json:"public"`  // TPM2B_PUBLIC
	Private []byte  `json:"private"` // TPM2B_PRIVATE
}

// ErrBootStateChanged is an unseal the TPM refused because the vault's
// PCRs are not those of the seal.
var ErrBootStateChanged = errors.New("the vault's own boot state changed: run reseal")

// Sealer seals and unseals K_dev.
type Sealer interface {
	Seal(secret []byte, pcrs []uint8) (*Sealed, error)
	// Unseal returns ErrBootStateChanged when the PCR policy fails.
	Unseal(s *Sealed) ([]byte, error)
}

// TPMSealer seals in the TPM at Path: a device such as /dev/tpmrm0, or a
// TPM simulator's Unix socket. It opens the TPM for each operation.
type TPMSealer struct {
	Path string
	mu   sync.Mutex // one TPM operation at a time, for the raw device and the simulator
}

const rawTPMPath = "/dev/tpm0"

// Open opens the TPM at path. The resource manager /dev/tpmrm0 falls back
// to the raw device when the kernel has none.
func Open(path string) (transport.TPMCloser, error) {
	if path == "/dev/tpmrm0" {
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			if _, err := os.Stat(rawTPMPath); err == nil {
				path = rawTPMPath
			}
		}
	}
	return transport.OpenTPM(path) // a device or a Unix socket
}

type primary struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	public tpm2.TPMTPublic
}

func createPrimary(t transport.TPM) (*primary, func(), error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("creating the storage primary: %w", err)
	}
	flush := func() { tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t) }
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		flush()
		return nil, nil, err
	}
	return &primary{handle: rsp.ObjectHandle, name: rsp.Name, public: *pub}, flush, nil
}

// pcrSelection is pcrs in the SHA-256 bank.
func pcrSelection(pcrs []uint8) tpm2.TPMLPCRSelection {
	bitmap := make([]byte, 3)
	for _, i := range pcrs {
		bitmap[i/8] |= 1 << (i % 8)
	}
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: bitmap}}}
}

// pcrPolicy is the PolicyPCR digest over pcrs at their current values.
func pcrPolicy(t transport.TPM, pcrs []uint8) ([]byte, error) {
	composite := sha256.New()
	for _, i := range pcrs { // one at a time: PCR_Read answers at most eight
		rsp, err := tpm2.PCRRead{PCRSelectionIn: pcrSelection([]uint8{i})}.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("reading PCR %d: %w", i, err)
		}
		if len(rsp.PCRValues.Digests) != 1 {
			return nil, fmt.Errorf("the TPM has no SHA-256 PCR %d", i)
		}
		composite.Write(rsp.PCRValues.Digests[0].Buffer)
	}
	calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}
	if err := (tpm2.PolicyPCR{PcrDigest: tpm2.TPM2BDigest{Buffer: composite.Sum(nil)}, Pcrs: pcrSelection(pcrs)}).Update(calc); err != nil {
		return nil, err
	}
	return calc.Hash().Digest, nil
}

// Seal implements Sealer.
func (s *TPMSealer) Seal(secret []byte, pcrs []uint8) (*Sealed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := Open(s.Path)
	if err != nil {
		return nil, fmt.Errorf("opening the TPM %s: %w", s.Path, err)
	}
	defer t.Close()
	p, flush, err := createPrimary(t)
	if err != nil {
		return nil, err
	}
	defer flush()

	var policy []byte
	if len(pcrs) > 0 {
		if policy, err = pcrPolicy(t, pcrs); err != nil {
			return nil, err
		}
	}
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: p.handle,
			Name:   p.name,
			// The secret travels to the TPM encrypted, under a session
			// salted with the primary.
			Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(p.handle, p.public)),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: secret}),
		}},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: len(pcrs) == 0,
				NoDA:         true,
			},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: policy},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull},
			}),
		}),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("sealing: %w", err)
	}
	return &Sealed{
		PCRs:    append([]uint8{}, pcrs...),
		Public:  tpm2.Marshal(rsp.OutPublic),
		Private: tpm2.Marshal(rsp.OutPrivate),
	}, nil
}

// Unseal implements Sealer.
func (s *TPMSealer) Unseal(sl *Sealed) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](sl.Public)
	if err != nil {
		return nil, fmt.Errorf("the sealed key's public area: %w", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](sl.Private)
	if err != nil {
		return nil, fmt.Errorf("the sealed key's private area: %w", err)
	}
	t, err := Open(s.Path)
	if err != nil {
		return nil, fmt.Errorf("opening the TPM %s: %w", s.Path, err)
	}
	defer t.Close()
	p, flush, err := createPrimary(t)
	if err != nil {
		return nil, err
	}
	defer flush()

	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: p.handle, Name: p.name, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    *priv,
		InPublic:     *pub,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("loading the sealed key: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(t)

	// The secret comes back encrypted, under a session salted with the
	// primary.
	opts := []tpm2.AuthOption{tpm2.AESEncryption(128, tpm2.EncryptOut), tpm2.Salted(p.handle, p.public)}
	var auth tpm2.Session
	if len(sl.PCRs) == 0 {
		auth = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, opts...)
	} else {
		sess, closeSess, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, opts...)
		if err != nil {
			return nil, fmt.Errorf("starting the policy session: %w", err)
		}
		defer closeSess()
		if _, err := (tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: pcrSelection(sl.PCRs)}).Execute(t); err != nil {
			return nil, fmt.Errorf("PolicyPCR: %w", err)
		}
		auth = sess
	}
	rsp, err := tpm2.Unseal{ItemHandle: tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: auth}}.Execute(t)
	if err != nil {
		if errors.Is(err, tpm2.TPMRCPolicyFail) {
			return nil, ErrBootStateChanged
		}
		return nil, fmt.Errorf("unsealing: %w", err)
	}
	return rsp.OutData.Buffer, nil
}
