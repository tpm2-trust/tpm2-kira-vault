// Package state is the vault's state directory: its configuration, the TLS
// key, the enrolled devices, the enrolment tokens and the audit log.
//
//	config.json             Config
//	tls/key.pem, cert.pem   the TLS key and its self-signed certificate
//	devices/<id>.json       one Device per enrolled machine (hex device ID)
//	tokens/<sha256>.json    one Token per unused enrolment token
//	operators/<name>.json   one Operator per bearer token of the operator interface
//	audit.log               JSON lines, append-only
//	lock                    held by serve, init and reseal (flock)
//
// The directory is 0700, every file 0600, and every file but the audit log
// is written atomically (temporary file, fsync, rename, fsync of the
// directory).
package state

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/mrwiora/tpm2-kira/core/vaultproto"

	"github.com/mrwiora/tpm2-kira-vault/internal/keys"
)

// DefaultDir is the state directory of an installed vault.
const DefaultDir = "/var/lib/tpm2-kira-vault"

// DefaultAdminSocket is where serve answers the CLI.
const DefaultAdminSocket = "/run/tpm2-kira-vault/admin.sock"

// DefaultTPM is the TPM the vault seals its device keys in.
const DefaultTPM = "/dev/tpmrm0"

// Config is config.json.
type Config struct {
	Listen      string  `json:"listen"`       // the machine-facing HTTPS address, e.g. ":8443"
	URL         string  `json:"url"`          // the public URL machines enrol with
	PCRs        []uint8 `json:"pcrs"`         // the vault's own PCR selection, SHA-256 bank; empty: no PCR policy
	TPM         string  `json:"tpm"`          // TPM device or swtpm socket
	AdminSocket string  `json:"admin_socket"` // the CLI's Unix socket

	// OperatorListen is the operator interface's HTTPS address, e.g.
	// ":8444"; empty: off.
	OperatorListen string `json:"operator_listen,omitempty"`

	// RecoveryPublic is the X25519 public key of the recovery key: every
	// device key is also encrypted to it, and only the recovery key opens
	// those copies (keys.RecoveryKey).
	RecoveryPublic []byte `json:"recovery_public"`
}

// Device is devices/<id>.json: what the vault pinned of a machine at
// enrolment, its release state, and its keys.
type Device struct {
	ID    []byte `json:"device_id"`
	Name  string `json:"name"`
	Label string `json:"label"`
	Mode  string `json:"mode"` // vaultproto.ModeAuto or ModeApprove
	// PepperRequired: the machine's key is derived with an operator's
	// pepper as well, so every release needs an approval carrying it. Such
	// a device is always in approve mode.
	PepperRequired bool   `json:"pepper_required"`
	EKPublic       []byte `json:"ek_public"`
	EKCert         []byte `json:"ek_cert,omitempty"`

	AKPublic            []byte               `json:"ak_public"`
	SigningPublic       []byte               `json:"signing_public"`
	PolicyRef           []byte               `json:"policy_ref"`
	GenerationIndexName []byte               `json:"generation_index_name"`
	Selection           vaultproto.Selection `json:"selection"`

	MinGeneration uint64     `json:"min_generation"` // the highest verified generation
	Revoked       bool       `json:"revoked"`
	Locked        bool       `json:"locked"`   // after MaxFailures failed verifications in a row
	Failures      int        `json:"failures"` // failed verifications in a row
	EnrolledAt    time.Time  `json:"enrolled_at"`
	LastRelease   *time.Time `json:"last_release,omitempty"`

	// Remote is the machine's wrapped R (the JSON of a vaultproto.Wrapped),
	// encrypted with AES-256-GCM under K_dev, the device ID as AAD.
	Remote []byte `json:"remote"`
	// Sealed is K_dev, sealed in the vault's TPM.
	Sealed keys.Sealed `json:"sealed"`
	// Recovery is K_dev encrypted to the recovery key, the device ID as AAD.
	Recovery []byte `json:"recovery"`
}

// Pinned is what VerifyRelease checks a release request against.
func (d *Device) Pinned() *vaultproto.Device {
	return &vaultproto.Device{
		DeviceID:            d.ID,
		AKPublic:            d.AKPublic,
		SigningPublic:       d.SigningPublic,
		PolicyRef:           d.PolicyRef,
		GenerationIndexName: d.GenerationIndexName,
		Selection:           d.Selection,
	}
}

// Token is tokens/<sha256 of the token>.json. The token itself is not
// kept.
type Token struct {
	Name    string    `json:"name"`
	Mode    string    `json:"mode"`
	Expires time.Time `json:"expires"`
	Replace []byte    `json:"replace,omitempty"` // the device this token may enrol again
}

// ErrNotFound is a device or token that is not there.
var ErrNotFound = errors.New("not found")

// ErrLocked is a state directory another process holds.
var ErrLocked = errors.New("the state directory is in use: is tpm2-kira-vault serve running? Stop it first")

// Dir is a state directory.
type Dir struct{ Path string }

func (d Dir) path(parts ...string) string {
	return filepath.Join(append([]string{d.Path}, parts...)...)
}

// TLSKeyPath and TLSCertPath are the TLS key and certificate (PEM).
func (d Dir) TLSKeyPath() string  { return d.path("tls", "key.pem") }
func (d Dir) TLSCertPath() string { return d.path("tls", "cert.pem") }

// AuditPath is the audit log.
func (d Dir) AuditPath() string { return d.path("audit.log") }

// Create makes the directory tree, 0700.
func (d Dir) Create() error {
	for _, p := range []string{d.Path, d.path("tls"), d.path("devices"), d.path("tokens"), d.path("operators")} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(p, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// Lock takes the directory's lock without waiting. The lock is released
// by the returned function, or when the process ends.
func (d Dir) Lock() (func(), error) {
	if err := os.MkdirAll(d.Path, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(d.path("lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}

// Initialised reports whether config.json exists.
func (d Dir) Initialised() bool {
	_, err := os.Stat(d.path("config.json"))
	return err == nil
}

// Config reads config.json.
func (d Dir) Config() (*Config, error) {
	var c Config
	if err := readJSON(d.path("config.json"), &c); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("%s is not a vault's state directory: run tpm2-kira-vault init", d.Path)
		}
		return nil, err
	}
	return &c, nil
}

// SaveConfig writes config.json.
func (d Dir) SaveConfig(c *Config) error { return writeJSON(d.path("config.json"), c) }

// DeviceFile is the file name of a device ID.
func DeviceFile(id []byte) string { return hex.EncodeToString(id) + ".json" }

// Device reads one device.
func (d Dir) Device(id []byte) (*Device, error) {
	if len(id) != vaultproto.DeviceIDSize {
		return nil, ErrNotFound
	}
	var dev Device
	if err := readJSON(d.path("devices", DeviceFile(id)), &dev); err != nil {
		return nil, err
	}
	return &dev, nil
}

// SaveDevice writes one device.
func (d Dir) SaveDevice(dev *Device) error {
	return writeJSON(d.path("devices", DeviceFile(dev.ID)), dev)
}

// Devices reads every device, ordered by name and ID.
func (d Dir) Devices() ([]*Device, error) {
	ents, err := os.ReadDir(d.path("devices"))
	if err != nil {
		return nil, err
	}
	var out []*Device
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id, err := hex.DecodeString(strings.TrimSuffix(name, ".json"))
		if err != nil {
			continue
		}
		dev, err := d.Device(id)
		if err != nil {
			return nil, fmt.Errorf("device %s: %w", name, err)
		}
		out = append(out, dev)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return hex.EncodeToString(out[i].ID) < hex.EncodeToString(out[j].ID)
	})
	return out, nil
}

func (d Dir) tokenPath(hash []byte) string {
	return d.path("tokens", hex.EncodeToString(hash)+".json")
}

// PutToken stores a token under the SHA-256 of its value.
func (d Dir) PutToken(hash []byte, t *Token) error { return writeJSON(d.tokenPath(hash), t) }

// Token reads the token with this hash.
func (d Dir) Token(hash []byte) (*Token, error) {
	var t Token
	if err := readJSON(d.tokenPath(hash), &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// ConsumeToken removes a token. Of several callers only one succeeds; the
// others get ErrNotFound.
func (d Dir) ConsumeToken(hash []byte) error {
	if err := os.Remove(d.tokenPath(hash)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	return syncDir(d.path("tokens"))
}

// Operator is operators/<name>.json: a bearer token of the operator
// interface, kept only as its SHA-256.
type Operator struct {
	Name        string    `json:"name"`
	TokenSHA256 []byte    `json:"token_sha256"`
	Created     time.Time `json:"created"`
}

// ValidOperatorName is a name an operator file can carry: 1 to 64 of
// letters, digits, '.', '_' and '-', not starting with '.'.
func ValidOperatorName(name string) bool {
	if name == "" || len(name) > 64 || name[0] == '.' {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (d Dir) operatorPath(name string) string { return d.path("operators", name+".json") }

// PutOperator stores a new operator; an existing name is fs.ErrExist.
func (d Dir) PutOperator(o *Operator) error {
	if !ValidOperatorName(o.Name) {
		return fmt.Errorf("operator name %q: 1 to 64 letters, digits, '.', '_' or '-'", o.Name)
	}
	if err := os.MkdirAll(d.path("operators"), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(d.operatorPath(o.Name)); err == nil {
		return fs.ErrExist
	}
	return writeJSON(d.operatorPath(o.Name), o)
}

// Operators reads every operator, ordered by name.
func (d Dir) Operators() ([]*Operator, error) {
	ents, err := os.ReadDir(d.path("operators"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var out []*Operator
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidOperatorName(name) {
			continue
		}
		var o Operator
		if err := readJSON(d.operatorPath(name), &o); err != nil {
			return nil, err
		}
		out = append(out, &o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// RemoveOperator removes an operator; an unknown one is ErrNotFound.
func (d Dir) RemoveOperator(name string) error {
	if !ValidOperatorName(name) {
		return ErrNotFound
	}
	if err := os.Remove(d.operatorPath(name)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	return syncDir(d.path("operators"))
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(path, append(b, '\n'))
}

// WriteFile writes a file atomically, 0600: a temporary file beside it,
// fsync, rename, fsync of the directory.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op after the rename
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
