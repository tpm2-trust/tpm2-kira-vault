// Package tlsutil makes and loads the vault's TLS key, and checks a pin the
// way a machine does.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mrwiora/tpm2-kira/core/vaultproto"

	"github.com/tpm2-trust/tpm2-kira-vault/internal/state"
)

// Generate makes an ECDSA P-256 key and a self-signed certificate for host,
// valid 100 years: machines pin its key (vaultproto.PinOf) and check
// neither its chain nor its dates.
func Generate(host string, now time.Time) (keyPEM, certPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(100, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else if host != "" {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// Write makes the key and certificate in the state directory.
func Write(d state.Dir, host string, now time.Time) error {
	k, c, err := Generate(host, now)
	if err != nil {
		return err
	}
	if err := state.WriteFile(d.TLSKeyPath(), k); err != nil {
		return err
	}
	return state.WriteFile(d.TLSCertPath(), c)
}

// Load reads the key and certificate of the state directory, and their pin.
func Load(d state.Dir) (tls.Certificate, string, error) {
	cert, err := tls.LoadX509KeyPair(d.TLSCertPath(), d.TLSKeyPath())
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("the TLS key: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, "", err
	}
	cert.Leaf = leaf
	return cert, vaultproto.PinOf(leaf.RawSubjectPublicKeyInfo), nil
}

// Pin reads the certificate of the state directory and returns its pin.
func Pin(d state.Dir) (string, error) {
	b, err := os.ReadFile(d.TLSCertPath())
	if err != nil {
		return "", err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return "", errors.New("the TLS certificate is not PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "", err
	}
	return vaultproto.PinOf(c.RawSubjectPublicKeyInfo), nil
}

// CurlPin is a pin ("sha256:" and hex) as curl's --pinnedpubkey takes it:
// "sha256//" and base64.
func CurlPin(pin string) string {
	raw, err := hex.DecodeString(strings.TrimPrefix(pin, "sha256:"))
	if err != nil {
		return ""
	}
	return "sha256//" + base64.StdEncoding.EncodeToString(raw)
}

// ServerConfig is the machine-facing TLS configuration: TLS 1.3 only.
func ServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
}

// PinnedConfig is a client's TLS configuration that accepts exactly the
// server whose certificate's key has this pin, as a machine connects: no
// chain, no dates, a failed pin is a refused connection.
func PinnedConfig(pin string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by VerifyConnection: the pin is the whole check
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the vault sent no certificate")
			}
			if got := vaultproto.PinOf(cs.PeerCertificates[0].RawSubjectPublicKeyInfo); got != pin {
				return fmt.Errorf("the vault's key has pin %s, not %s", got, pin)
			}
			return nil
		},
	}
}
