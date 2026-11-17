package sign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// PKCS11Config selects a key on a PIV/CAC card (or HSM) through the site's
// PKCS#11 tooling. govcode calls the tool as an external process, so the
// binary stays free of cgo and third-party code; the private key never
// leaves the token.
//
// ~/.config/govcode/signer.json (or $GOVCODE_SIGNER):
//
//	{"type": "pkcs11", "tool": "/usr/bin/pkcs11-tool",
//	 "module": "/usr/lib64/opensc-pkcs11.so", "token_label": "...", "key_id": "02"}
//
// key_id is the PKCS#11 CKA_ID in hex (on PIV cards "02" is usually the
// Digital Signature key, 9C).
type PKCS11Config struct {
	Type       string `json:"type"`
	Tool       string `json:"tool"`
	Module     string `json:"module"`
	TokenLabel string `json:"token_label"`
	KeyID      string `json:"key_id"`
}

// PINSource returns the user's PIN. It is called once per process.
type PINSource func(prompt string) (string, error)

type pkcs11Signer struct {
	cfg  PKCS11Config
	pub  *ecdsa.PublicKey
	cert *x509.Certificate
	pin  PINSource

	mu     sync.Mutex
	cached string
}

// LoadSignerConfig reads a signer configuration file.
func LoadSignerConfig(path string) (*PKCS11Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c PKCS11Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Type != "pkcs11" {
		return nil, fmt.Errorf("%s: type must be \"pkcs11\"", path)
	}
	if c.Tool == "" {
		c.Tool = "pkcs11-tool"
	}
	if c.Module == "" || c.KeyID == "" {
		return nil, fmt.Errorf("%s: module and key_id are required", path)
	}
	if _, err := hex.DecodeString(c.KeyID); err != nil {
		return nil, fmt.Errorf("%s: key_id must be hex", path)
	}
	return &c, nil
}

func (c PKCS11Config) args(extra ...string) []string {
	a := []string{"--module", c.Module}
	if c.TokenLabel != "" {
		a = append(a, "--token-label", c.TokenLabel)
	}
	return append(a, extra...)
}

// NewPKCS11Signer opens the key described by cfg. It reads the
// certificate from the token (or, failing that, the public key); it does
// not need the PIN until the first signature.
func NewPKCS11Signer(cfg PKCS11Config, pin PINSource) (Signer, error) {
	tmp, err := os.MkdirTemp("", "govcode-pkcs11-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	s := &pkcs11Signer{cfg: cfg, pin: pin}
	certPath := filepath.Join(tmp, "cert.der")
	if _, err := s.run(nil, cfg.args("--read-object", "--type", "cert", "--id", cfg.KeyID, "-o", certPath)...); err == nil {
		if der, err := os.ReadFile(certPath); err == nil && len(der) > 0 {
			if c, err := x509.ParseCertificate(der); err == nil {
				s.cert = c
			}
		}
	}
	var pub crypto.PublicKey
	if s.cert != nil {
		pub = s.cert.PublicKey
	} else {
		pubPath := filepath.Join(tmp, "pub.der")
		if out, err := s.run(nil, cfg.args("--read-object", "--type", "pubkey", "--id", cfg.KeyID, "-o", pubPath)...); err != nil {
			return nil, fmt.Errorf("pkcs11: no certificate or public key with id %s on the token: %v %s", cfg.KeyID, err, out)
		}
		der, err := os.ReadFile(pubPath)
		if err != nil {
			return nil, err
		}
		if pub, err = x509.ParsePKIXPublicKey(der); err != nil {
			return nil, fmt.Errorf("pkcs11: public key: %w", err)
		}
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("pkcs11: key %s is %T; govcode supports ECDSA P-256 token keys", cfg.KeyID, pub)
	}
	s.pub = ec
	return s, nil
}

func (s *pkcs11Signer) run(env []string, args ...string) (string, error) {
	cmd := exec.Command(s.cfg.Tool, args...)
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func (s *pkcs11Signer) Public() crypto.PublicKey { return s.pub }
func (s *pkcs11Signer) KeyID() string            { return KeyID(s.pub) }
func (s *pkcs11Signer) Alg() string              { return AlgECDSAP256 }
func (s *pkcs11Signer) Hardware() bool           { return true }

// Certificate is the token's certificate, if it holds one.
func (s *pkcs11Signer) Certificate() *x509.Certificate { return s.cert }

// Sign hashes msg with SHA-256 and has the token sign the digest (CKM_ECDSA).
// The PIN is passed in the child's environment, never on its command line,
// where other users could read it.
func (s *pkcs11Signer) Sign(msg []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached == "" {
		p, err := s.pin(fmt.Sprintf("PIN for %s (key %s): ", s.label(), s.KeyID()))
		if err != nil {
			return nil, fmt.Errorf("pkcs11: PIN: %w", err)
		}
		if p == "" {
			return nil, errors.New("pkcs11: empty PIN")
		}
		s.cached = p
	}
	tmp, err := os.MkdirTemp("", "govcode-pkcs11-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	h := sha256.Sum256(msg)
	in, out := filepath.Join(tmp, "digest"), filepath.Join(tmp, "sig")
	if err := os.WriteFile(in, h[:], 0o600); err != nil {
		return nil, err
	}
	res, err := s.run([]string{"GOVCODE_PKCS11_PIN=" + s.cached},
		s.cfg.args("--login", "--pin", "env:GOVCODE_PKCS11_PIN", "--sign", "--mechanism", "ECDSA",
			"--id", s.cfg.KeyID, "--signature-format", "openssl", "-i", in, "-o", out)...)
	if err != nil {
		if strings.Contains(res, "PIN_INCORRECT") || strings.Contains(res, "PIN_LOCKED") {
			s.cached = "" // ask again next time; the token counts failures
		}
		return nil, fmt.Errorf("pkcs11: sign failed: %v: %s", err, lastLine(res))
	}
	sig, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	// Never return a signature that would not verify.
	if !Verify(s.pub, msg, sig) {
		return nil, errors.New("pkcs11: token returned a signature that does not verify against its own key")
	}
	return sig, nil
}

func (s *pkcs11Signer) label() string {
	if s.cfg.TokenLabel != "" {
		return s.cfg.TokenLabel
	}
	return "token"
}

func lastLine(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	return l[len(l)-1]
}

// CertificatePEM returns the signer's certificate (or public key) as PEM,
// for registering in the keyring.
func CertificatePEM(s Signer) ([]byte, error) {
	if c, ok := s.(interface{ Certificate() *x509.Certificate }); ok && c.Certificate() != nil {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate().Raw}), nil
	}
	der, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
