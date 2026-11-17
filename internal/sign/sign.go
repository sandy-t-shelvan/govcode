// Package sign provides Ed25519 signing for audit entries, proposals,
// approvals, release manifests and model lock files.
//
// Ed25519 is approved in FIPS 186-5 and is implemented inside the Go
// Cryptographic Module; build with GOFIPS140=v1.0.0 and run with
// GODEBUG=fips140=on to use it in FIPS mode (see docs/SUPPLY_CHAIN.md).
// Keys are PKCS#8 / PKIX PEM so they can be generated or wrapped by
// standard PKI tooling; the Signer interface is the hook for PIV/HSM-held
// keys.
package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Signer signs as one user. File keys are Ed25519; hardware tokens (PIV/CAC
// through PKCS#11) are ECDSA P-256 with SHA-256.
type Signer interface {
	Sign(msg []byte) ([]byte, error)
	Public() crypto.PublicKey
	KeyID() string
}

// Algorithms recorded in detached signatures.
const (
	AlgEd25519   = "ed25519"
	AlgECDSAP256 = "ecdsa-p256-sha256"
)

// Alg names the signer's algorithm.
func Alg(s Signer) string {
	if a, ok := s.(interface{ Alg() string }); ok {
		return a.Alg()
	}
	return AlgEd25519
}

// IsHardware reports whether the key never leaves a hardware token.
func IsHardware(s Signer) bool {
	h, ok := s.(interface{ Hardware() bool })
	return ok && h.Hardware()
}

type fileSigner struct {
	priv ed25519.PrivateKey
}

func (s fileSigner) Sign(msg []byte) ([]byte, error) {
	return s.priv.Sign(rand.Reader, msg, crypto.Hash(0))
}
func (s fileSigner) Public() crypto.PublicKey { return s.priv.Public().(ed25519.PublicKey) }
func (s fileSigner) KeyID() string            { return KeyID(s.Public()) }

// KeyID is the first 16 hex chars of SHA-256 over the raw Ed25519 public
// key, or over the PKIX encoding of an ECDSA key.
func KeyID(pub crypto.PublicKey) string {
	var b []byte
	switch k := pub.(type) {
	case ed25519.PublicKey:
		b = k
	case *ecdsa.PublicKey:
		b, _ = x509.MarshalPKIXPublicKey(k)
	default:
		return "unsupported-key"
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// NewSigner wraps an in-memory key (used by tests and the eval harness).
func NewSigner(priv ed25519.PrivateKey) Signer { return fileSigner{priv} }

// GenerateKeyFiles writes <base>.key (0600) and <base>.pub (0644).
func GenerateKeyFiles(base string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(base), 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(base + ".key"); err == nil {
		return nil, fmt.Errorf("refusing to overwrite existing key %s.key", base)
	}
	pk8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := writeExcl(base+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk8}), 0o600); err != nil {
		return nil, err
	}
	if err := WritePublic(base+".pub", pub); err != nil {
		return nil, err
	}
	return pub, nil
}

func WritePublic(path string, pub crypto.PublicKey) error {
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}), 0o644)
}

func writeExcl(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// LoadSigner loads a private key, refusing keys readable by group/other or
// owned by someone other than the caller.
func LoadSigner(path string) (Signer, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w (run `govcode keygen`)", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("signing key %s has mode %o; must be 0600", path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return nil, fmt.Errorf("signing key %s is owned by uid %d, not the invoking user (uid %d)", path, st.Uid, os.Getuid())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "PRIVATE KEY" {
		return nil, errors.New("signing key: not a PKCS#8 PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key: not Ed25519")
	}
	return fileSigner{priv}, nil
}

func ParsePublic(data []byte) (ed25519.PublicKey, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "PUBLIC KEY" {
		return nil, errors.New("not a PEM public key")
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return pub, nil
}

func LoadPublic(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublic(data)
}

// Detached is the on-disk format of a detached signature (<file>.sig).
type Detached struct {
	Alg    string `json:"alg"`
	KeyID  string `json:"key_id"`
	SHA256 string `json:"sha256"`
	Sig    string `json:"sig"`
}

// SignFile signs the file's bytes and writes <path>.sig.
func SignFile(s Signer, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sig, err := s.Sign(data)
	if err != nil {
		return err
	}
	h := sha256.Sum256(data)
	d := Detached{Alg: Alg(s), KeyID: s.KeyID(), SHA256: hex.EncodeToString(h[:]), Sig: base64.StdEncoding.EncodeToString(sig)}
	out, _ := json.MarshalIndent(d, "", "  ")
	return os.WriteFile(path+".sig", append(out, '\n'), 0o644)
}

// VerifyFile checks <path>.sig against any of the trusted keys and returns
// the file contents only if the signature is valid.
func VerifyFile(path string, trusted ...ed25519.PublicKey) ([]byte, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	sigData, err := os.ReadFile(path + ".sig")
	if err != nil {
		return nil, "", fmt.Errorf("missing signature %s.sig: %w", path, err)
	}
	var d Detached
	if err := json.Unmarshal(sigData, &d); err != nil {
		return nil, "", fmt.Errorf("bad signature file: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(d.Sig)
	if err != nil {
		return nil, "", err
	}
	for _, pub := range trusted {
		if ed25519.Verify(pub, data, sig) {
			return data, KeyID(pub), nil
		}
	}
	return nil, "", fmt.Errorf("signature on %s does not verify against any trusted key (sig key_id=%s)", path, d.KeyID)
}

// Verify checks an Ed25519 signature, or an ASN.1 ECDSA P-256 signature over
// SHA-256(msg).
func Verify(pub crypto.PublicKey, msg, sig []byte) bool {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig)
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return false
		}
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(k, h[:], sig)
	}
	return false
}

// VerifyFileWith is VerifyFile for user keys of any supported type.
func VerifyFileWith(path string, trusted ...crypto.PublicKey) ([]byte, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	sigData, err := os.ReadFile(path + ".sig")
	if err != nil {
		return nil, "", fmt.Errorf("missing signature %s.sig: %w", path, err)
	}
	var d Detached
	if err := json.Unmarshal(sigData, &d); err != nil {
		return nil, "", fmt.Errorf("bad signature file: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(d.Sig)
	if err != nil {
		return nil, "", err
	}
	for _, pub := range trusted {
		if Verify(pub, data, sig) {
			return data, KeyID(pub), nil
		}
	}
	return nil, "", fmt.Errorf("signature on %s does not verify against any trusted key (sig key_id=%s)", path, d.KeyID)
}

// ParseUserKey reads a user's public key: a PEM PUBLIC KEY (Ed25519 or
// ECDSA P-256) or a PEM CERTIFICATE (for PIV/CAC), returning the
// certificate too when there is one.
func ParseUserKey(data []byte) (crypto.PublicKey, *x509.Certificate, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, nil, errors.New("not PEM")
	}
	var pub crypto.PublicKey
	var cert *x509.Certificate
	switch b.Type {
	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			return nil, nil, err
		}
		pub = k
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, nil, err
		}
		cert, pub = c, c.PublicKey
	default:
		return nil, nil, fmt.Errorf("unsupported PEM block %q", b.Type)
	}
	switch k := pub.(type) {
	case ed25519.PublicKey:
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, nil, errors.New("ECDSA keys must be P-256")
		}
	default:
		return nil, nil, fmt.Errorf("unsupported key type %T (Ed25519 or ECDSA P-256)", pub)
	}
	return pub, cert, nil
}
