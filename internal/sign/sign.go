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
	"crypto/ed25519"
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

type Signer interface {
	Sign(msg []byte) ([]byte, error)
	Public() ed25519.PublicKey
	KeyID() string
}

type fileSigner struct {
	priv ed25519.PrivateKey
}

func (s fileSigner) Sign(msg []byte) ([]byte, error) {
	return s.priv.Sign(rand.Reader, msg, crypto.Hash(0))
}
func (s fileSigner) Public() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }
func (s fileSigner) KeyID() string             { return KeyID(s.Public()) }

// KeyID is the first 16 hex chars of SHA-256 over the raw public key.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
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

func WritePublic(path string, pub ed25519.PublicKey) error {
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
	d := Detached{Alg: "ed25519", KeyID: s.KeyID(), SHA256: hex.EncodeToString(h[:]), Sig: base64.StdEncoding.EncodeToString(sig)}
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

func Verify(pub ed25519.PublicKey, msg, sig []byte) bool { return ed25519.Verify(pub, msg, sig) }
