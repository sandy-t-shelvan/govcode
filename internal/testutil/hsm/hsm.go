// Package hsm creates a SoftHSM2 token for tests: a software PKCS#11 token
// standing in for a PIV/CAC card. It is imported only by tests.
package hsm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const Module = "/usr/lib/softhsm/libsofthsm2.so"
const PIN = "123456"

type Token struct {
	Label, KeyID string
	t            *testing.T
}

// New creates a token with one ECDSA P-256 key (id 02), or skips the test
// where SoftHSM2 and OpenSC's pkcs11-tool are not installed.
func New(t *testing.T) *Token {
	t.Helper()
	if _, err := os.Stat(Module); err != nil {
		t.Skip("SoftHSM2 not installed")
	}
	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		t.Skip("pkcs11-tool (OpenSC) not installed")
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "tokens"), 0o700)
	conf := filepath.Join(dir, "softhsm2.conf")
	os.WriteFile(conf, []byte("directories.tokendir = "+filepath.Join(dir, "tokens")+"\nobjectstore.backend = file\nlog.level = ERROR\n"), 0o600)
	t.Setenv("SOFTHSM2_CONF", conf)
	tk := &Token{Label: fmt.Sprintf("gc%d", time.Now().UnixNano()%1e8), KeyID: "02", t: t}
	tk.run("softhsm2-util", "--init-token", "--free", "--label", tk.Label, "--so-pin", "87654321", "--pin", PIN)
	tk.tool("--login", "--pin", PIN, "--keypairgen", "--key-type", "EC:prime256v1", "--id", tk.KeyID, "--label", "PIV Digital Signature")
	return tk
}

func (tk *Token) run(name string, args ...string) {
	tk.t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		tk.t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func (tk *Token) tool(args ...string) {
	tk.t.Helper()
	tk.run("pkcs11-tool", append([]string{"--module", Module, "--token-label", tk.Label}, args...)...)
}

// Config is the signer.json content for this token.
func (tk *Token) Config() string {
	return fmt.Sprintf(`{"type":"pkcs11","tool":"pkcs11-tool","module":%q,"token_label":%q,"key_id":%q}`, Module, tk.Label, tk.KeyID)
}

// PublicKey reads the token key's public half.
func (tk *Token) PublicKey() *ecdsa.PublicKey {
	tk.t.Helper()
	der := filepath.Join(tk.t.TempDir(), "pub.der")
	tk.tool("--read-object", "--type", "pubkey", "--id", tk.KeyID, "-o", der)
	b, _ := os.ReadFile(der)
	k, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		tk.t.Fatal(err)
	}
	return k.(*ecdsa.PublicKey)
}

// CA is a test certificate authority.
type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func NewCA(t *testing.T, name string) *CA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().AddDate(0, 0, -30),
		NotAfter: time.Now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &CA{Cert: c, key: key}
}

// PEM is the CA bundle.
func (ca *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

// Issue makes a user certificate for pub valid from notBefore to notAfter.
func (ca *CA) Issue(t *testing.T, cn string, pub *ecdsa.PublicKey, notBefore, notAfter time.Time) []byte {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
