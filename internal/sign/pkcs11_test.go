package sign

import (
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"strings"
	"testing"
	"time"
)

const softhsm = "/usr/lib/softhsm/libsofthsm2.so"

// Token is a SoftHSM2 token standing in for a PIV/CAC card. Tests skip
// where SoftHSM2 and OpenSC's pkcs11-tool are not installed.
func Token(t *testing.T) PKCS11Config {
	t.Helper()
	if _, err := os.Stat(softhsm); err != nil {
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
	label := fmt.Sprintf("gc%d", time.Now().UnixNano()%1e8)
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run("softhsm2-util", "--init-token", "--free", "--label", label, "--so-pin", "87654321", "--pin", "123456")
	run("pkcs11-tool", "--module", softhsm, "--token-label", label, "--login", "--pin", "123456",
		"--keypairgen", "--key-type", "EC:prime256v1", "--id", "02", "--label", "PIV Digital Signature")
	return PKCS11Config{Type: "pkcs11", Tool: "pkcs11-tool", Module: softhsm, TokenLabel: label, KeyID: "02"}
}

func pinOf(p string, calls *int) PINSource {
	return func(string) (string, error) { *calls++; return p, nil }
}

func TestPKCS11SignAndVerify(t *testing.T) {
	cfg := Token(t)
	calls := 0
	s, err := NewPKCS11Signer(cfg, pinOf("123456", &calls))
	if err != nil {
		t.Fatal(err)
	}
	if Alg(s) != AlgECDSAP256 || !IsHardware(s) || len(s.KeyID()) != 16 {
		t.Fatalf("alg=%s hw=%v id=%s", Alg(s), IsHardware(s), s.KeyID())
	}
	for i := 0; i < 3; i++ {
		msg := []byte(fmt.Sprintf("audit entry %d", i))
		sig, err := s.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(s.Public(), msg, sig) || Verify(s.Public(), []byte("other"), sig) {
			t.Fatal("signature check wrong")
		}
	}
	if calls != 1 {
		t.Errorf("PIN asked %d times; want once per process", calls)
	}
	// Detached file signatures use the same path as file keys.
	f := filepath.Join(t.TempDir(), "proposal.json")
	os.WriteFile(f, []byte(`{"id":"p1"}`), 0o644)
	if err := SignFile(s, f); err != nil {
		t.Fatal(err)
	}
	if _, kid, err := VerifyFileWith(f, s.Public()); err != nil || kid != s.KeyID() {
		t.Fatalf("%v %s", err, kid)
	}
	sigFile, _ := os.ReadFile(f + ".sig")
	if !strings.Contains(string(sigFile), AlgECDSAP256) {
		t.Errorf("detached sig alg: %s", sigFile)
	}
}

func TestPKCS11WrongPINAsksAgain(t *testing.T) {
	cfg := Token(t)
	calls := 0
	pins := []string{"000000", "123456"}
	s, err := NewPKCS11Signer(cfg, func(string) (string, error) { p := pins[calls]; calls++; return p, nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign([]byte("x")); err == nil {
		t.Fatal("wrong PIN signed")
	}
	if _, err := s.Sign([]byte("x")); err != nil {
		t.Fatalf("correct PIN after a wrong one: %v", err)
	}
	if calls != 2 {
		t.Errorf("calls %d", calls)
	}
}

// A CA-issued certificate on the token is picked up and parses as a user key.
func TestPKCS11CertificateFromToken(t *testing.T) {
	cfg := Token(t)
	s, err := NewPKCS11Signer(cfg, pinOf("123456", new(int)))
	if err != nil {
		t.Fatal(err)
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Site CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "DOE.JOHN.1234567890"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, s.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	der := filepath.Join(t.TempDir(), "cert.der")
	os.WriteFile(der, leafDER, 0o644)
	if out, err := exec.Command("pkcs11-tool", "--module", cfg.Module, "--token-label", cfg.TokenLabel, "--login", "--pin", "123456",
		"--write-object", der, "--type", "cert", "--id", cfg.KeyID).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	s2, err := NewPKCS11Signer(cfg, pinOf("123456", new(int)))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := CertificatePEM(s2)
	if err != nil || !strings.Contains(string(pemBytes), "BEGIN CERTIFICATE") {
		t.Fatalf("%v %s", err, pemBytes)
	}
	pub, cert, err := ParseUserKey(pemBytes)
	if err != nil || cert == nil || cert.Subject.CommonName != "DOE.JOHN.1234567890" || KeyID(pub) != s.KeyID() {
		t.Fatalf("%v %+v", err, cert)
	}
	_ = pem.Block{}
}

func TestParseUserKeyRejectsOtherCurvesAndTypes(t *testing.T) {
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k384.PublicKey)
	if _, _, err := ParseUserKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err == nil {
		t.Error("P-384 accepted")
	}
	if _, _, err := ParseUserKey([]byte("junk")); err == nil {
		t.Error("junk accepted")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ = x509.MarshalPKIXPublicKey(pub)
	if _, _, err := ParseUserKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err != nil {
		t.Errorf("ed25519 refused: %v", err)
	}
}
