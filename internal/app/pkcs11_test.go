package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sandy-t-shelvan/govcode/internal/identity"
	"github.com/sandy-t-shelvan/govcode/internal/keyring"
	"github.com/sandy-t-shelvan/govcode/internal/policy"
	"github.com/sandy-t-shelvan/govcode/internal/proposal"
	"github.com/sandy-t-shelvan/govcode/internal/testutil/hsm"
)

// tokenWorld: the user signs with a SoftHSM token, the keyring holds a
// CA-issued certificate for it, and policy requires a hardware approver.
func tokenWorld(t *testing.T, certFor func(ca *hsm.CA, tk *hsm.Token) []byte) (*App, []Check, error) {
	t.Helper()
	tk := hsm.New(t)
	ca := hsm.NewCA(t, "Test DoD-style Root CA")
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	os.WriteFile(caFile, ca.PEM(), 0o644)
	cfg := filepath.Join(dir, "signer.json")
	os.WriteFile(cfg, []byte(tk.Config()), 0o600)
	t.Setenv("GOVCODE_SIGNER", cfg)
	t.Setenv("GOVCODE_PKCS11_PIN", hsm.PIN)
	certPEM := certFor(ca, tk)
	return openWorld(t, func(p *policy.Policy) {
		p.Trust.UserCA = caFile
		p.RequireHardwareApprover = true
		u, _ := identity.Current()
		kdir := p.Trust.KeyringDir
		if kdir == "" {
			kdir = filepath.Join(p.StateDir, "keys")
		}
		if _, err := keyring.RegisterPEM(kdir, u, certPEM); err != nil {
			t.Fatal(err)
		}
	})
}

func validCert(t *testing.T) func(ca *hsm.CA, tk *hsm.Token) []byte {
	return func(ca *hsm.CA, tk *hsm.Token) []byte {
		return ca.Issue(t, "DOE.JANE.1234567890", tk.PublicKey(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	}
}

func TestHardwareTokenProposeApproveVerify(t *testing.T) {
	a, checks, err := tokenWorld(t, validCert(t))
	if err != nil {
		t.Fatalf("%v %+v", err, checks)
	}
	var sk string
	for _, c := range checks {
		if c.Name == "signing key" {
			sk = c.Status + " " + c.Detail
		}
	}
	if !strings.HasPrefix(sk, "PASS PKCS#11 token key") || !strings.Contains(sk, "DOE.JANE") {
		t.Fatalf("signing key check: %s", sk)
	}
	p, err := a.Run(context.Background(), RunOptions{Task: "set port to 2", Backend: edit("int port = 2;")})
	if err != nil || p.Status != proposal.StatusReady {
		t.Fatalf("%v %+v", err, p)
	}
	res, err := a.Land(p, proposal.Rules{Classification: a.Policy.Classification}, "")
	if err != nil {
		t.Fatal(err)
	}
	v, err := a.VerifyEvidence(res.Commit)
	if err != nil || v.Record.Approver.Signer != "pkcs11" || !strings.Contains(v.Record.Approver.Certificate, "DOE.JANE") {
		t.Fatalf("%v %+v", err, v)
	}
	rep, err := a.Log.Verify(a.Keyring, nil, true)
	if err != nil || rep == nil {
		t.Fatalf("audit verify with ECDSA entries: %v %+v", err, rep)
	}
}

func TestCertificateNotFromSiteCAIsNotTrusted(t *testing.T) {
	_, _, err := tokenWorld(t, func(_ *hsm.CA, tk *hsm.Token) []byte {
		other := hsm.NewCA(t, "Some Other CA")
		return other.Issue(t, "MALLORY", tk.PublicKey(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	})
	if err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("certificate from a foreign CA accepted: %v", err)
	}
}

func TestExpiredCertificateCannotSign(t *testing.T) {
	_, _, err := tokenWorld(t, func(ca *hsm.CA, tk *hsm.Token) []byte {
		return ca.Issue(t, "DOE.JANE", tk.PublicKey(), time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	})
	if err == nil || !strings.Contains(err.Error(), "certificate for") {
		t.Fatalf("expired certificate accepted for signing: %v", err)
	}
}

func TestFileKeyApproverRefusedWhenHardwareRequired(t *testing.T) {
	a := world(t)
	a.Policy.RequireHardwareApprover = true // a file-key signer is loaded
	p, err := a.Run(context.Background(), RunOptions{Task: "set port to 2", Backend: edit("int port = 2;")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Land(p, proposal.Rules{}, ""); err == nil || !strings.Contains(err.Error(), "hardware key") {
		t.Fatalf("file-key approval accepted: %v", err)
	}
}

func TestHardwareApproverNeedsUserCA(t *testing.T) {
	_, _, err := openWorld(t, func(p *policy.Policy) { p.RequireHardwareApprover = true })
	if err == nil || !strings.Contains(err.Error(), "trust.user_ca") {
		t.Fatalf("%v", err)
	}
}
